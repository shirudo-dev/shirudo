// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "config_image.h"
#include "config_update.h"
#include "crypto.h"
#include "dm_verity.h"
#include "hex.h"
#include "image_cache.h"
#include "io.h"
#include "log.h"
#include "paths.h"
#include "seal.h"

struct image_download {
	int fd;
	int err;	/* why the last write was refused */
	__u64 limit;
	__u64 written;
};

/* A resolver thread can receive a process-directed SIGINT. */
static _Atomic bool download_interrupted;

#ifdef __GCC_ATOMIC_BOOL_LOCK_FREE
_Static_assert(__GCC_ATOMIC_BOOL_LOCK_FREE == 2, "SIGINT requires lock-free atomics");
#endif

static void download_sigint(int sig)
{
	download_interrupted = true;
}

static int download_enable_quick_exit(CURL *curl)
{
#if LIBCURL_VERSION_NUM >= 0x075700
	const struct curl_version_info_data *version =
		curl_version_info(CURLVERSION_NOW);

#if LIBCURL_VERSION_NUM < 0x081400
	if (version->version_num >= 0x081400)
		return -EOPNOTSUPP;
#endif
	if (!(version->features & CURL_VERSION_ASYNCHDNS) ||
	    curl_easy_setopt(curl, CURLOPT_QUICK_EXIT, 1L) != CURLE_OK)
		return -EOPNOTSUPP;
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

static int download_multi_perform(CURL *curl, CURLcode *result)
{
#if LIBCURL_VERSION_NUM >= 0x081400
	const struct curl_version_info_data *version =
		curl_version_info(CURLVERSION_NOW);
#endif
	CURLMcode status;
	CURLMsg *message;
	CURLM *multi;
	int running, left, ret = -EIO;

	multi = curl_multi_init();
	if (!multi)
		return -ENOMEM;
#if LIBCURL_VERSION_NUM >= 0x081400
	if (version->version_num >= 0x081400 &&
	    curl_multi_setopt(multi, CURLMOPT_QUICK_EXIT, 1L) != CURLM_OK)
		goto out;
#endif
	if (curl_multi_add_handle(multi, curl) != CURLM_OK)
		goto out;
	while (!download_interrupted) {
		status = curl_multi_perform(multi, &running);
		if (status != CURLM_OK)
			goto remove;
		if (!running || download_interrupted)
			break;
		if (curl_multi_poll(multi, NULL, 0, 1000, NULL) != CURLM_OK)
			goto remove;
	}
	if (download_interrupted) {
		ret = -EINTR;
		goto remove;
	}
	message = curl_multi_info_read(multi, &left);
	if (message && message->msg == CURLMSG_DONE) {
		*result = message->data.result;
		ret = 0;
	}
remove:
	curl_multi_remove_handle(multi, curl);
out:
	curl_multi_cleanup(multi);
	return ret;
}

static int download_perform(CURL *curl, CURLcode *result)
{
	struct sigaction action = { .sa_handler = download_sigint };
	struct sigaction previous;
	bool interruptible = false;
	int ret;

	if (sigaction(SIGINT, NULL, &previous))
		return -errno;
	/*
	 * Keep the inherited action when libcurl may block in the resolver
	 * or wait for a resolver thread after the transfer aborts.
	 */
	if (previous.sa_handler == SIG_DFL)
		interruptible = !download_enable_quick_exit(curl);
	if (!interruptible) {
		*result = curl_easy_perform(curl);
		return 0;
	}
	download_interrupted = false;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGINT, &action, NULL))
		return -errno;
	ret = download_multi_perform(curl, result);
	if (sigaction(SIGINT, &previous, NULL))
		return -errno;
	return download_interrupted ? -EINTR : ret;
}

static size_t download_write(char *data, size_t size, size_t count, void *ctx)
{
	struct image_download *download = ctx;
	size_t bytes;
	int ret;

	if (check_mul_overflow(size, count, &bytes)) {
		download->err = -EFBIG;
		return 0;
	}
	if (bytes > download->limit - download->written) {
		download->err = -EFBIG;
		return 0;
	}
	ret = write_complete(download->fd, data, bytes);
	if (ret) {
		download->err = ret;
		return 0;
	}
	download->written += bytes;
	return bytes;
}

static int download_https(const char *source, struct image_download *download)
{
	CURLcode result;
	CURL *curl;
	int ret;

	curl = curl_easy_init();
	if (!curl)
		return -ENOMEM;
	ret = tls_curl_policy(curl, NULL);
	if (ret)
		goto out;
	if (curl_easy_setopt(curl, CURLOPT_URL, source) != CURLE_OK ||
	    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https") != CURLE_OK ||
	    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR,
			     "https") != CURLE_OK ||
	    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L) != CURLE_OK ||
	    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L) != CURLE_OK ||
	    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L) != CURLE_OK ||
	    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L) != CURLE_OK ||
	    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1024L) != CURLE_OK ||
	    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 60L) != CURLE_OK ||
	    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
			     download_write) != CURLE_OK ||
	    curl_easy_setopt(curl, CURLOPT_WRITEDATA, download) != CURLE_OK) {
		ret = -EINVAL;
		goto out;
	}
	ret = download_perform(curl, &result);
	if (!ret && result != CURLE_OK)
		ret = download->err ? download->err : -EIO;
out:
	curl_easy_cleanup(curl);
	return ret;
}

static int copy_local(const char *source, struct image_download *download)
{
	char buffer[65536];
	struct stat st;
	ssize_t n;
	int fd, ret = 0;

	fd = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st)) {
		ret = -errno;
		goto out;
	}
	if (!S_ISREG(st.st_mode) || st.st_size < 0 ||
	    (__u64)st.st_size > download->limit) {
		ret = -EINVAL;
		goto out;
	}
	while ((n = read(fd, buffer, sizeof(buffer))) != 0) {
		if (n < 0) {
			if (errno == EINTR)
				continue;
			ret = -errno;
			break;
		}
		if (download_write(buffer, 1, n, download) != (size_t)n) {
			ret = download->err;
			break;
		}
	}
out:
	close(fd);
	return ret;
}

static int fetch_file(const char *source, const char *destination, __u64 max)
{
	struct image_download download = { .limit = max };
	int fd, ret;

	fd = open(destination,
		  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0)
		return -errno;
	download.fd = fd;
	ret = fsetxattr(fd, XATTR_SEAL, SEAL_LABEL,
			strlen(SEAL_LABEL), 0) ? -errno : 0;
	if (!ret)
		ret = str_has_prefix(source, "https://") ?
			download_https(source, &download) :
			copy_local(source, &download);
	if (!ret && fsync(fd))
		ret = -errno;
	close(fd);
	return ret;
}

/* Verify downloads before publishing their root-hash-named cache files. */
static int verify_incoming(const struct config_image_open *opened,
			   const char *staging)
{
	struct dm_verity device = {
		.data_loop_fd = -1,
		.hash_loop_fd = -1,
	};
	int ret, cleanup;
	char name[128];

	if (strsprintf(name, sizeof(name), "shirudo-verify-%s", strrchr(staging, '/') + 1) < 0)
		return -ENAMETOOLONG;
	ret = dm_verity_create(opened, name, &device);
	if (ret)
		return ret;
	ret = dm_verity_verify(&device, opened);
	cleanup = dm_verity_remove(&device, true);
	if (cleanup)
		pr_warn("image: cannot remove incoming mapping: %s",
			strerror(-cleanup));
	dm_verity_close(&device);
	return ret ? ret : cleanup;
}

int image_cache_fetch(const char *source,
		      struct config_update_target *target,
		      image_cache_verify_fn verify, void *ctx)
{
	static const struct {
		const char *suffix;
		__u64 max_bytes;
	} files[] = {
		{ ".roothash", 65 },
		{ ".p7s", CONFIG_IMAGE_SIG_MAX },
		{ ".img", CONFIG_IMAGE_MAX_BYTES },
		{ ".verity", CONFIG_IMAGE_MAX_BYTES },
	};
	struct config_image_open opened;
	char staging[] = IMAGE_CACHE_DIR "/incoming-XXXXXX";
	char incoming[PATH_MAX], from[PATH_MAX], to[PATH_MAX];
	char hex[65];
	int dir = -1, ret;
	size_t i;

	if (!verify)
		return -EINVAL;
	if (!mkdtemp(staging))
		return -errno;
	ret = seal_label(staging);
	if (ret)
		goto out;
	if (strsprintf(incoming, sizeof(incoming), "%s/image", staging) < 0) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	for (i = 0; i < ARRAY_SIZE(files); i++) {
		if (strsprintf(from, sizeof(from), "%s%s", source, files[i].suffix) < 0 ||
		    strsprintf(to, sizeof(to), "%s%s", incoming, files[i].suffix) < 0) {
			ret = -ENAMETOOLONG;
			goto out;
		}
		ret = fetch_file(from, to, files[i].max_bytes);
		if (ret)
			goto out;
	}
	ret = config_image_open(incoming, &opened);
	if (ret)
		goto out;
	ret = verify(&opened, ctx);
	if (!ret)
		ret = verify_incoming(&opened, staging);
	if (!ret) {
		memcpy(target->root_hash, opened.image.root_hash, 32);
		hex_encode(target->root_hash, 32, hex);
		if (strsprintf(target->prefix, sizeof(target->prefix), "%s/%s",
			       IMAGE_CACHE_DIR, hex) < 0)
			ret = -ENAMETOOLONG;
	}
	config_image_close(&opened);
	if (ret)
		goto out;
	for (i = 0; i < ARRAY_SIZE(files); i++) {
		if (strsprintf(from, sizeof(from), "%s%s", incoming, files[i].suffix) < 0 ||
		    strsprintf(to, sizeof(to), "%s%s", target->prefix, files[i].suffix) < 0) {
			ret = -ENAMETOOLONG;
			goto out;
		}
		if (link(from, to) && errno != EEXIST) {
			ret = -errno;
			goto out;
		}
	}
	dir = open(IMAGE_CACHE_DIR,
		   O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (dir < 0 || fsync(dir)) {
		ret = -errno;
		goto out;
	}
	ret = config_image_open(target->prefix, &opened);
	if (!ret) {
		if (memcmp(opened.image.root_hash, target->root_hash, 32))
			ret = -EKEYREJECTED;
		config_image_close(&opened);
	}
out:
	if (dir >= 0)
		close(dir);
	for (i = 0; i < ARRAY_SIZE(files); i++) {
		if (strsprintf(to, sizeof(to), "%s/image%s", staging, files[i].suffix) >= 0)
			unlink(to);
	}
	rmdir(staging);
	return ret;
}
