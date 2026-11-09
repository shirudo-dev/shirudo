// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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
	curl_easy_setopt(curl, CURLOPT_URL, source);
	curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
	curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
	curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1024L);
	curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 60L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, download_write);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, download);
	result = curl_easy_perform(curl);
	if (result != CURLE_OK)
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
		ret = !strncmp(source, "https://", 8) ?
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
