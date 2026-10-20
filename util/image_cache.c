// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>

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
#include "macros.h"
#include "paths.h"
#include "seal.h"

struct image_download {
	int fd;
	__u64 limit;
	__u64 written;
};

static size_t download_write(char *data, size_t size, size_t count, void *ctx)
{
	struct image_download *download = ctx;
	size_t bytes;

	if (size && count > SIZE_MAX / size)
		return 0;
	bytes = size * count;
	if (bytes > download->limit - download->written ||
	    write_complete(download->fd, data, bytes))
		return 0;
	download->written += bytes;
	return bytes;
}

static int download_https(const char *source, struct image_download *download)
{
	CURLcode result;
	CURL *curl;
	int rc;

	curl = curl_easy_init();
	if (!curl)
		return -ENOMEM;
	rc = tls_curl_policy(curl, NULL);
	if (rc)
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
		rc = -EIO;
out:
	curl_easy_cleanup(curl);
	return rc;
}

static int copy_local(const char *source, struct image_download *download)
{
	char buffer[65536];
	struct stat st;
	ssize_t n;
	int fd, rc = 0;

	fd = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st)) {
		rc = -errno;
		goto out;
	}
	if (!S_ISREG(st.st_mode) || st.st_size < 0 ||
	    (__u64)st.st_size > download->limit) {
		rc = -EINVAL;
		goto out;
	}
	while ((n = read(fd, buffer, sizeof(buffer))) != 0) {
		if (n < 0) {
			if (errno == EINTR)
				continue;
			rc = -errno;
			break;
		}
		if (download_write(buffer, 1, n, download) != (size_t)n) {
			rc = -EFBIG;
			break;
		}
	}
out:
	close(fd);
	return rc;
}

static int fetch_file(const char *source, const char *destination, __u64 max)
{
	struct image_download download = { .limit = max };
	int fd, rc;

	fd = open(destination,
		  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0)
		return -errno;
	download.fd = fd;
	rc = fsetxattr(fd, SHIRUDO_XATTR_NAME, SHIRUDO_SEAL_LABEL,
		       strlen(SHIRUDO_SEAL_LABEL), 0) ? -errno : 0;
	if (!rc)
		rc = !strncmp(source, "https://", 8) ?
			download_https(source, &download) :
			copy_local(source, &download);
	if (!rc && fsync(fd))
		rc = -errno;
	close(fd);
	return rc;
}

/* Verify downloads before publishing their root-hash-named cache files. */
static int verify_incoming(const struct shirudo_config_image_open *opened,
			   const char *staging)
{
	struct shirudo_dm_verity device = {
		.data_loop_fd = -1,
		.hash_loop_fd = -1,
	};
	int rc, cleanup;
	char name[128];

	snprintf(name, sizeof(name), "shirudo-verify-%s",
		 strrchr(staging, '/') + 1);
	rc = shirudo_dm_verity_create(opened, name, &device);
	if (rc)
		return rc;
	rc = shirudo_dm_verity_verify(&device, opened);
	cleanup = shirudo_dm_verity_remove(&device, true);
	if (cleanup)
		pr_warn("image: cannot remove incoming mapping: %s",
			strerror(-cleanup));
	shirudo_dm_verity_close(&device);
	return rc ? rc : cleanup;
}

int shirudo_image_cache_fetch(const char *source,
			      struct shirudo_config_update_target *target)
{
	static const struct {
		const char *suffix;
		__u64 max_bytes;
	} files[] = {
		{ ".roothash", 65 },
		{ ".p7s", SHIRUDO_CONFIG_IMAGE_SIG_MAX },
		{ ".img", SHIRUDO_CONFIG_IMAGE_MAX_BYTES },
		{ ".verity", SHIRUDO_CONFIG_IMAGE_MAX_BYTES },
	};
	struct shirudo_config_image_open opened;
	char staging[] = SHIRUDO_IMAGE_CACHE_DIR "/incoming-XXXXXX";
	char incoming[PATH_MAX], from[PATH_MAX], to[PATH_MAX];
	char hex[65];
	int dir = -1, rc;
	size_t i;

	if (!mkdtemp(staging))
		return -errno;
	rc = seal_label(staging);
	if (rc)
		goto out;
	snprintf(incoming, sizeof(incoming), "%s/image", staging);
	for (i = 0; i < ARRAY_SIZE(files); i++) {
		if (snprintf(from, sizeof(from), "%s%s", source,
			     files[i].suffix) >= (int)sizeof(from) ||
		    snprintf(to, sizeof(to), "%s%s", incoming,
			     files[i].suffix) >=
			    (int)sizeof(to)) {
			rc = -ENAMETOOLONG;
			goto out;
		}
		rc = fetch_file(from, to, files[i].max_bytes);
		if (rc)
			goto out;
	}
	rc = shirudo_config_image_open(incoming, &opened);
	if (rc)
		goto out;
	rc = verify_incoming(&opened, staging);
	if (!rc) {
		memcpy(target->root_hash, opened.image.root_hash, 32);
		hex_encode(target->root_hash, 32, hex);
		snprintf(target->prefix, sizeof(target->prefix), "%s/%s",
			 SHIRUDO_IMAGE_CACHE_DIR, hex);
	}
	shirudo_config_image_close(&opened);
	if (rc)
		goto out;
	for (i = 0; i < ARRAY_SIZE(files); i++) {
		snprintf(from, sizeof(from), "%s%s", incoming, files[i].suffix);
		snprintf(to, sizeof(to), "%s%s", target->prefix,
			 files[i].suffix);
		if (link(from, to) && errno != EEXIST) {
			rc = -errno;
			goto out;
		}
	}
	dir = open(SHIRUDO_IMAGE_CACHE_DIR,
		   O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (dir < 0 || fsync(dir)) {
		rc = -errno;
		goto out;
	}
	rc = shirudo_config_image_open(target->prefix, &opened);
	if (!rc) {
		if (memcmp(opened.image.root_hash, target->root_hash, 32))
			rc = -EKEYREJECTED;
		shirudo_config_image_close(&opened);
	}
out:
	if (dir >= 0)
		close(dir);
	for (i = 0; i < ARRAY_SIZE(files); i++) {
		snprintf(to, sizeof(to), "%s/image%s", staging,
			 files[i].suffix);
		unlink(to);
	}
	rmdir(staging);
	return rc;
}
