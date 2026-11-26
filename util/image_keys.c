// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "hex.h"
#include "image_keys.h"
#include "image_config.h"
#include "keyring.h"
#include "keys.h"
#include "log.h"
#include "malloc.h"
#include "paths.h"

static int revocations(int root_fd, bool apply, bool boot, size_t *records)
{
	struct dirent *entry;
	struct stat root, st;
	int keys_fd, dir_fd, err, ret = 0;
	DIR *dir;

	if (fstat(root_fd, &root))
		return -errno;
	keys_fd = openat(root_fd, "keys",
			 O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (keys_fd < 0)
		return errno == ENOENT ? 0 : -errno;
	dir_fd = openat(keys_fd, "revoked",
			O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	err = dir_fd < 0 ? errno : 0;
	close(keys_fd);
	if (dir_fd < 0)
		return err == ENOENT ? 0 : -err;
	dir = fdopendir(dir_fd);
	if (!dir) {
		ret = -errno;
		close(dir_fd);
		return ret;
	}
	errno = 0;
	while ((entry = readdir(dir)) != NULL) {
		__u8 *der = NULL;
		__u8 digest[32], fingerprint[32], expected[32];
		char canonical[69], name[65];
		size_t size = 0;
		int fd;

		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;
		if (strlen(entry->d_name) != 68 ||
		    strcmp(entry->d_name + 64, ".der")) {
			ret = -EINVAL;
			break;
		}
		memcpy(name, entry->d_name, 64);
		name[64] = 0;
		ret = hex_decode(name, expected, 32);
		if (ret)
			break;
		hex_encode(expected, 32, canonical);
		memcpy(canonical + 64, ".der", 5);
		if (strcmp(canonical, entry->d_name)) {
			ret = -EINVAL;
			break;
		}
		fd = openat(dir_fd, entry->d_name,
			    O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
		if (fd < 0) {
			ret = -errno;
			break;
		}
		ret = fstat(fd, &st) ? -errno : 0;
		if (!ret && (!S_ISREG(st.st_mode) || st.st_dev != root.st_dev ||
			     st.st_size <= 0 ||
			     st.st_size > KEYS_DER_MAX))
			ret = -EINVAL;
		if (!ret)
			ret = keys_read_der_fd(fd, &der, &size);
		close(fd);
		if (!ret)
			ret = keys_digest_der(der, size, digest,
					      fingerprint);
		if (!ret && memcmp(expected, fingerprint, 32))
			ret = -EKEYREJECTED;
		if (!ret && apply)
			ret = keys_revoke_image(der, size, boot);
		if (!ret)
			(*records)++;
		xfree(der, size);
		if (ret)
			break;
		errno = 0;
	}
	if (!entry && errno && !ret)
		ret = -errno;
	closedir(dir);
	return ret;
}

int keys_validate_image_set(const char *primary, int root_fd,
			    struct trusted_set *set)
{
	size_t records = 0;
	int ret;

	ret = image_config_validate(root_fd);
	if (ret) {
		pr_err("image trust set: validate config image: %s",
		       strerror(-ret));
		return ret;
	}
	ret = revocations(root_fd, false, false, &records);
	if (ret) {
		pr_err("image trust set: validate revocations: %s",
		       strerror(-ret));
		return ret;
	}
	ret = keys_load_image_root(primary, root_fd, true, set);
	if (ret) {
		pr_err("image trust set: load certificates: %s",
		       strerror(-ret));
		return ret;
	}
	if (!set->n || set->n_unvouched) {
		pr_err("image trust set: reject set with %zu certificates and %zu unvouched",
		       set->n, set->n_unvouched);
		return -EKEYREJECTED;
	}
	return 0;
}

int keys_check_image_set(const struct trusted_set *set)
{
	key_serial_t keyring;
	size_t i;
	int ret;

	keyring = keyring_bpf_serial();
	if (keyring < 0)
		return keyring;
	for (i = 0; i < set->n; i++) {
		const __u8 *der = NULL;
		size_t size = 0;

		ret = keys_cert_der(&set->certs[i], &der, &size);
		if (ret)
			return ret;
		ret = keyring_holds_cert(keyring, der, size);
		if (ret != 1)
			return ret < 0 ? ret : -ENOKEY;
	}
	return 0;
}

int keys_validate_image(int root_fd)
{
	struct trusted_set set;
	int ret;

	ret = keys_validate_image_set(RUNTIME_CERT_PATH,
				      root_fd, &set);
	return ret ? ret : keys_check_image_set(&set);
}

int keys_check_image_purge(int root_fd)
{
	size_t records = 0;
	int ret;

	ret = revocations(root_fd, false, false, &records);
	if (ret || !records)
		return ret;
	return keys_revoke_check();
}

int keys_apply_image(int root_fd, bool boot)
{
	size_t records = 0;
	int ret;

	ret = keys_validate_image(root_fd);
	if (!ret && !boot)
		ret = keys_check_image_purge(root_fd);
	return ret ? ret : revocations(root_fd, true, boot, &records);
}
