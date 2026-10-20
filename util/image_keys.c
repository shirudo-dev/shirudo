// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>

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
#include "malloc.h"
#include "paths.h"

static int revocations(int root_fd, bool apply, bool boot)
{
	struct dirent *entry;
	struct stat root, st;
	int keys_fd, dir_fd, rc = 0;
	DIR *dir;

	if (fstat(root_fd, &root))
		return -errno;
	keys_fd = openat(root_fd, "keys",
			 O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (keys_fd < 0)
		return errno == ENOENT ? 0 : -errno;
	dir_fd = openat(keys_fd, "revoked",
			O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	close(keys_fd);
	if (dir_fd < 0)
		return errno == ENOENT ? 0 : -errno;
	dir = fdopendir(dir_fd);
	if (!dir) {
		rc = -errno;
		close(dir_fd);
		return rc;
	}
	errno = 0;
	while ((entry = readdir(dir)) != NULL) {
		__u8 *der = NULL;
		__u8 digest[32], fingerprint[32], expected[32];
		char canonical[69], path[64], name[65];
		size_t size = 0;
		int fd;

		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;
		if (strlen(entry->d_name) != 68 ||
		    strcmp(entry->d_name + 64, ".der")) {
			rc = -EINVAL;
			break;
		}
		memcpy(name, entry->d_name, 64);
		name[64] = 0;
		rc = hex_decode(name, expected, 32);
		if (rc)
			break;
		hex_encode(expected, 32, canonical);
		memcpy(canonical + 64, ".der", 5);
		if (strcmp(canonical, entry->d_name)) {
			rc = -EINVAL;
			break;
		}
		fd = openat(dir_fd, entry->d_name,
			    O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
		if (fd < 0) {
			rc = -errno;
			break;
		}
		rc = fstat(fd, &st) ? -errno : 0;
		if (!rc && (!S_ISREG(st.st_mode) || st.st_dev != root.st_dev ||
			    st.st_size <= 0 ||
			    st.st_size > SHIRUDO_KEYS_DER_MAX))
			rc = -EINVAL;
		snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
		if (!rc)
			rc = keys_read_der(path, &der, &size);
		close(fd);
		if (!rc)
			rc = keys_digest_der(der, size, digest,
					     fingerprint);
		if (!rc && memcmp(expected, fingerprint, 32))
			rc = -EKEYREJECTED;
		if (!rc && apply)
			rc = shirudo_keys_revoke_image(der, size, boot);
		xfree(der, size);
		if (rc)
			break;
		errno = 0;
	}
	if (!entry && errno && !rc)
		rc = -errno;
	closedir(dir);
	return rc;
}

int shirudo_keys_validate_image_set(const char *primary, int root_fd,
				    struct shirudo_trusted_set *set)
{
	char keys[64], revoked[80];
	int rc;

	rc = shirudo_image_config_validate(root_fd);
	if (!rc)
		rc = revocations(root_fd, false, false);
	if (rc)
		return rc;
	snprintf(keys, sizeof(keys), "/proc/self/fd/%d/keys", root_fd);
	snprintf(revoked, sizeof(revoked), "%s/revoked", keys);
	rc = shirudo_keys_load_image(primary, keys, revoked, true, set);
	if (!rc && (!set->n || set->n_unvouched))
		rc = -EKEYREJECTED;
	return rc;
}

int shirudo_keys_check_image_set(const struct shirudo_trusted_set *set)
{
	key_serial_t keyring;
	size_t i;
	int rc;

	keyring = keyring_bpf_serial();
	if (keyring < 0)
		return keyring;
	for (i = 0; i < set->n; i++) {
		__u8 *der = NULL;
		size_t size = 0;

		rc = keys_read_der(set->certs[i].path, &der, &size);
		if (rc)
			return rc;
		rc = keyring_holds_cert(keyring, der, size);
		xfree(der, size);
		if (rc != 1)
			return rc < 0 ? rc : -ENOKEY;
	}
	return 0;
}

int shirudo_keys_validate_image(int root_fd)
{
	struct shirudo_trusted_set set;
	int rc;

	rc = shirudo_keys_validate_image_set(SHIRUDO_RUNTIME_CERT_PATH,
					     root_fd, &set);
	return rc ? rc : shirudo_keys_check_image_set(&set);
}

int shirudo_keys_apply_image(int root_fd, bool boot)
{
	int rc;

	rc = shirudo_keys_validate_image(root_fd);
	return rc ? rc : revocations(root_fd, true, boot);
}
