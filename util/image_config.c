// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "image_config.h"
#include "malloc.h"

static const char *const relative[SHIRUDO_IMAGE_PATH_COUNT] = {
	[SHIRUDO_IMAGE_ETC] = "etc/shirudo/bpm",
	[SHIRUDO_IMAGE_REGISTRIES] = "etc/shirudo/bpm/registries.d",
	[SHIRUDO_IMAGE_REPOSITORY_KEYS] = "etc/shirudo/bpm/keys",
	[SHIRUDO_IMAGE_TREE_CONF] = "etc/shirudo/bpm/upatch-tree.conf",
	[SHIRUDO_IMAGE_NODE_LABELS] = "etc/shirudo/node.labels",
	[SHIRUDO_IMAGE_TRUSTED_KEYS] = "keys/trusted",
	[SHIRUDO_IMAGE_REVOKED_KEYS] = "keys/revoked",
};

static char paths[SHIRUDO_IMAGE_PATH_COUNT][PATH_MAX];
static struct shirudo_config effective;
static bool active;
static int config_fd = -1;

bool shirudo_image_config_active(void)
{
	return active;
}

int shirudo_image_config_get(struct shirudo_config *out)
{
	if (!active)
		return 0;
	*out = effective;
	return 1;
}

int shirudo_image_config_root_fd(void)
{
	return config_fd;
}

const char *shirudo_image_path(enum shirudo_image_path which)
{
	if (which >= SHIRUDO_IMAGE_PATH_COUNT || config_fd < 0)
		return NULL;
	return paths[which];
}

int shirudo_image_path_relative(char *out, __u64 cap, const char *path)
{
	int n;

	if (config_fd < 0 || !path || path[0] == '/' || strstr(path, ".."))
		return -EINVAL;
	n = snprintf(out, cap, "/proc/self/fd/%d/%s", config_fd, path);
	return n < 0 || (__u64)n >= cap ? -ENAMETOOLONG : 0;
}

static int validate_tree(int root_fd, dev_t device, __u32 depth,
			 __u32 *entries)
{
	struct dirent *entry;
	struct stat st;
	DIR *dir;
	int fd, rc = 0;

	if (depth > 32)
		return -ELOOP;
	fd = openat(root_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	dir = fdopendir(fd);
	if (!dir) {
		rc = -errno;
		close(fd);
		return rc;
	}
	errno = 0;
	while ((entry = readdir(dir)) != NULL) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;
		if (++*entries > 65536) {
			rc = -E2BIG;
			break;
		}
		if (fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
			rc = -errno;
			break;
		}
		if (st.st_dev != device ||
		    (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))) {
			rc = -EPERM;
			break;
		}
		if (S_ISDIR(st.st_mode)) {
			int child = openat(fd, entry->d_name,
					   O_RDONLY | O_DIRECTORY | O_CLOEXEC |
						   O_NOFOLLOW);

			if (child < 0) {
				rc = -errno;
				break;
			}
			rc = validate_tree(child, device, depth + 1, entries);
			close(child);
			if (rc)
				break;
		}
		errno = 0;
	}
	if (!entry && errno && !rc)
		rc = -errno;
	closedir(dir);
	return rc;
}

static int validate_settings(int root_fd)
{
	char *line = NULL;
	size_t capacity = 0;
	FILE *file;
	ssize_t length;
	int fd, rc = 0;

	fd = openat(root_fd, "etc/shirudo/shirudo.conf",
		    O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -errno;
	file = fdopen(fd, "r");
	if (!file) {
		rc = -errno;
		close(fd);
		return rc;
	}
	while ((length = getline(&line, &capacity, file)) >= 0) {
		char *p = line, *end, *value;

		if (length > 1023 || strlen(line) != (size_t)length) {
			rc = -E2BIG;
			break;
		}
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '#' || *p == '\n' || !*p)
			continue;
		value = strchr(p, '=');
		if (!value) {
			rc = -EINVAL;
			break;
		}
		*value++ = 0;
		end = p + strlen(p);
		while (end > p && (end[-1] == ' ' || end[-1] == '\t'))
			end--;
		*end = 0;
		if (!strcmp(p, "eventlog.max_bytes")) {
			__u64 bytes;

			while (*value == ' ' || *value == '\t')
				value++;
			end = value + strlen(value);
			while (end > value && (end[-1] == ' ' ||
					       end[-1] == '\t' || end[-1] == '\r' ||
			       end[-1] == '\n'))
				end--;
			if (parse_u64(value, end - value, ~0ULL, &bytes)) {
				rc = -EINVAL;
				break;
			}
		} else if (strncmp(p, "map_export.", 11)) {
			rc = -EPERM;
			break;
		}
	}
	if (ferror(file) && !rc)
		rc = -EIO;
	libc_free(line);
	fclose(file);
	return rc;
}

int shirudo_image_config_validate(int root_fd)
{
	struct shirudo_config candidate;
	__u32 entries = 0;
	char path[64];
	struct stat st;
	int rc;

	if (fstat(root_fd, &st))
		return -errno;
	if (!S_ISDIR(st.st_mode))
		return -ENOTDIR;
	rc = validate_tree(root_fd, st.st_dev, 0, &entries);
	if (!rc)
		rc = validate_settings(root_fd);
	if (!rc) {
		snprintf(path, sizeof(path),
			 "/proc/self/fd/%d/etc/shirudo/shirudo.conf", root_fd);
		rc = config_load_path(&candidate, path);
		if (!rc && !candidate.map_export_valid)
			rc = -EINVAL;
		explicit_bzero(&candidate, sizeof(candidate));
	}
	return rc;
}

int shirudo_image_config_set(const struct shirudo_config *bootstrap,
			     int root_fd)
{
	struct shirudo_config candidate;
	char path[PATH_MAX];
	int fd = -1, rc;
	__u32 i;

	candidate = *bootstrap;
	if (root_fd >= 0) {
		rc = shirudo_image_config_validate(root_fd);
		if (rc)
			return rc;
		fd = fcntl(root_fd, F_DUPFD_CLOEXEC, 3);
		if (fd < 0)
			return -errno;
		snprintf(path, sizeof(path),
			 "/proc/self/fd/%d/etc/shirudo/shirudo.conf", fd);
		rc = config_load_path(&candidate, path);
		if (rc || !candidate.map_export_valid) {
			close(fd);
			return rc ? rc : -EINVAL;
		}
		memcpy(candidate.tpm_owner_auth, bootstrap->tpm_owner_auth,
		       sizeof(candidate.tpm_owner_auth));
		candidate.tpm_owner_auth_len = bootstrap->tpm_owner_auth_len;
		memcpy(candidate.tpm_tcti, bootstrap->tpm_tcti,
		       sizeof(candidate.tpm_tcti));
	}
	if (config_fd >= 0)
		close(config_fd);
	config_fd = fd;
	effective = candidate;
	active = true;
	for (i = 0; i < SHIRUDO_IMAGE_PATH_COUNT; i++)
		snprintf(paths[i], sizeof(paths[i]), "/proc/self/fd/%d/%s",
			 config_fd, relative[i]);
	return 0;
}

void shirudo_image_config_clear(void)
{
	if (config_fd >= 0)
		close(config_fd);
	config_fd = -1;
	active = false;
	explicit_bzero(&effective, sizeof(effective));
	memset(paths, 0, sizeof(paths));
}
