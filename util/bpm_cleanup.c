// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <shirudo/string.h>

#include "bpm_cleanup.h"
#include "bpm_package.h"
#include "bpm_state.h"
#include "log.h"
#include "malloc.h"
#include "seal.h"
#include "upatch.h"

static int remove_package_entry(int parent, const char *name, __u32 depth);

static int empty_package_dir(DIR *dir, __u32 depth, bool directives)
{
	struct dirent *entry;
	int ret;

	for (;;) {
		errno = 0;
		entry = readdir(dir);
		if (!entry)
			return -errno;
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;
		if ((bpm_upatch_member(entry->d_name, strlen(entry->d_name)) ==
		     BPM_UPATCH_UNLOAD) != directives)
			continue;
		ret = remove_package_entry(dirfd(dir), entry->d_name, depth + 1);
		if (ret && ret != -ENOENT)
			return ret;
	}
}

/* Takes ownership of fd, also on failure. */
static int remove_open_dir(int parent, const char *name, int fd, __u32 depth)
{
	DIR *dir;
	int ret;

	dir = fdopendir(fd);
	if (!dir) {
		ret = -errno;
		close(fd);
		return ret;
	}
	ret = empty_package_dir(dir, depth, false);
	if (!ret) {
		/* A stop with a load member left must leave its directive too. */
		rewinddir(dir);
		ret = empty_package_dir(dir, depth, true);
	}
	if (!ret && unlinkat(parent, name, AT_REMOVEDIR))
		ret = -errno;
	closedir(dir);
	return ret;
}

static int remove_package_entry(int parent, const char *name, __u32 depth)
{
	int fd;

	/* A ustar member's path fits in 256 bytes. */
	if (depth > 256)
		return -ENAMETOOLONG;
	fd = seal_open_child(parent, name, O_RDONLY | O_DIRECTORY);
	if (fd == -ENOTDIR && depth)
		return unlinkat(parent, name, 0) ? -errno : 0;
	if (fd < 0)
		return fd;
	return remove_open_dir(parent, name, fd, depth);
}

int bpm_pkg_remove_at(int parent, const char *name)
{
	return remove_package_entry(parent, name, 0);
}

struct package_directive {
	char path[PATH_MAX];
	int fd;
};

static int directive_compare_desc(const void *left, const void *right)
{
	const struct package_directive *a = left, *b = right;

	return strcmp(b->path, a->path);
}

static int check_unpaired_load(int dir, const char *name)
{
	char pair[NAME_MAX + 1];
	int fd, ret;

	ret = bpm_upatch_pair(name, strlen(name), pair, sizeof(pair));
	if (ret)
		return ret;
	fd = seal_open_child(dir, pair, O_RDONLY | O_NONBLOCK);
	if (fd >= 0) {
		close(fd);
		return 0;
	}
	if (fd != -ENOENT)
		return fd;
	fd = seal_open_child(dir, name, O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return fd;
	ret = upatch_member_active_fd(fd);
	close(fd);
	if (ret > 0) {
		pr_err("bpm uninstall: active %s is missing %s", name, pair);
		return -ENODATA;
	}
	return ret;
}

/* Keep the files we checked open through signature verification. */
static int open_directives(DIR *dir, const char *version_path,
			   struct package_directive *unloads, size_t *count)
{
	struct dirent *entry;
	struct package_directive *u;
	struct stat st;
	enum bpm_upatch_member kind;
	int ret;

	for (;;) {
		errno = 0;
		entry = readdir(dir);
		if (!entry)
			return -errno;
		kind = bpm_upatch_member(entry->d_name, strlen(entry->d_name));
		if (kind == BPM_UPATCH_LOAD) {
			ret = check_unpaired_load(dirfd(dir), entry->d_name);
			if (ret)
				return ret;
		}
		if (kind != BPM_UPATCH_UNLOAD)
			continue;
		if (*count == BPM_MAX_UPATCHES)
			return -E2BIG;
		u = &unloads[*count];
		if (strsprintf(u->path, sizeof(u->path), "%s/upatches/%s",
			       version_path, entry->d_name) < 0)
			return -ENAMETOOLONG;
		u->fd = seal_open_child(dirfd(dir), entry->d_name, O_RDONLY | O_NONBLOCK);
		if (u->fd < 0)
			return u->fd;
		(*count)++;
		if (fstat(u->fd, &st))
			return -errno;
		if (!S_ISREG(st.st_mode))
			return -EINVAL;
	}
}

static int unload_version(int version, const char *path)
{
	struct package_directive *unloads;
	size_t count = 0, i;
	int fd, ret;
	DIR *dir;

	fd = seal_open_child(version, "upatches", O_RDONLY | O_DIRECTORY);
	if (fd < 0)
		return fd == -ENOENT ? 0 : fd;
	dir = fdopendir(fd);
	if (!dir) {
		ret = -errno;
		close(fd);
		return ret;
	}
	unloads = xcalloc(BPM_MAX_UPATCHES, sizeof(*unloads));
	if (!unloads) {
		closedir(dir);
		return -ENOMEM;
	}
	ret = open_directives(dir, path, unloads, &count);
	closedir(dir);
	if (!ret) {
		qsort(unloads, count, sizeof(*unloads), directive_compare_desc);
		for (i = 0; i < count; i++) {
			if (upatch_remove_fd(unloads[i].path, unloads[i].fd)) {
				pr_err("bpm uninstall: unload %s failed", unloads[i].path);
				ret = -EIO;
				break;
			}
		}
	}
	for (i = 0; i < count; i++)
		close(unloads[i].fd);
	xfree(unloads, BPM_MAX_UPATCHES * sizeof(*unloads));
	return ret;
}

int bpm_uninstall_at(int store, const struct bpm_state_entry *st)
{
	int package, version, ret = 0;

	if (!bpm_name_ok(st->name) || !bpm_version_ok(st->version))
		return -EINVAL;
	package = seal_open_child(store, st->name, O_RDONLY | O_DIRECTORY);
	if (package < 0)
		return package == -ENOENT ? 0 : package;
	version = seal_open_child(package, st->version, O_RDONLY | O_DIRECTORY);
	if (version >= 0) {
		ret = unload_version(version, st->path);
		close(version);
	} else if (version != -ENOENT) {
		ret = version;
	}
	/* Upgrade keeps older versions and their archives in this directory. */
	if (!ret)
		ret = remove_open_dir(store, st->name, package, 0);
	else
		close(package);
	return ret;
}
