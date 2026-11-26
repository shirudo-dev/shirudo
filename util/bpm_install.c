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

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "bpm_cleanup.h"
#include "bpm_install.h"
#include "bpm_package.h"
#include "log.h"
#include "malloc.h"
#include "paths.h"
#include "seal.h"
#include "upatch.h"

/* One load member or one directive of a version. */
struct member {
	char		name[NAME_MAX + 1];
};

/* The upatches directory of one version of a package, -1 when it has none. */
struct upatches {
	int		dir;
	const char	*package;
	const char	*version;
};

static void close_fd(int *fd)
{
	if (*fd >= 0)
		close(*fd);
	*fd = -1;
}

/* bpm/<name> below the state root, each made when it is not there. */
static int bpm_dir(int root, const char *name)
{
	int bpm, fd;

	bpm = seal_mkdir_child(root, "bpm", 0700, false);
	if (bpm < 0)
		return bpm;
	fd = seal_mkdir_child(bpm, name, 0700, false);
	close(bpm);
	return fd;
}

int bpm_install_open(struct bpm_install *in, int root, const char *name,
		     const char *version)
{
	int store;

	*in = (struct bpm_install){
		.name = name, .version = version,
		.staging = -1, .package = -1, .dir = -1, .archive = -1,
	};
	if (!bpm_name_ok(name) || !bpm_version_ok(version))
		return -EINVAL;
	if (strsprintf(in->archive_name, sizeof(in->archive_name), "%s-%s.bee",
		       name, version) < 0)
		return -ENAMETOOLONG;
	store = bpm_dir(root, "packages");
	if (store < 0)
		return store;
	in->package = seal_mkdir_child(store, name, 0700, false);
	close(store);
	if (in->package < 0)
		return in->package;
	in->staging = bpm_dir(root, "staging");
	if (in->staging < 0)
		return in->staging;
	in->archive = seal_create_child(in->staging, in->archive_name,
					O_RDWR | O_CREAT | O_TRUNC, 0600);
	return min(in->archive, 0);
}

int bpm_install_extract(struct bpm_install *in)
{
	in->dir = seal_mkdir_child(in->package, in->version, 0700, true);
	if (in->dir < 0)
		return in->dir;
	in->extracted = true;
	return bpm_pkg_extract(in->archive, in->dir);
}

int bpm_install_member(const struct bpm_install *in, const char *name)
{
	return seal_open_child(in->dir, name, O_RDONLY | O_NONBLOCK);
}

static int member_compare(const void *left, const void *right)
{
	const struct member *a = left, *b = right;

	return strcmp(a->name, b->name);
}

/* The members of kind in the directory open as updir, in name order. */
static int list_members(int updir, enum bpm_upatch_member kind,
			struct member *names, int *count)
{
	struct dirent *entry;
	int fd, n = 0, ret;
	struct stat st;
	DIR *dir;

	fd = fcntl(updir, F_DUPFD_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	dir = fdopendir(fd);
	if (!dir) {
		ret = -errno;
		close(fd);
		return ret;
	}
	rewinddir(dir);
	for (;;) {
		errno = 0;
		entry = readdir(dir);
		if (!entry) {
			ret = -errno;
			break;
		}
		if (bpm_upatch_member(entry->d_name, strlen(entry->d_name)) != kind)
			continue;
		/* A load is a regular file; a directive is opened to see. */
		if (kind == BPM_UPATCH_LOAD &&
		    (fstatat(updir, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) ||
		     !S_ISREG(st.st_mode)))
			continue;
		if (n == BPM_MAX_UPATCHES) {
			ret = -E2BIG;
			break;
		}
		if (strscpy(names[n].name, entry->d_name,
			    sizeof(names[n].name)) < 0) {
			ret = -ENAMETOOLONG;
			break;
		}
		n++;
	}
	closedir(dir);
	if (ret)
		return ret;
	qsort(names, (size_t)n, sizeof(names[0]), member_compare);
	*count = n;
	return 0;
}

/*
 * Load or unload one member, read through the directory held open. 0,
 * -errno for a member that is not shirudo's own to read, or -EIO for
 * one the load or the unload refused.
 */
static int member_apply(const struct upatches *u, const char *name, bool load)
{
	char path[PATH_MAX];
	struct stat st;
	int fd, ret;

	if (strsprintf(path, sizeof(path), "%s/%s/%s/upatches/%s",
		       BPM_PACKAGES_DIR, u->package, u->version, name) < 0)
		return -ENAMETOOLONG;
	fd = seal_open_child(u->dir, name, O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return fd;
	if (fstat(fd, &st))
		ret = -errno;
	else if (!S_ISREG(st.st_mode))
		ret = -EINVAL;
	else if (load ? upatch_install_fd(path, fd) : upatch_remove_fd(path, fd))
		ret = -EIO;
	else
		ret = 0;
	close(fd);
	return ret;
}

/* The same for the member name is paired with: its directive, or its load. */
static int pair_apply(const struct upatches *u, const char *name, bool load)
{
	char pair[NAME_MAX + 1];

	if (bpm_upatch_pair(name, strlen(name), pair, sizeof(pair)))
		return -EINVAL;
	return member_apply(u, pair, load);
}

/* The upatches directory of an older version, left at -1 when it has none. */
static int open_old(const struct bpm_install *in, struct upatches *old)
{
	int version, fd;

	version = seal_open_child(in->package, old->version,
				  O_RDONLY | O_DIRECTORY);
	if (version == -ENOENT)
		return 0;
	if (version < 0)
		return version;
	fd = seal_open_child(version, "upatches", O_RDONLY | O_DIRECTORY);
	close(version);
	if (fd == -ENOENT)
		return 0;
	if (fd < 0)
		return fd;
	old->dir = fd;
	return 0;
}

int bpm_install_load(const struct bpm_install *in, const char *old_version)
{
	struct upatches new = { -1, in->name, in->version };
	struct upatches old = { -1, in->name, old_version };
	int nloads = 0, nunloads = 0, nactive, i, ret;
	struct member *loads, *unloads;

	loads = xcalloc(2 * BPM_MAX_UPATCHES, sizeof(*loads));
	if (!loads)
		return -ENOMEM;
	unloads = loads + BPM_MAX_UPATCHES;
	new.dir = seal_open_child(in->dir, "upatches", O_RDONLY | O_DIRECTORY);
	ret = new.dir < 0 ? new.dir :
	      list_members(new.dir, BPM_UPATCH_LOAD, loads, &nloads);
	if (!ret && !nloads)
		ret = -EINVAL;
	if (!ret && old_version && *old_version)
		ret = open_old(in, &old);
	if (!ret && old.dir >= 0)
		ret = list_members(old.dir, BPM_UPATCH_UNLOAD, unloads,
				   &nunloads);
	if (ret)
		goto out;
	/* Reverse name order, as uninstall runs the directives. */
	for (i = nunloads; i > 0; i--) {
		ret = member_apply(&old, unloads[i - 1].name, false);
		if (ret)
			goto restore;
	}
	for (nactive = 0; nactive < nloads; nactive++) {
		ret = member_apply(&new, loads[nactive].name, true);
		if (ret)
			break;
	}
	if (!ret)
		goto out;
	while (nactive--)
		pair_apply(&new, loads[nactive].name, false);
restore:
	/* From the first directive that ran, or with i at 0 all of them. */
	for (; i < nunloads; i++)
		pair_apply(&old, unloads[i].name, true);
out:
	close_fd(&new.dir);
	close_fd(&old.dir);
	xfree(loads, 2 * BPM_MAX_UPATCHES * sizeof(*loads));
	return ret;
}

int bpm_install_close(struct bpm_install *in, int err)
{
	int ret;

	if (!err && renameat(in->staging, in->archive_name, in->package,
			     in->archive_name)) {
		pr_warn("bpm: cannot keep %s/%s; dropping it", BPM_STAGING_DIR,
			in->archive_name);
		unlinkat(in->staging, in->archive_name, 0);
	}
	if (err && in->archive >= 0)
		unlinkat(in->staging, in->archive_name, 0);
	/* What failed to install must not block the next attempt. */
	if (err && in->extracted) {
		ret = bpm_pkg_remove_at(in->package, in->version);
		if (ret && ret != -ENOENT)
			pr_warn("bpm install: could not clean up %s/%s/%s: %s",
				BPM_PACKAGES_DIR, in->name, in->version,
				strerror(-ret));
	}
	close_fd(&in->archive);
	close_fd(&in->dir);
	close_fd(&in->package);
	close_fd(&in->staging);
	return err;
}
