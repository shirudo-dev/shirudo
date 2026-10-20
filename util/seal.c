// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Inode labelling for the bpf/seal.c filesystem-sealing LSM.
 */

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <shirudo/string.h>

#include "image_config.h"
#include "io.h"
#include "log.h"
#include "paths.h"
#include "seal.h"

#define SEAL_LABEL_LEN	(sizeof(SHIRUDO_SEAL_LABEL) - 1)

int seal_label(const char *path)
{
	if (lsetxattr(path, SHIRUDO_XATTR_NAME, SHIRUDO_SEAL_LABEL,
		      sizeof(SHIRUDO_SEAL_LABEL) - 1, 0) != 0)
		return -errno;
	return 0;
}

/*
 * nftw is callback-only with no user pointer, so the root device is
 * passed via a file-scope variable -- shirudo init is single-threaded
 * and never walks two trees at once.
 */
static dev_t seal_root_dev;
static int seal_walk_error;

static int seal_label_cb(const char *path, const struct stat *sb,
			 int typeflag, struct FTW *ftwbuf)
{
	int rc;

	(void)typeflag;
	(void)ftwbuf;
	/*
	 * Belt-and-suspenders with FTW_MOUNT: never label an inode on a
	 * different filesystem (the bpffs mount), which is bpf2's domain
	 * and uses a different xattr. Labelling it would make seal contend
	 * for those inodes.
	 */
	if (sb->st_dev != seal_root_dev)
		return 0;
	if (shirudo_image_config_active() &&
	    !S_ISREG(sb->st_mode) && !S_ISDIR(sb->st_mode))
		rc = -EINVAL;
	else
		rc = seal_label(path);
	if (rc) {
		pr_warn("seal: label %s: %s", path, strerror(-rc));
		if (shirudo_image_config_active()) {
			seal_walk_error = rc;
			return 1;
		}
	}
	return 0;
}

int seal_label_tree(void)
{
	char self[PATH_MAX];
	struct stat st;
	ssize_t n;

	/* The ordinary-mode label protects the binary and marks its tasks. */
	n = shirudo_image_config_active() ? -1 :
		readlink("/proc/self/exe", self, sizeof(self) - 1);
	if (n > 0) {
		self[n] = '\0';
		if (seal_label(self) != 0)
			pr_warn("seal: label %s: %s", self, strerror(errno));
	}

	if (stat(SHIRUDO_VAR_LIB, &st) != 0)
		return -errno;
	seal_root_dev = st.st_dev;
	seal_walk_error = 0;
	if (nftw(SHIRUDO_VAR_LIB, seal_label_cb, 16, FTW_PHYS | FTW_MOUNT) != 0)
		return seal_walk_error ? seal_walk_error : -errno;
	return 0;
}

/*
 * The length of an inode's label, 0 when it carries none or one of
 * another size, which the seal takes for none, -errno for a failed read.
 */
static ssize_t seal_label_len(ssize_t n)
{
	if (n >= 0)
		return n == (ssize_t)SEAL_LABEL_LEN ? n : 0;
	if (errno == ENODATA || errno == ENOTSUP || errno == ERANGE)
		return 0;
	return -errno;
}

static ssize_t seal_fget(int fd, char label[SEAL_LABEL_LEN])
{
	return seal_label_len(fgetxattr(fd, SHIRUDO_XATTR_NAME, label,
					SEAL_LABEL_LEN));
}

static ssize_t seal_lget(const char *path, char label[SEAL_LABEL_LEN])
{
	return seal_label_len(lgetxattr(path, SHIRUDO_XATTR_NAME, label,
					SEAL_LABEL_LEN));
}

static int seal_open_parent(const char *path, const char **name)
{
	const char *slash = strrchr(path, '/');
	char dir[PATH_MAX];
	size_t len;
	int fd;

	if (!slash) {
		*name = path;
		fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	} else {
		len = slash == path ? 1 : (size_t)(slash - path);
		if (len >= sizeof(dir))
			return -ENAMETOOLONG;
		memcpy(dir, path, len);
		dir[len] = '\0';
		*name = slash + 1;
		fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	}
	if (fd < 0)
		return -errno;
	if (!**name) {
		close(fd);
		return -EINVAL;
	}
	return fd;
}

int seal_inherit(int dfd, int fd)
{
	char parent[SEAL_LABEL_LEN], own[SEAL_LABEL_LEN];
	ssize_t plen, olen;

	plen = seal_fget(dfd, parent);
	if (plen <= 0)
		return (int)plen;
	olen = seal_fget(fd, own);
	if (olen < 0)
		return (int)olen;
	if (olen == plen && !memcmp(parent, own, (size_t)plen))
		return 0;
	if (fsetxattr(fd, SHIRUDO_XATTR_NAME, parent, (size_t)plen, 0))
		return -errno;
	return 0;
}

int seal_inherit_path(const char *path)
{
	char parent[SEAL_LABEL_LEN], own[SEAL_LABEL_LEN];
	ssize_t plen, olen;
	const char *name;
	int dfd;

	dfd = seal_open_parent(path, &name);
	if (dfd < 0)
		return dfd;
	plen = seal_fget(dfd, parent);
	close(dfd);
	if (plen <= 0)
		return (int)plen;
	olen = seal_lget(path, own);
	if (olen < 0)
		return (int)olen;
	if (olen == plen && !memcmp(parent, own, (size_t)plen))
		return 0;
	if (lsetxattr(path, SHIRUDO_XATTR_NAME, parent, (size_t)plen, 0))
		return -errno;
	return 0;
}

int seal_open(const char *path, int flags, mode_t mode)
{
	const char *name;
	int dfd, fd, rc;

	dfd = seal_open_parent(path, &name);
	if (dfd < 0)
		return dfd;
	fd = openat(dfd, name, flags | O_CLOEXEC, mode);
	if (fd < 0) {
		rc = -errno;
		close(dfd);
		return rc;
	}
	rc = seal_inherit(dfd, fd);
	close(dfd);
	if (rc) {
		close(fd);
		return rc;
	}
	return fd;
}

int seal_mkdir_p(const char *path, mode_t mode)
{
	char buf[PATH_MAX], *comp, *save;
	int dfd, nfd, rc = 0;
	bool created;

	if (strscpy(buf, path, sizeof(buf)) < 0)
		return -ENAMETOOLONG;
	dfd = open(buf[0] == '/' ? "/" : ".",
		   O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dfd < 0)
		return -errno;
	for (comp = strtok_r(buf, "/", &save); comp;
	     comp = strtok_r(NULL, "/", &save)) {
		created = mkdirat(dfd, comp, mode) == 0;
		if (!created && errno != EEXIST) {
			rc = -errno;
			break;
		}
		nfd = openat(dfd, comp, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (nfd < 0) {
			rc = -errno;
			break;
		}
		if (created)
			rc = seal_inherit(dfd, nfd);
		close(dfd);
		dfd = nfd;
		if (rc)
			break;
	}
	close(dfd);
	return rc;
}

int seal_write_file(const char *path, const void *data, size_t len,
		    mode_t mode)
{
	char tmp[NAME_MAX + 1];
	const char *name;
	int dfd, fd, rc;

	dfd = seal_open_parent(path, &name);
	if (dfd < 0)
		return dfd;
	if (strsprintf(tmp, sizeof(tmp), "%s.tmp", name) < 0) {
		close(dfd);
		return -ENAMETOOLONG;
	}
	fd = openat(dfd, tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
		    O_NOFOLLOW, mode);
	if (fd < 0) {
		rc = -errno;
		close(dfd);
		return rc;
	}
	rc = seal_inherit(dfd, fd);
	if (!rc)
		rc = write_complete(fd, data, len);
	if (!rc && fsync(fd))
		rc = -errno;
	if (close(fd) && !rc)
		rc = -errno;
	if (!rc && renameat(dfd, tmp, dfd, name))
		rc = -errno;
	if (!rc && fsync(dfd))
		rc = -errno;
	if (rc)
		unlinkat(dfd, tmp, 0);
	close(dfd);
	return rc;
}
