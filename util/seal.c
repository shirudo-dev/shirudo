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

#include "io.h"
#include "log.h"
#include "paths.h"
#include "seal.h"

#define SEAL_LABEL_LEN	(sizeof(SEAL_LABEL) - 1)

int seal_label(const char *path)
{
	if (lsetxattr(path, XATTR_NAME, SEAL_LABEL,
		      sizeof(SEAL_LABEL) - 1, 0) != 0)
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
static bool seal_first_init;

static ssize_t seal_lget(const char *path, char label[SEAL_LABEL_LEN]);

/*
 * The first init labels what the install left; from then on everything
 * shirudo makes is labelled as it is made, so an entry without the label,
 * or one of a kind shirudo never makes, came from someone else: it is
 * left alone, never labelled, followed or read as shirudo's own.
 */
static int seal_label_cb(const char *path, const struct stat *sb,
			 int typeflag __attribute__((__unused__)),
			 struct FTW *ftwbuf __attribute__((__unused__)))
{
	char label[SEAL_LABEL_LEN];
	int ret;

	/*
	 * Belt-and-suspenders with FTW_MOUNT: never label an inode on a
	 * different filesystem (the bpffs mount), which is bpf2's domain
	 * and uses a different xattr. Labelling it would make seal contend
	 * for those inodes.
	 */
	if (sb->st_dev != seal_root_dev)
		return 0;
	if (!S_ISREG(sb->st_mode) && !S_ISDIR(sb->st_mode)) {
		pr_warn("seal: %s is not a file or directory of shirudo's "
			"(foreign entry); ignored", path);
		return 0;
	}
	if (!seal_first_init) {
		if (seal_lget(path, label) <= 0)
			pr_warn("seal: %s carries no label (foreign entry); "
				"ignored", path);
		return 0;
	}
	ret = seal_label(path);
	if (ret) {
		pr_err("seal: label %s: %s", path, strerror(-ret));
		seal_walk_error = ret;
		return 1;
	}
	return 0;
}

/*
 * The first labelling is the bootstrap's alone, before enforcement is
 * live: with the hooks attached, a state root without the label is not
 * the one init sealed but a tree bound over its path, in a mount
 * namespace of root's say, and labelling it would hand root inodes the
 * seal takes for shirudo's own.
 */
int seal_label_tree(bool allow_first)
{
	char label[SEAL_LABEL_LEN];
	struct stat st;

	if (stat(VAR_LIB, &st) != 0)
		return -errno;
	seal_root_dev = st.st_dev;
	seal_walk_error = 0;
	seal_first_init = seal_lget(VAR_LIB, label) <= 0;
	if (seal_first_init && !allow_first) {
		pr_err("seal: %s carries no label with enforcement live "
		       "(foreign state tree); refusing", VAR_LIB);
		return -EPERM;
	}
	if (nftw(VAR_LIB, seal_label_cb, 16, FTW_PHYS | FTW_MOUNT) != 0)
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
	return seal_label_len(fgetxattr(fd, XATTR_NAME, label,
					SEAL_LABEL_LEN));
}

static ssize_t seal_lget(const char *path, char label[SEAL_LABEL_LEN])
{
	return seal_label_len(lgetxattr(path, XATTR_NAME, label,
					SEAL_LABEL_LEN));
}

/*
 * Whether the inode behind fd is of the directory open as dfd: under a
 * labelled directory an entry must carry the same label, so a file or
 * directory someone renamed or linked in, or made while the seal could
 * not label it, is refused rather than taken for shirudo's own. 0 when
 * it is, or the directory carries no label, -EPERM when it is not.
 */
static int seal_same(int dfd, int fd)
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
	return -EPERM;
}

/*
 * Open a directory by walking its components, following no symbolic
 * link and taking no foreign entry for shirudo's own; with create, make
 * what is missing, labelled as its parent is.
 */
static int seal_open_dir(const char *path, bool create, mode_t mode)
{
	char buf[PATH_MAX], *comp, *save;
	int dfd, nfd, ret = 0;
	bool created;

	if (strscpy(buf, path, sizeof(buf)) < 0)
		return -ENAMETOOLONG;
	dfd = open(buf[0] == '/' ? "/" : ".",
		   O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dfd < 0)
		return -errno;
	for (comp = strtok_r(buf, "/", &save); comp;
	     comp = strtok_r(NULL, "/", &save)) {
		created = create && mkdirat(dfd, comp, mode) == 0;
		if (create && !created && errno != EEXIST) {
			ret = -errno;
			break;
		}
		nfd = openat(dfd, comp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
			     O_CLOEXEC);
		if (nfd < 0) {
			ret = -errno;
			if (ret == -ELOOP || ret == -ENOTDIR)
				pr_err("%s: %s is not a directory of shirudo's "
				       "(foreign entry in sealed state)", path,
				       comp);
			break;
		}
		ret = created ? seal_inherit(dfd, nfd) : seal_same(dfd, nfd);
		if (ret == -EPERM)
			pr_err("%s: %s carries no label (foreign entry in "
			       "sealed state); refusing", path, comp);
		close(dfd);
		dfd = nfd;
		if (ret)
			break;
	}
	if (ret) {
		close(dfd);
		return ret;
	}
	return dfd;
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
		if (fd < 0)
			return -errno;
	} else {
		len = slash == path ? 1 : (size_t)(slash - path);
		if (len >= sizeof(dir))
			return -ENAMETOOLONG;
		memcpy(dir, path, len);
		dir[len] = '\0';
		*name = slash + 1;
		fd = seal_open_dir(dir, false, 0);
		if (fd < 0)
			return fd;
	}
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
	if (fsetxattr(fd, XATTR_NAME, parent, (size_t)plen, 0))
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
	if (lsetxattr(path, XATTR_NAME, parent, (size_t)plen, 0))
		return -errno;
	return 0;
}

/*
 * A FIFO planted in the tree before the seal was live would hold the
 * opener forever; the open does not wait, and what is not a regular
 * file is refused.
 */
static int seal_regular(int fd)
{
	struct stat st;

	if (fstat(fd, &st))
		return -errno;
	return S_ISREG(st.st_mode) ? 0 : -EINVAL;
}

/* 1 for a label of any size, 0 for none, -errno when unreadable. */
static int seal_fsealed(int fd)
{
	if (fgetxattr(fd, XATTR_NAME, NULL, 0) >= 0)
		return 1;
	return errno == ENODATA || errno == ENOTSUP ? 0 : -errno;
}

int seal_output_open(const char *path, int flags, mode_t mode)
{
	const char *name;
	struct stat st;
	int dfd, fd, ret;

	dfd = seal_open_parent(path, &name);
	if (dfd < 0)
		return dfd;
	ret = seal_fsealed(dfd);
	if (ret)
		goto out_dir;
	fd = openat(dfd, name, (flags & ~O_TRUNC) | O_NOFOLLOW | O_CLOEXEC,
		    mode);
	if (fd < 0) {
		ret = -errno;
		goto out_dir;
	}
	if (fstat(fd, &st)) {
		ret = -errno;
		goto out_fd;
	}
	if (!S_ISREG(st.st_mode)) {
		ret = -EINVAL;
		goto out_fd;
	}
	ret = seal_fsealed(fd);
	if (ret)
		goto out_fd;
	if ((flags & O_TRUNC) && ftruncate(fd, 0)) {
		ret = -errno;
		goto out_fd;
	}
	close(dfd);
	return fd;
out_fd:
	close(fd);
out_dir:
	close(dfd);
	if (ret > 0) {
		pr_err("%s: refusing to write sealed state", path);
		ret = -EPERM;
	}
	return ret;
}

int seal_open(const char *path, int flags, mode_t mode)
{
	const char *name;
	int dfd, fd, ret;

	dfd = seal_open_parent(path, &name);
	if (dfd < 0)
		return dfd;
	fd = openat(dfd, name, (flags & ~(O_CREAT | O_TRUNC)) | O_NOFOLLOW |
		    O_NONBLOCK | O_CLOEXEC, mode);
	if (fd >= 0) {
		if (flags & O_EXCL) {
			ret = -EEXIST;
		} else {
			ret = seal_regular(fd);
			if (!ret)
				ret = seal_same(dfd, fd);
			if (ret == -EPERM)
				pr_err("%s: carries no label (foreign entry "
				       "in sealed state); refusing", path);
			if (!ret && (flags & O_TRUNC) && ftruncate(fd, 0))
				ret = -errno;
		}
	} else if (errno == ENOENT && (flags & O_CREAT)) {
		fd = openat(dfd, name, flags | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
			    mode);
		ret = fd < 0 ? -errno : seal_inherit(dfd, fd);
	} else {
		ret = -errno;
		if (ret == -ELOOP)
			pr_err("%s: is a symbolic link (foreign entry in "
			       "sealed state); refusing", path);
	}
	close(dfd);
	if (ret) {
		if (fd >= 0)
			close(fd);
		return ret;
	}
	return fd;
}

int seal_open_read(const char *path)
{
	const char *name;
	int dfd, fd, ret;

	dfd = seal_open_parent(path, &name);
	if (dfd < 0)
		return dfd;
	fd = openat(dfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	ret = fd < 0 ? -errno : seal_regular(fd);
	if (!ret)
		ret = seal_same(dfd, fd);
	close(dfd);
	if (ret) {
		if (fd >= 0)
			close(fd);
		if (ret == -EPERM || ret == -ELOOP)
			pr_err("%s: not shirudo's own (foreign entry in sealed "
			       "state); refusing to read it", path);
		return ret;
	}
	return fd;
}

bool seal_owns(const char *path)
{
	int fd = seal_open_read(path);

	if (fd < 0)
		return false;
	close(fd);
	return true;
}

int seal_mkdir_p(const char *path, mode_t mode)
{
	int fd = seal_open_dir(path, true, mode);

	if (fd < 0)
		return fd;
	close(fd);
	return 0;
}

int seal_write_file(const char *path, const void *data, size_t len,
		    mode_t mode)
{
	char tmp[NAME_MAX + 1];
	const char *name;
	int dfd, fd, ret;

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
		ret = -errno;
		close(dfd);
		return ret;
	}
	ret = seal_inherit(dfd, fd);
	if (!ret)
		ret = write_complete(fd, data, len);
	if (!ret && fsync(fd))
		ret = -errno;
	if (close(fd) && !ret)
		ret = -errno;
	if (!ret && renameat(dfd, tmp, dfd, name))
		ret = -errno;
	if (!ret && fsync(dfd))
		ret = -errno;
	if (ret)
		unlinkat(dfd, tmp, 0);
	close(dfd);
	return ret;
}
