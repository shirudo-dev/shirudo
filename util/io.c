// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <linux/magic.h>
#include <linux/openat2.h>

#include <shirudo/misc.h>

#include "io.h"
#include "log.h"
#include "malloc.h"
#include "paths.h"
#include "seal.h"

static bool under(const char *path, const char *dir);

int write_complete(int fd, const void *buf, size_t len)
{
	const __u8 *p = buf;

	while (len) {
		ssize_t n = write(fd, p, len);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (n == 0)
			return -EIO;
		p += (size_t)n;
		len -= (size_t)n;
	}
	return 0;
}

/*
 * A path under a verified root resolves from its descriptor alone: no
 * symbolic link, no magic link and no step out of it, so nothing root
 * mounts or links elsewhere, /proc/<pid>/fd before an exec say, is
 * followed.
 */
size_t lines_len(const char *buf, size_t len)
{
	while (len && buf[len - 1] != '\n')
		len--;
	return len;
}

static int last_line_end(int fd, off_t size, off_t *end)
{
	char chunk[4096];
	const off_t step = sizeof(chunk);
	off_t off = size;

	while (off > 0) {
		size_t n = (size_t)min(off, step), i;
		off_t start = off - (off_t)n;
		ssize_t got = pread(fd, chunk, n, start);

		if (got < 0 && errno == EINTR)
			continue;
		if (got < 0)
			return -errno;
		if ((size_t)got != n)
			return -EIO;
		for (i = n; i; i--) {
			if (chunk[i - 1] == '\n') {
				*end = start + (off_t)i;
				return 0;
			}
		}
		off = start;
	}
	*end = 0;
	return 0;
}

int append_line(int fd, const char *path, const char *line, size_t len)
{
	struct stat st;
	off_t end = 0;
	char *buf;
	int ret;

	if (len && line[len - 1] == '\n')
		len--;
	if (memchr(line, '\n', len) || memchr(line, '\0', len))
		return -EINVAL;
	if (fstat(fd, &st))
		return -errno;
	ret = last_line_end(fd, st.st_size, &end);
	if (ret)
		return ret;
	if (end != st.st_size) {
		if (ftruncate(fd, end))
			return -errno;
		pr_warn("%s: dropped %lld bytes at its end, an append that did not finish",
			path, (__s64)(st.st_size - end));
	}
	buf = xmalloc(len + 1);
	if (!buf)
		return -ENOMEM;
	memcpy(buf, line, len);
	buf[len] = '\n';
	ret = write_complete(fd, buf, len + 1);
	xfree(buf, len + 1);
	if (!ret && fsync(fd))
		ret = -errno;
	if (ret && ftruncate(fd, end))
		pr_warn("%s: could not roll back a partial append: %s", path,
			strerror(errno));
	return ret;
}

int open_beneath(int dirfd, const char *rel, int flags)
{
	struct open_how how = {
		.flags = (__u64)flags | O_CLOEXEC,
		.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
			   RESOLVE_NO_MAGICLINKS,
	};
	long fd;

	if (dirfd < 0 || !rel || !*rel || *rel == '/')
		return -EINVAL;
	fd = syscall(SYS_openat2, dirfd, rel, &how, sizeof(how));
	return fd < 0 ? -errno : (int)fd;
}

/* The whole file behind the descriptor, from its start, xmalloc'd. */
int read_fd(int fd, const char *label, size_t max, void *out, size_t *len)
{
	struct stat st;
	char *buf, *p;
	size_t left;
	off_t off;
	int ret;

	if (fstat(fd, &st) != 0)
		return -errno;
	if (!S_ISREG(st.st_mode))
		return -EINVAL;
	ret = check_trusted(fd, label, false);
	if (ret)
		return ret;
	if ((uintmax_t)st.st_size > max)
		return -EFBIG;
	buf = xmalloc((size_t)st.st_size + 1);
	if (!buf)
		return -ENOMEM;
	for (p = buf, left = (size_t)st.st_size, off = 0; left; ) {
		ssize_t n = pread(fd, p, left, off);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			xfree(buf, (size_t)st.st_size + 1);
			return n < 0 ? -errno : -EIO;
		}
		p += n;
		off += n;
		left -= (size_t)n;
	}
	*(char **)out = buf;
	*len = (size_t)st.st_size;
	return 0;
}

/*
 * One line of text, at most max bytes before its newline, in getline's
 * buffer, which the caller frees with libc_free: 1, 0 at the end, -E2BIG
 * for a longer line and -EINVAL for one holding a NUL. fgets cut a long
 * line into two that each parsed, and a NUL ended the string where the
 * line went on.
 */
int read_text_line(FILE *f, char **line, size_t *cap, size_t max)
{
	ssize_t n;

	errno = 0;
	n = getline(line, cap, f);
	if (n < 0)
		return errno ? -errno : 0;
	if (memchr(*line, '\0', (size_t)n))
		return -EINVAL;
	if ((*line)[n - 1] == '\n')
		n--;
	return (size_t)n > max ? -E2BIG : 1;
}

int read_file(const char *path, size_t max, void *out, size_t *len)
{
	int fd, ret;

	if (under(path, VAR_LIB)) {
		fd = seal_open_read(path);
		if (fd < 0)
			return fd;
	} else {
		/* O_NONBLOCK: a FIFO is refused below, not waited on. */
		fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0)
			return -errno;
	}
	ret = read_fd(fd, path, max, out, len);
	close(fd);
	return ret;
}

static bool under(const char *path, const char *dir)
{
	size_t n = strlen(dir);

	return !strncmp(path, dir, n) && path[n] == '/';
}

static bool trusted_owner(uid_t uid)
{
	return uid == 0 || uid == geteuid();
}

int check_trusted(int fd, const char *path, bool secret)
{
	char real[PATH_MAX], *slash;
	struct stat st;

	if (!under(path, ETC_DIR) && !under(path, VAR_LIB))
		return 0;
	if (fstat(fd, &st))
		return -errno;
	if (!S_ISREG(st.st_mode) || !trusted_owner(st.st_uid) ||
	    (st.st_mode & (secret ? 077 : 022))) {
		pr_err("%s: owner %u, mode %04o: refusing a file another user "
		       "could %s", path, (__u32)st.st_uid,
		       (__u32)(st.st_mode & 07777),
		       secret ? "read or change" : "change");
		return -EPERM;
	}
	if (!realpath(path, real))
		return -errno;
	do {
		slash = strrchr(real, '/');
		if (slash == real)
			slash[1] = '\0';
		else
			*slash = '\0';
		if (stat(real, &st))
			return -errno;
		if (!S_ISDIR(st.st_mode) || !trusted_owner(st.st_uid) ||
		    ((st.st_mode & 022) &&
		     !((st.st_mode & S_ISVTX) && st.st_uid == 0))) {
			pr_err("%s: directory %s, owner %u, mode %04o: "
			       "refusing a file another user could replace",
			       path, real, (__u32)st.st_uid,
			       (__u32)(st.st_mode & 07777));
			return -EPERM;
		}
	} while (slash != real);
	return 0;
}

__u32 kernel_dev(dev_t dev)
{
	return (__u32)major(dev) << 20 | (minor(dev) & 0xfffffU);
}

int bpffs_mounted_at(const char *path)
{
	struct statx stx = {};
	struct statfs fs = {};
	int fd, ret;

	fd = open(path, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOENT ? 0 : -errno;
	if (fstatfs(fd, &fs) ||
	    statx(fd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW, 0, &stx))
		ret = -errno;
	else
		ret = fs.f_type == BPF_FS_MAGIC &&
		      stx.stx_attributes_mask & STATX_ATTR_MOUNT_ROOT &&
		      stx.stx_attributes & STATX_ATTR_MOUNT_ROOT;
	close(fd);
	return ret;
}

int lock_exclusive(int fd)
{
	while (flock(fd, LOCK_EX)) {
		if (errno != EINTR)
			return -errno;
	}
	return 0;
}
