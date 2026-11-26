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
#include <shirudo/string.h>

#include "io.h"
#include "log.h"
#include "malloc.h"
#include "paths.h"
#include "seal.h"

static bool under(const char *path, const char *dir);
static int open_checked(const char *path, int flags,
			int (*opener)(const char *path, int flags));

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

/*
 * A path under a verified root resolves from its descriptor alone: no
 * symbolic link, no magic link and no step out of it, so nothing root
 * mounts or links elsewhere, /proc/<pid>/fd before an exec say, is
 * followed.
 */
static int open_resolved(int dirfd, const char *rel, int flags, mode_t mode,
			 __u64 resolve)
{
	struct open_how how = {
		.flags = (__u64)flags | O_CLOEXEC,
		.mode = flags & O_CREAT ? mode : 0,
		.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
			   RESOLVE_NO_MAGICLINKS | resolve,
	};
	long fd;

	if (dirfd < 0 || !rel || !*rel || *rel == '/')
		return -EINVAL;
	fd = syscall(SYS_openat2, dirfd, rel, &how, sizeof(how));
	return fd < 0 ? -errno : (int)fd;
}

int open_beneath(int dirfd, const char *rel, int flags)
{
	return open_resolved(dirfd, rel, flags, 0, 0);
}

int open_beneath_same_mount(int dirfd, const char *rel, int flags)
{
	return open_resolved(dirfd, rel, flags, 0, RESOLVE_NO_XDEV);
}

int create_beneath_same_mount(int dirfd, const char *rel, int flags,
			      mode_t mode)
{
	return open_resolved(dirfd, rel, flags | O_CREAT | O_EXCL, mode,
			     RESOLVE_NO_XDEV);
}

/* The whole regular file behind the descriptor, from its start, xmalloc'd. */
static int read_whole(int fd, size_t max, void *out, size_t *len)
{
	struct stat st;
	char *buf, *p;
	size_t left;
	off_t off;

	if (fstat(fd, &st) != 0)
		return -errno;
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

int read_fd(int fd, const char *label, size_t max, void *out, size_t *len)
{
	struct stat st;
	int ret;

	if (fstat(fd, &st) != 0)
		return -errno;
	if (!S_ISREG(st.st_mode))
		return -EINVAL;
	ret = check_trusted(fd, label);
	return ret ? ret : read_whole(fd, max, out, len);
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

static int open_path(const char *path, int flags)
{
	int fd = open(path, flags | O_CLOEXEC);

	return fd < 0 ? -errno : fd;
}

/* A regular file for read_file(), as sealed state under /var/lib/shirudo. */
static int open_regular(const char *path, int flags)
{
	struct stat st;
	int fd, ret;

	/* O_NONBLOCK: a FIFO is refused below, not waited on. */
	fd = under(path, VAR_LIB) ? seal_open_read(path) :
	     open_path(path, flags | O_NONBLOCK);
	if (fd < 0)
		return fd;
	ret = fstat(fd, &st) ? -errno : S_ISREG(st.st_mode) ? 0 : -EINVAL;
	if (ret) {
		close(fd);
		return ret;
	}
	return fd;
}

int read_file(const char *path, size_t max, void *out, size_t *len)
{
	int fd, ret;

	fd = open_checked(path, O_RDONLY, open_regular);
	if (fd < 0)
		return fd;
	ret = read_whole(fd, max, out, len);
	close(fd);
	return ret;
}

static bool under(const char *path, const char *dir)
{
	const char *below = str_after_prefix(path, dir);

	return below && *below == '/';
}

static bool trusted_owner(uid_t uid)
{
	return uid == 0 || uid == geteuid();
}

/* As many links as the kernel follows on the way to one file. */
#define TRUSTED_LINKS_MAX	40

struct trusted_walk {
	const char *path;	/* as the caller named it, for messages */
	char rest[PATH_MAX];	/* the names still to look up */
	int dirfd;		/* the directory the next name is looked up in */
	int links;
};

/* What fd is open on, named for a message. */
static const char *opened_path(int fd, char name[PATH_MAX])
{
	char link[32];
	ssize_t n;

	if (strsprintf(link, sizeof(link), "/proc/self/fd/%d", fd) < 0)
		return "?";
	n = readlink(link, name, PATH_MAX - 1);
	if (n < 0)
		return "?";
	name[n] = '\0';
	return name;
}

static int trusted_dir(const struct trusted_walk *walk)
{
	char name[PATH_MAX];
	struct stat st;

	if (fstat(walk->dirfd, &st))
		return -errno;
	if (!S_ISDIR(st.st_mode))
		return -ENOTDIR;
	if (trusted_owner(st.st_uid) &&
	    (!(st.st_mode & 022) ||
	     ((st.st_mode & S_ISVTX) && st.st_uid == 0)))
		return 0;
	pr_err("%s: directory %s, owner %u, mode %04o: refusing a file another user could replace",
	       walk->path, opened_path(walk->dirfd, name), (__u32)st.st_uid,
	       (__u32)(st.st_mode & 07777));
	return -EPERM;
}

static int walk_from_root(struct trusted_walk *walk)
{
	if (walk->dirfd >= 0)
		close(walk->dirfd);
	walk->dirfd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
	return walk->dirfd < 0 ? -errno : 0;
}

/*
 * The target of the link open on fd goes ahead of the names left after
 * it. In a sticky directory a link is its owner's to replace, so another
 * user's link is refused wherever it is found.
 */
static int walk_link(struct trusted_walk *walk, int fd, uid_t owner,
		     const char *left)
{
	char target[PATH_MAX], name[PATH_MAX];
	ssize_t n;

	if (!trusted_owner(owner)) {
		pr_err("%s: link %s, owner %u: refusing a file another user could replace",
		       walk->path, opened_path(fd, name), (__u32)owner);
		return -EPERM;
	}
	if (++walk->links > TRUSTED_LINKS_MAX)
		return -ELOOP;
	n = readlinkat(fd, "", target, sizeof(target));
	if (n < 0)
		return -errno;
	if ((size_t)n >= sizeof(target))
		return -ENAMETOOLONG;
	target[n] = '\0';
	if (strsprintf(target + n, sizeof(target) - (size_t)n, "/%s", left) < 0 ||
	    strscpy(walk->rest, target, sizeof(walk->rest)) < 0)
		return -ENAMETOOLONG;
	return target[0] == '/' ? walk_from_root(walk) : 0;
}

/* The name that ends at end, looked up in the directory and not followed. */
static int walk_open(const struct trusted_walk *walk, const char *name,
		     char *end)
{
	char cut = *end;
	int fd, err;

	*end = '\0';
	fd = openat(walk->dirfd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
	err = errno;
	*end = cut;
	return fd < 0 ? -err : fd;
}

static char *skip_slashes(char *s)
{
	while (*s == '/')
		s++;
	return s;
}

/*
 * The path resolved one name at a time, each directory checked through
 * the descriptor the next name is looked up in, and each link read
 * through the one it was found by: a lookup of the whole path by name
 * can go another way than the open of the file did, through a name
 * another user swapped in between or a link another user made. 0 when
 * it ends at the file *file describes, -ESTALE unlogged when at another.
 */
static int trusted_walk(struct trusted_walk *walk, const struct stat *file)
{
	char *name = walk->rest, *end;
	struct stat st;
	int fd, ret;
	bool link;

	for (;;) {
		ret = trusted_dir(walk);
		if (ret)
			return ret;
		name = skip_slashes(name);
		end = strchr(name, '/');
		if (!end)
			end = name + strlen(name);
		if (end == name)
			return -EISDIR;
		fd = walk_open(walk, name, end);
		if (fd < 0)
			return fd;
		if (fstat(fd, &st)) {
			ret = -errno;
			close(fd);
			return ret;
		}
		if (S_ISDIR(st.st_mode)) {
			close(walk->dirfd);
			walk->dirfd = fd;
			name = end;
			continue;
		}
		link = S_ISLNK(st.st_mode);
		ret = link ? walk_link(walk, fd, st.st_uid, end) : 0;
		close(fd);
		if (ret)
			return ret;
		if (!link)
			break;
		name = walk->rest;
	}
	if (*skip_slashes(end))
		return -ENOTDIR;
	return st.st_dev == file->st_dev && st.st_ino == file->st_ino ?
	       0 : -ESTALE;
}

static void report_stale(const char *path)
{
	pr_err("%s: names another file than the one opened; refusing it",
	       path);
}

static bool trusted_place(const char *path)
{
	return under(path, ETC_DIR) || under(path, VAR_LIB);
}

/* The file open on fd by itself, whatever path led to it. */
static int trusted_file(int fd, const char *path, bool secret,
			struct stat *st)
{
	if (fstat(fd, st))
		return -errno;
	if (!S_ISREG(st->st_mode) || !trusted_owner(st->st_uid) ||
	    (st->st_mode & (secret ? 077 : 022))) {
		pr_err("%s: owner %u, mode %04o: refusing a file another user "
		       "could %s", path, (__u32)st->st_uid,
		       (__u32)(st->st_mode & 07777),
		       secret ? "read or change" : "change");
		return -EPERM;
	}
	return 0;
}

/* check_trusted(), a file renamed over left for the caller to report. */
static int trusted_check(int fd, const char *path)
{
	struct trusted_walk walk = { .path = path, .dirfd = -1 };
	struct stat st;
	int ret;

	if (!trusted_place(path))
		return 0;
	ret = trusted_file(fd, path, false, &st);
	if (ret)
		return ret;
	if (strscpy(walk.rest, path, sizeof(walk.rest)) < 0)
		return -ENAMETOOLONG;
	ret = walk_from_root(&walk);
	if (!ret)
		ret = trusted_walk(&walk, &st);
	if (walk.dirfd >= 0)
		close(walk.dirfd);
	return ret;
}

int check_trusted(int fd, const char *path)
{
	int ret = trusted_check(fd, path);

	if (ret == -ESTALE)
		report_stale(path);
	return ret;
}

int check_secret(int fd, const char *path)
{
	struct stat st;

	return trusted_place(path) ? trusted_file(fd, path, true, &st) : 0;
}

/* Reopens of a name that an open_trusted() makes after its first open. */
#define TRUSTED_REOPENS		3

/*
 * Each attempt opens the name again and runs the whole check on its own
 * descriptor, so that one passes only what a single check passes. A
 * rename that an attempt absorbs is not reported; the last is.
 */
static int open_checked(const char *path, int flags,
			int (*opener)(const char *path, int flags))
{
	int attempt, fd, ret;

	for (attempt = 0;; attempt++) {
		fd = opener(path, flags);
		if (fd < 0)
			return fd;
		ret = trusted_check(fd, path);
		if (!ret)
			return fd;
		close(fd);
		if (ret != -ESTALE || attempt == TRUSTED_REOPENS)
			break;
	}
	if (ret == -ESTALE)
		report_stale(path);
	return ret;
}

int open_trusted(const char *path, int flags)
{
	return open_checked(path, flags, open_path);
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
