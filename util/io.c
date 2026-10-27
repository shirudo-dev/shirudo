// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

int read_file(const char *path, size_t max, void *out, size_t *len)
{
	struct stat st;
	char *buf, *p;
	size_t left;
	int fd, rc;

	if (under(path, SHIRUDO_VAR_LIB))
		fd = seal_open_read(path);
	else
		fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return fd == -1 ? -errno : fd;
	if (fstat(fd, &st) != 0) {
		rc = -errno;
		goto out;
	}
	if (!S_ISREG(st.st_mode)) {
		rc = -EINVAL;
		goto out;
	}
	rc = check_trusted(fd, path, false);
	if (rc)
		goto out;
	if ((uintmax_t)st.st_size > max) {
		rc = -EFBIG;
		goto out;
	}
	buf = xmalloc((size_t)st.st_size + 1);
	if (!buf) {
		rc = -ENOMEM;
		goto out;
	}
	for (p = buf, left = (size_t)st.st_size; left; ) {
		ssize_t n = read(fd, p, left);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			rc = n < 0 ? -errno : -EIO;
			xfree(buf, (size_t)st.st_size + 1);
			goto out;
		}
		p += n;
		left -= (size_t)n;
	}
	*(char **)out = buf;
	*len = (size_t)st.st_size;
	rc = 0;
out:
	close(fd);
	return rc;
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

	if (!under(path, SHIRUDO_ETC_DIR) && !under(path, SHIRUDO_VAR_LIB))
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
