/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_IO_H
#define SHIRUDO_IO_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

#include <shirudo/types.h>

int write_complete(int fd, const void *buf, size_t len);

/*
 * A log record is a line that ends in its newline: a tail without one
 * is an append that did not finish, killed between its writes or cut by
 * a crash. lines_len() is how much of the len bytes at buf are whole
 * records, which is all a reader may take. append_line() drops such a
 * tail from the log open on fd at path, which the caller has opened
 * O_RDWR | O_APPEND and locked, and adds line and its newline in one
 * write, taking the file back to its last record when that fails. A
 * line with a newline or a NUL inside is -EINVAL.
 */
size_t lines_len(const char *buf, size_t len);
int append_line(int fd, const char *path, const char *line, size_t len);

/*
 * A regular file of at most max bytes, into *out xmalloc'd to *len + 1
 * bytes and NUL-terminated; out is the address of a char or unsigned
 * char pointer. read_file() opens path as open_trusted() does, read_fd()
 * checks what is open on fd once, under the name label.
 */
int read_file(const char *path, size_t max, void *out, size_t *len);
int read_fd(int fd, const char *label, size_t max, void *out, size_t *len);
int open_beneath(int dirfd, const char *rel, int flags);
/* Also refuse mount crossings, including bind mounts of the same file system. */
int open_beneath_same_mount(int dirfd, const char *rel, int flags);
/* The same for a file that must not be there yet, made with mode. */
int create_beneath_same_mount(int dirfd, const char *rel, int flags,
			      mode_t mode);
int read_text_line(FILE *f, char **line, size_t *cap, size_t max);

/*
 * Whether the file open on fd at path may steer what shirudo trusts.
 * Under /etc/shirudo and /var/lib/shirudo, where an installed shirudo
 * keeps such files, it must be a regular file of root's or of the user
 * running shirudo that nobody else can write, nor with secret read, and
 * the path must lead to it through directories nobody else can change
 * and links nobody else made; a sticky directory of root's guards its
 * entries the same way. A path elsewhere, where a test points shirudo,
 * is the caller's to vouch for. 0, -EPERM logged, or -ESTALE logged when
 * the path names another file than the one open on fd.
 */
int check_trusted(int fd, const char *path);

/*
 * Whether the file open on fd, which passed check_trusted() at path, may
 * hold a secret: nobody but its owner may read it either. Who reads a
 * file is the file's own to say, so the path is not walked again. 0 or
 * -EPERM logged.
 */
int check_secret(int fd, const char *path);

/*
 * A trusted file a config manager, a package or shirudo itself renames
 * over between its open and its check fails the check with -ESTALE.
 * open_trusted() then opens the name again and checks the new
 * descriptor in full, up to three more times, after which -ESTALE goes
 * to the caller: a descriptor on path opened with flags that passed
 * check_trusted(), or the open's or the last check's negative errno.
 */
int open_trusted(const char *path, int flags);

/* An exclusive flock() on fd, waited for through signals. 0 or -errno. */
int lock_exclusive(int fd);

/* A st_dev or st_rdev as the kernel encodes the dev_t in s_dev. */
__u32 kernel_dev(dev_t dev);

/*
 * 1 when path is the root of a bpf file system mount, which a bpffs
 * mounted on a directory above it or under another mount on top of it is
 * not; 0 when it is not, or there is no such path; else -errno.
 */
int bpffs_mounted_at(const char *path);

#endif /* SHIRUDO_IO_H */
