/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_IO_H
#define SHIRUDO_IO_H

#include <stdbool.h>
#include <stddef.h>

int write_complete(int fd, const void *buf, size_t len);

/*
 * A regular file of at most max bytes, into *out xmalloc'd to *len + 1
 * bytes and NUL-terminated; out is the address of a char or unsigned
 * char pointer.
 */
int read_file(const char *path, size_t max, void *out, size_t *len);

/*
 * Whether the file open on fd at path may steer what shirudo trusts.
 * Under /etc/shirudo and /var/lib/shirudo, where an installed shirudo
 * keeps such files, it must be a regular file of root's or of the user
 * running shirudo that nobody else can write, nor with secret read, in
 * directories up to / that nobody else can change; a sticky directory of
 * root's guards its files the same way. A path elsewhere, where a test
 * points shirudo, is the caller's to vouch for. 0, or -EPERM logged.
 */
int check_trusted(int fd, const char *path, bool secret);

#endif /* SHIRUDO_IO_H */
