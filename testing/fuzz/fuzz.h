/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What the libFuzzer targets for shirudo's parsers share.
 */

#ifndef SHIRUDO_FUZZ_H
#define SHIRUDO_FUZZ_H

#include <stddef.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <zlib.h>

#include <shirudo/misc.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const __u8 *data, size_t size);

/*
 * testing/fuzz/output.c, for the targets of what a command prints, which
 * call fuzz_output_capture() once to make stdout a memfd. fuzz_run() runs
 * cmd with the words up to the NULL as its argv, as the CLI does, and
 * returns its exit status. It abort()s unless what the command printed
 * to stdout is none or one JSON value that json_walk() takes and a line
 * feed, where the last word is --json, and otherwise keeps the promise of
 * text_sanitize() for a terminal: well-formed UTF-8 with no C0 or C1
 * control, no DEL and no bidi or zero-width format character, but for a
 * tab, a line feed and a carriage return before a line feed.
 * fuzz_output() returns what it printed, with a NUL behind, until the
 * next run.
 */
void fuzz_output_capture(void);
int fuzz_run(int (*cmd)(int argc, const char **argv), const char *word,
	     ...) __sentinel;
const char *fuzz_output(size_t *len);

/*
 * The input as a file for the parsers that read one by name: a memfd,
 * named through /proc/self/fd. -1, or the descriptor to close after.
 */
static inline int fuzz_file(const __u8 *data, size_t size, char *path,
			    size_t cap)
{
	int fd = memfd_create("fuzz", MFD_CLOEXEC);
	size_t off = 0;

	if (fd < 0)
		return -1;
	while (off < size) {
		ssize_t n = write(fd, data + off, size - off);

		if (n <= 0) {
			close(fd);
			return -1;
		}
		off += (size_t)n;
	}
	snprintf(path, cap, "/proc/self/fd/%d", fd);
	return fd;
}

/*
 * The input as a gzip'd file, compressed here unless it is already, so
 * that the fuzzer mutates the archive inside rather than the stream.
 */
static inline int fuzz_gzip_file(const __u8 *data, size_t size, char *path,
				 size_t cap)
{
	gzFile gz;
	int fd, wfd;

	if (size >= 2 && data[0] == 0x1f && data[1] == 0x8b)
		return fuzz_file(data, size, path, cap);
	fd = memfd_create("fuzz", MFD_CLOEXEC);
	if (fd < 0)
		return -1;
	wfd = dup(fd);
	gz = wfd < 0 ? NULL : gzdopen(wfd, "wb1");
	if (!gz) {
		if (wfd >= 0)
			close(wfd);
		close(fd);
		return -1;
	}
	if ((size && gzwrite(gz, data, (__u32)size) != (int)size) ||
	    gzclose(gz) != Z_OK) {
		close(fd);
		return -1;
	}
	snprintf(path, cap, "/proc/self/fd/%d", fd);
	return fd;
}

#endif /* SHIRUDO_FUZZ_H */
