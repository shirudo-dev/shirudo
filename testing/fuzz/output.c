// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * A command run as the CLI runs it, with what it prints to stdout held to
 * the rules of a terminal or of JSON, for the targets of the printers.
 */

#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "fuzz.h"

#include <shirudo/string.h>

#include "json.h"
#include "malloc.h"

/* The words of a command line fuzz_run() takes. */
#define RUN_ARGC_MAX	16

static int capture_fd = -1;
static char *printed;
static size_t printed_len;
static size_t printed_cap;

/*
 * A memfd rather than a memstream assigned to stdout, which would miss
 * what a printer writes to STDOUT_FILENO with write_complete().
 */
void fuzz_output_capture(void)
{
	capture_fd = memfd_create("fuzz-stdout", MFD_CLOEXEC);
	if (capture_fd < 0 || dup2(capture_fd, STDOUT_FILENO) < 0)
		abort();
}

/* What was written to stdout since the last take, which empties it. */
static void output_take(void)
{
	struct stat st;
	size_t size;
	char *grown;

	if (fflush(stdout) || fstat(capture_fd, &st) || st.st_size < 0)
		abort();
	size = (size_t)st.st_size;
	if (size >= printed_cap) {
		grown = xreallocarray(printed, printed_cap, size + 1, 1);
		if (!grown)
			abort();
		printed = grown;
		printed_cap = size + 1;
	}
	if (pread(capture_fd, printed, size, 0) != (ssize_t)size ||
	    ftruncate(capture_fd, 0) || lseek(capture_fd, 0, SEEK_SET))
		abort();
	printed[size] = '\0';
	printed_len = size;
}

const char *fuzz_output(size_t *len)
{
	*len = printed_len;
	return printed;
}

/* U+200B to U+200F, U+2028 to U+202E or U+2066 to U+2069 at s. */
static bool hidden_format3(const char *s)
{
	__u8 b1 = s[1], b2 = s[2];

	if ((__u8)s[0] != 0xe2)
		return false;
	return (b1 == 0x80 && ((b2 >= 0x8b && b2 <= 0x8f) ||
			       (b2 >= 0xa8 && b2 <= 0xae))) ||
	       (b1 == 0x81 && b2 >= 0xa6 && b2 <= 0xa9);
}

/*
 * Whether the width bytes at i are a control or a hidden format
 * character that text_sanitize() takes out.
 */
static bool stray_control(const char *s, size_t len, size_t i, size_t width)
{
	__u8 c = s[i];

	if (width == 2)
		return (c == 0xc2 && (__u8)s[i + 1] < 0xa0) ||
		       (c == 0xd8 && (__u8)s[i + 1] == 0x9c);
	if (width == 3)
		return hidden_format3(s + i);
	if (width != 1 || (c >= 0x20 && c != 0x7f) || c == '\t' || c == '\n')
		return false;
	return c != '\r' || i + 1 == len || s[i + 1] != '\n';
}

static bool text_sanitized(const char *s, size_t len)
{
	size_t i, width;

	for (i = 0; i < len; i += width) {
		width = utf8_width(s + i, len - i);
		if (!width || stray_control(s, len, i, width))
			return false;
	}
	return true;
}

static bool one_json_line(const char *s, size_t len)
{
	static const struct json_visitor any;

	return !len ||
	       (s[len - 1] == '\n' && !json_walk(s, len - 1, &any, NULL));
}

int fuzz_run(int (*cmd)(int argc, const char **argv), const char *word, ...)
{
	const char *argv[RUN_ARGC_MAX] = {};
	int argc = 0, status;
	va_list ap;
	bool json;

	va_start(ap, word);
	for (; word; word = va_arg(ap, const char *)) {
		if (argc == RUN_ARGC_MAX)
			abort();
		argv[argc++] = word;
	}
	va_end(ap);
	status = cmd(argc, argv);
	output_take();
	json = argc && !strcmp(argv[argc - 1], "--json");
	if (json ? !one_json_line(printed, printed_len) :
		   !text_sanitized(printed, printed_len))
		abort();
	return status;
}
