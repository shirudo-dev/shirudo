// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm_header() of util/bpm_oci.c, libcurl's header callback, for every
 * header line of up to LINE_MAX bytes, NULs included: it takes the whole
 * line, reads none longer than its copy nor one holding a NUL, and the
 * challenge and location it keeps are terminated inside their fields, the
 * location without a line break, a challenge longer than its field
 * dropped rather than cut. A new HTTP response clears both prior fields.
 * The copy and the challenge's field are of 24 and 4 bytes here, for 4096
 * and 2048, which are past what CBMC can hold: the checks against them
 * are the same expressions.
 */

#define BPM_OCI_HEADER_LINE_MAX	24
#define BPM_OCI_CHALLENGE_MAX	4

/* util/string.c is included behind a file that includes its header. */
#define STRING_INTERNAL
#define PROOF_MEMCPY_BYTEWISE

#include "proof.h"
#include "../../../util/bpm_oci.c"
#include "../../../util/string.c"

/* Past the copy, and room for a challenge longer than its field. */
#define LINE_MAX	(BPM_OCI_HEADER_LINE_MAX + 2)

/* What the line leaves in a field ends inside the line's length. */
static bool short_string(const char *s, size_t size)
{
	return memchr(s, '\0', min(size, (size_t)LINE_MAX + 1));
}

static char lower(char c)
{
	return c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c;
}

/* The line starts with the header's name, in any case. */
static bool named(const char *line, size_t n, const char *name)
{
	size_t i, len = strlen(name);

	for (i = 0; i < len; i++)
		if (i >= n || lower(line[i]) != lower(name[i]))
			return false;
	return true;
}

/* The challenge a WWW-Authenticate line holds: from its first non-blank. */
static void challenge(const char *line, size_t n, const char *kept)
{
	size_t from = strlen("WWW-Authenticate:"), len = 0;

	while (from < n && isspace((__u8)line[from]))
		from++;
	while (from + len < n && line[from + len])
		len++;
	if (len >= BPM_OCI_CHALLENGE_MAX) {
		__CPROVER_assert(!kept[0],
				 "a challenge longer than its field dropped");
		return;
	}
	__CPROVER_assert(!memcmp(kept, line + from, len) && !kept[len],
			 "a challenge that fits kept whole");
}

static bool has_any(const char *s, const char *set)
{
	size_t i, j;

	for (i = 0; s[i]; i++)
		for (j = 0; set[j]; j++)
			if (s[i] == set[j])
				return true;
	return false;
}

void harness(void)
{
	char *line = any_bytes(LINE_MAX);
	struct bpm_http_response r = {};
	size_t n;

	__CPROVER_assume(n <= LINE_MAX);
	if (named(line, n, "HTTP/")) {
		r.www_auth[0] = 'a';
		r.location[0] = 'b';
	}
	__CPROVER_assert(bpm_header(line, 1, n, &r) == n,
			 "the whole line taken");
	if (named(line, n, "HTTP/")) {
		__CPROVER_assert(!r.www_auth[0] && !r.location[0],
				 "no headers carried to a new response");
		return;
	}
	if (n >= BPM_OCI_HEADER_LINE_MAX) {
		__CPROVER_assert(!r.www_auth[0] && !r.location[0],
				 "a line longer than the copy read not at all");
		return;
	}
	if (memchr(line, '\0', n)) {
		__CPROVER_assert(!r.www_auth[0] && !r.location[0],
				 "a line holding a NUL read not at all");
		return;
	}
	__CPROVER_assert(short_string(r.www_auth, sizeof(r.www_auth)) &&
			 short_string(r.location, sizeof(r.location)),
			 "every value terminated inside its field");
	__CPROVER_assert(!has_any(r.location, "\r\n"),
			 "a location without its line break");
	__CPROVER_assert(!isspace((__u8)r.www_auth[0]) &&
			 !isspace((__u8)r.location[0]),
			 "no value starts with a blank");
	if (named(line, n, "WWW-Authenticate:"))
		challenge(line, n, r.www_auth);
}
