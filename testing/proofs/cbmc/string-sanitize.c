// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * text_sanitize() of util/string.c on every text of LEN bytes, each
 * length proofs.list names: what it leaves is well-formed UTF-8 without a
 * control or hidden format character but a kept line break, and it
 * changes only what it must, to '?'.
 */

#include <errno.h>
#include <stdbool.h>

#include "proof.h"
#include "../../../util/string.c"

static bool in(__u8 c, __u8 lo, __u8 hi)
{
	return c >= lo && c <= hi;
}

/* Table 3-7 of the Unicode Standard, row by row. */
static size_t table_width(const __u8 *s, size_t n)
{
	if (n >= 1 && s[0] <= 0x7f)
		return 1;
	if (n >= 2 && in(s[0], 0xc2, 0xdf) && in(s[1], 0x80, 0xbf))
		return 2;
	if (n >= 3 && in(s[2], 0x80, 0xbf) &&
	    ((s[0] == 0xe0 && in(s[1], 0xa0, 0xbf)) ||
	     (in(s[0], 0xe1, 0xec) && in(s[1], 0x80, 0xbf)) ||
	     (s[0] == 0xed && in(s[1], 0x80, 0x9f)) ||
	     (in(s[0], 0xee, 0xef) && in(s[1], 0x80, 0xbf))))
		return 3;
	if (n >= 4 && in(s[2], 0x80, 0xbf) && in(s[3], 0x80, 0xbf) &&
	    ((s[0] == 0xf0 && in(s[1], 0x90, 0xbf)) ||
	     (in(s[0], 0xf1, 0xf3) && in(s[1], 0x80, 0xbf)) ||
	     (s[0] == 0xf4 && in(s[1], 0x80, 0x8f))))
		return 4;
	return 0;
}

static bool control(const __u8 *s, size_t i, size_t len)
{
	return s[i] < 0x20 || s[i] == 0x7f ||
	       (s[i] == 0xc2 && i + 1 < len && in(s[i + 1], 0x80, 0x9f));
}

/* U+061C, U+200B to U+200F, U+2028 to U+202E or U+2066 to U+2069. */
static bool hidden_format_at(const __u8 *s, size_t i, size_t len)
{
	if (i + 1 < len && s[i] == 0xd8 && s[i + 1] == 0x9c)
		return true;
	if (i + 2 >= len || s[i] != 0xe2)
		return false;
	return (s[i + 1] == 0x80 && (in(s[i + 2], 0x8b, 0x8f) ||
				     in(s[i + 2], 0xa8, 0xae))) ||
	       (s[i + 1] == 0x81 && in(s[i + 2], 0xa6, 0xa9));
}

static bool line_break(const __u8 *s, size_t i, size_t len)
{
	return s[i] == '\t' || s[i] == '\n' ||
	       (s[i] == '\r' && i + 1 < len && s[i + 1] == '\n');
}

static void sanitized_text(void)
{
	const __u8 *t, *before;
	size_t len, i, j, w;
	char *s, *was;
	bool lines;

	len = LEN;
	s = any_bytes(len);
	was = any_bytes(len);
	memcpy(was, s, len);
	text_sanitize(s, len, lines);
	t = (const __u8 *)s;
	before = (const __u8 *)was;
	for (i = 0; i < len; i++)
		__CPROVER_assert(s[i] == '?' || s[i] == was[i],
				 "a byte kept or replaced by '?'");
	for (i = 0; i < len; i += w) {
		w = table_width(t + i, len - i);
		__CPROVER_assert(w, "well-formed UTF-8 throughout");
		if (!w)
			break;
		__CPROVER_assert(!control(t, i, len) ||
				 (lines && line_break(t, i, len)),
				 "no control character but a kept line break");
		__CPROVER_assert(!hidden_format_at(t, i, len),
				 "no hidden format character");
	}
	for (i = 0; i < len; i += w) {
		w = table_width(before + i, len - i);
		if (!w) {
			w = 1;
			continue;
		}
		if ((control(before, i, len) &&
		     !(lines && line_break(before, i, len))) ||
		    hidden_format_at(before, i, len))
			continue;
		for (j = i; j < i + w; j++)
			__CPROVER_assert(s[j] == was[j],
					 "a printable character kept as it was");
	}
}

void harness(void)
{
	sanitized_text();
}
