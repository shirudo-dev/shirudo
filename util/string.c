// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Bounded number parsing, string copies and formatting, tokens, DNS
 * names, UTF-8 characters and text for a terminal.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <shirudo/overflow.h>

/* Implements the wrappers; opt out of the poison in <shirudo/string.h>. */
#define STRING_INTERNAL
#include <shirudo/string.h>

size_t digits(const char *s, size_t len)
{
	size_t n = 0;

	while (n < len && s[n] >= '0' && s[n] <= '9')
		n++;
	return n;
}

static int digit_value(char c, __u32 base)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (base == 16 && c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (base == 16 && c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int parse_base(const char *s, size_t len, __u32 base, __u64 max,
		      __u64 *out)
{
	__u64 v = 0;
	size_t i;

	if (!len)
		return -EINVAL;
	for (i = 0; i < len; i++) {
		int d = digit_value(s[i], base);

		if (d < 0)
			return -EINVAL;
	}
	for (i = 0; i < len; i++) {
		__u64 d = (__u64)digit_value(s[i], base);

		if (check_mul_overflow(v, base, &v) ||
		    check_add_overflow(v, d, &v) || v > max)
			return -ERANGE;
	}
	*out = v;
	return 0;
}

int parse_u64(const char *s, size_t len, __u64 max, __u64 *out)
{
	return parse_base(s, len, 10, max, out);
}

int parse_x64(const char *s, size_t len, __u64 max, __u64 *out)
{
	return parse_base(s, len, 16, max, out);
}

int parse_s64(const char *s, size_t len, __s64 min, __s64 max, __s64 *out)
{
	bool neg = len && s[0] == '-';
	__u64 v;
	__s64 r;
	int ret;

	ret = parse_base(s + neg, len - neg, 10,
			 neg ? (__u64)INT64_MAX + 1 : (__u64)INT64_MAX, &v);
	if (ret)
		return ret;
	if (!neg)
		r = (__s64)v;
	else if (v == (__u64)INT64_MAX + 1)
		r = INT64_MIN;
	else
		r = -(__s64)v;
	if (r < min || r > max)
		return -ERANGE;
	*out = r;
	return 0;
}

ssize_t strscpy(char *dst, const char *src, size_t size)
{
	size_t len;

	if (!size)
		return -E2BIG;
	len = strnlen(src, size);
	if (len == size) {
		memcpy(dst, src, size - 1);
		dst[size - 1] = '\0';
		return -E2BIG;
	}
	memcpy(dst, src, len + 1);
	return (ssize_t)len;
}

int span_to_str(char *dst, size_t cap, const void *src, size_t len)
{
	if (memchr(src, '\0', len))
		return -EINVAL;
	if (len >= cap)
		return -E2BIG;
	memmove(dst, src, len);
	dst[len] = '\0';
	return 0;
}

static bool among(char c, const char *set)
{
	for (; *set; set++)
		if (c == *set)
			return true;
	return false;
}

size_t token_next(const char *s, size_t len, const char *delims, size_t *pos,
		  size_t *start)
{
	size_t at = min(*pos, len), n;

	while (at < len && among(s[at], delims))
		at++;
	n = span_until(s + at, len - at, delims);
	*start = at;
	*pos = at + n + (n < len - at);
	return n;
}

static bool numeric_dns_label(const char *label, size_t len)
{
	size_t i = 0;
	bool hex = len > 2 && label[0] == '0' &&
		   (label[1] == 'x' || label[1] == 'X');

	if (!len)
		return false;
	if (hex)
		i = 2;
	for (; i < len; i++) {
		__u8 c = label[i];

		if (c >= '0' && c <= '9')
			continue;
		if (hex && ((c >= 'a' && c <= 'f') ||
			    (c >= 'A' && c <= 'F')))
			continue;
		return false;
	}
	return !hex || i > 2;
}

bool name_has_suffix(const char *name, size_t len, const char *suffix)
{
	size_t n = strlen(suffix);

	return len > n && !memcmp(name + len - n, suffix, n);
}

static bool name_is_dot_or_dotdot(const char *name, size_t len)
{
	return (len == 1 || len == 2) && name[0] == '.' && name[len - 1] == '.';
}

bool name_glob_match(const char *pattern, const char *name, size_t len)
{
	const char *after_star = NULL;
	size_t i = 0, retry_at = 0;

	if (name_is_dot_or_dotdot(name, len))
		return false;
	while (i < len) {
		if (*pattern == '*') {
			after_star = ++pattern;
			retry_at = i;
		} else if (*pattern == '?' ||
			   (*pattern && *pattern == name[i])) {
			pattern++;
			i++;
		} else if (after_star) {
			pattern = after_star;
			i = ++retry_at;
		} else {
			return false;
		}
	}
	while (*pattern == '*')
		pattern++;
	return !*pattern;
}

bool dns_name_valid(const char *name)
{
	size_t len = strlen(name), label_len = 0, label_start = 0;
	bool numeric_address = true;
	size_t i;

	if (!len || len > 253)
		return false;
	for (i = 0; i < len; i++) {
		__u8 c = name[i];

		if (c == '.') {
			if (!label_len || label_len > 63 || name[i - 1] == '-')
				return false;
			if (!numeric_dns_label(name + label_start, label_len))
				numeric_address = false;
			label_start = i + 1;
			label_len = 0;
			continue;
		}
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '-') ||
		    (!label_len && c == '-'))
			return false;
		label_len++;
	}
	if (!label_len || label_len > 63 || name[len - 1] == '-')
		return false;
	if (!numeric_dns_label(name + label_start, label_len))
		numeric_address = false;
	return !numeric_address;
}

size_t utf8_width(const char *s, size_t n)
{
	size_t width, i;
	__u32 cp;
	__u8 c;

	if (!n)
		return 0;
	c = (__u8)s[0];
	if (c < 0x80)
		return 1;
	if ((c & 0xe0) == 0xc0) {
		width = 2;
		cp = c & 0x1f;
	} else if ((c & 0xf0) == 0xe0) {
		width = 3;
		cp = c & 0x0f;
	} else if ((c & 0xf8) == 0xf0) {
		width = 4;
		cp = c & 0x07;
	} else {
		return 0;
	}
	if (width > n)
		return 0;
	for (i = 1; i < width; i++) {
		if (((__u8)s[i] & 0xc0) != 0x80)
			return 0;
		cp = cp << 6 | ((__u8)s[i] & 0x3f);
	}
	if ((width == 2 && cp < 0x80) || (width == 3 && cp < 0x800) ||
	    (width == 4 && cp < 0x10000) || cp > 0x10ffff ||
	    (cp >= 0xd800 && cp <= 0xdfff))
		return 0;
	return width;
}

/*
 * Whether the width bytes at s, one well-formed character, are a format
 * character a terminal does not show but that changes how it shows the
 * text around it: the Arabic letter mark U+061C, the zero-width
 * characters and direction marks U+200B to U+200F, the line and
 * paragraph separators and the bidi embeddings and overrides U+2028 to
 * U+202E, and the bidi isolates U+2066 to U+2069.
 */
static bool hidden_format(const char *s, size_t width)
{
	__u8 b0 = s[0], b1, b2;

	if (width == 2)
		return b0 == 0xd8 && (__u8)s[1] == 0x9c;
	if (width != 3 || b0 != 0xe2)
		return false;
	b1 = s[1];
	b2 = s[2];
	if (b1 == 0x80)
		return (b2 >= 0x8b && b2 <= 0x8f) || (b2 >= 0xa8 && b2 <= 0xae);
	return b1 == 0x81 && b2 >= 0xa6 && b2 <= 0xa9;
}

void text_sanitize(char *s, size_t len, bool lines)
{
	size_t i, n;

	for (i = 0; i < len; i += n) {
		__u8 c = s[i];
		bool shown;

		n = utf8_width(s + i, len - i);
		if (c == '\t' || c == '\n')
			shown = lines;
		else if (c == '\r')
			shown = lines && i + 1 < len && s[i + 1] == '\n';
		else if (n == 1)
			shown = c >= 0x20 && c != 0x7f;
		else if (n == 2)
			shown = (c != 0xc2 || (__u8)s[i + 1] >= 0xa0) &&
				!hidden_format(s + i, n);
		else
			shown = n != 0 && !hidden_format(s + i, n);
		if (!n)
			n = 1;
		if (!shown)
			memset(s + i, '?', n);
	}
}

int vstrsprintf(char *buf, size_t size, const char *fmt, va_list ap)
{
	int n = vsnprintf(buf, size, fmt, ap);

	if (n >= 0 && (size_t)n < size)
		return n;
	if (size)
		buf[0] = '\0';
	return -E2BIG;
}

int strsprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vstrsprintf(buf, size, fmt, ap);
	va_end(ap);
	return n;
}
