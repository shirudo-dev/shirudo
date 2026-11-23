/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Bounded number parsing, string copies and formatting, file name
 * suffixes, tokens, DNS names, UTF-8 characters and text for a terminal,
 * from util/string.c, the compares of a prefix and of a span, and the
 * scrub and compare for secrets.
 */

#ifndef SHIRUDO_STRING_H
#define SHIRUDO_STRING_H

#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>

#include <shirudo/misc.h>

/* How many of the len bytes at s, from the first, are decimal digits. */
size_t digits(const char *s, size_t len);

/*
 * The number the len bytes at s spell, decimal for u64 and s64 and
 * hexadecimal for x64, within the bounds given: digits only, s64 with an
 * optional leading '-', and no blank, '+' or base prefix. Nothing past
 * len is read, so s need not be terminated. -EINVAL when the bytes are
 * not such a number, -ERANGE when it is out of bounds; *out is only
 * written on success.
 */
int parse_u64(const char *s, size_t len, __u64 max, __u64 *out);
int parse_x64(const char *s, size_t len, __u64 max, __u64 *out);
int parse_s64(const char *s, size_t len, __s64 min, __s64 max, __s64 *out);

/*
 * Copy the string src into the size bytes at dst, terminated whenever
 * size is not 0: its length, or -E2BIG when it did not fit and dst holds
 * as much of it as did. A string literal copied into an array takes
 * strscpy_literal() below, which cannot fail.
 */
ssize_t strscpy(char *dst, const char *src, size_t size) __must_check;

/*
 * Copy the string literal lit, terminator and all, into the array dst.
 * It cannot be cut: a lit that is no string literal, a dst that is a
 * pointer rather than an array, and a lit longer than dst fail the
 * build.
 */
#define strscpy_literal(dst, lit) do {					\
	BUILD_BUG_ON_MSG(sizeof(lit) > sizeof(dst) + __must_be_array(dst), \
			 #lit " does not fit in " #dst);		\
	memcpy(dst, "" lit, sizeof(lit));				\
} while (0)

/*
 * The len bytes at src as a string in the cap bytes at dst, terminated:
 * 0, -EINVAL when a NUL is among them, where a string would end short of
 * the bytes it was given, or -E2BIG when they and their terminator do
 * not fit. Nothing past len is read, so src need not be terminated; dst
 * is only written on success, and may be src where the bytes already sit
 * in a buffer with room for the terminator. What comes from outside the
 * program, a file, a reply or a field of a format, becomes a string
 * here, and only then goes to a function that reads up to a terminator.
 */
int span_to_str(char *dst, size_t cap, const void *src, size_t len)
	__must_check;

/*
 * snprintf() into the size bytes at buf: the length written, or -E2BIG,
 * with buf left empty, when the output did not fit. vstrsprintf() takes
 * the arguments as a va_list.
 */
int strsprintf(char *buf, size_t size, const char *fmt, ...)
	__printf(3, 4) __must_check;
int vstrsprintf(char *buf, size_t size, const char *fmt, va_list ap)
	__printf(3, 0) __must_check;

/*
 * Whether the len bytes at name are a stem of at least one byte and then
 * suffix, as a file name and its extension are.
 */
bool name_has_suffix(const char *name, size_t len, const char *suffix);

/*
 * Whether the len bytes at name are a file name that pattern matches: '*'
 * in pattern stands for any run of bytes and '?' for any one, every other
 * byte for itself. "." and ".." match no pattern.
 */
bool name_glob_match(const char *pattern, const char *name, size_t len);

/*
 * The length of prefix where s starts with it, else 0. prefix is a string
 * literal, whose length the compiler takes from its size: anything else
 * fails the build, so that the size of a pointer never stands in for it.
 * The _nocase form takes a letter in either case.
 */
#define str_has_prefix(s, prefix)					\
	(strncmp(s, "" prefix, sizeof(prefix) - 1) ? 0 : sizeof(prefix) - 1)
#define str_has_prefix_nocase(s, prefix)				\
	(strncasecmp(s, "" prefix, sizeof(prefix) - 1) ? 0 : sizeof(prefix) - 1)

/*
 * Whether *sp starts with the string literal prefix; where it does, *sp
 * moves past it. Where a test after it fails, *sp has still moved, so a
 * chain that tests the rest of the string takes str_has_prefix().
 */
#define str_skip_prefix(sp, prefix) ({					\
	__auto_type __sp = (sp);					\
	size_t __n = str_has_prefix(*__sp, prefix);			\
									\
	*__sp += __n;							\
	__n != 0;							\
})
#define str_skip_prefix_nocase(sp, prefix) ({				\
	__auto_type __sp = (sp);					\
	size_t __n = str_has_prefix_nocase(*__sp, prefix);		\
									\
	*__sp += __n;							\
	__n != 0;							\
})

/*
 * Where s goes on after prefix, or NULL where it does not start with it.
 * prefix is any string, the empty one included, which every string starts
 * with. The _nocase form takes a letter in either case.
 */
static inline const char *str_after_prefix(const char *s, const char *prefix)
{
	size_t n = strlen(prefix);

	return strncmp(s, prefix, n) ? NULL : s + n;
}

static inline const char *str_after_prefix_nocase(const char *s,
						  const char *prefix)
{
	size_t n = strlen(prefix);

	return strncasecmp(s, prefix, n) ? NULL : s + n;
}

/*
 * Whether the len bytes at s are the string literal lit, no more and no
 * fewer, its length again taken from its size.
 */
#define span_equals(s, len, lit)					\
	((len) == sizeof(lit) - 1 && !strncmp(s, "" lit, sizeof(lit) - 1))

/* The same for a string that is no literal. */
static inline bool span_equals_str(const char *s, size_t len, const char *str)
{
	return strlen(str) == len && !strncmp(s, str, len);
}

/*
 * The length of the string literal prefix where the len bytes at s, which
 * need no terminator, start with it in either case, else 0.
 */
#define span_has_prefix_nocase(s, len, prefix)				\
	(((len) >= sizeof(prefix) - 1 &&				\
	  !strncasecmp(s, "" prefix, sizeof(prefix) - 1)) ?		\
	 sizeof(prefix) - 1 : 0)

/* Whether a and b are the same string, a letter in either case. */
static inline bool str_equals_nocase(const char *a, const char *b)
{
	return !strcasecmp(a, b);
}

/*
 * How many of the len bytes at s, from the first, are none of the bytes
 * of set: the length of what comes before the first of them, or len.
 */
static inline size_t span_until(const char *s, size_t len, const char *set)
{
	size_t n, i;

	for (n = 0; n < len; n++)
		for (i = 0; set[i]; i++)
			if (s[n] == set[i])
				return n;
	return n;
}

/*
 * Where the string needle first lies in the len bytes at s, as a pointer
 * of the type of s, or NULL. Nothing past len is read, a NUL in the span
 * is a byte as any other, and the empty needle lies at s.
 */
#define span_find(s, len, needle) ({					\
	__auto_type __s = &(s)[0];					\
	const char *__needle = (needle);				\
									\
	(typeof(__s))memmem(__s, len, __needle, strlen(__needle));	\
})

/* Whether the string s holds the string needle. */
static inline bool str_contains(const char *s, const char *needle)
{
	return span_find(s, strlen(s), needle);
}

/*
 * The next token of the len bytes at s, from *pos on: a run of bytes that
 * are none of delims, after any that are. Its length, with its offset in
 * *start and *pos past it and past the delimiter that ended it, or 0 when
 * no token is left. Nothing is written, and a NUL is a byte as any other.
 */
size_t token_next(const char *s, size_t len, const char *delims, size_t *pos,
		  size_t *start);

/*
 * Run the body once for each token of the len bytes at s, tok at its
 * first byte, a pointer of the type of s, and tok_len its length. No
 * token is empty: delimiters in a row count as one. A body that owns the
 * buffer may end the token with a NUL where a byte follows it, the
 * delimiter or a string's terminator.
 */
#define __for_each_token(tok, tok_len, s, len, delims, n)		\
	for (__auto_type __text##n = &(s)[0]; __text##n; __text##n = NULL) \
		for (size_t __pos##n = 0, __start##n, __size##n = (len); \
		     ((tok_len) = token_next(__text##n, __size##n, delims, \
					     &__pos##n, &__start##n)) && \
		     ((tok) = __text##n + __start##n, true);)
#define __for_each_token_n(tok, tok_len, s, len, delims, n)		\
	__for_each_token(tok, tok_len, s, len, delims, n)
#define for_each_token(tok, tok_len, s, len, delims)			\
	__for_each_token_n(tok, tok_len, s, len, delims, __COUNTER__)

/*
 * A DNS host name: labels of letters, digits and inner hyphens, 1 to 63
 * bytes each and 253 in all. A name whose labels are all decimal or 0x
 * numbers is refused, as an IPv4 parser would read it as an address.
 */
bool dns_name_valid(const char *name);

/*
 * The length, 1 to 4, of the well-formed UTF-8 character the n bytes at
 * s start with, or 0 when they start none: a stray or cut byte, an
 * overlong form, a surrogate or a code point past U+10FFFF. Nothing past
 * n is read.
 */
size_t utf8_width(const char *s, size_t n);

/*
 * Make the len bytes at s, text from outside, safe to print on a
 * terminal: each byte of a control character, C0, DEL or C1 alike, and
 * each byte that starts no well-formed UTF-8 character becomes '?',
 * but for a tab and a line feed where lines is set, and there a carriage
 * return before a line feed. The length stays as it was.
 */
void text_sanitize(char *s, size_t len, bool lines);

/*
 * Zero the count bytes at s even when nothing reads them afterwards, as
 * when a secret is scrubbed before it goes out of scope or is freed,
 * where the compiler may drop a plain memset() as a dead store.
 */
static inline void memzero_explicit(void *s, size_t count)
{
	memset(s, 0, count);
	barrier_data(s);
}

/*
 * 0 when the size bytes at a and b are equal and 1 when they differ, in
 * a time that depends on size alone, for comparing a secret or a value
 * derived from one, where memcmp() returns at the first difference.
 */
static inline int memneq_explicit(const void *a, const void *b, size_t size)
{
	const __u8 *pa = a, *pb = b;
	__u8 neq = 0;
	size_t i;

	for (i = 0; i < size; i++) {
		neq |= pa[i] ^ pb[i];
		OPTIMIZER_HIDE_VAR(neq);
	}
	return neq != 0;
}

/*
 * What the functions above replace, refused once the headers included
 * above have declared it, so that a later include of those still works;
 * util/string.c and the xasprintf() of util/malloc.c opt out with
 * STRING_INTERNAL. With them go the functions of the C library that work
 * on a string and that nothing here calls: one comes off the list with
 * the first caller that needs it.
 */
#ifndef STRING_INTERNAL
# pragma GCC poison strtol strtoll strtoul strtoull strtoimax strtoumax
# pragma GCC poison strtod strtof strtold atoi atol atoll atof
# pragma GCC poison strtoq strtouq scanf fscanf sscanf vscanf vfscanf vsscanf
# pragma GCC poison strcpy strncpy strcat strncat strlcpy
# pragma GCC poison stpcpy stpncpy strlcat memccpy bcopy
# pragma GCC poison strncmp strncasecmp strcasecmp strcoll strxfrm bcmp
# pragma GCC poison strtok strtok_r strsep
# pragma GCC poison strspn strcspn strcasestr strchrnul strverscmp
# pragma GCC poison rawmemchr rindex
# pragma GCC poison strfry memfrob bzero gets
/*
 * glibc makes these macros, the last two under C23; poison the names
 * alone.
 */
# undef strdupa
# undef strndupa
# undef strpbrk
# undef strstr
# pragma GCC poison strdupa strndupa strpbrk strstr
/* Fortified glibc makes these macros for clang; poison the names alone. */
# undef sprintf
# undef snprintf
# pragma GCC poison sprintf vsprintf snprintf vsnprintf
# pragma GCC poison explicit_bzero
#endif

#endif /* SHIRUDO_STRING_H */
