/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What the CBMC harnesses share: memory of any contents, which the
 * allocators of util/malloc.h cannot give as they zero what they hand out.
 */

#ifndef SHIRUDO_PROOF_H
#define SHIRUDO_PROOF_H

/*
 * glibc's <ctype.h> macros index a locale table CBMC has no body for; the
 * functions they stand for CBMC models in the C locale, the one shirudo
 * runs in.
 */
#define __NO_CTYPE 1

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <shirudo/types.h>

/*
 * glibc 2.43 makes these const-preserving _Generic macros under C23,
 * which a definition of the function cannot be spelled through.
 */
#undef memchr
#undef strstr

/*
 * CBMC models neither strnlen(), memchr(), strcspn(), strstr() nor
 * vsnprintf(), and a function without a body returns anything.
 */
size_t strnlen(const char *s, size_t max)
{
	size_t n = 0;

	while (n < max && s[n])
		n++;
	return n;
}

#ifdef PROOF_MEMCHR_QUANTIFIED
/*
 * For ranges of thousands of bytes, which a loop unrolls too slowly, where
 * the caller asks whether a byte is there and not where: NULL exactly when
 * none of the n bytes matches, n a constant, and otherwise any match. CBMC
 * ignores a quantifier over a range it cannot bound ("warning: ignoring
 * forall"), and then this may also return NULL where a byte matches.
 */
void *memchr(const void *s, int c, size_t n)
{
	const __u8 *p = s;
	size_t i;

	__CPROVER_assert(__CPROVER_r_ok(s, n), "memchr() reads its range");
	if (__CPROVER_forall { size_t j; j >= n || p[j] != (__u8)c })
		return NULL;
	__CPROVER_assume(i < n && p[i] == (__u8)c);
	return (void *)(p + i);
}
#else
void *memchr(const void *s, int c, size_t n)
{
	const __u8 *p = s;
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] == (__u8)c)
			return (void *)(p + i);
	return NULL;
}
#endif

size_t strcspn(const char *s, const char *reject)
{
	size_t n, i;

	for (n = 0; s[n]; n++)
		for (i = 0; reject[i]; i++)
			if (s[n] == reject[i])
				return n;
	return n;
}

char *strstr(const char *s, const char *needle)
{
	size_t n = strlen(needle);

	for (;; s++) {
		if (!strncmp(s, needle, n))
			return (char *)s;
		if (!*s)
			return NULL;
	}
}

static size_t format_char(char *buf, size_t size, size_t n, char c)
{
	if (n + 1 < size)
		buf[n] = c;
	return n + 1;
}

static size_t format_number(char *buf, size_t size, size_t n, __u64 v,
			    bool neg, __u32 base, size_t width, bool zero)
{
	size_t k = 0;
	char d[20];

	do {
		d[k++] = "0123456789abcdef"[base == 16 ? v & 15 : v % 10];
		v = base == 16 ? v >> 4 : v / 10;
	} while (v);
	for (; !zero && width > k + neg; width--)
		n = format_char(buf, size, n, ' ');
	if (neg)
		n = format_char(buf, size, n, '-');
	for (; zero && width > k + neg; width--)
		n = format_char(buf, size, n, '0');
	while (k)
		n = format_char(buf, size, n, d[--k]);
	return n;
}

/*
 * CBMC passes each variadic argument as an object of its own type, a
 * char not promoted to int, so an integer is read by its size, a char or
 * short as unsigned.
 */
static __u64 integer_arg(va_list *ap, bool is_signed, bool *neg)
{
	__s64 v;

	switch (__CPROVER_OBJECT_SIZE(*(void **)*ap)) {
	case 1:
		return va_arg(*ap, __u8);
	case 2:
		return va_arg(*ap, __u16);
	case 4:
		v = is_signed ? va_arg(*ap, __s32) : va_arg(*ap, __u32);
		break;
	default:
		if (!is_signed)
			return va_arg(*ap, __u64);
		v = va_arg(*ap, __s64);
	}
	*neg = v < 0;
	return *neg ? (__u64)-(v + 1) + 1 : (__u64)v;
}

/*
 * CBMC has no vsnprintf() either. This one formats what shirudo's proofs
 * reach, %s and the d, u and x conversions with a zero flag, a width and
 * ll, and fails the proof on any other.
 */
int vsnprintf(char *buf, size_t size, const char *fmt, va_list ap)
{
	size_t n = 0;

	for (; *fmt; fmt++) {
		bool zero = false, neg = false;
		size_t width = 0;
		const char *s;
		__u64 v;

		if (*fmt != '%' || fmt[1] == '%') {
			n = format_char(buf, size, n, *fmt);
			fmt += *fmt == '%';
			continue;
		}
		if (*++fmt == '0') {
			zero = true;
			fmt++;
		}
		while (*fmt >= '1' && *fmt <= '9' && width < 10)
			width = width * 10 + (size_t)(*fmt++ - '0');
		if (fmt[0] == 'l' && fmt[1] == 'l')
			fmt += 2;
		if (*fmt == 's') {
			__CPROVER_assert(!zero && !width,
					 "a plain %s in the vsnprintf() model");
			for (s = va_arg(ap, const char *); *s; s++)
				n = format_char(buf, size, n, *s);
			continue;
		}
		__CPROVER_assert(*fmt == 'd' || *fmt == 'u' || *fmt == 'x',
				 "a conversion the vsnprintf() model has");
		v = integer_arg(&ap, *fmt == 'd', &neg);
		n = format_number(buf, size, n, v, neg, *fmt == 'x' ? 16 : 10,
				  width, zero);
	}
	if (size)
		buf[n < size ? n : size - 1] = '\0';
	return (int)n;
}

/*
 * CBMC 5.95's memcpy() reads wrong bytes from a string literal when the
 * source pointer is one of several literals picked by symbolic data, and
 * so fails a proof the code meets. A harness that copies from such a
 * pointer defines PROOF_MEMCPY_BYTEWISE before including this header.
 */
#ifdef PROOF_MEMCPY_BYTEWISE
void *memcpy(void *dst, const void *src, size_t n)
{
	const __u8 *s = src;
	__u8 *d = dst;
	size_t i;

	for (i = 0; i < n; i++)
		d[i] = s[i];
	return dst;
}
#endif

static inline void *any_bytes(size_t size)
{
	void *p = __CPROVER_allocate(size, 0);

	__CPROVER_assume(p);
	return p;
}

/*
 * An input of len bytes, any len, for code that reads at most max of
 * them: it ends where its object does, so that a read past len fails the
 * proof, and one longer than max is its first max bytes.
 */
static inline void *any_input(size_t len, size_t max)
{
	__u8 *p = any_bytes(max);

	return len <= max ? p + max - len : p;
}

#ifdef PROOF_DEVICE_NUMBERS
#include <sys/sysmacros.h>
#include <sys/types.h>

/* glibc defines these inline only when it optimizes; its encoding. */
dev_t gnu_dev_makedev(__u32 major, __u32 minor)
{
	return ((dev_t)(major & 0x00000fffu) << 8) |
	       ((dev_t)(major & 0xfffff000u) << 32) |
	       (dev_t)(minor & 0x000000ffu) |
	       ((dev_t)(minor & 0xffffff00u) << 12);
}

__u32 gnu_dev_major(dev_t dev)
{
	return ((dev & 0x00000000000fff00ull) >> 8) |
	       ((dev & 0xfffff00000000000ull) >> 32);
}

__u32 gnu_dev_minor(dev_t dev)
{
	return (dev & 0x00000000000000ffull) |
	       ((dev & 0x00000ffffff00000ull) >> 12);
}
#endif

#ifdef PROOF_FILE
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

/*
 * A file of PROOF_FILE bytes of any contents, or of the proof_file_len a
 * harness cuts it to, which getline() reads line by line, into a buffer of
 * a size the solver need not track, or fails to read with an I/O or
 * allocation error, and pread() reads at any offset.
 */
static size_t proof_file_at, proof_file_len;
static __u8 *proof_file;

/*
 * CBMC's own errno takes any value at every read, which lets a loop that
 * retries on EINTR run for ever; this one keeps what was stored.
 */
static int proof_errno;

int *__errno_location(void)
{
	return &proof_errno;
}

static inline void proof_file_open(void)
{
	proof_file = any_bytes(PROOF_FILE);
	proof_file_len = PROOF_FILE;
	proof_file_at = 0;
}

ssize_t getline(char **line, size_t *cap, FILE *f)
{
	size_t n = 0;
	bool fail;
	char *p;

	if (fail) {
		errno = EIO;
		return -1;
	}
	if (proof_file_at == proof_file_len)
		return -1;
	while (proof_file_at + n < proof_file_len &&
	       proof_file[proof_file_at + n++] != '\n')
		;
	p = malloc(PROOF_FILE + 1);
	if (!p) {
		errno = ENOMEM;
		return -1;
	}
	memcpy(p, proof_file + proof_file_at, n);
	p[n] = '\0';
	free(*line);
	*line = p;
	*cap = PROOF_FILE + 1;
	proof_file_at += n;
	return n;
}

ssize_t pread(int fd, void *buf, size_t n, off_t off)
{
	if (off < 0 || (size_t)off >= proof_file_len)
		return 0;
	if (n > proof_file_len - (size_t)off)
		n = proof_file_len - (size_t)off;
	memcpy(buf, proof_file + off, n);
	return n;
}
#endif

#endif /* SHIRUDO_PROOF_H */
