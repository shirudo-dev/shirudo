// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Zeroing allocator (see util/malloc.h).
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Implements the wrappers; opt out of the poison pragma in malloc.h. */
#define SHIRUDO_MALLOC_INTERNAL
#include "malloc.h"

void *xmalloc(size_t size)
{
	/*
	 * calloc zero-initialises. Treat a zero request as one byte so a
	 * NULL return means out-of-memory and nothing else.
	 */
	return calloc(1, size ? size : 1);
}

void *xcalloc(size_t nmemb, size_t size)
{
	/*
	 * Reject a multiply that would wrap before it reaches the
	 * allocator -- a caller computing nmemb * size itself would miss
	 * it. xmalloc() zero-initialises and handles the zero case.
	 */
	if (nmemb && size && nmemb > SIZE_MAX / size)
		return NULL;
	return xmalloc(nmemb * size);
}

void *xreallocarray(void *ptr, size_t old_nmemb, size_t new_nmemb,
		    size_t size)
{
	size_t old_size, new_size, copy;
	void *out;

	if (size && (new_nmemb > SIZE_MAX / size ||
		     old_nmemb > SIZE_MAX / size))
		return NULL;		/* overflow -- leave ptr untouched */
	old_size = old_nmemb * size;
	new_size = new_nmemb * size;

	out = xmalloc(new_size);	/* zeroed; the grown tail starts at 0 */
	if (!out)
		return NULL;		/* failure -- leave ptr untouched */
	if (ptr) {
		copy = old_size < new_size ? old_size : new_size;
		memcpy(out, ptr, copy);
		xfree(ptr, old_size);	/* scrub old block before release */
	}
	return out;
}

char *xstrdup(const char *s)
{
	size_t n;
	char *p;

	if (!s)
		return NULL;
	n = strlen(s) + 1;
	p = malloc(n);
	if (p)
		memcpy(p, s, n);
	return p;
}

char *xstrndup(const char *s, size_t n)
{
	size_t len;
	char *p;

	if (!s)
		return NULL;
	len = strnlen(s, n);
	p = malloc(len + 1);
	if (!p)
		return NULL;
	memcpy(p, s, len);
	p[len] = '\0';
	return p;
}

char *xasprintf(const char *fmt, ...)
{
	va_list ap;
	char *p;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (n < 0)
		return NULL;
	p = xmalloc((size_t)n + 1);
	if (!p)
		return NULL;
	va_start(ap, fmt);
	vsnprintf(p, (size_t)n + 1, fmt, ap);
	va_end(ap);
	return p;
}

#if defined(__SANITIZE_ADDRESS__)
#define SHIRUDO_ASAN	1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define SHIRUDO_ASAN	1
#endif
#endif

/*
 * ASan does not look inside explicit_bzero(), so a size that runs past
 * the allocation would go unreported in the sanitized builds and the
 * fuzzers: there the scrub goes through memset(), which it checks, by a
 * pointer the compiler cannot see through to drop it before free().
 */
static void scrub(void *ptr, size_t size)
{
#ifdef SHIRUDO_ASAN
	static void *(*volatile checked)(void *, int, size_t) = memset;

	checked(ptr, 0, size);
#else
	explicit_bzero(ptr, size);
#endif
}

void xfree(void *ptr, size_t size)
{
	if (!ptr)
		return;
	scrub(ptr, size);
	free(ptr);
}

void xstrfree(char *s)
{
	if (!s)
		return;
	scrub(s, strlen(s) + 1);
	free(s);
}

void libc_free(void *p)
{
	free(p);
}
