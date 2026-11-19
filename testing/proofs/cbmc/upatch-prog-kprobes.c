// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The attach metadata parser on arbitrary one-program tables large
 * enough for a kprobe multi block, with exact constant-size allocations
 * for every request these table lengths permit.
 */

#include <stddef.h>

static void *kprobe_malloc(size_t size);
static void *kprobe_calloc(size_t nmemb, size_t size);
static char *kprobe_strndup(const char *s, size_t len);
#define PROOF_XMALLOC kprobe_malloc
#define PROOF_XCALLOC kprobe_calloc
#define PROOF_XSTRNDUP kprobe_strndup

#include "upatch-prog-specs.c"

static void *kprobe_malloc(size_t size)
{
	if (size == 2)
		return xmalloc(2);
	if (size == 3)
		return xmalloc(3);
	if (size == 4)
		return xmalloc(4);
	if (size == 5)
		return xmalloc(5);
	if (size == 6)
		return xmalloc(6);
	__CPROVER_assert(false, "a symbol buffer of 2 to 6 bytes");
	return NULL;
}

static void *kprobe_calloc(size_t nmemb, size_t size)
{
	if (nmemb == 1 && size == sizeof(struct prog_spec))
		return xcalloc(1, sizeof(struct prog_spec));
	if (size == sizeof(const char *)) {
		if (nmemb == 1)
			return xcalloc(1, sizeof(const char *));
		if (nmemb == 2)
			return xcalloc(2, sizeof(const char *));
		if (nmemb == 3)
			return xcalloc(3, sizeof(const char *));
	}
	__CPROVER_assert(false, "one program or 1 to 3 symbol pointers");
	return NULL;
}

static char *kprobe_strndup(const char *s, size_t len)
{
	__CPROVER_assert(false, "no uprobe payload fits these metadata lengths");
	return NULL;
}
