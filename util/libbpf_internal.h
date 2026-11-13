/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Internal libbpf declarations used by shirudo.
 */

#ifndef SHIRUDO_LIBBPF_INTERNAL_H
#define SHIRUDO_LIBBPF_INTERNAL_H

#include <stddef.h>

/* Shirudo's local version of libbpf's libbpf_internal.h. */
int elf_resolve_pattern_offsets(const char *binary_path,
				const char *pattern,
				unsigned long **poffsets,
				size_t *pcnt);
long elf_find_func_offset_from_file(const char *binary_path,
				    const char *name);

#endif /* SHIRUDO_LIBBPF_INTERNAL_H */
