/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Access to the BPF objects embedded into shirudo via .incbin.
 */

#ifndef SHIRUDO_LOADER_H
#define SHIRUDO_LOADER_H

#include <stddef.h>

/* Symbols provided by the embedded object assembly in loader.c. */
extern const char shirudo_bpf2_o[], shirudo_bpf2_o_end[];
extern const char shirudo_seal_o[], shirudo_seal_o_end[];
extern const char shirudo_unload_bpf_o[], shirudo_unload_bpf_o_end[];

struct shirudo_embedded_bpf {
	const char	*name;
	const void	*data;
	size_t		size;
};

const struct shirudo_embedded_bpf *bpf2_blob(void);
const struct shirudo_embedded_bpf *seal_blob(void);
const struct shirudo_embedded_bpf *unload_blob(void);

#endif /* SHIRUDO_LOADER_H */
