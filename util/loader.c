// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * .incbin embedding of the bpf/ objects shipped inside shirudo.
 */

#include <stddef.h>

#include "loader.h"

asm(".section .rodata, \"a\"\n"
	".global shirudo_bpf2_o; shirudo_bpf2_o:\n"
	".incbin \"bpf/bpf2.bpf.o\"\n"
	".global shirudo_bpf2_o_end; shirudo_bpf2_o_end:\n"
	".previous\n");

asm(".section .rodata, \"a\"\n"
	".global shirudo_seal_o; shirudo_seal_o:\n"
	".incbin \"bpf/seal.bpf.o\"\n"
	".global shirudo_seal_o_end; shirudo_seal_o_end:\n"
	".previous\n");

asm(".section .rodata, \"a\"\n"
	".global shirudo_unload_bpf_o; shirudo_unload_bpf_o:\n"
	".incbin \"bpf/unload.bpf.o\"\n"
	".global shirudo_unload_bpf_o_end; shirudo_unload_bpf_o_end:\n"
	".previous\n");


static const struct shirudo_embedded_bpf bpf2 = {
	.name = "bpf2",
	.data = shirudo_bpf2_o,
	/*
	 * .size set at use-time -- end pointer arithmetic isn't a
	 * constant expression.
	 */
};

static const struct shirudo_embedded_bpf seal = {
	.name = "seal",
	.data = shirudo_seal_o,
};

static const struct shirudo_embedded_bpf unload = {
	.name = "unload",
	.data = shirudo_unload_bpf_o,
};

const struct shirudo_embedded_bpf *bpf2_blob(void)
{
	static struct shirudo_embedded_bpf b;

	b = bpf2;
	b.size = (size_t)(shirudo_bpf2_o_end - shirudo_bpf2_o);
	return &b;
}

const struct shirudo_embedded_bpf *seal_blob(void)
{
	static struct shirudo_embedded_bpf b;

	b = seal;
	b.size = (size_t)(shirudo_seal_o_end - shirudo_seal_o);
	return &b;
}

const struct shirudo_embedded_bpf *unload_blob(void)
{
	static struct shirudo_embedded_bpf b;

	b = unload;
	b.size = (size_t)(shirudo_unload_bpf_o_end - shirudo_unload_bpf_o);
	return &b;
}
