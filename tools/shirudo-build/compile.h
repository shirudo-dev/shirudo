/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * execv of clang -target bpf for .bpf.c -> .bpf.o.
 */

#ifndef SHIRUDO_BUILD_COMPILE_H
#define SHIRUDO_BUILD_COMPILE_H

int shirudo_build_compile(const char *source, const char *output,
			  const char *vmlinux_h,
			  const char *extra_cflags,
			  const char *shirudo_bpf_incdir);

#endif /* SHIRUDO_BUILD_COMPILE_H */
