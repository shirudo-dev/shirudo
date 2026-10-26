/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Read the signed .rodata initial value from a gen_loader upatch.
 */

#ifndef SHIRUDO_UTIL_UPATCH_RODATA_H
#define SHIRUDO_UTIL_UPATCH_RODATA_H

#include <stdbool.h>

#include "upatch.h"

struct shirudo_rodata_range {
	__u32 offset;
	__u32 size;
};

int upatch_rodata_print(const struct shirudo_upatch *u, const char *path,
			bool json);
int upatch_rodata_symbol_range(const struct shirudo_upatch *u,
			       const char *symbol,
			       struct shirudo_rodata_range *range);
int upatch_rodata_data_offset(const struct shirudo_upatch *u, __u32 *offset);
int upatch_rodata_watch_ranges(const struct shirudo_upatch *u,
			       struct shirudo_rodata_range ranges[2]);

#endif /* SHIRUDO_UTIL_UPATCH_RODATA_H */
