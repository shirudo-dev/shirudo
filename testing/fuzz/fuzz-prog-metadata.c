// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * prog_specs_parse() on a load upatch's signed program metadata.
 */

#include <stdint.h>
#include <string.h>

#include "fuzz.h"
#include "upatch.h"

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct upatch_prog_metadata md;
	struct prog_spec *specs;
	__u32 nr_maps = 0, nr_progs = 0;

	if (size > UINT32_MAX)
		return 0;
	/* The header claims the counts the container's header must match. */
	if (size >= sizeof(md)) {
		memcpy(&md, data, sizeof(md));
		nr_maps = le32_to_cpu(md.nr_maps);
		nr_progs = le32_to_cpu(md.nr_progs);
	}
	if (!prog_specs_parse(data, (__u32)size, nr_maps, nr_progs, &specs))
		prog_specs_free(specs, nr_progs);
	return 0;
}
