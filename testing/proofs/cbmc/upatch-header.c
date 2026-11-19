// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The header of a .upatch, the target's first look at a file from disk or
 * a registry, for files of every size: util/upatch.c reads nothing past
 * the header, and the sections of a header it accepts lie inside the file
 * and behind the header, a BPF payload with its loader and a Java payload
 * with none of the loader's fields.
 */

#include "proof.h"
#include "../../../util/upatch.c"

static bool inside(__u32 off, __u32 len, size_t n)
{
	return (__u64)off + len <= n &&
	       (!len || off >= UPATCH_HEADER_SIZE);
}

void harness(void)
{
	struct upatch_host_header h;
	size_t n;
	__u8 *m;

	m = any_bytes(UPATCH_HEADER_SIZE);
	if (parse_header(m, n, &h))
		return;
	__CPROVER_assert(n >= UPATCH_HEADER_SIZE, "a whole header");
	__CPROVER_assert(h.magic == UPATCH_MAGIC &&
			 h.version == UPATCH_VERSION && !h.reserved1,
			 "its magic, version and zero reserved field");
	__CPROVER_assert(memchr(h.name, '\0', sizeof(h.name)),
			 "a terminated name");
	if (validate_bounds(&h, n))
		return;
	__CPROVER_assert(h.type == UPATCH_TYPE_BPF ||
			 h.type == UPATCH_TYPE_JAVA, "a known payload");
	__CPROVER_assert(inside(h.loader_insns_off, h.loader_insns_len, n) &&
			 inside(h.signature_off, h.signature_len, n) &&
			 inside(h.metadata_off, h.metadata_len, n) &&
			 inside(h.data_off, h.data_len, n),
			 "every section inside the file, behind the header");
	__CPROVER_assert(h.signature_len, "a signature");
	if (h.type == UPATCH_TYPE_JAVA) {
		__CPROVER_assert(!h.loader_insns_off && !h.loader_insns_len &&
				 !h.metadata_len && !h.log_buf_sz &&
				 !h.nr_maps && !h.nr_progs &&
				 !h.rodata_data_off && h.data_len,
				 "data alone, without a loader's fields");
		return;
	}
	__CPROVER_assert(h.loader_insns_len, "a loader");
	__CPROVER_assert(!(h.loader_insns_off % 8) &&
			 !(h.loader_insns_len % 8),
			 "whole, aligned instructions");
	__CPROVER_assert(h.rodata_data_off <= h.data_len,
			 ".rodata offset inside the data");
}
