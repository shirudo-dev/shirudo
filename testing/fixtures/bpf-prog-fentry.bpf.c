// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} bpf_fentry_hits SEC(".maps");

/* Built against basic.bpf.c, runs whenever its program does */
SEC("fentry/shirudo_test_basic")
int BPF_PROG(shirudo_test_bpf_fentry)
{
	__u32 key = 0;
	__u64 *hits;

	hits = bpf_map_lookup_elem(&bpf_fentry_hits, &key);
	if (hits)
		__sync_fetch_and_add(hits, 1);
	return 0;
}
