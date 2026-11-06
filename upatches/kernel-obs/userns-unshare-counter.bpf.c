// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 * Count calls to unshare that request a new user namespace.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define CLONE_NEWUSER 0x10000000UL

char _license[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} userns_unshare_calls SEC(".maps");

SEC("fentry/ksys_unshare")
int BPF_PROG(count_userns_unshare, unsigned long unshare_flags)
{
	__u32 zero = 0;
	__u64 *count;

	if (!(unshare_flags & CLONE_NEWUSER))
		return 0;

	count = bpf_map_lookup_elem(&userns_unshare_calls, &zero);
	if (count)
		(*count)++;

	return 0;
}
