// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "serializer.h"

char _license[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct serial_chunk);
} shirudo_ser SEC(".maps");

SEC("fentry/do_nanosleep")
int mixed_entry(void *ctx)
{
	return 0;
}

SEC("syscall")
int shirudo_serialize__events(struct serialize_ctx *ctx)
{
	return 0;
}

SEC("kprobe/do_nanosleep")
int mixed_probe(struct pt_regs *ctx)
{
	return 0;
}
