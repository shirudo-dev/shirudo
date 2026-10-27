// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "nv-writer-fault.h"

#define EIO	5
#define EBADMSG	74

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct nv_writer_fault);
} fault SEC(".maps");

static __always_inline struct nv_writer_fault *current_fault(void)
{
	struct nv_writer_fault *state;
	__u32 zero = 0;

	state = bpf_map_lookup_elem(&fault, &zero);
	if (!state || state->pid != bpf_get_current_pid_tgid() >> 32)
		return NULL;
	return state;
}

SEC("lsm/key_alloc")
int BPF_PROG(fail_writer_import, struct key *key, const struct cred *cred,
	     unsigned long flags, int ret)
{
	char description[sizeof("shirudo.nv-writer") + 1] = {};
	struct nv_writer_fault *state;

	if (ret)
		return ret;
	state = current_fault();
	if (!state)
		return 0;
	if (bpf_probe_read_kernel_str(description, sizeof(description),
				      BPF_CORE_READ(key, description)) !=
	    sizeof("shirudo.nv-writer") ||
	    __builtin_memcmp(description, "shirudo.nv-writer", sizeof("shirudo.nv-writer")))
		return 0;
	state->imports++;
	if (!state->fail_import)
		return 0;
	state->failures++;
	return -EBADMSG;
}

SEC("lsm/bpf")
int BPF_PROG(fail_writer_map, int cmd, union bpf_attr *attr,
	     unsigned int size, bool kernel, int ret)
{
	struct nv_writer_fault *state;

	if (ret)
		return ret;
	state = current_fault();
	if (!state || !state->imports || kernel || !state->command ||
	    state->command != (__u32)cmd)
		return 0;
	state->failures++;
	return -EIO;
}

char _license[] SEC("license") = "Dual BSD/GPL";
