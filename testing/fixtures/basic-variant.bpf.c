// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

__u64 shirudo_test_basic_calls;

/* Another build of basic.bpf.c, with the same program and a new payload */
SEC("fentry/do_nanosleep")
int BPF_PROG(shirudo_test_basic)
{
	__sync_fetch_and_add(&shirudo_test_basic_calls, 1);
	return 0;
}
