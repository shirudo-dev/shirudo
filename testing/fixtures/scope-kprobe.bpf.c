// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_nanosleep")
int BPF_KPROBE(shirudo_test_scope_kprobe)
{
	return 0;
}
