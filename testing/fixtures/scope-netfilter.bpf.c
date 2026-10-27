// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define NF_ACCEPT	1

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("netfilter")
int shirudo_test_scope_netfilter(struct bpf_nf_ctx *ctx)
{
	return NF_ACCEPT;
}
