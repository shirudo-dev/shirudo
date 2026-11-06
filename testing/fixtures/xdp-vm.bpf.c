// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp/8")
int xdp_vm(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
