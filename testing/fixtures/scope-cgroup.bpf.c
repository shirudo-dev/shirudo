// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("cgroup_skb/ingress")
int shirudo_test_scope_cgroup(struct __sk_buff *skb)
{
	return 1;
}
