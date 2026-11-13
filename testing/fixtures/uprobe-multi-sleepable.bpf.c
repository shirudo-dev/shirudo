// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} hits SEC(".maps");

char _license[] SEC("license") = "Dual BSD/GPL";

/*
 * The verifier offers bpf_copy_from_user() to sleepable programs alone,
 * so a load proves the loader set BPF_F_SLEEPABLE.
 */
SEC("uprobe.multi.s//tmp/shirudo-test-uprobe-target:*Func")
int probe_sleepable(struct pt_regs *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	__u32 key = 0;
	__u64 *value;
	char c;

	if (bpf_copy_from_user(&c, sizeof(c), (void *)task->mm->arg_start))
		return 0;
	value = bpf_map_lookup_elem(&hits, &key);
	if (value)
		__sync_fetch_and_add(value, 1);
	return 0;
}
