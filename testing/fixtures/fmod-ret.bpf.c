// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

#define EOPNOTSUPP 95

/* A nice value that only t3119 asks for in the VM. */
#define TEST_NICE 17

/* security_*() is a target on every kernel, and its return value unchecked. */
SEC("fmod_ret/security_task_setnice")
int BPF_PROG(refuse_test_nice, struct task_struct *p, int nice, int ret)
{
	if (nice == TEST_NICE)
		return -EOPNOTSUPP;
	return 0;
}
