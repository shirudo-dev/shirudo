// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

#define ESRCH 3

#define TEST_LEN 1234567

/* vfs_fallocate() never returns -ESRCH, so no tag of it lists the error. */
SEC("fmod_ret/vfs_fallocate")
int BPF_PROG(return_unlisted, struct file *file, int mode, loff_t offset,
	     loff_t len, int ret)
{
	if (len == TEST_LEN)
		return -ESRCH;
	return 0;
}
