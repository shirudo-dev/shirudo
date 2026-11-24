// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

#define EFBIG 27

/* As in fentry-fexit.bpf.c, which t3119 loads beside this. */
#define TEST_LEN 1234567

/*
 * vfs_fallocate() is a target only by the tag of a kernel built with
 * CONFIG_BPF_FMODRET_SCAN, and -EFBIG one of the errors the tag lists.
 */
SEC("fmod_ret/vfs_fallocate")
int BPF_PROG(refuse_test_len, struct file *file, int mode, loff_t offset,
	     loff_t len, int ret)
{
	if (len == TEST_LEN)
		return -EFBIG;
	return 0;
}
