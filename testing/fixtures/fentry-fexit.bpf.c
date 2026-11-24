// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

/* A length that only t3118 and t3119 pass to fallocate(2) in the VM. */
#define TEST_LEN 1234567

enum {
	ENTRY_CALLS,
	ENTRY_INODE,
	EXIT_OK,
	EXIT_FAILED,
	EXIT_ERRNO,
	EXIT_OFFSET,
	NR_SEEN,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_SEEN);
	__type(key, __u32);
	__type(value, __u64);
} seen SEC(".maps");

static __always_inline void count(__u32 slot)
{
	__u64 *value = bpf_map_lookup_elem(&seen, &slot);

	if (value)
		__sync_fetch_and_add(value, 1);
}

static __always_inline void store(__u32 slot, __u64 last)
{
	__u64 *value = bpf_map_lookup_elem(&seen, &slot);

	if (value)
		*value = last;
}

SEC("fentry/vfs_fallocate")
int BPF_PROG(see_entry, struct file *file, int mode, loff_t offset,
	     loff_t len)
{
	if (len != TEST_LEN)
		return 0;
	count(ENTRY_CALLS);
	store(ENTRY_INODE, file->f_inode->i_ino);
	return 0;
}

SEC("fexit/vfs_fallocate")
int BPF_PROG(see_exit, struct file *file, int mode, loff_t offset,
	     loff_t len, int ret)
{
	if (len != TEST_LEN)
		return 0;
	if (!ret) {
		count(EXIT_OK);
		return 0;
	}
	count(EXIT_FAILED);
	store(EXIT_ERRNO, -ret);
	store(EXIT_OFFSET, offset);
	return 0;
}
