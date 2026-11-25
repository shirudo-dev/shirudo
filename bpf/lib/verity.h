/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_BPF_VERITY_H
#define SHIRUDO_BPF_VERITY_H

#include "lsm.h"
#include "../include/shirudo/runtime_entry.h"

#define DEVICE_RUNTIME		1
#define DEVICE_CONFIG		2

struct verity_device {
	__u32	dev;
	__u32	kind;
	__u8	root[32];
	__u64	diskseq;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, __u64);
	__type(value, struct verity_device);
} shirudo_devices SEC(".maps");

/* Trusted userspace records the expected root for the preparing task. */
struct expected_root {
	__u8	root[32];
	__u32	valid;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct expected_root);
} shirudo_roots SEC(".maps");

struct inode *bpf_real_data_inode(struct file *file) __ksym;

static __always_inline bool shirudo_bootstrap_task(void)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct task_authority *authority;

	authority = bpf_task_storage_get(&shirudo_tasks, task, NULL, 0);
	return authority && authority->trusted == TASK_BOOTSTRAP;
}

#define PF_DUMPCORE		0x00000200
#define MMF_HAS_UPROBES		19

/* A task loses authority for good, and the cause is counted once. */
static __always_inline bool shirudo_revoke(struct task_authority *authority,
					   enum tamper_point point)
{
	if (!authority->revoked) {
		authority->revoked = 1;
		shirudo_tamper_count(point);
	}
	return false;
}

/*
 * A uprobe that reaches a task's memory, set through tracefs or perf
 * where no hook sees it, has the kernel add to a counter in the task's
 * writable data at every exec and registration: what the program then
 * reads is no longer what the runtime image holds.
 */
static __always_inline bool shirudo_mm_has_uprobes(struct task_struct *task)
{
	unsigned long flags = BPF_CORE_READ(task, mm, flags.__mm_flags[0]);

	return flags & (1UL << MMF_HAS_UPROBES);
}

/*
 * The mark changes only when exec commits, so failed exec keeps authority.
 * An exec that fails after its commit dumps core, and so does a crash:
 * the dump runs as the task and unlinks and creates the file
 * core_pattern names, which is root's choice, not the program's.
 */
static __always_inline bool shirudo_task_is_self(const struct sb_id *id)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct task_authority *authority;

	authority = bpf_task_storage_get(&shirudo_tasks, task, NULL, 0);
	if (!authority || !authority->trusted || authority->revoked)
		return false;
	if (BPF_CORE_READ(task, flags) & PF_DUMPCORE)
		return shirudo_revoke(authority, TAMPER_SEAL_CORE_DUMP);
	if (shirudo_mm_has_uprobes(task))
		return shirudo_revoke(authority, TAMPER_SEAL_UPROBE);
	return true;
}

static __always_inline bool
shirudo_protected_filesystem(const struct sb_id *id, __u32 dev)
{
	return dev == id->sb_dev || (id->run_dev && dev == id->run_dev);
}

/* Device pointers can be reused even when the free hook did not run. */
static __always_inline struct verity_device *
shirudo_bdev_device(struct block_device *bdev)
{
	struct verity_device *device;
	__u64 cookie = (__u64)bdev;

	if (!bdev)
		return NULL;
	device = bpf_map_lookup_elem(&shirudo_devices, &cookie);
	if (!device || !device->diskseq ||
	    device->dev != BPF_CORE_READ(bdev, bd_dev) ||
	    device->diskseq != BPF_CORE_READ(bdev, bd_disk, diskseq))
		return NULL;
	return device;
}

static __always_inline struct verity_device *
shirudo_inode_device(struct inode *inode)
{
	struct block_device *bdev;
	struct super_block *sb;

	if (!inode)
		return NULL;
	sb = BPF_CORE_READ(inode, i_sb);
	if (!sb || !(BPF_CORE_READ(sb, s_flags) & 1))
		return NULL;
	bdev = BPF_CORE_READ(sb, s_bdev);
	if (!bdev)
		return NULL;
	return shirudo_bdev_device(bdev);
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct shirudo_runtime_entry);
} shirudo_rt_ent SEC(".maps");

/* A file of the runtime image the bootstrap bound. */
static __always_inline bool shirudo_file_runtime(struct file *file)
{
	struct verity_device *device;
	__u32 zero = 0;

	if (!file)
		return false;
	device = shirudo_inode_device(BPF_CORE_READ(file, f_inode));
	return device && device->kind == DEVICE_RUNTIME &&
	       shirudo_runtime_entry_matches(bpf_map_lookup_elem(&shirudo_rt_ent, &zero),
					     device->dev, device->diskseq);
}

/*
 * Fresh full authority: exec of the bound entry inode. A task that already
 * holds the role keeps it across exec of another file of the same runtime.
 */
static __always_inline bool shirudo_file_runtime_entry(struct file *file,
						       bool trusted)
{
	struct verity_device *device;
	__u32 zero = 0;

	if (!file)
		return false;
	device = shirudo_inode_device(BPF_CORE_READ(file, f_inode));
	if (!device || device->kind != DEVICE_RUNTIME)
		return false;
	return shirudo_runtime_may_exec(bpf_map_lookup_elem(&shirudo_rt_ent, &zero),
					BPF_CORE_READ(file, f_inode, i_ino),
					device->dev, device->diskseq, trusted,
					device->dev);
}

#endif /* SHIRUDO_BPF_VERITY_H */
