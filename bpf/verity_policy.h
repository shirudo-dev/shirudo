/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_BPF_VERITY_POLICY_H
#define SHIRUDO_BPF_VERITY_POLICY_H

#include "lsm.h"

#define SHIRUDO_DEVICE_RUNTIME		1
#define SHIRUDO_DEVICE_CONFIG		2

struct shirudo_device {
	__u32	dev;
	__u32	kind;
	__u8	root[32];
	__u64	diskseq;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, __u64);
	__type(value, struct shirudo_device);
} shirudo_devices SEC(".maps");

/* Trusted userspace records the expected root for the preparing task. */
struct shirudo_expected_root {
	__u8	root[32];
	__u32	valid;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct shirudo_expected_root);
} shirudo_roots SEC(".maps");

struct inode *bpf_real_data_inode(struct file *file) __ksym;

static __always_inline bool shirudo_bootstrap_task(void)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct shirudo_task_authority *authority;

	authority = bpf_task_storage_get(&shirudo_tasks, task, NULL, 0);
	return authority && authority->trusted == SHIRUDO_TASK_BOOTSTRAP;
}

/* The mark changes only when exec commits, so failed exec keeps authority. */
static __always_inline bool shirudo_task_is_self(const struct shirudo_sb_id *id)
{
	return shirudo_marked(bpf_get_current_task_btf());
}

static __always_inline bool
shirudo_protected_filesystem(const struct shirudo_sb_id *id, __u32 dev)
{
	return dev == id->sb_dev || (id->run_dev && dev == id->run_dev);
}

/* Device records expose pointers and belong only to trusted image tasks. */
static __always_inline bool shirudo_private_map(struct bpf_map *map)
{
	char name[16] = {};

	bpf_probe_read_kernel_str(name, sizeof(name), map->name);
	return !__builtin_memcmp(name, "shirudo_devices", sizeof(name));
}

/* Device pointers can be reused even when the free hook did not run. */
static __always_inline struct shirudo_device *
shirudo_bdev_device(struct block_device *bdev)
{
	struct shirudo_device *device;
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

static __always_inline struct shirudo_device *
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

static __always_inline bool shirudo_file_runtime(struct file *file)
{
	struct shirudo_device *device;

	if (!file)
		return false;
	device = shirudo_inode_device(BPF_CORE_READ(file, f_inode));
	return device && device->kind == SHIRUDO_DEVICE_RUNTIME;
}

#endif /* SHIRUDO_BPF_VERITY_POLICY_H */
