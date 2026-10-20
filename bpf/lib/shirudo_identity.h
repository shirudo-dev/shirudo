/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_BPF_IDENTITY_H
#define SHIRUDO_BPF_IDENTITY_H

/* Frozen ABI shared with struct shirudo_identity in util/identity.h. */
#define SHIRUDO_IDENTITY_KEYS_MAX	16

struct shirudo_sb_id {
	__u32	sb_dev;
	__u32	exe_dev;
	__u64	exe_ino;
	__s32	keyring_serial;
	__u32	keyring_type;
	__u32	alt_exe_dev;
	__u32	pad;
	__u64	alt_exe_ino;
	__u32	n_keys;
	__u32	pad2;
	__s32	key_serials[SHIRUDO_IDENTITY_KEYS_MAX];
	__u32	runtime_mode;
	__u32	run_dev;
	__u8	runtime_root[32];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct shirudo_sb_id);
} shirudo_bpffs_sb SEC(".maps");

static __always_inline bool shirudo_file_is_self(const struct shirudo_sb_id *id,
						 struct file *file)
{
	__u32 dev;
	__u64 ino;

	if (!file)
		return false;
	dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
	ino = BPF_CORE_READ(file, f_inode, i_ino);
	if (dev == id->exe_dev && ino == id->exe_ino)
		return true;
	return id->alt_exe_ino && dev == id->alt_exe_dev &&
	       ino == id->alt_exe_ino;
}

static __always_inline bool shirudo_task_matches_exe(const struct shirudo_sb_id *id)
{
	struct task_struct *task = bpf_get_current_task_btf();

	return shirudo_file_is_self(id, BPF_CORE_READ(task, mm, exe_file));
}

#endif /* SHIRUDO_BPF_IDENTITY_H */
