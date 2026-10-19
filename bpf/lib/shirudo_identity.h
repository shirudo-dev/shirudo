/* SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0) */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The identity record shirudo init freezes, shared by the bpf2 and seal
 * objects. Include it after vmlinux.h and the libbpf BPF headers.
 */

#ifndef SHIRUDO_BPF_IDENTITY_H
#define SHIRUDO_BPF_IDENTITY_H

/*
 * Frozen identity record, populated by `shirudo init` before the programs
 * attach: the private bpffs superblock device, the (dev, ino) of shirudo's
 * own executable, and the serial and kind (enum bpf_sig_keyring) of the
 * sealed keyring a signed load must have been verified against. Must match
 * struct shirudo_identity in util/identity.h byte-for-byte.
 */
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
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct shirudo_sb_id);
} shirudo_bpffs_sb SEC(".maps");

/*
 * Whether the calling task runs shirudo's own executable, the one
 * recorded at init, or the initrd's copy of it while that finishes
 * init. A task without an executable is not shirudo.
 */
static __always_inline bool shirudo_task_is_self(const struct shirudo_sb_id *id)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct file *exe = BPF_CORE_READ(task, mm, exe_file);
	__u32 exe_dev;
	__u64 exe_ino;

	if (!exe)
		return false;
	exe_dev = BPF_CORE_READ(exe, f_inode, i_sb, s_dev);
	exe_ino = BPF_CORE_READ(exe, f_inode, i_ino);
	if (exe_dev == id->exe_dev && exe_ino == id->exe_ino)
		return true;
	return id->alt_exe_ino && exe_dev == id->alt_exe_dev &&
	       exe_ino == id->alt_exe_ino;
}

#endif /* SHIRUDO_BPF_IDENTITY_H */
