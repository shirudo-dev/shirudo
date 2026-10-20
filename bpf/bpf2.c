// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

/*
 * Ordinary mode records executable device/inode identities at init. The common
 * admission checks also protect the bpffs and its payload xattrs. File labels
 * and task observation checks live in the matching seal object.
 */
#include "policy.h"
#include "admission.h"

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("lsm/sb_umount")
int BPF_PROG(shirudo_lsm_sb_umount, struct vfsmount *mnt, int flags,
	     int ret)
{
	__u32 dev;

	if (ret)
		return ret;
	if (BPF_CORE_READ_INTO(&dev, mnt, mnt_sb, s_dev))
		return shirudo_tamper_deny(SHIRUDO_TAMPER_BPFFS_UMOUNT,
					   -EPERM);
	return shirudo_deny_bpffs_mount(dev, SHIRUDO_TAMPER_BPFFS_UMOUNT);
}

SEC("lsm/move_mount")
int BPF_PROG(shirudo_lsm_move_mount, const struct path *from_path,
	     const struct path *to_path, int ret)
{
	__u32 from_dev = BPF_CORE_READ(from_path, mnt, mnt_sb, s_dev);
	__u32 to_dev = BPF_CORE_READ(to_path, mnt, mnt_sb, s_dev);

	if (ret)
		return ret;
	if (shirudo_deny_bpffs_mount(from_dev, SHIRUDO_TAMPER_BPFFS_MOUNT))
		return -EPERM;
	return shirudo_deny_bpffs_mount(to_dev, SHIRUDO_TAMPER_BPFFS_MOUNT);
}

SEC("lsm/sb_mount")
int BPF_PROG(shirudo_lsm_sb_mount, const char *dev_name,
	     const struct path *path, const char *type,
	     unsigned long flags, void *data, int ret)
{
	if (ret)
		return ret;
	return shirudo_deny_bpffs_mount(BPF_CORE_READ(path, mnt, mnt_sb, s_dev),
					SHIRUDO_TAMPER_BPFFS_MOUNT);
}

SEC("lsm/sb_remount")
int BPF_PROG(shirudo_lsm_sb_remount, struct super_block *sb,
	     void *mnt_opts, int ret)
{
	if (ret)
		return ret;
	return shirudo_deny_bpffs_mount(BPF_CORE_READ(sb, s_dev),
					SHIRUDO_TAMPER_BPFFS_MOUNT);
}
