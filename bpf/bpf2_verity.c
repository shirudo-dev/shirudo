// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

/*
 * Image mode authorizes tasks marked after exec from the authenticated runtime.
 * These extra hooks track verity devices, restrict DM controls, and protect the
 * runtime/config mounts alongside the shared bpffs and BPF admission checks.
 */
#include "verity_policy.h"
#include "admission.h"

char _license[] SEC("license") = "Dual BSD/GPL";

static __always_inline int shirudo_parent_mount(struct super_block *sb,
						bool trusted_target)
{
	struct shirudo_sb_id *id = shirudo_policy();

	if (!sb || !id || !id->run_dev ||
	    BPF_CORE_READ(sb, s_dev) != id->run_dev)
		return 0;
	return trusted_target && shirudo_task_is_self(id) ? 0 : -EPERM;
}

static __always_inline int shirudo_image_mount(struct super_block *sb,
					       bool replace)
{
	struct shirudo_sb_id *id = shirudo_policy();
	struct shirudo_device *device;
	struct block_device *bdev;

	if (!sb || !id)
		return 0;
	bdev = BPF_CORE_READ(sb, s_bdev);
	if (!bdev)
		return 0;
	device = shirudo_bdev_device(bdev);
	if (!device)
		return 0;
	if (replace && device->kind == SHIRUDO_DEVICE_CONFIG &&
	    shirudo_task_is_self(id))
		return 0;
	return -EPERM;
}

SEC("lsm/sb_umount")
int BPF_PROG(shirudo_lsm_sb_umount, struct vfsmount *mnt, int flags,
	     int ret)
{
	struct super_block *sb = BPF_CORE_READ(mnt, mnt_sb);
	__u32 dev;

	if (ret)
		return ret;
	ret = shirudo_parent_mount(sb, false);
	if (ret)
		return ret;
	if (BPF_CORE_READ_INTO(&dev, sb, s_dev))
		return shirudo_tamper_deny(SHIRUDO_TAMPER_BPFFS_UMOUNT,
					   -EPERM);
	ret = shirudo_deny_bpffs_mount(dev, SHIRUDO_TAMPER_BPFFS_UMOUNT);
	return ret ? ret : shirudo_image_mount(sb, true);
}

SEC("lsm/move_mount")
int BPF_PROG(shirudo_lsm_move_mount, const struct path *from_path,
	     const struct path *to_path, int ret)
{
	struct super_block *from = BPF_CORE_READ(from_path, mnt, mnt_sb);
	struct super_block *to = BPF_CORE_READ(to_path, mnt, mnt_sb);

	if (ret)
		return ret;
	if (shirudo_parent_mount(from, false) ||
	    shirudo_parent_mount(to, true))
		return -EPERM;
	if (shirudo_deny_bpffs_mount(BPF_CORE_READ(from, s_dev),
				     SHIRUDO_TAMPER_BPFFS_MOUNT) ||
	    shirudo_deny_bpffs_mount(BPF_CORE_READ(to, s_dev),
				     SHIRUDO_TAMPER_BPFFS_MOUNT))
		return -EPERM;
	ret = shirudo_image_mount(from, true);
	return ret ? ret : shirudo_image_mount(to, true);
}

SEC("lsm/sb_mount")
int BPF_PROG(shirudo_lsm_sb_mount, const char *dev_name,
	     const struct path *path, const char *type,
	     unsigned long flags, void *data, int ret)
{
	struct super_block *sb = BPF_CORE_READ(path, mnt, mnt_sb);

	if (ret)
		return ret;
	if ((flags & ((1UL << 17) | (1UL << 18) | (1UL << 19) |
		      (1UL << 20))) && shirudo_parent_mount(sb, false))
		return -EPERM;
	ret = shirudo_parent_mount(sb, true);
	if (ret)
		return ret;
	ret = shirudo_deny_bpffs_mount(BPF_CORE_READ(sb, s_dev),
				       SHIRUDO_TAMPER_BPFFS_MOUNT);
	return ret ? ret : shirudo_image_mount(sb, true);
}

SEC("lsm/sb_remount")
int BPF_PROG(shirudo_lsm_sb_remount, struct super_block *sb,
	     void *mnt_opts, int ret)
{
	if (ret)
		return ret;
	ret = shirudo_parent_mount(sb, false);
	if (ret)
		return ret;
	ret = shirudo_deny_bpffs_mount(BPF_CORE_READ(sb, s_dev),
				       SHIRUDO_TAMPER_BPFFS_MOUNT);
	return ret ? ret : shirudo_image_mount(sb, false);
}

struct dm_verity_digest___shirudo {
	const char *alg;
	const __u8 *digest;
	size_t digest_len;
} __attribute__((preserve_access_index));

/*
 * Runtime roots match the frozen UKI value. Config roots must match the current
 * trusted task's one-use expectation; unrelated mappings gain no status.
 */
SEC("lsm.s/bdev_setintegrity")
int BPF_PROG(shirudo_lsm_bdev_setintegrity, struct block_device *bdev,
	     enum lsm_integrity_type type, const void *value,
	     size_t size, int ret)
{
	const struct dm_verity_digest___shirudo *digest = value;
	struct shirudo_sb_id *id = shirudo_policy();
	struct shirudo_expected_root *expected;
	struct shirudo_device device = {};
	__u64 cookie = (__u64)bdev;
	const unsigned char *root;
	const char *algorithm;
	unsigned int i;
	char name[8];
	int diff;

	if (ret)
		return ret;
	if (!id || type != LSM_INT_DMVERITY_ROOTHASH)
		return 0;
	if (!value) {
		bpf_map_delete_elem(&shirudo_devices, &cookie);
		return 0;
	}
	if (shirudo_bdev_device(bdev))
		return -EPERM;
	if (BPF_CORE_READ(digest, digest_len) != sizeof(device.root))
		return 0;
	algorithm = BPF_CORE_READ(digest, alg);
	if (bpf_probe_read_kernel_str(name, sizeof(name), algorithm) != 7 ||
	    name[0] != 's' || name[1] != 'h' || name[2] != 'a' ||
	    name[3] != '2' || name[4] != '5' || name[5] != '6')
		return 0;
	root = BPF_CORE_READ(digest, digest);
	if (bpf_probe_read_kernel(device.root, sizeof(device.root), root))
		return -EACCES;
	diff = 0;
	for (i = 0; i < sizeof(device.root); i++)
		diff |= device.root[i] ^ id->runtime_root[i];
	if (!diff) {
		device.kind = SHIRUDO_DEVICE_RUNTIME;
	} else {
		if (!shirudo_task_is_self(id))
			return 0;
		expected = bpf_task_storage_get(&shirudo_roots,
						bpf_get_current_task_btf(),
						NULL, 0);
		if (!expected || !expected->valid)
			return 0;
		diff = 0;
		for (i = 0; i < sizeof(device.root); i++)
			diff |= device.root[i] ^ expected->root[i];
		if (diff)
			return 0;
		expected->valid = 0;
		device.kind = SHIRUDO_DEVICE_CONFIG;
	}
	device.dev = BPF_CORE_READ(bdev, bd_dev);
	device.diskseq = BPF_CORE_READ(bdev, bd_disk, diskseq);
	if (!device.diskseq)
		return -EACCES;
	if (bpf_map_update_elem(&shirudo_devices, &cookie, &device,
				BPF_ANY))
		return -ENOMEM;
	return 0;
}

SEC("lsm/bdev_free_security")
void BPF_PROG(shirudo_lsm_bdev_free_security, struct block_device *bdev)
{
	__u64 cookie = (__u64)bdev;

	bpf_map_delete_elem(&shirudo_devices, &cookie);
}

#define SHIRUDO_DM_CONTROL_DEV	((10U << 20) | 236U)
#define SHIRUDO_DM_IOCTL_TYPE	0xfdU

/* Match the kernel's type/number dispatch. */
static __always_inline int shirudo_dm_ioctl(struct file *file,
					    unsigned int cmd, int ret)
{
	struct shirudo_sb_id *id = shirudo_policy();
	struct inode *inode;

	if (ret || !id || shirudo_task_is_self(id))
		return ret;
	inode = BPF_CORE_READ(file, f_inode);
	if ((BPF_CORE_READ(inode, i_mode) & 0170000) != 0020000 ||
	    BPF_CORE_READ(inode, i_rdev) != SHIRUDO_DM_CONTROL_DEV)
		return 0;
	if (((cmd >> 8) & 0xff) != SHIRUDO_DM_IOCTL_TYPE)
		return -EPERM;
	switch (cmd & 0xff) {
	case 0:  /* DM_VERSION */
	case 2:  /* DM_LIST_DEVICES */
	case 7:  /* DM_DEV_STATUS */
	case 8:  /* DM_DEV_WAIT */
	case 11: /* DM_TABLE_DEPS */
	case 12: /* DM_TABLE_STATUS */
	case 13: /* DM_LIST_VERSIONS */
	case 17: /* DM_GET_TARGET_VERSION */
		return 0;
	default:
		return -EPERM;
	}
}

SEC("lsm/file_ioctl")
int BPF_PROG(shirudo_lsm_file_ioctl, struct file *file, unsigned int cmd,
	     unsigned long arg, int ret)
{
	return shirudo_dm_ioctl(file, cmd, ret);
}
