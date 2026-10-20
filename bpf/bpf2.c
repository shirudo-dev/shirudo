// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The central "BPF on BPF" LSM enforcement program. Every refusal is counted
 * at its point in the tamper map, which `shirudo status` reads back.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef EPERM
#define EPERM	1
#endif
#ifndef EACCES
#define EACCES	13
#endif
#ifndef ENOMEM
#define ENOMEM	12
#endif
#ifndef ENOSYS
#define ENOSYS	38
#endif
#ifndef FMODE_WRITE
#define FMODE_WRITE	0x2
#endif
#define LSM_UNSAFE_PTRACE	2
#define PR_SET_MM		35
#define PR_SET_MM_EXE_FILE	13
#define PR_SET_MM_MAP		14

char _license[] SEC("license") = "Dual BSD/GPL";

#include "policy.h"
#include "../include/shirudo_mode.h"
#include "shirudo_tamper.h"

/* The mode selects executable identity or committed task authority. */
static __always_inline int shirudo_self_or_deny(enum shirudo_tamper_point point)
{
	struct shirudo_sb_id *id;
	__u32 zero = 0;

	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (!id || !shirudo_task_is_self(id))
		return shirudo_tamper_deny(point, -EACCES);
	return 0;
}

SEC("lsm/bpf")
int BPF_PROG(shirudo_lsm_bpf, int cmd, union bpf_attr *attr,
	     unsigned int size, bool kernel, int ret)
{
	enum shirudo_tamper_point point;

	if (ret)
		return ret;
	if (kernel)
		return 0;

	switch (cmd) {
	case BPF_PROG_LOAD:
		if (BPF_CORE_READ(attr, prog_type) != BPF_PROG_TYPE_SYSCALL)
			point = SHIRUDO_TAMPER_LOAD_NOT_LOADER;
		else if (BPF_CORE_READ(attr, signature_size) == 0)
			point = SHIRUDO_TAMPER_LOAD_UNSIGNED;
		else
			return 0;
		return shirudo_tamper_deny(point, -EACCES);
	case BPF_MAP_CREATE:
		return shirudo_self_or_deny(SHIRUDO_TAMPER_MAP_CREATE);
	case BPF_MAP_UPDATE_ELEM:
	case BPF_MAP_FREEZE:
		return shirudo_self_or_deny(SHIRUDO_TAMPER_MAP_WRITE);
	case BPF_PROG_TEST_RUN:
		return shirudo_self_or_deny(SHIRUDO_TAMPER_PROG_RUN);
	case BPF_LINK_CREATE:
	case BPF_RAW_TRACEPOINT_OPEN:
		return shirudo_self_or_deny(SHIRUDO_TAMPER_ATTACH);
	case BPF_OBJ_PIN:
		return shirudo_self_or_deny(SHIRUDO_TAMPER_OBJ_PIN);
	/*
	 * Read-only/observability cmds, so `bpftool prog show`, `shirudo
	 * status`, and `shirudo upatch get/map` keep working.
	 */
	case BPF_MAP_LOOKUP_ELEM:
	case BPF_MAP_GET_NEXT_KEY:
	case BPF_MAP_LOOKUP_BATCH:
	case BPF_OBJ_GET:
	case BPF_OBJ_GET_INFO_BY_FD:
	case BPF_PROG_QUERY:
	case BPF_PROG_GET_NEXT_ID:
	case BPF_MAP_GET_NEXT_ID:
	case BPF_BTF_GET_NEXT_ID:
	case BPF_LINK_GET_NEXT_ID:
	case BPF_PROG_GET_FD_BY_ID:
	case BPF_MAP_GET_FD_BY_ID:
	case BPF_BTF_GET_FD_BY_ID:
	case BPF_LINK_GET_FD_BY_ID:
	case BPF_TASK_FD_QUERY:
		return 0;
	default:
		return shirudo_tamper_deny(SHIRUDO_TAMPER_BPF_CMD, -EACCES);
	}
}

SEC("lsm/bpf_map")
int BPF_PROG(shirudo_lsm_bpf_map, struct bpf_map *map, fmode_t fmode,
	     int ret)
{
	struct shirudo_sb_id *id = shirudo_policy();
	char name[16] = {};
	bool private;

	if (ret)
		return ret;
	bpf_probe_read_kernel_str(name, sizeof(name), map->name);
	private = !__builtin_memcmp(name, "shirudo_devices", 16);
	if (fmode & FMODE_WRITE)
		return shirudo_self_or_deny(SHIRUDO_TAMPER_MAP_FD);
	if (!private)
		return 0;
	if (!id || !shirudo_task_is_self(id))
		return -EACCES;
	return 0;
}

SEC("lsm/bpf_prog_load")
int BPF_PROG(shirudo_lsm_bpf_prog_load, struct bpf_prog *prog,
	     union bpf_attr *attr, struct bpf_token *token,
	     bool kernel, int ret)
{
	struct shirudo_sb_id *id;
	__u32 zero = 0, verdict, ktype;
	__s32 serial;

	/*
	 * kernel == true means the load originates from inside an already-
	 * vetted signed loader running in kernel context; those are always
	 * allowed (the loader itself passed this gate when it was loaded
	 * from userspace).
	 */
	if (ret)
		return ret;
	if (kernel)
		return 0;

	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (!id || id->keyring_serial == 0)
		return -EACCES;

	verdict = BPF_CORE_READ(prog, aux, sig.verdict);
	ktype   = BPF_CORE_READ(prog, aux, sig.keyring_type);
	serial  = BPF_CORE_READ(prog, aux, sig.keyring_serial);

	if (verdict != BPF_SIG_VERIFIED)
		return shirudo_tamper_deny(SHIRUDO_TAMPER_LOAD_UNVERIFIED,
					   -EACCES);
	if (ktype != id->keyring_type)
		return shirudo_tamper_deny(SHIRUDO_TAMPER_LOAD_KEYRING_KIND,
					   -EACCES);
	if (ktype == BPF_SIG_KEYRING_BPF) {
		if (serial && serial != id->keyring_serial)
			return shirudo_tamper_deny(SHIRUDO_TAMPER_LOAD_KEYRING,
						   -EACCES);
	} else if (serial != id->keyring_serial) {
		return shirudo_tamper_deny(SHIRUDO_TAMPER_LOAD_KEYRING,
					   -EACCES);
	}
	return 0;
}

SEC("lsm/task_prctl")
int BPF_PROG(shirudo_lsm_task_prctl, int option, unsigned long arg2,
	     unsigned long arg3, unsigned long arg4, unsigned long arg5,
	     int ret)
{
	struct shirudo_sb_id *id;
	__u32 zero = 0;

	if (ret && ret != -ENOSYS)
		return ret;
	if (option == SHIRUDO_PR_GET_MODE) {
		id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
		if (!id)
			return -EACCES;
		return id->runtime_mode ? -SHIRUDO_PR_MODE_IMAGE_ERR :
		       -SHIRUDO_PR_MODE_LEGACY_ERR;
	}
	if (option != PR_SET_MM ||
	    (arg2 != PR_SET_MM_EXE_FILE && arg2 != PR_SET_MM_MAP))
		return ret ? ret : -ENOSYS;
	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (!id)
		return -EACCES;
	if (!shirudo_task_is_self(id))
		return shirudo_tamper_deny(SHIRUDO_TAMPER_EXE_IDENTITY, -EPERM);
	return -ENOSYS;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(shirudo_lsm_bprm_check_security, struct linux_binprm *bprm,
	     int ret)
{
	struct shirudo_sb_id *id;
	__u32 zero = 0;

	if (ret)
		return ret;
	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (!id || !shirudo_file_is_self(id, bprm->file))
		return 0;
	if (BPF_CORE_READ(bprm, unsafe) & LSM_UNSAFE_PTRACE)
		return shirudo_tamper_deny(SHIRUDO_TAMPER_EXEC_TRACED, -EPERM);
	bpf_bprm_opts_set(bprm, BPF_F_BPRM_SECUREEXEC);
	return 0;
}

static __always_inline int shirudo_bpffs_guard(__u32 target_dev,
					       enum shirudo_tamper_point point)
{
	struct shirudo_sb_id *id;
	__u32 zero = 0;

	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (!id || id->sb_dev == 0)
		return 0;
	if (target_dev != id->sb_dev &&
	    (!id->runtime_mode || !id->run_dev || target_dev != id->run_dev))
		return 0;
	if (shirudo_task_is_self(id))
		return 0;
	if (target_dev == id->sb_dev && point != SHIRUDO_TAMPER_MAX)
		return shirudo_tamper_deny(point, -EPERM);
	return -EPERM;
}

/*
 * The trust anchor in the kernel's keyrings: the keyring init froze
 * and the keys it holds. Root owns the bpf keyring with write and
 * setattr permission, so without this hook a single keyctl could
 * unlink, clear, revoke or invalidate the certificates every load is
 * verified against. Deny those needs to every task but shirudo. A
 * search is denied only through an unpossessed reference, which is
 * how keyctl reaches a key by serial to invalidate it; the kernel
 * verifies a signature by searching the keyring it possesses, and
 * that stays open to every loader.
 */
SEC("lsm/key_permission")
int BPF_PROG(shirudo_lsm_key_permission, key_ref_t key_ref,
	     const struct cred *cred, enum key_need_perm need, int ret)
{
	struct shirudo_sb_id *id;
	__u32 zero = 0, i;
	struct key *key;
	bool possessed;
	__s32 serial;

	if (ret)
		return ret;
	switch (need) {
	case KEY_NEED_WRITE:
	case KEY_NEED_SEARCH:
	case KEY_NEED_SETATTR:
	case KEY_NEED_UNLINK:
		break;
	default:
		return 0;
	}
	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (!id || id->keyring_serial == 0)
		return 0;
	possessed = (unsigned long)key_ref & 1;
	key = (struct key *)((unsigned long)key_ref & ~1UL);
	serial = BPF_CORE_READ(key, serial);
	if (serial != id->keyring_serial) {
		for (i = 0; i < SHIRUDO_IDENTITY_KEYS_MAX; i++) {
			if (i < id->n_keys && id->key_serials[i] == serial)
				break;
		}
		if (i == SHIRUDO_IDENTITY_KEYS_MAX)
			return 0; /* not the anchor -- not ours */
	}
	if (need == KEY_NEED_SEARCH && possessed)
		return 0;
	return shirudo_task_is_self(id) ? 0 :
	       shirudo_tamper_deny(SHIRUDO_TAMPER_KEYRING, -EACCES);
}

/*
 * Inside shirudo's bpffs: only shirudo's own executable may unlink
 * (the `upatch unload` path). Every other caller -- including root
 * `rm` -- is denied, so the LSM link cannot be detached by removing
 * its pin.
 */
SEC("lsm/inode_unlink")
int BPF_PROG(shirudo_lsm_inode_unlink, struct inode *dir,
	     struct dentry *dentry, int ret)
{
	if (ret)
		return ret;
	return shirudo_bpffs_guard(BPF_CORE_READ(dir, i_sb, s_dev),
				   SHIRUDO_TAMPER_PIN_UNLINK);
}

SEC("lsm/inode_rmdir")
int BPF_PROG(shirudo_lsm_inode_rmdir, struct inode *dir,
	     struct dentry *dentry, int ret)
{
	if (ret)
		return ret;
	return shirudo_bpffs_guard(BPF_CORE_READ(dir, i_sb, s_dev),
				   SHIRUDO_TAMPER_MAX);
}

SEC("lsm/inode_rename")
int BPF_PROG(shirudo_lsm_inode_rename, struct inode *old_dir,
	     struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry, int ret)
{
	if (ret)
		return ret;
	ret = shirudo_bpffs_guard(BPF_CORE_READ(old_dir, i_sb, s_dev),
				  SHIRUDO_TAMPER_PIN_RENAME);
	return ret ? ret :
	       shirudo_bpffs_guard(BPF_CORE_READ(new_dir, i_sb, s_dev),
				   SHIRUDO_TAMPER_PIN_RENAME);
}

/*
 * Only shirudo may set xattrs on its own bpffs, so the
 * security.bpf.shirudo.payload value recorded on each pin directory
 * cannot be forged by a root attacker. See the file header.
 */
SEC("lsm/inode_setxattr")
int BPF_PROG(shirudo_lsm_inode_setxattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name, const void *value,
	     __u64 size, int flags, int ret)
{
	if (ret)
		return ret;
	return shirudo_bpffs_guard(BPF_CORE_READ(dentry, d_inode, i_sb, s_dev),
				   SHIRUDO_TAMPER_PIN_XATTR);
}

/* Symmetric to setxattr: deny removing a pin's xattrs from non-shirudo. */
SEC("lsm/inode_removexattr")
int BPF_PROG(shirudo_lsm_inode_removexattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name, int ret)
{
	if (ret)
		return ret;
	return shirudo_bpffs_guard(BPF_CORE_READ(dentry, d_inode, i_sb, s_dev),
				   SHIRUDO_TAMPER_PIN_XATTR);
}

/*
 * Mount-lifecycle lockdown of shirudo's private bpffs superblock.
 *
 * The pinned LSM links live only in this bpffs, and shirudo is agentless
 * -- once `shirudo init` exits no process holds an fd to them, so the
 * pins are their only reference. Tearing the superblock down therefore
 * detaches every hook at once: a plain `umount /run/shirudo/bpffs`
 * drops the pinned inodes, releases the links, and silently disables all
 * enforcement (no signature, keyring, or TPM involved). The inode guards
 * above stop `rm` of a pin but a mount is not an inode op, so it slips
 * past them. Gate the whole mount lifecycle of this one superblock:
 * unmount, relocate (move_mount), mounting over the pin tree (sb_mount),
 * and remount. shirudo never performs any of these on its own bpffs
 * after init, so the deny is unconditional -- the mount is immutable for
 * the boot's lifetime, for every caller including shirudo itself. The
 * hooks are self-protecting: their own pins live in the bpffs they keep
 * mounted.
 *
 * A lazy unmount (MNT_DETACH) of a mount above the bpffs, /run or the
 * root, takes the subtree down with it and fires sb_umount for the
 * ancestor alone. The original mount must stay; namespace copies may
 * go when none of the removed mounts can propagate the unmount out.
 * switch-root moves /run and retains the original mount's unique ID.
 */
static __always_inline __u32 shirudo_bpffs_dev(void)
{
	struct shirudo_sb_id *id;
	__u32 zero = 0;

	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	return id ? id->sb_dev : 0;
}

/* -EPERM, counted at `point`, when sb_dev is the bpffs; else 0. */
static __always_inline int
shirudo_deny_bpffs_mount(__u32 sb_dev, enum shirudo_tamper_point point)
{
	__u32 bpffs = shirudo_bpffs_dev();

	if (!bpffs || sb_dev != bpffs)
		return 0;
	return shirudo_tamper_deny(point, -EPERM);
}

static __always_inline int shirudo_parent_mount(struct super_block *sb,
						bool trusted_target)
{
	struct shirudo_sb_id *id = shirudo_policy();

	if (!sb || !id || !id->runtime_mode || !id->run_dev ||
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

	if (!sb || !id || !id->runtime_mode)
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

SEC("lsm.s/bdev_setintegrity")
int BPF_PROG(shirudo_lsm_bdev_setintegrity, struct block_device *bdev,
	     enum lsm_integrity_type type, const void *value,
	     size_t size, int ret)
{
	const struct dm_verity_digest___shirudo *digest = value;
	struct shirudo_sb_id *id = shirudo_policy();
	struct shirudo_device device = {};
	__u64 cookie = (__u64)bdev;
	const unsigned char *root;
	const char *algorithm;
	unsigned int i;
	char name[8];
	int diff;

	if (ret)
		return ret;
	if (!id || !id->runtime_mode || type != LSM_INT_DMVERITY_ROOTHASH)
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
	if (!diff)
		device.kind = SHIRUDO_DEVICE_RUNTIME;
	else if (shirudo_task_is_self(id))
		device.kind = SHIRUDO_DEVICE_CONFIG;
	else
		return 0;
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

	if (ret || !id || !id->runtime_mode || shirudo_task_is_self(id))
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
