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
#define PR_SET_MM		35
#define PR_SET_MM_EXE_FILE	13
#define PR_SET_MM_MAP		14
#define PERF_EVENT_IOC_SET_BPF	0x40042408	/* _IOW('$', 8, __u32) */

char _license[] SEC("license") = "Dual BSD/GPL";

#include "shirudo_identity.h"
#include "shirudo_tamper.h"

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
	     unsigned int size, bool kernel)
{
	enum shirudo_tamper_point point;

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
int BPF_PROG(shirudo_lsm_bpf_map, struct bpf_map *map, fmode_t fmode)
{
	if (!(fmode & FMODE_WRITE))
		return 0;
	return shirudo_self_or_deny(SHIRUDO_TAMPER_MAP_FD);
}

SEC("lsm/bpf_prog_load")
int BPF_PROG(shirudo_lsm_bpf_prog_load, struct bpf_prog *prog,
	     union bpf_attr *attr, struct bpf_token *token, bool kernel)
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

/*
 * A perf event takes a program by ioctl, outside bpf(), so a signed
 * kprobe program fetched by its id could be put on any other function.
 */
SEC("lsm/file_ioctl")
int BPF_PROG(shirudo_lsm_file_ioctl, struct file *file, unsigned int cmd,
	     unsigned long arg)
{
	if (cmd != PERF_EVENT_IOC_SET_BPF)
		return 0;
	return shirudo_self_or_deny(SHIRUDO_TAMPER_ATTACH);
}

SEC("lsm/file_ioctl_compat")
int BPF_PROG(shirudo_lsm_file_ioctl_compat, struct file *file,
	     unsigned int cmd, unsigned long arg)
{
	if (cmd != PERF_EVENT_IOC_SET_BPF)
		return 0;
	return shirudo_self_or_deny(SHIRUDO_TAMPER_ATTACH);
}

SEC("lsm/task_prctl")
int BPF_PROG(shirudo_lsm_task_prctl, int option, unsigned long arg2,
	     unsigned long arg3, unsigned long arg4, unsigned long arg5,
	     int ret)
{
	struct shirudo_sb_id *id;
	__u32 zero = 0;

	if ((ret && ret != -ENOSYS) || option != PR_SET_MM ||
	    (arg2 != PR_SET_MM_EXE_FILE && arg2 != PR_SET_MM_MAP))
		return ret ? ret : -ENOSYS;
	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (!id)
		return -EACCES;
	if (!shirudo_task_is_self(id))
		return shirudo_tamper_deny(SHIRUDO_TAMPER_EXE_IDENTITY, -EPERM);
	return -ENOSYS;
}

static __always_inline int shirudo_bpffs_guard(__u32 target_dev,
					       enum shirudo_tamper_point point)
{
	struct shirudo_sb_id *id;
	__u32 zero = 0;

	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (!id || id->sb_dev == 0)
		return 0;
	if (target_dev != id->sb_dev)
		return 0; /* not shirudo's bpffs -- not ours to guard */
	return shirudo_task_is_self(id) ? 0 :
	       shirudo_tamper_deny(point, -EPERM);
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
	     const struct cred *cred, enum key_need_perm need)
{
	struct shirudo_sb_id *id;
	__u32 zero = 0, i;
	struct key *key;
	bool possessed;
	__s32 serial;

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
	     struct dentry *dentry)
{
	return shirudo_bpffs_guard(BPF_CORE_READ(dir, i_sb, s_dev),
				   SHIRUDO_TAMPER_PIN_UNLINK);
}

/*
 * Rename is the other way a pin can go: the VFS asks only this hook of
 * it, and simple_rename() unlinks the victim without inode_unlink, so
 * renaming any pin over a link's pin would drop that link's only
 * reference. Both directories share the superblock, a rename never
 * crossing one, so the source directory names it for both ends.
 */
SEC("lsm/inode_rename")
int BPF_PROG(shirudo_lsm_inode_rename, struct inode *old_dir,
	     struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry)
{
	return shirudo_bpffs_guard(BPF_CORE_READ(old_dir, i_sb, s_dev),
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
	     __u64 size, int flags)
{
	return shirudo_bpffs_guard(BPF_CORE_READ(dentry, d_inode, i_sb, s_dev),
				   SHIRUDO_TAMPER_PIN_XATTR);
}

/* Symmetric to setxattr: deny removing a pin's xattrs from non-shirudo. */
SEC("lsm/inode_removexattr")
int BPF_PROG(shirudo_lsm_inode_removexattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name)
{
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
 * ancestor alone, so sb_umount also refuses any mount that has the
 * bpffs beneath it. Nothing unmounts /run or the root on a live
 * system; switch-root moves /run and never unmounts it.
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

/* The address a trusted pointer holds, as a plain number. */
static __always_inline unsigned long shirudo_ptr_addr(const void *ptr)
{
	unsigned long addr = 0;

	bpf_probe_read_kernel(&addr, sizeof(addr), &ptr);
	return addr;
}

#define shirudo_mount_of(ptr, member)					\
	((struct mount *)((unsigned long)(ptr) -			\
			  bpf_core_field_offset(struct mount, member)))

#define SHIRUDO_MOUNT_WALK_MAX	4096
#define SHIRUDO_MOUNT_DEPTH_MAX	64

/*
 * Whether `root` or a mount below it is of the file system `sb_dev`:
 * the subtree an unmount of `root` takes down. The walk is over the
 * caller's own mount tree, so a copy of the bpffs mount in another
 * namespace is found where a propagated unmount would reach it.
 * Stackless: down to the first child, else across to the next sibling
 * of the nearest ancestor that has one, until the walk is back at
 * `root`. A tree the budget cannot cover is taken to hold the bpffs.
 */
static __always_inline bool shirudo_mount_tree_has(struct mount *root,
						   __u32 sb_dev)
{
	struct mount *cur = root, *parent;
	struct list_head *next;
	bool climbed;
	int i, j;

	bpf_for(i, 0, SHIRUDO_MOUNT_WALK_MAX) {
		if (BPF_CORE_READ(cur, mnt.mnt_sb, s_dev) == sb_dev)
			return true;
		next = BPF_CORE_READ(cur, mnt_mounts.next);
		if (next != &cur->mnt_mounts) {
			cur = shirudo_mount_of(next, mnt_child);
			continue;
		}
		climbed = false;
		bpf_for(j, 0, SHIRUDO_MOUNT_DEPTH_MAX) {
			if (cur == root)
				return false;
			parent = BPF_CORE_READ(cur, mnt_parent);
			next = BPF_CORE_READ(cur, mnt_child.next);
			if (next != &parent->mnt_mounts) {
				cur = shirudo_mount_of(next, mnt_child);
				climbed = true;
				break;
			}
			cur = parent;
		}
		if (!climbed)
			return true;
	}
	return true;
}

SEC("lsm/sb_umount")
int BPF_PROG(shirudo_lsm_sb_umount, struct vfsmount *mnt, int flags)
{
	__u32 bpffs = shirudo_bpffs_dev();
	struct mount *target;

	if (!bpffs)
		return 0;
	if (BPF_CORE_READ(mnt, mnt_sb, s_dev) == bpffs)
		return shirudo_tamper_deny(SHIRUDO_TAMPER_BPFFS_UMOUNT, -EPERM);
	target = shirudo_mount_of(shirudo_ptr_addr(mnt), mnt);
	if (shirudo_mount_tree_has(target, bpffs))
		return shirudo_tamper_deny(SHIRUDO_TAMPER_BPFFS_UMOUNT_ABOVE,
					   -EPERM);
	return 0;
}

SEC("lsm/move_mount")
int BPF_PROG(shirudo_lsm_move_mount, const struct path *from_path,
	     const struct path *to_path)
{
	__u32 from = BPF_CORE_READ(from_path, mnt, mnt_sb, s_dev);
	__u32 to = BPF_CORE_READ(to_path, mnt, mnt_sb, s_dev);

	if (shirudo_deny_bpffs_mount(from, SHIRUDO_TAMPER_BPFFS_MOUNT))
		return -EPERM;
	return shirudo_deny_bpffs_mount(to, SHIRUDO_TAMPER_BPFFS_MOUNT);
}

/*
 * Deny mounting anything whose target path resolves onto shirudo's
 * bpffs -- i.e. mounting over the pin tree to shadow it. init's own
 * mount is unaffected: it runs before this hook attaches, and at that
 * point the mountpoint still resolves to the underlying fs, not the
 * (not-yet-mounted) bpffs.
 */
SEC("lsm/sb_mount")
int BPF_PROG(shirudo_lsm_sb_mount, const char *dev_name,
	     const struct path *path, const char *type,
	     unsigned long flags, void *data)
{
	return shirudo_deny_bpffs_mount(BPF_CORE_READ(path, mnt, mnt_sb, s_dev),
					SHIRUDO_TAMPER_BPFFS_MOUNT);
}

SEC("lsm/sb_remount")
int BPF_PROG(shirudo_lsm_sb_remount, struct super_block *sb, void *mnt_opts)
{
	return shirudo_deny_bpffs_mount(BPF_CORE_READ(sb, s_dev),
					SHIRUDO_TAMPER_BPFFS_MOUNT);
}
