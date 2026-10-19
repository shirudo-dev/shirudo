// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0)
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The central "BPF on BPF" LSM enforcement program.
 *
 * Hooks:
 *   lsm/bpf          -- gates the bpf() syscall. Kernel-context (signed
 *                       loader) calls return immediately; userspace
 *                       BPF_PROG_LOAD must be prog_type=SYSCALL and have
 *                       a non-zero signature in this cheap pre-filter.
 *                       The authoritative verdict is enforced by
 *                       lsm/bpf_prog_load below, after the kernel has
 *                       verified the signature.
 *   lsm/bpf_prog_load -- the admission gate that runs INSIDE the
 *                       verifier, after signature verification, so the
 *                       kernel-recorded verdict is final here. A
 *                       userspace load is admitted only when the kernel
 *                       recorded BPF_SIG_VERIFIED against exactly the
 *                       keyring init sealed: sig.verdict must be
 *                       VERIFIED and sig.keyring_type the kind init
 *                       froze into the identity map, the bpf keyring
 *                       (the kernel's singleton, recorded without a
 *                       serial) or a staged user keyring, which
 *                       sig.keyring_serial must then name by the
 *                       serial init froze. Everything else -- unsigned,
 *                       signed by any other keyring, or signed against
 *                       a substituted same-named keyring -- is denied.
 *                       This is what makes "only shirudo-signed BPF
 *                       loads from userspace" a kernel-enforced
 *                       invariant rather than a best-effort keyring_id
 *                       choice by the caller.
 *   lsm/bpf_map -- denies writable map file descriptors to every
 *                       process except shirudo. Read-only map access
 *                       remains available; this also blocks writable
 *                       mmap of arena maps.
 *   lsm/inode_unlink -- denies VFS unlink on shirudo's private
 *                       bpffs superblock unless the caller is shirudo
 *                       itself (its exe_file inode matches the
 *                       identity recorded at init). Permanently
 *                       protects the LSM-link and upatch pins from an
 *                       attacker's `rm` (seal excludes the bpffs
 *                       mount, so bpf2 is the only protector here),
 *                       while letting `shirudo upatch unload` remove
 *                       a pin to detach a program. The exe-inode check
 *                       is the interim of the xattr-based identity
 *                       seal will use. The task_prctl hook below
 *                       prevents non-Shirudo callers from changing
 *                       mm->exe_file through PR_SET_MM.
 *   lsm/key_permission -- guards the trust anchor in the kernel's
 *                       keyrings: the sealed keyring init froze and the
 *                       keys it holds may be viewed and searched by
 *                       anyone, but written, unlinked, revoked, given
 *                       attributes or looked up for invalidation only
 *                       by shirudo's own executable. Sealing stops keys
 *                       from being added; this stops root from taking
 *                       them away, which is what makes unlinking a key
 *                       the revocation primitive and nothing else.
 *   lsm/inode_setxattr,
 *   lsm/inode_removexattr -- same exe-identity gate over the bpffs
 *                       superblock, so only shirudo may set or remove
 *                       extended attributes on its own pins. shirudo
 *                       records each loaded upatch's payload_sha256 as
 *                       the security.bpf.shirudo.payload xattr on the
 *                       pin directory; this gate makes that value
 *                       unforgeable by a root attacker (the unload
 *                       payload_mismatch check trusts it).
 *   lsm/sb_umount,
 *   lsm/move_mount,
 *   lsm/sb_mount,
 *   lsm/sb_remount -- mount-lifecycle lockdown of the private bpffs
 *                       superblock (identified by s_dev). Unconditional
 *                       deny: no caller, not even shirudo, may unmount,
 *                       relocate, mount over, or remount it for the boot.
 *                       Without this a single `umount` of the bpffs drops
 *                       the pinned links and detaches ALL enforcement,
 *                       since shirudo is agentless and the pins are the
 *                       links' only reference. See the hook block below.
 *   lsm/task_prctl     -- deny PR_SET_MM executable changes to callers
 *                       outside the frozen Shirudo executable identity.
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

char _license[] SEC("license") = "Dual BSD/GPL";

#include "shirudo_identity.h"

SEC("lsm/bpf")
int BPF_PROG(shirudo_lsm_bpf, int cmd, union bpf_attr *attr,
	     unsigned int size, bool kernel)
{
	struct shirudo_sb_id *id;
	__u32 prog_type, sig_sz;
	__u32 zero = 0;

	if (kernel)
		return 0;

	switch (cmd) {
	case BPF_PROG_LOAD:
		/*
		 * Signed-loader entry. Require SYSCALL prog_type AND a
		 * non-zero signature; the kernel verifies the CMS blob
		 * against attr->keyring_id immediately after this hook.
		 */
		prog_type = BPF_CORE_READ(attr, prog_type);
		if (prog_type != BPF_PROG_TYPE_SYSCALL)
			return -EACCES;
		sig_sz = BPF_CORE_READ(attr, signature_size);
		if (sig_sz == 0)
			return -EACCES;
		return 0;

	/*
	 * Vetted mutating cmds the signed-loader data-map + attach/pin
	 * pattern needs from userspace. Map updates and freezes are restricted
	 * below to shirudo itself; signed-loader map mutations run in kernel
	 * context. A prog_fd is only obtainable via the signature-gated
	 * BPF_PROG_LOAD above or GET_FD_BY_ID of an already-vetted prog.
	 * gen_loader emits no link-create and bpf_sys_bpf() cannot
	 * BPF_OBJ_PIN, so shirudo's one-shot CLI must create + pin the link
	 * itself. Attaching an already-vetted program grants no new
	 * code-execution capability.
	 */
	case BPF_MAP_CREATE:
		id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
		if (!id || !shirudo_task_is_self(id))
			return -EACCES;
		return 0;

	case BPF_MAP_UPDATE_ELEM:
	case BPF_MAP_FREEZE:
		id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
		if (!id || !shirudo_task_is_self(id))
			return -EACCES;
		return 0;

	case BPF_PROG_TEST_RUN:
		id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
		if (!id || !shirudo_task_is_self(id))
			return -EACCES;
		return 0;

	case BPF_OBJ_PIN:
	case BPF_LINK_CREATE:
	case BPF_RAW_TRACEPOINT_OPEN:

	/*
	 * Read-only / observability cmds, so `bpftool prog show`,
	 * `shirudo status`, and `shirudo upatch get/map` keep working.
	 * BPF_OBJ_UNPIN does not exist as a bpf() cmd; VFS unlink removes
	 * pins and shirudo's lsm/inode_unlink hook blocks `rm` on the
	 * private bpffs.
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

	/*
	 * Default-DENY, fail closed. This covers the tear-down / replace /
	 * corruption cmds an attacker would use to detach or swap out
	 * shirudo's own LSM/upatch links or drain map state
	 * (BPF_LINK_DETACH, BPF_LINK_UPDATE, BPF_PROG_ATTACH/DETACH,
	 * BPF_BTF_LOAD, BPF_MAP_DELETE_ELEM and the *_BATCH /
	 * LOOKUP_AND_DELETE variants) and -- critically -- every cmd
	 * shirudo has not explicitly vetted above, including ones a newer
	 * kernel may add (BPF_TOKEN_CREATE, BPF_PROG_BIND_MAP,
	 * BPF_ITER_CREATE, BPF_PROG_ASSOC_STRUCT_OPS, ...). A future
	 * mutating cmd therefore cannot silently bypass policy: it stays
	 * denied until explicitly classified. -EACCES matches the LSM
	 * denial errno used throughout (threat-model.rst T1/T2).
	 */
	default:
		return -EACCES;
	}
}

/*
 * Writable map fds let userspace alter array contents and writable
 * mmap lets it alter arena pages without another bpf() command. Keep
 * both paths exclusive to shirudo while leaving read-only map access
 * available to observers.
 */
SEC("lsm/bpf_map")
int BPF_PROG(shirudo_lsm_bpf_map, struct bpf_map *map, fmode_t fmode)
{
	struct shirudo_sb_id *id;
	__u32 zero = 0;

	if (!(fmode & FMODE_WRITE))
		return 0;
	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (!id || !shirudo_task_is_self(id))
		return -EACCES;
	return 0;
}

/*
 * Admission gate. Fires from a single call site inside the verifier
 * (bpf_check), after the kernel has verified any PKCS#7 signature and
 * recorded the verdict on prog->aux->sig -- so the fields read here are
 * final. A userspace load is admitted only if the kernel verified it
 * against exactly shirudo's own sealed keyring; every other program is
 * denied, fail-closed.
 *
 * kernel == true means the load originates from inside an already-vetted
 * signed loader running in kernel context; those are always allowed
 * (the loader itself passed this gate when it was loaded from userspace).
 */
SEC("lsm/bpf_prog_load")
int BPF_PROG(shirudo_lsm_bpf_prog_load, struct bpf_prog *prog,
	     union bpf_attr *attr, struct bpf_token *token, bool kernel)
{
	struct shirudo_sb_id *id;
	__u32 zero = 0, verdict, ktype;
	__s32 serial;

	if (kernel)
		return 0;

	/*
	 * Fail closed if the identity record is missing or carries no
	 * keyring serial: without the trust anchor there is no way to tell
	 * a shirudo-signed load from an attacker's, so admit nothing.
	 */
	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (!id || id->keyring_serial == 0)
		return -EACCES;

	verdict = BPF_CORE_READ(prog, aux, sig.verdict);
	ktype   = BPF_CORE_READ(prog, aux, sig.keyring_type);
	serial  = BPF_CORE_READ(prog, aux, sig.keyring_serial);

	if (verdict != BPF_SIG_VERIFIED)
		return -EACCES;
	if (ktype != id->keyring_type)
		return -EACCES;
	/*
	 * The bpf keyring is the kernel's own singleton, resolved by the
	 * kernel and recorded without a serial (0) because it is held
	 * without a reference, so the kind alone names it. A staged user
	 * keyring is named by the serial init froze, which a same-named
	 * substitute cannot match.
	 */
	if (ktype == BPF_SIG_KEYRING_BPF) {
		if (serial && serial != id->keyring_serial)
			return -EACCES;
	} else if (serial != id->keyring_serial) {
		return -EACCES;
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

	(void)arg3;
	(void)arg4;
	(void)arg5;
	if ((ret && ret != -ENOSYS) || option != PR_SET_MM ||
	    (arg2 != PR_SET_MM_EXE_FILE && arg2 != PR_SET_MM_MAP))
		return ret ? ret : -ENOSYS;
	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (!id)
		return -EACCES;
	if (!shirudo_task_is_self(id))
		return -EPERM;
	return -ENOSYS;
}

/*
 * Verdict for an operation targeting an inode in superblock target_dev:
 * allow (0) if it is not shirudo's bpffs, or if the calling task's
 * exe_file matches the identity recorded at init; deny (-EPERM)
 * otherwise. The single guard shared by inode_unlink, inode_setxattr
 * and inode_removexattr -- "only shirudo may mutate its own bpffs".
 */
static __always_inline int shirudo_bpffs_guard(__u32 target_dev)
{
	struct shirudo_sb_id *id;
	__u32 zero = 0;

	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (!id || id->sb_dev == 0)
		return 0;
	if (target_dev != id->sb_dev)
		return 0;	/* not shirudo's bpffs -- not ours to guard */
	return shirudo_task_is_self(id) ? 0 : -EPERM;
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
		for (i = 0; i < SHIRUDO_IDENTITY_KEYS_MAX; i++)
			if (i < id->n_keys && id->key_serials[i] == serial)
				break;
		if (i == SHIRUDO_IDENTITY_KEYS_MAX)
			return 0;	/* not the anchor -- not ours */
	}
	if (need == KEY_NEED_SEARCH && possessed)
		return 0;
	return shirudo_task_is_self(id) ? 0 : -EACCES;
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
	return shirudo_bpffs_guard(BPF_CORE_READ(dir, i_sb, s_dev));
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
	return shirudo_bpffs_guard(BPF_CORE_READ(dentry, d_inode, i_sb, s_dev));
}

/* Symmetric to setxattr: deny removing a pin's xattrs from non-shirudo. */
SEC("lsm/inode_removexattr")
int BPF_PROG(shirudo_lsm_inode_removexattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name)
{
	return shirudo_bpffs_guard(BPF_CORE_READ(dentry, d_inode, i_sb, s_dev));
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
 * Residual: a lazy unmount (MNT_DETACH) of an *ancestor* mount can tear
 * down the subtree without firing sb_umount on this child; that needs
 * the ancestor (e.g. /var) to be unmountable, a far higher bar than the
 * trivial direct unmount closed here.
 */
static __always_inline int shirudo_deny_bpffs_mount(__u32 sb_dev)
{
	struct shirudo_sb_id *id;
	__u32 zero = 0;

	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (!id || id->sb_dev == 0)
		return 0;
	return sb_dev == id->sb_dev ? -EPERM : 0;
}

SEC("lsm/sb_umount")
int BPF_PROG(shirudo_lsm_sb_umount, struct vfsmount *mnt, int flags)
{
	return shirudo_deny_bpffs_mount(BPF_CORE_READ(mnt, mnt_sb, s_dev));
}

SEC("lsm/move_mount")
int BPF_PROG(shirudo_lsm_move_mount, const struct path *from_path,
	     const struct path *to_path)
{
	if (shirudo_deny_bpffs_mount(BPF_CORE_READ(from_path, mnt, mnt_sb, s_dev)))
		return -EPERM;
	return shirudo_deny_bpffs_mount(BPF_CORE_READ(to_path, mnt, mnt_sb, s_dev));
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
	return shirudo_deny_bpffs_mount(BPF_CORE_READ(path, mnt, mnt_sb, s_dev));
}

SEC("lsm/sb_remount")
int BPF_PROG(shirudo_lsm_sb_remount, struct super_block *sb, void *mnt_opts)
{
	return shirudo_deny_bpffs_mount(BPF_CORE_READ(sb, s_dev));
}
