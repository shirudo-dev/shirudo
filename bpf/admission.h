/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_BPF_ADMISSION_H
#define SHIRUDO_BPF_ADMISSION_H

/*
 * Both modes use the same BPF command allowlist. The selected policy authorizes
 * the frozen executable in ordinary mode, or a committed task in image mode.
 */
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
		/*
		 * Signed-loader entry. Require SYSCALL prog_type AND a
		 * non-zero signature; the kernel verifies the CMS blob
		 * against attr->keyring_id immediately after this hook.
		 */
		if (BPF_CORE_READ(attr, prog_type) != BPF_PROG_TYPE_SYSCALL)
			point = SHIRUDO_TAMPER_LOAD_NOT_LOADER;
		else if (BPF_CORE_READ(attr, signature_size) == 0)
			point = SHIRUDO_TAMPER_LOAD_UNSIGNED;
		else
			return 0;
		return shirudo_tamper_deny(point, -EACCES);

	/*
	 * Vetted mutating cmds the signed-loader data-map + attach/pin
	 * pattern needs from userspace, each left to a caller authorized by
	 * the selected policy. Signed-loader mutations run in kernel context.
	 * A prog_fd is only obtainable via the signature-gated
	 * BPF_PROG_LOAD above or GET_FD_BY_ID of an already-vetted prog.
	 * gen_loader emits no link-create and bpf_sys_bpf() cannot
	 * BPF_OBJ_PIN, so shirudo's one-shot CLI must create + pin the
	 * link itself, and nobody else has a reason to: a vetted kprobe
	 * program re-attached by root at a site of its choosing would run
	 * signed code where its signer never meant it to, and a pin of
	 * root's into the private bpffs is an entry shirudo did not make.
	 */
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
		return shirudo_tamper_deny(SHIRUDO_TAMPER_BPF_CMD, -EACCES);
	}
}

/*
 * Writable map fds let userspace alter array contents and writable
 * mmap lets it alter arena pages without another bpf() command. Keep
 * both paths exclusive to shirudo while leaving read-only map access
 * available to observers.
 */
SEC("lsm/bpf_map")
int BPF_PROG(shirudo_lsm_bpf_map, struct bpf_map *map, fmode_t fmode,
	     int ret)
{
	struct shirudo_sb_id *id = shirudo_policy();

	if (ret)
		return ret;
	if (fmode & FMODE_WRITE)
		return shirudo_self_or_deny(SHIRUDO_TAMPER_MAP_FD);
	if (!shirudo_private_map(map))
		return 0;
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
	     union bpf_attr *attr, struct bpf_token *token,
	     bool kernel, int ret)
{
	struct shirudo_sb_id *id;
	__u32 zero = 0, verdict, ktype;
	__s32 serial;

	if (ret)
		return ret;
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

	/*
	 * Three ways to fail, each counted apart: no verified signature
	 * on the program, a signature verified against a keyring of the
	 * wrong kind, or against a keyring of the right kind that is not
	 * the one init froze.
	 */
	if (verdict != BPF_SIG_VERIFIED)
		return shirudo_tamper_deny(SHIRUDO_TAMPER_LOAD_UNVERIFIED,
					   -EACCES);
	if (ktype != id->keyring_type)
		return shirudo_tamper_deny(SHIRUDO_TAMPER_LOAD_KEYRING_KIND,
					   -EACCES);
	/*
	 * The bpf keyring is the kernel's own singleton, resolved by the
	 * kernel and recorded without a serial (0) because it is held
	 * without a reference, so the kind alone names it. A staged user
	 * keyring is named by the serial init froze, which a same-named
	 * substitute cannot match.
	 */
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

	(void)arg3;
	(void)arg4;
	(void)arg5;
	if (ret && ret != -ENOSYS)
		return ret;
	if (option == SHIRUDO_PR_GET_MODE) {
		id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
		if (!id)
			return -EACCES;
		return -SHIRUDO_MODE_ERROR;
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

/*
 * Verdict for an operation targeting an inode in superblock target_dev:
 * Ordinary mode protects the bpffs; image mode also protects the /run
 * filesystem holding its mountpoints. Only an authorized caller may mutate
 * these inodes. Count bpffs refusals at `point`. Unrelated filesystems pass.
 */
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
	if (!shirudo_protected_filesystem(id, target_dev))
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
		for (i = 0; i < SHIRUDO_IDENTITY_KEYS_MAX; i++)
			if (i < id->n_keys && id->key_serials[i] == serial)
				break;
		if (i == SHIRUDO_IDENTITY_KEYS_MAX)
			return 0;	/* not the anchor -- not ours */
	}
	if (need == KEY_NEED_SEARCH && possessed)
		return 0;
	return shirudo_task_is_self(id) ? 0 :
	       shirudo_tamper_deny(SHIRUDO_TAMPER_KEYRING, -EACCES);
}

/*
 * Inside shirudo's bpffs: only an authorized caller may unlink
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
 * cannot be forged by a root attacker. The unload check trusts this value.
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
 * These checks cover the bpffs itself. A lazy unmount of a parent is not
 * covered: the VFS calls sb_umount for that parent alone. Protecting pins
 * against that case is a separate problem (issue 22).
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

#endif /* SHIRUDO_BPF_ADMISSION_H */
