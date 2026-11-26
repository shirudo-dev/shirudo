// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

/*
 * shirudo authorizes tasks marked after exec from the authenticated runtime.
 * These hooks track verity devices, restrict DM controls, and protect the
 * runtime/config mounts alongside the shared bpffs and BPF admission checks.
 */
#include "verity.h"
#include <bpf/bpf_endian.h>
#include <shirudo/pin_grant.h>

/*
 * BPF mutations require a task marked by successful exec from the runtime
 * image. Verified signed loaders perform their own calls in kernel context.
 */
static __always_inline int shirudo_self_or_deny(enum tamper_point point)
{
	struct sb_id *id;
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
	enum tamper_point point;

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
			point = TAMPER_LOAD_NOT_LOADER;
		else if (BPF_CORE_READ(attr, signature_size) == 0)
			point = TAMPER_LOAD_UNSIGNED;
		else
			return 0;
		return shirudo_tamper_deny(point, -EACCES);

	/*
	 * Vetted mutating cmds the signed-loader data-map + attach/pin
	 * pattern needs from userspace, each left to a caller authorized by
	 * successful runtime exec. Signed-loader mutations run in kernel context.
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
		return shirudo_self_or_deny(TAMPER_MAP_CREATE);

	case BPF_MAP_UPDATE_ELEM:
	case BPF_MAP_FREEZE:
		return shirudo_self_or_deny(TAMPER_MAP_WRITE);

	case BPF_PROG_TEST_RUN:
		return shirudo_self_or_deny(TAMPER_PROG_RUN);

	case BPF_LINK_CREATE:
	case BPF_RAW_TRACEPOINT_OPEN:
		return shirudo_self_or_deny(TAMPER_ATTACH);

	case BPF_OBJ_PIN:
		return shirudo_self_or_deny(TAMPER_OBJ_PIN);

	/*
	 * A descriptor keeps its object alive: a link held open stays
	 * attached after shirudo unpins it for an unload, a revocation or
	 * the undo of a refused load, and no LSM hook sees a link descriptor
	 * being handed out. A map descriptor reads the state the serializers
	 * own. Neither is root's to take, by pin or by id.
	 */
	case BPF_OBJ_GET:
	case BPF_MAP_GET_FD_BY_ID:
	case BPF_LINK_GET_FD_BY_ID:
		return shirudo_self_or_deny(TAMPER_OBJ_GET);

	/*
	 * Read-only / observability cmds. BPF_OBJ_UNPIN does not exist as a
	 * bpf() cmd; VFS unlink removes pins and shirudo's lsm/inode_unlink
	 * hook blocks `rm` on the private bpffs.
	 */
	case BPF_MAP_LOOKUP_ELEM:
	case BPF_MAP_GET_NEXT_KEY:
	case BPF_MAP_LOOKUP_BATCH:
	case BPF_OBJ_GET_INFO_BY_FD:
	case BPF_PROG_QUERY:
	case BPF_PROG_GET_NEXT_ID:
	case BPF_MAP_GET_NEXT_ID:
	case BPF_BTF_GET_NEXT_ID:
	case BPF_LINK_GET_NEXT_ID:
	case BPF_PROG_GET_FD_BY_ID:
	case BPF_BTF_GET_FD_BY_ID:
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
		return shirudo_tamper_deny(TAMPER_BPF_CMD, -EACCES);
	}
}

/*
 * Writable map fds let userspace alter array contents and writable
 * mmap lets it alter arena pages without another bpf() command; a
 * read-only one reads what the serializers own. Every route to a map
 * descriptor ends here, so every one is shirudo's.
 */
SEC("lsm/bpf_map")
int BPF_PROG(shirudo_lsm_bpf_map, struct bpf_map *map, fmode_t fmode,
	     int ret)
{
	if (ret)
		return ret;
	if (fmode & FMODE_WRITE)
		return shirudo_self_or_deny(TAMPER_MAP_FD);
	return shirudo_self_or_deny(TAMPER_OBJ_GET);
}

/* XDP descriptors also authorize netlink attachment, outside lsm/bpf. */
SEC("lsm/bpf_prog")
int BPF_PROG(shirudo_lsm_bpf_prog, struct bpf_prog *prog, int ret)
{
	if (ret)
		return ret;
	if (BPF_CORE_READ(prog, type) == BPF_PROG_TYPE_XDP)
		return shirudo_self_or_deny(TAMPER_OBJ_GET);
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
	struct sb_id *id;
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
		return shirudo_tamper_deny(TAMPER_LOAD_UNVERIFIED,
					   -EACCES);
	if (ktype != BPF_SIG_KEYRING_BPF)
		return shirudo_tamper_deny(TAMPER_LOAD_KEYRING_KIND,
					   -EACCES);
	/* The kernel singleton is recorded without a serial on some loads. */
	if (serial && serial != id->keyring_serial)
		return shirudo_tamper_deny(TAMPER_LOAD_KEYRING, -EACCES);

	return 0;
}

SEC("lsm/task_prctl")
int BPF_PROG(shirudo_lsm_task_prctl, int option, unsigned long arg2,
	     unsigned long arg3, unsigned long arg4, unsigned long arg5,
	     int ret)
{
	struct sb_id *id;
	__u32 zero = 0;

	if (ret && ret != -ENOSYS)
		return ret;
	if (option == PR_GET_ENFORCEMENT) {
		id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
		if (!id)
			return -EACCES;
		return -PR_ENFORCING_ERR;
	}
	if (option != PR_SET_MM ||
	    (arg2 != PR_SET_MM_EXE_FILE && arg2 != PR_SET_MM_MAP))
		return ret ? ret : -ENOSYS;
	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (!id)
		return -EACCES;
	if (!shirudo_task_is_self(id))
		return shirudo_tamper_deny(TAMPER_EXE_IDENTITY, -EPERM);
	return -ENOSYS;
}

/* Runtime executables always get secure-exec and refuse tracing at exec. */
SEC("lsm/bprm_check_security")
int BPF_PROG(shirudo_lsm_bprm_check_security, struct linux_binprm *bprm,
	     int ret)
{
	struct sb_id *id;
	__u32 zero = 0;

	if (ret)
		return ret;
	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (!id || !shirudo_file_runtime(bprm->file))
		return 0;
	if (BPF_CORE_READ(bprm, unsafe) & LSM_UNSAFE_PTRACE)
		return shirudo_tamper_deny(TAMPER_EXEC_TRACED, -EPERM);
	bpf_bprm_opts_set(bprm, BPF_F_BPRM_SECUREEXEC);
	return 0;
}

/*
 * Protect bpffs and the filesystem holding image mountpoints. Only a trusted
 * runtime task may change their inodes. Count bpffs refusals at `point`.
 */
static __always_inline int shirudo_bpffs_guard(__u32 target_dev,
					       enum tamper_point point)
{
	struct sb_id *id;
	__u32 zero = 0;

	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (!id || id->sb_dev == 0)
		return 0;
	if (!shirudo_protected_filesystem(id, target_dev))
		return 0;
	if (shirudo_task_is_self(id))
		return 0;
	if (target_dev == id->sb_dev && point != TAMPER_MAX)
		return shirudo_tamper_deny(point, -EPERM);
	return -EPERM;
}

/*
 * The trust anchors in the kernel's keyrings: the bpf and dm-verity
 * keyrings init froze and the keys they hold. Root owns both with write
 * and setattr permission, so without this hook a single keyctl could
 * unlink, clear, revoke or invalidate the certificates every load and
 * every config root is verified against. Deny those needs to every
 * task but shirudo. A search is denied only through an unpossessed
 * reference, which is how keyctl reaches a key by serial to invalidate
 * it; the kernel verifies a signature by searching the keyring it
 * possesses, and that stays open to every loader.
 */
SEC("lsm/key_permission")
int BPF_PROG(shirudo_lsm_key_permission, key_ref_t key_ref,
	     const struct cred *cred, enum key_need_perm need, int ret)
{
	struct sb_id *id;
	__u32 zero = 0, i;
	struct key *key;
	bool possessed;
	__s32 serial;

	if (ret)
		return ret;
	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (!id)
		return 0;
	key = (struct key *)((unsigned long)key_ref & ~1UL);
	serial = BPF_CORE_READ(key, serial);
	switch (need) {
	case KEY_NEED_WRITE:
	case KEY_NEED_SEARCH:
	case KEY_NEED_SETATTR:
	case KEY_NEED_UNLINK:
		break;
	default:
		return 0;
	}
	if (id->keyring_serial == 0)
		return 0;
	possessed = (unsigned long)key_ref & 1;
	if (serial != id->keyring_serial && serial != id->dm_verity_ring) {
		for (i = 0; i < IDENTITY_KEYS_MAX; i++)
			if (i < id->n_keys && id->key_serials[i] == serial)
				break;
		if (i == IDENTITY_KEYS_MAX) {
			for (i = 0; i < IDENTITY_KEYS_MAX; i++)
				if (i < id->n_dm_verity_keys &&
				    id->dm_verity_keys[i] == serial)
					break;
			if (i == IDENTITY_KEYS_MAX)
				return 0;
		}
	}
	if (need == KEY_NEED_SEARCH && possessed)
		return 0;
	return shirudo_task_is_self(id) ? 0 :
	       shirudo_tamper_deny(TAMPER_KEYRING, -EACCES);
}

/*
 * Inside shirudo's bpffs: only an authorized caller may unlink
 * (the `upatch unload` path). Every other caller -- including root
 * `rm` -- is denied, so the LSM link cannot be detached by removing
 * its pin.
 */
#define MOUNTPOINT_DEPTH_MAX	32

/*
 * Removing or renaming a dentry detaches or moves what is mounted on it
 * in every namespace, without sb_umount: from a namespace where /run is
 * not mounted, an rmdir of the directory init's /run covers takes the
 * private bpffs with it. The mount points from that bpffs up to the
 * root of init's namespace are shirudo's alone to remove or rename.
 */
static __always_inline int shirudo_mountpoint_guard(struct dentry *dentry)
{
	struct mount_record *rec;
	struct mount *m, *parent;
	struct sb_id *id;
	__u32 zero = 0;
	int i;

	if (!dentry || !(BPF_CORE_READ(dentry, d_flags) &
			 bpf_core_enum_value(enum dentry_flags, DCACHE_MOUNTED)))
		return 0;
	rec = bpf_map_lookup_elem(&shirudo_mnt_rec, &zero);
	if (!rec || !rec->mount)
		return 0;
	m = (struct mount *)rec->mount;
	bpf_for(i, 0, MOUNTPOINT_DEPTH_MAX) {
		if (BPF_CORE_READ(m, mnt_mountpoint) == dentry)
			goto deny;
		parent = BPF_CORE_READ(m, mnt_parent);
		if (!parent || parent == m)
			return 0;
		m = parent;
	}
deny:
	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (id && shirudo_task_is_self(id))
		return 0;
	return shirudo_tamper_deny(TAMPER_BPFFS_UMOUNT_ABOVE, -EPERM);
}

/* Core pins live outside the per-upatch directories and cannot be granted. */
static __always_inline bool upatch_directory(struct dentry *d)
{
	struct dentry *parent = BPF_CORE_READ(d, d_parent);
	struct dentry *root = BPF_CORE_READ(d, d_sb, s_root);
	char name[sizeof("upatches")];

	if ((BPF_CORE_READ(d, d_inode, i_mode) & S_IFMT) != S_IFDIR ||
	    d == parent || parent == root || BPF_CORE_READ(parent, d_parent) != root ||
	    BPF_CORE_READ(parent, d_name.len) != sizeof("upatches") - 1)
		return false;
	if (bpf_probe_read_kernel_str(name, sizeof(name), BPF_CORE_READ(parent, d_name.name)) !=
	    sizeof(name))
		return false;
	return !bpf_strncmp(name, sizeof(name), "upatches");
}

static __always_inline int pin_grant_ioctl(struct file *file, unsigned int cmd)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct sb_id *id = shirudo_policy();
	struct dentry *d;
	__u64 *ino;

	if (!id || !id->sb_dev || BPF_CORE_READ(file, f_inode, i_sb, s_dev) != id->sb_dev ||
	    !shirudo_task_is_self(id))
		return -EPERM;
	if (cmd == SHIRUDO_PIN_GRANT_END) {
		bpf_task_storage_delete(&shirudo_unlink_grant, task);
		return -SHIRUDO_PIN_GRANT_ACK;
	}
	d = BPF_CORE_READ(file, f_path.dentry);
	if (!upatch_directory(d))
		return -EPERM;
	ino = bpf_task_storage_get(&shirudo_unlink_grant, task, NULL,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ino)
		return -ENOMEM;
	*ino = BPF_CORE_READ(file, f_inode, i_ino);
	return -SHIRUDO_PIN_GRANT_ACK;
}

static __always_inline int pin_delete(struct inode *dir, struct dentry *d, bool rmdir)
{
	struct task_struct *task = bpf_get_current_task_btf();
	__u32 dev = BPF_CORE_READ(dir, i_sb, s_dev);
	struct sb_id *id = shirudo_policy();
	enum pin_grant_action action;
	__u64 *grant;
	int ret;

	ret = shirudo_bpffs_guard(dev, rmdir ? TAMPER_MAX : TAMPER_PIN_UNLINK);
	if (ret || !id || !id->sb_dev || dev != id->sb_dev || shirudo_bootstrap_task())
		return ret;
	grant = bpf_task_storage_get(&shirudo_unlink_grant, task, NULL, 0);
	action = pin_grant_delete(grant ? *grant : 0, BPF_CORE_READ(d, d_inode, i_ino),
				  BPF_CORE_READ(dir, i_ino),
				  BPF_CORE_READ(d, d_parent, d_parent, d_inode, i_ino), rmdir);
	if (action == PIN_GRANT_CONSUME)
		bpf_task_storage_delete(&shirudo_unlink_grant, task);
	if (action != PIN_GRANT_DENY)
		return 0;
	return shirudo_tamper_deny(TAMPER_PIN_UNLINK, -EPERM);
}

SEC("lsm/inode_unlink")
int BPF_PROG(shirudo_lsm_inode_unlink, struct inode *dir,
	     struct dentry *dentry, int ret)
{
	if (ret)
		return ret;
	ret = pin_delete(dir, dentry, false);
	return ret ? ret : shirudo_mountpoint_guard(dentry);
}

SEC("lsm/inode_rmdir")
int BPF_PROG(shirudo_lsm_inode_rmdir, struct inode *dir,
	     struct dentry *dentry, int ret)
{
	if (ret)
		return ret;
	ret = pin_delete(dir, dentry, true);
	return ret ? ret : shirudo_mountpoint_guard(dentry);
}

/*
 * The private bpffs takes no entry shirudo did not make. bpffs lets
 * root make directories, symbolic links and hard links: a symbolic
 * link in place of a pin directory would send the pins of the next
 * load into a bpffs of root's own, where no guard reaches them, and a
 * hard link to a pin would keep the link alive past its unlink.
 */
SEC("lsm/inode_mkdir")
int BPF_PROG(shirudo_lsm_inode_mkdir, const struct mnt_idmap *idmap,
	     struct inode *dir, struct dentry *dentry, umode_t mode, int ret)
{
	if (ret)
		return ret;
	return shirudo_bpffs_guard(BPF_CORE_READ(dir, i_sb, s_dev),
				   TAMPER_PIN_ENTRY);
}

SEC("lsm/inode_symlink")
int BPF_PROG(shirudo_lsm_inode_symlink, const struct mnt_idmap *idmap,
	     struct inode *dir, struct dentry *dentry, const char *old_name,
	     int ret)
{
	if (ret)
		return ret;
	return shirudo_bpffs_guard(BPF_CORE_READ(dir, i_sb, s_dev),
				   TAMPER_PIN_ENTRY);
}

SEC("lsm/inode_link")
int BPF_PROG(shirudo_lsm_inode_link, const struct mnt_idmap *idmap,
	     struct dentry *old_dentry, struct inode *dir,
	     struct dentry *new_dentry, int ret)
{
	if (ret)
		return ret;
	return shirudo_bpffs_guard(BPF_CORE_READ(dir, i_sb, s_dev),
				   TAMPER_PIN_ENTRY);
}

/*
 * A kexec hands the machine to a kernel and an initrd of root's
 * choosing with the TPM as it is, the PCRs and this boot's register
 * with it, so the evidence of this boot would vouch for whatever runs
 * after. No task loads a kexec image or initramfs by either system
 * call.
 */
SEC("lsm/kernel_load_data")
int BPF_PROG(shirudo_lsm_kernel_load_data, enum kernel_load_data_id id,
	     bool contents, int ret)
{
	if (ret)
		return ret;
	if (id != LOADING_KEXEC_IMAGE && id != LOADING_KEXEC_INITRAMFS)
		return 0;
	return shirudo_tamper_deny(TAMPER_KEXEC, -EPERM);
}

SEC("lsm/kernel_read_file")
int BPF_PROG(shirudo_lsm_kernel_read_file, struct file *file,
	     enum kernel_read_file_id id, bool contents, int ret)
{
	if (ret)
		return ret;
	if (id != READING_KEXEC_IMAGE && id != READING_KEXEC_INITRAMFS)
		return 0;
	return shirudo_tamper_deny(TAMPER_KEXEC, -EPERM);
}

#define REASON(name)	bpf_core_enum_value(enum lockdown_reason, name)

/* The kernel's numbers move between releases; the counters' do not. */
static __always_inline enum integrity_point
integrity_point_of(enum lockdown_reason what)
{
	if (what == REASON(LOCKDOWN_MODULE_SIGNATURE))
		return INTEGRITY_MODULE_SIGNATURE;
	if (what == REASON(LOCKDOWN_DEV_MEM))
		return INTEGRITY_DEV_MEM;
	if (what == REASON(LOCKDOWN_EFI_TEST))
		return INTEGRITY_EFI_TEST;
	if (what == REASON(LOCKDOWN_KEXEC))
		return INTEGRITY_KEXEC;
	if (what == REASON(LOCKDOWN_PCI_ACCESS))
		return INTEGRITY_PCI_ACCESS;
	if (what == REASON(LOCKDOWN_IOPORT))
		return INTEGRITY_IOPORT;
	if (what == REASON(LOCKDOWN_MSR))
		return INTEGRITY_MSR;
	if (what == REASON(LOCKDOWN_ACPI_TABLES))
		return INTEGRITY_ACPI_TABLES;
	if (what == REASON(LOCKDOWN_DEVICE_TREE))
		return INTEGRITY_DEVICE_TREE;
	if (what == REASON(LOCKDOWN_PCMCIA_CIS))
		return INTEGRITY_PCMCIA_CIS;
	if (what == REASON(LOCKDOWN_TIOCSSERIAL))
		return INTEGRITY_TIOCSSERIAL;
	if (what == REASON(LOCKDOWN_MODULE_PARAMETERS))
		return INTEGRITY_MODULE_PARAMETERS;
	if (what == REASON(LOCKDOWN_MMIOTRACE))
		return INTEGRITY_MMIOTRACE;
	if (what == REASON(LOCKDOWN_DEBUGFS))
		return INTEGRITY_DEBUGFS;
	if (what == REASON(LOCKDOWN_XMON_WR))
		return INTEGRITY_XMON_WR;
	if (what == REASON(LOCKDOWN_BPF_WRITE_USER))
		return INTEGRITY_BPF_WRITE_USER;
	if (what == REASON(LOCKDOWN_DBG_WRITE_KERNEL))
		return INTEGRITY_DBG_WRITE_KERNEL;
	if (what == REASON(LOCKDOWN_RTAS_ERROR_INJECTION))
		return INTEGRITY_RTAS_ERROR_INJECTION;
	if (what == REASON(LOCKDOWN_XEN_USER_ACTIONS))
		return INTEGRITY_XEN_USER_ACTIONS;
	if (what == REASON(LOCKDOWN_KCORE))
		return INTEGRITY_KCORE;
	return INTEGRITY_OTHER;
}

#undef REASON

/*
 * Lockdown in integrity mode, the ways root has to change the running
 * kernel, from an unsigned module and /dev/mem to debugfs writes, and
 * /proc/kcore, which that mode leaves readable, whether or not the
 * command line asks for lockdown: the kernel's own lockdown LSM decides
 * first where it runs. Each refusal counts on the integrity counter of
 * its reason. The hibernation check, which every read of
 * /sys/power/state makes, is refused without a count.
 */
SEC("lsm/locked_down")
int BPF_PROG(shirudo_lsm_locked_down, enum lockdown_reason what, int ret)
{
	if (ret)
		return ret;
	if (what == bpf_core_enum_value(enum lockdown_reason,
					LOCKDOWN_HIBERNATION))
		return -EPERM;
	if (what == bpf_core_enum_value(enum lockdown_reason, LOCKDOWN_KCORE) ||
	    (what > LOCKDOWN_NONE &&
	     what < bpf_core_enum_value(enum lockdown_reason,
					LOCKDOWN_INTEGRITY_MAX)))
		return shirudo_integrity_deny(integrity_point_of(what), -EPERM);
	return 0;
}

SEC("lsm/inode_rename")
int BPF_PROG(shirudo_lsm_inode_rename, struct inode *old_dir,
	     struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry, int ret)
{
	struct sb_id *id;
	__u32 dev;

	if (ret)
		return ret;
	id = shirudo_policy();
	dev = BPF_CORE_READ(old_dir, i_sb, s_dev);
	/* Pin lifecycle operations have no rename step. */
	if (id && id->sb_dev && id->sb_dev == dev && !shirudo_bootstrap_task())
		return shirudo_tamper_deny(TAMPER_PIN_RENAME, -EPERM);
	ret = shirudo_bpffs_guard(dev,
				  TAMPER_PIN_RENAME);
	if (!ret)
		ret = shirudo_bpffs_guard(BPF_CORE_READ(new_dir, i_sb, s_dev),
					  TAMPER_PIN_RENAME);
	if (!ret)
		ret = shirudo_mountpoint_guard(old_dentry);
	return ret ? ret : shirudo_mountpoint_guard(new_dentry);
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
				   TAMPER_PIN_XATTR);
}

/* Symmetric to setxattr: deny removing a pin's xattrs from non-shirudo. */
SEC("lsm/inode_removexattr")
int BPF_PROG(shirudo_lsm_inode_removexattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name, int ret)
{
	if (ret)
		return ret;
	return shirudo_bpffs_guard(BPF_CORE_READ(dentry, d_inode, i_sb, s_dev),
				   TAMPER_PIN_XATTR);
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
 * These checks cover the bpffs itself. The VFS calls sb_umount for the
 * requested mount alone, so an unmount of a mount above the bpffs, or
 * of one whose unmount propagates to such a mount, is caught by the walk
 * in bpf2.c from the mount init recorded.
 */
static __always_inline __u32 shirudo_bpffs_dev(void)
{
	struct sb_id *id;
	__u32 zero = 0;

	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	return id ? id->sb_dev : 0;
}

/* -EPERM, counted at `point`, when sb_dev is the bpffs; else 0. */
static __always_inline int
shirudo_deny_bpffs_mount(__u32 sb_dev, enum tamper_point point)
{
	__u32 bpffs = shirudo_bpffs_dev();

	if (!bpffs || sb_dev != bpffs)
		return 0;
	return shirudo_tamper_deny(point, -EPERM);
}

char _license[] SEC("license") = "Dual BSD/GPL";

#define MOUNT_WALK_MAX		1024
#define MOUNT_DEPTH_MAX		32
#define MOUNT_MASTERS_MAX	4
#define MOUNT_CHILDREN_MAX	64
#define MOUNT_CHAIN_MAX		8
#define SHIRUDO_MNT_DETACH	2
#define SHIRUDO_MS_REC		(1UL << 14)
#define SHIRUDO_MS_SILENT	(1UL << 15)
#define SHIRUDO_MS_SHARED	(1UL << 20)
/* MS_UNBINDABLE, MS_PRIVATE, MS_SLAVE and MS_SHARED from linux/mount.h. */
#define PROPAGATION_TYPES	((1UL << 17) | (1UL << 18) | (1UL << 19) | SHIRUDO_MS_SHARED)

static __always_inline struct mount *shirudo_mount_of(struct vfsmount *mnt)
{
	return (struct mount *)((__u64)mnt -
				bpf_core_field_offset(struct mount, mnt));
}

static __always_inline struct mount *shirudo_mount_child(__u64 entry)
{
	return (struct mount *)(entry -
				bpf_core_field_offset(struct mount, mnt_child));
}

static __always_inline __u64 shirudo_mount_children(struct mount *m)
{
	return (__u64)m + bpf_core_field_offset(struct mount, mnt_mounts);
}

/* The peer group a mount propagates to, 0 for one that propagates to none. */
static __always_inline int shirudo_mount_group(struct mount *m)
{
	if (!(BPF_CORE_READ(m, mnt_t_flags) & T_SHARED))
		return 0;
	return BPF_CORE_READ(m, mnt_group_id);
}

/*
 * Whether unmounting m unmounts a: a is m, or a copy of m that
 * propagation made, at m's mountpoint on a peer of m's parent or on a
 * slave of that peer group, directly or through masters of its own. A
 * peer of m itself at another mountpoint stays: a bind of a shared
 * mount is a peer of its source, and the root's binds are peers of the
 * root.
 */
static __always_inline bool shirudo_umount_reaches(struct mount *m,
						   struct mount *a)
{
	struct mount *parent;
	int group, i;

	if (a == m)
		return true;
	if (BPF_CORE_READ(a, mnt_mp) != BPF_CORE_READ(m, mnt_mp))
		return false;
	parent = BPF_CORE_READ(m, mnt_parent);
	if (!parent)
		return true;
	group = shirudo_mount_group(parent);
	if (!group)
		return false;
	parent = BPF_CORE_READ(a, mnt_parent);
	bpf_for(i, 0, MOUNT_MASTERS_MAX) {
		if (!parent)
			return false;
		if (shirudo_mount_group(parent) == group)
			return true;
		parent = BPF_CORE_READ(parent, mnt_master);
	}
	return true;
}

/*
 * Whether unmounting m unmounts the bpffs mount init made or one above
 * it. The root of the namespace has no parent to be unmounted from.
 */
static __always_inline bool shirudo_umount_takes_bpffs(struct mount *m,
						       struct mount *bpffs)
{
	struct mount *a = bpffs, *parent;
	int i;

	bpf_for(i, 0, MOUNT_DEPTH_MAX) {
		parent = BPF_CORE_READ(a, mnt_parent);
		if (!parent || parent == a)
			return false;
		if (shirudo_umount_reaches(m, a))
			return true;
		a = parent;
	}
	return true;
}

/*
 * From m, the last mount of a subtree walked, the next one in
 * first-child, next-sibling order: the next sibling of m or of its
 * nearest ancestor below t that has one. 1 with *m set to it, 0 when the
 * walk is back at t, -1 when the tree cannot be walked within the bounds.
 */
static __always_inline int shirudo_mount_next_sibling(struct mount *t,
						      struct mount **m)
{
	struct mount *parent, *cur = *m;
	__u64 next;
	int j;

	bpf_for(j, 0, MOUNT_DEPTH_MAX) {
		if (cur == t)
			return 0;
		parent = BPF_CORE_READ(cur, mnt_parent);
		next = (__u64)BPF_CORE_READ(cur, mnt_child.next);
		if (!parent || !next)
			return -1;
		if (next != shirudo_mount_children(parent)) {
			*m = shirudo_mount_child(next);
			return 1;
		}
		cur = parent;
	}
	return -1;
}

/*
 * The pins hold the enforcement links through the bpffs superblock,
 * which goes with the last mount of it: a lazy unmount of /run took the
 * private bpffs with it, and so did one of a copy of /run in another
 * namespace whose mounts still propagated to init's. Walk what the
 * unmount of t takes down, its subtree in first-child, next-sibling
 * order without a stack and through each mount what propagation takes
 * along, and refuse one that reaches the recorded mount or one above
 * it. The namespace lock is not held here, so a tree that cannot be
 * walked within the bounds is refused rather than taken for safe.
 */
static __always_inline bool shirudo_umount_takes(struct mount *t,
						 struct mount *bpffs)
{
	struct mount *m = t;
	__u64 next;
	int i, ret;

	bpf_for(i, 0, MOUNT_WALK_MAX) {
		if (shirudo_umount_takes_bpffs(m, bpffs))
			return true;
		next = (__u64)BPF_CORE_READ(m, mnt_mounts.next);
		if (!next)
			return true;
		if (next != shirudo_mount_children(m)) {
			m = shirudo_mount_child(next);
			continue;
		}
		ret = shirudo_mount_next_sibling(t, &m);
		if (!ret)
			return false;
		if (ret < 0)
			return true;
	}
	return true;
}

/* A recursive bind preserves the mounted subtree root and its child mountpoints. */
static __always_inline struct mount *
shirudo_mount_find_child(struct mount *parent, struct mount *skip,
			 struct mount *original, bool same_mountpoint)
{
	__u64 head = shirudo_mount_children(parent), next;
	struct super_block *sb = BPF_CORE_READ(original, mnt.mnt_sb);
	struct dentry *root = BPF_CORE_READ(original, mnt.mnt_root);
	struct mountpoint *mp = BPF_CORE_READ(original, mnt_mp);
	struct mount *child;
	int i;

	if (!sb || !root || (same_mountpoint && !mp))
		return NULL;

	next = (__u64)BPF_CORE_READ(parent, mnt_mounts.next);
	bpf_for(i, 0, MOUNT_CHILDREN_MAX) {
		if (!next || next == head)
			return NULL;
		child = shirudo_mount_child(next);
		if (child != skip &&
		    BPF_CORE_READ(child, mnt.mnt_sb) == sb &&
		    BPF_CORE_READ(child, mnt.mnt_root) == root &&
		    (!same_mountpoint || BPF_CORE_READ(child, mnt_mp) == mp))
			return child;
		next = (__u64)BPF_CORE_READ(child, mnt_child.next);
	}
	return NULL;
}

/*
 * PID 1 leaves the initrd by binding /run recursively into the new
 * root, pivot_root(".", ".") and a lazy unmount of the old root, now
 * stacked on the new root's own root. The recorded bpffs mount goes
 * with the old root while the recursive copy of it keeps the superblock
 * mounted. That one unmount, once per boot, may hand the record over
 * to the copy: return the copy when the caller is PID 1, the unmount is
 * lazy, t is stacked on PID 1's root and the record lies below t, as
 * the bpffs on the /run/shirudo tmpfs on systemd's /run. The copy is
 * found by following the same chain down from the new root: a child of
 * it on the superblock of the chain's top below t, then at each level a
 * child on the next superblock at the same mountpoint, which a
 * recursive bind reuses. A soft reboot binds /run alone and finds none.
 */
static __always_inline struct mount *
shirudo_root_switch_copy(struct mount *t, int flags,
			 const struct mount_record *rec, struct mount *bpffs)
{
	struct task_struct *task = bpf_get_current_task_btf();
	__u64 chain[MOUNT_CHAIN_MAX] = {};
	struct mount *root, *a, *orig, *copy;
	int i, level, depth = 0;

	if (!(flags & SHIRUDO_MNT_DETACH) ||
	    (__u32)bpf_get_current_pid_tgid() != 1 || !rec->initrd_root_id ||
	    BPF_CORE_READ(t, mnt_id_unique) != rec->initrd_root_id)
		return NULL;
	root = shirudo_mount_of(BPF_CORE_READ(task, fs, root.mnt));
	if (BPF_CORE_READ(root, mnt_id_unique) != rec->sysroot_id ||
	    BPF_CORE_READ(t, mnt_parent) != root ||
	    BPF_CORE_READ(t, mnt_mp, m_dentry) !=
	    BPF_CORE_READ(task, fs, root.dentry))
		return NULL;
	a = bpffs;
	bpf_for(i, 0, MOUNT_CHAIN_MAX) {
		if (!a || a == t || a == root)
			break;
		chain[i] = (__u64)a;
		depth = i + 1;
		a = BPF_CORE_READ(a, mnt_parent);
	}
	if (a != t || !depth)
		return NULL;
	copy = root;
	bpf_for(i, 0, MOUNT_CHAIN_MAX) {
		level = depth - 1 - i;
		if (level < 0 || level >= MOUNT_CHAIN_MAX)
			break;
		orig = (struct mount *)chain[level];
		copy = shirudo_mount_find_child(copy, i ? NULL : t, orig, i != 0);
		if (!copy)
			return NULL;
	}
	return copy == root ? NULL : copy;
}

/*
 * Refuse an unmount that takes the recorded bpffs mount or one above
 * it, except PID 1's switch from the initrd, which keeps a copy of it
 * mounted and records that copy in its place.
 */
static __always_inline int shirudo_umount_above(struct vfsmount *mnt,
						int flags)
{
	struct mount_record *rec;
	struct mount *t, *copy, *bpffs;
	__u32 zero = 0;

	rec = bpf_map_lookup_elem(&shirudo_mnt_rec, &zero);
	if (!rec)
		return 0;
	bpffs = (struct mount *)rec->mount;
	if (!bpffs)
		return 0;
	t = shirudo_mount_of(mnt);
	if (!shirudo_umount_takes(t, bpffs))
		return 0;
	copy = shirudo_root_switch_copy(t, flags, rec, bpffs);
	if (copy && !shirudo_umount_takes(t, copy) &&
	    __sync_val_compare_and_swap(&rec->mount, (__u64)bpffs,
					(__u64)copy) == (__u64)bpffs) {
		rec->initrd_root_id = 0;
		return 0;
	}
	return shirudo_tamper_deny(TAMPER_BPFFS_UMOUNT_ABOVE, -EPERM);
}

#define EFIVARFS_MAGIC		0xde5e81e4
#define FMODE_WRITE		0x2
#define HIBERNATE_LOCATION	"HibernateLocation-"

/*
 * systemd in the initrd resumes from the device the HibernateLocation
 * EFI variable names, before init attaches a guard: a variable root
 * writes now would have the next boot resume an image of root's making.
 */
static __always_inline bool hibernate_location(struct file *file)
{
	char name[sizeof(HIBERNATE_LOCATION)];
	const unsigned char *s;

	if (BPF_CORE_READ(file, f_inode, i_sb, s_magic) != EFIVARFS_MAGIC ||
	    !(BPF_CORE_READ(file, f_mode) & FMODE_WRITE))
		return false;
	s = BPF_CORE_READ(file, f_path.dentry, d_name.name);
	if (bpf_probe_read_kernel_str(name, sizeof(name), s) != sizeof(name))
		return false;
	return !bpf_strncmp(name, sizeof(name) - 1, HIBERNATE_LOCATION);
}

/*
 * A pin opened as a file reads a map's contents through bpffs, so pins
 * open for shirudo alone; directories stay listable. The bpffs mount of
 * init's namespace is recorded once when the bootstrap task opens its
 * root with the mount guards live: the one the unmount guard keeps,
 * where a copy in another namespace is any process's to drop.
 */
SEC("lsm/file_open")
int BPF_PROG(shirudo_lsm_file_open, struct file *file, int ret)
{
	struct sb_id *id = shirudo_policy();
	struct mount_record *rec;
	struct vfsmount *mnt;
	__u32 zero = 0;

	if (ret)
		return ret;
	if (hibernate_location(file))
		return shirudo_integrity_deny(INTEGRITY_HIBERNATE_LOCATION,
					      -EPERM);
	if (!id)
		return 0;
	mnt = BPF_CORE_READ(file, f_path.mnt);
	if (!mnt || BPF_CORE_READ(mnt, mnt_sb, s_dev) != id->sb_dev)
		return 0;
	if ((BPF_CORE_READ(file, f_inode, i_mode) & S_IFMT) != S_IFDIR)
		return shirudo_self_or_deny(TAMPER_OBJ_GET);
	if (!shirudo_bootstrap_task())
		return 0;
	rec = bpf_map_lookup_elem(&shirudo_mnt_rec, &zero);
	if (rec && !rec->mount) {
		struct mount *mount = shirudo_mount_of(mnt);

		rec->mount_ns = (__u64)BPF_CORE_READ(mount, mnt_ns);
		if (rec->mount_ns)
			rec->mount = (__u64)mount;
	}
	return 0;
}

static __always_inline int shirudo_parent_mount(struct super_block *sb,
						bool trusted_target)
{
	struct sb_id *id = shirudo_policy();

	if (!sb || !id || !id->run_dev ||
	    BPF_CORE_READ(sb, s_dev) != id->run_dev)
		return 0;
	return trusted_target && shirudo_task_is_self(id) ? 0 : -EPERM;
}

static __always_inline int shirudo_image_mount(struct super_block *sb,
					       bool replace)
{
	struct sb_id *id = shirudo_policy();
	struct verity_device *device;
	struct block_device *bdev;

	if (!sb || !id)
		return 0;
	bdev = BPF_CORE_READ(sb, s_bdev);
	if (!bdev)
		return 0;
	device = shirudo_bdev_device(bdev);
	if (!device)
		return 0;
	if (replace && device->kind == DEVICE_CONFIG &&
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
		return shirudo_tamper_deny(TAMPER_BPFFS_UMOUNT,
					   -EPERM);
	ret = shirudo_deny_bpffs_mount(dev, TAMPER_BPFFS_UMOUNT);
	if (!ret)
		ret = shirudo_umount_above(mnt, flags);
	return ret ? ret : shirudo_image_mount(sb, true);
}

/* Only the host's PID 1 can cross between the two roots recorded by bootstrap. */
static __always_inline bool shirudo_initrd_pid1(const struct mount_record *rec)
{
	struct task_struct *task;
	struct vfsmount *vfsmnt;
	struct mount *root;

	if ((__u32)bpf_get_current_pid_tgid() != 1 || !rec->initrd_root_id)
		return false;
	task = bpf_get_current_task_btf();
	vfsmnt = BPF_CORE_READ(task, fs, root.mnt);
	if (!vfsmnt)
		return false;
	root = shirudo_mount_of(vfsmnt);
	return BPF_CORE_READ(root, mnt_id_unique) == rec->initrd_root_id;
}

/*
 * Refuse a change to the recorded bpffs mount or to a mount above it,
 * in the namespace bootstrap recorded, to every caller but PID 1 on the
 * initrd root.
 */
static __always_inline int shirudo_bpffs_tree_change(struct mount *target)
{
	struct mnt_namespace *ns;
	struct mount_record *rec;
	struct mount *m, *parent;
	__u32 zero = 0;
	int i;

	rec = bpf_map_lookup_elem(&shirudo_mnt_rec, &zero);
	if (!rec)
		return 0;
	m = (struct mount *)rec->mount;
	if (!m)
		return 0;
	if (BPF_CORE_READ_INTO(&ns, target, mnt_ns))
		goto deny;
	if ((__u64)ns != rec->mount_ns)
		return 0;
	if (shirudo_initrd_pid1(rec))
		return 0;
	bpf_for(i, 0, MOUNT_DEPTH_MAX) {
		if (m == target)
			break;
		parent = BPF_CORE_READ(m, mnt_parent);
		if (parent == m)
			return 0;
		if (!parent)
			break;
		m = parent;
	}
deny:
	return shirudo_tamper_deny(TAMPER_BPFFS_MOUNT, -EPERM);
}

static __always_inline int shirudo_propagation(struct mount *target,
					       unsigned long type)
{
	/*
	 * The kernel refuses to move a mount whose parent is shared, so a
	 * request to share only restores what this guard keeps. Tools ask
	 * for it on directories below the ancestry: ip netns on /run/netns.
	 */
	if (type == SHIRUDO_MS_SHARED)
		return 0;
	return shirudo_bpffs_tree_change(target);
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
				     TAMPER_BPFFS_MOUNT) ||
	    shirudo_deny_bpffs_mount(BPF_CORE_READ(to, s_dev),
				     TAMPER_BPFFS_MOUNT))
		return -EPERM;
	ret = shirudo_image_mount(from, true);
	return ret ? ret : shirudo_image_mount(to, true);
}

SEC("lsm/sb_pivotroot")
int BPF_PROG(shirudo_lsm_sb_pivotroot, const struct path *put_old,
	     const struct path *new_root, int ret)
{
	struct mnt_namespace *ns;
	struct mount_record *rec;
	struct mount *target;
	struct vfsmount *vfsmnt;
	__u32 zero = 0;

	if (ret)
		return ret;
	rec = bpf_map_lookup_elem(&shirudo_mnt_rec, &zero);
	if (!rec || !rec->mount_ns)
		return 0;
	vfsmnt = BPF_CORE_READ(new_root, mnt);
	target = shirudo_mount_of(vfsmnt);
	if (BPF_CORE_READ_INTO(&ns, target, mnt_ns))
		goto deny;
	if ((__u64)ns != rec->mount_ns)
		return 0;
	if (shirudo_initrd_pid1(rec) &&
	    BPF_CORE_READ(target, mnt_id_unique) == rec->sysroot_id)
		return 0;
deny:
	return shirudo_tamper_deny(TAMPER_BPFFS_UMOUNT_ABOVE, -EPERM);
}

SEC("lsm/sb_mount")
int BPF_PROG(shirudo_lsm_sb_mount, const char *dev_name,
	     const struct path *path, const char *type,
	     unsigned long flags, void *data, int ret)
{
	struct super_block *sb = BPF_CORE_READ(path, mnt, mnt_sb);

	if (ret)
		return ret;
	if ((flags & PROPAGATION_TYPES) &&
	    !(flags & ~(PROPAGATION_TYPES | SHIRUDO_MS_REC | SHIRUDO_MS_SILENT))) {
		struct vfsmount *vfsmnt = BPF_CORE_READ(path, mnt);
		unsigned long propagation = flags & PROPAGATION_TYPES;

		ret = shirudo_propagation(shirudo_mount_of(vfsmnt), propagation);
		return ret ? ret : shirudo_image_mount(sb, true);
	}
	if ((flags & PROPAGATION_TYPES) && shirudo_parent_mount(sb, false))
		return -EPERM;
	ret = shirudo_parent_mount(sb, true);
	if (ret)
		return ret;
	ret = shirudo_deny_bpffs_mount(BPF_CORE_READ(sb, s_dev),
				       TAMPER_BPFFS_MOUNT);
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
				       TAMPER_BPFFS_MOUNT);
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
	struct sb_id *id = shirudo_policy();
	struct expected_root *expected;
	struct verity_device device = {};
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
		device.kind = DEVICE_RUNTIME;
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
		device.kind = DEVICE_CONFIG;
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

#define DM_CONTROL_DEV	((10U << 20) | 236U)
#define DM_IOCTL_TYPE	0xfdU

/* Match the kernel's type/number dispatch. */
static __always_inline int shirudo_dm_ioctl(struct file *file,
					    unsigned int cmd, int ret)
{
	struct sb_id *id = shirudo_policy();
	struct inode *inode;

	if (ret || !id || shirudo_task_is_self(id))
		return ret;
	inode = BPF_CORE_READ(file, f_inode);
	if ((BPF_CORE_READ(inode, i_mode) & 0170000) != 0020000 ||
	    BPF_CORE_READ(inode, i_rdev) != DM_CONTROL_DEV)
		return 0;
	if (((cmd >> 8) & 0xff) != DM_IOCTL_TYPE)
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

/*
 * PERF_EVENT_IOC_SET_BPF binds a program to a perf event without a bpf()
 * command, and a program's fd is root's for the asking by id: a kprobe
 * program a signed loader created would run at a probe of root's own.
 * Keep it to the caller BPF_LINK_CREATE is kept to.
 */
#define XFS_SUPER_MAGIC		0x58465342
#define XFS_IOC_ATTRMULTI_NR	123

/*
 * XFS_IOC_ATTRMULTI_BY_HANDLE sets and removes the attributes of the
 * inode a handle names through xfs_attr_change(), past vfs_setxattr()
 * and so past every xattr hook: a seal label removed that way unseals
 * the inode. Matched by type and number, as its size differs between
 * the native and the compat call.
 */
static __always_inline bool xfs_attrmulti(struct file *file, unsigned int cmd)
{
	return ((cmd >> 8) & 0xff) == 'X' &&
	       (cmd & 0xff) == XFS_IOC_ATTRMULTI_NR &&
	       BPF_CORE_READ(file, f_inode, i_sb, s_magic) == XFS_SUPER_MAGIC;
}

static __always_inline int shirudo_ioctl(struct file *file, unsigned int cmd,
					 int ret)
{
	if (ret)
		return ret;
	if (cmd == SHIRUDO_PIN_GRANT_BEGIN || cmd == SHIRUDO_PIN_GRANT_END)
		return pin_grant_ioctl(file, cmd);
	if (cmd == PERF_EVENT_IOC_SET_BPF)
		return shirudo_self_or_deny(TAMPER_PERF_ATTACH);
	if (xfs_attrmulti(file, cmd))
		return shirudo_self_or_deny(TAMPER_XATTR_HANDLE);
	return shirudo_dm_ioctl(file, cmd, ret);
}

SEC("lsm/file_ioctl")
int BPF_PROG(shirudo_lsm_file_ioctl, struct file *file, unsigned int cmd,
	     unsigned long arg, int ret)
{
	return shirudo_ioctl(file, cmd, ret);
}

SEC("lsm/file_ioctl_compat")
int BPF_PROG(shirudo_lsm_file_ioctl_compat, struct file *file,
	     unsigned int cmd, unsigned long arg, int ret)
{
	return shirudo_ioctl(file, cmd, ret);
}

#define SHIRUDO_TPM_COPY(out, in, size) bpf_probe_read_kernel(out, size, in)
#include "../include/shirudo/tpm_command.h"
#undef SHIRUDO_TPM_COPY

/* Inspect each submitted command, including writes through inherited FDs. */
SEC("lsm/tpm_command")
int BPF_PROG(shirudo_lsm_tpm_command, struct file *file,
	     const __u8 *command, __u64 length, int ret)
{
	struct sb_id *id = shirudo_policy();
	enum shirudo_tpm_access access;

	if (ret)
		return ret;
	if (!id || length > 4096)
		return -EPERM;
	access = shirudo_tpm_access(command, length, id->config_pcr);
	if (shirudo_tpm_allowed(access, shirudo_task_is_self(id)))
		return 0;
	if (length >= 18) {
		__u32 code, index;

		if (!bpf_probe_read_kernel(&code, sizeof(code), command + 6) &&
		    !bpf_probe_read_kernel(&index, sizeof(index), command + 14) &&
		    bpf_ntohl(code) == TPM_CC_NV_EXTEND &&
		    bpf_ntohl(index) == id->nv_index)
			shirudo_tamper_count(TAMPER_TPM_EXTEND);
	}
	return shirudo_tamper_deny(SHIRUDO_TAMPER_TPM_WRITE, -EACCES);
}
