// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0)
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Filesystem-sealing LSM: xattr-based labels, never paths.
 *
 * Every file/directory under /var/lib/shirudo/ (except the private bpffs
 * mount, which bpf/bpf2.c guards) is labelled with the inode xattr
 * security.bpf.shirudo whose value is one fixed 64-character string; the
 * shirudo binary carries the same label. The filesystem hooks read the
 * target's label and, if present, require the calling task to run the
 * executable shirudo init recorded in the identity map (the test bpf2
 * applies to the bpffs) -- so only shirudo may modify, unlink, rename,
 * or relabel its own on-disk state. The label only marks a target, and
 * only shirudo may set it; its value is public and a mounted file system
 * can present it, so a binary carrying it proves nothing about the
 * caller. The exec hooks cache whether the successfully executed file
 * carries a Shirudo label in task storage for later access-control
 * decisions. An unlabelled filesystem target is not ours and is allowed
 * through untouched; a label that cannot be read, unless the caller may
 * not read the file, is taken to be there. No bpf_d_path(), no path
 * strings: the label rides the inode, immune to bind-mount / namespace /
 * TOCTOU games. Reads are not gated; only write-mode opens and the
 * mutating inode ops are.
 *
 * The filesystem and exec xattr hooks are sleepable (lsm.s/) because
 * reading an xattr can sleep. The xattr-reading kfuncs write into a
 * bpf_dynptr over map memory (the verifier rejects stack), so the
 * scratch buffer lives in per-task storage: a task is in only one of
 * these syscalls at a time, and its storage survives CPU migration
 * across the sleeping read -- so no cross-invocation races, unlike a
 * shared global buffer.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "shirudo_identity.h"

#ifndef EPERM
#define EPERM		1
#endif
#ifndef EACCES
#define EACCES		13
#endif
#ifndef ENODATA
#define ENODATA		61
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP	95
#endif
#ifndef FMODE_WRITE
#define FMODE_WRITE	0x2
#endif

char _license[] SEC("license") = "Dual BSD/GPL";

#define SHIRUDO_XATTR	"security.bpf.shirudo"
/* The label is a SHA-256 hex string (util/seal.h) -- always 64 bytes. */
#define LABEL_LEN	64

struct seal_scratch {
	char	target[LABEL_LEN];
	__u8	exec_candidate_valid;
	__u8	exec_candidate_labelled;
	__u8	exe_is_shirudo;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct seal_scratch);
} seal_scratch_map SEC(".maps");

extern int bpf_get_dentry_xattr(struct dentry *dentry, const char *name__str,
				struct bpf_dynptr *value_p) __ksym;
extern int bpf_get_file_xattr(struct file *file, const char *name__str,
			      struct bpf_dynptr *value_p) __ksym;

/* 0 if the caller runs the executable recorded at init, else -EACCES. */
static __always_inline int seal_caller(void)
{
	struct shirudo_sb_id *id;
	__u32 zero = 0;

	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (!id)
		return -EACCES;
	return shirudo_task_is_self(id) ? 0 : -EACCES;
}

/*
 * Decide on the result of reading the target's label (tlen). No label
 * (-ENODATA) or no security xattrs on the file system (-EOPNOTSUPP) is
 * not shirudo's inode. Neither is one the caller may not read (-EACCES,
 * -EPERM): the kfunc checks read permission for the caller, so failing
 * those closed would refuse every write-only open and every unlink of an
 * unreadable file. A label of any size, or any other error, requires the
 * caller to be shirudo. 0 = allow, -EACCES = deny.
 */
static __always_inline int seal_verdict(int tlen)
{
	switch (tlen) {
	case -ENODATA:
	case -EOPNOTSUPP:
	case -EACCES:
	case -EPERM:
		return 0;
	default:
		return seal_caller();
	}
}

/* Whether an xattr name is the label itself, not a longer name under it. */
static __always_inline bool seal_is_label(const char *name)
{
	char buf[sizeof(SHIRUDO_XATTR) + 1];
	long n;

	n = bpf_probe_read_kernel_str(buf, sizeof(buf), name);
	if (n != sizeof(SHIRUDO_XATTR))
		return false;
	return !bpf_strncmp(buf, sizeof(SHIRUDO_XATTR), SHIRUDO_XATTR);
}

static __always_inline struct seal_scratch *seal_scratch_get(
						struct task_struct *task)
{
	return bpf_task_storage_get(&seal_scratch_map, task, NULL,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

/*
 * Stage the candidate executable's seal label during exec. A later LSM
 * hook may still reject the exec, so the persistent task marker is only
 * updated by bprm_committed_creds after a successful exec. This is because
 * the task struct storage would be reused on the error case for some
 * other task.
 */
SEC("lsm.s/bprm_check_security")
int BPF_PROG(shirudo_seal_bprm_check_security,
	     struct linux_binprm *bprm)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct seal_scratch *s = seal_scratch_get(task);
	struct file *file = bprm->file;
	struct bpf_dynptr dp;
	int len = -1;

	if (!s)
		return 0;
	if (file) {
		bpf_dynptr_from_mem(s->target, LABEL_LEN, 0, &dp);
		len = bpf_get_file_xattr(file, SHIRUDO_XATTR, &dp);
	}
	s->exec_candidate_labelled = len == LABEL_LEN;
	s->exec_candidate_valid = 1;
	return 0;
}

SEC("lsm.s/bprm_committed_creds")
void BPF_PROG(shirudo_seal_bprm_committed_creds,
	      const struct linux_binprm *bprm)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct seal_scratch *s =
		bpf_task_storage_get(&seal_scratch_map, task, NULL, 0);

	(void)bprm;
	if (!s || !s->exec_candidate_valid)
		return;
	if (!s->exec_candidate_labelled) {
		/* Scratch is transient; unlabelled tasks need no persistent entry. */
		bpf_task_storage_delete(&seal_scratch_map, task);
		return;
	}
	s->exe_is_shirudo = 1;
	s->exec_candidate_valid = 0;
	s->exec_candidate_labelled = 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(shirudo_seal_task_alloc, struct task_struct *child,
	     __u64 clone_flags)
{
	struct task_struct *parent = bpf_get_current_task_btf();
	struct seal_scratch *parent_s;
	struct seal_scratch *child_s;

	(void)clone_flags;
	parent_s = bpf_task_storage_get(&seal_scratch_map, parent, NULL, 0);
	if (!parent_s || !parent_s->exe_is_shirudo)
		return 0;
	child_s = seal_scratch_get(child);
	if (child_s)
		child_s->exe_is_shirudo = 1;
	return 0;
}

/* Do not create task-bound perf events for a committed Shirudo task. */
SEC("lsm/perf_event_alloc")
int BPF_PROG(shirudo_seal_perf_event_alloc,
	     struct perf_event *event, int ret)
{
	struct task_struct *target;
	struct seal_scratch *s;

	if (ret)
		return ret;

	target = event->hw.target;
	if (!target)
		return 0; /* CPU-wide events have no task target to inspect. */

	s = bpf_task_storage_get(&seal_scratch_map, target, NULL, 0);
	if (s && s->exe_is_shirudo)
		return -EACCES;

	return 0;
}

/* Do not allow ptrace access to tasks whose committed executable is Shirudo. */
SEC("lsm/ptrace_access_check")
int BPF_PROG(shirudo_seal_ptrace_access_check,
	     struct task_struct *child, unsigned int mode, int ret)
{
	struct seal_scratch *s;

	(void)mode;
	if (ret)
		return ret;

	s = bpf_task_storage_get(&seal_scratch_map, child, NULL, 0);
	if (s && s->exe_is_shirudo)
		return -EACCES;

	return 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(shirudo_seal_file_open, struct file *file)
{
	struct task_struct *task;
	struct seal_scratch *s;
	struct bpf_dynptr tdp;

	if (!(BPF_CORE_READ(file, f_mode) & FMODE_WRITE))
		return 0;		/* reads are fine */
	task = bpf_get_current_task_btf();
	s = seal_scratch_get(task);
	if (!s)
		return seal_caller();	/* cannot read the label */
	bpf_dynptr_from_mem(s->target, LABEL_LEN, 0, &tdp);
	return seal_verdict(bpf_get_file_xattr(file, SHIRUDO_XATTR, &tdp));
}

static __always_inline int seal_dentry(struct dentry *dentry)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct seal_scratch *s = seal_scratch_get(task);
	struct bpf_dynptr tdp;

	if (!s)
		return seal_caller();
	bpf_dynptr_from_mem(s->target, LABEL_LEN, 0, &tdp);
	return seal_verdict(bpf_get_dentry_xattr(dentry, SHIRUDO_XATTR, &tdp));
}

SEC("lsm.s/inode_unlink")
int BPF_PROG(shirudo_seal_inode_unlink, struct inode *dir,
	     struct dentry *dentry)
{
	return seal_dentry(dentry);
}

/* Whether an inode is the executable recorded at init. */
static __always_inline bool seal_is_exe(struct inode *inode)
{
	struct shirudo_sb_id *id;
	__u32 zero = 0;

	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	return id && BPF_CORE_READ(inode, i_sb, s_dev) == id->exe_dev &&
	       BPF_CORE_READ(inode, i_ino) == id->exe_ino;
}

/*
 * Protect both ends of a rename: moving a labelled inode out and
 * replacing one. The recorded executable may be replaced, as a package
 * upgrade does; the new binary is not shirudo until init records it.
 */
SEC("lsm.s/inode_rename")
int BPF_PROG(shirudo_seal_inode_rename, struct inode *old_dir,
	     struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry)
{
	struct inode *target = BPF_CORE_READ(new_dentry, d_inode);
	int err;

	err = seal_dentry(old_dentry);
	if (err)
		return err;
	if (!target || seal_is_exe(target))
		return 0;
	return seal_dentry(new_dentry);
}

/* Truncate, chmod, chown and utimes all come through here. */
SEC("lsm.s/inode_setattr")
int BPF_PROG(shirudo_seal_inode_setattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, struct iattr *attr)
{
	return seal_dentry(dentry);
}

SEC("lsm.s/inode_setxattr")
int BPF_PROG(shirudo_seal_inode_setxattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name, const void *value,
	     __u64 size, int flags)
{
	if (seal_is_label(name))
		return seal_caller();
	return seal_dentry(dentry);
}

SEC("lsm.s/inode_removexattr")
int BPF_PROG(shirudo_seal_inode_removexattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name)
{
	return seal_dentry(dentry);
}
