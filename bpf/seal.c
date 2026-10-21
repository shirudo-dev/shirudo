// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Filesystem-sealing LSM: an inode label, never a path, marks what only
 * shirudo may modify.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "shirudo_identity.h"
#include "shirudo_tamper.h"

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
#ifndef S_IFMT
#define S_IFMT		00170000
#endif
#ifndef S_IFDIR
#define S_IFDIR		0040000
#endif

char _license[] SEC("license") = "Dual BSD/GPL";

#define SHIRUDO_XATTR	"security.bpf.shirudo"
/* SHA-256 hex, as util/seal.h writes it. */
#define LABEL_LEN	64

/*
 * The xattr kfuncs refuse a stack buffer, and a task is in one of these
 * hooks at a time.
 */
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

struct seal_dir_mark {
	char	label[LABEL_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct seal_dir_mark);
} seal_dir_marks SEC(".maps");

extern int bpf_get_dentry_xattr(struct dentry *dentry, const char *name__str,
				struct bpf_dynptr *value_p) __ksym;
extern int bpf_get_file_xattr(struct file *file, const char *name__str,
			      struct bpf_dynptr *value_p) __ksym;
extern int bpf_inode_init_xattr(struct xattr *xattrs,
				int *xattr_count__ctx_out,
				const char *name__str,
				const struct bpf_dynptr *value_p) __ksym;

static __always_inline int seal_caller(enum shirudo_tamper_point point)
{
	struct shirudo_sb_id *id;
	__u32 zero = 0;

	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (!id)
		return -EACCES;
	return shirudo_task_is_self(id) ? 0 :
	       shirudo_tamper_deny(point, -EACCES);
}

/*
 * No label, or a file system without security xattrs, is not shirudo's
 * inode. Neither is one the caller may not read: the kfunc checks read
 * permission, and failing that closed would refuse every write-only
 * open and every unlink of an unreadable file. Anything else needs
 * shirudo.
 */
static __always_inline int seal_verdict(int tlen,
					enum shirudo_tamper_point point)
{
	switch (tlen) {
	case -ENODATA:
	case -EOPNOTSUPP:
	case -EACCES:
	case -EPERM:
		return 0;
	default:
		return seal_caller(point);
	}
}

static __always_inline bool seal_is_label(const char *name)
{
	char buf[sizeof(SHIRUDO_XATTR) + 1];
	long n;

	n = bpf_probe_read_kernel_str(buf, sizeof(buf), name);
	if (n != sizeof(SHIRUDO_XATTR))
		return false;
	return !bpf_strncmp(buf, sizeof(SHIRUDO_XATTR), SHIRUDO_XATTR);
}

static __always_inline struct seal_scratch *
seal_scratch_get(struct task_struct *task)
{
	return bpf_task_storage_get(&seal_scratch_map, task, NULL,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

static __always_inline bool seal_is_dir(struct inode *inode)
{
	return (BPF_CORE_READ(inode, i_mode) & S_IFMT) == S_IFDIR;
}

static __always_inline void seal_mark(struct inode *inode, const char *label,
				      int len)
{
	struct seal_dir_mark *m;

	if (len != LABEL_LEN) {
		bpf_inode_storage_delete(&seal_dir_marks, inode);
		return;
	}
	m = bpf_inode_storage_get(&seal_dir_marks, inode, NULL,
				  BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (m)
		__builtin_memcpy(m->label, label, LABEL_LEN);
}

/*
 * A later hook may still reject the exec, so the label is only staged
 * here and becomes the task's mark in bprm_committed_creds.
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
		return 0;

	s = bpf_task_storage_get(&seal_scratch_map, target, NULL, 0);
	if (s && s->exe_is_shirudo)
		return shirudo_tamper_deny(SHIRUDO_TAMPER_SEAL_PERF, -EACCES);

	return 0;
}

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
		return shirudo_tamper_deny(SHIRUDO_TAMPER_SEAL_PTRACE, -EACCES);

	return 0;
}

static __always_inline bool seal_is_exe(struct inode *inode)
{
	struct shirudo_sb_id *id;
	__u32 zero = 0;

	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	return id && BPF_CORE_READ(inode, i_sb, s_dev) == id->exe_dev &&
	       BPF_CORE_READ(inode, i_ino) == id->exe_ino;
}

SEC("lsm.s/file_open")
int BPF_PROG(shirudo_seal_file_open, struct file *file)
{
	struct inode *inode = file->f_inode;
	struct task_struct *task;
	struct seal_scratch *s;
	struct bpf_dynptr tdp;

	task = bpf_get_current_task_btf();
	if (seal_is_dir(inode)) {
		/* never opened for writing; mark it */
		s = seal_scratch_get(task);
		if (!s)
			return 0;
		bpf_dynptr_from_mem(s->target, LABEL_LEN, 0, &tdp);
		seal_mark(inode, s->target,
			  bpf_get_file_xattr(file, SHIRUDO_XATTR, &tdp));
		return 0;
	}
	if (!(BPF_CORE_READ(file, f_mode) & FMODE_WRITE))
		return 0;
	/*
	 * Whoever cannot read the label passes seal_verdict(), and an ACL,
	 * which no sleepable hook sees, can grant write without read: the
	 * binary that is shirudo does not depend on the label.
	 */
	if (seal_is_exe(inode))
		return seal_caller(SHIRUDO_TAMPER_SEAL_WRITE);
	s = seal_scratch_get(task);
	if (!s) /* cannot read the label */
		return seal_caller(SHIRUDO_TAMPER_SEAL_WRITE);
	bpf_dynptr_from_mem(s->target, LABEL_LEN, 0, &tdp);
	return seal_verdict(bpf_get_file_xattr(file, SHIRUDO_XATTR, &tdp),
			    SHIRUDO_TAMPER_SEAL_WRITE);
}

static __always_inline void seal_mark_dentry(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct seal_scratch *s;
	struct bpf_dynptr tdp;

	if (!inode || !seal_is_dir(inode))
		return;
	s = seal_scratch_get(bpf_get_current_task_btf());
	if (!s)
		return;
	bpf_dynptr_from_mem(s->target, LABEL_LEN, 0, &tdp);
	seal_mark(inode, s->target,
		  bpf_get_dentry_xattr(dentry, SHIRUDO_XATTR, &tdp));
}

SEC("lsm.s/inode_post_setxattr")
void BPF_PROG(shirudo_seal_inode_post_setxattr, struct dentry *dentry,
	      const char *name, const void *value, __u64 size, int flags)
{
	seal_mark_dentry(dentry);
}

SEC("lsm.s/inode_post_removexattr")
void BPF_PROG(shirudo_seal_inode_post_removexattr, struct dentry *dentry,
	      const char *name)
{
	seal_mark_dentry(dentry);
}

/*
 * The hook cannot sleep, so a new inode takes its label from the
 * parent's mark, and a new directory is marked in turn so a subtree
 * created in one go needs no reopen. A failed claim aborts the
 * creation: better no inode than one of shirudo's without its label,
 * and the verifier wants an LSM errno, not the kfunc's. A file system
 * that takes no xattrs at creation gets its label from userspace.
 */
SEC("lsm/inode_init_security")
int BPF_PROG(shirudo_seal_inode_init_security, struct inode *inode,
	     struct inode *dir, const struct qstr *qstr,
	     struct xattr *xattrs, int *xattr_count)
{
	struct seal_dir_mark *m, *child;
	struct bpf_dynptr dp;

	if (!xattrs)
		return 0;
	m = bpf_inode_storage_get(&seal_dir_marks, dir, NULL, 0);
	if (!m)
		return 0;
	bpf_dynptr_from_mem(m->label, LABEL_LEN, 0, &dp);
	if (bpf_inode_init_xattr(xattrs, xattr_count, SHIRUDO_XATTR, &dp))
		return -EACCES;
	if (!seal_is_dir(inode))
		return 0;
	child = bpf_inode_storage_get(&seal_dir_marks, inode, NULL,
				      BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (child)
		__builtin_memcpy(child->label, m->label, LABEL_LEN);
	return 0;
}

static __always_inline int seal_dentry(struct dentry *dentry,
				       enum shirudo_tamper_point point)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct seal_scratch *s = seal_scratch_get(task);
	struct bpf_dynptr tdp;

	if (!s)
		return seal_caller(point);
	bpf_dynptr_from_mem(s->target, LABEL_LEN, 0, &tdp);
	return seal_verdict(bpf_get_dentry_xattr(dentry, SHIRUDO_XATTR, &tdp),
			    point);
}

SEC("lsm.s/inode_unlink")
int BPF_PROG(shirudo_seal_inode_unlink, struct inode *dir,
	     struct dentry *dentry)
{
	return seal_dentry(dentry, SHIRUDO_TAMPER_SEAL_UNLINK);
}

/*
 * The recorded executable may be renamed over, as a package upgrade
 * does; the new binary is not shirudo until init records it.
 */
SEC("lsm.s/inode_rename")
int BPF_PROG(shirudo_seal_inode_rename, struct inode *old_dir,
	     struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry)
{
	struct inode *target = BPF_CORE_READ(new_dentry, d_inode);
	int err;

	err = seal_dentry(old_dentry, SHIRUDO_TAMPER_SEAL_RENAME);
	if (err)
		return err;
	if (!target || seal_is_exe(target))
		return 0;
	return seal_dentry(new_dentry, SHIRUDO_TAMPER_SEAL_RENAME);
}

SEC("lsm.s/inode_setattr")
int BPF_PROG(shirudo_seal_inode_setattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = BPF_CORE_READ(dentry, d_inode);

	if (inode && seal_is_exe(inode))
		return seal_caller(SHIRUDO_TAMPER_SEAL_SETATTR);
	return seal_dentry(dentry, SHIRUDO_TAMPER_SEAL_SETATTR);
}

SEC("lsm.s/inode_setxattr")
int BPF_PROG(shirudo_seal_inode_setxattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name, const void *value,
	     __u64 size, int flags)
{
	if (seal_is_label(name))
		return seal_caller(SHIRUDO_TAMPER_SEAL_LABEL);
	return seal_dentry(dentry, SHIRUDO_TAMPER_SEAL_XATTR);
}

/*
 * The label itself is shirudo's to remove, whatever seal_dentry() can
 * read: a caller with CAP_SYS_ADMIN and an fsuid that cannot read the
 * inode would pass it, and nothing else would stand in the way.
 */
SEC("lsm.s/inode_removexattr")
int BPF_PROG(shirudo_seal_inode_removexattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name)
{
	if (seal_is_label(name))
		return seal_caller(SHIRUDO_TAMPER_SEAL_LABEL);
	return seal_dentry(dentry, SHIRUDO_TAMPER_SEAL_XATTR);
}
