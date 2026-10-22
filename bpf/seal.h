/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_BPF_SEAL_H
#define SHIRUDO_BPF_SEAL_H

#ifndef ENOMEM
#define ENOMEM		12
#endif
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

#define SHIRUDO_XATTR	"security.bpf.shirudo"
/* The label is a SHA-256 hex string (util/seal.h) -- always 64 bytes. */
#define LABEL_LEN	64

/*
 * Xattr kfuncs may sleep and need dynptr-backed map memory. Task storage keeps
 * this scratch private across CPU migration; stack or shared globals do not.
 */
struct seal_scratch {
	char	target[LABEL_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct seal_scratch);
} seal_scratch_map SEC(".maps");

/* The label of a directory, as the last hook with a handle on it read it. */
struct seal_dir_mark {
	char	label[LABEL_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct seal_dir_mark);
} seal_dir_marks SEC(".maps");

int bpf_get_dentry_xattr(struct dentry *dentry, const char *name__str,
			 struct bpf_dynptr *value_p) __ksym;
int bpf_get_file_xattr(struct file *file, const char *name__str,
		       struct bpf_dynptr *value_p) __ksym;
int bpf_inode_init_xattr(struct xattr *xattrs, int *xattr_count__ctx_out,
			 const char *name__str,
			 const struct bpf_dynptr *value_p) __ksym;

/*
 * Labels identify protected writable targets. Caller authority comes from
 * successful runtime exec, never from a label on the caller's binary.
 */
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
 * Decide on the result of reading the target's label (tlen). No label
 * (-ENODATA) or no security xattrs on the file system (-EOPNOTSUPP) is
 * not shirudo's inode. Neither is one the caller may not read (-EACCES,
 * -EPERM): the kfunc checks read permission for the caller, so failing
 * those closed would refuse every write-only open and every unlink of an
 * unreadable file. A label of any size, or any other error, requires the
 * caller to be shirudo. 0 = allow, -EACCES = deny.
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

/* Remember a directory's label as just read (len bytes), or forget it. */
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

/* Commit only the last exec candidate; failed exec never reaches this hook. */
SEC("lsm.s/bprm_committed_creds")
void BPF_PROG(shirudo_seal_bprm_committed_creds,
	      const struct linux_binprm *bprm)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct shirudo_task_authority *authority;

	(void)bprm;
	authority = bpf_task_storage_get(&shirudo_tasks, task, NULL, 0);
	if (!authority)
		return;
	authority->trusted = authority->candidate_valid &&
			     authority->candidate_trusted;
	authority->candidate_valid = 0;
	authority->candidate_trusted = 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(shirudo_seal_task_alloc, struct task_struct *child,
	     __u64 clone_flags, int ret)
{
	struct task_struct *parent = bpf_get_current_task_btf();
	struct shirudo_task_authority *parent_authority;
	struct shirudo_task_authority *authority;

	(void)clone_flags;
	if (ret)
		return ret;
	parent_authority = bpf_task_storage_get(&shirudo_tasks, parent,
						NULL, 0);
	if (!parent_authority || !parent_authority->trusted)
		return 0;
	authority = bpf_task_storage_get(&shirudo_tasks, child, NULL,
					 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!authority)
		return -ENOMEM;
	authority->trusted = parent_authority->trusted;
	return 0;
}

/* Protect tasks marked by successful exec from the runtime image. */
SEC("lsm/perf_event_alloc")
int BPF_PROG(shirudo_seal_perf_event_alloc,
	     struct perf_event *event, int ret)
{
	struct task_struct *target;

	if (ret)
		return ret;

	target = event->hw.target;
	if (!target)
		return 0; /* CPU-wide events have no task target to inspect. */

	if (shirudo_marked(target))
		return shirudo_tamper_deny(SHIRUDO_TAMPER_SEAL_PERF, -EACCES);

	return 0;
}

/* Keep ptrace away from processes with committed exec marks. */
SEC("lsm/ptrace_access_check")
int BPF_PROG(shirudo_seal_ptrace_access_check,
	     struct task_struct *child, unsigned int mode, int ret)
{
	(void)mode;
	if (ret)
		return ret;

	if (shirudo_marked(child))
		return shirudo_tamper_deny(SHIRUDO_TAMPER_SEAL_PTRACE, -EACCES);

	return 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(shirudo_seal_file_open, struct file *file, int ret)
{
	struct inode *inode = file->f_inode;
	struct task_struct *task;
	struct seal_scratch *s;
	struct bpf_dynptr tdp;

	if (ret)
		return ret;
	task = bpf_get_current_task_btf();
	if (seal_is_dir(inode)) {
		/* Only ever opened for reading; its label marks it. */
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
	s = seal_scratch_get(task);
	if (!s)				/* cannot read the label */
		return seal_caller(SHIRUDO_TAMPER_SEAL_WRITE);
	bpf_dynptr_from_mem(s->target, LABEL_LEN, 0, &tdp);
	return seal_verdict(bpf_get_file_xattr(file, SHIRUDO_XATTR, &tdp),
			    SHIRUDO_TAMPER_SEAL_WRITE);
}

/* Refresh a directory's mark from its label after an xattr change. */
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
 * Label a new inode inside the transaction that creates it when its
 * parent directory is marked, with the parent's label, and mark a new
 * directory in turn so a subtree created in one go needs no reopen.
 * The hook cannot sleep, so the label comes from the mark, not from
 * disk. A claim that fails (no slot left, no memory) aborts the
 * creation: better no inode than one of shirudo's without its label,
 * and the verifier wants a constant in the LSM's error range rather
 * than the kfunc's. A filesystem that takes no xattrs at creation
 * passes none; the label follows from userspace there.
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
	     struct dentry *dentry, int ret)
{
	return ret ? ret : seal_dentry(dentry, SHIRUDO_TAMPER_SEAL_UNLINK);
}

/* Protect both the source and an existing destination of a rename. */
SEC("lsm.s/inode_rename")
int BPF_PROG(shirudo_seal_inode_rename, struct inode *old_dir,
	     struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry, int ret)
{
	struct inode *target = BPF_CORE_READ(new_dentry, d_inode);
	int err;

	if (ret)
		return ret;
	err = seal_dentry(old_dentry, SHIRUDO_TAMPER_SEAL_RENAME);
	if (err)
		return err;
	if (!target)
		return 0;
	return seal_dentry(new_dentry, SHIRUDO_TAMPER_SEAL_RENAME);
}

/* Truncate, chmod, chown and utimes all come through here. */
SEC("lsm.s/inode_setattr")
int BPF_PROG(shirudo_seal_inode_setattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, struct iattr *attr, int ret)
{
	return ret ? ret : seal_dentry(dentry, SHIRUDO_TAMPER_SEAL_SETATTR);
}

SEC("lsm.s/inode_setxattr")
int BPF_PROG(shirudo_seal_inode_setxattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name, const void *value,
	     __u64 size, int flags, int ret)
{
	if (ret)
		return ret;
	if (seal_is_label(name))
		return seal_caller(SHIRUDO_TAMPER_SEAL_LABEL);
	return seal_dentry(dentry, SHIRUDO_TAMPER_SEAL_XATTR);
}

SEC("lsm.s/inode_removexattr")
int BPF_PROG(shirudo_seal_inode_removexattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name, int ret)
{
	return ret ? ret : seal_dentry(dentry, SHIRUDO_TAMPER_SEAL_XATTR);
}

#endif /* SHIRUDO_BPF_SEAL_H */
