// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

/* shirudo retains the writable-state label seal and trusts runtime execs. */
#include "verity.h"
#include "xattr.h"

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

/*
 * The label of an inode as the last hook with a handle on it read it: a
 * directory at every open, a file at an open for writing by anyone, at
 * any open by an authorized task and at its creation under a marked
 * directory. Where a hook cannot read the label, or the read fails for
 * the caller, the mark stands in for it.
 */
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
static __always_inline int seal_caller(enum tamper_point point)
{
	struct sb_id *id;
	__u32 zero = 0;

	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	if (!id)
		return -EACCES;
	return shirudo_task_is_self(id) ? 0 :
	       shirudo_tamper_deny(point, -EACCES);
}

static __always_inline bool seal_task_authorized(void)
{
	struct sb_id *id;
	__u32 zero = 0;

	id = bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
	return id && shirudo_task_is_self(id);
}

static __always_inline bool seal_marked(struct inode *inode)
{
	return inode && bpf_inode_storage_get(&seal_dir_marks, inode, NULL, 0);
}

/*
 * Decide on the result of reading the target's label (tlen). No label
 * (-ENODATA) or no security xattrs on the file system (-EOPNOTSUPP) is
 * not shirudo's inode. The kfunc checks read permission for the caller
 * against the raw ids of the inode, so the read fails with -EACCES or
 * -EPERM for a caller that may neither read nor write, and for one that
 * an ACL or an idmapped mount lets write what it may not read. Failing
 * every such read closed would refuse every write-only open and every
 * unlink of an unreadable file, so the mark of the inode, or of the
 * directory the operation changes, decides there. A label of any size,
 * or any other error, requires the caller to be shirudo. 0 = allow,
 * -EACCES = deny.
 */
static __always_inline int seal_verdict(int tlen, struct inode *inode,
					struct inode *dir,
					enum tamper_point point)
{
	switch (tlen) {
	case -ENODATA:
	case -EOPNOTSUPP:
		return 0;
	case -EACCES:
	case -EPERM:
		if (seal_marked(inode) || seal_marked(dir))
			return seal_caller(point);
		return 0;
	default:
		return seal_caller(point);
	}
}

/* Whether an xattr name is the label itself, not a longer name under it. */
static __always_inline bool seal_is_label(const char *name)
{
	char buf[sizeof(XATTR_SEAL) + 1];
	long n;

	n = bpf_probe_read_kernel_str(buf, sizeof(buf), name);
	if (n != sizeof(XATTR_SEAL))
		return false;
	return !bpf_strncmp(buf, sizeof(XATTR_SEAL), XATTR_SEAL);
}

static __always_inline bool seal_is_policy(const char *name)
{
	char buf[sizeof(XATTR_POLICY) + 1];
	long n;

	n = bpf_probe_read_kernel_str(buf, sizeof(buf), name);
	if (n != sizeof(XATTR_POLICY))
		return false;
	return !bpf_strncmp(buf, sizeof(XATTR_POLICY), XATTR_POLICY);
}

static __always_inline bool seal_is_ancestor(const char *name)
{
	char buf[sizeof(XATTR_ANCESTOR) + 1];
	long n;

	n = bpf_probe_read_kernel_str(buf, sizeof(buf), name);
	if (n != sizeof(XATTR_ANCESTOR))
		return false;
	return !bpf_strncmp(buf, sizeof(XATTR_ANCESTOR), XATTR_ANCESTOR);
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

/*
 * Remember a directory's label as just read (len bytes), or forget it
 * when there is none. A read that failed, for a caller who may not read
 * the directory say, tells nothing about the label: the mark stands.
 */
static __always_inline void seal_mark(struct inode *inode, const char *label,
				      int len)
{
	struct seal_dir_mark *m;

	if (len < 0 && len != -ENODATA && len != -EOPNOTSUPP)
		return;
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
	struct task_authority *authority;
	struct task_policy *policy;

	policy = bpf_task_storage_get(&shirudo_task_policy, task, NULL, 0);
	if (policy) {
		policy->active = policy->candidate;
		policy->candidate = 0;
	}
	authority = bpf_task_storage_get(&shirudo_tasks, task, NULL, 0);
	if (!authority)
		return;
	authority->trusted = authority->candidate_valid &&
			     authority->candidate_trusted;
	authority->revoked = 0;
	authority->candidate_valid = 0;
	authority->candidate_trusted = 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(shirudo_seal_task_alloc, struct task_struct *child,
	     __u64 clone_flags, int ret)
{
	struct task_struct *parent = bpf_get_current_task_btf();
	struct task_authority *parent_authority;
	struct task_policy *parent_policy;
	struct task_authority *authority;
	struct task_policy *policy;

	if (ret)
		return ret;
	parent_policy = bpf_task_storage_get(&shirudo_task_policy, parent,
					     NULL, 0);
	if (parent_policy && parent_policy->active) {
		policy = bpf_task_storage_get(&shirudo_task_policy, child, NULL,
					      BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (!policy)
			return -ENOMEM;
		policy->active = parent_policy->active;
	}
	parent_authority = bpf_task_storage_get(&shirudo_tasks, parent,
						NULL, 0);
	if (!parent_authority || !parent_authority->trusted)
		return 0;
	authority = bpf_task_storage_get(&shirudo_tasks, child, NULL,
					 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!authority)
		return -ENOMEM;
	authority->trusted = parent_authority->trusted;
	authority->revoked = parent_authority->revoked;
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
		return shirudo_tamper_deny(TAMPER_SEAL_PERF, -EACCES);

	return 0;
}

/*
 * Keep every ptrace mode away from processes with committed exec marks,
 * but count only attach mode: journald reads /proc/<pid>/exe of every
 * client it logs for, and ps reads /proc/<pid>/stat, so a counted read
 * mode would make an honest node look tampered.
 */
SEC("lsm/ptrace_access_check")
int BPF_PROG(shirudo_seal_ptrace_access_check,
	     struct task_struct *child, unsigned int mode, int ret)
{
	if (ret)
		return ret;
	if (!shirudo_marked(child))
		return 0;
	if (mode & PTRACE_MODE_ATTACH)
		return shirudo_tamper_deny(TAMPER_SEAL_PTRACE, -EACCES);
	return -EACCES;
}

/*
 * mm_access() grants a read-mode access to CAP_PERFMON after the check
 * above refused it, and asks here first (carried patch 0005): the
 * environment, memory map and page map of a marked task stay its own,
 * refused as uncounted as any read mode.
 */
SEC("lsm/mm_read_access")
int BPF_PROG(shirudo_seal_mm_read_access, struct task_struct *task,
	     unsigned int mode, int ret)
{
	if (ret)
		return ret;
	return shirudo_marked(task) ? -EACCES : 0;
}

/*
 * A signal from outside is let through: root may end a command that
 * hangs, and systemd stops the runs its timers start. It is counted, so
 * that a load stopped between its pins and its extend shows in the
 * counters before the next command finds what it left. Signal 0 only
 * probes.
 */
SEC("lsm/task_kill")
int BPF_PROG(shirudo_seal_task_kill, struct task_struct *p,
	     struct kernel_siginfo *info, int sig, const struct cred *cred,
	     int ret)
{
	if (ret)
		return ret;
	if (sig && shirudo_marked(p) && !seal_task_authorized())
		shirudo_tamper_count(TAMPER_SEAL_SIGNAL);
	return 0;
}

/*
 * A file size or CPU time limit has the kernel itself signal a command,
 * which task_kill never sees. A command resets its own limits when it
 * starts, and no one else changes them while it runs.
 */
SEC("lsm/task_setrlimit")
int BPF_PROG(shirudo_seal_task_setrlimit, struct task_struct *p,
	     unsigned int resource, struct rlimit *new_rlim, int ret)
{
	if (ret)
		return ret;
	if (p == bpf_get_current_task_btf() || !shirudo_marked(p) ||
	    seal_task_authorized())
		return 0;
	return shirudo_tamper_deny(TAMPER_SEAL_RLIMIT, -EPERM);
}

SEC("lsm.s/file_open")
int BPF_PROG(shirudo_seal_file_open, struct file *file, int ret)
{
	struct inode *inode = file->f_inode;
	struct task_struct *task;
	struct seal_scratch *s;
	struct bpf_dynptr tdp;
	int tlen;

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
			  bpf_get_file_xattr(file, XATTR_SEAL, &tdp));
		return 0;
	}
	if (!(BPF_CORE_READ(file, f_mode) & FMODE_WRITE)) {
		/* A read by shirudo marks what it reads; others cost nothing. */
		if (!seal_task_authorized())
			return 0;
		s = seal_scratch_get(task);
		if (!s)
			return 0;
		bpf_dynptr_from_mem(s->target, LABEL_LEN, 0, &tdp);
		seal_mark(inode, s->target,
			  bpf_get_file_xattr(file, XATTR_SEAL, &tdp));
		return 0;
	}
	s = seal_scratch_get(task);
	if (!s)				/* cannot read the label */
		return seal_caller(TAMPER_SEAL_WRITE);
	bpf_dynptr_from_mem(s->target, LABEL_LEN, 0, &tdp);
	tlen = bpf_get_file_xattr(file, XATTR_SEAL, &tdp);
	if (tlen == LABEL_LEN)
		seal_mark(inode, s->target, tlen);
	return seal_verdict(tlen, inode, NULL, TAMPER_SEAL_WRITE);
}

/*
 * An overlay copies a lower inode up before the first write reaches it,
 * label and all, since the copy-up runs as the writer: a write shirudo
 * made through one mounted over sealed state landed in the upper
 * directory, root's, and the sealed inode stayed as it was. Sealed
 * state is never copied up, by anyone.
 */
SEC("lsm.s/inode_copy_up")
int BPF_PROG(shirudo_seal_inode_copy_up, struct dentry *src,
	     struct cred **new, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct seal_scratch *s = seal_scratch_get(task);
	struct bpf_dynptr tdp;
	int tlen;

	if (ret)
		return ret;
	if (!s)
		return shirudo_tamper_deny(TAMPER_SEAL_COPY_UP, -EPERM);
	bpf_dynptr_from_mem(s->target, LABEL_LEN, 0, &tdp);
	tlen = bpf_get_dentry_xattr(src, XATTR_SEAL, &tdp);
	if (tlen == -ENODATA || tlen == -EOPNOTSUPP)
		return 0;
	if ((tlen == -EACCES || tlen == -EPERM) && !seal_marked(src->d_inode))
		return 0;
	return shirudo_tamper_deny(TAMPER_SEAL_COPY_UP, -EPERM);
}

/* Refresh an inode's mark from its label after an xattr change. */
static __always_inline void seal_mark_dentry(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct seal_scratch *s;
	struct bpf_dynptr tdp;

	if (!inode)
		return;
	s = seal_scratch_get(bpf_get_current_task_btf());
	if (!s)
		return;
	bpf_dynptr_from_mem(s->target, LABEL_LEN, 0, &tdp);
	seal_mark(inode, s->target,
		  bpf_get_dentry_xattr(dentry, XATTR_SEAL, &tdp));
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
 * parent directory is marked, with the parent's label, and mark the new
 * inode in turn: a subtree created in one go needs no reopen, and a
 * file carries its mark from the start.
 * The hook cannot sleep and has no dentry, so the label comes from the
 * mark, which the entry hook of the same operation refreshed from the
 * directory's label just before. A claim that fails (no slot left, no
 * memory) aborts the creation: better no inode than one of shirudo's
 * without its label, and the verifier wants a constant in the LSM's
 * error range rather than the kfunc's. A filesystem that takes no
 * xattrs at creation passes none; the label follows from userspace
 * there.
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
	if (bpf_inode_init_xattr(xattrs, xattr_count, XATTR_SEAL, &dp))
		return -EACCES;
	child = bpf_inode_storage_get(&seal_dir_marks, inode, NULL,
				      BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (child)
		__builtin_memcpy(child->label, m->label, LABEL_LEN);
	return 0;
}

static __always_inline int seal_dentry(struct inode *dir,
				       struct dentry *dentry,
				       enum tamper_point point)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct seal_scratch *s = seal_scratch_get(task);
	struct bpf_dynptr tdp;

	if (!s)
		return seal_caller(point);
	bpf_dynptr_from_mem(s->target, LABEL_LEN, 0, &tdp);
	return seal_verdict(bpf_get_dentry_xattr(dentry, XATTR_SEAL, &tdp),
			    dentry->d_inode, dir, point);
}

SEC("lsm.s/inode_unlink")
int BPF_PROG(shirudo_seal_inode_unlink, struct inode *dir,
	     struct dentry *dentry, int ret)
{
	return ret ? ret : seal_dentry(dir, dentry, TAMPER_SEAL_UNLINK);
}

/*
 * A sealed directory takes new entries from shirudo alone. The label a
 * creation inherits stops writes to the new inode, but a rename or a
 * link brings an inode in with its contents, and a symbolic link sends
 * whoever follows it elsewhere. The directory's label is read from the
 * new entry's parent dentry, and its mark refreshed on the way, which
 * inode_init_security labels the new inode from a moment later.
 */
static __always_inline int seal_parent(struct dentry *dentry,
				       enum tamper_point point)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct seal_scratch *s = seal_scratch_get(task);
	struct dentry *parent = dentry->d_parent;
	struct bpf_dynptr tdp;
	int tlen;

	if (!s || !parent)
		return seal_caller(point);
	bpf_dynptr_from_mem(s->target, LABEL_LEN, 0, &tdp);
	tlen = bpf_get_dentry_xattr(parent, XATTR_SEAL, &tdp);
	if (parent->d_inode)
		seal_mark(parent->d_inode, s->target, tlen);
	return seal_verdict(tlen, NULL, parent->d_inode, point);
}

SEC("lsm.s/inode_create")
int BPF_PROG(shirudo_seal_inode_create, const struct mnt_idmap *idmap,
	     struct inode *dir, struct dentry *dentry, umode_t mode, int ret)
{
	return ret ? ret : seal_parent(dentry, TAMPER_SEAL_ENTRY);
}

SEC("lsm.s/inode_mkdir")
int BPF_PROG(shirudo_seal_inode_mkdir, const struct mnt_idmap *idmap,
	     struct inode *dir, struct dentry *dentry, umode_t mode, int ret)
{
	return ret ? ret : seal_parent(dentry, TAMPER_SEAL_ENTRY);
}

SEC("lsm.s/inode_symlink")
int BPF_PROG(shirudo_seal_inode_symlink, const struct mnt_idmap *idmap,
	     struct inode *dir, struct dentry *dentry, const char *old_name,
	     int ret)
{
	return ret ? ret : seal_parent(dentry, TAMPER_SEAL_ENTRY);
}

SEC("lsm.s/inode_mknod")
int BPF_PROG(shirudo_seal_inode_mknod, const struct mnt_idmap *idmap,
	     struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev,
	     int ret)
{
	return ret ? ret : seal_parent(dentry, TAMPER_SEAL_ENTRY);
}

/* A sealed inode is linked nowhere by anyone else: it keeps its label. */
SEC("lsm.s/inode_link")
int BPF_PROG(shirudo_seal_inode_link, const struct mnt_idmap *idmap,
	     struct dentry *old_dentry, struct inode *dir,
	     struct dentry *new_dentry, int ret)
{
	int err;

	if (ret)
		return ret;
	err = seal_dentry(NULL, old_dentry, TAMPER_SEAL_ENTRY);
	if (err)
		return err;
	return seal_parent(new_dentry, TAMPER_SEAL_ENTRY);
}

/*
 * A rename of a directory above the state root, /var/lib say, moves the
 * sealed tree aside, and the next boot's bootstrap init labels whatever
 * root then puts at the path as shirudo's. init marks those directories
 * with an xattr of their own, which only this check reads: the seal
 * label would refuse root every new entry there.
 */
static __always_inline int seal_ancestor(struct dentry *dentry)
{
	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	struct seal_scratch *s;
	struct bpf_dynptr tdp;
	int len;

	if (!inode || !seal_is_dir(inode))
		return 0;
	s = seal_scratch_get(bpf_get_current_task_btf());
	if (!s)
		return seal_caller(TAMPER_SEAL_RENAME);
	bpf_dynptr_from_mem(s->target, LABEL_LEN, 0, &tdp);
	len = bpf_get_dentry_xattr(dentry, XATTR_ANCESTOR, &tdp);
	if (len == -ENODATA || len == -EOPNOTSUPP)
		return 0;
	return seal_caller(TAMPER_SEAL_RENAME);
}

/* Protect the source, the destination directory and an existing target. */
SEC("lsm.s/inode_rename")
int BPF_PROG(shirudo_seal_inode_rename, struct inode *old_dir,
	     struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry, int ret)
{
	struct inode *target = BPF_CORE_READ(new_dentry, d_inode);
	int err;

	if (ret)
		return ret;
	err = seal_dentry(old_dir, old_dentry, TAMPER_SEAL_RENAME);
	if (err)
		return err;
	err = seal_ancestor(old_dentry);
	if (err)
		return err;
	err = seal_parent(new_dentry, TAMPER_SEAL_ENTRY);
	if (err)
		return err;
	if (!target)
		return 0;
	err = seal_dentry(new_dir, new_dentry, TAMPER_SEAL_RENAME);
	return err ? err : seal_ancestor(new_dentry);
}

/* Truncate, chmod, chown and utimes all come through here. */
SEC("lsm.s/inode_setattr")
int BPF_PROG(shirudo_seal_inode_setattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, struct iattr *attr, int ret)
{
	return ret ? ret : seal_dentry(NULL, dentry, TAMPER_SEAL_SETATTR);
}

SEC("lsm.s/inode_setxattr")
int BPF_PROG(shirudo_seal_inode_setxattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name, const void *value,
	     __u64 size, int flags, int ret)
{
	if (ret)
		return ret;
	if (seal_is_label(name) || seal_is_policy(name) ||
	    seal_is_ancestor(name))
		return seal_caller(TAMPER_SEAL_LABEL);
	return seal_dentry(NULL, dentry, TAMPER_SEAL_XATTR);
}

/*
 * The label read fails with -EACCES for a caller who may not read the
 * inode, which root becomes at will with setfsuid() while it keeps the
 * CAP_SYS_ADMIN the removal needs: the labels are never left to it.
 */
SEC("lsm.s/inode_removexattr")
int BPF_PROG(shirudo_seal_inode_removexattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name, int ret)
{
	if (ret)
		return ret;
	if (seal_is_label(name) || seal_is_policy(name) ||
	    seal_is_ancestor(name))
		return seal_caller(TAMPER_SEAL_LABEL);
	return seal_dentry(NULL, dentry, TAMPER_SEAL_XATTR);
}

/*
 * An ACL that grants another id a write without a read would open a
 * sealed inode to that id, whose label read then fails (seal_verdict),
 * and the inode flags of chattr make a file immutable or append-only.
 */
SEC("lsm.s/inode_set_acl")
int BPF_PROG(shirudo_seal_inode_set_acl, const struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *acl_name,
	     struct posix_acl *kacl, int ret)
{
	return ret ? ret : seal_dentry(NULL, dentry, TAMPER_SEAL_XATTR);
}

SEC("lsm.s/inode_remove_acl")
int BPF_PROG(shirudo_seal_inode_remove_acl, const struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *acl_name, int ret)
{
	return ret ? ret : seal_dentry(NULL, dentry, TAMPER_SEAL_XATTR);
}

SEC("lsm.s/inode_file_setattr")
int BPF_PROG(shirudo_seal_inode_file_setattr, struct dentry *dentry,
	     struct file_kattr *fa, int ret)
{
	return ret ? ret : seal_dentry(NULL, dentry, TAMPER_SEAL_SETATTR);
}

SEC("lsm.s/inode_rmdir")
int BPF_PROG(shirudo_seal_inode_rmdir, struct inode *dir,
	     struct dentry *dentry, int ret)
{
	return ret ? ret : seal_dentry(dir, dentry, TAMPER_SEAL_UNLINK);
}

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("lsm/socket_post_create")
int BPF_PROG(shirudo_seal_socket_post_create, struct socket *sock, int family,
	     int type, int protocol, int kern, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct task_policy *policy;
	struct sock *sk;
	__u64 active;

	if (ret)
		return ret;
	if (!sock)
		return -ENOMEM;
	policy = bpf_task_storage_get(&shirudo_task_policy, task, NULL, 0);
	if (!policy || !policy->active)
		return 0;
	sk = sock->sk;
	if (!sk)
		return -ENOMEM;
	active = policy->active;
	if (!bpf_sk_storage_get(&shirudo_sock_policy, sk, &active,
				BPF_LOCAL_STORAGE_GET_F_CREATE))
		return -ENOMEM;
	return 0;
}

struct seccomp___shirudo {
	int mode;
} __attribute__((preserve_access_index));

/* CONFIG_SECCOMP=n leaves struct seccomp empty in the kernel BTF. */
static __always_inline bool shirudo_task_has_seccomp(struct task_struct *task)
{
	struct seccomp___shirudo *seccomp = (void *)&task->seccomp;

	return bpf_core_field_exists(seccomp->mode) &&
	       BPF_CORE_READ(seccomp, mode);
}

SEC("lsm.s/bprm_creds_for_exec")
int BPF_PROG(shirudo_seal_bprm_creds_for_exec, struct linux_binprm *bprm,
	     int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct task_policy *policy;

	if (ret)
		return ret;
	policy = bpf_task_storage_get(&shirudo_task_policy, task, NULL,
				      BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!policy)
		return -ENOMEM;
	policy->candidate = policy->active;
	return 0;
}

#define LSM_UNSAFE_SHARE	1

/*
 * shirudo grants authority only to a direct file on the verified runtime.
 * Overlay copies cannot qualify. Ptrace or seccomp supplied before exec must
 * not control the new trusted process, nor a process that shares its root
 * and working directory, which exec does not unshare. A failed exec retains
 * the old mark.
 */
SEC("lsm.s/bprm_check_security")
int BPF_PROG(shirudo_seal_bprm_check_security,
	     struct linux_binprm *bprm, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct task_authority *authority;
	struct seal_scratch *scratch;
	struct task_policy *policy;
	struct inode *real_inode;
	struct bpf_dynptr tdp;
	bool trusted;
	__u64 value;
	int len;

	if (ret)
		return ret;
	if (!shirudo_policy())
		return -EACCES;
	scratch = seal_scratch_get(task);
	if (!scratch)
		return -ENOMEM;
	bpf_dynptr_from_mem(scratch->target, sizeof(value), 0, &tdp);
	len = bpf_get_file_xattr(bprm->file, XATTR_POLICY, &tdp);
	if (len == -ENODATA || len == -EOPNOTSUPP)
		value = 0;
	else if (len != sizeof(value))
		return -EACCES;
	if (len == sizeof(value))
		__builtin_memcpy(&value, scratch->target, sizeof(value));
	policy = bpf_task_storage_get(&shirudo_task_policy, task, NULL, 0);
	if (!policy)
		return -ENOMEM;
	policy->candidate |= value;
	real_inode = bpf_real_data_inode(bprm->file);
	authority = bpf_task_storage_get(&shirudo_tasks, task, NULL, 0);
	trusted = real_inode == BPF_CORE_READ(bprm, file, f_inode) &&
		  shirudo_file_runtime_entry(bprm->file,
					     authority && authority->trusted);
	if (trusted && BPF_CORE_READ(task, ptrace))
		return shirudo_tamper_deny(TAMPER_EXEC_TRACED, -EACCES);
	if (trusted && (BPF_CORE_READ(bprm, unsafe) & LSM_UNSAFE_SHARE))
		return shirudo_tamper_deny(TAMPER_EXEC_SHARED, -EACCES);
	if (trusted && shirudo_task_has_seccomp(task))
		return -EACCES;
	authority = bpf_task_storage_get(&shirudo_tasks, task, NULL,
					 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!authority)
		return -ENOMEM;
	authority->candidate_trusted = trusted;
	authority->candidate_valid = 1;
	return 0;
}

#define PROT_WRITE	2
#define PROT_EXEC	4
#define VM_EXEC		4

/* Executable mappings in a trusted process must come from its runtime image. */
SEC("lsm/mmap_file")
int BPF_PROG(shirudo_seal_mmap_file, struct file *file,
	     unsigned long reqprot, unsigned long prot,
	     unsigned long flags, int ret)
{
	struct sb_id *id = shirudo_policy();

	if (ret)
		return ret;
	if (!id || !shirudo_task_is_self(id) ||
	    shirudo_bootstrap_task() || !(prot & PROT_EXEC))
		return 0;
	if ((prot & PROT_WRITE) || !shirudo_file_runtime(file))
		return -EACCES;
	return 0;
}

/* Disallow executable promotion of pages that could have been modified. */
SEC("lsm/file_mprotect")
int BPF_PROG(shirudo_seal_file_mprotect, struct vm_area_struct *vma,
	     unsigned long reqprot, unsigned long prot, int ret)
{
	struct sb_id *id = shirudo_policy();
	unsigned long old_flags;

	if (ret)
		return ret;
	old_flags = BPF_CORE_READ(vma, vm_flags);
	if (!id || !shirudo_task_is_self(id) ||
	    shirudo_bootstrap_task())
		return 0;
	if ((old_flags & VM_EXEC) && (prot & PROT_WRITE))
		return -EACCES;
	if (!(prot & PROT_EXEC))
		return 0;
	if (!(old_flags & VM_EXEC) ||
	    !shirudo_file_runtime(BPF_CORE_READ(vma, vm_file)))
		return -EACCES;
	return 0;
}
