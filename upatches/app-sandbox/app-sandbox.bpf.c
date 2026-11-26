// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * app-sandbox: restrict tasks carrying a sandbox's policy bit in exec,
 * network peers, socket families, UNIX sockets, file operations and
 * privileged operations. gen_policy.py writes sandbox_policy.
 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "policy.h"

char _license[] SEC("license") = "Dual BSD/GPL";

#define SANDBOX_MAX		32
#define SANDBOX_NET_MAX		128
#define SANDBOX_NET_DENY_MAX	64
#define SANDBOX_FIM_MAX		64
#define SANDBOX_GLOB_MAX	32
#define SANDBOX_FAMILY_MAX	64

#define SANDBOX_FIM_CREATE	0x1
#define SANDBOX_FIM_RENAME	0x2
#define SANDBOX_FIM_WRITE	0x4
#define SANDBOX_FIM_READ	0x8
#define SANDBOX_FIM_UNIX	0x10

#define EACCES			13
#define ENODATA			61
#define EOPNOTSUPP		95
#define AF_UNSPEC		0
#define AF_INET			2
#define AF_INET6		10
#define AF_PACKET		17
#define SOCK_RAW		3
#define SOCK_TYPE_MASK		0xf
#define FMODE_READ		0x1
#define FMODE_WRITE		0x2
#define ATTR_SIZE		0x8
#define NAME_MAX		255

/* gen_policy.py packs these structs byte for byte. */
struct sandbox_exec_rule {
	__u64	sandbox;
	__u64	allowed;
};

/* An address in network byte order, IPv4 as ::ffff:a.b.c.d. */
union sandbox_addr {
	__u8	bytes[16];
	__be32	words[4];
	__u64	halves[2];
};

struct sandbox_net_rule {
	__u64	sandboxes;
	__u64	addr[2];
	__u64	mask[2];
};

struct sandbox_family_rule {
	__u64	sandbox;
	__u64	denied;
};

union sandbox_part {
	__u8	bytes[SANDBOX_GLOB_MAX];
	__u64	words[SANDBOX_GLOB_MAX / 8];
};

struct sandbox_fim_rule {
	__u64			sandboxes;
	__u8			ops;
	__u8			prefix_len;
	__u8			suffix_len;
	__u8			wildcard;
	__u8			parent_len;
	__u8			reserved[3];
	__u8			prefix[SANDBOX_GLOB_MAX];
	__u8			suffix[SANDBOX_GLOB_MAX];
	union sandbox_part	parent;
};

struct sandbox_policy {
	__u64	sandboxes;
	__u64	exec_enforced;
	__u64	net_enforced;
	__u64	net_deny_enforced;
	__u64	family_enforced;
	__u64	read_enforced;
	__u64	unix_enforced;
	__u64	deny_userns;
	__u64	deny_mount;
	__u64	deny_ptrace;
	__u64	deny_module;
	__u32	nr_exec;
	__u32	nr_net;
	__u32	nr_net_deny;
	__u32	nr_family;
	__u32	nr_fim;
	__u32	fim_has_parent;
	struct sandbox_exec_rule	exec[SANDBOX_MAX];
	struct sandbox_net_rule		net[SANDBOX_NET_MAX];
	struct sandbox_net_rule		net_deny[SANDBOX_NET_DENY_MAX];
	struct sandbox_family_rule	family[SANDBOX_MAX];
	struct sandbox_fim_rule		fim[SANDBOX_FIM_MAX];
};

const volatile struct sandbox_policy sandbox_policy = {};

struct sandbox_label {
	__u64	bits;
};

/* bpf_dynptr_from_mem() takes map memory only, and the exec hook sleeps. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct sandbox_label);
} sandbox_label SEC(".maps");

/* The parts of a dentry and its parent name that a pattern compares. */
struct sandbox_name {
	__u32			len;
	__u32			tail_len;
	__u32			parent_len;
	__u32			reserved;
	__u8			head[SANDBOX_GLOB_MAX];
	__u8			tail[SANDBOX_GLOB_MAX];
	union sandbox_part	parent;
};

int bpf_get_file_xattr(struct file *file, const char *name__str,
		       struct bpf_dynptr *value_p) __ksym;

static __always_inline __u64 current_sandboxes(void)
{
	struct task_policy *policy;

	policy = bpf_task_storage_get(&shirudo_task_policy,
				      bpf_get_current_task_btf(), NULL, 0);
	return policy ? policy->active & sandbox_policy.sandboxes : 0;
}

static __always_inline int file_policy_bits(struct file *file, __u64 *bits)
{
	struct sandbox_label *label;
	struct bpf_dynptr value;
	int len;

	label = bpf_task_storage_get(&sandbox_label,
				     bpf_get_current_task_btf(), NULL,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!label ||
	    bpf_dynptr_from_mem(&label->bits, sizeof(label->bits), 0, &value))
		return -EACCES;
	len = bpf_get_file_xattr(file, XATTR_POLICY, &value);
	if (len == -ENODATA || len == -EOPNOTSUPP) {
		*bits = 0;
		return 0;
	}
	if (len != sizeof(label->bits))
		return -EACCES;
	*bits = label->bits;
	return 0;
}

static __always_inline bool exec_allowed(__u64 sandboxes, __u64 file_bits)
{
	const volatile struct sandbox_exec_rule *rule;
	__u32 nr_exec = sandbox_policy.nr_exec;
	__u32 i;

	for (i = 0; i < SANDBOX_MAX; i++) {
		if (i >= nr_exec)
			break;
		rule = &sandbox_policy.exec[i];
		if ((sandboxes & rule->sandbox) && !(file_bits & rule->allowed))
			return false;
	}
	return true;
}

/* The kernel calls it for a script and again for each interpreter. */
SEC("lsm.s/bprm_check_security")
int BPF_PROG(sandbox_exec, struct linux_binprm *bprm, int ret)
{
	__u64 sandboxes, file_bits;

	if (ret)
		return ret;
	sandboxes = current_sandboxes() & sandbox_policy.exec_enforced;
	if (!sandboxes)
		return 0;
	if (!bprm->file || file_policy_bits(bprm->file, &file_bits))
		return -EACCES;
	return exec_allowed(sandboxes, file_bits) ? 0 : -EACCES;
}

static __always_inline bool net_allowed(__u64 sandboxes,
					const union sandbox_addr *addr)
{
	const volatile struct sandbox_net_rule *rule;
	__u32 nr_net = sandbox_policy.nr_net;
	__u64 allowed = 0;
	__u32 i;

	for (i = 0; i < SANDBOX_NET_MAX; i++) {
		if (i >= nr_net)
			break;
		rule = &sandbox_policy.net[i];
		if ((addr->halves[0] & rule->mask[0]) == rule->addr[0] &&
		    (addr->halves[1] & rule->mask[1]) == rule->addr[1])
			allowed |= rule->sandboxes;
	}
	return !(sandboxes & ~allowed);
}

static __always_inline bool net_denied(__u64 sandboxes,
				       const union sandbox_addr *addr)
{
	const volatile struct sandbox_net_rule *rule;
	__u32 nr_deny = sandbox_policy.nr_net_deny;
	__u32 i;

	for (i = 0; i < SANDBOX_NET_DENY_MAX; i++) {
		if (i >= nr_deny)
			break;
		rule = &sandbox_policy.net_deny[i];
		if ((rule->sandboxes & sandboxes) &&
		    (addr->halves[0] & rule->mask[0]) == rule->addr[0] &&
		    (addr->halves[1] & rule->mask[1]) == rule->addr[1])
			return true;
	}
	return false;
}

static __always_inline int peer_verdict(__u64 sandboxes, __u16 family,
					const struct sockaddr *address,
					int addrlen)
{
	union sandbox_addr addr = {};
	struct sockaddr_in6 sin6;
	struct sockaddr_in sin;

	if (family == AF_INET) {
		if (addrlen < (int)sizeof(sin) ||
		    bpf_probe_read_kernel(&sin, sizeof(sin), address))
			return -EACCES;
		addr.words[2] = bpf_htonl(0xffff);
		addr.words[3] = sin.sin_addr.s_addr;
	} else if (family == AF_INET6) {
		if (addrlen < (int)sizeof(sin6) ||
		    bpf_probe_read_kernel(&sin6, sizeof(sin6), address))
			return -EACCES;
		__builtin_memcpy(addr.bytes, &sin6.sin6_addr,
				 sizeof(addr.bytes));
	} else {
		return 0;
	}
	if ((sandboxes & sandbox_policy.net_deny_enforced) &&
	    net_denied(sandboxes & sandbox_policy.net_deny_enforced, &addr))
		return -EACCES;
	if ((sandboxes & sandbox_policy.net_enforced) &&
	    !net_allowed(sandboxes & sandbox_policy.net_enforced, &addr))
		return -EACCES;
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(sandbox_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	__u64 sandboxes, mask;
	__u16 family;

	if (ret)
		return ret;
	mask = sandbox_policy.net_enforced | sandbox_policy.net_deny_enforced;
	if (!mask)
		return 0;
	sandboxes = current_sandboxes() & mask;
	if (!sandboxes)
		return 0;
	if (!address || addrlen < (int)sizeof(family) ||
	    bpf_probe_read_kernel(&family, sizeof(family),
				  &address->sa_family))
		return -EACCES;
	return peer_verdict(sandboxes, family, address, addrlen);
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(sandbox_sendmsg, struct socket *sock, struct msghdr *msg,
	     int size, int ret)
{
	struct sockaddr *address;
	__u64 sandboxes, mask;
	struct sock *sk;
	__u16 family;
	int addrlen;

	if (ret)
		return ret;
	mask = sandbox_policy.net_enforced | sandbox_policy.net_deny_enforced;
	if (!mask)
		return 0;
	address = msg->msg_name;
	if (!address)
		return 0;
	sandboxes = current_sandboxes() & mask;
	if (!sandboxes)
		return 0;
	addrlen = msg->msg_namelen;
	if (addrlen < (int)sizeof(family) ||
	    bpf_probe_read_kernel(&family, sizeof(family),
				  &address->sa_family))
		return -EACCES;
	/* IPv4 sends to an AF_UNSPEC address as to an AF_INET one. */
	sk = sock->sk;
	if (family == AF_UNSPEC && sk && sk->__sk_common.skc_family == AF_INET)
		family = AF_INET;
	return peer_verdict(sandboxes, family, address, addrlen);
}

static __always_inline bool family_denied(__u64 sandboxes, int family)
{
	const volatile struct sandbox_family_rule *rule;
	__u32 nr_family = sandbox_policy.nr_family;
	__u64 bit;
	__u32 i;

	if (family < 0 || family >= SANDBOX_FAMILY_MAX)
		return true;
	bit = 1ULL << (__u32)family;
	for (i = 0; i < SANDBOX_MAX; i++) {
		if (i >= nr_family)
			break;
		rule = &sandbox_policy.family[i];
		if ((sandboxes & rule->sandbox) && (rule->denied & bit))
			return true;
	}
	return false;
}

/* A raw or packet socket writes its own headers, past both hooks above. */
SEC("lsm/socket_create")
int BPF_PROG(sandbox_socket_create, int family, int type, int protocol,
	     int kern, int ret)
{
	__u64 sandboxes;
	bool net_raw;

	if (ret || kern)
		return ret;
	net_raw = family == AF_PACKET ||
		  ((family == AF_INET || family == AF_INET6) &&
		   (type & SOCK_TYPE_MASK) == SOCK_RAW);
	if (!net_raw && !sandbox_policy.family_enforced)
		return 0;
	sandboxes = current_sandboxes();
	if (!sandboxes)
		return 0;
	if (net_raw && (sandboxes & sandbox_policy.net_enforced))
		return -EACCES;
	if ((sandboxes & sandbox_policy.family_enforced) &&
	    family_denied(sandboxes & sandbox_policy.family_enforced, family))
		return -EACCES;
	return 0;
}

static __always_inline int read_name(struct dentry *dentry,
				     struct sandbox_name *name)
{
	const unsigned char *bytes;
	struct dentry *pdentry;
	__u32 len, part_len;
	__u32 plen;

	bytes = BPF_CORE_READ(dentry, d_name.name);
	len = BPF_CORE_READ(dentry, d_name.len);
	if (!bytes || !len || len > NAME_MAX)
		return -EACCES;
	part_len = len;
	if (part_len > SANDBOX_GLOB_MAX)
		part_len = SANDBOX_GLOB_MAX;
	if (bpf_probe_read_kernel(name->head, part_len, bytes) ||
	    bpf_probe_read_kernel(name->tail, part_len, bytes + len - part_len))
		return -EACCES;
	name->len = len;
	name->tail_len = part_len;
	if (!sandbox_policy.fim_has_parent)
		return 0;
	pdentry = BPF_CORE_READ(dentry, d_parent);
	if (!pdentry)
		return 0;
	bytes = BPF_CORE_READ(pdentry, d_name.name);
	plen = BPF_CORE_READ(pdentry, d_name.len);
	if (!bytes || !plen || plen > NAME_MAX)
		return -EACCES;
	name->parent_len = plen;
	if (plen <= SANDBOX_GLOB_MAX &&
	    bpf_probe_read_kernel(name->parent.bytes, plen, bytes))
		return -EACCES;
	return 0;
}

static __always_inline bool byte_matches(__u8 pattern, __u8 byte)
{
	return pattern == '?' || pattern == byte;
}

static __always_inline bool
parent_matches(const volatile union sandbox_part *rule,
	       const union sandbox_part *actual)
{
	return rule->words[0] == actual->words[0] &&
	       rule->words[1] == actual->words[1] &&
	       rule->words[2] == actual->words[2] &&
	       rule->words[3] == actual->words[3];
}

static __always_inline bool
name_matches(const volatile struct sandbox_fim_rule *rule,
	     const struct sandbox_name *name)
{
	__u32 prefix_len = rule->prefix_len;
	__u32 suffix_len = rule->suffix_len;
	__u32 i, tail_at;

	if (rule->parent_len) {
		if (rule->parent_len > SANDBOX_GLOB_MAX)
			return true;
		if (name->parent_len != rule->parent_len ||
		    !parent_matches(&rule->parent, &name->parent))
			return false;
	}
	if (prefix_len > SANDBOX_GLOB_MAX || suffix_len > SANDBOX_GLOB_MAX)
		return true;
	if (rule->wildcard ? name->len < prefix_len + suffix_len :
			     name->len != prefix_len)
		return false;
	for (i = 0; i < SANDBOX_GLOB_MAX; i++) {
		if (i >= prefix_len)
			break;
		if (!byte_matches(rule->prefix[i], name->head[i]))
			return false;
	}
	tail_at = name->tail_len - suffix_len;
	for (i = 0; i < SANDBOX_GLOB_MAX; i++) {
		if (i >= suffix_len)
			break;
		if (!byte_matches(rule->suffix[i],
				  name->tail[(tail_at + i) &
					     (SANDBOX_GLOB_MAX - 1)]))
			return false;
	}
	return true;
}

static __noinline bool name_denied(__u64 sandboxes, __u32 op,
				   struct dentry *dentry)
{
	const volatile struct sandbox_fim_rule *rule;
	__u32 nr_fim = sandbox_policy.nr_fim;
	struct sandbox_name name = {};
	__u32 i;

	if (!dentry || read_name(dentry, &name))
		return true;
	for (i = 0; i < SANDBOX_FIM_MAX; i++) {
		if (i >= nr_fim)
			break;
		rule = &sandbox_policy.fim[i];
		if ((rule->sandboxes & sandboxes) && (rule->ops & op) &&
		    name_matches(rule, &name))
			return true;
	}
	return false;
}

static __always_inline int name_verdict(__u32 op, struct dentry *dentry)
{
	__u64 sandboxes = current_sandboxes();

	if (!sandboxes)
		return 0;
	return name_denied(sandboxes, op, dentry) ? -EACCES : 0;
}

SEC("lsm/inode_create")
int BPF_PROG(sandbox_create, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, umode_t mode, int ret)
{
	return ret ? ret : name_verdict(SANDBOX_FIM_CREATE, dentry);
}

SEC("lsm/inode_mkdir")
int BPF_PROG(sandbox_mkdir, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, umode_t mode, int ret)
{
	return ret ? ret : name_verdict(SANDBOX_FIM_CREATE, dentry);
}

SEC("lsm/inode_symlink")
int BPF_PROG(sandbox_symlink, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, const char *old_name, int ret)
{
	return ret ? ret : name_verdict(SANDBOX_FIM_CREATE, dentry);
}

SEC("lsm/inode_mknod")
int BPF_PROG(sandbox_mknod, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, umode_t mode, dev_t dev, int ret)
{
	return ret ? ret : name_verdict(SANDBOX_FIM_CREATE, dentry);
}

SEC("lsm/inode_link")
int BPF_PROG(sandbox_link, struct mnt_idmap *idmap, struct dentry *old_dentry,
	     struct inode *dir, struct dentry *new_dentry, int ret)
{
	__u64 sandboxes;

	if (ret)
		return ret;
	sandboxes = current_sandboxes();
	if (!sandboxes)
		return 0;
	if (name_denied(sandboxes, SANDBOX_FIM_CREATE, new_dentry))
		return -EACCES;
	if ((sandboxes & sandbox_policy.read_enforced) &&
	    name_denied(sandboxes & sandbox_policy.read_enforced,
			SANDBOX_FIM_READ, old_dentry))
		return -EACCES;
	return 0;
}

SEC("lsm/inode_rename")
int BPF_PROG(sandbox_rename, struct inode *old_dir, struct dentry *old_dentry,
	     struct inode *new_dir, struct dentry *new_dentry, int ret)
{
	__u64 sandboxes;
	__u32 old_ops;

	if (ret)
		return ret;
	sandboxes = current_sandboxes();
	if (!sandboxes)
		return 0;
	old_ops = SANDBOX_FIM_RENAME;
	if (sandboxes & sandbox_policy.read_enforced)
		old_ops |= SANDBOX_FIM_READ;
	if (name_denied(sandboxes, old_ops, old_dentry) ||
	    name_denied(sandboxes, SANDBOX_FIM_RENAME, new_dentry))
		return -EACCES;
	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(sandbox_open, struct file *file, int ret)
{
	__u64 sandboxes;
	__u32 op = 0;

	if (ret)
		return ret;
	if (file->f_mode & FMODE_WRITE)
		op |= SANDBOX_FIM_WRITE;
	if ((file->f_mode & FMODE_READ) && sandbox_policy.read_enforced)
		op |= SANDBOX_FIM_READ;
	if (!op)
		return 0;
	sandboxes = current_sandboxes();
	if (!sandboxes)
		return 0;
	if (!(sandboxes & sandbox_policy.read_enforced))
		op &= ~SANDBOX_FIM_READ;
	if (!op)
		return 0;
	return name_denied(sandboxes, op, file->f_path.dentry) ? -EACCES : 0;
}

SEC("lsm/inode_setattr")
int BPF_PROG(sandbox_truncate, struct mnt_idmap *idmap, struct dentry *dentry,
	     struct iattr *attr, int ret)
{
	if (ret || !(attr->ia_valid & ATTR_SIZE))
		return ret;
	return name_verdict(SANDBOX_FIM_WRITE, dentry);
}

/* Match the listening socket's resolved dentry, past symlinks and chdir. */
static __always_inline int unix_peer_verdict(struct sock *other)
{
	struct unix_sock *u = (struct unix_sock *)other;
	struct dentry *dentry;
	__u64 sandboxes;

	if (!other)
		return 0;
	sandboxes = current_sandboxes() & sandbox_policy.unix_enforced;
	if (!sandboxes)
		return 0;
	dentry = BPF_CORE_READ(u, path.dentry);
	if (!dentry)
		return 0;
	return name_denied(sandboxes, SANDBOX_FIM_UNIX, dentry) ? -EACCES : 0;
}

SEC("lsm/unix_stream_connect")
int BPF_PROG(sandbox_unix_connect, struct sock *sock, struct sock *other,
	     struct sock *newsk, int ret)
{
	if (ret || !sandbox_policy.unix_enforced)
		return ret;
	return unix_peer_verdict(other);
}

SEC("lsm/unix_may_send")
int BPF_PROG(sandbox_unix_send, struct socket *sock, struct socket *other,
	     int ret)
{
	if (ret || !sandbox_policy.unix_enforced || !other)
		return ret;
	return unix_peer_verdict(BPF_CORE_READ(other, sk));
}

SEC("lsm/userns_create")
int BPF_PROG(sandbox_userns, const struct cred *cred, int ret)
{
	if (ret || !sandbox_policy.deny_userns)
		return ret;
	return current_sandboxes() & sandbox_policy.deny_userns ? -EACCES : 0;
}

SEC("lsm/sb_mount")
int BPF_PROG(sandbox_mount, const char *dev_name, const struct path *path,
	     const char *type, unsigned long flags, void *data, int ret)
{
	if (ret || !sandbox_policy.deny_mount)
		return ret;
	return current_sandboxes() & sandbox_policy.deny_mount ? -EACCES : 0;
}

SEC("lsm/move_mount")
int BPF_PROG(sandbox_move_mount, const struct path *from_path,
	     const struct path *to_path, int ret)
{
	if (ret || !sandbox_policy.deny_mount)
		return ret;
	return current_sandboxes() & sandbox_policy.deny_mount ? -EACCES : 0;
}

/* Keep /proc/self working while denying cross-process ptrace and /proc. */
SEC("lsm/ptrace_access_check")
int BPF_PROG(sandbox_ptrace, struct task_struct *child, unsigned int mode,
	     int ret)
{
	if (ret || !sandbox_policy.deny_ptrace || !child)
		return ret;
	if ((__u32)BPF_CORE_READ(child, tgid) ==
	    (__u32)(bpf_get_current_pid_tgid() >> 32))
		return 0;
	return current_sandboxes() & sandbox_policy.deny_ptrace ? -EACCES : 0;
}

SEC("lsm/kernel_module_request")
int BPF_PROG(sandbox_module, char *kmod_name, int ret)
{
	if (ret || !sandbox_policy.deny_module)
		return ret;
	return current_sandboxes() & sandbox_policy.deny_module ? -EACCES : 0;
}
