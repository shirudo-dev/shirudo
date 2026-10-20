/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */
#ifndef KERNEL_OBS_COMMON_H
#define KERNEL_OBS_COMMON_H

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "shirudo_misc.h"

#if !defined(__BPF_FEATURE_ADDR_SPACE_CAST)
#error "BPF arena access requires clang address-space cast support"
#endif

#define __arena		__attribute__((address_space(1))) \
			__attribute__((btf_type_tag("arena")))
#define NUMA_NO_NODE	(-1)

#define E2BIG		7
#define ENOMEM		12
#define EINVAL		22
#define ENOSPC		28

#define AF_UNIX		1
#define AF_INET		2
#define AF_INET6	10
#define AF_NETLINK	16
#define AF_PACKET	17
#define AF_VSOCK	40
#define AF_XDP		44
#define SOCK_TYPE_MASK	0xf
#define ETH_P_IP	0x0800
#define ETH_P_IPV6	0x86DD

#define OBS_NAME_LEN	32
#define OBS_PATH_LEN	128
#define OBS_ARENA_PAGES	4096

/* Record and header flags shared by every serializer page. */
#define OBS_HDR_F_PEEK		(1u << 0)
#define OBS_REC_F_PRESENT	(1u << 0)

/* ctx->flags bit the exporter sets to read without draining. */
#define OBS_CTX_F_PEEK		SHIRUDO_SERIAL_CTX_F_PEEK

enum obs_touch_status {
	OBS_TOUCH_HIT = 0,
	OBS_TOUCH_CREATED = 1,
	OBS_TOUCH_NO_STATE = 2,
	OBS_TOUCH_OVERFLOW = 3,
	OBS_TOUCH_CAS_FAIL = 4,
};

/*
 * Kernels built without IPv6 have no skc_v6_* fields; every IPv6 read
 * goes through this shadow type so the load does not fail on them.  The
 * fields are structs because CO-RE only matches a struct field against
 * a struct, and the kernel's are struct in6_addr.
 */
struct obs_in6 {
	__u32 addr[4];
};

struct sock_common___ipv6 {
	struct obs_in6 skc_v6_daddr;
	struct obs_in6 skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

static __always_inline bool obs_ipv6_enabled(void)
{
	return bpf_core_field_exists(struct sock_common___ipv6, skc_v6_daddr);
}

struct obs_sockaddr_in6 {
	__u16 sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	__u32 sin6_addr[4];
	__u32 sin6_scope_id;
};

struct obs_ipv6hdr {
	__be32 version_flow;
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u32 saddr[4];
	__u32 daddr[4];
};

struct obs_exe {
	__u64 ino;
	__u32 dev;
	__u32 _pad;
};

struct obs_ident {
	struct obs_exe exe;
	__u64 cgroup;
};

#define OBS_TASK_INFERRED	(1u << 0)
#define OBS_TASK_ANOMALY	(1u << 1)

struct obs_task_meta {
	struct obs_exe exe;
	__u32 euid;
	__u32 flags;
};

enum obs_role {
	OBS_ROLE_NONE = 0,
	OBS_ROLE_INITIATOR = 1,
	OBS_ROLE_ACCEPTOR = 2,
	OBS_ROLE_LISTENER = 3,
};

#define OBS_SOCK_META_OWNER_INFERRED	(1u << 0)
#define OBS_SOCK_META_OWNER_UNKNOWN	(1u << 1)

struct obs_sock_meta {
	struct obs_exe exe;
	__u64 cgroup;
	__u32 owner_pid;
	__u32 role;
	__u32 flags;
	__u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct obs_task_meta);
} obs_i_task SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct obs_sock_meta);
} obs_i_sock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, OBS_ARENA_PAGES);
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
	enum { obs_map_extra = 1ULL << 32 } map_extra;
#else
	enum { obs_map_extra = 1ULL << 44 } map_extra;
#endif
} obs_i_arena SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, struct shirudo_serial_chunk);
} shirudo_ser SEC(".maps");

void __arena *bpf_arena_alloc_pages(void *map, void __arena *addr,
				    __u32 page_cnt, int node_id,
				    __u64 flags) __ksym __weak;
void bpf_arena_free_pages(void *map, void __arena *ptr,
			  __u32 page_cnt) __ksym __weak;

/*
 * The verifier binds a program to the arena only through a direct
 * reference to the map.  Programs that merely dereference pointers the
 * init program allocated make this no-op call on their cold path.
 */
static __always_inline void obs_arena_associate(void)
{
	(void)bpf_arena_alloc_pages(&obs_i_arena, 0, 0, NUMA_NO_NODE, 0);
}

static __always_inline __u64 obs_now(void)
{
	return bpf_ktime_get_boot_ns();
}

static __always_inline __u32 obs_tgid(void)
{
	return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline __u64 obs_hash_mix(__u64 h, __u64 v)
{
	h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdULL;
	h ^= h >> 33;
	return h;
}

static __always_inline int obs_exe_from_file(struct file *file,
					     struct obs_exe *exe)
{
	struct inode *inode;

	if (!file)
		return -1;
	inode = BPF_CORE_READ(file, f_inode);
	if (!inode || !BPF_CORE_READ(inode, i_sb))
		return -1;
	exe->ino = BPF_CORE_READ(inode, i_ino);
	exe->dev = BPF_CORE_READ(inode, i_sb, s_dev);
	exe->_pad = 0;
	return exe->ino ? 0 : -1;
}

static __always_inline __u32 obs_name_from_file(struct file *file,
						char *name)
{
	const unsigned char *src;
	struct dentry *dentry;
	long copied;

	name[0] = '\0';
	if (!file)
		return 0;
	dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry)
		return 0;
	src = BPF_CORE_READ(dentry, d_name.name);
	if (!src)
		return 0;
	copied = bpf_probe_read_kernel_str(name, OBS_NAME_LEN, src);
	if (copied <= 0) {
		name[0] = '\0';
		return 0;
	}
	return (__u32)copied - 1;
}

/*
 * The objective credentials: override_creds() swaps the subjective ones
 * while the kernel acts on a task's behalf, as overlayfs does on every
 * open, and that must not look like an escalation.
 */
static __always_inline __u32 obs_task_euid(struct task_struct *task)
{
	return BPF_CORE_READ(task, real_cred, euid.val);
}

static __always_inline __u32 obs_current_euid(void)
{
	return obs_task_euid(bpf_get_current_task_btf());
}

/*
 * Processes that started before the upatch loaded have no stored
 * identity; derive one from the mapped executable so that their
 * activity is attributed rather than dropped.
 */
static __always_inline struct obs_task_meta *
obs_task_meta(struct task_struct *task)
{
	struct obs_task_meta *meta;
	struct obs_exe exe = {};
	struct file *file;

	if (!task)
		return 0;
	meta = bpf_task_storage_get(&obs_i_task, task, 0, 0);
	if (meta)
		return meta;
	file = BPF_CORE_READ(task, mm, exe_file);
	if (obs_exe_from_file(file, &exe))
		return 0;
	meta = bpf_task_storage_get(&obs_i_task, task, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!meta)
		return 0;
	meta->exe = exe;
	meta->euid = obs_task_euid(task);
	meta->flags = OBS_TASK_INFERRED;
	return meta;
}

static __always_inline bool obs_task_exe(struct task_struct *task,
					 struct obs_exe *exe)
{
	struct obs_task_meta *meta = obs_task_meta(task);

	if (!meta)
		return false;
	*exe = meta->exe;
	return true;
}

/*
 * Word copies and compares keep the table template independent of the
 * key layout; every key and value is a multiple of eight bytes.  The
 * barriers keep clang from forming memcpy or memset intrinsics, which
 * the BPF backend cannot lower for arena memory.
 */
static __always_inline void obs_copy_in(void __arena *dst, const void *src,
					__u32 words)
{
	__u64 __arena *d = dst;
	const __u64 *s = src;
	__u32 i;

#pragma clang loop unroll(disable)
	for (i = 0; i < words; i++) {
		barrier_var(i);
		d[i] = s[i];
	}
}

static __always_inline void obs_zero(void __arena *dst, __u32 words)
{
	__u64 __arena *d = dst;
	__u32 i;

#pragma clang loop unroll(disable)
	for (i = 0; i < words; i++) {
		barrier_var(i);
		d[i] = 0;
	}
}

static __always_inline bool obs_words_equal(const void __arena *a,
					    const void *b, __u32 words)
{
	const __u64 __arena *x = a;
	const __u64 *y = b;
	__u32 i;

#pragma clang loop unroll(full)
	for (i = 0; i < words; i++) {
		if (x[i] != y[i])
			return false;
	}
	return true;
}

static __always_inline __u32 obs_hash_words(const void *p, __u32 words)
{
	const __u64 *w = p;
	__u64 h = 0;
	__u32 i;

#pragma clang loop unroll(full)
	for (i = 0; i < words; i++)
		h = obs_hash_mix(h, w[i]);
	return (__u32)h;
}

/* Serializer page header, written into slot zero of every page. */
struct obs_serial_header {
	__u32 magic;
	__u16 version;
	__u16 header_size;
	__u16 record_size;
	__u16 records_per_page;
	__u32 capacity;
	__u32 buckets;
	__u32 key_size;
	__u32 val_size;
	__u32 flags;
	__u64 boot_now_ns;
	__u64 since_ns;
	__u32 used;
	__u32 overflow;
	__u32 lost;
	__u32 reserved;
};

BUILD_BUG_ON(sizeof(struct obs_serial_header) != 64);

#define OBS_SERIAL_VERSION	1
#define OBS_SERIAL_PAGE_CHUNKS	4

static __always_inline void obs_serial_error(struct shirudo_serialize_ctx *ctx,
					     int status)
{
	struct shirudo_serial_chunk *chunk;
	__u32 key = 0;

	chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
	if (!chunk)
		return;
	chunk->magic = SHIRUDO_SERIAL_MAGIC;
	chunk->version = SHIRUDO_SERIAL_VERSION;
	chunk->flags = SHIRUDO_SERIAL_F_DONE;
	chunk->status = status;
	chunk->chunk_index = 0;
	chunk->total_chunks = 1;
	chunk->bytes_total = 0;
	chunk->bytes_in_chunk = 0;
	chunk->page_index = ctx ? ctx->page_index : 0;
	chunk->reserved = 0;
	chunk->cursor = ctx ? ctx->cursor : 0;
	chunk->next_cursor = chunk->cursor;
	chunk->invocation_id = ctx ? ctx->invocation_id : 0;
}

/* Copy arena words into a serializer chunk at a verifier-known offset. */
static __always_inline void obs_emit_bytes(struct shirudo_serial_chunk *chunk,
					   __u32 off, const void __arena *src,
					   __u32 words)
{
	const __u64 __arena *s = src;
	__u32 i;

#pragma clang loop unroll(full)
	for (i = 0; i < words; i++)
		*(__u64 *)&chunk->data[off + i * 8] = s[i];
}

static __always_inline bool
obs_serial_ctx_valid(const struct shirudo_serialize_ctx *ctx)
{
	return ctx && ctx->magic == SHIRUDO_SERIAL_MAGIC &&
	       ctx->version == SHIRUDO_SERIAL_VERSION &&
	       ctx->chunk_payload_size == SHIRUDO_SERIAL_CHUNK_PAYLOAD;
}

#endif /* KERNEL_OBS_COMMON_H */
