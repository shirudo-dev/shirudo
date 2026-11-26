// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * java-watch.bpf.c -- the JVMs that run on the host, and the agents of the
 * Java upatches each of them opened. Nothing in this upatch enforces.
 */

#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "decoder.h"
#include "serializer.h"
#include "xattr.h"

char _license[] SEC("license") = "Dual BSD/GPL";

#if !defined(__BPF_FEATURE_ADDR_SPACE_CAST)
#error "BPF arena access requires clang address-space cast support"
#endif

#define __arena		__attribute__((address_space(1))) \
			__attribute__((btf_type_tag("arena")))
#define NUMA_NO_NODE	(-1)

#define E2BIG		7
#define EINVAL		22
#define ENOMEM		12

#define PROT_EXEC	0x4

#define JW_CAPACITY	512
#define JW_HASH_SHIFT	23	/* 32 - log2(JW_CAPACITY) */
#define JW_STEPS	16
#define JW_AGENTS	4
#define JW_NAME_LEN	40
#define JW_ARENA_PAGES	40

/*
 * A slot's seq holds its state in the low two bits and its generation
 * above them. Freeing a slot moves it to the next generation, so a reader
 * that sees the same seq before and after reading the fields read one JVM.
 */
#define JW_FREE		0ULL
#define JW_CLAIMED	1ULL
#define JW_LIVE		2ULL
#define JW_STATE_MASK	3ULL
#define JW_GEN_STEP	4ULL

/* The state of a process's reference to its slot. */
#define JW_REF_NONE	0
#define JW_REF_CLAIMING	1
#define JW_REF_READY	2
#define JW_REF_FAILED	3

#define JW_MAGIC	0x534d564au	/* "JVMS" little-endian */
#define JW_VERSION	1
#define JW_HEADER	64
#define JW_RECORD	256
#define JW_PER_PAGE	(SERIAL_CHUNK_PAYLOAD / JW_RECORD - 1)

#define JW_REC_PRESENT		(1u << 0)
#define JW_REC_MORE_AGENTS	(1u << 1)
#define JW_REC_NAME_CUT(i)	(1u << (8 + (i)))

struct jw_agent {
	__u64 ino;
	__u32 ready;
	__u32 name_cut;
	char name[JW_NAME_LEN];
};

struct jw_slot {
	__u64 seq;
	__u32 tgid;
	__u32 euid;
	__u64 start_ns;
	__u64 cgroup;
	__u64 seen_ns;
	__u32 mnt_ns;
	__u32 jvm_dev;
	__u64 jvm_ino;
	__u32 more_agents;
	__u32 _pad;
	struct jw_agent agents[JW_AGENTS];
};

struct jw_table {
	__u32 overflow;
	__u32 _pad;
	struct jw_slot slots[JW_CAPACITY];
};

enum {
	JW_TABLE_PAGES = (sizeof(struct jw_table) + 4095) / 4096,
};

BUILD_BUG_ON(JW_CAPACITY != 1u << (32 - JW_HASH_SHIFT));
BUILD_BUG_ON(JW_TABLE_PAGES > JW_ARENA_PAGES);
BUILD_BUG_ON(JW_NAME_LEN % 8);
BUILD_BUG_ON(JW_HEADER + JW_AGENTS * (8 + JW_NAME_LEN) != JW_RECORD);

struct jw_ref {
	__u64 seq;
	__u32 idx;
	__u32 state;
};

struct jw_scratch {
	char label[LABEL_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, JW_ARENA_PAGES);
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
	__ulong(map_extra, (1ull << 32));
#else
	__ulong(map_extra, (1ull << 44));
#endif
} obs_i_arena SEC(".maps");

/* Kept on the thread group leader: every thread of a JVM finds its slot. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct jw_ref);
} obs_i_jvm_task SEC(".maps");

/* bpf_get_file_xattr() sleeps and reads into map memory, never the stack. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct jw_scratch);
} obs_i_jvm_scr SEC(".maps");

/* The table lives in the arena; this map carries its name. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} jvms SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct serial_chunk);
} shirudo_ser SEC(".maps");

const struct decoder_manifest jvms_decoder SEC(".rodata") = {
	.magic = DECODER_MANIFEST_MAGIC,
	.version = UPATCH_DECODER_VERSION,
	.language = UPATCH_DECODER_LANG_LUA,
	.api_version = 1,
	.input_format = UPATCH_DECODER_INPUT_MAP_V1,
	.export_signal = UPATCH_DECODER_EXPORT_LOG,
	.upatch = "java-watch",
	.map = "jvms",
	.source = "decoders/jvms.lua",
	.entrypoint = "decode",
};

void __arena *bpf_arena_alloc_pages(void *map, void __arena *addr, __u32 page_cnt,
				    int node_id, __u64 flags) __ksym __weak;
int bpf_get_file_xattr(struct file *file, const char *name__str,
		       struct bpf_dynptr *value_p) __ksym;
void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

static struct jw_table __arena *jw_table;

/*
 * The verifier binds a program to the arena only through a direct
 * reference to the map; this no-op call is that reference.
 */
static __always_inline struct jw_table __arena *jw_table_get(void)
{
	struct jw_table __arena *table = READ_ONCE(jw_table);

	if (!table)
		bpf_arena_alloc_pages(&obs_i_arena, 0, 0, NUMA_NO_NODE, 0);
	return table;
}

static __always_inline bool jw_dentry_name_is(struct dentry *dentry, const char *want,
					      __u32 want_len)
{
	const unsigned char *name;
	char buf[16];
	__u32 i;

	if (!dentry || BPF_CORE_READ(dentry, d_name.len) != want_len)
		return false;
	name = BPF_CORE_READ(dentry, d_name.name);
	if (!name || bpf_probe_read_kernel(buf, want_len, name))
		return false;
#pragma clang loop unroll(full)
	for (i = 0; i < want_len; i++) {
		if (buf[i] != want[i])
			return false;
	}
	return true;
}

static __always_inline bool jw_is_libjvm(struct file *file)
{
	return jw_dentry_name_is(file->f_path.dentry, "libjvm.so", 9);
}

/* A jar shirudo installed: <name>.jar in /run/shirudo-java. */
static __always_inline bool jw_in_agent_dir(struct file *file)
{
	struct dentry *dentry = file->f_path.dentry;
	const unsigned char *name;
	char tail[4];
	__u32 len;

	if (!dentry)
		return false;
	len = BPF_CORE_READ(dentry, d_name.len);
	if (len < 5)
		return false;
	name = BPF_CORE_READ(dentry, d_name.name);
	if (!name || bpf_probe_read_kernel(tail, sizeof(tail), name + len - 4))
		return false;
	if (tail[0] != '.' || tail[1] != 'j' || tail[2] != 'a' || tail[3] != 'r')
		return false;
	return jw_dentry_name_is(BPF_CORE_READ(dentry, d_parent), "shirudo-java", 12);
}

/*
 * Only a task with shirudo's runtime authority can set the seal label,
 * so a labeled jar is one shirudo wrote, wherever root mounts a copy.
 */
static __always_inline bool jw_sealed(struct task_struct *task, struct file *file)
{
	struct jw_scratch *s;
	struct bpf_dynptr dp;

	s = bpf_task_storage_get(&obs_i_jvm_scr, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!s)
		return false;
	bpf_dynptr_from_mem(s->label, LABEL_LEN, 0, &dp);
	return bpf_get_file_xattr(file, XATTR_SEAL, &dp) == LABEL_LEN;
}

static __always_inline void jw_fill(struct jw_slot __arena *slot, struct task_struct *task,
				    struct task_struct *leader, struct file *file)
{
	__u32 i;

	slot->tgid = leader->tgid;
	slot->euid = BPF_CORE_READ(task, real_cred, euid.val);
	slot->start_ns = leader->start_boottime;
	slot->cgroup = bpf_get_current_cgroup_id();
	slot->seen_ns = bpf_ktime_get_boot_ns();
	slot->mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	slot->jvm_dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
	slot->jvm_ino = BPF_CORE_READ(file, f_inode, i_ino);
	slot->more_agents = 0;
#pragma clang loop unroll(full)
	for (i = 0; i < JW_AGENTS; i++) {
		slot->agents[i].ino = 0;
		slot->agents[i].ready = 0;
		slot->agents[i].name_cut = 0;
	}
}

/*
 * The fields are written while the slot is claimed, then published with
 * a release store of its seq, which the serializer loads with acquire.
 */
static __always_inline void jw_claim(struct task_struct *task, struct task_struct *leader,
				     struct file *file, struct jw_ref *ref)
{
	struct jw_table __arena *table = jw_table_get();
	struct jw_slot __arena *slot;
	__u32 start, idx, i;
	__u64 seq;

	if (!table) {
		__atomic_store_n(&ref->state, JW_REF_FAILED, __ATOMIC_RELEASE);
		return;
	}
	start = (leader->tgid * 0x9e3779b1u) >> JW_HASH_SHIFT;
#pragma clang loop unroll(disable)
	for (i = 0; i < JW_STEPS; i++) {
		idx = (start + i) & (JW_CAPACITY - 1);
		slot = &table->slots[idx];
		seq = READ_ONCE(slot->seq);
		if ((seq & JW_STATE_MASK) != JW_FREE)
			continue;
		if (__sync_val_compare_and_swap(&slot->seq, seq, seq + JW_CLAIMED) != seq)
			continue;
		jw_fill(slot, task, leader, file);
		__atomic_store_n(&slot->seq, seq + JW_LIVE, __ATOMIC_RELEASE);
		ref->idx = idx;
		ref->seq = seq + JW_LIVE;
		__atomic_store_n(&ref->state, JW_REF_READY, __ATOMIC_RELEASE);
		return;
	}
	__sync_fetch_and_add(&table->overflow, 1);
	__atomic_store_n(&ref->state, JW_REF_FAILED, __ATOMIC_RELEASE);
}

/* Fails when the slot has been freed since, so a slot is freed once. */
static __always_inline void jw_free(__u32 idx, __u64 seq)
{
	struct jw_table __arena *table = jw_table_get();

	if (!table || (seq & JW_STATE_MASK) != JW_LIVE)
		return;
	__sync_val_compare_and_swap(&table->slots[idx & (JW_CAPACITY - 1)].seq, seq,
				    (seq & ~JW_STATE_MASK) + JW_GEN_STEP);
}

static __always_inline void jw_free_ref(struct jw_ref *ref)
{
	if (__atomic_load_n(&ref->state, __ATOMIC_ACQUIRE) == JW_REF_READY)
		jw_free(ref->idx, ref->seq);
}

/*
 * A thread other than the leader that execs becomes the leader, and the
 * old leader goes with the reference: find the slot by the identity the
 * new leader inherits.
 */
static __always_inline void jw_free_process(__u32 tgid, __u64 start_ns)
{
	struct jw_table __arena *table = jw_table_get();
	struct jw_slot __arena *slot;
	__u32 start, idx, i;
	__u64 seq;

	if (!table)
		return;
	start = (tgid * 0x9e3779b1u) >> JW_HASH_SHIFT;
#pragma clang loop unroll(disable)
	for (i = 0; i < JW_STEPS; i++) {
		idx = (start + i) & (JW_CAPACITY - 1);
		slot = &table->slots[idx];
		seq = __atomic_load_n(&slot->seq, __ATOMIC_ACQUIRE);
		if ((seq & JW_STATE_MASK) != JW_LIVE)
			continue;
		if (slot->tgid == tgid && slot->start_ns == start_ns)
			jw_free(idx, seq);
	}
}

static __always_inline bool jw_task_ref(struct task_struct *task, struct jw_ref *out)
{
	struct jw_ref *ref;
	bool ready = false;

	bpf_rcu_read_lock();
	ref = bpf_task_storage_get(&obs_i_jvm_task, task->group_leader, 0, 0);
	if (ref && __atomic_load_n(&ref->state, __ATOMIC_ACQUIRE) == JW_REF_READY) {
		out->idx = ref->idx;
		out->seq = ref->seq;
		ready = true;
	}
	bpf_rcu_read_unlock();
	return ready;
}

static __always_inline void jw_agent_name(struct jw_agent __arena *agent, struct file *file)
{
	char name[JW_NAME_LEN] = {};
	const unsigned char *src;
	__u64 *words = (__u64 *)name;
	__u64 __arena *dst = (__u64 __arena *)agent->name;
	__u32 i;

	src = BPF_CORE_READ(file, f_path.dentry, d_name.name);
	if (src)
		bpf_probe_read_kernel_str(name, sizeof(name), src);
	if (BPF_CORE_READ(file, f_path.dentry, d_name.len) >= JW_NAME_LEN)
		agent->name_cut = 1;
#pragma clang loop unroll(full)
	for (i = 0; i < JW_NAME_LEN / 8; i++)
		dst[i] = words[i];
}

/*
 * The threads of a JVM open jars at once. An agent takes the first free
 * entry by compare-and-swap of its inode, and its name is published with
 * a release store of ready.
 */
static __always_inline void jw_add_agent(const struct jw_ref *ref, struct file *file)
{
	struct jw_table __arena *table = jw_table_get();
	struct jw_agent __arena *agent;
	struct jw_slot __arena *slot;
	__u64 ino, cur;
	__u32 i;

	if (!table)
		return;
	slot = &table->slots[ref->idx & (JW_CAPACITY - 1)];
	if (READ_ONCE(slot->seq) != ref->seq)
		return;
	ino = BPF_CORE_READ(file, f_inode, i_ino);
#pragma clang loop unroll(full)
	for (i = 0; i < JW_AGENTS; i++) {
		agent = &slot->agents[i];
		cur = READ_ONCE(agent->ino);
		if (cur == ino)
			return;
		if (cur)
			continue;
		cur = __sync_val_compare_and_swap(&agent->ino, 0, ino);
		if (cur == ino)
			return;
		if (cur)
			continue;
		jw_agent_name(agent, file);
		__atomic_store_n(&agent->ready, 1, __ATOMIC_RELEASE);
		return;
	}
	WRITE_ONCE(slot->more_agents, 1);
}

SEC("lsm/mmap_file")
int BPF_PROG(jw_mmap_file, struct file *file, unsigned long reqprot, unsigned long prot,
	     unsigned long flags, int ret)
{
	struct task_struct *task, *leader;
	struct jw_ref *ref;

	if (ret || !file || !(prot & PROT_EXEC) || !jw_is_libjvm(file))
		return ret;
	task = bpf_get_current_task_btf();
	leader = task->group_leader;
	ref = bpf_task_storage_get(&obs_i_jvm_task, leader, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ref)
		return 0;
	/* The loader maps each executable segment of libjvm.so on its own. */
	if (__sync_val_compare_and_swap(&ref->state, JW_REF_NONE, JW_REF_CLAIMING) != JW_REF_NONE)
		return 0;
	jw_claim(task, leader, file, ref);
	return 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(jw_file_open, struct file *file, int ret)
{
	struct task_struct *task;
	struct jw_ref ref;

	if (ret || !file)
		return ret;
	task = bpf_get_current_task_btf();
	if (!jw_task_ref(task, &ref) || !jw_in_agent_dir(file) || !jw_sealed(task, file))
		return 0;
	jw_add_agent(&ref, file);
	return 0;
}

/* After de_thread(): the task that execs is the leader and alone. */
SEC("lsm/bprm_committed_creds")
int BPF_PROG(jw_exec, const struct linux_binprm *bprm)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct jw_ref *ref;

	ref = bpf_task_storage_get(&obs_i_jvm_task, task, 0, 0);
	if (!ref) {
		jw_free_process(task->tgid, task->start_boottime);
		return 0;
	}
	jw_free_ref(ref);
	bpf_task_storage_delete(&obs_i_jvm_task, task);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(jw_exit, struct task_struct *task, bool group_dead)
{
	struct jw_ref *ref;

	if (!group_dead || !task)
		return 0;
	ref = bpf_task_storage_get(&obs_i_jvm_task, task->group_leader, 0, 0);
	if (ref)
		jw_free_ref(ref);
	return 0;
}

static __always_inline void jw_emit_name(struct serial_chunk *chunk, __u32 off,
					 const struct jw_agent __arena *agent)
{
	const __u64 __arena *src = (const __u64 __arena *)agent->name;
	__u32 i;

#pragma clang loop unroll(full)
	for (i = 0; i < JW_NAME_LEN / 8; i++)
		*(__u64 *)&chunk->data[off + i * 8] = src[i];
}

/*
 * The seqlock's read side: the fetch-and-add of zero orders the field
 * reads before the second read of seq, which a free has changed.
 */
static __always_inline bool jw_emit_slot(struct serial_chunk *chunk, __u32 off,
					 struct jw_slot __arena *slot, __u32 idx)
{
	struct jw_agent __arena *agent;
	__u32 flags = JW_REC_PRESENT, n = 0, i, aoff;
	__u64 seq;

	seq = __atomic_load_n(&slot->seq, __ATOMIC_ACQUIRE);
	if ((seq & JW_STATE_MASK) != JW_LIVE)
		return false;
	*(__u32 *)&chunk->data[off] = idx;
	*(__u32 *)&chunk->data[off + 8] = slot->tgid;
	*(__u32 *)&chunk->data[off + 12] = slot->euid;
	*(__u64 *)&chunk->data[off + 16] = slot->start_ns;
	*(__u64 *)&chunk->data[off + 24] = slot->cgroup;
	*(__u64 *)&chunk->data[off + 32] = slot->seen_ns;
	*(__u32 *)&chunk->data[off + 40] = slot->mnt_ns;
	*(__u32 *)&chunk->data[off + 44] = slot->jvm_dev;
	*(__u64 *)&chunk->data[off + 48] = slot->jvm_ino;
	if (READ_ONCE(slot->more_agents))
		flags |= JW_REC_MORE_AGENTS;
#pragma clang loop unroll(full)
	for (i = 0; i < JW_AGENTS; i++) {
		agent = &slot->agents[i];
		if (!__atomic_load_n(&agent->ready, __ATOMIC_ACQUIRE))
			continue;
		aoff = off + JW_HEADER + n * (8 + JW_NAME_LEN);
		*(__u64 *)&chunk->data[aoff] = agent->ino;
		jw_emit_name(chunk, aoff + 8, agent);
		if (agent->name_cut)
			flags |= JW_REC_NAME_CUT(n);
		n++;
	}
	*(__u32 *)&chunk->data[off + 4] = flags;
	*(__u32 *)&chunk->data[off + 56] = n;
	*(__u32 *)&chunk->data[off + 60] = 0;
	return __sync_fetch_and_add(&slot->seq, 0) == seq;
}

struct jw_emit {
	struct jw_table __arena *table;
	__u32 start;
	__u32 next;
	__u32 out;
	int ret;
};

static int jw_emit_cb(__u32 scanned, void *data)
{
	struct jw_emit *emit = data;
	struct serial_chunk *chunk;
	__u32 key = 0, idx, off;

	idx = emit->start + scanned;
	if (idx >= JW_CAPACITY) {
		emit->next = JW_CAPACITY;
		return 1;
	}
	if (emit->out >= JW_PER_PAGE) {
		emit->next = idx;
		return 1;
	}
	emit->next = idx + 1;
	chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
	if (!chunk) {
		emit->ret = -ENOMEM;
		return 1;
	}
	off = (emit->out + 1) * JW_RECORD;
	barrier_var(off);
	if (off > SERIAL_CHUNK_PAYLOAD - JW_RECORD)
		return 1;
	if (jw_emit_slot(chunk, off, &emit->table->slots[idx], idx))
		emit->out++;
	return 0;
}

static __always_inline void jw_emit_header(struct serial_chunk *chunk,
					   const struct jw_table __arena *table)
{
	*(__u32 *)&chunk->data[0] = JW_MAGIC;
	*(__u16 *)&chunk->data[4] = JW_VERSION;
	*(__u16 *)&chunk->data[6] = JW_HEADER;
	*(__u16 *)&chunk->data[8] = JW_RECORD;
	*(__u16 *)&chunk->data[10] = JW_PER_PAGE;
	*(__u32 *)&chunk->data[12] = JW_CAPACITY;
	*(__u32 *)&chunk->data[16] = READ_ONCE(table->overflow);
	*(__u32 *)&chunk->data[20] = JW_AGENTS;
	*(__u64 *)&chunk->data[24] = bpf_ktime_get_boot_ns();
}

static __always_inline void jw_chunk_meta(struct serial_chunk *chunk,
					  const struct serialize_ctx *ctx, __u32 flags,
					  __u32 bytes, __u64 next_cursor)
{
	chunk->magic = SERIAL_MAGIC;
	chunk->version = SERIAL_VERSION;
	chunk->flags = flags;
	chunk->status = 0;
	chunk->chunk_index = 0;
	chunk->total_chunks = 1;
	chunk->bytes_total = bytes;
	chunk->bytes_in_chunk = bytes;
	chunk->page_index = ctx->page_index;
	chunk->reserved = 0;
	chunk->cursor = ctx->cursor;
	chunk->next_cursor = next_cursor;
	chunk->invocation_id = ctx->invocation_id;
}

static __always_inline void jw_serial_error(struct serial_chunk *chunk,
					    const struct serialize_ctx *ctx, int status)
{
	jw_chunk_meta(chunk, ctx, SERIAL_F_DONE, 0, ctx->cursor);
	chunk->status = status;
}

/*
 * The table is the set of JVMs running now, not an interval of events:
 * a read takes nothing away, with or without SERIAL_CTX_F_PEEK.
 */
SEC("syscall")
int shirudo_serialize__jvms(struct serialize_ctx *ctx)
{
	struct jw_table __arena *table;
	struct jw_emit emit = {};
	struct serial_chunk *chunk;
	__u32 key = 0, flags = 0;
	long ret;

	if (!ctx || ctx->magic != SERIAL_MAGIC || ctx->version != SERIAL_VERSION ||
	    ctx->chunk_payload_size != SERIAL_CHUNK_PAYLOAD)
		return -EINVAL;
	chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
	if (!chunk)
		return -ENOMEM;
	if (ctx->max_chunks < 1 || ctx->cursor > JW_CAPACITY) {
		jw_serial_error(chunk, ctx, -EINVAL);
		return -EINVAL;
	}
	table = jw_table_get();
	if (!table) {
		jw_serial_error(chunk, ctx, -ENOMEM);
		return -ENOMEM;
	}

	emit.table = table;
	emit.start = ctx->cursor;
	emit.next = JW_CAPACITY;
	if (emit.start < JW_CAPACITY) {
		ret = bpf_loop(JW_CAPACITY - emit.start, jw_emit_cb, &emit, 0);
		if (ret < 0 || emit.ret) {
			jw_serial_error(chunk, ctx, ret < 0 ? ret : emit.ret);
			return ret < 0 ? ret : emit.ret;
		}
	}
	if (emit.next >= JW_CAPACITY)
		flags = SERIAL_F_DONE;
	jw_emit_header(chunk, table);
	jw_chunk_meta(chunk, ctx, flags, (emit.out + 1) * JW_RECORD, emit.next);
	return 0;
}

/* Runs once right after attachment and allocates the table. */
SEC("syscall")
int shirudo_test__java_watch(void *ctx)
{
	struct jw_table __arena *table;

	if (READ_ONCE(jw_table))
		return 0;
	table = bpf_arena_alloc_pages(&obs_i_arena, 0, JW_TABLE_PAGES, NUMA_NO_NODE, 0);
	if (!table)
		return -ENOMEM;
	__atomic_store_n(&jw_table, table, __ATOMIC_RELEASE);
	return 0;
}
