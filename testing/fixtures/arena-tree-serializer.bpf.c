// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Reference serializer for an arena-resident binary tree. The program
 * builds a deterministic tree inside BPF_MAP_TYPE_ARENA and serializes
 * it into paged shirudo_ser output when `shirudo upatch map <id>
 * tree_arena` runs.
 */

#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "shirudo_serializer.h"

#define E2BIG		7
#define EINVAL		22
#define ENOSPC		28

#define NUMA_NO_NODE	(-1)

#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
#define __arena	__attribute__((address_space(1)))
#else
#define __arena
#endif

#define TREE_NODES	192u

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 32);	/* pages */
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
	__ulong(map_extra, (1ull << 32));	/* start of mmap() region */
#else
	__ulong(map_extra, (1ull << 44));	/* start of mmap() region */
#endif
} tree_arena SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, struct shirudo_serial_chunk);
} shirudo_ser SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} tree_error SEC(".maps");

struct tree_node {
	__u32 key;
	__u32 value;
	struct tree_node __arena *left;
	struct tree_node __arena *right;
};

struct arena_tree_state {
	struct tree_node nodes[TREE_NODES];
};

struct tree_record {
	__u32 key;
	__u32 value;
	__s32 left_key;
	__s32 right_key;
};

enum {
	TREE_RECORD_SIZE = sizeof(struct tree_record),
	TREE_SERIAL_BYTES = TREE_NODES * TREE_RECORD_SIZE,
	TREE_RECORDS_PER_CHUNK =
		SHIRUDO_SERIAL_CHUNK_PAYLOAD / TREE_RECORD_SIZE,
	TREE_RECORDS_PER_PAGE = 64,
	TREE_PAGE_BYTES = TREE_RECORDS_PER_PAGE * TREE_RECORD_SIZE,
	TREE_PAGE_CHUNKS =
		(TREE_PAGE_BYTES + SHIRUDO_SERIAL_CHUNK_PAYLOAD - 1) /
		SHIRUDO_SERIAL_CHUNK_PAYLOAD,
	TREE_ARENA_PAGES =
		(sizeof(struct arena_tree_state) + 4095) / 4096,
};

void __arena *bpf_arena_alloc_pages(void *map, void __arena *addr,
				    __u32 page_cnt, int node_id,
				    __u64 flags) __ksym __weak;

static struct tree_node __arena *root;

static __always_inline void set_error(struct shirudo_serialize_ctx *ctx,
				      int status)
{
	struct shirudo_serial_chunk *chunk;
	__u32 key = 0;
	__u32 page_index = ctx ? ctx->page_index : 0;
	__u64 cursor = ctx ? ctx->cursor : 0;

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
	chunk->page_index = page_index;
	chunk->reserved = 0;
	chunk->cursor = cursor;
	chunk->next_cursor = cursor;
	chunk->invocation_id = ctx ? ctx->invocation_id : 0;
}

static __always_inline int init_page_chunks(__u32 records, __u32 flags,
					    __u32 page_index, __u64 cursor,
					    __u64 next_cursor,
					    __u64 invocation_id)
{
	__u32 page_bytes = records * TREE_RECORD_SIZE;
	__u32 total_chunks;
	__u32 i;

	total_chunks = (page_bytes + SHIRUDO_SERIAL_CHUNK_PAYLOAD - 1) /
		       SHIRUDO_SERIAL_CHUNK_PAYLOAD;
	if (total_chunks == 0)
		total_chunks = 1;

	for (i = 0; i < total_chunks; i++) {
		struct shirudo_serial_chunk *chunk;
		__u32 key = i;
		__u32 used = page_bytes -
			     i * SHIRUDO_SERIAL_CHUNK_PAYLOAD;

		chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
		if (!chunk)
			return -ENOSPC;
		if (used > SHIRUDO_SERIAL_CHUNK_PAYLOAD)
			used = SHIRUDO_SERIAL_CHUNK_PAYLOAD;
		chunk->magic = SHIRUDO_SERIAL_MAGIC;
		chunk->version = SHIRUDO_SERIAL_VERSION;
		chunk->flags = flags;
		chunk->status = 0;
		chunk->chunk_index = i;
		chunk->total_chunks = total_chunks;
		chunk->bytes_total = page_bytes;
		chunk->bytes_in_chunk = used;
		chunk->page_index = page_index;
		chunk->reserved = 0;
		chunk->cursor = cursor;
		chunk->next_cursor = next_cursor;
		chunk->invocation_id = invocation_id;
	}
	return 0;
}

static __always_inline int build_tree(void)
{
	struct arena_tree_state __arena *state;
	__u32 i;

	if (root)
		return 0;

	state = bpf_arena_alloc_pages(&tree_arena, 0, TREE_ARENA_PAGES,
				      NUMA_NO_NODE, 0);
	if (!state)
		return -ENOSPC;
	for (i = 0; i < TREE_NODES; i++) {
		__u32 left = 2 * i + 1;
		__u32 right = left + 1;

		state->nodes[i].key = i;
		state->nodes[i].value = i * 3 + 7;
		state->nodes[i].left = left < TREE_NODES ?
				       &state->nodes[left] : 0;
		state->nodes[i].right = right < TREE_NODES ?
					&state->nodes[right] : 0;
	}
	root = &state->nodes[0];
	return 0;
}

static __always_inline int emit_record(struct tree_node __arena *node,
				       __u32 absolute, __u32 page_slot)
{
	struct shirudo_serial_chunk *chunk;
	struct tree_record rec = {};
	__u32 chunk_key = page_slot / TREE_RECORDS_PER_CHUNK;
	__u32 slot = page_slot % TREE_RECORDS_PER_CHUNK;
	__u32 off = slot * TREE_RECORD_SIZE;
	__u32 left = 2 * absolute + 1;
	__u32 right = left + 1;

	if (chunk_key >= TREE_PAGE_CHUNKS)
		return -ENOSPC;
	chunk = bpf_map_lookup_elem(&shirudo_ser, &chunk_key);
	if (!chunk)
		return -ENOSPC;

	rec.key = node->key;
	rec.value = node->value;
	rec.left_key = left < TREE_NODES ? (__s32)left : -1;
	rec.right_key = right < TREE_NODES ? (__s32)right : -1;
	__builtin_memcpy(&chunk->data[off], &rec, sizeof(rec));
	return 0;
}

SEC("syscall")
int shirudo_serialize__tree_arena(struct shirudo_serialize_ctx *ctx)
{
	__u32 start, records, emitted, flags = 0;
	__u64 next_cursor;
	int rc;

	if (!ctx || ctx->magic != SHIRUDO_SERIAL_MAGIC ||
	    ctx->version != SHIRUDO_SERIAL_VERSION ||
	    ctx->chunk_payload_size != SHIRUDO_SERIAL_CHUNK_PAYLOAD ||
	    ctx->invocation_id == 0)
		return -EINVAL;
	if (ctx->max_chunks < TREE_PAGE_CHUNKS) {
		set_error(ctx, -E2BIG);
		return -E2BIG;
	}
	if (ctx->cursor > TREE_NODES) {
		set_error(ctx, -EINVAL);
		return -EINVAL;
	}

	rc = build_tree();
	if (rc) {
		set_error(ctx, rc);
		return rc;
	}

	start = (__u32)ctx->cursor;
	records = TREE_NODES - start;
	if (records > TREE_RECORDS_PER_PAGE)
		records = TREE_RECORDS_PER_PAGE;

	next_cursor = start + records;
	if (next_cursor >= TREE_NODES)
		flags = SHIRUDO_SERIAL_F_DONE;

	rc = init_page_chunks(records, flags, ctx->page_index, ctx->cursor,
			      next_cursor, ctx->invocation_id);
	if (rc) {
		set_error(ctx, rc);
		return rc;
	}

	for (emitted = 0; emitted < TREE_RECORDS_PER_PAGE; emitted++) {
		__u32 absolute = start + emitted;
		struct tree_node __arena *cur;

		if (emitted >= records)
			break;
		if (absolute >= TREE_NODES) {
			set_error(ctx, -EINVAL);
			return -EINVAL;
		}
		cur = root + absolute;
		if (!cur || cur->key >= TREE_NODES) {
			set_error(ctx, -EINVAL);
			return -EINVAL;
		}
		rc = emit_record(cur, absolute, emitted);
		if (rc) {
			set_error(ctx, rc);
			return rc;
		}
	}
	return 0;
}

SEC("syscall")
int shirudo_serialize__tree_error(struct shirudo_serialize_ctx *ctx)
{
	if (!ctx || !ctx->invocation_id)
		return -EINVAL;
	set_error(ctx, -EINVAL);
	return -EINVAL;
}

char _license[] SEC("license") = "Dual BSD/GPL";
