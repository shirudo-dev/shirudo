// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The signed attach metadata of a .upatch, for metadata of LEN bytes, each
 * length proofs.list names, with as many programs as it has room for:
 * prog_specs_parse() reads nothing outside it, gives every program a known
 * role and kind with terminated names, every uprobe an absolute path and
 * rising offsets, every kprobe multi program terminated, strictly rising
 * names in its buffer, every XDP program known device classes, and frees
 * all it took on refusal, as prog_specs_free() does.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#ifdef PROOF_XMALLOC
#define xmalloc PROOF_XMALLOC
#endif
#ifdef PROOF_XCALLOC
#define xcalloc PROOF_XCALLOC
#endif
#ifdef PROOF_XSTRNDUP
#define xstrndup PROOF_XSTRNDUP
#endif
#include "../../../util/upatch.c"
#ifdef PROOF_XMALLOC
#undef xmalloc
#endif
#ifdef PROOF_XCALLOC
#undef xcalloc
#endif
#ifdef PROOF_XSTRNDUP
#undef xstrndup
#endif

/* A harness that includes this one may fix bytes of the metadata. */
#ifndef SHAPE_METADATA
#define SHAPE_METADATA(metadata)
#endif

#define ENTRIES_LEN	(LEN - (__s64)sizeof(struct upatch_prog_metadata))
#define NR_PROGS	(ENTRIES_LEN < 0 ? 0 : \
			 ENTRIES_LEN / sizeof(struct upatch_prog_entry))

static bool terminated(const char *s, size_t size)
{
	return memchr(s, '\0', size);
}

static bool needs_target(__u32 kind)
{
	return kind == UPATCH_ATTACH_KPROBE ||
	       kind == UPATCH_ATTACH_KRETPROBE ||
	       kind_has_uprobe_target(kind);
}

static void uprobe_valid(const struct prog_spec *s)
{
	__u32 j;

	__CPROVER_assert(s->uprobe_path && s->uprobe_path[0] == '/' &&
			 strnlen(s->uprobe_path, UPATCH_UPROBE_PATH_MAX) <
			 UPATCH_UPROBE_PATH_MAX,
			 "an absolute, terminated path");
	if (kind_is_uprobe_multi(s->kind))
		__CPROVER_assert(!strchr(s->target, ',') && !strchr(s->target, '|'),
				 "a glob without separators");
	else
		__CPROVER_assert(s->nr_uprobe_offsets == 1, "one offset for a uprobe");
	__CPROVER_assert(s->build_id_len && s->build_id_len <=
			 UPATCH_BUILD_ID_MAX, "a build ID");
	__CPROVER_assert(s->nr_uprobe_offsets && s->uprobe_offsets,
			 "an offset");
	for (j = 1; j < s->nr_uprobe_offsets; j++)
		__CPROVER_assert(s->uprobe_offsets[j - 1] <
				 s->uprobe_offsets[j], "rising offsets");
}

static void kprobe_multi_valid(const struct prog_spec *s)
{
	__u32 i;

	__CPROVER_assert(s->nr_kprobe_syms && s->kprobe_syms &&
			 s->nr_kprobe_syms <= UPATCH_KPROBE_SYMS_MAX, "names within the limit");
	for (i = 0; i < s->nr_kprobe_syms; i++) {
		size_t off = (size_t)(s->kprobe_syms[i] - s->kprobe_sym_buf);

		__CPROVER_assert(off < s->kprobe_sym_buf_len &&
				 terminated(s->kprobe_syms[i], s->kprobe_sym_buf_len - off),
				 "a terminated name in the buffer");
		__CPROVER_assert(!i || strcmp(s->kprobe_syms[i - 1], s->kprobe_syms[i]) < 0,
				 "rising names");
	}
}

static void attach_valid(const struct prog_spec *s)
{
	__CPROVER_assert(!s->map[0], "no map");
	__CPROVER_assert(s->kind <= UPATCH_ATTACH_KRETPROBE_MULTI, "a known attach kind");
	if (s->kind == UPATCH_ATTACH_XDP)
		__CPROVER_assert(s->device_classes &&
				 !(s->device_classes & ~(__u32)UPATCH_XDP_ALL),
				 "known device classes");
	if (kind_is_kprobe_multi(s->kind))
		kprobe_multi_valid(s);
	if (!needs_target(s->kind)) {
		__CPROVER_assert(!s->target[0] && !s->offset,
				 "no target or offset");
		return;
	}
	__CPROVER_assert(s->target[0], "a target");
	__CPROVER_assert(s->kind == UPATCH_ATTACH_KPROBE || s->kind == UPATCH_ATTACH_UPROBE ||
			 !s->offset, "an offset for a kprobe or uprobe alone");
	if (kind_has_uprobe_target(s->kind))
		uprobe_valid(s);
}

static void spec_valid(const struct prog_spec *s)
{
	__CPROVER_assert(s->target_fd == -1, "no descriptor yet");
	__CPROVER_assert(terminated(s->target, sizeof(s->target)) &&
			 terminated(s->map, sizeof(s->map)),
			 "terminated target and map");
	if (!kind_has_uprobe_target(s->kind))
		__CPROVER_assert(!s->uprobe_path && !s->uprobe_offsets,
				 "uprobe targets for uprobes alone");
	if (s->kind != UPATCH_ATTACH_XDP)
		__CPROVER_assert(!s->device_classes,
				 "device classes for XDP alone");
	if (!kind_is_kprobe_multi(s->kind))
		__CPROVER_assert(!s->kprobe_syms && !s->kprobe_sym_buf,
				 "kprobe names for kprobe multi alone");
	switch (s->role) {
	case UPATCH_PROG_ROLE_ATTACH:
		attach_valid(s);
		break;
	case UPATCH_PROG_ROLE_SERIALIZER:
		__CPROVER_assert(s->map[0] && !s->target[0] && !s->kind &&
				 !s->offset, "a map and nothing else");
		break;
	case UPATCH_PROG_ROLE_TEST_RUN:
		__CPROVER_assert(!s->map[0] && !s->target[0] && !s->kind &&
				 !s->offset, "nothing");
		break;
	default:
		__CPROVER_assert(false, "a known role");
	}
}

void harness(void)
{
	struct prog_spec *specs = (void *)1;
	const __u32 nr_progs = NR_PROGS;
	__u32 nr_maps, i;
	__u8 *metadata;
	int ret;

	metadata = any_bytes(LEN);
	SHAPE_METADATA(metadata);
	ret = prog_specs_parse(metadata, LEN, nr_maps, nr_progs, &specs);
	if (ret) {
		__CPROVER_assert(ret < 0 && !specs, "an error and no specs");
		return;
	}
	__CPROVER_assert(specs, "the specs");
	__CPROVER_assert(get_le32(metadata) == UPATCH_PROG_MAGIC &&
			 get_le32(metadata + 4) == UPATCH_PROG_VERSION &&
			 get_le32(metadata + 8) == nr_progs &&
			 get_le32(metadata + 12) == nr_maps,
			 "the magic, version and counts of the upatch");
	for (i = 0; i < nr_progs; i++)
		spec_valid(&specs[i]);
	prog_specs_free(specs, nr_progs);
}
