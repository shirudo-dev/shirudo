// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The signed attach metadata of a .upatch, for metadata of LEN bytes, each
 * length proofs.list names, with as many programs as it has room for:
 * prog_specs_parse() reads nothing outside it, gives every program a known
 * role and kind with terminated names, every uprobe an absolute path and
 * rising offsets, every XDP program known device classes, and frees all it
 * took on refusal, as prog_specs_free() does.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/upatch.c"

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
	       kind == UPATCH_ATTACH_UPROBE_MULTI;
}

static void uprobe_valid(const struct prog_spec *s)
{
	__u32 j;

	__CPROVER_assert(s->uprobe_path && s->uprobe_path[0] == '/' &&
			 strnlen(s->uprobe_path, s->uprobe_path_len + 1) ==
			 s->uprobe_path_len, "an absolute path of its length");
	__CPROVER_assert(!strchr(s->target, ',') && !strchr(s->target, '|'),
			 "a target without separators");
	__CPROVER_assert(s->build_id_len && s->build_id_len <=
			 UPATCH_BUILD_ID_MAX, "a build ID");
	__CPROVER_assert(s->nr_uprobe_offsets && s->uprobe_offsets,
			 "an offset");
	for (j = 1; j < s->nr_uprobe_offsets; j++)
		__CPROVER_assert(s->uprobe_offsets[j - 1] <
				 s->uprobe_offsets[j], "rising offsets");
}

static void attach_valid(const struct prog_spec *s)
{
	__CPROVER_assert(!s->map[0], "no map");
	__CPROVER_assert(s->kind <= UPATCH_ATTACH_XDP, "a known attach kind");
	if (s->kind == UPATCH_ATTACH_XDP)
		__CPROVER_assert(s->device_classes &&
				 !(s->device_classes & ~(__u32)UPATCH_XDP_ALL),
				 "known device classes");
	if (!needs_target(s->kind)) {
		__CPROVER_assert(!s->target[0] && !s->offset,
				 "no target or offset");
		return;
	}
	__CPROVER_assert(s->target[0], "a target");
	__CPROVER_assert(s->kind == UPATCH_ATTACH_KPROBE || !s->offset,
			 "an offset for a kprobe alone");
	if (s->kind == UPATCH_ATTACH_UPROBE_MULTI)
		uprobe_valid(s);
}

static void spec_valid(const struct prog_spec *s)
{
	__CPROVER_assert(s->target_fd == -1, "no descriptor yet");
	__CPROVER_assert(terminated(s->target, sizeof(s->target)) &&
			 terminated(s->map, sizeof(s->map)),
			 "terminated target and map");
	if (s->kind != UPATCH_ATTACH_UPROBE_MULTI)
		__CPROVER_assert(!s->uprobe_path && !s->uprobe_offsets,
				 "uprobe targets for uprobes alone");
	if (s->kind != UPATCH_ATTACH_XDP)
		__CPROVER_assert(!s->device_classes,
				 "device classes for XDP alone");
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
