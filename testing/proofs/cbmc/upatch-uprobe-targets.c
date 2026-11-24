// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * parse_uprobe_targets() of util/upatch.c on a uprobe target block of LEN
 * bytes, for the program table prog_specs_parse() hands it: it reads
 * nothing outside the block, leaves what the program entry set as it was,
 * and accepts a record only with an absolute path, a build ID and rising
 * offsets.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/upatch.c"

/* The fields a program entry sets, which the block leaves alone. */
static void entry_kept(const struct prog_spec *s, const struct prog_spec *e)
{
	__CPROVER_assert(s->role == e->role && s->kind == e->kind &&
			 s->device_classes == e->device_classes &&
			 s->offset == e->offset && s->target_fd == e->target_fd &&
			 !memcmp(s->target, e->target, sizeof(s->target)) &&
			 !memcmp(s->map, e->map, sizeof(s->map)),
			 "the fields of the program entry unchanged");
}

static void uprobe_valid(const struct prog_spec *s)
{
	__u32 j;

	__CPROVER_assert(s->uprobe_path && s->uprobe_path[0] == '/' &&
			 strnlen(s->uprobe_path, UPATCH_UPROBE_PATH_MAX) <
			 UPATCH_UPROBE_PATH_MAX,
			 "an absolute, terminated path");
	if (!kind_is_uprobe_multi(s->kind))
		__CPROVER_assert(s->nr_uprobe_offsets == 1, "one offset for a uprobe");
	__CPROVER_assert(s->build_id_len && s->build_id_len <=
			 UPATCH_BUILD_ID_MAX, "a build ID");
	__CPROVER_assert(s->nr_uprobe_offsets && s->uprobe_offsets,
			 "an offset");
	for (j = 1; j < s->nr_uprobe_offsets; j++)
		__CPROVER_assert(s->uprobe_offsets[j - 1] <
				 s->uprobe_offsets[j], "rising offsets");
}

void harness(void)
{
	struct prog_spec entry, *specs;
	const __u8 *block, *pos;
	int ret;

	/*
	 * One program of a uprobe kind, as prog_specs_parse() calls this only
	 * with a uprobe among its programs: the entry's fields any value, the
	 * uprobe fields as xcalloc() left them.
	 */
	__CPROVER_assume(kind_has_uprobe_target(entry.kind));
	entry.uprobe_path = NULL;
	entry.build_id_len = 0;
	entry.uprobe_offsets = NULL;
	entry.nr_uprobe_offsets = 0;
	entry.kprobe_sym_buf = NULL;
	entry.kprobe_sym_buf_len = 0;
	entry.kprobe_syms = NULL;
	entry.nr_kprobe_syms = 0;
	entry.target_fd = -1;
	specs = xcalloc(1, sizeof(*specs));
	if (!specs)
		return;
	*specs = entry;

	block = any_bytes(LEN);
	pos = block;
	ret = parse_uprobe_targets(&pos, block + LEN, specs, 1, 1);
	if (ret) {
		__CPROVER_assert(ret < 0, "an error");
	} else {
		__CPROVER_assert(pos >= block && pos <= block + LEN,
				 "an end within the block");
		entry_kept(specs, &entry);
		uprobe_valid(specs);
	}
	prog_specs_free(specs, 1);
}
