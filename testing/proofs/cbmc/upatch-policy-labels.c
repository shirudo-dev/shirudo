// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The policy labels section of a .upatch, for sections of LEN bytes, each
 * length proofs.list names: util/upatch.c accepts one only when its labels
 * fill it, it names two distinct maps of the upatch, and every label has
 * one bit, a name and an absolute path of at most 255 bytes that does not
 * end in '/' and has no wildcard before its last component; a refusal
 * writes nothing.
 */

#define PROOF_MEMCHR_QUANTIFIED
#include "proof.h"
#include "../../../util/upatch.c"

#define HEADER_LEN	sizeof(struct upatch_policy_label_header)
#define ENTRY_LEN	sizeof(struct upatch_policy_label_entry)

static bool terminated(const char *s, size_t size)
{
	return memchr(s, '\0', size);
}

/* The rule of policy_path_valid(), stated for any one byte before the last '/'. */
static void path_valid(const char *path)
{
	size_t len, last_slash = 0, any;

	__CPROVER_assert(path[0] == '/' &&
			 terminated(path, UPATCH_POLICY_PATH_LEN_MAX + 1),
			 "an absolute path of at most 255 bytes");
	for (len = 0; path[len]; len++)
		if (path[len] == '/')
			last_slash = len;
	__CPROVER_assert(last_slash + 1 < len, "a last component");
	__CPROVER_assume(any < last_slash);
	__CPROVER_assert(path[any] != '*' && path[any] != '?',
			 "no wildcard in a directory");
}

static void label_valid(const __u8 *p, __u32 i)
{
	struct upatch_policy_label_entry e;
	__u64 bit;

	memcpy(&e, p + HEADER_LEN + i * ENTRY_LEN, sizeof(e));
	bit = le64_to_cpu(e.bit);
	__CPROVER_assert(bit && !(bit & (bit - 1)), "one bit");
	__CPROVER_assert(e.policy[0] && terminated(e.policy, sizeof(e.policy)),
			 "a terminated policy name");
	path_valid(e.path);
}

void harness(void)
{
	__u32 nr_maps, idx, socket_idx, i;
	const __u32 unset = 0xdeadbeef;
	const size_t len = LEN;
	const size_t nr_fit = len < HEADER_LEN ? 0 :
			      (len - HEADER_LEN) / ENTRY_LEN;
	__u8 *p;

	p = any_bytes(len);
	idx = unset;
	socket_idx = unset;
	if (!parse_policy_labels(p, len, nr_maps, &idx, &socket_idx)) {
		__CPROVER_assert(idx == unset && socket_idx == unset,
				 "a refusal writes nothing");
		return;
	}
	__CPROVER_assert(get_le32(p) == UPATCH_POLICY_LABELS_MAGIC &&
			 get_le32(p + 4) == UPATCH_POLICY_LABELS_VERSION,
			 "its magic and version");
	__CPROVER_assert(nr_fit && get_le32(p + 8) == nr_fit &&
			 len == HEADER_LEN + nr_fit * ENTRY_LEN,
			 "labels that fill the section");
	__CPROVER_assert(idx == get_le32(p + 12) &&
			 socket_idx == get_le32(p + 16),
			 "the maps it names");
	__CPROVER_assert(idx < nr_maps && socket_idx < nr_maps &&
			 idx < UPATCH_MAPS_MAX &&
			 socket_idx < UPATCH_MAPS_MAX && idx != socket_idx,
			 "two distinct maps of the upatch");
	for (i = 0; i < nr_fit; i++)
		label_valid(p, i);
}
