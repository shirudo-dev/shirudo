// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The DECODERS section of a .upatch, for sections of every length that
 * declare up to NR_MAX decoders, or any count at all where the section
 * has no room for NR_MAX + 1 entries: util/upatch.c reads only the
 * entries the section holds, and every decoder it views has terminated
 * names and a source inside the section, behind the entries.
 */

#include "proof.h"
#include "../../../util/upatch.c"

#define NR_MAX	2

static bool terminated(const char *s, size_t size)
{
	return memchr(s, '\0', size);
}

static void viewed(const struct upatch *u, __u32 idx)
{
	const __u8 *entries_end, *end, *source;
	struct upatch_decoder_view d;

	entries_end = u->map + sizeof(struct upatch_decoder_blob) +
		      u->nr_decoders * sizeof(struct upatch_decoder_entry);
	end = u->map + u->map_size;
	__CPROVER_assert(!upatch_decoder_view(u, idx, &d), "viewed");
	source = (const __u8 *)d.source;
	__CPROVER_assert(d.source_len && source >= entries_end &&
			 source <= end &&
			 d.source_len <= (size_t)(end - source),
			 "a source inside the section, behind the entries");
	__CPROVER_assert(terminated(d.upatch, sizeof(d.upatch)) &&
			 terminated(d.map, sizeof(d.map)) &&
			 terminated(d.source_name, sizeof(d.source_name)) &&
			 terminated(d.entrypoint, sizeof(d.entrypoint)),
			 "terminated names");
	__CPROVER_assert(d.language && d.api_version && d.input_format &&
			 d.export_signal, "a language, API, input and signal");
}

void harness(void)
{
	struct upatch_decoder_view d;
	struct upatch u = {};
	__u32 len, i;
	__u8 *bp;

	bp = any_bytes(len);
	__CPROVER_assume(len < 12 || get_le32(bp + 8) <= NR_MAX ||
			 len < sizeof(struct upatch_decoder_blob) +
			       (NR_MAX + 1) * sizeof(struct upatch_decoder_entry));
	u.map = bp;
	u.map_size = len;
	if (!parse_decoders(&u, bp, len)) {
		__CPROVER_assert(!u.decoder_blob && !u.nr_decoders,
				 "nothing kept of a refused section");
		__CPROVER_assert(upatch_decoder_view(&u, 0, &d) == -ENOENT &&
				 !d.source, "no decoder to view");
		return;
	}
	__CPROVER_assert((const __u8 *)u.decoder_blob == bp &&
			 u.nr_decoders == get_le32(bp + 8) && u.nr_decoders,
			 "the whole section and its count");
	for (i = 0; i < NR_MAX; i++)
		if (i < u.nr_decoders)
			viewed(&u, i);
	__CPROVER_assert(upatch_decoder_view(&u, u.nr_decoders, &d) ==
			 -ENOENT && !d.source, "none past the last");
}
