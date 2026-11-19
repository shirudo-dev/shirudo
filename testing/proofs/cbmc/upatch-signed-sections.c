// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The signed sections of a .upatch, read from its data before any
 * signature is checked, for data of LEN bytes, each length proofs.list
 * names, with one section where it can hold a name: util/upatch.c keeps
 * sections only behind a valid trailer, each inside the data and below the
 * directory, the name terminated, and no length or count without them.
 */

#define PROOF_MEMCHR_QUANTIFIED
#include "proof.h"
#include "../../../util/upatch.c"

#define NAMED_LEN	(UPATCH_NAME_MAX + \
			 sizeof(struct upatch_signed_section) + \
			 sizeof(struct upatch_signed_trailer))

static bool below(const struct upatch *u, const void *p, size_t len,
		  __u32 dir_off)
{
	const __u8 *b = p;

	return b >= u->map && b <= u->map + dir_off &&
	       len <= (size_t)(u->map + dir_off - b);
}

static bool kept_any(const struct upatch *u)
{
	return u->signed_name || u->signed_attach ||
	       u->signed_unload_payload || u->signed_policy_labels ||
	       u->decoder_blob || u->signed_type || u->signed_jar;
}

static void forgotten(const struct upatch *u)
{
	__CPROVER_assert(!u->signed_attach_len &&
			 !u->signed_policy_labels_len &&
			 !u->decoder_blob_len && !u->nr_decoders &&
			 !u->signed_policy_map_idx &&
			 !u->signed_socket_policy_map_idx &&
			 !u->signed_jar_len,
			 "no length, count or map without a section");
}

void harness(void)
{
	const struct upatch_signed_trailer *tr;
	const size_t len = LEN;
	struct upatch u = {};
	__u32 dir_off, nr;

	u.map = any_bytes(len);
	tr = len < sizeof(*tr) ? NULL :
	     (const void *)(u.map + len - sizeof(*tr));
	if (len >= NAMED_LEN)
		__CPROVER_assume(get_le32(&tr->nr_sections) <= 1);
	u.map_size = len;
	u.hdr.data_len = len;
	/*
	 * No length here holds a policy labels section, which
	 * upatch-policy-labels.c proves; without maps, CBMC sees that the
	 * section is refused before its labels are read.
	 */
	u.hdr.nr_maps = 0;
	parse_signed_sections(&u);
	if (!kept_any(&u)) {
		forgotten(&u);
		return;
	}
	dir_off = get_le32(&tr->dir_off);
	nr = get_le32(&tr->nr_sections);
	__CPROVER_assert(get_le32(&tr->magic) == UPATCH_SIGNED_TRAILER_MAGIC &&
			 get_le32(&tr->version) == UPATCH_SIGNED_VERSION &&
			 nr && nr <= UPATCH_SIGNED_SECTIONS_MAX,
			 "a valid trailer");
	__CPROVER_assert((__u64)dir_off + nr *
			 sizeof(struct upatch_signed_section) <=
			 len - sizeof(*tr), "the directory below the trailer");
	__CPROVER_assert(!u.signed_name ||
			 (below(&u, u.signed_name, UPATCH_NAME_MAX, dir_off) &&
			  memchr(u.signed_name, '\0', UPATCH_NAME_MAX)),
			 "a terminated name below the directory");
	__CPROVER_assert(!u.signed_attach ||
			 (u.signed_attach_len &&
			  below(&u, u.signed_attach, u.signed_attach_len,
				dir_off)),
			 "attach metadata below the directory");
	__CPROVER_assert(!u.signed_unload_payload ||
			 below(&u, u.signed_unload_payload,
			       UPATCH_PAYLOAD_HASH_LEN, dir_off),
			 "an unload digest below the directory");
	__CPROVER_assert(!u.signed_type ||
			 below(&u, u.signed_type, sizeof(__le32), dir_off),
			 "a payload type below the directory");
	__CPROVER_assert(!u.signed_jar ||
			 (u.signed_jar_len &&
			  below(&u, u.signed_jar, u.signed_jar_len, dir_off)),
			 "a jar below the directory");
	__CPROVER_assert(!u.signed_policy_labels, "no policy labels");
	__CPROVER_assert(!u.decoder_blob ||
			 (u.nr_decoders &&
			  below(&u, u.decoder_blob, u.decoder_blob_len,
				dir_off)),
			 "decoders below the directory");
}
