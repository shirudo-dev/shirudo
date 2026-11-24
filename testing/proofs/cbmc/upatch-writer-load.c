// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The four signed sections of a load, as compose_signed_data() lays them
 * behind loader data of LEN bytes: the name, attach metadata that ends off
 * a boundary, and any bytes for one decoder and one policy label. The data
 * has the length the format gives, and the reader keeps the sections, each
 * where it was written, exactly when it takes those decoders and labels.
 */

#define LOAD_SECTIONS
#include "upatch-writer-sections.c"

#define ATTACH_LEN	3
#define DECODERS_LEN	(sizeof(struct upatch_decoder_blob) + \
			 sizeof(struct upatch_decoder_entry) + 1)
#define LABELS_LEN	(sizeof(struct upatch_policy_label_header) + \
			 sizeof(struct upatch_policy_label_entry))
#define ALIGNED(len)	(((len) + 7) & ~7u)
#define NAME_OFF	ALIGNED(LEN)
#define ATTACH_OFF	(NAME_OFF + UPATCH_NAME_MAX)
#define DECODERS_OFF	ALIGNED(ATTACH_OFF + ATTACH_LEN)
#define LABELS_OFF	ALIGNED(DECODERS_OFF + DECODERS_LEN)
#define DIR_OFF		ALIGNED(LABELS_OFF + LABELS_LEN)
#define DATA_LEN	(DIR_OFF + 4 * sizeof(struct upatch_signed_section) + \
			 sizeof(struct upatch_signed_trailer))

static bool written(const struct upatch *u, const void *got, __u32 off,
		    const void *p, __u32 len)
{
	return got == u->map + off && read_back(u, got, p, len);
}

void harness(void)
{
	__u32 nr_maps, map_idx, socket_map_idx, len = 0xdeadbeef, k;
	const __u8 *decoders = any_bytes(DECODERS_LEN);
	const __u8 *labels = any_bytes(LABELS_LEN);
	const __u8 *attach = any_bytes(ATTACH_LEN);
	const __u8 *data = any_bytes(LEN);
	struct upatch u = {}, alone = {};
	void *out = (void *)1;
	bool taken;

	/* finalize_object() signs a name its strscpy() fit into 256 bytes. */
	name = any_bytes(UPATCH_NAME_MAX);
	__CPROVER_assume(k < UPATCH_NAME_MAX && !name[k]);
	u.hdr.nr_maps = nr_maps;
	taken = parse_decoders(&alone, decoders, DECODERS_LEN) &&
		parse_policy_labels(labels, LABELS_LEN, nr_maps, &map_idx,
				    &socket_map_idx);
	add_section(UPATCH_SECTION_NAME, name, UPATCH_NAME_MAX);
	add_section(UPATCH_SECTION_ATTACH, attach, ATTACH_LEN);
	add_section(UPATCH_SECTION_DECODERS, decoders, DECODERS_LEN);
	add_section(UPATCH_SECTION_POLICY_LABELS, labels, LABELS_LEN);
	__CPROVER_assert(!compose_signed_data(data, LEN, sections, nr_sections,
					      &out, &len) && len == DATA_LEN,
			 "data of the length the format gives");
	u.map = out;
	u.map_size = len;
	u.hdr.data_len = len;
	parse_signed_sections(&u);
	__CPROVER_assert(!!u.signed_name == taken,
			 "kept exactly with decoders and labels the reader takes");
	if (!taken)
		return;
	__CPROVER_assert(written(&u, u.signed_name, NAME_OFF, name,
				 UPATCH_NAME_MAX) &&
			 written(&u, u.signed_attach, ATTACH_OFF, attach,
				 ATTACH_LEN) &&
			 u.signed_attach_len == ATTACH_LEN,
			 "the name and the attach metadata");
	__CPROVER_assert(written(&u, u.decoder_blob, DECODERS_OFF, decoders,
				 DECODERS_LEN) &&
			 u.nr_decoders == alone.nr_decoders,
			 "the decoders behind the padding");
	__CPROVER_assert(written(&u, u.signed_policy_labels, LABELS_OFF,
				 labels, LABELS_LEN) &&
			 u.signed_policy_labels_len == LABELS_LEN &&
			 u.signed_policy_map_idx == map_idx &&
			 u.signed_socket_policy_map_idx == socket_map_idx,
			 "the policy labels and the maps they name");
	__CPROVER_assert(!u.signed_unload_payload, "no unload digest");
}
