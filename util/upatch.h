/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * .upatch container parser. On-disk layout in <shirudo/upatch.h>.
 */

#ifndef SHIRUDO_UTIL_UPATCH_H
#define SHIRUDO_UTIL_UPATCH_H

#include <shirudo/misc.h>
#include <shirudo/upatch.h>
#include <dirent.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>

/* The largest container the parser accepts. */
#define UPATCH_FILE_MAX		(16u * 1024u * 1024u)

/* struct upatch_header as parse_header() reads it, in host order. */
struct upatch_host_header {
	__u64		magic;
	__u32		version;
	__u32		flags;
	char		name[UPATCH_NAME_MAX];
	__u8		payload_sha256[UPATCH_PAYLOAD_HASH_LEN];
	__u32		loader_insns_off;
	__u32		loader_insns_len;
	__u32		signature_off;
	__u32		signature_len;
	__u32		metadata_off;
	__u32		metadata_len;
	__u32		data_off;
	__u32		data_len;
	__u32		log_buf_sz;
	__u32		nr_maps;
	__u32		nr_progs;
	__u32		rodata_data_off;
	__u32		type;
	__u32		reserved1;
};

struct upatch {
	struct upatch_host_header	hdr;
	const __u8			*map;
	size_t				map_size;
	bool				owned;
	bool				rodata_offset_valid;
	const struct upatch_decoder_blob *decoder_blob;
	__u32				decoder_blob_len;
	__u32				nr_decoders;
	const char			*signed_name;	/* UPATCH_NAME_MAX */
	const __u8			*signed_attach;
	__u32				signed_attach_len;
	const __u8			*signed_unload_payload;	/* 32 bytes */
	const void			*signed_policy_labels;
	__u32				signed_policy_labels_len;
	__u32				signed_policy_map_idx;
	__u32				signed_socket_policy_map_idx;
};

struct upatch_decoder_view {
	__u32		language;
	__u32		api_version;
	__u32		input_format;
	__u32		export_signal;
	char		upatch[64];
	char		map[16];
	char		source_name[64];
	char		entrypoint[32];
	const char	*source;
	__u32		source_len;
};

/*
 * Returns 0 on success, -errno on failure. Logs nothing -- caller
 * decides whether to emit user-facing diagnostics.
 */
int  upatch_open(const char *path, struct upatch *out);
int  upatch_open_fd(int fd, struct upatch *out);
int  upatch_open_memory(const void *data, size_t size,
			struct upatch *out);
void upatch_close(struct upatch *u);

/*
 * Section accessors. Pointers reference the mmap; valid only until
 * upatch_close().
 */
const void *upatch_loader(const struct upatch *u);
const void *upatch_signature(const struct upatch *u);
const void *upatch_metadata(const struct upatch *u);
const void *upatch_data(const struct upatch *u);

bool upatch_is_unload(const struct upatch *u);
const char *upatch_type_str(const struct upatch *u);

bool upatch_has_decoders(const struct upatch *u);
int upatch_decoder_view(const struct upatch *u, __u32 idx,
			struct upatch_decoder_view *out);

/*
 * The signed sections, NULL where the data carries none: the name,
 * NUL-padded to UPATCH_NAME_MAX like the header's; the attach
 * metadata of a load; the payload digest an unload directive expects.
 * A load or unload refuses what it needs and does not find; inspection
 * shows what there is.
 */
const char *upatch_signed_name(const struct upatch *u);
const void *upatch_signed_attach(const struct upatch *u,
				 __u32 *len);
const __u8 *upatch_signed_unload_payload(const struct upatch *u);

const void *upatch_signed_policy_labels(const struct upatch *u,
					__u32 *len);

/*
 * Validate an externally-provided upatch name: non-empty, doesn't
 * start with '.', and matches [A-Za-z0-9._-]+. Rejects anything that
 * could escape the bpffs / on-disk path namespace.
 */
bool upatch_name_valid(const char *name);

/* A scandir() filter for the archived .upatch files. */
int upatch_select(const struct dirent *e);

struct prog_spec {
	__u32 role;
	__u32 kind;
	__u64 offset;
	char target[UPATCH_ATTACH_TARGET_MAX];
	char map[UPATCH_PROG_MAP_MAX];
	char *uprobe_path;
	__u32 uprobe_path_len;
	__u8 build_id[UPATCH_BUILD_ID_MAX];
	__u32 build_id_len;
	__u64 *uprobe_offsets;
	__u32 nr_uprobe_offsets;
	int target_fd;
	struct stat target_stat;
	char bpf_upatch[UPATCH_NAME_MAX];
	__u8 bpf_payload[UPATCH_PAYLOAD_HASH_LEN];
	__u32 bpf_prog_idx;
	__u32 bpf_prog_id;	/* of the target, found before the load */
};

/*
 * The attach metadata of a load upatch, parsed strictly into one spec
 * per program, target_fd -1. 0 or -errno; free with prog_specs_free().
 */
int prog_specs_parse(const void *metadata, __u32 metadata_len,
		     __u32 nr_maps, __u32 nr_progs, struct prog_spec **out);
void prog_specs_free(struct prog_spec *specs, __u32 nr_progs);

/*
 * The target's upatch lifecycle, which builtin-upatch.c implements for
 * init, bpm and keys: load, install, unload.
 */
int upatch_apply(const char *path);
int upatch_install(const char *path);
int upatch_remove(const char *path);

/*
 * upatch_install() when the signed payload is valid but its
 * kprobe target is not there, because the module that has it is not
 * loaded.
 */
#define UPATCH_INSTALL_TARGET_MISSING	2

/*
 * Detach, unpin and unarchive without a directive, because the key
 * that signed the upatch was revoked: 1 when the unload was measured,
 * 0 when only the archive went, -errno otherwise.
 */
int upatch_purge(const char *name, const char *reason);

#endif /* SHIRUDO_UTIL_UPATCH_H */
