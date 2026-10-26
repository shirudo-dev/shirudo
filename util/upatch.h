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
#define SHIRUDO_UPATCH_FILE_MAX		(16u * 1024u * 1024u)

struct shirudo_upatch {
	struct shirudo_upatch_header	hdr;	/* host byte order */
	const __u8			*map;
	size_t				map_size;
	bool				mapped;
	bool				rodata_offset_valid;
	const struct shirudo_upatch_decoder_blob *decoder_blob;
	__u32				decoder_blob_len;
	__u32				nr_decoders;
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
int  upatch_open(const char *path, struct shirudo_upatch *out);
int  upatch_open_memory(const void *data, size_t size,
			struct shirudo_upatch *out);
void upatch_close(struct shirudo_upatch *u);

/*
 * Section accessors. Pointers reference the mmap; valid only until
 * upatch_close().
 */
const void *upatch_loader(const struct shirudo_upatch *u);
const void *upatch_signature(const struct shirudo_upatch *u);
const void *upatch_metadata(const struct shirudo_upatch *u);
const void *upatch_data(const struct shirudo_upatch *u);

bool upatch_is_unload(const struct shirudo_upatch *u);
const char *upatch_type_str(const struct shirudo_upatch *u);

bool upatch_has_decoders(const struct shirudo_upatch *u);
int upatch_decoder_view(const struct shirudo_upatch *u, __u32 idx,
			struct upatch_decoder_view *out);

/*
 * Validate an externally-provided upatch name: non-empty, doesn't
 * start with '.', and matches [A-Za-z0-9._-]+. Rejects anything that
 * could escape the bpffs / on-disk path namespace.
 */
bool upatch_name_valid(const char *name);

/* A scandir() filter for the archived .upatch files. */
int upatch_select(const struct dirent *e);

struct shirudo_prog_spec {
	__u32 role;
	__u32 kind;
	__u64 offset;
	char target[SHIRUDO_UPATCH_ATTACH_TARGET_MAX];
	char map[SHIRUDO_UPATCH_PROG_MAP_MAX];
	char *uprobe_path;
	__u32 uprobe_path_len;
	__u8 build_id[SHIRUDO_UPATCH_BUILD_ID_MAX];
	__u32 build_id_len;
	__u64 *uprobe_offsets;
	__u32 nr_uprobe_offsets;
	int target_fd;
	struct stat target_stat;
};

/*
 * The program metadata of a load upatch, which the loader signature does
 * not cover: parsed strictly into one spec per program, target_fd -1.
 * 0 or -errno; free with prog_specs_free().
 */
int prog_specs_parse(const void *metadata, __u32 metadata_len,
		     __u32 nr_progs, struct shirudo_prog_spec **out);
void prog_specs_free(struct shirudo_prog_spec *specs, __u32 nr_progs);

#endif /* SHIRUDO_UTIL_UPATCH_H */
