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
	bool				rodata_offset_in_header;
	const struct upatch_decoder_blob *decoder_blob;
	__u32				nr_decoders;
	const char			*signed_name;	/* UPATCH_NAME_MAX */
	const __u8			*signed_attach;
	__u32				signed_attach_len;
	const __u8			*signed_unload_payload;	/* 32 bytes */
	const void			*signed_policy_labels;
	__u32				signed_policy_labels_len;
	__u32				signed_policy_map_idx;
	__u32				signed_socket_policy_map_idx;
	const __u8			*signed_type;	/* __le32 */
	const __u8			*signed_jar;
	__u32				signed_jar_len;
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

/*
 * A member of a set of measured upatches, as an init record and the
 * commands that predict one list it: a name upatch_name_valid() takes and
 * the 64 hex digits of its payload's SHA-256.
 */
bool upatch_member_valid(const char *name, const char *payload_hex);

/* The name in the header, which the file need not terminate, with a NUL. */
void upatch_header_name(const struct upatch *u, char out[UPATCH_NAME_MAX + 1]);
/*
 * Whether the header's name is the one the signed sections carry: the
 * header's is what the pins, the archive and the eventlog go by.
 */
bool upatch_name_signed(const struct upatch *u);
/*
 * The name the loader program takes, zero-padded to size: at most
 * size - 1 bytes of the header's, with every byte but those
 * bpf_obj_name_cpy() takes, an alphanumeric, '_' or '.', made '_'.
 */
void upatch_prog_name(const struct upatch *u, char *out, size_t size);
const void *upatch_signed_attach(const struct upatch *u,
				 __u32 *len);
const __u8 *upatch_signed_unload_payload(const struct upatch *u);

const void *upatch_signed_policy_labels(const struct upatch *u,
					__u32 *len);
/*
 * The payload type the signed sections carry, UPATCH_TYPE_BPF where they
 * carry none. A file opens only when it equals the header's type.
 */
__u32 upatch_signed_type(const struct upatch *u);
/* The agent .jar of a Java load, NULL where there is none. */
const void *upatch_signed_jar(const struct upatch *u, __u32 *len);

/*
 * An upatch name: [A-Za-z0-9._-]+ not starting with '.', so nothing that
 * leaves the bpffs or the archive directory, and short enough for its pin
 * directory, which spells each '.' in two bytes, to fit NAME_MAX.
 */
bool upatch_name_valid(const char *name);

/* A scandir() filter for the archived .upatch files. */
int upatch_select(const struct dirent *e);

struct prog_spec {
	__u32 role;
	__u32 kind;
	__u32 device_classes;
	__u64 offset;
	char target[UPATCH_ATTACH_TARGET_MAX];
	char map[UPATCH_PROG_MAP_MAX];
	char *uprobe_path;
	__u8 build_id[UPATCH_BUILD_ID_MAX];
	__u32 build_id_len;
	__u64 *uprobe_offsets;
	__u32 nr_uprobe_offsets;
	char *kprobe_sym_buf;
	size_t kprobe_sym_buf_len;
	const char **kprobe_syms;
	__u32 nr_kprobe_syms;
	int target_fd;
	struct stat target_stat;
};

static inline bool kind_is_uprobe_multi(__u32 kind)
{
	return kind == UPATCH_ATTACH_UPROBE_MULTI || kind == UPATCH_ATTACH_URETPROBE_MULTI;
}

static inline bool kind_is_uprobe_single(__u32 kind)
{
	return kind == UPATCH_ATTACH_UPROBE || kind == UPATCH_ATTACH_URETPROBE;
}

/* The kinds that attach to a userspace binary named in the UPUT block. */
static inline bool kind_has_uprobe_target(__u32 kind)
{
	return kind_is_uprobe_multi(kind) || kind_is_uprobe_single(kind);
}

static inline bool kind_is_kprobe_multi(__u32 kind)
{
	return kind == UPATCH_ATTACH_KPROBE_MULTI || kind == UPATCH_ATTACH_KRETPROBE_MULTI;
}

/*
 * Whether the size bytes at path hold a string that a policy label can
 * name files with: an absolute path of at most UPATCH_POLICY_PATH_LEN_MAX
 * bytes that does not end in '/', with '*' and '?' in its last component
 * alone.
 */
bool policy_path_valid(const char *path, size_t size);

/*
 * The last component of a path policy_path_valid() took where it is a
 * pattern for name_glob_match(), else NULL: the path then names one file.
 */
const char *policy_path_pattern(const char *path);

/*
 * Whether the len bytes at sym can be one name of a kprobe multi target:
 * 1 to UPATCH_KPROBE_SYM_MAX - 1 printable ASCII bytes, none of them a
 * space or one of the list and glob characters ",*?|".
 */
bool kprobe_sym_valid(const char *sym, size_t len);

/*
 * The attach metadata of a load upatch, parsed strictly into one spec
 * per program, target_fd -1. 0 or -errno; free with prog_specs_free().
 */
int prog_specs_parse(const void *metadata, __u32 metadata_len,
		     __u32 nr_maps, __u32 nr_progs, struct prog_spec **out);
void prog_specs_free(struct prog_spec *specs, __u32 nr_progs);
/* Every device class an XDP program among the specs selects. */
__u32 prog_specs_xdp_classes(const struct prog_spec *specs, __u32 nr_progs);

/*
 * The target's upatch lifecycle, which builtin-upatch.c implements for
 * init, bpm and keys: boot restore, install, unload.
 */
int upatch_restore(const char *path);
int upatch_install(const char *path);
int upatch_remove(const char *path);
int upatch_remove_fd(const char *path, int fd);

/* A missing optional kprobe module permits tree projection advancement. */
#define UPATCH_INSTALL_TARGET_MISSING	2

struct cert;

/*
 * Detach, unpin and unarchive without a directive, because the key
 * that signed the upatch was revoked: 1 when the unload was measured,
 * 0 when only the archive went, UPATCH_PURGE_OTHER_SIGNER when the archive
 * stays because another key signed it, UPATCH_PURGE_NO_ARCHIVE when the
 * name has none, UPATCH_PURGE_NO_SIGNER when it stays because no signer
 * can be read from it and nothing runs under its name, -errno on
 * failure. An -ENOENT is a failure like any other: the register lock or
 * a pin was not there.
 */
#define UPATCH_PURGE_OTHER_SIGNER	2
#define UPATCH_PURGE_NO_ARCHIVE		3
#define UPATCH_PURGE_NO_SIGNER		4
int upatch_purge(const char *name, const struct cert *signer,
		 const char *reason);

/*
 * Whether upatch_purge() could tell who signed the archive of name: 0,
 * UPATCH_PURGE_NO_ARCHIVE without an archive, -errno for one that does
 * not parse, is filed under another name than it signs or has no
 * signer, and when the register lock cannot be taken.
 */
int upatch_purge_check(const char *name);

#endif /* SHIRUDO_UTIL_UPATCH_H */
