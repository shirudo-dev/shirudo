/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * On-disk .upatch container layout. Little-endian throughout.
 */

#ifndef SHIRUDO_UPATCH_H
#define SHIRUDO_UPATCH_H

#include <string.h>

#include <shirudo/byteorder.h>
#include <shirudo/misc.h>

#define UPATCH_MAGIC		0x53485244554e4150ULL	/* "SHRDUNAP" */
/*
 * The PKCS#7 signature covers insns || data (the gen_loader metadata
 * blob), verified by the kernel at load time; payload_sha256 is SHA-256
 * of that same concatenation. See the kernel's Documentation/bpf/signing.rst
 * and Documentation/reference/formats/upatch-format.rst in this tree.
 */
#define UPATCH_VERSION		1u
#define UPATCH_HEADER_SIZE	360u

#define DIRECTIVE_UNLOAD	(1u << 0)

enum upatch_type {
	UPATCH_TYPE_BPF = 1,
};

#define UPATCH_NAME_MAX		256
#define UPATCH_BPFFS_NAME_MAX	(2 * UPATCH_NAME_MAX)
#define UPATCH_PAYLOAD_HASH_LEN	32	/* SHA-256 */

struct upatch_header {
	__le64		magic;			/* UPATCH_MAGIC */
	__le32		version;		/* UPATCH_VERSION */
	__le32		flags;			/* DIRECTIVE_* */
	char		name[UPATCH_NAME_MAX];
	/*
	 * SHA-256 of the signed content, insns || data. Distinct from the
	 * loader's excl_prog_hash (SHA-256 of insns alone), which the target
	 * recomputes at load. This is the value recorded as the pin xattr,
	 * the TPM register event, and the unload match target.
	 */
	__u8		payload_sha256[UPATCH_PAYLOAD_HASH_LEN];
	__le32		loader_insns_off;	/* file offset */
	__le32		loader_insns_len;
	__le32		signature_off;
	__le32		signature_len;
	__le32		metadata_off;
	__le32		metadata_len;
	__le32		data_off;		/* gen_loader_opts.data */
	__le32		data_len;
	__le32		log_buf_sz;		/* verifier-log buf size */
	__le32		nr_maps;		/* loader ctx bpf_map_desc count */
	__le32		nr_progs;		/* loader ctx bpf_prog_desc count */
	__le32		rodata_data_off;	/* offset in gen_loader_opts.data */
	__le32		type;			/* enum upatch_type */
	__le32		reserved1;		/* zero; keeps the header 8-byte aligned */
};

BUILD_BUG_ON(sizeof(struct upatch_header) != UPATCH_HEADER_SIZE);

/*
 * The signed sections: what the target needs beyond the loader and its
 * data, appended to the data section before signing so the kernel's
 * signature check covers them, and located through a trailer in the
 * data's last 16 bytes. The loader ignores the bytes behind its own.
 * A LOAD carries its name and its attach metadata, an UNLOAD directive
 * the name of its target and the payload digest it expects, and a LOAD
 * carries decoders when its programs declare any.
 */
#define UPATCH_SIGNED_TRAILER_MAGIC	0x52544753u	/* "SGTR" le */
#define UPATCH_SIGNED_VERSION		1u
#define UPATCH_SIGNED_SECTIONS_MAX	8u

enum upatch_section_tag {
	UPATCH_SECTION_NAME	= 0x454d414eu,	/* "NAME" le */
	UPATCH_SECTION_ATTACH	= 0x4d475055u,	/* "UPGM" le */
	UPATCH_SECTION_UNLOAD	= 0x444c4e55u,	/* "UNLD" le */
	UPATCH_SECTION_DECODERS	= 0x42444344u,	/* "DCDB" le */
	UPATCH_SECTION_POLICY_LABELS	= 0x4c504853u,	/* "SHPL" le */
};

#define UPATCH_POLICY_LABELS_MAGIC	0x4c504853u	/* "SHPL" le */
#define UPATCH_POLICY_LABELS_VERSION	1u
#define UPATCH_MAPS_MAX			64u
#define UPATCH_POLICY_NAME_MAX		64u
#define UPATCH_POLICY_PATH_MAX		4096u

struct upatch_policy_label_header {
	__le32	magic;
	__le32	version;
	__le32	count;
	__le32	policy_map_idx;
	__le32	socket_policy_map_idx;
};

struct upatch_policy_label_entry {
	__le64	bit;
	char	policy[UPATCH_POLICY_NAME_MAX];
	char	path[UPATCH_POLICY_PATH_MAX];
};

BUILD_BUG_ON(sizeof(struct upatch_policy_label_header) != 20);
BUILD_BUG_ON(sizeof(struct upatch_policy_label_entry) != 4168);

struct upatch_signed_section {
	__le32		tag;		/* enum upatch_section_tag */
	__le32		reserved;	/* zero */
	__le32		off;		/* from the start of data */
	__le32		len;
};

struct upatch_signed_trailer {
	__le32		magic;		/* UPATCH_SIGNED_TRAILER_MAGIC */
	__le32		version;	/* UPATCH_SIGNED_VERSION */
	__le32		dir_off;	/* the section directory, from the start of data */
	__le32		nr_sections;
};

/*
 * Decoders embedded inside the signature-covered data section. BPF
 * programs declare a struct decoder_manifest in .rodata; shirudo-build
 * resolves and embeds the decoder source before signing.
 */
#define DECODER_MANIFEST_MAGIC	0x44434544u	/* "DECD" le */
#define UPATCH_DECODER_MAGIC	0x42444344u	/* "DCDB" le */
#define UPATCH_DECODER_VERSION	1u
#define UPATCH_DECODER_LANG_LUA	1u
#define UPATCH_DECODER_INPUT_MAP_V1	1u

enum upatch_decoder_export_signal {
	UPATCH_DECODER_EXPORT_LOG = 1,
	UPATCH_DECODER_EXPORT_METRIC = 2,
};

struct decoder_manifest {
	__le32		magic;
	__le16		version;
	__le16		language;
	__le16		api_version;
	__le16		input_format; /* UPATCH_DECODER_INPUT_MAP_V1 */
	__le16		export_signal;
	__le16		reserved;
	char	upatch[64];
	char	map[16];
	char	source[64];
	char	entrypoint[32];
};

struct upatch_decoder_entry {
	__le32		language;
	__le32		api_version;
	__le32		input_format;
	__le32		export_signal;
	char	upatch[64];
	char	map[16];
	char	source[64];
	char	entrypoint[32];
	__le32		source_off;
	__le32		source_len;
};

struct upatch_decoder_blob {
	__le32		magic;
	__le32		version;
	__le32		nr_decoders;
	__le32		reserved;
	struct upatch_decoder_entry decoders[];
};

/*
 * The attach metadata of a LOAD upatch, its ATTACH section: how the
 * target attaches each program after the signed loader has created it.
 * Programs without a special attach kind use RAW_TRACEPOINT, preserving
 * the original attach_btf_id behavior. The program bytes are hash-locked
 * by the signed loader; the site a kprobe, uprobe, cgroup or netfilter
 * program attaches at comes from here, which is why it is signed.
 */
#define UPATCH_ATTACH_TARGET_MAX	128u
#define UPATCH_PROG_MAGIC	0x4d475055u	/* "UPGM" le */
#define UPATCH_PROG_VERSION	1u
#define UPATCH_PROG_MAP_MAX	16u		/* BPF_OBJ_NAME_LEN */
#define UPATCH_UPROBE_TARGET_MAGIC	0x54555055u /* "UPUT" le */
#define UPATCH_UPROBE_TARGET_VERSION	1u
#define UPATCH_UPROBE_PATH_MAX	4096u
#define UPATCH_BUILD_ID_MAX	64u
#define UPATCH_UPROBE_OFFSETS_MAX	(1u << 20)
#define UPATCH_BPF_TARGET_MAGIC	0x54425055u	/* "UPBT" le */
#define UPATCH_BPF_TARGET_VERSION	1u

enum upatch_attach_kind {
	UPATCH_ATTACH_RAW_TRACEPOINT = 0,
	UPATCH_ATTACH_KPROBE = 1,
	UPATCH_ATTACH_KRETPROBE = 2,
	UPATCH_ATTACH_CGROUP_SKB_INGRESS = 3,
	UPATCH_ATTACH_CGROUP_SKB_EGRESS = 4,
	UPATCH_ATTACH_FMOD_RET = 5,
	UPATCH_ATTACH_NETFILTER_IPV6_PRE_ROUTING = 6,
	UPATCH_ATTACH_UPROBE_MULTI = 7,
	/* fentry, fexit or freplace on a program of another upatch */
	UPATCH_ATTACH_BPF_PROG = 8,
};

enum upatch_prog_role {
	UPATCH_PROG_ROLE_ATTACH = 0,
	UPATCH_PROG_ROLE_SERIALIZER = 1,
	UPATCH_PROG_ROLE_TEST_RUN = 2,
};

struct upatch_prog_entry {
	__le32		role;		/* enum upatch_prog_role */
	__le32		kind;		/* enum upatch_attach_kind */
	__le64		offset;		/* kprobe offset; zero for kretprobe */
	char		target[UPATCH_ATTACH_TARGET_MAX]; /* kprobe symbol */
	char		map[UPATCH_PROG_MAP_MAX];
};

struct upatch_prog_metadata {
	__le32		magic;		/* UPATCH_PROG_MAGIC */
	__le32		version;		/* UPATCH_PROG_VERSION */
	__le32		nr_progs;
	__le32		nr_maps;
	/*
	 * Then: nr_progs struct upatch_prog_entry entries in
	 * libbpf/gen_loader program iteration order.
	 */
	struct upatch_prog_entry progs[];
};

/*
 * UPGM v1 optionally appends one UPUT block after the fixed program
 * entries. It is required when any program has UPROBE_MULTI attach kind
 * and absent otherwise. Each variable-length record is followed by
 * path_len path bytes (without NUL), build_id_len build-ID bytes, and
 * nr_offsets little-endian __u64 file offsets. Records have no padding.
 */
struct upatch_uprobe_targets {
	__le32		magic;		/* UPATCH_UPROBE_TARGET_MAGIC */
	__le32		version;	/* UPATCH_UPROBE_TARGET_VERSION */
	__le32		nr_targets;
	__le32		reserved;
};

struct upatch_uprobe_target {
	__le32		prog_idx;
	__le32		path_len;
	__le32		build_id_len;
	__le32		nr_offsets;
};

/*
 * UPGM v1 optionally appends one UPBT block, after the UPUT block if any.
 * It is required when any program has BPF_PROG attach kind and absent
 * otherwise. The target is program target_prog_idx of the upatch with the
 * name and the payload_sha256 below: the signed loader opens that program's
 * pin and uses the BTF ID of the function in the entry's target, found in
 * that upatch's BTF at build time, so it fits no other build.
 */
struct upatch_bpf_targets {
	__le32		magic;		/* UPATCH_BPF_TARGET_MAGIC */
	__le32		version;	/* UPATCH_BPF_TARGET_VERSION */
	__le32		nr_targets;
	__le32		reserved;
};

struct upatch_bpf_target {
	__le32		prog_idx;
	__le32		target_prog_idx;
	__u8		payload_sha256[UPATCH_PAYLOAD_HASH_LEN];
	char		upatch[UPATCH_NAME_MAX];
};


#endif /* SHIRUDO_UPATCH_H */
