/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * On-disk .upatch container layout. Little-endian throughout.
 */

#ifndef SHIRUDO_UPATCH_H
#define SHIRUDO_UPATCH_H

#include <endian.h>
#include <string.h>

#include <shirudo/misc.h>

#define SHIRUDO_UPATCH_MAGIC		0x53485244554e4150ULL	/* "SHRDUNAP" */
/*
 * The PKCS#7 signature covers insns || data (the gen_loader metadata
 * blob), verified by the kernel at load time; payload_sha256 is SHA-256
 * of that same concatenation. See the kernel's Documentation/bpf/signing.rst
 * and Documentation/upatch-spec.rst in this tree.
 */
#define SHIRUDO_UPATCH_VERSION		1u
#define SHIRUDO_UPATCH_HEADER_SIZE	360u

#define SHIRUDO_DIRECTIVE_UNLOAD	(1u << 0)

enum shirudo_upatch_type {
	SHIRUDO_UPATCH_TYPE_BPF = 1,
};

#define SHIRUDO_UPATCH_NAME_MAX		256
/*
 * The longest name a target takes: files named after it get suffixes up
 * to ".unload.upatch.tmp", and each must stay within NAME_MAX.
 */
#define SHIRUDO_UPATCH_NAME_LEN_MAX	224
#define SHIRUDO_UPATCH_BPFFS_NAME_MAX	(2 * SHIRUDO_UPATCH_NAME_MAX)
#define SHIRUDO_UPATCH_PAYLOAD_HASH_LEN	32	/* SHA-256 */

struct shirudo_upatch_header {
	__u64		magic;			/* SHIRUDO_UPATCH_MAGIC */
	__u32		version;		/* SHIRUDO_UPATCH_VERSION */
	__u32		flags;			/* SHIRUDO_DIRECTIVE_* */
	char		name[SHIRUDO_UPATCH_NAME_MAX];
	/*
	 * SHA-256 of the signed content, insns || data. Distinct from the
	 * loader's excl_prog_hash (SHA-256 of insns alone), which the target
	 * recomputes at load. This is the value recorded as the pin xattr,
	 * the TPM register event, and the unload match target.
	 */
	__u8		payload_sha256[SHIRUDO_UPATCH_PAYLOAD_HASH_LEN];
	__u32		loader_insns_off;	/* file offset */
	__u32		loader_insns_len;
	__u32		signature_off;
	__u32		signature_len;
	__u32		metadata_off;
	__u32		metadata_len;
	__u32		data_off;		/* gen_loader_opts.data */
	__u32		data_len;
	__u32		log_buf_sz;		/* verifier-log buf size */
	__u32		nr_maps;		/* loader ctx bpf_map_desc count */
	__u32		nr_progs;		/* loader ctx bpf_prog_desc count */
	__u32		reserved0;		/* zero */
	__u32		type;			/* enum shirudo_upatch_type */
	__u32		reserved1;		/* zero; keeps the v1 header 8-byte aligned */
};

_Static_assert(sizeof(struct shirudo_upatch_header) ==
	       SHIRUDO_UPATCH_HEADER_SIZE, "unexpected upatch header padding");

/*
 * Optional decoder metadata embedded inside the signature-covered data
 * section. BPF programs declare a shirudo_decoder_manifest in .rodata;
 * shirudo-build resolves and embeds the decoder source before signing.
 */
#define SHIRUDO_DECODER_MANIFEST_MAGIC	0x44434544u	/* "DECD" le */
#define SHIRUDO_UPATCH_DECODER_MAGIC	0x42444344u	/* "DCDB" le */
#define SHIRUDO_UPATCH_DECODER_TRAILER_MAGIC 0x52544344u /* "DCTR" le */
#define SHIRUDO_UPATCH_DECODER_VERSION	1u
#define SHIRUDO_UPATCH_DECODER_LANG_LUA	1u
#define SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1	1u

enum shirudo_upatch_decoder_export_signal {
	SHIRUDO_UPATCH_DECODER_EXPORT_LOG = 1,
	SHIRUDO_UPATCH_DECODER_EXPORT_METRIC = 2,
};

struct shirudo_decoder_manifest {
	__u32		magic;
	__u16		version;
	__u16		language;
	__u16		api_version;
	__u16		input_format; /* SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1 */
	__u16		export_signal;
	__u16		reserved;
	char	upatch[64];
	char	map[16];
	char	source[64];
	char	entrypoint[32];
};

struct shirudo_upatch_decoder_entry {
	__u32		language;
	__u32		api_version;
	__u32		input_format;
	__u32		export_signal;
	char	upatch[64];
	char	map[16];
	char	source[64];
	char	entrypoint[32];
	__u32		source_off;
	__u32		source_len;
};

struct shirudo_upatch_decoder_blob {
	__u32		magic;
	__u32		version;
	__u32		nr_decoders;
	__u32		reserved;
	struct shirudo_upatch_decoder_entry decoders[];
};

struct shirudo_upatch_decoder_trailer {
	__u32		magic;
	__u32		version;
	__u32		decoder_off;
	__u32		decoder_len;
};

/*
 * Optional metadata format for LOAD upatches. This tells the target how
 * each program should be attached after the signed loader has created it.
 * Programs without a special attach kind use RAW_TRACEPOINT, preserving
 * the original attach_btf_id behavior.
 *
 * Metadata is not signature-covered in the v1 container format. The program
 * bytes are still hash-locked by the signed loader; this blob is attach
 * policy for the target to validate before creating links.
 */
#define SHIRUDO_UPATCH_ATTACH_TARGET_MAX	128u
#define SHIRUDO_UPATCH_PROG_MAGIC	0x4d475055u	/* "UPGM" le */
#define SHIRUDO_UPATCH_PROG_VERSION	1u
#define SHIRUDO_UPATCH_PROG_MAP_MAX	16u		/* BPF_OBJ_NAME_LEN */
#define SHIRUDO_UPATCH_UPROBE_TARGET_MAGIC	0x54555055u /* "UPUT" le */
#define SHIRUDO_UPATCH_UPROBE_TARGET_VERSION	1u
#define SHIRUDO_UPATCH_UPROBE_PATH_MAX	4096u
#define SHIRUDO_UPATCH_BUILD_ID_MAX	64u
#define SHIRUDO_UPATCH_UPROBE_OFFSETS_MAX	(1u << 20)

enum shirudo_upatch_attach_kind {
	SHIRUDO_UPATCH_ATTACH_RAW_TRACEPOINT = 0,
	SHIRUDO_UPATCH_ATTACH_KPROBE = 1,
	SHIRUDO_UPATCH_ATTACH_KRETPROBE = 2,
	SHIRUDO_UPATCH_ATTACH_CGROUP_SKB_INGRESS = 3,
	SHIRUDO_UPATCH_ATTACH_CGROUP_SKB_EGRESS = 4,
	SHIRUDO_UPATCH_ATTACH_FMOD_RET = 5,
	SHIRUDO_UPATCH_ATTACH_NETFILTER_IPV6_PRE_ROUTING = 6,
	SHIRUDO_UPATCH_ATTACH_UPROBE_MULTI = 7,
};

enum shirudo_upatch_prog_role {
	SHIRUDO_UPATCH_PROG_ROLE_ATTACH = 0,
	SHIRUDO_UPATCH_PROG_ROLE_SERIALIZER = 1,
	SHIRUDO_UPATCH_PROG_ROLE_TEST_RUN = 2,
};

struct shirudo_upatch_prog_entry {
	__u32		role;		/* enum shirudo_upatch_prog_role */
	__u32		kind;		/* enum shirudo_upatch_attach_kind */
	__u64		offset;		/* kprobe offset; zero for kretprobe */
	char		target[SHIRUDO_UPATCH_ATTACH_TARGET_MAX]; /* kprobe symbol */
	char		map[SHIRUDO_UPATCH_PROG_MAP_MAX];
};

struct shirudo_upatch_prog_metadata {
	__u32		magic;		/* SHIRUDO_UPATCH_PROG_MAGIC */
	__u32		version;		/* SHIRUDO_UPATCH_PROG_VERSION */
	__u32		nr_progs;
	__u32		reserved;
	/*
	 * Then: nr_progs struct shirudo_upatch_prog_entry entries in
	 * libbpf/gen_loader program iteration order.
	 */
	struct shirudo_upatch_prog_entry progs[];
};

/*
 * UPGM v1 optionally appends one UPUT block after the fixed program
 * entries. It is required when any program has UPROBE_MULTI attach kind
 * and absent otherwise. Each variable-length record is followed by
 * path_len path bytes (without NUL), build_id_len build-ID bytes, and
 * nr_offsets little-endian __u64 file offsets. Records have no padding.
 */
struct shirudo_upatch_uprobe_targets {
	__u32		magic;		/* SHIRUDO_UPATCH_UPROBE_TARGET_MAGIC */
	__u32		version;	/* SHIRUDO_UPATCH_UPROBE_TARGET_VERSION */
	__u32		nr_targets;
	__u32		reserved;
};

struct shirudo_upatch_uprobe_target {
	__u32		prog_idx;
	__u32		path_len;
	__u32		build_id_len;
	__u32		nr_offsets;
};

static inline __u16 rd_le16(const void *p)
{
	__u16 v;

	memcpy(&v, p, sizeof(v));
	return le16toh(v);
}

static inline __u32 rd_le32(const void *p)
{
	__u32 v;

	memcpy(&v, p, sizeof(v));
	return le32toh(v);
}

static inline __u64 rd_le64(const void *p)
{
	__u64 v;

	memcpy(&v, p, sizeof(v));
	return le64toh(v);
}

#endif /* SHIRUDO_UPATCH_H */
