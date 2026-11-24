// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * .upatch container parser.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include "hex.h"
#include "malloc.h"
#include "upatch.h"

static int parse_header(const __u8 *m, size_t n,
			struct upatch_host_header *out)
{
	const __u8 *p = m;

	if (n < UPATCH_HEADER_SIZE)
		return -EINVAL;

	out->magic = get_le64(p);
	p += 8;
	if (out->magic != UPATCH_MAGIC)
		return -EINVAL;

	out->version = get_le32(p);
	p += 4;
	if (out->version != UPATCH_VERSION)
		return -EINVAL;

	out->flags = get_le32(p);
	p += 4;

	memcpy(out->name, p, sizeof(out->name));
	if (!memchr(out->name, '\0', sizeof(out->name)))
		return -EINVAL;
	p += sizeof(out->name);

	memcpy(out->payload_sha256, p, sizeof(out->payload_sha256));
	p += sizeof(out->payload_sha256);

	out->loader_insns_off	= get_le32(p);
	p += 4;
	out->loader_insns_len	= get_le32(p);
	p += 4;
	out->signature_off	= get_le32(p);
	p += 4;
	out->signature_len	= get_le32(p);
	p += 4;
	out->metadata_off	= get_le32(p);
	p += 4;
	out->metadata_len	= get_le32(p);
	p += 4;
	out->data_off		= get_le32(p);
	p += 4;
	out->data_len		= get_le32(p);
	p += 4;
	out->log_buf_sz		= get_le32(p);
	p += 4;
	out->nr_maps		= get_le32(p);
	p += 4;
	out->nr_progs		= get_le32(p);
	p += 4;
	out->rodata_data_off	= get_le32(p);
	p += 4;
	out->type		= get_le32(p);
	p += 4;
	out->reserved1		= get_le32(p);
	if (out->reserved1 != 0)
		return -EINVAL;
	return 0;
}

static int section_inside(__u32 off, __u32 len, size_t n)
{
	size_t end;

	if (check_add_overflow(off, len, &end) || end > n)
		return 0;
	if (len != 0 && off < UPATCH_HEADER_SIZE)
		return 0;
	return 1;
}

static int validate_bpf_bounds(const struct upatch_host_header *h,
			       size_t n)
{
	if (h->loader_insns_off < UPATCH_HEADER_SIZE ||
	    h->loader_insns_off % 8 || h->loader_insns_len % 8 ||
	    !section_inside(h->loader_insns_off, h->loader_insns_len, n))
		return -EINVAL;
	if (h->rodata_data_off > h->data_len || h->loader_insns_len == 0)
		return -EINVAL;
	return 0;
}

/* A Java payload is all data: none of the loader's fields apply. */
static int validate_java_bounds(const struct upatch_host_header *h)
{
	if (h->loader_insns_off || h->loader_insns_len || h->metadata_len ||
	    h->log_buf_sz || h->nr_maps || h->nr_progs ||
	    h->rodata_data_off || h->data_len == 0)
		return -EINVAL;
	return 0;
}

static int validate_bounds(const struct upatch_host_header *h,
			   size_t n)
{
	if (!section_inside(h->signature_off, h->signature_len, n))
		return -EINVAL;
	if (!section_inside(h->metadata_off, h->metadata_len, n))
		return -EINVAL;
	if (!section_inside(h->data_off, h->data_len, n))
		return -EINVAL;
	if (h->signature_len == 0)
		return -EINVAL;
	switch (h->type) {
	case UPATCH_TYPE_BPF:
		return validate_bpf_bounds(h, n);
	case UPATCH_TYPE_JAVA:
		return validate_java_bounds(h);
	default:
		return -EINVAL;
	}
}

static bool has_nul(const char *s, size_t n)
{
	return memchr(s, '\0', n);
}

bool policy_path_valid(const char *path, size_t size)
{
	size_t end = min(size, (size_t)UPATCH_POLICY_PATH_LEN_MAX + 1);
	bool wildcard = false;
	size_t i;

	if (!size || path[0] != '/')
		return false;
	for (i = 1; i < end && path[i]; i++) {
		if (path[i] == '*' || path[i] == '?')
			wildcard = true;
		else if (path[i] == '/' && wildcard)
			return false;
	}
	return i < end && path[i - 1] != '/';
}

const char *policy_path_pattern(const char *path)
{
	const char *name = strrchr(path, '/') + 1;

	return strchr(name, '*') || strchr(name, '?') ? name : NULL;
}

static bool parse_policy_labels(const __u8 *p, __u32 len, __u32 nr_maps,
				__u32 *map_idx, __u32 *socket_map_idx)
{
	struct upatch_policy_label_header h;
	struct upatch_policy_label_entry e;
	__u32 count, idx, socket_idx;

	if (len < sizeof(h))
		return false;
	memcpy(&h, p, sizeof(h));
	count = le32_to_cpu(h.count);
	idx = le32_to_cpu(h.policy_map_idx);
	socket_idx = le32_to_cpu(h.socket_policy_map_idx);
	if (le32_to_cpu(h.magic) != UPATCH_POLICY_LABELS_MAGIC ||
	    le32_to_cpu(h.version) != UPATCH_POLICY_LABELS_VERSION ||
	    idx >= nr_maps || idx >= UPATCH_MAPS_MAX ||
	    socket_idx >= nr_maps || socket_idx >= UPATCH_MAPS_MAX ||
	    idx == socket_idx || !count ||
	    size_add(sizeof(h), size_mul(count, sizeof(e))) != len)
		return false;
	for (__u32 i = 0; i < count; i++) {
		__u64 bit;

		memcpy(&e, p + sizeof(h) + i * sizeof(e), sizeof(e));
		bit = le64_to_cpu(e.bit);
		if (!bit || (bit & (bit - 1)) ||
		    !has_nul(e.policy, sizeof(e.policy)) || !e.policy[0] ||
		    !policy_path_valid(e.path, sizeof(e.path)))
			return false;
	}
	*map_idx = idx;
	*socket_map_idx = socket_idx;
	return true;
}

/* The DECODERS section: entries and sources within the blob. */
static bool parse_decoders(struct upatch *u, const __u8 *bp,
			   __u32 decoder_len)
{
	__u32 nr_decoders;
	__u64 entries_end;
	size_t i;

	if (decoder_len < sizeof(struct upatch_decoder_blob))
		return false;
	if (get_le32(bp) != UPATCH_DECODER_MAGIC ||
	    get_le32(bp + 4) != UPATCH_DECODER_VERSION)
		return false;

	nr_decoders = get_le32(bp + 8);
	if (nr_decoders == 0)
		return false;
	entries_end = sizeof(struct upatch_decoder_blob) +
		      (__u64)nr_decoders *
		      sizeof(struct upatch_decoder_entry);
	if (entries_end > decoder_len)
		return false;

	/* The blob sits behind the signature, so entries are unaligned. */
	for (i = 0; i < nr_decoders; i++) {
		struct upatch_decoder_entry d;
		__u32 source_off, source_len;

		memcpy(&d, bp + sizeof(struct upatch_decoder_blob) +
		       i * sizeof(d), sizeof(d));
		if (!has_nul(d.upatch, sizeof(d.upatch)) ||
		    !has_nul(d.map, sizeof(d.map)) ||
		    !has_nul(d.source, sizeof(d.source)) ||
		    !has_nul(d.entrypoint, sizeof(d.entrypoint)))
			return false;
		if (le32_to_cpu(d.language) == 0 ||
		    le32_to_cpu(d.api_version) == 0 ||
		    le32_to_cpu(d.input_format) == 0 ||
		    le32_to_cpu(d.export_signal) == 0)
			return false;

		source_off = le32_to_cpu(d.source_off);
		source_len = le32_to_cpu(d.source_len);
		if (source_len == 0 || source_off < entries_end ||
		    source_off > decoder_len ||
		    source_len > decoder_len - source_off)
			return false;
	}

	u->decoder_blob = (const void *)bp;
	u->decoder_blob_len = decoder_len;
	u->nr_decoders = nr_decoders;
	return true;
}

static void forget_signed_sections(struct upatch *u)
{
	u->decoder_blob = NULL;
	u->decoder_blob_len = 0;
	u->nr_decoders = 0;
	u->signed_name = NULL;
	u->signed_attach = NULL;
	u->signed_attach_len = 0;
	u->signed_unload_payload = NULL;
	u->signed_policy_labels = NULL;
	u->signed_policy_labels_len = 0;
	u->signed_policy_map_idx = 0;
	u->signed_socket_policy_map_idx = 0;
	u->signed_type = NULL;
	u->signed_jar = NULL;
	u->signed_jar_len = 0;
}

/*
 * The signed sections behind the loader data. Each lies below the
 * directory, the directory ends where the trailer begins, and each tag
 * appears once; a directory that breaks any of that is taken for none,
 * so a load or unload refuses for what it then lacks.
 *
 * The signature covers insns || data with nothing between the two, and
 * the header that says where one ends is not signed. The trailer is the
 * last of the signed bytes wherever the header puts that end, and a
 * directory that ends at the trailer makes dir_off and the count the
 * length of the data: of all the ways to split what one signature
 * covers, only the signer's keeps its sections.
 */
static void parse_signed_sections(struct upatch *u)
{
	struct upatch_signed_trailer tr;
	__u32 i, nr, dir_off, seen = 0;
	const __u8 *data, *dir;
	__u64 end;

	if (u->hdr.data_len < sizeof(tr))
		return;
	data = u->map + u->hdr.data_off;
	memcpy(&tr, data + u->hdr.data_len - sizeof(tr), sizeof(tr));
	if (le32_to_cpu(tr.magic) != UPATCH_SIGNED_TRAILER_MAGIC ||
	    le32_to_cpu(tr.version) != UPATCH_SIGNED_VERSION)
		return;
	nr = le32_to_cpu(tr.nr_sections);
	dir_off = le32_to_cpu(tr.dir_off);
	end = u->hdr.data_len - sizeof(tr);
	if (nr == 0 || nr > UPATCH_SIGNED_SECTIONS_MAX ||
	    dir_off > end ||
	    (__u64)nr * sizeof(struct upatch_signed_section) !=
	    end - dir_off)
		return;
	dir = data + dir_off;
	for (i = 0; i < nr; i++) {
		struct upatch_signed_section s;
		__u32 tag, off, len, bit;

		memcpy(&s, dir + i * sizeof(s), sizeof(s));
		tag = le32_to_cpu(s.tag);
		off = le32_to_cpu(s.off);
		len = le32_to_cpu(s.len);
		if (le32_to_cpu(s.reserved) || off > dir_off ||
		    len > dir_off - off)
			goto reject;
		switch (tag) {
		case UPATCH_SECTION_NAME:
			bit = 1;
			if (len != UPATCH_NAME_MAX ||
			    !memchr(data + off, '\0', len))
				goto reject;
			u->signed_name = (const char *)data + off;
			break;
		case UPATCH_SECTION_ATTACH:
			bit = 2;
			if (len == 0)
				goto reject;
			u->signed_attach = data + off;
			u->signed_attach_len = len;
			break;
		case UPATCH_SECTION_UNLOAD:
			bit = 4;
			if (len != UPATCH_PAYLOAD_HASH_LEN)
				goto reject;
			u->signed_unload_payload = data + off;
			break;
		case UPATCH_SECTION_DECODERS:
			bit = 8;
			if (!parse_decoders(u, data + off, len))
				goto reject;
			break;
		case UPATCH_SECTION_POLICY_LABELS:
			bit = 16;
			if (!parse_policy_labels(data + off, len, u->hdr.nr_maps,
						 &u->signed_policy_map_idx,
						 &u->signed_socket_policy_map_idx))
				goto reject;
			u->signed_policy_labels = data + off;
			u->signed_policy_labels_len = len;
			break;
		case UPATCH_SECTION_TYPE:
			bit = 32;
			if (len != sizeof(__le32))
				goto reject;
			u->signed_type = data + off;
			break;
		case UPATCH_SECTION_JAR:
			bit = 64;
			if (len == 0)
				goto reject;
			u->signed_jar = data + off;
			u->signed_jar_len = len;
			break;
		default:
			goto reject;
		}
		if (seen & bit)
			goto reject;
		seen |= bit;
	}
	return;
reject:
	forget_signed_sections(u);
}

static int upatch_parse(const void *data, size_t size,
			struct upatch *out)
{
	int ret;

	memset(out, 0, sizeof(*out));
	if (!data || !size || size > UPATCH_FILE_MAX)
		return -EINVAL;
	out->map = data;
	out->map_size = size;
	ret = parse_header(out->map, out->map_size, &out->hdr);
	if (ret)
		goto err;
	out->rodata_offset_in_header = true;
	ret = validate_bounds(&out->hdr, out->map_size);
	if (ret)
		goto err;
	parse_signed_sections(out);
	/*
	 * The header is not signed: a type it names that the signed
	 * sections do not would route the bytes to the wrong verifier.
	 */
	if (upatch_signed_type(out) != out->hdr.type) {
		ret = -EINVAL;
		goto err;
	}
	return 0;
err:
	memset(out, 0, sizeof(*out));
	return ret;
}

int upatch_open_memory(const void *data, size_t size,
		       struct upatch *out)
{
	return upatch_parse(data, size, out);
}

/*
 * A copy, not a mapping: a private mapping still shows what is written to
 * the file after mmap(), so the bytes parsed here, the ones handed to the
 * kernel and the ones acted on after its signature check could differ.
 */
int upatch_open_fd(int fd, struct upatch *out)
{
	struct stat st;
	size_t size, off;
	__u8 *buf;
	int ret;

	memset(out, 0, sizeof(*out));
	if (fstat(fd, &st) != 0)
		return -errno;
	if (!S_ISREG(st.st_mode) || st.st_size <= 0)
		return -EINVAL;
	/* refuse pathologically-large inputs; .upatch is small */
	if ((uintmax_t)st.st_size > UPATCH_FILE_MAX)
		return -EFBIG;

	size = (size_t)st.st_size;
	buf = xmalloc(size);
	if (!buf)
		return -ENOMEM;
	for (off = 0; off < size; ) {
		ssize_t n = pread(fd, buf + off, size - off, (off_t)off);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			ret = n < 0 ? -errno : -EIO;
			goto err;
		}
		off += (size_t)n;
	}
	ret = upatch_parse(buf, size, out);
	if (ret)
		goto err;
	out->owned = true;
	return 0;
err:
	xfree(buf, size);
	return ret;
}

int upatch_open(const char *path, struct upatch *out)
{
	int fd, ret;

	memset(out, 0, sizeof(*out));
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	ret = upatch_open_fd(fd, out);
	close(fd);
	return ret;
}

void upatch_close(struct upatch *u)
{
	if (u->map && u->owned)
		xfree((void *)u->map, u->map_size);
	if (u->map) {
		u->map = NULL;
		u->map_size = 0;
		u->owned = false;
		forget_signed_sections(u);
	}
}

void upatch_header_name(const struct upatch *u, char out[UPATCH_NAME_MAX + 1])
{
	memcpy(out, u->hdr.name, UPATCH_NAME_MAX);
	out[UPATCH_NAME_MAX] = '\0';
}

bool upatch_name_signed(const struct upatch *u)
{
	const char *name = upatch_signed_name(u);

	return name && !memcmp(name, u->hdr.name, UPATCH_NAME_MAX);
}

static bool prog_name_char(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '_' || c == '.';
}

void upatch_prog_name(const struct upatch *u, char *out, size_t size)
{
	size_t i, n = strnlen(u->hdr.name, sizeof(u->hdr.name));

	if (!size)
		return;
	memset(out, 0, size);
	n = min(n, size - 1);
	for (i = 0; i < n; i++)
		out[i] = prog_name_char(u->hdr.name[i]) ? u->hdr.name[i] : '_';
}

const char *upatch_signed_name(const struct upatch *u)
{
	return u->map ? u->signed_name : NULL;
}

const void *upatch_signed_attach(const struct upatch *u, __u32 *len)
{
	*len = u->map ? u->signed_attach_len : 0;
	return u->map ? u->signed_attach : NULL;
}

const __u8 *upatch_signed_unload_payload(const struct upatch *u)
{
	return u->map ? u->signed_unload_payload : NULL;
}

const void *upatch_signed_policy_labels(const struct upatch *u,
					__u32 *len)
{
	*len = u->map ? u->signed_policy_labels_len : 0;
	return u->map ? u->signed_policy_labels : NULL;
}

const void *upatch_loader(const struct upatch *u)
{
	if (!u->map)
		return NULL;
	return u->map + u->hdr.loader_insns_off;
}

const void *upatch_signature(const struct upatch *u)
{
	if (!u->map)
		return NULL;
	return u->map + u->hdr.signature_off;
}

const void *upatch_metadata(const struct upatch *u)
{
	if (!u->map || u->hdr.metadata_len == 0)
		return NULL;
	return u->map + u->hdr.metadata_off;
}

const void *upatch_data(const struct upatch *u)
{
	if (!u->map || u->hdr.data_len == 0)
		return NULL;
	return u->map + u->hdr.data_off;
}

bool upatch_is_unload(const struct upatch *u)
{
	return (u->hdr.flags & DIRECTIVE_UNLOAD) != 0;
}

const char *upatch_type_str(const struct upatch *u)
{
	return u->hdr.type == UPATCH_TYPE_JAVA ? "java" : "bpf";
}

__u32 upatch_signed_type(const struct upatch *u)
{
	if (!u->map || !u->signed_type)
		return UPATCH_TYPE_BPF;
	return get_le32(u->signed_type);
}

const void *upatch_signed_jar(const struct upatch *u, __u32 *len)
{
	*len = u->map ? u->signed_jar_len : 0;
	return u->map ? u->signed_jar : NULL;
}

bool upatch_has_decoders(const struct upatch *u)
{
	return u->map && u->decoder_blob && u->nr_decoders > 0;
}

int upatch_decoder_view(const struct upatch *u, __u32 idx,
			struct upatch_decoder_view *out)
{
	struct upatch_decoder_entry d;
	const __u8 *bp;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	if (!upatch_has_decoders(u) || idx >= u->nr_decoders)
		return -ENOENT;

	bp = (const __u8 *)u->decoder_blob;
	memcpy(&d, bp + sizeof(struct upatch_decoder_blob) +
	       (size_t)idx * sizeof(d), sizeof(d));
	out->language = le32_to_cpu(d.language);
	out->api_version = le32_to_cpu(d.api_version);
	out->input_format = le32_to_cpu(d.input_format);
	out->export_signal = le32_to_cpu(d.export_signal);
	memcpy(out->upatch, d.upatch, sizeof(out->upatch));
	memcpy(out->map, d.map, sizeof(out->map));
	memcpy(out->source_name, d.source, sizeof(out->source_name));
	memcpy(out->entrypoint, d.entrypoint, sizeof(out->entrypoint));
	out->source = (const char *)(bp + le32_to_cpu(d.source_off));
	out->source_len = le32_to_cpu(d.source_len);
	return 0;
}

bool upatch_name_valid(const char *name)
{
	size_t i, pin = 0;

	if (!name || name[0] == '\0' || name[0] == '.')
		return false;
	for (i = 0; name[i]; i++) {
		char c = name[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '.' || c == '_' ||
		      c == '-'))
			return false;
		pin += c == '.' ? 2 : 1;
		if (pin > NAME_MAX)
			return false;
	}
	return true;
}

bool upatch_member_valid(const char *name, const char *payload_hex)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN];

	return upatch_name_valid(name) && payload_hex &&
	       !hex_decode(payload_hex, payload, sizeof(payload));
}

int upatch_select(const struct dirent *e)
{
	return name_has_suffix(e->d_name, strlen(e->d_name), ".upatch");
}

void prog_specs_free(struct prog_spec *specs, __u32 nr_progs)
{
	__u32 i;

	if (!specs)
		return;
	for (i = 0; i < nr_progs; i++) {
		if (specs[i].target_fd >= 0)
			close(specs[i].target_fd);
		xstrfree(specs[i].uprobe_path);
		xfree(specs[i].uprobe_offsets,
		      (size_t)specs[i].nr_uprobe_offsets *
		      sizeof(*specs[i].uprobe_offsets));
		xfree(specs[i].kprobe_sym_buf, specs[i].kprobe_sym_buf_len);
		xfree(specs[i].kprobe_syms, (size_t)specs[i].nr_kprobe_syms *
		      sizeof(*specs[i].kprobe_syms));
	}
	xfree(specs, (size_t)nr_progs * sizeof(*specs));
}

__u32 prog_specs_xdp_classes(const struct prog_spec *specs, __u32 nr_progs)
{
	__u32 i, classes = 0;

	for (i = 0; i < nr_progs; i++)
		if (specs[i].kind == UPATCH_ATTACH_XDP)
			classes |= specs[i].device_classes;
	return classes;
}

bool kprobe_sym_valid(const char *sym, size_t len)
{
	size_t i;

	if (!len || len >= UPATCH_KPROBE_SYM_MAX)
		return false;
	for (i = 0; i < len; i++) {
		__u8 c = (__u8)sym[i];

		if (c <= ' ' || c >= 0x7f || c == ',' || c == '*' || c == '?' || c == '|')
			return false;
	}
	return true;
}

static int parse_uprobe_targets(const __u8 **pos, const __u8 *end, struct prog_spec *specs,
				__u32 nr_progs, __u32 nr_uprobes)
{
	struct upatch_uprobe_targets targets;
	const __u8 *cursor = *pos;
	__u32 nr_targets, i;

	if ((size_t)(end - cursor) < sizeof(targets))
		return -EINVAL;
	memcpy(&targets, cursor, sizeof(targets));
	cursor += sizeof(targets);
	nr_targets = le32_to_cpu(targets.nr_targets);
	if (le32_to_cpu(targets.magic) != UPATCH_UPROBE_TARGET_MAGIC ||
	    le32_to_cpu(targets.version) != UPATCH_UPROBE_TARGET_VERSION ||
	    le32_to_cpu(targets.reserved) != 0 || nr_targets != nr_uprobes)
		return -EINVAL;

	for (i = 0; i < nr_targets; i++) {
		struct upatch_uprobe_target record;
		__u32 prog_idx, path_len, build_id_len, nr_offsets, j;
		struct prog_spec *spec;
		size_t payload_len;

		if ((size_t)(end - cursor) < sizeof(record))
			return -EINVAL;
		memcpy(&record, cursor, sizeof(record));
		cursor += sizeof(record);
		prog_idx = le32_to_cpu(record.prog_idx);
		path_len = le32_to_cpu(record.path_len);
		build_id_len = le32_to_cpu(record.build_id_len);
		nr_offsets = le32_to_cpu(record.nr_offsets);
		if (prog_idx >= nr_progs || !kind_has_uprobe_target(specs[prog_idx].kind) ||
		    specs[prog_idx].uprobe_path || path_len == 0 ||
		    path_len >= UPATCH_UPROBE_PATH_MAX || build_id_len == 0 ||
		    build_id_len > UPATCH_BUILD_ID_MAX || nr_offsets == 0 ||
		    nr_offsets > UPATCH_UPROBE_OFFSETS_MAX ||
		    (kind_is_uprobe_single(specs[prog_idx].kind) && nr_offsets != 1))
			return -EINVAL;
		payload_len = (size_t)path_len + build_id_len + (size_t)nr_offsets * sizeof(__u64);
		if ((size_t)(end - cursor) < payload_len ||
		    cursor[0] != '/' || memchr(cursor, '\0', path_len))
			return -EINVAL;
		spec = &specs[prog_idx];
		spec->uprobe_path = xstrndup((const char *)cursor, path_len);
		if (!spec->uprobe_path)
			return -ENOMEM;
		cursor += path_len;
		memcpy(spec->build_id, cursor, build_id_len);
		spec->build_id_len = build_id_len;
		cursor += build_id_len;
		spec->uprobe_offsets = xcalloc(nr_offsets, sizeof(*spec->uprobe_offsets));
		if (!spec->uprobe_offsets)
			return -ENOMEM;
		spec->nr_uprobe_offsets = nr_offsets;
		for (j = 0; j < nr_offsets; j++) {
			spec->uprobe_offsets[j] = get_le64(cursor);
			cursor += sizeof(__le64);
			if (j && spec->uprobe_offsets[j] <= spec->uprobe_offsets[j - 1])
				return -EINVAL;
		}
	}
	for (i = 0; i < nr_progs; i++) {
		if (kind_has_uprobe_target(specs[i].kind) && !specs[i].uprobe_path)
			return -EINVAL;
	}
	*pos = cursor;
	return 0;
}

/* The caller's prog_specs_free() releases what a failure leaves in spec. */
static int parse_kprobe_syms(const __u8 *syms, __u32 syms_len, __u32 nr_syms,
			     struct prog_spec *spec)
{
	size_t off = 0;
	__u32 i;

	spec->kprobe_sym_buf = xmalloc(syms_len);
	if (!spec->kprobe_sym_buf)
		return -ENOMEM;
	spec->kprobe_sym_buf_len = syms_len;
	memcpy(spec->kprobe_sym_buf, syms, syms_len);
	spec->kprobe_syms = xcalloc(nr_syms, sizeof(*spec->kprobe_syms));
	if (!spec->kprobe_syms)
		return -ENOMEM;
	spec->nr_kprobe_syms = nr_syms;

	for (i = 0; i < nr_syms; i++) {
		const char *name = spec->kprobe_sym_buf + off;
		const char *nul;

		if (off >= syms_len)
			return -EINVAL;
		nul = memchr(name, '\0', syms_len - off);
		if (!nul || !kprobe_sym_valid(name, (size_t)(nul - name)))
			return -EINVAL;
		if (i && strcmp(spec->kprobe_syms[i - 1], name) >= 0)
			return -EINVAL;
		spec->kprobe_syms[i] = name;
		off += (size_t)(nul - name) + 1;
	}
	return off == syms_len ? 0 : -EINVAL;
}

static int parse_kprobe_targets(const __u8 **pos, const __u8 *end, struct prog_spec *specs,
				__u32 nr_progs, __u32 nr_kprobe_multis)
{
	struct upatch_kprobe_targets targets;
	const __u8 *cursor = *pos;
	__u32 i;

	if ((size_t)(end - cursor) < sizeof(targets))
		return -EINVAL;
	memcpy(&targets, cursor, sizeof(targets));
	cursor += sizeof(targets);
	if (le32_to_cpu(targets.magic) != UPATCH_KPROBE_TARGET_MAGIC ||
	    le32_to_cpu(targets.version) != UPATCH_KPROBE_TARGET_VERSION ||
	    le32_to_cpu(targets.reserved) != 0 ||
	    le32_to_cpu(targets.nr_targets) != nr_kprobe_multis)
		return -EINVAL;

	for (i = 0; i < nr_kprobe_multis; i++) {
		struct upatch_kprobe_target record;
		__u32 prog_idx, nr_syms, syms_len;
		int ret;

		if ((size_t)(end - cursor) < sizeof(record))
			return -EINVAL;
		memcpy(&record, cursor, sizeof(record));
		cursor += sizeof(record);
		prog_idx = le32_to_cpu(record.prog_idx);
		nr_syms = le32_to_cpu(record.nr_syms);
		syms_len = le32_to_cpu(record.syms_len);
		if (prog_idx >= nr_progs || !kind_is_kprobe_multi(specs[prog_idx].kind) ||
		    specs[prog_idx].kprobe_syms || nr_syms == 0 ||
		    nr_syms > UPATCH_KPROBE_SYMS_MAX || syms_len / 2 < nr_syms ||
		    (size_t)(end - cursor) < syms_len)
			return -EINVAL;
		ret = parse_kprobe_syms(cursor, syms_len, nr_syms, &specs[prog_idx]);
		if (ret)
			return ret;
		cursor += syms_len;
	}
	*pos = cursor;
	return 0;
}

int prog_specs_parse(const void *metadata, __u32 metadata_len,
		     __u32 nr_maps, __u32 nr_progs, struct prog_spec **out)
{
	__u32 magic, version, count, i, nr_uprobes = 0, nr_kprobe_multis = 0;
	__u32 xdp_classes = 0;
	const struct upatch_prog_entry empty = {};
	struct upatch_prog_metadata md;
	struct prog_spec *specs = NULL;
	const __u8 *cursor, *end;
	int ret = -EINVAL;
	size_t base_len;

	*out = NULL;
	if (!metadata || metadata_len < sizeof(__u32))
		return -EINVAL;
	magic = get_le32(metadata);
	if (magic != UPATCH_PROG_MAGIC)
		return -EINVAL;
	if (metadata_len < sizeof(md))
		return -EINVAL;
	memcpy(&md, metadata, sizeof(md));
	version = le32_to_cpu(md.version);
	count = le32_to_cpu(md.nr_progs);
	if (version != UPATCH_PROG_VERSION)
		return -EOPNOTSUPP;
	if (count != nr_progs || le32_to_cpu(md.nr_maps) != nr_maps)
		return -EINVAL;
	base_len = struct_size(&md, progs, count);
	if (base_len > UINT32_MAX)
		return -EOVERFLOW;
	if (metadata_len < base_len)
		return -EINVAL;
	specs = xcalloc(nr_progs, sizeof(*specs));
	if (!specs)
		return -ENOMEM;
	for (i = 0; i < nr_progs; i++)
		specs[i].target_fd = -1;

	for (i = 0; i < nr_progs; i++) {
		struct upatch_prog_entry prog;
		struct prog_spec *spec = &specs[i];
		__u32 role, kind;

		memcpy(&prog, (const __u8 *)metadata + sizeof(md) +
		       (size_t)i * sizeof(prog), sizeof(prog));
		role = le32_to_cpu(prog.role);
		switch (role) {
		case UPATCH_PROG_ROLE_ATTACH:
			break;
		case UPATCH_PROG_ROLE_SERIALIZER:
			if (prog.kind || prog.offset || prog.target[0])
				goto out;
			if (!memchr(prog.map, '\0', sizeof(prog.map)) ||
			    prog.map[0] == '\0')
				goto out;
			spec->role = role;
			memcpy(spec->map, prog.map, sizeof(spec->map));
			spec->map[sizeof(spec->map) - 1] = '\0';
			continue;
		case UPATCH_PROG_ROLE_TEST_RUN:
			if (prog.kind || prog.offset || prog.target[0] || prog.map[0])
				goto out;
			spec->role = role;
			continue;
		default:
			goto out;
		}
		if (prog.map[0])
			goto out;
		spec->role = role;

		kind = le32_to_cpu(prog.kind);
		switch (kind) {
		case UPATCH_ATTACH_RAW_TRACEPOINT:
			spec->kind = kind;
			if (prog.target[0] || prog.offset)
				goto out;
			continue;
		case UPATCH_ATTACH_CGROUP_SKB_INGRESS:
		case UPATCH_ATTACH_CGROUP_SKB_EGRESS:
		case UPATCH_ATTACH_NETFILTER_IPV6_PRE_ROUTING:
			spec->kind = kind;
			if (prog.target[0] || prog.offset)
				goto out;
			continue;
		case UPATCH_ATTACH_FMOD_RET:
			spec->kind = kind;
			if (prog.target[0] || prog.offset)
				goto out;
			continue;
		case UPATCH_ATTACH_KPROBE:
		case UPATCH_ATTACH_KRETPROBE:
			break;
		case UPATCH_ATTACH_UPROBE_MULTI:
		case UPATCH_ATTACH_URETPROBE_MULTI:
			if (prog.offset)
				goto out;
			nr_uprobes++;
			break;
		case UPATCH_ATTACH_UPROBE:
		case UPATCH_ATTACH_URETPROBE:
			nr_uprobes++;
			break;
		case UPATCH_ATTACH_XDP:
			spec->device_classes = le32_to_cpu(prog.xdp.device_classes);
			/* A device runs one native XDP program at a time. */
			if (!spec->device_classes ||
			    (spec->device_classes & ~(__u32)UPATCH_XDP_ALL) ||
			    (spec->device_classes & xdp_classes) ||
			    prog.xdp.reserved ||
			    memcmp(prog.target, empty.target, sizeof(prog.target)) ||
			    memcmp(prog.map, empty.map, sizeof(prog.map)))
				goto out;
			xdp_classes |= spec->device_classes;
			spec->kind = kind;
			continue;
		case UPATCH_ATTACH_KPROBE_MULTI:
		case UPATCH_ATTACH_KRETPROBE_MULTI:
			spec->kind = kind;
			if (prog.target[0] || prog.offset)
				goto out;
			nr_kprobe_multis++;
			continue;
		default:
			goto out;
		}
		if (!memchr(prog.target, '\0', sizeof(prog.target)) ||
		    prog.target[0] == '\0')
			goto out;
		spec->kind = kind;
		spec->offset = le64_to_cpu(prog.offset);
		memcpy(spec->target, prog.target, sizeof(spec->target));
		spec->target[sizeof(spec->target) - 1] = '\0';
		if ((kind == UPATCH_ATTACH_KRETPROBE || kind == UPATCH_ATTACH_URETPROBE) &&
		    spec->offset)
			goto out;
		if (kind_is_uprobe_multi(kind) &&
		    (strchr(spec->target, ',') || strchr(spec->target, '|')))
			goto out;
	}

	cursor = (const __u8 *)metadata + base_len;
	end = (const __u8 *)metadata + metadata_len;
	if (nr_uprobes) {
		ret = parse_uprobe_targets(&cursor, end, specs, nr_progs, nr_uprobes);
		if (ret)
			goto out;
	}
	if (nr_kprobe_multis) {
		ret = parse_kprobe_targets(&cursor, end, specs, nr_progs, nr_kprobe_multis);
		if (ret)
			goto out;
	}
	ret = -EINVAL;
	if (cursor != end)
		goto out;
	*out = specs;
	return 0;
out:
	prog_specs_free(specs, nr_progs);
	return ret;
}
