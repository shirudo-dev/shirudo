// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * .upatch container parser.
 */

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <shirudo/misc.h>

#include "malloc.h"
#include "upatch.h"

static int parse_header(const __u8 *m, size_t n,
			struct shirudo_upatch_header *out)
{
	const __u8 *p = m;

	if (n < SHIRUDO_UPATCH_HEADER_SIZE)
		return -EINVAL;

	out->magic = rd_le64(p);
	p += 8;
	if (out->magic != SHIRUDO_UPATCH_MAGIC)
		return -EINVAL;

	out->version = rd_le32(p);
	p += 4;
	if (out->version != SHIRUDO_UPATCH_VERSION)
		return -EINVAL;

	out->flags = rd_le32(p);
	p += 4;

	memcpy(out->name, p, sizeof(out->name));
	p += sizeof(out->name);

	memcpy(out->payload_sha256, p, sizeof(out->payload_sha256));
	p += sizeof(out->payload_sha256);

	out->loader_insns_off	= rd_le32(p);
	p += 4;
	out->loader_insns_len	= rd_le32(p);
	p += 4;
	out->signature_off	= rd_le32(p);
	p += 4;
	out->signature_len	= rd_le32(p);
	p += 4;
	out->metadata_off	= rd_le32(p);
	p += 4;
	out->metadata_len	= rd_le32(p);
	p += 4;
	out->data_off		= rd_le32(p);
	p += 4;
	out->data_len		= rd_le32(p);
	p += 4;
	out->log_buf_sz		= rd_le32(p);
	p += 4;
	out->nr_maps		= rd_le32(p);
	p += 4;
	out->nr_progs		= rd_le32(p);
	p += 4;
	out->rodata_data_off	= rd_le32(p);
	p += 4;
	out->type		= rd_le32(p);
	p += 4;
	out->reserved1		= rd_le32(p);
	p += 4;
	if (out->reserved1 != 0)
		return -EINVAL;
	return 0;
}

static int section_inside(__u32 off, __u32 len, size_t n)
{
	if (off > n || len > n)
		return 0;
	if ((__u64)off + (__u64)len > (__u64)n)
		return 0;
	if (len != 0 && off < SHIRUDO_UPATCH_HEADER_SIZE)
		return 0;
	return 1;
}

static int validate_bounds(const struct shirudo_upatch_header *h, size_t n)
{
	if (h->type != SHIRUDO_UPATCH_TYPE_BPF)
		return -EINVAL;
	if (h->loader_insns_off < SHIRUDO_UPATCH_HEADER_SIZE ||
	    !section_inside(h->loader_insns_off, h->loader_insns_len, n))
		return -EINVAL;
	if (!section_inside(h->signature_off, h->signature_len, n))
		return -EINVAL;
	if (!section_inside(h->metadata_off, h->metadata_len, n))
		return -EINVAL;
	if (!section_inside(h->data_off, h->data_len, n))
		return -EINVAL;
	if (h->rodata_data_off > h->data_len)
		return -EINVAL;
	if (h->loader_insns_len == 0 || h->signature_len == 0)
		return -EINVAL;
	return 0;
}

static bool has_nul(const char *s, size_t n)
{
	return memchr(s, '\0', n);
}

/* The DECODERS section: entries and sources within the blob. */
static bool parse_decoders(struct shirudo_upatch *u, const __u8 *bp,
			   __u32 decoder_len)
{
	__u32 nr_decoders;
	__u64 entries_end;
	size_t i;

	if (decoder_len < sizeof(struct shirudo_upatch_decoder_blob))
		return false;
	if (rd_le32(bp) != SHIRUDO_UPATCH_DECODER_MAGIC ||
	    rd_le32(bp + 4) != SHIRUDO_UPATCH_DECODER_VERSION)
		return false;

	nr_decoders = rd_le32(bp + 8);
	if (nr_decoders == 0)
		return false;
	entries_end = sizeof(struct shirudo_upatch_decoder_blob) +
		      (__u64)nr_decoders *
		      sizeof(struct shirudo_upatch_decoder_entry);
	if (entries_end > decoder_len)
		return false;

	/* The blob sits behind the signature, so entries are unaligned. */
	for (i = 0; i < nr_decoders; i++) {
		struct shirudo_upatch_decoder_entry d;
		__u32 source_off, source_len;

		memcpy(&d, bp + sizeof(struct shirudo_upatch_decoder_blob) +
		       i * sizeof(d), sizeof(d));
		if (!has_nul(d.upatch, sizeof(d.upatch)) ||
		    !has_nul(d.map, sizeof(d.map)) ||
		    !has_nul(d.source, sizeof(d.source)) ||
		    !has_nul(d.entrypoint, sizeof(d.entrypoint)))
			return false;
		if (le32toh(d.language) == 0 ||
		    le32toh(d.api_version) == 0 ||
		    le32toh(d.input_format) == 0 ||
		    le32toh(d.export_signal) == 0)
			return false;

		source_off = le32toh(d.source_off);
		source_len = le32toh(d.source_len);
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

static void forget_signed_sections(struct shirudo_upatch *u)
{
	u->decoder_blob = NULL;
	u->decoder_blob_len = 0;
	u->nr_decoders = 0;
	u->signed_name = NULL;
	u->signed_attach = NULL;
	u->signed_attach_len = 0;
	u->signed_unload_payload = NULL;
}

/*
 * The signed sections behind the loader data. Each lies below the
 * directory, the directory below the trailer, and each tag appears
 * once; a directory that breaks any of that is taken for none, so a
 * load or unload refuses for what it then lacks.
 */
static void parse_signed_sections(struct shirudo_upatch *u)
{
	struct shirudo_upatch_signed_trailer tr;
	__u32 i, nr, dir_off, seen = 0;
	const __u8 *data, *dir;
	__u64 end;

	if (u->hdr.data_len < sizeof(tr))
		return;
	data = u->map + u->hdr.data_off;
	memcpy(&tr, data + u->hdr.data_len - sizeof(tr), sizeof(tr));
	if (le32toh(tr.magic) != SHIRUDO_UPATCH_SIGNED_TRAILER_MAGIC ||
	    le32toh(tr.version) != SHIRUDO_UPATCH_SIGNED_VERSION)
		return;
	nr = le32toh(tr.nr_sections);
	dir_off = le32toh(tr.dir_off);
	end = u->hdr.data_len - sizeof(tr);
	if (nr == 0 || nr > SHIRUDO_UPATCH_SIGNED_SECTIONS_MAX ||
	    dir_off > end ||
	    (__u64)nr * sizeof(struct shirudo_upatch_signed_section) >
	    end - dir_off)
		return;
	dir = data + dir_off;
	for (i = 0; i < nr; i++) {
		struct shirudo_upatch_signed_section s;
		__u32 tag, off, len, bit;

		memcpy(&s, dir + i * sizeof(s), sizeof(s));
		tag = le32toh(s.tag);
		off = le32toh(s.off);
		len = le32toh(s.len);
		if (le32toh(s.reserved) || off > dir_off ||
		    len > dir_off - off)
			goto reject;
		switch (tag) {
		case SHIRUDO_UPATCH_SECTION_NAME:
			bit = 1;
			if (len != SHIRUDO_UPATCH_NAME_MAX)
				goto reject;
			u->signed_name = (const char *)data + off;
			break;
		case SHIRUDO_UPATCH_SECTION_ATTACH:
			bit = 2;
			if (len == 0)
				goto reject;
			u->signed_attach = data + off;
			u->signed_attach_len = len;
			break;
		case SHIRUDO_UPATCH_SECTION_UNLOAD:
			bit = 4;
			if (len != SHIRUDO_UPATCH_PAYLOAD_HASH_LEN)
				goto reject;
			u->signed_unload_payload = data + off;
			break;
		case SHIRUDO_UPATCH_SECTION_DECODERS:
			bit = 8;
			if (!parse_decoders(u, data + off, len))
				goto reject;
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
			struct shirudo_upatch *out)
{
	int rc;

	memset(out, 0, sizeof(*out));
	if (!data || !size || size > SHIRUDO_UPATCH_FILE_MAX)
		return -EINVAL;
	out->map = data;
	out->map_size = size;
	rc = parse_header(out->map, out->map_size, &out->hdr);
	if (rc)
		goto err;
	out->rodata_offset_valid = true;
	rc = validate_bounds(&out->hdr, out->map_size);
	if (rc)
		goto err;
	parse_signed_sections(out);
	return 0;
err:
	memset(out, 0, sizeof(*out));
	return rc;
}

int upatch_open_memory(const void *data, size_t size,
		       struct shirudo_upatch *out)
{
	return upatch_parse(data, size, out);
}

int upatch_open(const char *path, struct shirudo_upatch *out)
{
	struct stat st;
	void *m;
	int fd;
	int rc;

	memset(out, 0, sizeof(*out));

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) != 0) {
		rc = -errno;
		close(fd);
		return rc;
	}
	if (!S_ISREG(st.st_mode) || st.st_size <= 0) {
		close(fd);
		return -EINVAL;
	}
	/* refuse pathologically-large inputs; .upatch is small */
	if ((uintmax_t)st.st_size > SHIRUDO_UPATCH_FILE_MAX) {
		close(fd);
		return -EFBIG;
	}

	m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (m == MAP_FAILED)
		return -errno;

	rc = upatch_parse(m, (size_t)st.st_size, out);
	if (rc) {
		munmap(m, (size_t)st.st_size);
		return rc;
	}
	out->mapped = true;
	return 0;
}

void upatch_close(struct shirudo_upatch *u)
{
	if (u->map && u->mapped)
		munmap((void *)u->map, u->map_size);
	if (u->map) {
		u->map = NULL;
		u->map_size = 0;
		u->mapped = false;
		forget_signed_sections(u);
	}
}

const char *upatch_signed_name(const struct shirudo_upatch *u)
{
	return u->map ? u->signed_name : NULL;
}

const void *upatch_signed_attach(const struct shirudo_upatch *u, __u32 *len)
{
	*len = u->map ? u->signed_attach_len : 0;
	return u->map ? u->signed_attach : NULL;
}

const __u8 *upatch_signed_unload_payload(const struct shirudo_upatch *u)
{
	return u->map ? u->signed_unload_payload : NULL;
}

const void *upatch_loader(const struct shirudo_upatch *u)
{
	if (!u->map)
		return NULL;
	return u->map + u->hdr.loader_insns_off;
}

const void *upatch_signature(const struct shirudo_upatch *u)
{
	if (!u->map)
		return NULL;
	return u->map + u->hdr.signature_off;
}

const void *upatch_metadata(const struct shirudo_upatch *u)
{
	if (!u->map || u->hdr.metadata_len == 0)
		return NULL;
	return u->map + u->hdr.metadata_off;
}

const void *upatch_data(const struct shirudo_upatch *u)
{
	if (!u->map || u->hdr.data_len == 0)
		return NULL;
	return u->map + u->hdr.data_off;
}

bool upatch_is_unload(const struct shirudo_upatch *u)
{
	return (u->hdr.flags & SHIRUDO_DIRECTIVE_UNLOAD) != 0;
}

const char *upatch_type_str(const struct shirudo_upatch *u)
{
	return "bpf";
}

bool upatch_has_decoders(const struct shirudo_upatch *u)
{
	return u->map && u->decoder_blob && u->nr_decoders > 0;
}

int upatch_decoder_view(const struct shirudo_upatch *u, __u32 idx,
			struct upatch_decoder_view *out)
{
	struct shirudo_upatch_decoder_entry d;
	const __u8 *bp;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	if (!upatch_has_decoders(u) || idx >= u->nr_decoders)
		return -ENOENT;

	bp = (const __u8 *)u->decoder_blob;
	memcpy(&d, bp + sizeof(struct shirudo_upatch_decoder_blob) +
	       (size_t)idx * sizeof(d), sizeof(d));
	out->language = le32toh(d.language);
	out->api_version = le32toh(d.api_version);
	out->input_format = le32toh(d.input_format);
	out->export_signal = le32toh(d.export_signal);
	memcpy(out->upatch, d.upatch, sizeof(out->upatch));
	memcpy(out->map, d.map, sizeof(out->map));
	memcpy(out->source_name, d.source, sizeof(out->source_name));
	memcpy(out->entrypoint, d.entrypoint, sizeof(out->entrypoint));
	out->source = (const char *)(bp + le32toh(d.source_off));
	out->source_len = le32toh(d.source_len);
	return 0;
}

bool upatch_name_valid(const char *name)
{
	size_t i;

	if (!name || name[0] == '\0' || name[0] == '.')
		return false;
	for (i = 0; name[i]; i++) {
		char c = name[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '.' || c == '_' ||
		      c == '-'))
			return false;
	}
	return true;
}

int upatch_select(const struct dirent *e)
{
	size_t n = strlen(e->d_name);

	return n > 7 && strcmp(e->d_name + n - 7, ".upatch") == 0;
}

void prog_specs_free(struct shirudo_prog_spec *specs, __u32 nr_progs)
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
	}
	xfree(specs, (size_t)nr_progs * sizeof(*specs));
}

int prog_specs_parse(const void *metadata, __u32 metadata_len,
		     __u32 nr_progs, struct shirudo_prog_spec **out)
{
	struct shirudo_upatch_prog_metadata md;
	struct shirudo_prog_spec *specs = NULL;
	const __u8 *cursor, *end;
	size_t base_len;
	__u32 magic, version, count, i, nr_uprobes = 0;
	int rc = -EINVAL;

	*out = NULL;
	if (!metadata || metadata_len < sizeof(__u32))
		return -EINVAL;
	memcpy(&magic, metadata, sizeof(magic));
	magic = le32toh(magic);
	if (magic != SHIRUDO_UPATCH_PROG_MAGIC)
		return -EINVAL;
	if (metadata_len < sizeof(md))
		return -EINVAL;
	memcpy(&md, metadata, sizeof(md));
	version = le32toh(md.version);
	count = le32toh(md.nr_progs);
	if (version != SHIRUDO_UPATCH_PROG_VERSION)
		return -EOPNOTSUPP;
	if (count != nr_progs || le32toh(md.reserved) != 0)
		return -EINVAL;
	if (count > (UINT32_MAX - sizeof(md)) /
	    sizeof(struct shirudo_upatch_prog_entry))
		return -EOVERFLOW;
	base_len = sizeof(md) + (size_t)count *
		   sizeof(struct shirudo_upatch_prog_entry);
	if (metadata_len < base_len)
		return -EINVAL;
	specs = xcalloc(nr_progs, sizeof(*specs));
	if (!specs)
		return -ENOMEM;
	for (i = 0; i < nr_progs; i++)
		specs[i].target_fd = -1;

	for (i = 0; i < nr_progs; i++) {
		struct shirudo_upatch_prog_entry prog;
		struct shirudo_prog_spec *spec = &specs[i];
		__u32 role, kind;

		memcpy(&prog, (const __u8 *)metadata + sizeof(md) +
		       (size_t)i * sizeof(prog), sizeof(prog));
		role = le32toh(prog.role);
		switch (role) {
		case SHIRUDO_UPATCH_PROG_ROLE_ATTACH:
			break;
		case SHIRUDO_UPATCH_PROG_ROLE_SERIALIZER:
			if (prog.kind || prog.offset || prog.target[0])
				goto out;
			if (!memchr(prog.map, '\0', sizeof(prog.map)) ||
			    prog.map[0] == '\0')
				goto out;
			spec->role = role;
			memcpy(spec->map, prog.map, sizeof(spec->map));
			spec->map[sizeof(spec->map) - 1] = '\0';
			continue;
		case SHIRUDO_UPATCH_PROG_ROLE_TEST_RUN:
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

		kind = le32toh(prog.kind);
		switch (kind) {
		case SHIRUDO_UPATCH_ATTACH_RAW_TRACEPOINT:
			spec->kind = kind;
			if (prog.target[0] || prog.offset)
				goto out;
			continue;
		case SHIRUDO_UPATCH_ATTACH_CGROUP_SKB_INGRESS:
		case SHIRUDO_UPATCH_ATTACH_CGROUP_SKB_EGRESS:
		case SHIRUDO_UPATCH_ATTACH_NETFILTER_IPV6_PRE_ROUTING:
			spec->kind = kind;
			if (prog.target[0] || prog.offset)
				goto out;
			continue;
		case SHIRUDO_UPATCH_ATTACH_FMOD_RET:
			spec->kind = kind;
			if (prog.target[0] || prog.offset)
				goto out;
			continue;
		case SHIRUDO_UPATCH_ATTACH_KPROBE:
		case SHIRUDO_UPATCH_ATTACH_KRETPROBE:
			break;
		case SHIRUDO_UPATCH_ATTACH_UPROBE_MULTI:
			if (prog.offset)
				goto out;
			nr_uprobes++;
			break;
		default:
			goto out;
		}
		if (!memchr(prog.target, '\0', sizeof(prog.target)) ||
		    prog.target[0] == '\0')
			goto out;
		spec->kind = kind;
		spec->offset = le64toh(prog.offset);
		memcpy(spec->target, prog.target, sizeof(spec->target));
		spec->target[sizeof(spec->target) - 1] = '\0';
		if (kind == SHIRUDO_UPATCH_ATTACH_KRETPROBE && spec->offset)
			goto out;
		if (kind == SHIRUDO_UPATCH_ATTACH_UPROBE_MULTI &&
		    (strchr(spec->target, ',') || strchr(spec->target, '|')))
			goto out;
	}

	if (!nr_uprobes) {
		if (metadata_len != base_len)
			goto out;
		*out = specs;
		return 0;
	}

	cursor = (const __u8 *)metadata + base_len;
	end = (const __u8 *)metadata + metadata_len;
	if ((size_t)(end - cursor) <
	    sizeof(struct shirudo_upatch_uprobe_targets))
		goto out;
	{
		struct shirudo_upatch_uprobe_targets targets;
		__u32 nr_targets;

		memcpy(&targets, cursor, sizeof(targets));
		cursor += sizeof(targets);
		nr_targets = le32toh(targets.nr_targets);
		if (le32toh(targets.magic) !=
		    SHIRUDO_UPATCH_UPROBE_TARGET_MAGIC ||
		    le32toh(targets.version) !=
		    SHIRUDO_UPATCH_UPROBE_TARGET_VERSION ||
		    le32toh(targets.reserved) != 0 || nr_targets != nr_uprobes)
			goto out;

		for (i = 0; i < nr_targets; i++) {
			struct shirudo_upatch_uprobe_target record;
			struct shirudo_prog_spec *spec;
			__u32 prog_idx, path_len, build_id_len, nr_offsets, j;
			size_t payload_len;

			if ((size_t)(end - cursor) < sizeof(record))
				goto out;
			memcpy(&record, cursor, sizeof(record));
			cursor += sizeof(record);
			prog_idx = le32toh(record.prog_idx);
			path_len = le32toh(record.path_len);
			build_id_len = le32toh(record.build_id_len);
			nr_offsets = le32toh(record.nr_offsets);
			if (prog_idx >= nr_progs ||
			    specs[prog_idx].kind !=
			    SHIRUDO_UPATCH_ATTACH_UPROBE_MULTI ||
			    specs[prog_idx].uprobe_path || path_len == 0 ||
			    path_len >= SHIRUDO_UPATCH_UPROBE_PATH_MAX ||
			    build_id_len == 0 ||
			    build_id_len > SHIRUDO_UPATCH_BUILD_ID_MAX ||
			    nr_offsets == 0 ||
			    nr_offsets > SHIRUDO_UPATCH_UPROBE_OFFSETS_MAX)
				goto out;
			payload_len = (size_t)path_len + build_id_len +
				      (size_t)nr_offsets * sizeof(__u64);
			if ((size_t)(end - cursor) < payload_len ||
			    cursor[0] != '/' || memchr(cursor, '\0', path_len))
				goto out;
			spec = &specs[prog_idx];
			spec->uprobe_path = xstrndup((const char *)cursor,
						     path_len);
			if (!spec->uprobe_path) {
				rc = -ENOMEM;
				goto out;
			}
			spec->uprobe_path_len = path_len;
			cursor += path_len;
			memcpy(spec->build_id, cursor, build_id_len);
			spec->build_id_len = build_id_len;
			cursor += build_id_len;
			spec->uprobe_offsets =
				xcalloc(nr_offsets, sizeof(*spec->uprobe_offsets));
			if (!spec->uprobe_offsets) {
				rc = -ENOMEM;
				goto out;
			}
			spec->nr_uprobe_offsets = nr_offsets;
			for (j = 0; j < nr_offsets; j++) {
				__u64 offset;

				memcpy(&offset, cursor, sizeof(offset));
				cursor += sizeof(offset);
				spec->uprobe_offsets[j] = le64toh(offset);
				if (j && spec->uprobe_offsets[j] <=
				    spec->uprobe_offsets[j - 1])
					goto out;
			}
		}
	}
	if (cursor != end)
		goto out;
	for (i = 0; i < nr_progs; i++) {
		if (specs[i].kind == SHIRUDO_UPATCH_ATTACH_UPROBE_MULTI &&
		    !specs[i].uprobe_path)
			goto out;
	}
	*out = specs;
	return 0;
out:
	prog_specs_free(specs, nr_progs);
	return rc;
}
