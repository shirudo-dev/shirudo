// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <endian.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "io.h"
#include "json.h"
#include "log.h"
#include "macros.h"
#include "malloc.h"
#include "upatch.h"
#include "upatch_rodata.h"

#define RODATA_MAPS_MAX	64
#define RODATA_JSON_MAX_DEPTH	8

struct rodata_map {
	char name[BPF_OBJ_NAME_LEN + 1];
	__u32 value_size;
	bool found;
};

struct rodata_view {
	struct btf *btf;
	const __u8 *bytes;
	__u32 data_offset;
	__u32 size;
	__u32 type_id;
};

static bool loader_lddw(const struct bpf_insn *insns, size_t count,
			size_t i, __u8 reg, __u32 *value)
{
	if (i + 1 >= count ||
	    insns[i].code != (BPF_LD | BPF_DW | BPF_IMM) ||
	    insns[i].dst_reg != reg ||
	    insns[i].src_reg != BPF_PSEUDO_MAP_IDX_VALUE ||
	    insns[i].off || insns[i].imm || insns[i + 1].code ||
	    insns[i + 1].off)
		return false;
	*value = (__u32)insns[i + 1].imm;
	return true;
}

static bool sys_bpf_call(const struct bpf_insn *insns, size_t count,
			 size_t i, __u32 *cmd, __u32 *attr, __u32 *attr_size)
{
	if (i < 4 || i >= count ||
	    insns[i].code != (BPF_JMP | BPF_CALL) ||
	    insns[i].imm != BPF_FUNC_sys_bpf ||
	    insns[i - 4].code != (BPF_ALU64 | BPF_MOV | BPF_K) ||
	    insns[i - 4].dst_reg != BPF_REG_1 ||
	    insns[i - 3].code != (BPF_LD | BPF_DW | BPF_IMM) ||
	    !loader_lddw(insns, count, i - 3, BPF_REG_2, attr) ||
	    insns[i - 1].code != (BPF_ALU64 | BPF_MOV | BPF_K) ||
	    insns[i - 1].dst_reg != BPF_REG_3)
		return false;
	*cmd = (__u32)insns[i - 4].imm;
	*attr_size = (__u32)insns[i - 1].imm;
	return true;
}

static bool map_create_slot(const struct bpf_insn *insns, size_t count,
			    size_t call, size_t next_call, __u32 *slot)
{
	size_t i;

	for (i = call + 1; i + 2 < next_call; i++) {
		__u32 off;

		if (loader_lddw(insns, count, i, BPF_REG_1, &off) &&
		    insns[i + 2].code == (BPF_STX | BPF_W | BPF_MEM) &&
		    insns[i + 2].dst_reg == BPF_REG_1 &&
		    insns[i + 2].src_reg == BPF_REG_7 &&
		    !insns[i + 2].off && !(off % sizeof(__u32)) &&
		    off / sizeof(__u32) < RODATA_MAPS_MAX) {
			*slot = off / sizeof(__u32);
			return true;
		}
	}
	return false;
}

static bool map_update_slot(const struct bpf_insn *insns, size_t count,
			    size_t call, __u32 attr, __u32 *slot)
{
	size_t start = call > 48 ? call - 48 : 0;
	size_t i;
	__u32 map_fd_off = attr + offsetof(union bpf_attr, map_fd);

	for (i = start; i + 5 < call; i++) {
		__u32 fd_array_off, dest_off;

		if (!loader_lddw(insns, count, i, BPF_REG_2, &fd_array_off) ||
		    insns[i + 2].code != (BPF_LDX | BPF_W | BPF_MEM) ||
		    insns[i + 2].dst_reg != BPF_REG_0 ||
		    insns[i + 2].src_reg != BPF_REG_2 || insns[i + 2].off ||
		    !loader_lddw(insns, count, i + 3, BPF_REG_1, &dest_off) ||
		    dest_off != map_fd_off ||
		    insns[i + 5].code != (BPF_STX | BPF_W | BPF_MEM) ||
		    insns[i + 5].dst_reg != BPF_REG_1 ||
		    insns[i + 5].src_reg != BPF_REG_0 || insns[i + 5].off ||
		    fd_array_off % sizeof(__u32) ||
		    fd_array_off / sizeof(__u32) >= RODATA_MAPS_MAX)
			continue;
		*slot = fd_array_off / sizeof(__u32);
		return true;
	}
	return false;
}

static bool map_update_value(const struct bpf_insn *insns, size_t count,
			     size_t call, __u32 attr, __u32 *value_off)
{
	size_t start = call > 24 ? call - 24 : 0;
	size_t i;
	__u32 value_field = attr + offsetof(union bpf_attr, value);

	for (i = start; i + 4 < call; i++) {
		__u32 source_off, dest_off;

		if (!loader_lddw(insns, count, i, BPF_REG_0, &source_off) ||
		    !loader_lddw(insns, count, i + 2, BPF_REG_1, &dest_off) ||
		    dest_off != value_field ||
		    insns[i + 4].code != (BPF_STX | BPF_DW | BPF_MEM) ||
		    insns[i + 4].dst_reg != BPF_REG_1 ||
		    insns[i + 4].src_reg != BPF_REG_0 || insns[i + 4].off)
			continue;
		*value_off = source_off;
		return true;
	}
	return false;
}

static bool map_name_rodata(const char *name)
{
	static const char suffix[] = ".rodata";
	size_t name_len = strlen(name), suffix_len = sizeof(suffix) - 1;

	return name_len >= suffix_len &&
	       !strcmp(name + name_len - suffix_len, suffix);
}

static int find_rodata_data(const struct shirudo_upatch *u,
			    const struct btf *btf, __u32 datasec_id,
			    struct rodata_view *view)
{
	const struct btf_type *sec = btf__type_by_id(btf, datasec_id);
	const struct bpf_insn *insns = upatch_loader(u);
	const __u8 *data = upatch_data(u);
	struct rodata_map maps[RODATA_MAPS_MAX] = {};
	size_t count = u->hdr.loader_insns_len / sizeof(*insns), i;
	__u32 sec_size;
	int rc = -ENODATA;

	if (!sec || BTF_INFO_KIND(sec->info) != BTF_KIND_DATASEC ||
	    u->hdr.loader_insns_len % sizeof(*insns))
		return -EINVAL;
	sec_size = sec->size;
	for (i = 4; i < count; i++) {
		__u32 cmd, attr_off, attr_size;

		if (!sys_bpf_call(insns, count, i, &cmd, &attr_off,
				  &attr_size))
			continue;
		if (cmd == BPF_MAP_CREATE) {
			union bpf_attr attr = {};
			__u32 end, next;
			char name[BPF_OBJ_NAME_LEN + 1];

			if (attr_size > sizeof(attr) ||
			    attr_size < offsetof(union bpf_attr, map_name) +
					 BPF_OBJ_NAME_LEN ||
			    attr_off > u->hdr.data_len ||
			    attr_size > u->hdr.data_len - attr_off)
				return -EINVAL;
			memcpy(&attr, data + attr_off, attr_size);
			memcpy(name, attr.map_name, BPF_OBJ_NAME_LEN);
			name[BPF_OBJ_NAME_LEN] = '\0';
			end = (__u32)count;
			for (next = (__u32)i + 1; next < count; next++) {
				__u32 ignored_cmd, ignored_attr, ignored_size;

				if (sys_bpf_call(insns, count, next, &ignored_cmd,
						 &ignored_attr, &ignored_size)) {
					end = next;
					break;
				}
			}
			if (map_name_rodata(name)) {
				__u32 slot;

				if (!map_create_slot(insns, count, i, end, &slot))
					return -EOPNOTSUPP;
				maps[slot].value_size = attr.value_size;
				maps[slot].found = true;
				strscpy(maps[slot].name, name,
					sizeof(maps[slot].name));
			}
		} else if (cmd == BPF_MAP_UPDATE_ELEM) {
			__u32 slot, value_off;

			if (!map_update_slot(insns, count, i, attr_off, &slot) ||
			    !map_update_value(insns, count, i, attr_off,
					      &value_off))
				continue;
			if (!maps[slot].found)
				continue;
			if (maps[slot].value_size != sec_size ||
			    value_off > u->hdr.data_len ||
			    maps[slot].value_size > u->hdr.data_len - value_off)
				return -EINVAL;
			view->bytes = data + value_off;
			view->data_offset = value_off;
			view->size = sec_size;
			view->type_id = datasec_id;
			return 0;
		}
	}
	return rc;
}

static int btf_rodata_btf(const struct shirudo_upatch *u,
			  struct rodata_view *view)
{
	const __u8 *data = upatch_data(u);
	struct btf *found = NULL;
	__u32 found_id = 0;
	size_t i;

	for (i = 0; i + sizeof(struct btf_header) <= u->hdr.data_len; i++) {
		struct btf_header hdr;
		__u32 end, type_end, str_end, layout_end;
		struct btf *btf;
	__s32 id;

		if (data[i] != (BTF_MAGIC & 0xff) ||
		    data[i + 1] != (BTF_MAGIC >> 8))
			continue;
		memcpy(&hdr, data + i, sizeof(hdr));
		hdr.hdr_len = le32toh(hdr.hdr_len);
		hdr.type_off = le32toh(hdr.type_off);
		hdr.type_len = le32toh(hdr.type_len);
		hdr.str_off = le32toh(hdr.str_off);
		hdr.str_len = le32toh(hdr.str_len);
		hdr.layout_off = le32toh(hdr.layout_off);
		hdr.layout_len = le32toh(hdr.layout_len);
		if (hdr.hdr_len < offsetof(struct btf_header, layout_off) ||
		    hdr.hdr_len > u->hdr.data_len - i)
			continue;
		if (hdr.hdr_len < sizeof(hdr)) {
			hdr.layout_off = 0;
			hdr.layout_len = 0;
		}
		type_end = hdr.type_off + hdr.type_len;
		str_end = hdr.str_off + hdr.str_len;
		layout_end = hdr.layout_off + hdr.layout_len;
		if (type_end < hdr.type_off || str_end < hdr.str_off ||
		    layout_end < hdr.layout_off)
			continue;
		end = hdr.hdr_len + (type_end > str_end ? type_end : str_end);
		if (layout_end > end - hdr.hdr_len)
			end = hdr.hdr_len + layout_end;
		if (end < hdr.hdr_len || end > u->hdr.data_len - i)
			continue;
		btf = btf__new(data + i, end);
		if (libbpf_get_error(btf))
			continue;
		id = btf__find_by_name_kind(btf, ".rodata", BTF_KIND_DATASEC);
		if (id <= 0) {
			btf__free(btf);
			continue;
		}
		if (found) {
			btf__free(btf);
			btf__free(found);
			return -E2BIG;
		}
		found = btf;
		found_id = (__u32)id;
	}
	if (!found)
		return -ENOENT;
	view->btf = found;
	if (u->rodata_offset_valid) {
		const struct btf_type *sec = btf__type_by_id(found, found_id);
		__u32 size = sec ? sec->size : 0;

		if (!size || u->hdr.rodata_data_off > u->hdr.data_len ||
		    size > u->hdr.data_len - u->hdr.rodata_data_off) {
			btf__free(found);
			view->btf = NULL;
			return -EINVAL;
		}
	view->bytes = (const __u8 *)upatch_data(u) +
			u->hdr.rodata_data_off;
		view->data_offset = u->hdr.rodata_data_off;
		view->size = size;
		view->type_id = found_id;
		return 0;
	}
	return find_rodata_data(u, found, found_id, view);
}

int upatch_rodata_data_offset(const struct shirudo_upatch *u, __u32 *offset)
{
	struct rodata_view view = {};
	int rc;

	if (!u || !offset)
		return -EINVAL;
	rc = btf_rodata_btf(u, &view);
	if (!rc)
		*offset = view.data_offset;
	btf__free(view.btf);
	return rc;
}

int upatch_rodata_symbol_range(const struct shirudo_upatch *u,
			       const char *symbol,
			       struct shirudo_rodata_range *range)
{
	struct rodata_view view = {};
	const struct btf_type *sec;
	const struct btf_var_secinfo *vars;
	bool found = false;
	__u32 i;
	int rc;

	if (!u || !symbol || !symbol[0] || !range)
		return -EINVAL;
	rc = btf_rodata_btf(u, &view);
	if (rc) {
		btf__free(view.btf);
		return rc;
	}
	sec = btf__type_by_id(view.btf, view.type_id);
	if (!sec || BTF_INFO_KIND(sec->info) != BTF_KIND_DATASEC) {
		rc = -EINVAL;
		goto out;
	}
	vars = (const struct btf_var_secinfo *)(sec + 1);
	for (i = 0; i < BTF_INFO_VLEN(sec->info); i++) {
		const struct btf_type *var;
		const char *name;
		__u32 offset, size;

		var = btf__type_by_id(view.btf, vars[i].type);
		if (!var || BTF_INFO_KIND(var->info) != BTF_KIND_VAR)
			continue;
		name = btf__name_by_offset(view.btf, var->name_off);
		if (!name)
			continue;
		if (strcmp(name, symbol))
			continue;
		if (found) {
			rc = -EEXIST;
			goto out;
		}
		offset = vars[i].offset;
		size = vars[i].size;
		if (offset > view.size || size > view.size - offset ||
		    view.data_offset > u->hdr.data_len ||
		    offset > u->hdr.data_len - view.data_offset ||
		    size > u->hdr.data_len - view.data_offset - offset) {
			rc = -EINVAL;
			goto out;
		}
		range->offset = view.data_offset + offset;
		range->size = size;
		found = true;
	}
	rc = found ? 0 : -ENOENT;
out:
	btf__free(view.btf);
	return rc;
}

int upatch_rodata_watch_ranges(const struct shirudo_upatch *u,
			       struct shirudo_rodata_range ranges[2])
{
	int rc;

	if (!ranges)
		return -EINVAL;
	rc = upatch_rodata_symbol_range(u, "obs_watch_v4", &ranges[0]);
	if (rc)
		return rc;
	return upatch_rodata_symbol_range(u, "obs_watch_v6", &ranges[1]);
}

static __u32 btf_unwrap(const struct btf *btf, __u32 id)
{
	const struct btf_type *t;
	__u32 i;

	for (i = 0; i < RODATA_JSON_MAX_DEPTH; i++) {
		t = btf__type_by_id(btf, id);
		if (!t)
			return 0;
		switch (BTF_INFO_KIND(t->info)) {
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_TYPE_TAG:
			id = t->type;
			break;
		default:
			return id;
		}
	}
	return 0;
}

static int append_type_name(const struct btf *btf, __u32 id, char *buf,
			    size_t cap, size_t *off, __u32 depth)
{
	const struct btf_type *t;
	const char *name;
	__u16 kind;
	int n;

	if (depth >= RODATA_JSON_MAX_DEPTH || *off >= cap)
		return -E2BIG;
	t = btf__type_by_id(btf, id);
	if (!t)
		return -EINVAL;
	kind = BTF_INFO_KIND(t->info);
	name = btf__name_by_offset(btf, t->name_off);
	if (kind == BTF_KIND_TYPEDEF && name && name[0]) {
		n = strsprintf(buf + *off, cap - *off, "%s", name);
		if (n < 0)
			return -ENOSPC;
		*off += (size_t)n;
		return 0;
	}
	if (kind == BTF_KIND_TYPEDEF || kind == BTF_KIND_VOLATILE ||
	    kind == BTF_KIND_CONST || kind == BTF_KIND_RESTRICT ||
	    kind == BTF_KIND_TYPE_TAG)
		return append_type_name(btf, t->type, buf, cap, off, depth + 1);
	if (kind == BTF_KIND_ARRAY) {
		const struct btf_array *a = (const struct btf_array *)(t + 1);

		if (append_type_name(btf, a->type, buf, cap, off, depth + 1))
			return -EINVAL;
		n = strsprintf(buf + *off, cap - *off, "[%u]", a->nelems);
		if (n < 0)
			return -ENOSPC;
		*off += (size_t)n;
		return 0;
	}
	if (kind == BTF_KIND_PTR) {
		if (append_type_name(btf, t->type, buf, cap, off, depth + 1))
			return -EINVAL;
		if (*off + 2 > cap)
			return -ENOSPC;
		memcpy(buf + *off, " *", 2);
		*off += 2;
		return 0;
	}
	if (name && name[0]) {
		n = strsprintf(buf + *off, cap - *off, "%s%s",
			       kind == BTF_KIND_STRUCT ? "struct " :
			       kind == BTF_KIND_UNION ? "union " :
			       kind == BTF_KIND_ENUM ? "enum " : "", name);
	} else {
		const char *fallback = "?";

		switch (kind) {
		case BTF_KIND_INT:
			fallback = "integer";
			break;
		case BTF_KIND_STRUCT:
			fallback = "struct";
			break;
		case BTF_KIND_UNION:
			fallback = "union";
			break;
		case BTF_KIND_ENUM:
		case BTF_KIND_ENUM64:
			fallback = "enum";
			break;
		case BTF_KIND_FLOAT:
			fallback = "float";
			break;
		case BTF_KIND_FWD:
			fallback = "forward declaration";
			break;
		}
		n = strsprintf(buf + *off, cap - *off, "%s", fallback);
	}
	if (n < 0)
		return -ENOSPC;
	*off += (size_t)n;
	return 0;
}

static int json_number(struct shirudo_json_emit *e, __u64 value,
		       bool is_signed)
{
	char number[32];
	int n;

	if (is_signed)
		n = strsprintf(number, sizeof(number), "%lld", (__s64)value);
	else
		n = strsprintf(number, sizeof(number), "%llu",
			       (__u64)value);
	if (n < 0)
		return n;
	json_raw_value(e, number, (size_t)n);
	return e->err;
}

static int btf_integer(const struct btf_type *t, const void *bytes,
		       size_t size, __u64 *value, bool *is_signed,
		       bool *is_bool)
{
	__u32 enc, bits, bit_off;
	__u32 i;
	__u64 result = 0;

	if (t->size > size || !t->size || t->size > sizeof(result))
		return -EINVAL;
	enc = *(__u32 *)(t + 1);
	bits = BTF_INT_BITS(enc);
	bit_off = BTF_INT_OFFSET(enc);
	if (!bits || bits > 64 || bit_off + bits > t->size * 8)
		return -EINVAL;
	for (i = 0; i < bits; i++) {
		__u32 b = bit_off + i;

		if (((const __u8 *)bytes)[b / 8] & (1u << (b % 8)))
			result |= (__u64)1 << i;
	}
	*is_signed = (BTF_INT_ENCODING(enc) & BTF_INT_SIGNED) != 0;
	*is_bool = (BTF_INT_ENCODING(enc) & BTF_INT_BOOL) != 0;
	if (*is_signed && bits < 64 && (result & ((__u64)1 << (bits - 1))))
		result |= ~(((__u64)1 << bits) - 1);
	*value = result;
	return 0;
}

static void json_hex(struct shirudo_json_emit *e, const void *bytes,
		     size_t size)
{
	static const char hex[] = "0123456789abcdef";
	char *text;
	const __u8 *p = bytes;
	size_t i, cap;

	if (size > (SHIRUDO_JSON_MAX_BYTES - 3) / 2) {
		e->err = -E2BIG;
		return;
	}
	cap = size * 2 + 3;
	text = xmalloc(cap);
	if (!text) {
		e->err = -ENOMEM;
		return;
	}
	text[0] = '0';
	text[1] = 'x';
	for (i = 0; i < size; i++) {
		text[2 + i * 2] = hex[p[i] >> 4];
		text[3 + i * 2] = hex[p[i] & 0x0f];
	}
	text[2 + size * 2] = '\0';
	json_str_value(e, text);
	xfree(text, cap);
}

static int json_btf_value(struct shirudo_json_emit *e, const struct btf *btf,
			  __u32 type_id, const __u8 *bytes, size_t size,
			  __u32 depth)
{
	const struct btf_type *t;
	__u16 kind;
	int rc;

	if (depth >= RODATA_JSON_MAX_DEPTH || !type_id || !bytes)
		return -EINVAL;
	type_id = btf_unwrap(btf, type_id);
	t = btf__type_by_id(btf, type_id);
	if (!t)
		return -EINVAL;
	kind = BTF_INFO_KIND(t->info);
	if (kind == BTF_KIND_INT) {
		__u64 value;
		bool sign, boolean;

		rc = btf_integer(t, bytes, size, &value, &sign, &boolean);
		if (rc)
			return rc;
		if (boolean)
			json_raw_value(e, value ? "true" : "false", value ? 4 : 5);
		else
			return json_number(e, value, sign);
		return e->err;
	}
	if (kind == BTF_KIND_ENUM || kind == BTF_KIND_ENUM64) {
		__u64 value = 0;
		bool sign = BTF_INFO_KFLAG(t->info);
		__u32 i, vlen = BTF_INFO_VLEN(t->info);
		const char *enum_name = NULL;

		if (!t->size || t->size > sizeof(value) || t->size > size)
			return -EINVAL;
		for (i = 0; i < t->size; i++)
			value |= (__u64)bytes[i] << (i * 8);
		if (sign && t->size < sizeof(value) &&
		    (value & ((__u64)1 << (t->size * 8 - 1))))
			value |= ~(((__u64)1 << (t->size * 8)) - 1);
		if (kind == BTF_KIND_ENUM) {
			const struct btf_enum *vals = (const struct btf_enum *)(t + 1);
			__u32 v = (__u32)value;

			for (i = 0; i < vlen; i++)
				if ((__u32)vals[i].val == v) {
					enum_name = btf__name_by_offset(btf,
									vals[i].name_off);
					break;
				}
		} else {
			const struct btf_enum64 *vals =
				(const struct btf_enum64 *)(t + 1);

			for (i = 0; i < vlen; i++) {
				__u64 v = (__u64)vals[i].val_lo32 |
					  (__u64)vals[i].val_hi32 << 32;

				if (v == value) {
					enum_name = btf__name_by_offset(btf,
									vals[i].name_off);
					break;
				}
			}
		}
		json_obj_value_open(e);
		if (enum_name && enum_name[0])
			json_kv_string(e, "name", enum_name);
		json_key(e, "value");
		json_number(e, value, sign);
		json_obj_close(e);
		return e->err;
	}
	if (kind == BTF_KIND_STRUCT) {
		const struct btf_member *m = (const struct btf_member *)(t + 1);
		__u32 vlen = BTF_INFO_VLEN(t->info), i;

		json_obj_value_open(e);
		for (i = 0; i < vlen && !e->err; i++) {
			__u32 bit_off = BTF_INFO_KFLAG(t->info) ?
				BTF_MEMBER_BIT_OFFSET(m[i].offset) : m[i].offset;
			__u32 bit_size = BTF_INFO_KFLAG(t->info) ?
				BTF_MEMBER_BITFIELD_SIZE(m[i].offset) : 0;
			__u32 byte_off = bit_off / 8;
			const char *name = btf__name_by_offset(btf,
								m[i].name_off);
			__s64 member_size = btf__resolve_size(btf, m[i].type);
			char fallback[24];

			if (!name || !name[0]) {
				if (strsprintf(fallback, sizeof(fallback), "member_%u",
					       i) < 0)
					return -EINVAL;
				name = fallback;
			}
			json_key(e, name);
			if (bit_size) {
				__u32 n = (bit_off % 8 + bit_size + 7) / 8;
				__u32 j;
				const struct btf_type *member_type =
					btf__type_by_id(btf,
							btf_unwrap(btf, m[i].type));
				__u32 enc;
				__u64 val = 0;
				bool sign;

				if (bit_size > 64 || byte_off + n > size ||
				    !member_type ||
				    BTF_INFO_KIND(member_type->info) != BTF_KIND_INT)
					return -EINVAL;
				enc = *(__u32 *)(member_type + 1);
				sign = BTF_INT_ENCODING(enc) & BTF_INT_SIGNED;
				for (j = 0; j < bit_size; j++) {
					__u32 pos = bit_off + j;

					if (bytes[pos / 8] & (1u << (pos % 8)))
						val |= (__u64)1 << j;
				}
				if (sign && bit_size < 64 &&
				    (val & ((__u64)1 << (bit_size - 1))))
					val |= ~(((__u64)1 << bit_size) - 1);
				json_number(e, val, sign);
			} else {
				if (member_size < 0 || byte_off > size ||
				    (size_t)member_size > size - byte_off)
					return -EINVAL;
				rc = json_btf_value(e, btf, m[i].type,
						    bytes + byte_off,
						    (size_t)member_size,
						    depth + 1);
				if (rc)
					return rc;
			}
		}
		json_obj_close(e);
		return e->err;
	}
	if (kind == BTF_KIND_ARRAY) {
		const struct btf_array *a = (const struct btf_array *)(t + 1);
		__s64 elem_size = btf__resolve_size(btf, a->type);
		__u32 i;

		if (elem_size < 0)
			return -EINVAL;
		if (elem_size && (__u64)elem_size * a->nelems > size)
			return -EINVAL;
		json_arr_open_value(e);
		for (i = 0; i < a->nelems && !e->err; i++) {
			if (!elem_size)
				return -EINVAL;
			rc = json_btf_value(e, btf, a->type,
					    bytes + (size_t)i * elem_size,
					    (size_t)elem_size, depth + 1);
			if (rc)
				return rc;
		}
		json_arr_close(e);
		return e->err;
	}
	if (kind == BTF_KIND_PTR) {
		__u64 value = 0;
		char text[32];
		int n;

		if (size > sizeof(value))
			return -EINVAL;
		memcpy(&value, bytes, size);
		n = strsprintf(text, sizeof(text), "0x%llx",
			       (__u64)value);
		if (n < 0)
			return n;
		json_str_value(e, text);
		return e->err;
	}
	json_hex(e, bytes, size);
	return e->err;
}

static const char *btf_var_name(const struct btf *btf,
				const struct btf_var_secinfo *var)
{
	const struct btf_type *t = btf__type_by_id(btf, var->type);

	return t && BTF_INFO_KIND(t->info) == BTF_KIND_VAR ?
	       btf__name_by_offset(btf, t->name_off) : NULL;
}

static int btf_var_type(const struct btf *btf,
			const struct btf_var_secinfo *var, __u32 *type_id)
{
	const struct btf_type *t = btf__type_by_id(btf, var->type);

	if (!t || BTF_INFO_KIND(t->info) != BTF_KIND_VAR)
		return -EINVAL;
	*type_id = t->type;
	return 0;
}

static void print_text(void *ctx, const char *fmt, va_list args)
{
	FILE *fp = ctx;

	vfprintf(fp, fmt, args);
}

static int print_rodata_text(const struct shirudo_upatch *u,
			     const char *path, const struct rodata_view *view)
{
	struct btf_dump_type_data_opts opts = {
		.sz = sizeof(opts),
		.indent_str = "  ",
		.emit_zeroes = true,
		.emit_strings = true,
	};
	struct btf_dump *dump;
	const struct btf_type *sec = btf__type_by_id(view->btf,
							    view->type_id);
	const struct btf_var_secinfo *vars =
		(const struct btf_var_secinfo *)(sec + 1);
	__u32 i, vlen = BTF_INFO_VLEN(sec->info);
	char name[SHIRUDO_UPATCH_NAME_MAX + 1];
	int rc = 0;

	memcpy(name, u->hdr.name, SHIRUDO_UPATCH_NAME_MAX);
	name[SHIRUDO_UPATCH_NAME_MAX] = '\0';
	printf("upatch %s (%s) .rodata: %u bytes at data+%u, file+%u\n",
	       name, path, view->size, view->data_offset,
	       u->hdr.data_off + view->data_offset);
	dump = btf_dump__new(view->btf, print_text, stdout, NULL);
	if (libbpf_get_error(dump))
		return -EINVAL;
	for (i = 0; i < vlen; i++) {
		__u32 type_id;
		const char *var_name = btf_var_name(view->btf, &vars[i]);
		char type[256] = {};
		size_t type_off = 0;

		if (!var_name || !var_name[0] ||
		    btf_var_type(view->btf, &vars[i], &type_id)) {
			rc = -EINVAL;
			goto out;
		}
		rc = append_type_name(view->btf, type_id, type,
				      sizeof(type), &type_off, 0);
		if (rc)
			goto out;
		if (vars[i].offset > view->size ||
		    vars[i].size > view->size - vars[i].offset) {
			rc = -EINVAL;
			goto out;
		}
		printf("\n%s: %s, size=%u, rodata+%u, data+%u, file+%u = ",
		       var_name, type, vars[i].size, vars[i].offset,
		       view->data_offset + vars[i].offset,
		       u->hdr.data_off + view->data_offset + vars[i].offset);
		rc = btf_dump__dump_type_data(dump, type_id,
					      view->bytes + vars[i].offset,
					      vars[i].size, &opts);
		if (rc < 0)
			goto out;
		putchar('\n');
	}
	putchar('\n');
	btf_dump__free(dump);
	return 0;
out:
	btf_dump__free(dump);
	return rc;
}

static int print_rodata_json(const struct shirudo_upatch *u,
			     const char *path, const struct rodata_view *view)
{
	const struct btf_type *sec = btf__type_by_id(view->btf,
							    view->type_id);
	const struct btf_var_secinfo *vars =
		(const struct btf_var_secinfo *)(sec + 1);
	char name[SHIRUDO_UPATCH_NAME_MAX + 1];
	char *buf = xmalloc(SHIRUDO_JSON_MAX_BYTES);
	struct shirudo_json_emit e = {};
	__u32 i, vlen = BTF_INFO_VLEN(sec->info);
	int rc = 0;

	if (!buf)
		return -ENOMEM;
	e.buf = buf;
	e.cap = SHIRUDO_JSON_MAX_BYTES;
	memcpy(name, u->hdr.name, SHIRUDO_UPATCH_NAME_MAX);
	name[SHIRUDO_UPATCH_NAME_MAX] = '\0';
	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_kv_string(&e, "upatch", name);
	json_kv_string(&e, "path", path);
	json_kv_string(&e, "section", ".rodata");
	json_kv_int(&e, "size", view->size);
	json_kv_int(&e, "data_offset", view->data_offset);
	json_kv_int(&e, "file_offset", u->hdr.data_off + view->data_offset);
	json_arr_open(&e, "variables");
	for (i = 0; i < vlen && !e.err; i++) {
		const char *var_name = btf_var_name(view->btf, &vars[i]);
		char type[256] = {};
		size_t type_off = 0;
		__u32 type_id;

		if (!var_name || !var_name[0] ||
		    btf_var_type(view->btf, &vars[i], &type_id)) {
			rc = -EINVAL;
			break;
		}
		rc = append_type_name(view->btf, type_id, type,
				      sizeof(type), &type_off, 0);
		if (rc)
			break;
		if (vars[i].offset > view->size ||
		    vars[i].size > view->size - vars[i].offset) {
			rc = -EINVAL;
			break;
		}
		json_obj_open(&e);
		json_kv_string(&e, "name", var_name);
		json_kv_string(&e, "type", type);
		json_kv_int(&e, "size", vars[i].size);
		json_kv_int(&e, "rodata_offset", vars[i].offset);
		json_kv_int(&e, "data_offset",
			    view->data_offset + vars[i].offset);
		json_kv_int(&e, "file_offset",
			    u->hdr.data_off + view->data_offset + vars[i].offset);
		json_key(&e, "value");
		rc = json_btf_value(&e, view->btf, type_id,
				    view->bytes + vars[i].offset,
				    vars[i].size, 0);
		json_obj_close(&e);
		if (rc)
			break;
	}
	json_arr_close(&e);
	json_obj_close(&e);
	if (!rc && e.err)
		rc = e.err;
	if (!rc)
		rc = write_complete(STDOUT_FILENO, buf, e.len);
	if (!rc)
		rc = write_complete(STDOUT_FILENO, "\n", 1);
	if (rc == -ENOSPC)
		pr_err("BTF JSON output exceeds %u bytes", SHIRUDO_JSON_MAX_BYTES);
	xfree(buf, SHIRUDO_JSON_MAX_BYTES);
	return rc;
}

int upatch_rodata_print(const struct shirudo_upatch *u, const char *path,
			bool json)
{
	struct rodata_view view = {};
	int rc;

	if (upatch_is_unload(u))
		return -EINVAL;
	rc = btf_rodata_btf(u, &view);
	if (rc)
		goto out;
	rc = json ? print_rodata_json(u, path, &view) :
		    print_rodata_text(u, path, &view);
out:
	if (view.btf)
		btf__free(view.btf);
	return rc;
}
