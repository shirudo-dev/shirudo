// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Signed Lua decoders for serialized maps: a small LuaJIT host API and
 * the serialisation of what they return.
 */

#include <errno.h>

#include "upatch_decode.h"

#ifndef HAVE_LUAJIT

int upatch_decode_map_json(const struct map_view *v,
			   char **out, size_t *out_len)
{
	if (!v || !out || !out_len)
		return -EINVAL;
	*out = NULL;
	*out_len = 0;
	return -EOPNOTSUPP;
}

int upatch_decode_map_json_limit(const struct map_view *v,
				 size_t max_bytes,
				 char **out, size_t *out_len)
{
	return upatch_decode_map_json(v, out, out_len);
}

int upatch_decode_map_otel(const struct map_view *v,
			   char **out, size_t *out_len)
{
	return upatch_decode_map_json(v, out, out_len);
}

int upatch_decode_map_file_json(const char *path,
				const struct map_view *v,
				char **out, size_t *out_len)
{
	return upatch_decode_map_json(v, out, out_len);
}

int upatch_decode_map_file_json_limit(const char *path,
				      const struct map_view *v,
				      size_t max_bytes, char **out,
				      size_t *out_len)
{
	return upatch_decode_map_json(v, out, out_len);
}

int upatch_decode_map_file_otel(const char *path,
				const struct map_view *v,
				char **out, size_t *out_len)
{
	return upatch_decode_map_json(v, out, out_len);
}

#else /* HAVE_LUAJIT */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <luajit.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include "crypto.h"
#include "json.h"
#include "hex.h"
#include "log.h"
#include "malloc.h"
#include "paths.h"
#include "seal.h"
#include "upatch.h"
#include "upatch_decode.h"
#include "upatch_maps.h"
#include "bpf/lib/serializer.h"

#define LUA_INSN_LIMIT		1000000
#define LUA_HOOK_COUNT		10000
#define LUA_MEMORY_LIMIT	(32u * 1024u * 1024u)
#define LUA_JSON_MAX_DEPTH	32
#define LUA_SLOT_MT		"shirudo.slot"

#ifndef lua_absindex
static int lua_absindex(lua_State *L, int idx)
{
	if (idx > 0 || idx <= LUA_REGISTRYINDEX)
		return idx;
	return lua_gettop(L) + idx + 1;
}
#endif

struct lua_slot {
	__u32		len;
	__u8		data[];
};

struct lua_budget {
	int	remaining;
};

struct lua_memory {
	lua_Alloc	inner;
	void		*inner_ud;
	size_t		used;
	size_t		limit;
};

static struct lua_budget *current_lua_budget;

/*
 * Wraps LuaJIT's own allocator rather than xmalloc(): a GC64 state must
 * live below 2^47, which LuaJIT's allocator guarantees and a PIE's heap
 * on arm64 does not meet. What is freed is scrubbed first, as xfree()
 * would.
 */
static void *lua_limited_alloc(void *ud, void *ptr, size_t old_size,
			       size_t new_size)
{
	struct lua_memory *memory = ud;
	size_t base = ptr && memory->used >= old_size ?
		memory->used - old_size : memory->used;
	size_t total;
	void *next;

	if (new_size == 0) {
		if (ptr) {
			memzero_explicit(ptr, old_size);
			memory->inner(memory->inner_ud, ptr, old_size, 0);
			memory->used = base;
		}
		return NULL;
	}
	if (check_add_overflow(base, new_size, &total) ||
	    total > memory->limit)
		return NULL;
	next = memory->inner(memory->inner_ud, NULL, 0, new_size);
	if (!next)
		return NULL;
	memset(next, 0, new_size);
	if (ptr) {
		memcpy(next, ptr, min(old_size, new_size));
		memzero_explicit(ptr, old_size);
		memory->inner(memory->inner_ud, ptr, old_size, 0);
	}
	memory->used = total;
	return next;
}

static int lua_table_is_array(lua_State *L, int idx, size_t *len_out)
{
	size_t count = 0, max = 0;
	int is_array = 1;

	idx = lua_absindex(L, idx);
	lua_pushnil(L);
	while (lua_next(L, idx) != 0) {
		if (lua_type(L, -2) == LUA_TNUMBER) {
			lua_Number n = lua_tonumber(L, -2);
			size_t k;

			if (!isfinite((double)n) || n < 1 || n > INT_MAX) {
				is_array = 0;
			} else {
				k = (size_t)n;
				if ((lua_Number)k != n) {
					is_array = 0;
					lua_pop(L, 1);
					continue;
				}
				if (k > max)
					max = k;
				count++;
			}
		} else {
			is_array = 0;
		}
		lua_pop(L, 1);
	}
	if (is_array && count == max) {
		*len_out = max;
		return 1;
	}
	*len_out = 0;
	return 0;
}

/*
 * A table key as text: a string as it is, a number and a boolean
 * spelled out. Names the kernel hands over are raw bytes, cut at a fixed
 * length mid-character as often as not, and one bad byte must not cost
 * the whole snapshot, which the serializer has already drained: the
 * lossy writers export it as U+FFFD.
 */
static void lua_json_emit_key(lua_State *L, int idx, struct json_emit *e,
			      bool as_key)
{
	const char *s = "unsupported_key";
	size_t n = strlen(s);
	char num[64];

	switch (lua_type(L, idx)) {
	case LUA_TSTRING:
		s = lua_tolstring(L, idx, &n);
		if (!s) {
			s = "";
			n = 0;
		}
		break;
	case LUA_TNUMBER:
		if (strsprintf(num, sizeof(num), "%.17g",
			       (double)lua_tonumber(L, idx)) < 0) {
			e->err = -E2BIG;
			return;
		}
		s = num;
		n = strlen(num);
		break;
	case LUA_TBOOLEAN:
		s = lua_toboolean(L, idx) ? "true" : "false";
		n = strlen(s);
		break;
	default:
		break;
	}
	if (as_key)
		json_key_lossy(e, s, n);
	else
		json_str_lossy(e, s, n);
}

static int lua_json_emit_value(lua_State *L, int idx, struct json_emit *e,
			       int depth);

static int lua_json_emit_table(lua_State *L, int idx, struct json_emit *e,
			       int depth)
{
	size_t len = 0, i;

	idx = lua_absindex(L, idx);
	if (lua_table_is_array(L, idx, &len)) {
		json_arr_open_value(e);
		for (i = 1; i <= len && !e->err; i++) {
			lua_rawgeti(L, idx, (int)i);
			lua_json_emit_value(L, -1, e, depth + 1);
			lua_pop(L, 1);
		}
		json_arr_close(e);
		return e->err;
	}

	json_obj_value_open(e);
	lua_pushnil(L);
	while (lua_next(L, idx) != 0) {
		int key_type = lua_type(L, -2);

		if (key_type != LUA_TSTRING && key_type != LUA_TNUMBER &&
		    key_type != LUA_TBOOLEAN) {
			e->err = -EINVAL;
			lua_pop(L, 2);
			break;
		}
		lua_json_emit_key(L, -2, e, true);
		lua_json_emit_value(L, -1, e, depth + 1);
		lua_pop(L, 1);
		if (e->err) {
			lua_pop(L, 1);
			break;
		}
	}
	json_obj_close(e);
	return e->err;
}

static int lua_otel_emit_value(lua_State *L, int idx, struct json_emit *e,
			       int depth);

static int lua_otel_emit_table(lua_State *L, int idx, struct json_emit *e,
			       int depth)
{
	size_t len = 0, i;

	idx = lua_absindex(L, idx);
	json_obj_value_open(e);
	if (lua_table_is_array(L, idx, &len)) {
		json_obj_open_key(e, "arrayValue");
		json_arr_open(e, "values");
		for (i = 1; i <= len && !e->err; i++) {
			lua_rawgeti(L, idx, (int)i);
			lua_otel_emit_value(L, -1, e, depth + 1);
			lua_pop(L, 1);
		}
		json_arr_close(e);
		json_obj_close(e);
		json_obj_close(e);
		return e->err;
	}

	json_obj_open_key(e, "kvlistValue");
	json_arr_open(e, "values");
	lua_pushnil(L);
	while (lua_next(L, idx) != 0) {
		int key_type = lua_type(L, -2);

		if (key_type != LUA_TSTRING && key_type != LUA_TNUMBER &&
		    key_type != LUA_TBOOLEAN) {
			e->err = -EINVAL;
			lua_pop(L, 2);
			break;
		}
		json_obj_value_open(e);
		json_key(e, "key");
		lua_json_emit_key(L, -2, e, false);
		json_key(e, "value");
		lua_otel_emit_value(L, -1, e, depth + 1);
		json_obj_close(e);
		lua_pop(L, 1);
		if (e->err) {
			lua_pop(L, 1);
			break;
		}
	}
	json_arr_close(e);
	json_obj_close(e);
	json_obj_close(e);
	return e->err;
}

static int lua_otel_emit_value(lua_State *L, int idx, struct json_emit *e,
			       int depth)
{
	const double max_exact_integer = 9007199254740991.0;
	char num[64];
	const char *s;
	double value;
	size_t n;

	if (depth > LUA_JSON_MAX_DEPTH) {
		e->err = -E2BIG;
		return e->err;
	}

	switch (lua_type(L, idx)) {
	case LUA_TNIL:
		/* An empty AnyValue represents a Lua nil. */
		json_obj_value_open(e);
		json_obj_close(e);
		break;
	case LUA_TBOOLEAN:
		json_obj_value_open(e);
		json_kv_bool(e, "boolValue", lua_toboolean(L, idx));
		json_obj_close(e);
		break;
	case LUA_TNUMBER:
		value = (double)lua_tonumber(L, idx);
		if (!isfinite(value)) {
			e->err = -EINVAL;
			break;
		}
		json_obj_value_open(e);
		if (shirudo_trunc(value) == value &&
		    fabs(value) <= max_exact_integer) {
			if (strsprintf(num, sizeof(num), "%.0f",
				       value == 0 ? 0 : value) < 0) {
				e->err = -E2BIG;
				break;
			}
			json_kv_string(e, "intValue", num);
		} else {
			if (strsprintf(num, sizeof(num), "%.17g", value) < 0) {
				e->err = -E2BIG;
				break;
			}
			json_kv_raw(e, "doubleValue", num, strlen(num));
		}
		json_obj_close(e);
		break;
	case LUA_TSTRING:
		s = lua_tolstring(L, idx, &n);
		json_obj_value_open(e);
		json_key(e, "stringValue");
		json_str_lossy(e, s ? s : "", s ? n : 0);
		json_obj_close(e);
		break;
	case LUA_TTABLE:
		lua_otel_emit_table(L, idx, e, depth);
		break;
	default:
		e->err = -EINVAL;
		break;
	}
	return e->err;
}

static int lua_json_emit_value(lua_State *L, int idx, struct json_emit *e,
			       int depth)
{
	char num[64];
	const char *s;
	size_t n;

	if (depth > LUA_JSON_MAX_DEPTH) {
		e->err = -E2BIG;
		return e->err;
	}

	switch (lua_type(L, idx)) {
	case LUA_TNIL:
		json_raw_value(e, "null", 4);
		break;
	case LUA_TBOOLEAN:
		s = lua_toboolean(L, idx) ? "true" : "false";
		json_raw_value(e, s, strlen(s));
		break;
	case LUA_TNUMBER:
		if (!isfinite((double)lua_tonumber(L, idx))) {
			e->err = -EINVAL;
			break;
		}
		if (strsprintf(num, sizeof(num), "%.17g",
			       (double)lua_tonumber(L, idx)) < 0) {
			e->err = -E2BIG;
			break;
		}
		json_raw_value(e, num, strlen(num));
		break;
	case LUA_TSTRING:
		s = lua_tolstring(L, idx, &n);
		json_str_lossy(e, s ? s : "", s ? n : 0);
		break;
	case LUA_TTABLE:
		lua_json_emit_table(L, idx, e, depth);
		break;
	default:
		e->err = -EINVAL;
		break;
	}
	return e->err;
}

/*
 * The bytes go into a userdata pushed on the stack, which the collector
 * frees: a Lua error raised while they are in use, a slot index out of
 * range or the memory limit, would leak a buffer of our own.
 */
static int hex_decode_push(lua_State *L, const char *hex, size_t len,
			   __u8 **out, size_t *out_len)
{
	size_t digits = 0, off = 0, i;
	__u8 *buf;

	*out = NULL;
	*out_len = 0;
	for (i = 0; i < len; i++) {
		if (!isspace((__u8)hex[i]))
			digits++;
	}
	if (digits & 1)
		return -EINVAL;
	buf = lua_newuserdata(L, digits / 2);
	for (i = 0; i < len;) {
		int hi, lo;

		while (i < len && isspace((__u8)hex[i]))
			i++;
		if (i >= len)
			break;
		hi = hex_nibble((__u8)hex[i++]);
		while (i < len && isspace((__u8)hex[i]))
			i++;
		if (i >= len) {
			lua_pop(L, 1);
			return -EINVAL;
		}
		lo = hex_nibble((__u8)hex[i++]);
		if (hi < 0 || lo < 0) {
			lua_pop(L, 1);
			return -EINVAL;
		}
		buf[off++] = (__u8)((hi << 4) | lo);
	}
	*out = buf;
	*out_len = off;
	return 0;
}

static struct lua_slot *lua_check_slot(lua_State *L)
{
	return luaL_checkudata(L, 1, LUA_SLOT_MT);
}

static int lua_check_c_int(lua_State *L, int arg)
{
	lua_Integer value = luaL_checkinteger(L, arg);

	if (value < INT_MIN || value > INT_MAX)
		return luaL_argerror(L, arg, "integer out of range");
	return (int)value;
}

static int lua_slot_u8(lua_State *L)
{
	struct lua_slot *slot = lua_check_slot(L);
	int off = lua_check_c_int(L, 2);

	lua_pushinteger(L, off >= 0 && off < (int)slot->len ?
			slot->data[off] : 0);
	return 1;
}

static __u16 rd_u16(const __u8 *p)
{
	return (__u16)p[0] | ((__u16)p[1] << 8);
}

static __u32 rd_u32(const __u8 *p)
{
	return (__u32)p[0] | ((__u32)p[1] << 8) |
	       ((__u32)p[2] << 16) | ((__u32)p[3] << 24);
}

static __u64 rd_u64(const __u8 *p)
{
	return (__u64)rd_u32(p) | ((__u64)rd_u32(p + 4) << 32);
}

static int lua_slot_u16(lua_State *L)
{
	struct lua_slot *slot = lua_check_slot(L);
	int off = lua_check_c_int(L, 2);

	lua_pushinteger(L, off >= 0 && off <= (int)slot->len - 2 ?
			rd_u16(slot->data + off) : 0);
	return 1;
}

static int lua_slot_u32(lua_State *L)
{
	struct lua_slot *slot = lua_check_slot(L);
	int off = lua_check_c_int(L, 2);

	lua_pushnumber(L, off >= 0 && off <= (int)slot->len - 4 ?
		       (lua_Number)rd_u32(slot->data + off) : 0);
	return 1;
}

static int lua_slot_u64(lua_State *L)
{
	struct lua_slot *slot = lua_check_slot(L);
	char buf[32];
	int off = lua_check_c_int(L, 2);
	__u64 v = 0;

	if (off >= 0 && off <= (int)slot->len - 8)
		v = rd_u64(slot->data + off);
	if (strsprintf(buf, sizeof(buf), "%llu", v) < 0)
		lua_pushnil(L);
	else
		lua_pushstring(L, buf);
	return 1;
}

static int lua_slot_cstring(lua_State *L)
{
	struct lua_slot *slot = lua_check_slot(L);
	int off = lua_check_c_int(L, 2);
	int len = lua_gettop(L) >= 3 ? lua_check_c_int(L, 3) : 0;
	int max = lua_gettop(L) >= 4 ? lua_check_c_int(L, 4) : len;
	int n = 0;

	if (off < 0 || off >= (int)slot->len || max <= 0) {
		lua_pushliteral(L, "");
		return 1;
	}
	if (len <= 0 || len > max)
		len = max;
	if (len > (int)slot->len - off)
		len = (int)slot->len - off;
	while (n < len && slot->data[off + n] != '\0')
		n++;
	lua_pushlstring(L, (const char *)slot->data + off, (size_t)n);
	return 1;
}

static void lua_push_slot(lua_State *L, const __u8 *data, size_t len)
{
	struct lua_slot *slot;

	slot = lua_newuserdata(L, sizeof(*slot) + len);
	slot->len = (__u32)len;
	memcpy(slot->data, data, len);
	luaL_getmetatable(L, LUA_SLOT_MT);
	lua_setmetatable(L, -2);
}

static __u64 lua_page_u64(lua_State *L, int idx, const char *field)
{
	lua_Number n;

	idx = lua_absindex(L, idx);
	lua_getfield(L, idx, field);
	n = lua_tonumber(L, -1);
	lua_pop(L, 1);
	if (!isfinite((double)n) || n < 0 || n > 9007199254740991.0)
		return 0;
	return (__u64)n;
}

static int lua_store_slot(lua_State *L, int slots_idx, __u64 abs,
			  const __u8 *data, size_t slot_size)
{
	if (abs >= INT_MAX)
		return luaL_error(L, "slot index too large");
	lua_push_slot(L, data, slot_size);
	lua_rawseti(L, slots_idx, (int)abs + 1);
	return 0;
}

static void lua_split_page_slots(lua_State *L, int slots_idx,
				 const __u8 *data, size_t len,
				 __u64 cursor, __u64 chunks,
				 size_t slot_size)
{
	size_t slots_per_chunk = SERIAL_CHUNK_PAYLOAD / slot_size;

	if (chunks > 1 && slots_per_chunk > 0 &&
	    SERIAL_CHUNK_PAYLOAD % slot_size != 0) {
		size_t off = 0;
		__u64 chunk;

		for (chunk = 0; chunk < chunks && off < len; chunk++) {
			size_t chunk_bytes = len - off;
			size_t local_slots, i;

			if (chunk_bytes > SERIAL_CHUNK_PAYLOAD)
				chunk_bytes = SERIAL_CHUNK_PAYLOAD;
			local_slots = chunk_bytes / slot_size;
			if (local_slots > slots_per_chunk)
				local_slots = slots_per_chunk;
			for (i = 0; i < local_slots; i++) {
				__u64 page_slot = chunk * slots_per_chunk + i;

				lua_store_slot(L, slots_idx, cursor + page_slot,
					       data + off + i * slot_size,
					       slot_size);
			}
			off += chunk_bytes;
		}
		return;
	}

	for (size_t i = 0; i + slot_size <= len; i += slot_size)
		lua_store_slot(L, slots_idx, cursor + i / slot_size,
			       data + i, slot_size);
}

static void lua_push_u64_string(lua_State *L, __u64 value);

static int lua_shirudo_page_slots(lua_State *L)
{
	const char *hex;
	__u8 *data = NULL;
	size_t hex_len, data_len = 0, off = 0, per_chunk;
	__u64 chunks;
	int slot_size, n = 0, ret;

	luaL_checktype(L, 1, LUA_TTABLE);
	slot_size = lua_check_c_int(L, 2);
	if (slot_size <= 0 || slot_size > (int)SERIAL_CHUNK_PAYLOAD)
		return luaL_error(L, "invalid slot size");
	chunks = lua_page_u64(L, 1, "chunks");
	lua_getfield(L, 1, "data_hex");
	hex = lua_tolstring(L, -1, &hex_len);
	if (!hex) {
		lua_pop(L, 1);
		lua_newtable(L);
		return 1;
	}
	ret = hex_decode_push(L, hex, hex_len, &data, &data_len);
	if (ret)
		return luaL_error(L, "invalid page data_hex");
	per_chunk = SERIAL_CHUNK_PAYLOAD / (size_t)slot_size;
	lua_newtable(L);
	while (off < data_len) {
		size_t chunk_bytes = data_len - off, local_slots, i;

		if (chunks > 1 && chunk_bytes > SERIAL_CHUNK_PAYLOAD)
			chunk_bytes = SERIAL_CHUNK_PAYLOAD;
		local_slots = chunk_bytes / (size_t)slot_size;
		if (chunks > 1 && local_slots > per_chunk)
			local_slots = per_chunk;
		for (i = 0; i < local_slots; i++) {
			lua_push_slot(L, data + off + i * (size_t)slot_size,
				      (size_t)slot_size);
			lua_rawseti(L, -2, ++n);
		}
		if (local_slots == 0)
			break;
		off += chunk_bytes;
	}
	return 1;
}

static int lua_check_u64_string(lua_State *L, int arg, __u64 *out)
{
	size_t len;
	const char *s = luaL_checklstring(L, arg, &len);
	int ret = parse_u64(s, len, UINT64_MAX, out);

	if (ret == -ERANGE)
		return luaL_argerror(L, arg, "u64 string out of range");
	if (ret)
		return luaL_argerror(L, arg, "expected a decimal u64 string");
	return 0;
}

/* Exact 64-bit arithmetic on decimal strings; Lua numbers lose nanoseconds. */
static int lua_shirudo_u64_add(lua_State *L)
{
	__u64 a, b, sum;

	lua_check_u64_string(L, 1, &a);
	lua_check_u64_string(L, 2, &b);
	lua_push_u64_string(L, check_add_overflow(a, b, &sum) ?
			    UINT64_MAX : sum);
	return 1;
}

static int lua_shirudo_u64_sub(lua_State *L)
{
	__u64 a, b;

	lua_check_u64_string(L, 1, &a);
	lua_check_u64_string(L, 2, &b);
	lua_push_u64_string(L, a < b ? 0 : a - b);
	return 1;
}

static int lua_shirudo_hex_u64(lua_State *L)
{
	const char *hex;
	size_t hex_len;
	int off = lua_check_c_int(L, 2);
	__u64 v = 0;
	int i;

	hex = luaL_checklstring(L, 1, &hex_len);
	if (off < 0 || (size_t)off * 2 + 16 > hex_len) {
		lua_push_u64_string(L, 0);
		return 1;
	}
	for (i = 7; i >= 0; i--) {
		const char *p = hex + (size_t)off * 2 + (size_t)i * 2;
		int hi = hex_nibble(p[0]);
		int lo = hex_nibble(p[1]);

		if (hi < 0 || lo < 0) {
			lua_push_u64_string(L, 0);
			return 1;
		}
		v = (v << 8) | (__u64)((hi << 4) | lo);
	}
	lua_push_u64_string(L, v);
	return 1;
}

static int lua_shirudo_fixed_records(lua_State *L)
{
	int pages_idx, slots_idx;
	size_t n_pages, i;
	int slot_size;

	luaL_checktype(L, 1, LUA_TTABLE);
	slot_size = lua_check_c_int(L, 2);
	if (slot_size <= 0)
		return luaL_error(L, "invalid slot size");

	pages_idx = lua_absindex(L, 1);
	lua_newtable(L);
	slots_idx = lua_absindex(L, -1);
	n_pages = lua_objlen(L, pages_idx);
	for (i = 1; i <= n_pages; i++) {
		const char *hex;
		__u8 *data = NULL;
		__u64 cursor, chunks;
		size_t hex_len, data_len = 0;
		int ret;

		lua_rawgeti(L, pages_idx, (int)i);
		if (!lua_istable(L, -1)) {
			lua_pop(L, 1);
			continue;
		}
		cursor = lua_page_u64(L, -1, "cursor");
		chunks = lua_page_u64(L, -1, "chunks");
		lua_getfield(L, -1, "data_hex");
		hex = lua_tolstring(L, -1, &hex_len);
		if (!hex) {
			lua_pop(L, 2);
			continue;
		}
		ret = hex_decode_push(L, hex, hex_len, &data, &data_len);
		if (ret) {
			lua_pop(L, 2);
			return luaL_error(L, "invalid page data_hex");
		}
		lua_split_page_slots(L, slots_idx, data, data_len, cursor,
				     chunks, (size_t)slot_size);
		lua_pop(L, 3);
	}
	return 1;
}

static void lua_register_slot(lua_State *L)
{
	luaL_newmetatable(L, LUA_SLOT_MT);
	lua_newtable(L);
	lua_pushcfunction(L, lua_slot_u8);
	lua_setfield(L, -2, "u8");
	lua_pushcfunction(L, lua_slot_u16);
	lua_setfield(L, -2, "u16");
	lua_pushcfunction(L, lua_slot_u32);
	lua_setfield(L, -2, "u32");
	lua_pushcfunction(L, lua_slot_u64);
	lua_setfield(L, -2, "u64");
	lua_pushcfunction(L, lua_slot_cstring);
	lua_setfield(L, -2, "cstring");
	lua_setfield(L, -2, "__index");
	/* A __gc a decoder added to it would run with hooks off. */
	lua_pushliteral(L, LUA_SLOT_MT);
	lua_setfield(L, -2, "__metatable");
	lua_pop(L, 1);
}

static void lua_install_host_api(lua_State *L)
{
	lua_register_slot(L);
	lua_newtable(L);
	lua_pushcfunction(L, lua_shirudo_fixed_records);
	lua_setfield(L, -2, "fixed_records");
	lua_pushcfunction(L, lua_shirudo_page_slots);
	lua_setfield(L, -2, "page_slots");
	lua_pushcfunction(L, lua_shirudo_u64_add);
	lua_setfield(L, -2, "u64_add");
	lua_pushcfunction(L, lua_shirudo_u64_sub);
	lua_setfield(L, -2, "u64_sub");
	lua_pushcfunction(L, lua_shirudo_hex_u64);
	lua_setfield(L, -2, "hex_u64");
	lua_setglobal(L, "shirudo");
}

/*
 * LuaJIT runs a finalizer with hooks off, so newproxy(), which makes a
 * userdata that takes one, would run code past the budget, and so does
 * the handler xpcall() calls for the error the budget hook raises, from
 * inside the hook. A pattern match is one C call the count hook never
 * interrupts, and backtracks for as long as the subject, a string a map
 * recorded, makes it.
 */
static void lua_disable_globals(lua_State *L)
{
	static const char *const deny[] = {
		"io", "os", "package", "require", "debug", "jit", "ffi",
		"dofile", "loadfile", "load", "loadstring", "module",
		"collectgarbage", "newproxy", "xpcall", "print",
	};
	static const char *const patterns[] = {
		"find", "match", "gmatch", "gsub",
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(deny); i++) {
		lua_pushnil(L);
		lua_setglobal(L, deny[i]);
	}
	lua_getglobal(L, "string");
	for (i = 0; i < ARRAY_SIZE(patterns); i++) {
		lua_pushnil(L);
		lua_setfield(L, -2, patterns[i]);
	}
	lua_pop(L, 1);
}

/*
 * pcall() catches the error, so once the budget is spent every
 * instruction raises it again: no protected call runs past it.
 */
static void lua_budget_hook(lua_State *L, lua_Debug *ar)
{
	struct lua_budget *budget;

	budget = current_lua_budget;
	if (!budget || --budget->remaining > 0)
		return;
	lua_sethook(L, lua_budget_hook, LUA_MASKCOUNT, 1);
	luaL_error(L, "decoder instruction limit exceeded");
}

static void lua_install_budget(lua_State *L, struct lua_budget *budget)
{
	current_lua_budget = budget;
	lua_sethook(L, lua_budget_hook, LUA_MASKCOUNT, LUA_HOOK_COUNT);
}

static __u64 decoder_realtime_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		return 0;
	return (__u64)ts.tv_sec * 1000000000ULL +
		(__u64)ts.tv_nsec;
}

static void lua_push_u64_string(lua_State *L, __u64 value)
{
	char buf[32];

	if (strsprintf(buf, sizeof(buf), "%llu", value) < 0)
		lua_pushnil(L);
	else
		lua_pushstring(L, buf);
}

/*
 * Lua raises on an allocation it cannot make and never returns here, so
 * a buffer this walk owned would leak: the hex lives in a userdata the
 * collector owns until the string is made from it.
 */
static void lua_push_hex(lua_State *L, const void *data, size_t len)
{
	char *hex = lua_newuserdata(L, len * 2 + 1);

	hex_encode(data, len, hex);
	lua_pushstring(L, hex);
	lua_remove(L, -2);
}

static void lua_push_map_input(lua_State *L, const struct map_view *v)
{
	__u64 now_ns = decoder_realtime_ns();
	__u64 start_ns = v->lifetime_start_ns ?: now_ns;
	__u32 p, i;

	lua_newtable(L);
	lua_pushinteger(L, 1);
	lua_setfield(L, -2, "schema");
	lua_pushstring(L, v->upatch);
	lua_setfield(L, -2, "upatch");
	lua_pushstring(L, v->name);
	lua_setfield(L, -2, "map");
	/*
	 * Metric decoders need valid OTLP wall-clock timestamps. Keep these
	 * as decimal strings because Lua numbers cannot represent uint64_ns.
	 */
	lua_push_u64_string(L, start_ns);
	lua_setfield(L, -2, "startTimeUnixNano");
	lua_push_u64_string(L, now_ns);
	lua_setfield(L, -2, "timeUnixNano");

	lua_newtable(L);
	lua_pushstring(L, v->name);
	lua_setfield(L, -2, "name");
	lua_pushstring(L, v->type_name ? v->type_name : "");
	lua_setfield(L, -2, "type");
	lua_pushnumber(L, v->max_entries);
	lua_setfield(L, -2, "max_entries");
	lua_pushnumber(L, v->n_entries);
	lua_setfield(L, -2, "n_entries");
	lua_pushboolean(L, v->serialized);
	lua_setfield(L, -2, "serialized");
	lua_pushnumber(L, v->n_serial_pages);
	lua_setfield(L, -2, "serialized_pages");
	lua_pushnumber(L, (lua_Number)v->serial_bytes_total);
	lua_setfield(L, -2, "serialized_bytes");
	lua_pushnumber(L, v->key_size);
	lua_setfield(L, -2, "key_size");
	lua_pushnumber(L, v->value_size);
	lua_setfield(L, -2, "value_size");
	lua_pushnumber(L, v->n_cpus);
	lua_setfield(L, -2, "n_cpus");
	lua_pushboolean(L, v->truncated);
	lua_setfield(L, -2, "truncated");

	/* Raw bytes are always available, including when BTF rendering is not. */
	lua_newtable(L);
	for (i = 0; i < v->n_entries; i++) {
		const struct map_entry *entry = &v->entries[i];
		size_t value_bytes = (size_t)v->value_stride * v->n_cpus;

		lua_newtable(L);
		lua_push_hex(L, entry->key, v->key_size);
		lua_setfield(L, -2, "key_hex");
		lua_push_hex(L, entry->value, value_bytes);
		lua_setfield(L, -2, "value_hex");
		lua_rawseti(L, -2, (int)i + 1);
	}
	lua_setfield(L, -2, "entries");

	lua_newtable(L);
	for (p = 0; p < v->n_serial_pages; p++) {
		const struct serial_page *page = &v->serial_pages[p];

		lua_newtable(L);
		lua_pushnumber(L, page->page_index);
		lua_setfield(L, -2, "page_index");
		lua_pushnumber(L, (lua_Number)page->cursor);
		lua_setfield(L, -2, "cursor");
		lua_pushnumber(L, (lua_Number)page->next_cursor);
		lua_setfield(L, -2, "next_cursor");
		lua_pushboolean(L, page->done);
		lua_setfield(L, -2, "done");
		lua_pushnumber(L, page->flags);
		lua_setfield(L, -2, "flags");
		lua_pushnumber(L, page->chunks);
		lua_setfield(L, -2, "chunks");
		lua_pushnumber(L, page->bytes);
		lua_setfield(L, -2, "bytes");
		lua_push_hex(L, page->data, page->bytes);
		lua_setfield(L, -2, "data_hex");
		lua_rawseti(L, -2, (int)p + 1);
	}
	lua_setfield(L, -2, "pages");
	lua_setfield(L, -2, "data");
}

static int lua_get_decoder_entrypoint(lua_State *L, const char *entrypoint)
{
	if (lua_istable(L, -1)) {
		lua_getfield(L, -1, entrypoint);
		if (lua_isfunction(L, -1)) {
			lua_remove(L, -2);
			return 0;
		}
		lua_pop(L, 1);
	}
	if (lua_isfunction(L, -1))
		return 0;
	lua_pop(L, 1);
	lua_getglobal(L, entrypoint);
	return lua_isfunction(L, -1) ? 0 : -ENOENT;
}

struct lua_decoder_call {
	const struct map_view *view;
	struct json_emit *jo;
	bool otel;
	int ret;
};

/* The result is encoded under the same pcall, as it may run out of memory. */
static int lua_call_decoder(lua_State *L)
{
	struct lua_decoder_call *call = lua_touserdata(L, lua_upvalueindex(1));

	lua_pushvalue(L, lua_upvalueindex(2));
	lua_push_map_input(L, call->view);
	lua_call(L, 1, 1);
	call->ret = call->otel ? lua_otel_emit_value(L, -1, call->jo, 0) :
		lua_json_emit_value(L, -1, call->jo, 0);
	return 0;
}

/* The message is the decoder's, and may carry what a map recorded. */
static void lua_report(lua_State *L, const char *what)
{
	const char *message = "unknown Lua error";
	char shown[256];
	ssize_t len;

	if (lua_type(L, -1) == LUA_TSTRING)
		message = lua_tostring(L, -1);
	len = strscpy(shown, message, sizeof(shown));
	if (len < 0)
		len = sizeof(shown) - 1;
	text_sanitize(shown, len, false);
	pr_err("upatch map: %s: %s", what, shown);
}

/*
 * Restoring the native allocator before close would let finalizers bypass
 * the memory limit and skip scrubbing. A separate state owns the arena so
 * the decoder keeps its wrapper until close has freed all its objects.
 */
static int run_lua_decoder(const struct upatch_decoder_view *d,
			   const struct map_view *v,
			   bool otel, size_t max_bytes,
			   char **out, size_t *out_len)
{
	struct json_emit jo = {};
	struct lua_decoder_call call = {
		.view = v,
		.jo = &jo,
		.otel = otel,
	};
	struct lua_budget budget = {
		.remaining = LUA_INSN_LIMIT / LUA_HOOK_COUNT,
	};
	struct lua_memory memory = {
		.limit = LUA_MEMORY_LIMIT,
	};
	lua_State *allocator, *L;
	int ret = 0;

	allocator = luaL_newstate();
	if (!allocator)
		return -ENOMEM;
	memory.inner = lua_getallocf(allocator, &memory.inner_ud);
	L = lua_newstate(lua_limited_alloc, &memory);
	if (!L) {
		lua_close(allocator);
		return -ENOMEM;
	}
	jo.max = max_bytes;
	luaL_openlibs(L);
	lua_disable_globals(L);
	/* Instruction hooks must observe every instruction; do not run traces. */
	if (!luaJIT_setmode(L, 0, LUAJIT_MODE_ENGINE | LUAJIT_MODE_OFF)) {
		lua_close(L);
		lua_close(allocator);
		return -EINVAL;
	}
	lua_install_host_api(L);
	lua_install_budget(L, &budget);

	/* LuaJIT checks no bytecode it loads; a decoder is source text. */
	if (luaL_loadbufferx(L, d->source, d->source_len, d->source_name,
			     "t") ||
	    lua_pcall(L, 0, 1, 0)) {
		lua_report(L, "decoder load failed");
		ret = -EINVAL;
		goto out_close;
	}
	ret = lua_get_decoder_entrypoint(L, d->entrypoint);
	if (ret) {
		pr_err("upatch map: decoder entrypoint %s not found",
		       d->entrypoint);
		goto out_close;
	}
	lua_pushlightuserdata(L, &call);
	lua_pushvalue(L, -2);
	lua_pushcclosure(L, lua_call_decoder, 2);
	lua_remove(L, -2);
	if (lua_pcall(L, 0, 0, 0)) {
		lua_report(L, "decoder failed");
		ret = -EINVAL;
		goto out_close;
	}
	ret = call.ret;
	if (ret) {
		pr_err("upatch map: decoder encode failed: %s", strerror(-ret));
		goto out_close;
	}
	if (jo.err) {
		ret = jo.err;
		goto out_close;
	}
	*out = jo.buf;
	*out_len = jo.len;
	jo.buf = NULL;
	jo.cap = 0;

out_close:
	xfree(jo.buf, jo.cap);
	lua_sethook(L, NULL, 0, 0);
	current_lua_budget = NULL;
	lua_close(L);
	lua_close(allocator);
	return ret;
}

static int decoder_matches(const struct upatch_decoder_view *d,
			   const struct map_view *v)
{
	if (d->language != UPATCH_DECODER_LANG_LUA ||
	    d->api_version != 1 ||
	    d->input_format != UPATCH_DECODER_INPUT_MAP_V1 ||
	    (d->export_signal != UPATCH_DECODER_EXPORT_LOG &&
	     d->export_signal != UPATCH_DECODER_EXPORT_METRIC))
		return 0;
	/*
	 * The map alone picks the decoder: the archive it comes from is the
	 * upatch these maps belong to, by the payload the pin directory
	 * recorded, and its signature covers the decoders. The decoder's
	 * upatch field holds 63 of the 255 characters a name may have, or
	 * nothing.
	 */
	if (strcmp(d->map, v->name) != 0)
		return 0;
	return 1;
}

static int payload_digest(const struct upatch *u,
			  __u8 out[UPATCH_PAYLOAD_HASH_LEN])
{
	struct sha256_ctx ctx;
	int ret;

	ret = sha256_init(&ctx);
	if (ret)
		return ret;
	ret = sha256_update(&ctx, upatch_loader(u), u->hdr.loader_insns_len);
	if (!ret)
		ret = sha256_update(&ctx, upatch_data(u), u->hdr.data_len);
	if (!ret)
		ret = sha256_final(&ctx, out);
	sha256_free(&ctx);
	return ret;
}

/*
 * The archived artifact the decoders come from, opened as sealed state
 * when archived: an entry under the archive that is not shirudo's own,
 * brought in while the directory's mark was gone, is refused rather
 * than run, signed or not, and so is an archive whose bytes are not the
 * payload the pin directory says was loaded.
 */
static int archive_open(const char *path, bool archived,
			const struct map_view *v, struct upatch *u)
{
	__u8 digest[UPATCH_PAYLOAD_HASH_LEN];
	int fd, ret;

	if (!archived)
		return upatch_open(path, u);
	fd = seal_open_read(path);
	if (fd < 0)
		return fd;
	ret = upatch_open_fd(fd, u);
	close(fd);
	if (ret)
		return ret;
	ret = payload_digest(u, digest);
	if (!ret && (!v->has_payload ||
		     memneq_explicit(digest, v->payload, sizeof(digest)) ||
		     memneq_explicit(u->hdr.payload_sha256, v->payload,
				     sizeof(digest)))) {
		pr_err("upatch map: the archive of %s is not the upatch loaded; its decoders do not run",
		       v->upatch);
		ret = -ESTALE;
	}
	if (ret)
		upatch_close(u);
	return ret;
}

static int decode_map_open(const char *path, bool archived,
			   const struct map_view *v,
			   bool otel, size_t max_bytes,
			   char **out, size_t *out_len)
{
	struct upatch u;
	__u32 i;
	int ret;

	if (!path || !v || !out || !out_len)
		return -EINVAL;
	*out = NULL;
	*out_len = 0;
	if (!upatch_name_valid(v->upatch))
		return -EINVAL;
	ret = archive_open(path, archived, v, &u);
	if (ret)
		return ret == -ENOENT ? -ENOENT : ret;
	ret = -ENODATA;
	for (i = 0; i < u.nr_decoders; i++) {
		struct upatch_decoder_view d;

		if (upatch_decoder_view(&u, i, &d))
			continue;
		if (!decoder_matches(&d, v))
			continue;
		ret = run_lua_decoder(&d, v, otel, max_bytes, out, out_len);
		break;
	}
	upatch_close(&u);
	/* A map no decoder claims still has its BTF: the cells the text
	   output prints are the cells a JSON reader wants, so the
	   no-decoder fallback is the same formatting under JSON keys.
	   The output says so, because a consumer that expects a
	   decoder's shape is reading a different document. Without
	   this, `upatch map --json` fails on exactly the maps that
	   print fine without --json. */
	if (ret == -ENODATA && !otel) {
		struct json_emit e = { .max = max_bytes };

		json_obj_open(&e);
		json_kv_string(&e, "format", "btf");
		upatch_maps_emit_json_fields(&e, v);
		json_obj_close(&e);
		if (!e.err) {
			*out = e.buf;
			*out_len = e.len;
			e.buf = NULL;
			e.cap = 0;
			ret = 0;
		} else {
			ret = e.err;
		}
		xfree(e.buf, e.cap);
	}
	return ret;
}

static int decode_map_file(const char *path, const struct map_view *v,
			   bool otel, size_t max_bytes,
			   char **out, size_t *out_len)
{
	return decode_map_open(path, false, v, otel, max_bytes, out, out_len);
}

int upatch_decode_map_signal(const struct map_view *v,
			     __u32 *signal_out)
{
	struct upatch u;
	char path[PATH_MAX];
	__u32 i;
	int ret;

	if (!v || !signal_out || !upatch_name_valid(v->upatch))
		return -EINVAL;
	if (strsprintf(path, sizeof(path), "%s/%s.upatch", UPATCHES_DIR,
		       v->upatch) < 0)
		return -ENAMETOOLONG;
	ret = archive_open(path, true, v, &u);
	if (ret)
		return ret == -ENOENT ? -ENOENT : ret;
	ret = -ENODATA;
	for (i = 0; i < u.nr_decoders; i++) {
		struct upatch_decoder_view d;

		if (upatch_decoder_view(&u, i, &d) ||
		    !decoder_matches(&d, v))
			continue;
		*signal_out = d.export_signal;
		ret = 0;
		break;
	}
	upatch_close(&u);
	return ret;
}

static int decode_map(const struct map_view *v, bool otel,
		      size_t max_bytes, char **out, size_t *out_len)
{
	char path[PATH_MAX];

	if (!v)
		return -EINVAL;
	if (strsprintf(path, sizeof(path), "%s/%s.upatch", UPATCHES_DIR,
		       v->upatch) < 0)
		return -ENAMETOOLONG;
	return decode_map_open(path, true, v, otel, max_bytes, out, out_len);
}

int upatch_decode_map_json(const struct map_view *v,
			   char **out, size_t *out_len)
{
	return upatch_decode_map_json_limit(v,
					    JSON_MAX_BYTES,
					    out, out_len);
}

int upatch_decode_map_json_limit(const struct map_view *v,
				 size_t max_bytes,
				 char **out, size_t *out_len)
{
	if (!max_bytes)
		return -EINVAL;
	return decode_map(v, false, max_bytes, out, out_len);
}

int upatch_decode_map_otel(const struct map_view *v,
			   char **out, size_t *out_len)
{
	return decode_map(v, true, JSON_MAX_BYTES, out, out_len);
}

int upatch_decode_map_file_json(const char *path,
				const struct map_view *v,
				char **out, size_t *out_len)
{
	return upatch_decode_map_file_json_limit(path, v,
						 JSON_MAX_BYTES,
						 out, out_len);
}

int upatch_decode_map_file_json_limit(const char *path,
				      const struct map_view *v,
				      size_t max_bytes, char **out,
				      size_t *out_len)
{
	if (!max_bytes)
		return -EINVAL;
	return decode_map_file(path, v, false, max_bytes, out, out_len);
}

int upatch_decode_map_file_otel(const char *path,
				const struct map_view *v,
				char **out, size_t *out_len)
{
	return decode_map_file(path, v, true, JSON_MAX_BYTES,
			       out, out_len);
}

#endif /* HAVE_LUAJIT */
