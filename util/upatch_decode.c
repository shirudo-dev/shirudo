// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Signed Lua decoders for serialized maps: a small LuaJIT host API and
 * the serialisation of what they return.
 */

#include <errno.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "upatch_decode.h"

#ifndef SHIRUDO_HAVE_LUAJIT

int upatch_decode_map_json(const struct shirudo_map_view *v,
			   char **out, size_t *out_len)
{
	if (!v || !out || !out_len)
		return -EINVAL;
	*out = NULL;
	*out_len = 0;
	return -EOPNOTSUPP;
}

int upatch_decode_map_json_limit(const struct shirudo_map_view *v,
				 size_t max_bytes,
				 char **out, size_t *out_len)
{
	(void)max_bytes;
	return upatch_decode_map_json(v, out, out_len);
}

int upatch_decode_map_otel(const struct shirudo_map_view *v,
			   char **out, size_t *out_len)
{
	return upatch_decode_map_json(v, out, out_len);
}

int upatch_decode_map_file_json(const char *path,
				const struct shirudo_map_view *v,
				char **out, size_t *out_len)
{
	(void)path;
	return upatch_decode_map_json(v, out, out_len);
}

int upatch_decode_map_file_json_limit(const char *path,
				      const struct shirudo_map_view *v,
				      size_t max_bytes, char **out,
				      size_t *out_len)
{
	(void)path;
	(void)max_bytes;
	return upatch_decode_map_json(v, out, out_len);
}

int upatch_decode_map_file_otel(const char *path,
				const struct shirudo_map_view *v,
				char **out, size_t *out_len)
{
	(void)path;
	return upatch_decode_map_json(v, out, out_len);
}

#else /* SHIRUDO_HAVE_LUAJIT */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <luajit.h>

#include "json.h"
#include "hex.h"
#include "macros.h"
#include "malloc.h"
#include "paths.h"
#include "upatch.h"
#include "upatch_decode.h"
#include "upatch_maps.h"
#include "bpf/lib/shirudo_serializer.h"

#define SHIRUDO_LUA_INSN_LIMIT		1000000
#define SHIRUDO_LUA_HOOK_COUNT		10000
#define SHIRUDO_LUA_MEMORY_LIMIT	(32u * 1024u * 1024u)
#define SHIRUDO_LUA_JSON_MAX_DEPTH	32
#define SHIRUDO_LUA_SLOT_MT		"shirudo.slot"

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

struct json_out {
	char	*buf;
	size_t	len;
	size_t	cap;
	size_t	max_bytes;
	int	err;
};

struct lua_budget {
	int	remaining;
};

struct lua_memory {
	size_t	used;
	size_t	limit;
};

static struct lua_budget *current_lua_budget;

static void *lua_limited_alloc(void *ud, void *ptr, size_t old_size,
			       size_t new_size)
{
	struct lua_memory *memory = ud;
	size_t base = ptr && memory->used >= old_size ?
		memory->used - old_size : memory->used;
	void *next;

	if (new_size == 0) {
		if (ptr) {
			xfree(ptr, old_size);
			memory->used = base;
		}
		return NULL;
	}
	if (base > memory->limit || new_size > memory->limit - base)
		return NULL;
	next = xmalloc(new_size);
	if (!next)
		return NULL;
	if (ptr) {
		memcpy(next, ptr, old_size < new_size ? old_size : new_size);
		xfree(ptr, old_size);
	}
	memory->used = base + new_size;
	return next;
}

static int json_out_reserve(struct json_out *out, size_t need)
{
	char *buf;
	size_t new_cap;

	if (out->err)
		return out->err;
	if (need > out->max_bytes) {
		out->err = -E2BIG;
		return out->err;
	}
	if (need <= out->cap)
		return 0;

	new_cap = out->cap ? out->cap : 4096;
	while (new_cap < need) {
		if (new_cap > out->max_bytes / 2) {
			new_cap = out->max_bytes;
			break;
		}
		new_cap *= 2;
	}
	buf = xmalloc(new_cap);
	if (!buf) {
		out->err = -ENOMEM;
		return out->err;
	}
	if (out->buf) {
		memcpy(buf, out->buf, out->len);
		xfree(out->buf, out->cap);
	}
	out->buf = buf;
	out->cap = new_cap;
	out->buf[out->len] = '\0';
	return 0;
}

static void json_putc(struct json_out *out, char ch)
{
	if (json_out_reserve(out, out->len + 2))
		return;
	out->buf[out->len++] = ch;
	out->buf[out->len] = '\0';
}

static void json_puts(struct json_out *out, const char *s)
{
	size_t n;

	if (!s || out->err)
		return;
	n = strlen(s);
	if (json_out_reserve(out, out->len + n + 1))
		return;
	memcpy(out->buf + out->len, s, n);
	out->len += n;
	out->buf[out->len] = '\0';
}

/*
 * The bytes of one well-formed UTF-8 character at s, or 0. Names the
 * kernel hands over are raw bytes, cut at a fixed length mid-character
 * as often as not, and one bad byte must not cost the whole snapshot,
 * which the serializer has already drained: it is exported as U+FFFD.
 */
static size_t utf8_width(const char *s, size_t n)
{
	__u8 c = s[0];
	size_t width, j;
	__u32 cp;

	if ((c & 0xe0) == 0xc0) {
		width = 2;
		cp = c & 0x1f;
	} else if ((c & 0xf0) == 0xe0) {
		width = 3;
		cp = c & 0x0f;
	} else if ((c & 0xf8) == 0xf0) {
		width = 4;
		cp = c & 0x07;
	} else {
		return 0;
	}
	if (width > n)
		return 0;
	for (j = 1; j < width; j++) {
		if (((__u8)s[j] & 0xc0) != 0x80)
			return 0;
		cp = cp << 6 | ((__u8)s[j] & 0x3f);
	}
	if ((width == 2 && cp < 0x80) || (width == 3 && cp < 0x800) ||
	    (width == 4 && cp < 0x10000) || cp > 0x10ffff ||
	    (cp >= 0xd800 && cp <= 0xdfff))
		return 0;
	return width;
}

static void json_put_string(struct json_out *out, const char *s, size_t n)
{
	static const char hexdigits[] = "0123456789abcdef";
	size_t i;

	json_putc(out, '"');
	for (i = 0; i < n && !out->err; i++) {
		__u8 c = s[i];

		switch (c) {
		case '"':
		case '\\':
			json_putc(out, '\\');
			json_putc(out, (char)c);
			break;
		case '\b':
			json_puts(out, "\\b");
			break;
		case '\f':
			json_puts(out, "\\f");
			break;
		case '\n':
			json_puts(out, "\\n");
			break;
		case '\r':
			json_puts(out, "\\r");
			break;
		case '\t':
			json_puts(out, "\\t");
			break;
		default:
			if (c < 0x20) {
				json_puts(out, "\\u00");
				json_putc(out, hexdigits[c >> 4]);
				json_putc(out, hexdigits[c & 0xf]);
			} else if (c >= 0x80) {
				size_t width = utf8_width(s + i, n - i), j;

				if (!width) {
					json_puts(out, "\\ufffd");
					break;
				}
				for (j = 0; j < width; j++)
					json_putc(out, s[i + j]);
				i += width - 1;
			} else {
				json_putc(out, (char)c);
			}
			break;
		}
	}
	json_putc(out, '"');
}

static int lua_json_emit_value(lua_State *L, int idx, struct json_out *out,
			       int depth);

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

static void lua_json_emit_key(lua_State *L, int idx, struct json_out *out)
{
	char num[64];
	size_t n;
	const char *s;

	switch (lua_type(L, idx)) {
	case LUA_TSTRING:
		s = lua_tolstring(L, idx, &n);
		json_put_string(out, s ? s : "", n);
		break;
	case LUA_TNUMBER:
		snprintf(num, sizeof(num), "%.17g", (double)lua_tonumber(L, idx));
		json_put_string(out, num, strlen(num));
		break;
	case LUA_TBOOLEAN:
		s = lua_toboolean(L, idx) ? "true" : "false";
		json_put_string(out, s, strlen(s));
		break;
	default:
		json_put_string(out, "unsupported_key", strlen("unsupported_key"));
		break;
	}
}

static int lua_json_emit_table(lua_State *L, int idx, struct json_out *out,
			       int depth)
{
	size_t len = 0;
	size_t i;
	int first = 1;

	idx = lua_absindex(L, idx);
	if (lua_table_is_array(L, idx, &len)) {
		json_putc(out, '[');
		for (i = 1; i <= len && !out->err; i++) {
			if (!first)
				json_putc(out, ',');
			first = 0;
			lua_rawgeti(L, idx, (int)i);
			lua_json_emit_value(L, -1, out, depth + 1);
			lua_pop(L, 1);
		}
		json_putc(out, ']');
		return out->err;
	}

	json_putc(out, '{');
	lua_pushnil(L);
	while (lua_next(L, idx) != 0) {
		int key_type = lua_type(L, -2);

		if (key_type != LUA_TSTRING && key_type != LUA_TNUMBER &&
		    key_type != LUA_TBOOLEAN) {
			out->err = -EINVAL;
			lua_pop(L, 1);
			break;
		}
		if (!first)
			json_putc(out, ',');
		first = 0;
		lua_json_emit_key(L, -2, out);
		json_putc(out, ':');
		lua_json_emit_value(L, -1, out, depth + 1);
		lua_pop(L, 1);
		if (out->err)
			break;
	}
	json_putc(out, '}');
	return out->err;
}

static int lua_otel_emit_value(lua_State *L, int idx, struct json_out *out,
			       int depth);

static int lua_otel_emit_table(lua_State *L, int idx, struct json_out *out,
			       int depth)
{
	size_t len = 0, i;
	int first = 1;

	idx = lua_absindex(L, idx);
	if (lua_table_is_array(L, idx, &len)) {
		json_puts(out, "{\"arrayValue\":{\"values\":[");
		for (i = 1; i <= len && !out->err; i++) {
			if (!first)
				json_putc(out, ',');
			first = 0;
			lua_rawgeti(L, idx, (int)i);
			lua_otel_emit_value(L, -1, out, depth + 1);
			lua_pop(L, 1);
		}
		json_puts(out, "]}}");
		return out->err;
	}

	json_puts(out, "{\"kvlistValue\":{\"values\":[");
	lua_pushnil(L);
	while (lua_next(L, idx) != 0) {
		int key_type = lua_type(L, -2);

		if (key_type != LUA_TSTRING && key_type != LUA_TNUMBER &&
		    key_type != LUA_TBOOLEAN) {
			out->err = -EINVAL;
			lua_pop(L, 1);
			break;
		}
		if (!first)
			json_putc(out, ',');
		first = 0;
		json_puts(out, "{\"key\":");
		lua_json_emit_key(L, -2, out);
		json_puts(out, ",\"value\":");
		lua_otel_emit_value(L, -1, out, depth + 1);
		json_putc(out, '}');
		lua_pop(L, 1);
		if (out->err)
			break;
	}
	json_puts(out, "]}}");
	return out->err;
}

static int lua_otel_emit_value(lua_State *L, int idx, struct json_out *out,
			       int depth)
{
	const double max_exact_integer = 9007199254740991.0;
	char num[64];
	const char *s;
	size_t n;
	double value;

	if (depth > SHIRUDO_LUA_JSON_MAX_DEPTH) {
		out->err = -E2BIG;
		return out->err;
	}

	switch (lua_type(L, idx)) {
	case LUA_TNIL:
		/* An empty AnyValue represents a Lua nil. */
		json_puts(out, "{}");
		break;
	case LUA_TBOOLEAN:
		json_puts(out, "{\"boolValue\":");
		json_puts(out, lua_toboolean(L, idx) ? "true}" : "false}");
		break;
	case LUA_TNUMBER:
		value = (double)lua_tonumber(L, idx);
		if (!isfinite(value)) {
			out->err = -EINVAL;
			break;
		}
		if (shirudo_trunc(value) == value &&
		    fabs(value) <= max_exact_integer) {
			snprintf(num, sizeof(num), "%.0f", value == 0 ? 0 : value);
			json_puts(out, "{\"intValue\":");
			json_put_string(out, num, strlen(num));
			json_putc(out, '}');
		} else {
			snprintf(num, sizeof(num), "%.17g", value);
			json_puts(out, "{\"doubleValue\":");
			json_puts(out, num);
			json_putc(out, '}');
		}
		break;
	case LUA_TSTRING:
		s = lua_tolstring(L, idx, &n);
		json_puts(out, "{\"stringValue\":");
		json_put_string(out, s ? s : "", n);
		json_putc(out, '}');
		break;
	case LUA_TTABLE:
		lua_otel_emit_table(L, idx, out, depth);
		break;
	default:
		out->err = -EINVAL;
		break;
	}
	return out->err;
}

static int lua_json_emit_value(lua_State *L, int idx, struct json_out *out,
			       int depth)
{
	char num[64];
	size_t n;
	const char *s;
	int type;

	if (depth > SHIRUDO_LUA_JSON_MAX_DEPTH) {
		out->err = -E2BIG;
		return out->err;
	}

	type = lua_type(L, idx);
	switch (type) {
	case LUA_TNIL:
		json_puts(out, "null");
		break;
	case LUA_TBOOLEAN:
		json_puts(out, lua_toboolean(L, idx) ? "true" : "false");
		break;
	case LUA_TNUMBER:
		if (!isfinite((double)lua_tonumber(L, idx))) {
			out->err = -EINVAL;
			break;
		}
		snprintf(num, sizeof(num), "%.17g", (double)lua_tonumber(L, idx));
		json_puts(out, num);
		break;
	case LUA_TSTRING:
		s = lua_tolstring(L, idx, &n);
		json_put_string(out, s ? s : "", n);
		break;
	case LUA_TTABLE:
		lua_json_emit_table(L, idx, out, depth);
		break;
	default:
		out->err = -EINVAL;
		break;
	}
	return out->err;
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
	return luaL_checkudata(L, 1, SHIRUDO_LUA_SLOT_MT);
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
	snprintf(buf, sizeof(buf), "%llu", v);
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
	luaL_getmetatable(L, SHIRUDO_LUA_SLOT_MT);
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
	size_t slots_per_chunk = SHIRUDO_SERIAL_CHUNK_PAYLOAD / slot_size;

	if (chunks > 1 && slots_per_chunk > 0 &&
	    SHIRUDO_SERIAL_CHUNK_PAYLOAD % slot_size != 0) {
		size_t off = 0;
		__u64 chunk;

		for (chunk = 0; chunk < chunks && off < len; chunk++) {
			size_t chunk_bytes = len - off;
			size_t local_slots, i;

			if (chunk_bytes > SHIRUDO_SERIAL_CHUNK_PAYLOAD)
				chunk_bytes = SHIRUDO_SERIAL_CHUNK_PAYLOAD;
			local_slots = chunk_bytes / slot_size;
			if (local_slots > slots_per_chunk)
				local_slots = slots_per_chunk;
			for (i = 0; i < local_slots; i++) {
				__u64 page_slot = chunk * slots_per_chunk + i;

				if (page_slot == 0)
					continue;
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
	int slot_size, n = 0, rc;

	luaL_checktype(L, 1, LUA_TTABLE);
	slot_size = lua_check_c_int(L, 2);
	if (slot_size <= 0 || slot_size > (int)SHIRUDO_SERIAL_CHUNK_PAYLOAD)
		return luaL_error(L, "invalid slot size");
	chunks = lua_page_u64(L, 1, "chunks");
	lua_getfield(L, 1, "data_hex");
	hex = lua_tolstring(L, -1, &hex_len);
	if (!hex) {
		lua_pop(L, 1);
		lua_newtable(L);
		return 1;
	}
	rc = hex_decode_push(L, hex, hex_len, &data, &data_len);
	if (rc)
		return luaL_error(L, "invalid page data_hex");
	per_chunk = SHIRUDO_SERIAL_CHUNK_PAYLOAD / (size_t)slot_size;
	lua_newtable(L);
	while (off < data_len) {
		size_t chunk_bytes = data_len - off, local_slots, i;

		if (chunks > 1 && chunk_bytes > SHIRUDO_SERIAL_CHUNK_PAYLOAD)
			chunk_bytes = SHIRUDO_SERIAL_CHUNK_PAYLOAD;
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
	int rc = parse_u64(s, len, UINT64_MAX, out);

	if (rc == -ERANGE)
		return luaL_argerror(L, arg, "u64 string out of range");
	if (rc)
		return luaL_argerror(L, arg, "expected a decimal u64 string");
	return 0;
}

/* Exact 64-bit arithmetic on decimal strings; Lua numbers lose nanoseconds. */
static int lua_shirudo_u64_add(lua_State *L)
{
	__u64 a, b;

	lua_check_u64_string(L, 1, &a);
	lua_check_u64_string(L, 2, &b);
	lua_push_u64_string(L, a > UINT64_MAX - b ? UINT64_MAX : a + b);
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
		int rc;

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
		rc = hex_decode_push(L, hex, hex_len, &data, &data_len);
		if (rc) {
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
	luaL_newmetatable(L, SHIRUDO_LUA_SLOT_MT);
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

static void lua_disable_globals(lua_State *L)
{
	static const char *const deny[] = {
		"io", "os", "package", "require", "debug", "jit", "ffi",
		"dofile", "loadfile", "load", "loadstring", "module",
		"collectgarbage",
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(deny); i++) {
		lua_pushnil(L);
		lua_setglobal(L, deny[i]);
	}
}

static void lua_budget_hook(lua_State *L, lua_Debug *ar)
{
	struct lua_budget *budget;

	(void)ar;
	budget = current_lua_budget;
	if (!budget || --budget->remaining > 0)
		return;
	luaL_error(L, "decoder instruction limit exceeded");
}

static void lua_install_budget(lua_State *L, struct lua_budget *budget)
{
	current_lua_budget = budget;
	lua_sethook(L, lua_budget_hook, LUA_MASKCOUNT, SHIRUDO_LUA_HOOK_COUNT);
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

	snprintf(buf, sizeof(buf), "%llu", value);
	lua_pushstring(L, buf);
}

static void lua_push_map_input(lua_State *L, const struct shirudo_map_view *v)
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
		const struct shirudo_map_entry *entry = &v->entries[i];
		size_t value_bytes = (size_t)v->value_stride * v->n_cpus;
		char *key_hex = hex_alloc(entry->key, v->key_size);
		char *value_hex = hex_alloc(entry->value, value_bytes);

		if (!key_hex || !value_hex) {
			xfree(key_hex, (size_t)v->key_size * 2 + 1);
			xfree(value_hex, value_bytes * 2 + 1);
			luaL_error(L, "decoder map data is too large");
		}
		lua_newtable(L);
		lua_pushstring(L, key_hex);
		lua_setfield(L, -2, "key_hex");
		lua_pushstring(L, value_hex);
		lua_setfield(L, -2, "value_hex");
		lua_rawseti(L, -2, (int)i + 1);
		xfree(key_hex, (size_t)v->key_size * 2 + 1);
		xfree(value_hex, value_bytes * 2 + 1);
	}
	lua_setfield(L, -2, "entries");

	lua_newtable(L);
	for (p = 0; p < v->n_serial_pages; p++) {
		const struct shirudo_serial_page *page = &v->serial_pages[p];
		char *hex = hex_alloc(page->data, page->bytes);

		if (!hex)
			luaL_error(L, "decoder page data is too large");

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
		lua_pushstring(L, hex ? hex : "");
		lua_setfield(L, -2, "data_hex");
		xfree(hex, (size_t)page->bytes * 2 + 1);
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
	const struct shirudo_map_view *view;
};

static int lua_call_decoder(lua_State *L)
{
	const struct lua_decoder_call *call =
		lua_touserdata(L, lua_upvalueindex(1));

	lua_pushvalue(L, lua_upvalueindex(2));
	lua_push_map_input(L, call->view);
	lua_call(L, 1, 1);
	return 1;
}

static const char *lua_error_message(lua_State *L)
{
	const char *message = lua_tostring(L, -1);

	return message ? message : "unknown Lua error";
}

static int run_lua_decoder(const struct upatch_decoder_view *d,
			   const struct shirudo_map_view *v,
			   bool otel, size_t max_bytes,
			   char **out, size_t *out_len)
{
	struct lua_budget budget = {
		.remaining = SHIRUDO_LUA_INSN_LIMIT / SHIRUDO_LUA_HOOK_COUNT,
	};
	struct lua_memory memory = {
		.limit = SHIRUDO_LUA_MEMORY_LIMIT,
	};
	struct lua_decoder_call call = {
		.view = v,
	};
	struct json_out jo = {};
	lua_State *L;
	int rc = 0;

	L = lua_newstate(lua_limited_alloc, &memory);
	if (!L)
		return -ENOMEM;
	jo.max_bytes = max_bytes;
	luaL_openlibs(L);
	lua_disable_globals(L);
	/* Instruction hooks must observe every instruction; do not run traces. */
	if (!luaJIT_setmode(L, 0, LUAJIT_MODE_ENGINE | LUAJIT_MODE_OFF)) {
		lua_close(L);
		return -EINVAL;
	}
	lua_install_host_api(L);
	lua_install_budget(L, &budget);

	if (luaL_loadbuffer(L, d->source, d->source_len, d->source_name) ||
	    lua_pcall(L, 0, 1, 0)) {
		fprintf(stderr, "upatch map: decoder load failed: %s\n",
			lua_error_message(L));
		rc = -EINVAL;
		goto out_close;
	}
	rc = lua_get_decoder_entrypoint(L, d->entrypoint);
	if (rc) {
		fprintf(stderr, "upatch map: decoder entrypoint '%s' not found\n",
			d->entrypoint);
		goto out_close;
	}
	lua_pushlightuserdata(L, &call);
	lua_pushvalue(L, -2);
	lua_pushcclosure(L, lua_call_decoder, 2);
	lua_remove(L, -2);
	if (lua_pcall(L, 0, 1, 0)) {
		fprintf(stderr, "upatch map: decoder failed: %s\n",
			lua_error_message(L));
		rc = -EINVAL;
		goto out_close;
	}
	rc = otel ? lua_otel_emit_value(L, -1, &jo, 0) :
		lua_json_emit_value(L, -1, &jo, 0);
	if (rc) {
		fprintf(stderr, "upatch map: decoder encode failed: %s\n",
			strerror(-rc));
		goto out_close;
	}
	if (jo.err) {
		rc = jo.err;
		goto out_close;
	}
	*out = jo.buf;
	*out_len = jo.len;
	jo.buf = NULL;
	jo.len = 0;
	jo.cap = 0;

out_close:
	if (jo.buf)
		xfree(jo.buf, jo.cap);
	lua_sethook(L, NULL, 0, 0);
	current_lua_budget = NULL;
	lua_close(L);
	return rc;
}

static int decoder_matches(const struct upatch_decoder_view *d,
			   const struct shirudo_map_view *v)
{
	if (d->language != SHIRUDO_UPATCH_DECODER_LANG_LUA ||
	    d->api_version != 1 ||
	    d->input_format != SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1 ||
	    (d->export_signal != SHIRUDO_UPATCH_DECODER_EXPORT_LOG &&
	     d->export_signal != SHIRUDO_UPATCH_DECODER_EXPORT_METRIC))
		return 0;
	if (strcmp(d->upatch, v->upatch) != 0)
		return 0;
	if (strcmp(d->map, v->name) != 0)
		return 0;
	return 1;
}

static int decode_map_file(const char *path, const struct shirudo_map_view *v,
			   bool otel, size_t max_bytes,
			   char **out, size_t *out_len)
{
	struct shirudo_upatch u;
	__u32 i;
	int rc;

	if (!path || !v || !out || !out_len)
		return -EINVAL;
	*out = NULL;
	*out_len = 0;
	if (!upatch_name_valid(v->upatch))
		return -EINVAL;
	rc = upatch_open(path, &u);
	if (rc)
		return rc == -ENOENT ? -ENOENT : rc;
	rc = -ENOENT;
	for (i = 0; i < u.nr_decoders; i++) {
		struct upatch_decoder_view d;

		if (upatch_decoder_view(&u, i, &d))
			continue;
		if (!decoder_matches(&d, v))
			continue;
		rc = run_lua_decoder(&d, v, otel, max_bytes, out, out_len);
		break;
	}
	upatch_close(&u);
	return rc;
}

int upatch_decode_map_signal(const struct shirudo_map_view *v,
			     __u32 *signal_out)
{
	struct shirudo_upatch u;
	char path[PATH_MAX];
	__u32 i;
	int rc;

	if (!v || !signal_out || !upatch_name_valid(v->upatch))
		return -EINVAL;
	if (strsprintf(path, sizeof(path), "%s/%s.upatch", SHIRUDO_UPATCHES_DIR,
		       v->upatch) < 0)
		return -ENAMETOOLONG;
	rc = upatch_open(path, &u);
	if (rc)
		return rc == -ENOENT ? -ENOENT : rc;
	rc = -ENOENT;
	for (i = 0; i < u.nr_decoders; i++) {
		struct upatch_decoder_view d;

		if (upatch_decoder_view(&u, i, &d) ||
		    !decoder_matches(&d, v))
			continue;
		*signal_out = d.export_signal;
		rc = 0;
		break;
	}
	upatch_close(&u);
	return rc;
}

static int decode_map(const struct shirudo_map_view *v, bool otel,
		      size_t max_bytes, char **out, size_t *out_len)
{
	char path[PATH_MAX];

	if (!v)
		return -EINVAL;
	if (strsprintf(path, sizeof(path), "%s/%s.upatch", SHIRUDO_UPATCHES_DIR,
		       v->upatch) < 0)
		return -ENAMETOOLONG;
	return decode_map_file(path, v, otel, max_bytes, out, out_len);
}

int upatch_decode_map_json(const struct shirudo_map_view *v,
			   char **out, size_t *out_len)
{
	return upatch_decode_map_json_limit(v,
					    SHIRUDO_JSON_MAX_BYTES,
					    out, out_len);
}

int upatch_decode_map_json_limit(const struct shirudo_map_view *v,
				 size_t max_bytes,
				 char **out, size_t *out_len)
{
	if (!max_bytes)
		return -EINVAL;
	return decode_map(v, false, max_bytes, out, out_len);
}

int upatch_decode_map_otel(const struct shirudo_map_view *v,
			   char **out, size_t *out_len)
{
	return decode_map(v, true, SHIRUDO_JSON_MAX_BYTES, out, out_len);
}

int upatch_decode_map_file_json(const char *path,
				const struct shirudo_map_view *v,
				char **out, size_t *out_len)
{
	return upatch_decode_map_file_json_limit(path, v,
						 SHIRUDO_JSON_MAX_BYTES,
						 out, out_len);
}

int upatch_decode_map_file_json_limit(const char *path,
				      const struct shirudo_map_view *v,
				      size_t max_bytes, char **out,
				      size_t *out_len)
{
	if (!max_bytes)
		return -EINVAL;
	return decode_map_file(path, v, false, max_bytes, out, out_len);
}

int upatch_decode_map_file_otel(const char *path,
				const struct shirudo_map_view *v,
				char **out, size_t *out_len)
{
	return decode_map_file(path, v, true, SHIRUDO_JSON_MAX_BYTES,
			       out, out_len);
}

#endif /* SHIRUDO_HAVE_LUAJIT */
