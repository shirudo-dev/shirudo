// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <stdio.h>
#include <string.h>

#include <lua.h>
#include <lauxlib.h>

#include "util/malloc.h"
#include "util/upatch_decode.h"
#include "util/upatch_maps.h"

static int dump_chunk(lua_State * __attribute__((__unused__)) L,
		      const void *p, size_t sz, void *ud)
{
	return fwrite(p, 1, sz, ud) == sz ? 0 : 1;
}

/* The bytecode LuaJIT makes of a source file, for a decoder that is none. */
static int dump(const char *source)
{
	lua_State *L = luaL_newstate();
	int ret = 1;

	if (!L)
		return 1;
	if (!luaL_loadfile(L, source))
		ret = lua_dump(L, dump_chunk, stdout);
	lua_close(L);
	return ret ? 1 : 0;
}

int main(int argc, char **argv)
{
	struct map_view view = {
		.serialized = true,
		.max_entries = 1,
		.type_name = "array",
	};
	char *out = NULL;
	size_t out_len = 0;
	int ret;

	if (argc == 3 && strcmp(argv[1], "dump") == 0)
		return dump(argv[2]);
	if (argc != 3 || (strcmp(argv[1], "json") != 0 &&
			  strcmp(argv[1], "otel") != 0 &&
			  strcmp(argv[1], "loop") != 0 &&
			  strcmp(argv[1], "memory") != 0 &&
			  strcmp(argv[1], "utf8") != 0)) {
		fprintf(stderr,
			"usage: %s <json|otel|loop|memory|utf8> <file.upatch>\n"
			"       %s dump <decoder.lua>\n",
			argv[0], argv[0]);
		return 2;
	}
	snprintf(view.upatch, sizeof(view.upatch), "%s", "t3002");
	snprintf(view.name, sizeof(view.name), "%s", "t0005_map");
	if (strcmp(argv[1], "memory") == 0)
		view.serial_bytes_total = 997;
	else if (strcmp(argv[1], "utf8") == 0)
		view.serial_bytes_total = 998;
	else if (strcmp(argv[1], "loop") == 0)
		view.serial_bytes_total = 999;
	if (strcmp(argv[1], "otel") == 0)
		ret = upatch_decode_map_file_otel(argv[2], &view,
						  &out, &out_len);
	else
		ret = upatch_decode_map_file_json(argv[2], &view,
						  &out, &out_len);
	if (ret) {
		fprintf(stderr, "decode: %d\n", ret);
		return 1;
	}
	if (fwrite(out, 1, out_len, stdout) != out_len) {
		xfree(out, out_len + 1);
		return 1;
	}
	xfree(out, out_len + 1);
	return 0;
}
