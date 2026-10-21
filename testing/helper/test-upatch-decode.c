// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <stdio.h>
#include <string.h>

#include "util/malloc.h"
#include "util/upatch_decode.h"
#include "util/upatch_maps.h"

int main(int argc, char **argv)
{
	struct shirudo_map_view view = {
		.serialized = true,
		.max_entries = 1,
		.type_name = "array",
	};
	char *out = NULL;
	size_t out_len = 0;
	int rc;

	if (argc != 3 || (strcmp(argv[1], "json") != 0 &&
			  strcmp(argv[1], "otel") != 0 &&
			  strcmp(argv[1], "loop") != 0 &&
			  strcmp(argv[1], "memory") != 0 &&
			  strcmp(argv[1], "utf8") != 0 &&
			  strcmp(argv[1], "catch") != 0)) {
		fprintf(stderr,
			"usage: %s <json|otel|loop|memory|utf8|catch> "
			"<file.upatch>\n", argv[0]);
		return 2;
	}
	snprintf(view.upatch, sizeof(view.upatch), "%s", "t0005");
	snprintf(view.name, sizeof(view.name), "%s", "t0005_map");
	if (strcmp(argv[1], "memory") == 0)
		view.serial_bytes_total = 997;
	else if (strcmp(argv[1], "utf8") == 0)
		view.serial_bytes_total = 998;
	else if (strcmp(argv[1], "loop") == 0)
		view.serial_bytes_total = 999;
	else if (strcmp(argv[1], "catch") == 0)
		view.serial_bytes_total = 996;
	if (strcmp(argv[1], "otel") == 0)
		rc = upatch_decode_map_file_otel(argv[2], &view,
						 &out, &out_len);
	else
		rc = upatch_decode_map_file_json(argv[2], &view,
						 &out, &out_len);
	if (rc) {
		fprintf(stderr, "decode: %d\n", rc);
		return 1;
	}
	if (fwrite(out, 1, out_len, stdout) != out_len) {
		xfree(out, out_len + 1);
		return 1;
	}
	xfree(out, out_len + 1);
	return 0;
}
