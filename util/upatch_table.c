// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Unified upatches-loaded table; see util/upatch_table.h.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "json.h"
#include "timefmt.h"
#include "upatch_table.h"

__s64 upatch_age_sec(const char *ts)
{
	struct tm tm = {};

	if (!ts || !ts[0])
		return -1;
	if (!strptime(ts, "%Y-%m-%dT%H:%M:%SZ", &tm))
		return -1;
	return (__s64)(time(NULL) - timegm(&tm));
}

/* "?" when they could not be read, "-" for an upatch of no counted kind. */
static const char *missed_text(const struct upatch_table_row *r, char *buf,
			       size_t cap)
{
	if (r->missed_ret)
		return "?";
	if (!r->missed_counted)
		return "-";
	return strsprintf(buf, cap, "%llu", r->missed_runs) < 0 ? "?" : buf;
}

void upatch_table_print(const struct upatch_table_row *rows,
			size_t n)
{
	size_t i;

	printf("\nLoaded upatches (%zu):\n", n);
	if (n == 0) {
		printf("  none\n");
		return;
	}
	printf("  %-24s  %-28s  %5s  %6s  %-28s  %s\n",
	       "NAME", "LOCATION", "MAPS", "MISSED", "STATUS", "AGE");
	for (i = 0; i < n; i++) {
		const struct upatch_table_row *r = &rows[i];
		char age[16] = "?", missed[24];

		if (r->age_sec >= 0)
			format_duration((long)r->age_sec,
					age, sizeof(age));
		printf("  %-24s  %-28s  %5u  %6s  %-28s  %s\n", r->name,
		       r->location[0] ? r->location : "-", r->n_maps,
		       missed_text(r, missed, sizeof(missed)),
		       r->status[0] ? r->status : "success", age);
	}
}

void upatch_table_emit_json(struct json_emit *e,
			    const struct upatch_table_row *rows,
			    size_t n)
{
	size_t i;

	json_arr_open(e, "upatches_loaded");
	for (i = 0; i < n; i++) {
		const struct upatch_table_row *r = &rows[i];

		json_obj_open(e);
		json_kv_string(e, "name", r->name);
		json_kv_string(e, "location", r->location);
		json_kv_string(e, "status",
			       r->status[0] ? r->status : "success");
		json_kv_int(e, "n_maps", (__s64)r->n_maps);
		if (!r->missed_ret && r->missed_counted)
			json_kv_u64(e, "missed_runs", r->missed_runs);
		else
			json_kv_null(e, "missed_runs");
		json_kv_string(e, "loaded_at", r->loaded_at);
		if (r->age_sec >= 0)
			json_kv_int(e, "age_sec", r->age_sec);
		else
			json_kv_null(e, "age_sec");
		if (r->payload_sha256[0])
			json_kv_string(e, "payload_sha256",
				       r->payload_sha256);
		else
			json_kv_null(e, "payload_sha256");
		json_obj_close(e);
	}
	json_arr_close(e);
}
