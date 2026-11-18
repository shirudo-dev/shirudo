/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The upatches-loaded table of `shirudo status`.
 */

#ifndef SHIRUDO_UTIL_UPATCH_TABLE_H
#define SHIRUDO_UTIL_UPATCH_TABLE_H

#include <stddef.h>

#include <shirudo/misc.h>
#include <shirudo/upatch.h>

#include "upatch_resolve.h"

struct json_emit;

struct upatch_table_row {
	char		name[UPATCH_NAME_MAX + 1];
	char		location[UPATCH_LOCATION_MAX];	/* SEC()-style */
	char		loaded_at[32];	/* ISO-8601 UTC, "" if unknown */
	char		status[64];	/* success or a tree skip reason */
	__u32		n_maps;
	int		missed_ret;	/* of upatch_missed_runs() */
	__u32		missed_counted;	/* links it counted, 0 for none */
	__u64		missed_runs;
	__s64		age_sec;	/* derived from loaded_at; -1 if unknown */
	char		payload_sha256[65];	/* "" if unavailable; JSON only */
};

void upatch_table_print(const struct upatch_table_row *rows,
			size_t n);

void upatch_table_emit_json(struct json_emit *e,
			    const struct upatch_table_row *rows,
			    size_t n);

__s64 upatch_age_sec(const char *ts);

#endif /* SHIRUDO_UTIL_UPATCH_TABLE_H */
