// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "unit.h"

#include <shirudo/string.h>

#include <util/json.h>
#include <util/upatch_table.h>

static struct upatch_table_row row(const char *name, const char *location)
{
	struct upatch_table_row r = {};

	ASSERT_TRUE(strscpy(r.name, name, sizeof(r.name)) >= 0);
	ASSERT_TRUE(strscpy(r.location, location, sizeof(r.location)) >= 0);
	return r;
}

static void age_sec_parses_a_utc_timestamp(void)
{
	__s64 age = upatch_age_sec("2000-01-01T00:00:00Z");

	EXPECT_GT(age, 20LL * 365 * 24 * 3600);
}

static void age_sec_is_negative_for_a_future_timestamp(void)
{
	EXPECT_LT(upatch_age_sec("2999-12-31T23:59:59Z"), 0);
}

static void age_sec_rejects_what_is_not_a_timestamp(void)
{
	EXPECT_EQ(upatch_age_sec(NULL), -1);
	EXPECT_EQ(upatch_age_sec(""), -1);
	EXPECT_EQ(upatch_age_sec("not-a-date"), -1);
	EXPECT_EQ(upatch_age_sec("2026-01-01 00:00:00"), -1);
	EXPECT_EQ(upatch_age_sec("2026-01-01T00:00:00+01:00"), -1);
}

static void capture(char *buf, size_t cap,
		    const struct upatch_table_row *rows, size_t n)
{
	FILE *f = tmpfile();
	ssize_t got;
	int saved;

	ASSERT_TRUE(f);
	fflush(stdout);
	saved = dup(STDOUT_FILENO);
	ASSERT_TRUE(saved >= 0);
	ASSERT_EQ(dup2(fileno(f), STDOUT_FILENO), STDOUT_FILENO);
	upatch_table_print(rows, n);
	fflush(stdout);
	ASSERT_EQ(dup2(saved, STDOUT_FILENO), STDOUT_FILENO);
	ASSERT_EQ(close(saved), 0);
	rewind(f);
	got = fread(buf, 1, cap - 1, f);
	ASSERT_TRUE(got >= 0);
	buf[got] = '\0';
	ASSERT_EQ(fclose(f), 0);
}

static void print_marks_an_empty_table(void)
{
	char buf[256];

	capture(buf, sizeof(buf), NULL, 0);
	EXPECT_STREQ(buf, "\nLoaded upatches (0):\n  none\n");
}

static void print_shows_every_column(void)
{
	struct upatch_table_row r = row("demo", "xdp");
	char buf[1024];

	r.n_maps = 2;
	r.missed_counted = 1;
	r.missed_runs = 3;
	r.age_sec = 90;
	capture(buf, sizeof(buf), &r, 1);
	EXPECT_STREQ(buf,
		     "\nLoaded upatches (1):\n"
		     "  NAME                      LOCATION                       MAPS  MISSED  STATUS                        AGE\n"
		     "  demo                      xdp                               2       3  success                       1m\n");
}

static void print_falls_back_on_missing_fields(void)
{
	struct upatch_table_row r = row("demo", "xdp");
	char buf[1024];

	r.missed_ret = -5;
	r.age_sec = -1;
	capture(buf, sizeof(buf), &r, 1);
	EXPECT_STREQ(buf,
		     "\nLoaded upatches (1):\n"
		     "  NAME                      LOCATION                       MAPS  MISSED  STATUS                        AGE\n"
		     "  demo                      xdp                               0       ?  success                       ?\n");
}

static void print_marks_an_upatch_with_no_counted_links(void)
{
	struct upatch_table_row r = row("demo", "xdp");
	char buf[1024];

	r.age_sec = 30;
	capture(buf, sizeof(buf), &r, 1);
	EXPECT_STREQ(buf,
		     "\nLoaded upatches (1):\n"
		     "  NAME                      LOCATION                       MAPS  MISSED  STATUS                        AGE\n"
		     "  demo                      xdp                               0       -  success                       30s\n");
}

static void print_shows_a_skip_status(void)
{
	struct upatch_table_row r = row("demo", "xdp");
	char buf[1024];

	ASSERT_TRUE(strscpy(r.status, "skipped", sizeof(r.status)) >= 0);
	capture(buf, sizeof(buf), &r, 1);
	EXPECT_TRUE(str_contains(buf, "skipped"));
}

static void emit(char *buf, size_t cap,
		 const struct upatch_table_row *rows, size_t n)
{
	struct json_emit e = { .buf = buf, .cap = cap };

	json_obj_open(&e);
	upatch_table_emit_json(&e, rows, n);
	json_obj_close(&e);
	ASSERT_EQ(e.err, 0);
}

static void json_has_an_empty_array_for_no_rows(void)
{
	char buf[256];

	emit(buf, sizeof(buf), NULL, 0);
	EXPECT_STREQ(buf, "{\"upatches_loaded\":[]}");
}

static void json_emits_every_field(void)
{
	struct upatch_table_row r = row("demo", "xdp");
	char buf[1024];

	ASSERT_TRUE(strscpy(r.loaded_at, "2026-11-20T12:34:56Z",
			    sizeof(r.loaded_at)) >= 0);
	ASSERT_TRUE(strscpy(r.payload_sha256, "0123456789abcdef",
			    sizeof(r.payload_sha256)) >= 0);
	r.n_maps = 2;
	r.missed_counted = 1;
	r.missed_runs = 3;
	r.age_sec = 90;
	emit(buf, sizeof(buf), &r, 1);
	EXPECT_STREQ(buf,
		     "{\"upatches_loaded\":[{\"name\":\"demo\","
		     "\"location\":\"xdp\",\"status\":\"success\","
		     "\"n_maps\":2,\"missed_runs\":3,"
		     "\"loaded_at\":\"2026-11-20T12:34:56Z\","
		     "\"age_sec\":90,"
		     "\"payload_sha256\":\"0123456789abcdef\"}]}");
}

static void json_emits_null_for_missing_fields(void)
{
	struct upatch_table_row r = row("demo", "xdp");
	char buf[1024];

	ASSERT_TRUE(strscpy(r.status, "skipped", sizeof(r.status)) >= 0);
	r.missed_ret = -5;
	r.age_sec = -1;
	emit(buf, sizeof(buf), &r, 1);
	EXPECT_STREQ(buf,
		     "{\"upatches_loaded\":[{\"name\":\"demo\","
		     "\"location\":\"xdp\",\"status\":\"skipped\","
		     "\"n_maps\":0,\"missed_runs\":null,"
		     "\"loaded_at\":\"\",\"age_sec\":null,"
		     "\"payload_sha256\":null}]}");
}

static void json_prefers_the_read_error_over_a_count(void)
{
	struct upatch_table_row r = row("demo", "xdp");
	char buf[1024];

	r.missed_ret = -5;
	r.missed_counted = 1;
	r.missed_runs = 3;
	r.age_sec = 0;
	emit(buf, sizeof(buf), &r, 1);
	EXPECT_TRUE(str_contains(buf, "\"missed_runs\":null"));
}

static const struct unit_case cases[] = {
	UNIT_CASE(age_sec_parses_a_utc_timestamp),
	UNIT_CASE(age_sec_is_negative_for_a_future_timestamp),
	UNIT_CASE(age_sec_rejects_what_is_not_a_timestamp),
	UNIT_CASE(print_marks_an_empty_table),
	UNIT_CASE(print_shows_every_column),
	UNIT_CASE(print_falls_back_on_missing_fields),
	UNIT_CASE(print_marks_an_upatch_with_no_counted_links),
	UNIT_CASE(print_shows_a_skip_status),
	UNIT_CASE(json_has_an_empty_array_for_no_rows),
	UNIT_CASE(json_emits_every_field),
	UNIT_CASE(json_emits_null_for_missing_fields),
	UNIT_CASE(json_prefers_the_read_error_over_a_count),
	{}
};

UNIT_SUITE(upatch_table, cases);
