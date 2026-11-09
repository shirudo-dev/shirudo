// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

#include "conditions.h"
#include "unit.h"

static const struct condition *upatches_measured(const struct conditions_input *in,
						 struct condition *c)
{
	size_t n = conditions(in, c, CONDITIONS_MAX), i;

	for (i = 0; i < n; i++)
		if (!strcmp(c[i].type, "UpatchesMeasured"))
			return &c[i];
	return NULL;
}

static void changed_xdp_archive_is_tampered(void)
{
	struct conditions_input in = {
		.reachable = true,
		.parsed = true,
		.lsm_attached = 1,
		.xdp_tampered = 1,
		.xdp_tampered_detail = "fix",
	};
	struct condition c[CONDITIONS_MAX];
	const struct condition *row;

	row = upatches_measured(&in, c);
	ASSERT_TRUE(row);
	EXPECT_STREQ(row->status, "ALERT");
	EXPECT_TRUE(strstr(row->detail, "1 XDP archives differ"));
	EXPECT_TRUE(strstr(row->detail, "fix"));
	EXPECT_STREQ(status_verdict(&in), "tampered");
}

static void a_changed_archive_outranks_a_pin_warning(void)
{
	struct conditions_input in = {
		.reachable = true,
		.parsed = true,
		.pins_rc = -ENOENT,
		.xdp_tampered = 2,
	};
	struct condition c[CONDITIONS_MAX];
	const struct condition *row;

	row = upatches_measured(&in, c);
	ASSERT_TRUE(row);
	EXPECT_STREQ(row->status, "ALERT");
}

static void no_change_leaves_the_condition_alone(void)
{
	struct conditions_input in = {
		.reachable = true,
		.parsed = true,
		.lsm_attached = 1,
	};
	struct condition c[CONDITIONS_MAX];
	const struct condition *row;

	row = upatches_measured(&in, c);
	ASSERT_TRUE(row);
	EXPECT_STREQ(row->status, "OK");
	EXPECT_TRUE(strcmp(status_verdict(&in), "tampered"));
}

static const struct unit_case cases[] = {
	UNIT_CASE(changed_xdp_archive_is_tampered),
	UNIT_CASE(a_changed_archive_outranks_a_pin_warning),
	UNIT_CASE(no_change_leaves_the_condition_alone),
	{}
};

UNIT_SUITE(conditions, cases);
