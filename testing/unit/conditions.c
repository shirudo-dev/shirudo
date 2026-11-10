// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

#include "conditions.h"
#include "unit.h"

static const struct condition *condition_of(const struct conditions_input *in,
					    struct condition *c, const char *type)
{
	size_t n = conditions(in, c, CONDITIONS_MAX), i;

	for (i = 0; i < n; i++)
		if (!strcmp(c[i].type, type))
			return &c[i];
	return NULL;
}

static const struct condition *upatches_measured(const struct conditions_input *in,
						 struct condition *c)
{
	return condition_of(in, c, "UpatchesMeasured");
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

static void a_lost_link_is_tampered(void)
{
	struct conditions_input in = {
		.reachable = true,
		.parsed = true,
		.pins_rc = -ENOENT,
		.links_lost = 1,
		.links_lost_detail = "fix",
	};
	struct condition c[CONDITIONS_MAX];
	const struct condition *row;

	row = upatches_measured(&in, c);
	ASSERT_TRUE(row);
	EXPECT_STREQ(row->status, "ALERT");
	EXPECT_TRUE(strstr(row->detail, "missing a link or their archive: fix"));
	EXPECT_STREQ(status_verdict(&in), "tampered");
}

static void a_check_that_could_not_run_warns(void)
{
	struct conditions_input in = {
		.reachable = true,
		.parsed = true,
		.lsm_attached = 1,
		.checks_rc = -EACCES,
	};
	struct condition c[CONDITIONS_MAX];
	const struct condition *row;

	row = upatches_measured(&in, c);
	ASSERT_TRUE(row);
	EXPECT_STREQ(row->status, "WARN");
	EXPECT_TRUE(strstr(row->detail, "not checked"));
	EXPECT_TRUE(strcmp(status_verdict(&in), "tampered"));
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

static void an_uncovered_device_degrades(void)
{
	struct conditions_input in = {
		.reachable = true,
		.parsed = true,
		.lsm_attached = 1,
		.keyring_present = 1,
		.chain_seen = 1,
		.xdp_uncovered = 1,
		.xdp_uncovered_detail = "fw on eth1 (no multi-buffer XDP)",
	};
	struct condition c[CONDITIONS_MAX];
	const struct condition *row;
	char reason[128];

	row = condition_of(&in, c, "XdpCovered");
	ASSERT_TRUE(row);
	EXPECT_STREQ(row->status, "WARN");
	EXPECT_TRUE(strstr(row->detail, "fw on eth1 (no multi-buffer XDP)"));
	EXPECT_STREQ(status_verdict(&in), "degraded");
	status_reason(&in, reason, sizeof(reason));
	EXPECT_TRUE(strstr(reason, "XDP upatch selects"));
}

static void unchecked_coverage_warns_without_degrading(void)
{
	struct conditions_input in = {
		.reachable = true,
		.parsed = true,
		.lsm_attached = 1,
		.keyring_present = 1,
		.chain_seen = 1,
		.xdp_coverage_rc = -EACCES,
	};
	struct condition c[CONDITIONS_MAX];
	const struct condition *row;

	row = condition_of(&in, c, "XdpCovered");
	ASSERT_TRUE(row);
	EXPECT_STREQ(row->status, "WARN");
	EXPECT_TRUE(strstr(row->detail, "not checked"));
	EXPECT_STREQ(status_verdict(&in), "ok");
}

static void covered_devices_are_ok(void)
{
	struct conditions_input in = {
		.reachable = true,
		.parsed = true,
		.lsm_attached = 1,
		.keyring_present = 1,
		.chain_seen = 1,
	};
	struct condition c[CONDITIONS_MAX];
	const struct condition *row;

	row = condition_of(&in, c, "XdpCovered");
	ASSERT_TRUE(row);
	EXPECT_STREQ(row->status, "OK");
	EXPECT_STREQ(status_verdict(&in), "ok");
}

static void a_long_list_is_cut_not_dropped(void)
{
	char names[256];
	struct conditions_input in = {
		.reachable = true,
		.parsed = true,
		.lsm_attached = 1,
		.keyring_present = 1,
		.chain_seen = 1,
		.xdp_uncovered = 20,
		.xdp_uncovered_detail = names,
	};
	struct condition c[CONDITIONS_MAX];
	const struct condition *row;
	size_t len;

	memset(names, 'x', sizeof(names) - 1);
	names[sizeof(names) - 1] = '\0';
	memcpy(names, "fw on eth1", strlen("fw on eth1"));
	row = condition_of(&in, c, "XdpCovered");
	ASSERT_TRUE(row);
	len = strlen(row->detail);
	EXPECT_EQ(len, sizeof(row->detail) - 1);
	EXPECT_TRUE(strstr(row->detail, "fw on eth1"));
	EXPECT_STREQ(row->detail + len - 3, "...");
}

static const struct unit_case cases[] = {
	UNIT_CASE(changed_xdp_archive_is_tampered),
	UNIT_CASE(a_changed_archive_outranks_a_pin_warning),
	UNIT_CASE(a_lost_link_is_tampered),
	UNIT_CASE(a_check_that_could_not_run_warns),
	UNIT_CASE(no_change_leaves_the_condition_alone),
	UNIT_CASE(an_uncovered_device_degrades),
	UNIT_CASE(unchecked_coverage_warns_without_degrading),
	UNIT_CASE(covered_devices_are_ok),
	UNIT_CASE(a_long_list_is_cut_not_dropped),
	{}
};

UNIT_SUITE(conditions, cases);
