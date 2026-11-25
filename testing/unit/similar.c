// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include "unit.h"

#include <util/similar.h>

static void suggest_orders_matches_by_distance(void)
{
	const char *const cmds[] = { "status", "stop", "stats" };
	struct suggestion out[3];

	ASSERT_EQ(suggest("stops", cmds, 3, 4, out, 3), 3);
	EXPECT_STREQ(out[0].name, "stop");
	EXPECT_EQ(out[0].dist, 1);
	EXPECT_STREQ(out[1].name, "stats");
	EXPECT_EQ(out[1].dist, 2);
	EXPECT_STREQ(out[2].name, "status");
	EXPECT_EQ(out[2].dist, 3);
}

static void suggest_keeps_command_order_on_a_tie(void)
{
	const char *const cmds[] = { "status", "statue" };
	struct suggestion out[2];

	ASSERT_EQ(suggest("statux", cmds, 2, 2, out, 2), 2);
	EXPECT_STREQ(out[0].name, "status");
	EXPECT_STREQ(out[1].name, "statue");
	EXPECT_EQ(out[0].dist, out[1].dist);
}

static void suggest_drops_what_passes_the_cap(void)
{
	const char *const cmds[] = { "status", "stop", "stats" };
	struct suggestion out[2];

	ASSERT_EQ(suggest("stops", cmds, 3, 4, out, 2), 2);
	EXPECT_STREQ(out[0].name, "stop");
	EXPECT_STREQ(out[1].name, "stats");
}

static void suggest_returns_nothing_at_cap_zero(void)
{
	const char *const cmds[] = { "status" };
	struct suggestion out[1];

	EXPECT_EQ(suggest("status", cmds, 1, 4, out, 0), 0);
}

static void suggest_skips_candidates_past_max_dist(void)
{
	const char *const cmds[] = { "status", "completely-different" };
	struct suggestion out[2];

	ASSERT_EQ(suggest("status", cmds, 2, 2, out, 2), 1);
	EXPECT_STREQ(out[0].name, "status");
	EXPECT_EQ(out[0].dist, 0);
}

static void suggest_gives_up_past_the_length_bound(void)
{
	const char *const cmds[] = {
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	};
	struct suggestion out[1];

	EXPECT_EQ(suggest("a", cmds, 1, 4, out, 1), 0);
}

static void resolve_exact_beats_prefix(void)
{
	const char *const cands[] = { "load", "loader" };
	size_t m[2];

	ASSERT_EQ(resolve("load", cands, 2, m, 2), 1);
	EXPECT_EQ(m[0], 0);
}

static void resolve_counts_every_prefix_match(void)
{
	const char *const cands[] = { "load", "loader", "status" };
	size_t m[3];

	ASSERT_EQ(resolve("loa", cands, 3, m, 3), 2);
	EXPECT_EQ(m[0], 0);
	EXPECT_EQ(m[1], 1);
}

static void resolve_falls_back_to_candidate_prefix(void)
{
	const char *const cands[] = { "load", "status" };
	size_t m[2];

	ASSERT_EQ(resolve("loader", cands, 2, m, 2), 1);
	EXPECT_EQ(m[0], 0);
}

static void resolve_candidate_prefix_only_when_no_input_prefix(void)
{
	const char *const cands[] = { "loader", "load", "status" };
	size_t m[3];

	ASSERT_EQ(resolve("loader", cands, 3, m, 3), 1);
	EXPECT_EQ(m[0], 0);
}

static void resolve_reports_none(void)
{
	const char *const cands[] = { "load", "status" };
	size_t m[2];

	EXPECT_EQ(resolve("nope", cands, 2, m, 2), 0);
}

static void resolve_cap_cuts_the_match_list(void)
{
	const char *const cands[] = { "xa", "xb", "xc" };
	size_t m[3];

	ASSERT_EQ(resolve("x", cands, 3, m, 2), 2);
	EXPECT_EQ(m[0], 0);
	EXPECT_EQ(m[1], 1);
}

static const struct unit_case cases[] = {
	UNIT_CASE(suggest_orders_matches_by_distance),
	UNIT_CASE(suggest_keeps_command_order_on_a_tie),
	UNIT_CASE(suggest_drops_what_passes_the_cap),
	UNIT_CASE(suggest_returns_nothing_at_cap_zero),
	UNIT_CASE(suggest_skips_candidates_past_max_dist),
	UNIT_CASE(suggest_gives_up_past_the_length_bound),
	UNIT_CASE(resolve_exact_beats_prefix),
	UNIT_CASE(resolve_counts_every_prefix_match),
	UNIT_CASE(resolve_falls_back_to_candidate_prefix),
	UNIT_CASE(resolve_candidate_prefix_only_when_no_input_prefix),
	UNIT_CASE(resolve_reports_none),
	UNIT_CASE(resolve_cap_cuts_the_match_list),
	{}
};

UNIT_SUITE(similar, cases);
