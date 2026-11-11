// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

#include "paths.h"
#include "unit.h"

static void pin_path_is_the_bpffs_name_and_its_parts(void)
{
	char out[256];

	ASSERT_EQ(upatch_pin_path(out, sizeof(out), "kernel.obs", NULL), 0);
	EXPECT_STREQ(out, BPFFS_UPATCHES_DIR "/kernel~dobs");
	ASSERT_EQ(upatch_pin_path(out, sizeof(out), "a", "link", NULL), 0);
	EXPECT_STREQ(out, BPFFS_UPATCHES_DIR "/a/link");
	ASSERT_EQ(upatch_pin_path(out, sizeof(out), "a.b", "maps", "m.1", NULL),
		  0);
	EXPECT_STREQ(out, BPFFS_UPATCHES_DIR "/a~db/maps/m.1");
}

static void pin_path_too_long_is_empty(void)
{
	char out[sizeof(BPFFS_UPATCHES_DIR "/a/link")];

	EXPECT_EQ(upatch_pin_path(out, sizeof(out), "a", "link", NULL), 0);
	EXPECT_EQ(upatch_pin_path(out, sizeof(out), "ab", "link", NULL),
		  -ENAMETOOLONG);
	EXPECT_STREQ(out, "");
	EXPECT_EQ(upatch_pin_path(out, sizeof(out), "a", "links", NULL),
		  -ENAMETOOLONG);
	EXPECT_STREQ(out, "");
}

static void join_is_dir_slash_name(void)
{
	char out[sizeof("dir/name")];

	ASSERT_EQ(path_join(out, sizeof(out), "dir", "name"), 0);
	EXPECT_STREQ(out, "dir/name");
	EXPECT_EQ(path_join(out, sizeof(out), "dir", "names"), -ENAMETOOLONG);
	EXPECT_STREQ(out, "");
}

static void bpffs_name_round_trips(void)
{
	char bpffs[64], back[32];

	ASSERT_EQ(upatch_bpffs_name(bpffs, sizeof(bpffs), "a.b..c"), 0);
	EXPECT_STREQ(bpffs, "a~db~d~dc");
	ASSERT_EQ(upatch_name_from_bpffs(back, sizeof(back), bpffs), 0);
	EXPECT_STREQ(back, "a.b..c");
	EXPECT_EQ(upatch_name_from_bpffs(back, sizeof(back), "a~x"), -EINVAL);
	EXPECT_EQ(upatch_name_from_bpffs(back, sizeof(back), "a~"), -EINVAL);
	EXPECT_EQ(upatch_bpffs_name(bpffs, 4, "a.b"), -ENAMETOOLONG);
}

static const struct unit_case cases[] = {
	UNIT_CASE(pin_path_is_the_bpffs_name_and_its_parts),
	UNIT_CASE(pin_path_too_long_is_empty),
	UNIT_CASE(join_is_dir_slash_name),
	UNIT_CASE(bpffs_name_round_trips),
	{}
};

UNIT_SUITE(paths, cases);
