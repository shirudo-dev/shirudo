// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#include "paths.h"
#include "unit.h"
#include "upatch_pins.h"

static void names_are_parsed_strictly(void)
{
	static const char * const ignored[] = {
		"link_", "link_07", "link_1x", "link_-1", "link_+1",
		"link_4294967296", "link_ 1", "links", "xdp_prog_",
		"xdp_prog_01", "xdp_prog_a", "test", "maps", "serializers",
		".", "..",
	};
	struct upatch_pins pins = {};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(ignored); i++)
		upatch_pins_note(&pins, ignored[i]);
	EXPECT_FALSE(pins.has_link);
	EXPECT_UEQ(pins.nr_links, 0);
	EXPECT_UEQ(pins.nr_xdp_progs, 0);
	EXPECT_FALSE(upatch_pins_loaded(&pins));
}

static void lowest_index_is_kept_in_any_order(void)
{
	struct upatch_pins pins = {};

	upatch_pins_note(&pins, "link_7");
	upatch_pins_note(&pins, "link_4294967295");
	upatch_pins_note(&pins, "link_2");
	upatch_pins_note(&pins, "xdp_prog_3");
	upatch_pins_note(&pins, "xdp_prog_1");
	EXPECT_UEQ(pins.nr_links, 3);
	EXPECT_UEQ(pins.first_link, 2);
	EXPECT_UEQ(pins.nr_xdp_progs, 2);
	EXPECT_UEQ(pins.first_xdp_prog, 1);
}

static void loaded_needs_the_first_link_or_a_program(void)
{
	struct upatch_pins pins = {};

	upatch_pins_note(&pins, "link_1");
	EXPECT_FALSE(upatch_pins_loaded(&pins));
	upatch_pins_note(&pins, "link_0");
	EXPECT_TRUE(upatch_pins_loaded(&pins));

	memset(&pins, 0, sizeof(pins));
	upatch_pins_note(&pins, "link");
	EXPECT_TRUE(upatch_pins_loaded(&pins));

	memset(&pins, 0, sizeof(pins));
	upatch_pins_note(&pins, "xdp_prog_4");
	EXPECT_TRUE(upatch_pins_loaded(&pins));
}

static void complete_means_every_link(void)
{
	struct upatch_pins pins = {};

	EXPECT_TRUE(upatch_pins_complete(&pins, 0));
	EXPECT_FALSE(upatch_pins_complete(&pins, 1));
	upatch_pins_note(&pins, "link");
	EXPECT_TRUE(upatch_pins_complete(&pins, 1));

	memset(&pins, 0, sizeof(pins));
	upatch_pins_note(&pins, "link_0");
	EXPECT_FALSE(upatch_pins_complete(&pins, 1));
	EXPECT_FALSE(upatch_pins_complete(&pins, 2));
	upatch_pins_note(&pins, "link_1");
	EXPECT_TRUE(upatch_pins_complete(&pins, 2));
	EXPECT_FALSE(upatch_pins_complete(&pins, 3));

	memset(&pins, 0, sizeof(pins));
	upatch_pins_note(&pins, "link_1");
	upatch_pins_note(&pins, "link_2");
	EXPECT_FALSE(upatch_pins_complete(&pins, 2));

	memset(&pins, 0, sizeof(pins));
	upatch_pins_note(&pins, "link_0");
	upatch_pins_note(&pins, "link_2");
	EXPECT_FALSE(upatch_pins_complete(&pins, 2));
}

static void absent_upatch_has_no_pins(void)
{
	struct upatch_pins pins = { .has_link = true };

	EXPECT_EQ(upatch_pins_read("shirudo-unit-no-such-upatch", &pins),
		  -ENOENT);
	EXPECT_FALSE(pins.has_link);
	EXPECT_FALSE(upatch_loaded_pins("shirudo-unit-no-such-upatch"));
}

static void xdp_program_pins_have_one_name(void)
{
	char pin[PATH_MAX], small[8];
	size_t len;

	ASSERT_EQ(upatch_xdp_prog_pin(pin, sizeof(pin), "fw", 3), 0);
	len = strlen(pin);
	ASSERT_TRUE(len > strlen("/xdp_prog_3"));
	EXPECT_STREQ(pin + len - strlen("/xdp_prog_3"), "/xdp_prog_3");
	EXPECT_EQ(upatch_xdp_prog_pin(small, sizeof(small), "fw", 3),
		  -ENAMETOOLONG);
}

static void an_unpinned_xdp_program_does_not_open(void)
{
	__u32 id = 0;

	EXPECT_TRUE(upatch_xdp_prog_open("shirudo-unit-no-such-upatch", 0,
					 &id) < 0);
	EXPECT_EQ(id, 0);
}

static void link_pins_read_back_as_links(void)
{
	struct upatch_pins pins = {};
	char pin[64], small[8];

	ASSERT_EQ(upatch_link_pin(pin, sizeof(pin), "/d", 4294967295U), 0);
	EXPECT_STREQ(pin, "/d/link_4294967295");
	upatch_pins_note(&pins, pin + strlen("/d/"));
	EXPECT_UEQ(pins.nr_links, 1);
	EXPECT_UEQ(pins.last_link, 4294967295U);
	EXPECT_EQ(upatch_link_pin(small, sizeof(small), "/d", 10),
		  -ENAMETOOLONG);
}

static void payload_of_absent_upatch_is_enoent(void)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN];
	char name[PATH_MAX];

	EXPECT_EQ(upatch_pin_payload("shirudo-unit-no-such-upatch", payload),
		  -ENOENT);
	memset(name, 'a', sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';
	EXPECT_EQ(upatch_pin_payload(name, payload), -ENAMETOOLONG);
}

static int count_pinned(const char *name, void *ctx)
{
	(*(int *)ctx)++;
	return 0;
}

static void no_pin_directory_is_no_upatch(void)
{
	int seen = 0;

	if (access(BPFFS_UPATCHES_DIR, F_OK) == 0)
		unit_skip("this host has a shirudo pin directory");
	EXPECT_EQ(upatch_each_pinned(count_pinned, &seen), 0);
	EXPECT_EQ(seen, 0);
}

static const struct unit_case cases[] = {
	UNIT_CASE(names_are_parsed_strictly),
	UNIT_CASE(lowest_index_is_kept_in_any_order),
	UNIT_CASE(loaded_needs_the_first_link_or_a_program),
	UNIT_CASE(complete_means_every_link),
	UNIT_CASE(absent_upatch_has_no_pins),
	UNIT_CASE(xdp_program_pins_have_one_name),
	UNIT_CASE(an_unpinned_xdp_program_does_not_open),
	UNIT_CASE(link_pins_read_back_as_links),
	UNIT_CASE(payload_of_absent_upatch_is_enoent),
	UNIT_CASE(no_pin_directory_is_no_upatch),
	{}
};

UNIT_SUITE(upatch_pins, cases);
