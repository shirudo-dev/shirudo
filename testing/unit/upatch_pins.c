// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>

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

static const struct unit_case cases[] = {
	UNIT_CASE(names_are_parsed_strictly),
	UNIT_CASE(lowest_index_is_kept_in_any_order),
	UNIT_CASE(loaded_needs_the_first_link_or_a_program),
	UNIT_CASE(complete_means_every_link),
	UNIT_CASE(absent_upatch_has_no_pins),
	{}
};

UNIT_SUITE(upatch_pins, cases);
