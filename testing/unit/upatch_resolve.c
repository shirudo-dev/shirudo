// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>

#include "unit.h"
#include "upatch_resolve.h"

static int never_called(__u32 index, const char *pin,
			const struct bpf_link_info *info, void *ctx)
{
	(*(int *)ctx)++;
	return 0;
}

static void links_of_an_absent_upatch_are_not_read(void)
{
	int calls = 0;

	EXPECT_EQ(upatch_each_link_info("shirudo-unit-no-such-upatch",
					never_called, &calls), -ENOENT);
	EXPECT_EQ(calls, 0);
}

static const struct unit_case cases[] = {
	UNIT_CASE(links_of_an_absent_upatch_are_not_read),
	{}
};

UNIT_SUITE(upatch_resolve, cases);
