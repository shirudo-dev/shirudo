// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <string.h>

#include "keys.h"
#include "unit.h"

static struct trusted_set set;

static void member_is_found_by_fingerprint(void)
{
	__u8 absent[32];

	memset(&set, 0, sizeof(set));
	set.n = 2;
	memset(set.certs[0].fingerprint, 0x11, 32);
	memset(set.certs[1].fingerprint, 0x22, 32);
	memset(absent, 0x33, sizeof(absent));

	EXPECT_TRUE(keys_member(&set, set.certs[1].fingerprint) ==
		    &set.certs[1]);
	EXPECT_TRUE(!keys_member(&set, absent));
}

/* Entries past n are a stale tail, not members. */
static void member_past_the_count_is_none(void)
{
	__u8 stale[32];

	memset(&set, 0, sizeof(set));
	set.n = 1;
	memset(set.certs[1].fingerprint, 0x22, 32);
	memset(stale, 0x22, sizeof(stale));

	EXPECT_TRUE(!keys_member(&set, stale));
}

static const struct unit_case cases[] = {
	UNIT_CASE(member_is_found_by_fingerprint),
	UNIT_CASE(member_past_the_count_is_none),
	{}
};

UNIT_SUITE(keys, cases);
