// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>

#include "chain.h"
#include "crypto.h"
#include "measured.h"
#include "unit.h"

#define BPF	UPATCH_TYPE_BPF
#define JAVA	UPATCH_TYPE_JAVA
#define PAYLOAD "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

/* An init event lists each upatch once, by a name an upatch can have. */
static void set_takes_each_upatch_once(void)
{
	struct measured_upatch set[2];
	size_t n = 0;

	EXPECT_EQ(measured_set_add(set, &n, 2, "a", PAYLOAD, BPF), 0);
	EXPECT_EQ(measured_set_add(set, &n, 2, "a", PAYLOAD, BPF), -EEXIST);
	EXPECT_EQ(measured_set_add(set, &n, 2, "a", PAYLOAD, JAVA), -EEXIST);
	EXPECT_EQ(measured_set_add(set, &n, 2, "a\n" PAYLOAD " b", PAYLOAD,
				   BPF), -EINVAL);
	EXPECT_EQ(measured_set_add(set, &n, 2, "b", "00", BPF), -EINVAL);
	EXPECT_EQ(measured_set_add(set, &n, 2, "b", PAYLOAD, 3), -EINVAL);
	EXPECT_EQ(measured_set_add(set, &n, 2, "b", PAYLOAD, JAVA), 0);
	EXPECT_EQ(measured_set_add(set, &n, 2, "c", PAYLOAD, BPF), -E2BIG);
	ASSERT_EQ(n, 2);
	EXPECT_STREQ(set[0].name, "a");
	EXPECT_UEQ(set[0].type, BPF);
	EXPECT_STREQ(set[1].payload_hex, PAYLOAD);
	EXPECT_UEQ(set[1].type, JAVA);
}

static void member_type_is_bpf_or_java(void)
{
	__u32 type = 0;

	EXPECT_EQ(measured_member_type("", &type), 0);
	EXPECT_UEQ(type, BPF);
	EXPECT_EQ(measured_member_type("java", &type), 0);
	EXPECT_UEQ(type, JAVA);
	EXPECT_EQ(measured_member_type("bpf", &type), -EINVAL);
	EXPECT_EQ(measured_member_type("Java", &type), -EINVAL);
}

/*
 * A Java member lists with its prefix, so a set that differs only in a
 * member's type gives another init event.
 */
static void init_event_tells_java_from_bpf(void)
{
	__u8 cert[32] = {}, root[32] = {}, digest[32], want[32];
	__u8 bpf_event[32], java_event[32];
	static const char listing[] = "java " PAYLOAD " a\n";
	struct measured_upatch set[1] = {
		{ .name = "a", .payload_hex = PAYLOAD, .type = BPF },
	};

	ASSERT_EQ(chain_init_event(cert, set, 1, root, digest, bpf_event), 0);
	set[0].type = JAVA;
	ASSERT_EQ(chain_init_event(cert, set, 1, root, digest, java_event), 0);
	EXPECT_TRUE(memcmp(bpf_event, java_event, sizeof(bpf_event)));
	ASSERT_EQ(sha256_buffer(listing, sizeof(listing) - 1, want), 0);
	EXPECT_MEMEQ(digest, want, sizeof(want));
}

static const struct unit_case cases[] = {
	UNIT_CASE(set_takes_each_upatch_once),
	UNIT_CASE(member_type_is_bpf_or_java),
	UNIT_CASE(init_event_tells_java_from_bpf),
	{}
};

UNIT_SUITE(measured, cases);
