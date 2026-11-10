// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "unit.h"
#include "upatch.h"

#define ONE_PROG_LEN \
	(sizeof(struct upatch_prog_metadata) + sizeof(struct upatch_prog_entry))

static void one_raw_tracepoint(__u8 *buf, __u32 nr_maps)
{
	struct upatch_prog_metadata md = {};
	struct upatch_prog_entry prog = {};

	md.magic = cpu_to_le32(UPATCH_PROG_MAGIC);
	md.version = cpu_to_le32(UPATCH_PROG_VERSION);
	md.nr_progs = cpu_to_le32(1);
	md.nr_maps = cpu_to_le32(nr_maps);
	prog.role = cpu_to_le32(UPATCH_PROG_ROLE_ATTACH);
	prog.kind = cpu_to_le32(UPATCH_ATTACH_RAW_TRACEPOINT);
	memcpy(buf, &md, sizeof(md));
	memcpy(buf + sizeof(md), &prog, sizeof(prog));
}

static void prog_specs_take_the_signed_counts(void)
{
	struct prog_spec *specs = NULL;
	__u8 buf[ONE_PROG_LEN];

	one_raw_tracepoint(buf, 3);
	ASSERT_EQ(prog_specs_parse(buf, sizeof(buf), 3, 1, &specs), 0);
	ASSERT_TRUE(specs);
	EXPECT_UEQ(specs[0].role, UPATCH_PROG_ROLE_ATTACH);
	EXPECT_UEQ(specs[0].kind, UPATCH_ATTACH_RAW_TRACEPOINT);
	EXPECT_EQ(specs[0].target_fd, -1);
	prog_specs_free(specs, 1);
}

static void prog_specs_refuse_another_header_count(void)
{
	struct prog_spec *specs = NULL;
	__u8 buf[ONE_PROG_LEN];

	one_raw_tracepoint(buf, 3);
	EXPECT_EQ(prog_specs_parse(buf, sizeof(buf), 4, 1, &specs), -EINVAL);
	EXPECT_FALSE(specs);
	EXPECT_EQ(prog_specs_parse(buf, sizeof(buf), 2, 1, &specs), -EINVAL);
	EXPECT_EQ(prog_specs_parse(buf, sizeof(buf), 3, 2, &specs), -EINVAL);
	EXPECT_EQ(prog_specs_parse(buf, sizeof(buf), 3, 0, &specs), -EINVAL);
	EXPECT_FALSE(specs);
}

static void header_name_is_terminated(void)
{
	char out[UPATCH_NAME_MAX + 1];
	struct upatch u = {};

	memcpy(u.hdr.name, "kernel-obs", 10);
	upatch_header_name(&u, out);
	EXPECT_STREQ(out, "kernel-obs");
	memset(u.hdr.name, 'a', sizeof(u.hdr.name));
	upatch_header_name(&u, out);
	EXPECT_EQ(strlen(out), UPATCH_NAME_MAX);
}

static void prog_name_is_what_the_kernel_takes(void)
{
	char out[16];
	struct upatch u = {};

	memcpy(u.hdr.name, "fix-cve.2026", 12);
	upatch_prog_name(&u, out, sizeof(out));
	EXPECT_STREQ(out, "fix_cve.2026");
	memset(u.hdr.name, 'a', sizeof(u.hdr.name));
	upatch_prog_name(&u, out, sizeof(out));
	EXPECT_EQ(strlen(out), 15);
}

static void name_signed_is_the_header_name(void)
{
	char signed_name[UPATCH_NAME_MAX] = "fix";
	struct upatch u = {};

	memcpy(u.hdr.name, "fix", 3);
	u.map = (const __u8 *)signed_name;
	EXPECT_FALSE(upatch_name_signed(&u));
	u.signed_name = signed_name;
	EXPECT_TRUE(upatch_name_signed(&u));
	u.hdr.name[2] = 'y';
	EXPECT_FALSE(upatch_name_signed(&u));
}

#define PAYLOAD "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

static void member_is_a_name_and_a_payload(void)
{
	EXPECT_TRUE(upatch_member_valid("fix", PAYLOAD));
	EXPECT_FALSE(upatch_member_valid("a\nb", PAYLOAD));
	EXPECT_FALSE(upatch_member_valid("../fix", PAYLOAD));
	EXPECT_FALSE(upatch_member_valid("", PAYLOAD));
	EXPECT_FALSE(upatch_member_valid("fix", PAYLOAD "0"));
	EXPECT_FALSE(upatch_member_valid("fix", "00"));
	EXPECT_FALSE(upatch_member_valid("fix", NULL));
}

/* A name's pin directory spells each dot in two bytes, within NAME_MAX. */
static void name_fits_its_pin_directory(void)
{
	char name[NAME_MAX + 2];

	memset(name, 'a', NAME_MAX);
	name[NAME_MAX] = '\0';
	EXPECT_TRUE(upatch_name_valid(name));
	name[NAME_MAX - 1] = '.';
	EXPECT_FALSE(upatch_name_valid(name));
	name[NAME_MAX - 1] = '\0';
	name[NAME_MAX - 2] = '.';
	EXPECT_TRUE(upatch_name_valid(name));
	memset(name, 'a', NAME_MAX + 1);
	name[NAME_MAX + 1] = '\0';
	EXPECT_FALSE(upatch_name_valid(name));
}

static void xdp_classes_come_from_xdp_programs_alone(void)
{
	struct prog_spec specs[] = {
		{ .kind = UPATCH_ATTACH_XDP, .device_classes = 1 },
		{ .kind = UPATCH_ATTACH_RAW_TRACEPOINT, .device_classes = 16 },
		{ .kind = UPATCH_ATTACH_XDP, .device_classes = 8 },
	};

	EXPECT_UEQ(prog_specs_xdp_classes(specs, 3), 9);
	EXPECT_UEQ(prog_specs_xdp_classes(specs + 1, 1), 0);
	EXPECT_UEQ(prog_specs_xdp_classes(specs, 0), 0);
}

static void xdp_masks_are_signed_and_bounded(void)
{
	struct upatch_prog_entry prog = {};
	struct prog_spec *specs = NULL;
	__u8 buf[ONE_PROG_LEN];
	__u32 mask;

	EXPECT_UEQ(sizeof(prog), 160);
	for (mask = 1; mask <= 31; mask++) {
		one_raw_tracepoint(buf, 0);
		prog.kind = cpu_to_le32(UPATCH_ATTACH_XDP);
		prog.xdp.device_classes = cpu_to_le32(mask);
		memcpy(buf + sizeof(struct upatch_prog_metadata), &prog, sizeof(prog));
		if (mask & ~(__u32)UPATCH_XDP_ALL) {
			EXPECT_TRUE(prog_specs_parse(buf, sizeof(buf), 0, 1, &specs) < 0);
			continue;
		}
		ASSERT_EQ(prog_specs_parse(buf, sizeof(buf), 0, 1, &specs), 0);
		EXPECT_UEQ(specs[0].kind, UPATCH_ATTACH_XDP);
		EXPECT_UEQ(specs[0].device_classes, mask);
		EXPECT_UEQ(specs[0].offset, 0);
		prog_specs_free(specs, 1);
	}
	for (mask = 0; mask < 7; mask++) {
		memset(&prog, 0, sizeof(prog));
		prog.kind = cpu_to_le32(UPATCH_ATTACH_XDP);
		prog.xdp.device_classes = cpu_to_le32(UPATCH_XDP_ALL);
		if (mask == 0)
			prog.xdp.device_classes = 0;
		else if (mask == 1)
			prog.xdp.device_classes = cpu_to_le32(32);
		else if (mask == 2)
			prog.xdp.reserved = cpu_to_le32(1);
		else if (mask == 3)
			prog.target[0] = 'x';
		else if (mask == 4)
			prog.map[0] = 'x';
		else if (mask == 5)
			prog.target[sizeof(prog.target) - 1] = 'x';
		else
			prog.map[sizeof(prog.map) - 1] = 'x';
		memcpy(buf + sizeof(struct upatch_prog_metadata), &prog, sizeof(prog));
		EXPECT_EQ(prog_specs_parse(buf, sizeof(buf), 0, 1, &specs), -EINVAL);
		EXPECT_FALSE(specs);
	}
}

static int parse_two_xdp(__u32 first, __u32 second, struct prog_spec **specs)
{
	__u8 buf[sizeof(struct upatch_prog_metadata) +
		 2 * sizeof(struct upatch_prog_entry)];
	struct upatch_prog_metadata md = {};
	struct upatch_prog_entry prog = {};

	md.magic = cpu_to_le32(UPATCH_PROG_MAGIC);
	md.version = cpu_to_le32(UPATCH_PROG_VERSION);
	md.nr_progs = cpu_to_le32(2);
	memcpy(buf, &md, sizeof(md));
	prog.role = cpu_to_le32(UPATCH_PROG_ROLE_ATTACH);
	prog.kind = cpu_to_le32(UPATCH_ATTACH_XDP);
	prog.xdp.device_classes = cpu_to_le32(first);
	memcpy(buf + sizeof(md), &prog, sizeof(prog));
	prog.xdp.device_classes = cpu_to_le32(second);
	memcpy(buf + sizeof(md) + sizeof(prog), &prog, sizeof(prog));
	return prog_specs_parse(buf, sizeof(buf), 0, 2, specs);
}

static void xdp_programs_select_disjoint_classes(void)
{
	struct prog_spec *specs = NULL;

	ASSERT_EQ(parse_two_xdp(UPATCH_XDP_NETWORK, UPATCH_XDP_VIRTUAL, &specs),
		  0);
	prog_specs_free(specs, 2);
	specs = NULL;
	EXPECT_EQ(parse_two_xdp(UPATCH_XDP_NETWORK | UPATCH_XDP_VIRTUAL,
				UPATCH_XDP_VIRTUAL, &specs), -EINVAL);
	EXPECT_FALSE(specs);
}

static const struct unit_case cases[] = {
	UNIT_CASE(prog_specs_take_the_signed_counts),
	UNIT_CASE(prog_specs_refuse_another_header_count),
	UNIT_CASE(header_name_is_terminated),
	UNIT_CASE(prog_name_is_what_the_kernel_takes),
	UNIT_CASE(name_signed_is_the_header_name),
	UNIT_CASE(member_is_a_name_and_a_payload),
	UNIT_CASE(name_fits_its_pin_directory),
	UNIT_CASE(xdp_classes_come_from_xdp_programs_alone),
	UNIT_CASE(xdp_masks_are_signed_and_bounded),
	UNIT_CASE(xdp_programs_select_disjoint_classes),
	{}
};

UNIT_SUITE(upatch, cases);
