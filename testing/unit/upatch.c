// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <limits.h>
#include <stddef.h>
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

#define KPROBE_BLOCK_LEN \
	(sizeof(struct upatch_kprobe_targets) + \
	 sizeof(struct upatch_kprobe_target))
#define KPROBE_NAMES_MAX	16

/* Metadata of one program whose UPKS block holds the given names. */
static __u32 one_kprobe_multi(__u8 *buf, __u32 kind, const char *names,
			      __u32 names_len, __u32 nr_syms)
{
	struct upatch_kprobe_targets targets = {};
	struct upatch_kprobe_target record = {};
	struct upatch_prog_entry prog;
	__u8 *cursor = buf + ONE_PROG_LEN;

	one_raw_tracepoint(buf, 0);
	memcpy(&prog, buf + sizeof(struct upatch_prog_metadata), sizeof(prog));
	prog.kind = cpu_to_le32(kind);
	memcpy(buf + sizeof(struct upatch_prog_metadata), &prog, sizeof(prog));
	targets.magic = cpu_to_le32(UPATCH_KPROBE_TARGET_MAGIC);
	targets.version = cpu_to_le32(UPATCH_KPROBE_TARGET_VERSION);
	targets.nr_targets = cpu_to_le32(1);
	record.nr_syms = cpu_to_le32(nr_syms);
	record.syms_len = cpu_to_le32(names_len);
	memcpy(cursor, &targets, sizeof(targets));
	cursor += sizeof(targets);
	memcpy(cursor, &record, sizeof(record));
	cursor += sizeof(record);
	memcpy(cursor, names, names_len);
	return (__u32)(ONE_PROG_LEN + KPROBE_BLOCK_LEN + names_len);
}

static int parse_one(const __u8 *buf, __u32 len)
{
	struct prog_spec *specs = NULL;
	int ret;

	ret = prog_specs_parse(buf, len, 0, 1, &specs);
	if (!ret)
		prog_specs_free(specs, 1);
	else
		EXPECT_FALSE(specs);
	return ret;
}

static void kprobe_multi_names_are_parsed_in_order(void)
{
	__u8 buf[ONE_PROG_LEN + KPROBE_BLOCK_LEN + KPROBE_NAMES_MAX];
	struct prog_spec *specs = NULL;
	__u32 len;

	len = one_kprobe_multi(buf, UPATCH_ATTACH_KRETPROBE_MULTI, "vfs_a\0vfs_b", 12, 2);
	ASSERT_EQ(prog_specs_parse(buf, len, 0, 1, &specs), 0);
	EXPECT_UEQ(specs[0].kind, UPATCH_ATTACH_KRETPROBE_MULTI);
	ASSERT_UEQ(specs[0].nr_kprobe_syms, 2);
	EXPECT_STREQ(specs[0].kprobe_syms[0], "vfs_a");
	EXPECT_STREQ(specs[0].kprobe_syms[1], "vfs_b");
	prog_specs_free(specs, 1);
}

static void kprobe_multi_refuses_a_malformed_list(void)
{
	__u8 buf[ONE_PROG_LEN + KPROBE_BLOCK_LEN + KPROBE_NAMES_MAX];
	const __u32 k = UPATCH_ATTACH_KPROBE_MULTI;
	__u32 len;

	len = one_kprobe_multi(buf, k, "b\0a", 4, 2);
	EXPECT_EQ(parse_one(buf, len), -EINVAL);
	len = one_kprobe_multi(buf, k, "a\0a", 4, 2);
	EXPECT_EQ(parse_one(buf, len), -EINVAL);
	len = one_kprobe_multi(buf, k, "a\0b", 4, 1);
	EXPECT_EQ(parse_one(buf, len), -EINVAL);
	len = one_kprobe_multi(buf, k, "a", 2, 0);
	EXPECT_EQ(parse_one(buf, len), -EINVAL);
	len = one_kprobe_multi(buf, k, "a*", 3, 1);
	EXPECT_EQ(parse_one(buf, len), -EINVAL);
	len = one_kprobe_multi(buf, k, "\0a", 3, 1);
	EXPECT_EQ(parse_one(buf, len), -EINVAL);
	len = one_kprobe_multi(buf, k, "abc", 3, 1);
	EXPECT_EQ(parse_one(buf, len), -EINVAL);
}

static void kprobe_multi_block_is_exact(void)
{
	__u8 buf[ONE_PROG_LEN + KPROBE_BLOCK_LEN + KPROBE_NAMES_MAX];
	struct upatch_prog_entry prog;
	__u32 len;

	len = one_kprobe_multi(buf, UPATCH_ATTACH_KPROBE_MULTI, "a", 2, 1);
	EXPECT_EQ(parse_one(buf, len), 0);
	EXPECT_EQ(parse_one(buf, ONE_PROG_LEN), -EINVAL);
	EXPECT_EQ(parse_one(buf, len - 1), -EINVAL);
	EXPECT_EQ(parse_one(buf, len + 1), -EINVAL);

	buf[ONE_PROG_LEN] ^= 1;
	EXPECT_EQ(parse_one(buf, len), -EINVAL);
	buf[ONE_PROG_LEN] ^= 1;

	memcpy(&prog, buf + sizeof(struct upatch_prog_metadata), sizeof(prog));
	prog.target[0] = 'a';
	memcpy(buf + sizeof(struct upatch_prog_metadata), &prog, sizeof(prog));
	EXPECT_EQ(parse_one(buf, len), -EINVAL);
	prog.target[0] = '\0';
	prog.offset = cpu_to_le64(1);
	memcpy(buf + sizeof(struct upatch_prog_metadata), &prog, sizeof(prog));
	EXPECT_EQ(parse_one(buf, len), -EINVAL);
}

static void kprobe_sym_is_one_plain_name(void)
{
	char name[UPATCH_KPROBE_SYM_MAX + 1];

	EXPECT_TRUE(kprobe_sym_valid("vfs_read", 8));
	EXPECT_TRUE(kprobe_sym_valid("foo.cold.1", 10));
	EXPECT_FALSE(kprobe_sym_valid("", 0));
	EXPECT_FALSE(kprobe_sym_valid("a,b", 3));
	EXPECT_FALSE(kprobe_sym_valid("a*", 2));
	EXPECT_FALSE(kprobe_sym_valid("a?", 2));
	EXPECT_FALSE(kprobe_sym_valid("a|b", 3));
	EXPECT_FALSE(kprobe_sym_valid("a b", 3));
	EXPECT_FALSE(kprobe_sym_valid("a\n", 2));
	EXPECT_FALSE(kprobe_sym_valid("a\x7f", 2));
	EXPECT_FALSE(kprobe_sym_valid("a\xc3", 2));
	memset(name, 'a', sizeof(name));
	EXPECT_TRUE(kprobe_sym_valid(name, UPATCH_KPROBE_SYM_MAX - 1));
	EXPECT_FALSE(kprobe_sym_valid(name, UPATCH_KPROBE_SYM_MAX));
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

struct java_fixture {
	struct upatch_header header;
	__u8 signature[8];
	__u8 jar[8];
	char name[UPATCH_NAME_MAX];
	__le32 type;
	__u8 pad[4];
	struct upatch_signed_section dir[3];
	struct upatch_signed_trailer trailer;
};

#define JAVA_DATA_OFF	offsetof(struct java_fixture, jar)

static void java_section(struct java_fixture *f, __u32 i, __u32 tag,
			 size_t off, __u32 len)
{
	f->dir[i].tag = cpu_to_le32(tag);
	f->dir[i].off = cpu_to_le32(off - JAVA_DATA_OFF);
	f->dir[i].len = cpu_to_le32(len);
}

static void java_load(struct java_fixture *f, __u32 signed_type)
{
	memset(f, 0, sizeof(*f));
	f->header.magic = cpu_to_le64(UPATCH_MAGIC);
	f->header.version = cpu_to_le32(UPATCH_VERSION);
	f->header.type = cpu_to_le32(UPATCH_TYPE_JAVA);
	memcpy(f->header.name, "agent", sizeof("agent"));
	f->header.signature_off =
		cpu_to_le32(offsetof(struct java_fixture, signature));
	f->header.signature_len = cpu_to_le32(sizeof(f->signature));
	f->header.data_off = cpu_to_le32(JAVA_DATA_OFF);
	f->header.data_len = cpu_to_le32(sizeof(*f) - JAVA_DATA_OFF);
	memcpy(f->jar, "PK\x03\x04jar", sizeof(f->jar));
	memcpy(f->name, "agent", sizeof("agent"));
	f->type = cpu_to_le32(signed_type);
	java_section(f, 0, UPATCH_SECTION_NAME,
		     offsetof(struct java_fixture, name), sizeof(f->name));
	java_section(f, 1, UPATCH_SECTION_JAR,
		     offsetof(struct java_fixture, jar), sizeof(f->jar));
	java_section(f, 2, UPATCH_SECTION_TYPE,
		     offsetof(struct java_fixture, type), sizeof(f->type));
	f->trailer.magic = cpu_to_le32(UPATCH_SIGNED_TRAILER_MAGIC);
	f->trailer.version = cpu_to_le32(UPATCH_SIGNED_VERSION);
	f->trailer.dir_off =
		cpu_to_le32(offsetof(struct java_fixture, dir) - JAVA_DATA_OFF);
	f->trailer.nr_sections = cpu_to_le32(3);
}

static void java_load_opens_with_its_jar(void)
{
	struct java_fixture f;
	struct upatch u;
	const void *jar;
	__u32 len;

	java_load(&f, UPATCH_TYPE_JAVA);
	ASSERT_EQ(upatch_open_memory(&f, sizeof(f), &u), 0);
	EXPECT_STREQ(upatch_type_str(&u), "java");
	EXPECT_UEQ(upatch_signed_type(&u), UPATCH_TYPE_JAVA);
	EXPECT_TRUE(upatch_name_signed(&u));
	jar = upatch_signed_jar(&u, &len);
	EXPECT_UEQ(len, sizeof(f.jar));
	EXPECT_TRUE(jar && !memcmp(jar, f.jar, sizeof(f.jar)));
	upatch_close(&u);
}

static void java_header_needs_the_signed_type(void)
{
	struct java_fixture f;
	struct upatch u;

	java_load(&f, UPATCH_TYPE_BPF);
	EXPECT_EQ(upatch_open_memory(&f, sizeof(f), &u), -EINVAL);
	java_load(&f, UPATCH_TYPE_JAVA);
	f.trailer.nr_sections = cpu_to_le32(2);
	EXPECT_EQ(upatch_open_memory(&f, sizeof(f), &u), -EINVAL);
	java_load(&f, UPATCH_TYPE_JAVA);
	f.header.type = cpu_to_le32(3);
	EXPECT_EQ(upatch_open_memory(&f, sizeof(f), &u), -EINVAL);
}

static void java_header_carries_no_loader(void)
{
	struct java_fixture f;
	struct upatch u;

	java_load(&f, UPATCH_TYPE_JAVA);
	f.header.loader_insns_off = f.header.signature_off;
	f.header.loader_insns_len = cpu_to_le32(8);
	EXPECT_EQ(upatch_open_memory(&f, sizeof(f), &u), -EINVAL);
	java_load(&f, UPATCH_TYPE_JAVA);
	f.header.nr_progs = cpu_to_le32(1);
	EXPECT_EQ(upatch_open_memory(&f, sizeof(f), &u), -EINVAL);
	java_load(&f, UPATCH_TYPE_JAVA);
	f.header.signature_len = 0;
	EXPECT_EQ(upatch_open_memory(&f, sizeof(f), &u), -EINVAL);
}

static const struct unit_case cases[] = {
	UNIT_CASE(prog_specs_take_the_signed_counts),
	UNIT_CASE(prog_specs_refuse_another_header_count),
	UNIT_CASE(kprobe_multi_names_are_parsed_in_order),
	UNIT_CASE(kprobe_multi_refuses_a_malformed_list),
	UNIT_CASE(kprobe_multi_block_is_exact),
	UNIT_CASE(kprobe_sym_is_one_plain_name),
	UNIT_CASE(header_name_is_terminated),
	UNIT_CASE(prog_name_is_what_the_kernel_takes),
	UNIT_CASE(name_signed_is_the_header_name),
	UNIT_CASE(member_is_a_name_and_a_payload),
	UNIT_CASE(name_fits_its_pin_directory),
	UNIT_CASE(xdp_classes_come_from_xdp_programs_alone),
	UNIT_CASE(xdp_masks_are_signed_and_bounded),
	UNIT_CASE(xdp_programs_select_disjoint_classes),
	UNIT_CASE(java_load_opens_with_its_jar),
	UNIT_CASE(java_header_needs_the_signed_type),
	UNIT_CASE(java_header_carries_no_loader),
	{}
};

UNIT_SUITE(upatch, cases);
