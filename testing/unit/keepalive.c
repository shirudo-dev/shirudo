// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <shirudo/string.h>

#include "integrity.h"
#include "json.h"
#include "keepalive.h"
#include "tamper.h"
#include "unit.h"

#define APPLIED		1
#define PASSED_OVER	2
#define NOT_ATTACHED	3

#define FIXTURES	"fixtures/keepalive/"
#define FIXTURE_BODY_MAX	1200
#define ALL_OK		5461
#define STRING_MAX	255

#define VERSION_ID \
	"d6d918ad22ff597579e6678bef75adca84d30f9661e0b7bbdbf534eebc138c1f"
#define CONFIG_ROOT_A \
	"1d8465c5b17838303fee92b3905420d294d2c22c576a0bdef0f69f190ed22807"
#define CONFIG_ROOT_B \
	"ff2cbeff5d0e9c41a7b36f28d14ce09b73a5182e6fc40d97b5e2a1683c0f7ff8"
#define IMAGE_ROOT \
	"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"
#define ZEROS \
	"0000000000000000000000000000000000000000000000000000000000000000"
#define ONES \
	"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
#define ROOT_AFTER_1 \
	"04f83540c1727aefcf3c53449a99594c8fd1cc15e1466dbdbf3168cc8f9dc136"
#define ROOT_AFTER_3 \
	"154522480ff8884daa95589e80f26f20248bbf9c192dfbb3cee04e03b4f136a1"
#define SET_1_0_0 \
	"6c9e113d02cd14646f617d7bba4a092b91bc3802dfdaae50e2fef7a01e0580aa"
#define SET_1_1_0 \
	"74e5bd2c665109f6d8f926af5476c266ad70ab07293ff13b1a13d0b89aa5c1bf"
#define SET_EMPTY \
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

static const __u64 no_tamper[TAMPER_MAX];
static const __u64 no_integrity[INTEGRITY_MAX];

static void expect_mask(const __u8 *codes, size_t n, const char *want)
{
	char b64[KEEPALIVE_MASK_B64_MAX];

	ASSERT_EQ(keepalive_mask(codes, n, b64, sizeof(b64)), 0);
	EXPECT_STREQ(b64, want);
}

static void mask_of_one_operation(void)
{
	static const __u8 applied[] = { APPLIED };
	static const __u8 passed_over[] = { PASSED_OVER };

	expect_mask(applied, 1, "QA==");
	expect_mask(passed_over, 1, "gA==");
}

static void mask_of_the_release_example(void)
{
	static const __u8 node_a[] = { APPLIED, APPLIED, APPLIED };
	static const __u8 node_b[] = { PASSED_OVER, PASSED_OVER, PASSED_OVER };

	expect_mask(node_a, ARRAY_SIZE(node_a), "VA==");
	expect_mask(node_b, ARRAY_SIZE(node_b), "qA==");
}

static void mask_of_sixteen_operations(void)
{
	static const __u8 codes[] = {
		APPLIED, APPLIED, PASSED_OVER, APPLIED,
		NOT_ATTACHED, APPLIED, PASSED_OVER, APPLIED,
		APPLIED, APPLIED, PASSED_OVER, APPLIED,
		0, 0, 0, 0,
	};

	expect_mask(codes, ARRAY_SIZE(codes), "WdlZAA==");
}

static void mask_of_no_operation_is_empty(void)
{
	static const __u8 codes[] = { APPLIED };

	expect_mask(codes, 0, "");
}

static void mask_fills_a_byte_then_pads_the_next(void)
{
	static const __u8 codes[] = {
		APPLIED, APPLIED, APPLIED, APPLIED, APPLIED,
	};

	expect_mask(codes, 4, "VQ==");
	expect_mask(codes, 5, "VUA=");
}

static void mask_of_a_full_window(void)
{
	char want[KEEPALIVE_MASK_B64_MAX];
	__u8 codes[KEEPALIVE_MASK_OPS + 1];
	char b64[KEEPALIVE_MASK_B64_MAX];

	memset(codes, APPLIED, sizeof(codes));
	memset(want, 'V', sizeof(want) - 1);
	memcpy(want + sizeof(want) - 5, "VVU=", 5);

	EXPECT_EQ(sizeof(want), 173);
	expect_mask(codes, KEEPALIVE_MASK_OPS, want);
	EXPECT_EQ(keepalive_mask(codes, KEEPALIVE_MASK_OPS + 1, b64,
				 sizeof(b64)), -EINVAL);
}

static void mask_refuses_a_code_past_two_bits(void)
{
	static const __u8 codes[] = { APPLIED, 4 };
	char b64[KEEPALIVE_MASK_B64_MAX];

	EXPECT_EQ(keepalive_mask(codes, ARRAY_SIZE(codes), b64, sizeof(b64)),
		  -EINVAL);
}

static void mask_refuses_a_buffer_too_small(void)
{
	static const __u8 codes[] = {
		APPLIED, APPLIED, APPLIED, APPLIED, APPLIED,
	};
	char b64[5];

	EXPECT_EQ(keepalive_mask(codes, 0, b64, 0), -E2BIG);
	EXPECT_EQ(keepalive_mask(codes, 0, b64, 1), 0);
	EXPECT_STREQ(b64, "");
	EXPECT_EQ(keepalive_mask(codes, 1, b64, 4), -E2BIG);
	EXPECT_EQ(keepalive_mask(codes, 5, b64, 4), -E2BIG);
	EXPECT_EQ(keepalive_mask(codes, 5, b64, sizeof(b64)), 0);
	EXPECT_STREQ(b64, "VUA=");
}

static void cond_of_all_ok(void)
{
	static const struct condition conds[] = {
		{ .type = "LsmAttached", .status = "OK" },
		{ .type = "KeyringSealed", .status = "OK" },
		{ .type = "ChainIntact", .status = "OK" },
		{ .type = "UpatchesMeasured", .status = "OK" },
		{ .type = "TpmMeasured", .status = "OK" },
		{ .type = "ConfigActive", .status = "OK" },
		{ .type = "XdpCovered", .status = "OK" },
	};
	static const struct condition reordered[] = {
		{ .type = "XdpCovered", .status = "OK" },
		{ .type = "ChainIntact", .status = "OK" },
		{ .type = "ConfigActive", .status = "OK" },
		{ .type = "LsmAttached", .status = "OK" },
		{ .type = "TpmMeasured", .status = "OK" },
		{ .type = "KeyringSealed", .status = "OK" },
		{ .type = "UpatchesMeasured", .status = "OK" },
	};

	EXPECT_EQ(keepalive_cond(conds, ARRAY_SIZE(conds)), 5461);
	EXPECT_EQ(keepalive_cond(reordered, ARRAY_SIZE(reordered)), 5461);
}

static void cond_of_a_config_warning(void)
{
	static const struct condition conds[] = {
		{ .type = "LsmAttached", .status = "OK" },
		{ .type = "KeyringSealed", .status = "OK" },
		{ .type = "ChainIntact", .status = "OK" },
		{ .type = "UpatchesMeasured", .status = "OK" },
		{ .type = "TpmMeasured", .status = "OK" },
		{ .type = "ConfigActive", .status = "WARN" },
		{ .type = "XdpCovered", .status = "OK" },
	};
	static const struct condition reordered[] = {
		{ .type = "ConfigActive", .status = "WARN" },
		{ .type = "XdpCovered", .status = "OK" },
		{ .type = "TpmMeasured", .status = "OK" },
		{ .type = "UpatchesMeasured", .status = "OK" },
		{ .type = "ChainIntact", .status = "OK" },
		{ .type = "KeyringSealed", .status = "OK" },
		{ .type = "LsmAttached", .status = "OK" },
	};

	EXPECT_EQ(keepalive_cond(conds, ARRAY_SIZE(conds)), 6485);
	EXPECT_EQ(keepalive_cond(reordered, ARRAY_SIZE(reordered)), 6485);
}

static void cond_leaves_a_missing_condition_at_zero(void)
{
	static const struct condition conds[] = {
		{ .type = "LsmAttached", .status = "OK" },
		{ .type = "KeyringSealed", .status = "OK" },
		{ .type = "UpatchesMeasured", .status = "OK" },
		{ .type = "TpmMeasured", .status = "OK" },
		{ .type = "ConfigActive", .status = "OK" },
		{ .type = "XdpCovered", .status = "OK" },
	};

	EXPECT_EQ(keepalive_cond(conds, ARRAY_SIZE(conds)), 5461 & ~(3 << 4));
	EXPECT_EQ(keepalive_cond(conds, 0), 0);
}

static void cond_places_each_status_by_name(void)
{
	static const struct condition conds[] = {
		{ .type = "XdpCovered", .status = "ALERT" },
		{ .type = "Unknown", .status = "ALERT" },
		{ .type = "LsmAttached", .status = "ALERT" },
		{ .type = "KeyringSealed", .status = "WARN" },
	};

	EXPECT_EQ(keepalive_cond(conds, ARRAY_SIZE(conds)),
		  (3 << 12) | (2 << 2) | 3);
}

static void cond_follows_the_order_conditions_returns(void)
{
	struct conditions_input in = {
		.reachable = true,
		.parsed = true,
		.lsm_attached = 1,
	};
	struct condition conds[CONDITIONS_MAX];
	size_t n = conditions(&in, conds, CONDITIONS_MAX), i;
	__u16 cond = keepalive_cond(conds, n);

	ASSERT_EQ(n, CONDITIONS_MAX);
	for (i = 0; i < n; i++)
		EXPECT_NE((cond >> (2 * i)) & 3, 0);
	EXPECT_EQ(cond & 3, 1);
}

/* make -C testing runs from testing/, and by hand from the top of the tree. */
static size_t read_fixture(const char *name, char *body, size_t cap)
{
	char path[256];
	size_t len;
	FILE *f;

	ASSERT_TRUE(strsprintf(path, sizeof(path), FIXTURES "%s", name) > 0);
	f = fopen(path, "r");
	if (!f) {
		ASSERT_TRUE(strsprintf(path, sizeof(path),
				       "testing/" FIXTURES "%s", name) > 0);
		f = fopen(path, "r");
	}
	ASSERT_TRUE(f);
	len = fread(body, 1, cap, f);
	ASSERT_TRUE(feof(f));
	fclose(f);
	return len;
}

static void expect_fixture(const struct keepalive_input *in, const char *name)
{
	char want[KEEPALIVE_BODY_MAX], body[KEEPALIVE_BODY_MAX];
	size_t want_len = read_fixture(name, want, sizeof(want)), len;

	EXPECT_LT(want_len, FIXTURE_BODY_MAX + 1);
	ASSERT_EQ(keepalive_emit(in, body, sizeof(body), &len), 0);
	ASSERT_EQ(len, want_len);
	EXPECT_MEMEQ(body, want, len);
	EXPECT_EQ(body[len], '\0');
}

static void expect_body(const struct keepalive_input *in, const char *want)
{
	char body[KEEPALIVE_BODY_MAX];
	size_t len;

	ASSERT_EQ(keepalive_emit(in, body, sizeof(body), &len), 0);
	EXPECT_STREQ(body, want);
	EXPECT_EQ(len, strlen(want));
}

static void expect_member(const struct keepalive_input *in, const char *want)
{
	char body[KEEPALIVE_BODY_MAX];
	size_t len;

	ASSERT_EQ(keepalive_emit(in, body, sizeof(body), &len), 0);
	UNIT_CHECK(0, strstr(body, want), "no %s in %s", want, body);
}

static void expect_refused(const struct keepalive_input *in, int ret)
{
	char body[KEEPALIVE_BODY_MAX] = "left";
	size_t len = sizeof(body);

	EXPECT_EQ(keepalive_emit(in, body, sizeof(body), &len), ret);
	EXPECT_STREQ(body, "");
	EXPECT_EQ(len, 0);
}

static struct keepalive_input node_a(void)
{
	return (struct keepalive_input){
		.boot_id = "168d20a1-5011-4e1b-9924-d8b73c85aa4e",
		.version_id = VERSION_ID,
		.config_root = CONFIG_ROOT_A,
		.kernel_release = "7.4.2",
		.image_id = "fleet-os",
		.image_version = "2026.11.1",
		.image_root = IMAGE_ROOT,
		.verdict = "ok",
		.cond = ALL_OK,
		.tamper = no_tamper,
		.integrity = no_integrity,
		.tree = true,
		.tree_id = "fleet-base",
		.base_root = ZEROS,
	};
}

static struct keepalive_input node_b(void)
{
	struct keepalive_input in = node_a();

	in.boot_id = "9a6f14ea-0cc2-45e1-8e23-7b887120cf54";
	in.config_root = CONFIG_ROOT_B;
	in.image_root = "";
	in.projection_root = ZEROS;
	in.set_sha256 = SET_EMPTY;
	return in;
}

static void at_release(struct keepalive_input *in, __u64 generation,
		       __u8 outcome, char mask[KEEPALIVE_MASK_B64_MAX])
{
	__u8 codes[KEEPALIVE_MASK_OPS];

	memset(codes, outcome, sizeof(codes));
	ASSERT_EQ(keepalive_mask(codes, generation, mask,
				 KEEPALIVE_MASK_B64_MAX), 0);
	in->generation = generation;
	in->last_seq = generation;
	in->mask = mask;
}

static void body_of_node_a_after_release_1_0_0(void)
{
	struct keepalive_input in = node_a();
	char mask[KEEPALIVE_MASK_B64_MAX];

	at_release(&in, 1, APPLIED, mask);
	in.projection_root = ROOT_AFTER_1;
	in.set_sha256 = SET_1_0_0;
	in.count = 1;
	expect_fixture(&in, "node-a-1.0.0.json");
}

static void body_of_node_a_after_release_1_1_0(void)
{
	struct keepalive_input in = node_a();
	char mask[KEEPALIVE_MASK_B64_MAX];

	at_release(&in, 3, APPLIED, mask);
	in.projection_root = ROOT_AFTER_3;
	in.set_sha256 = SET_1_1_0;
	in.count = 1;
	expect_fixture(&in, "node-a-1.1.0.json");
}

static void body_of_node_b_after_release_1_0_0(void)
{
	struct keepalive_input in = node_b();
	char mask[KEEPALIVE_MASK_B64_MAX];

	at_release(&in, 1, PASSED_OVER, mask);
	expect_fixture(&in, "node-b-1.0.0.json");
}

static void body_of_node_b_after_release_1_1_0(void)
{
	struct keepalive_input in = node_b();
	char mask[KEEPALIVE_MASK_B64_MAX];

	at_release(&in, 3, PASSED_OVER, mask);
	expect_fixture(&in, "node-b-1.1.0.json");
}

static void body_of_sixteen_operations(void)
{
	struct keepalive_input in = node_a();

	in.boot_id = "d5140906-4eab-4983-a62c-29e49d449ea3";
	in.config_root =
		"1fbdff17ad8d50404772901df54d5aa2c698eddbb413e286fc654f80931c688a";
	in.kernel_release = "7.4.0-shirudo";
	in.generation = 42;
	in.last_seq = 12;
	in.projection_root =
		"f59301708fc8e150c5d2abb1009b4f13fc0dcc1304b708f77dc14b1541679e28";
	in.mask = "WdlZAA==";
	in.set_sha256 =
		"ac1af1d44b5c1fe3f616384db421138aa4d296595797b5864908a89276e17e6d";
	in.count = 7;
	expect_fixture(&in, "ops-16.json");
}

static struct keepalive_input all_null(void)
{
	return (struct keepalive_input){
		.boot_id = "b",
		.version_id = VERSION_ID,
		.kernel_release = "k",
		.verdict = "init-pending",
		.flags = 72,
		.set_sha256 = SET_EMPTY,
	};
}

static void body_with_every_nullable_key_null(void)
{
	struct keepalive_input in = all_null();

	expect_body(&in,
		    "{\"schema\":\"shirudo.keepalive/1\",\"boot_id\":\"b\","
		    "\"version_id\":\"" VERSION_ID "\",\"config_root\":null,"
		    "\"kernel_release\":\"k\",\"image_id\":null,"
		    "\"image_version\":null,\"image_root\":null,"
		    "\"verdict\":\"init-pending\",\"cond\":0,\"flags\":72,"
		    "\"tamper\":null,\"integrity\":null,\"tree_id\":null,"
		    "\"generation\":null,\"base_seq\":null,\"last_seq\":null,"
		    "\"base_root\":null,"
		    "\"projection_root\":null,\"mask\":null,"
		    "\"set_sha256\":\"" SET_EMPTY "\",\"count\":0,"
		    "\"not_ok\":0}");
}

static void body_without_a_tree_ignores_the_tree_values(void)
{
	char with_values[KEEPALIVE_BODY_MAX], without[KEEPALIVE_BODY_MAX];
	struct keepalive_input in = node_a();
	size_t len;

	in.projection_root = ROOT_AFTER_1;
	in.set_sha256 = SET_1_0_0;
	in.mask = "QA==";
	in.generation = 1;
	in.last_seq = 1;
	in.tree = false;
	ASSERT_EQ(keepalive_emit(&in, with_values, sizeof(with_values), &len),
		  0);
	in.tree_id = NULL;
	in.projection_root = "not a hash";
	in.base_root = NULL;
	in.mask = NULL;
	ASSERT_EQ(keepalive_emit(&in, without, sizeof(without), &len), 0);
	EXPECT_STREQ(with_values, without);
	expect_member(&in, ",0],\"tree_id\":null,"
		      "\"generation\":null,\"base_seq\":null,\"last_seq\":null,"
		      "\"base_root\":null,\"projection_root\":null,"
		      "\"mask\":null,\"set_sha256\":");
}

static struct keepalive_input node_a_at_1_0_0(void)
{
	struct keepalive_input in = node_a();

	in.generation = 1;
	in.last_seq = 1;
	in.projection_root = ROOT_AFTER_1;
	in.mask = "QA==";
	in.set_sha256 = SET_1_0_0;
	in.count = 1;
	return in;
}

static void body_gives_each_nullable_key_as_null(void)
{
	struct keepalive_input in = node_a_at_1_0_0();

	in.config_root = NULL;
	expect_member(&in, ",\"config_root\":null,\"kernel_release\":");
	in.config_root = "";
	expect_member(&in, ",\"config_root\":null,\"kernel_release\":");
	in.image_id = NULL;
	expect_member(&in, ",\"image_id\":null,\"image_version\":\"");
	in.image_id = "";
	expect_member(&in, ",\"image_id\":null,\"image_version\":\"");
	in.image_version = NULL;
	expect_member(&in, ",\"image_version\":null,\"image_root\":\"");
	in.image_version = "";
	expect_member(&in, ",\"image_version\":null,\"image_root\":\"");
	in.image_root = NULL;
	expect_member(&in, ",\"image_root\":null,\"verdict\":");
	in.image_root = "";
	expect_member(&in, ",\"image_root\":null,\"verdict\":");
	in.tamper = NULL;
	expect_member(&in, ",\"tamper\":null,\"integrity\":[0,");
	in.integrity = NULL;
	expect_member(&in, ",\"integrity\":null,\"tree_id\":\"fleet-base\",");
	in.base_root = NULL;
	expect_member(&in, ",\"base_root\":null,\"projection_root\":\"");
	in.base_root = "";
	expect_member(&in, ",\"base_root\":null,\"projection_root\":\"");
	in.mask = NULL;
	expect_member(&in, ",\"mask\":null,\"set_sha256\":");
	expect_member(&in, ",\"tree_id\":\"fleet-base\",\"generation\":1,"
		      "\"base_seq\":0,\"last_seq\":1,\"base_root\":null,"
		      "\"projection_root\":\"" ROOT_AFTER_1 "\",\"mask\":null,");
}

static void body_tells_an_empty_mask_from_none(void)
{
	struct keepalive_input in = node_a_at_1_0_0();
	char mask[KEEPALIVE_MASK_B64_MAX];

	ASSERT_EQ(keepalive_mask(NULL, 0, mask, sizeof(mask)), 0);
	in.mask = mask;
	expect_member(&in, ",\"mask\":\"\",\"set_sha256\":");
}

struct key_walk {
	size_t	n;
	size_t	depth;
	bool	in_order;
};

static const char * const body_keys[] = {
	"schema", "boot_id", "version_id", "config_root", "kernel_release",
	"image_id", "image_version", "image_root", "verdict", "cond", "flags",
	"tamper", "integrity", "tree_id", "generation", "base_seq", "last_seq",
	"base_root", "projection_root", "mask", "set_sha256", "count", "not_ok",
};

static int walk_open(void *ctx, bool array)
{
	struct key_walk *walk = ctx;

	walk->depth++;
	return 0;
}

static int walk_close(void *ctx, bool array)
{
	struct key_walk *walk = ctx;

	walk->depth--;
	return 0;
}

static int walk_key(void *ctx, const char *key)
{
	struct key_walk *walk = ctx;

	if (walk->depth != 1 || walk->n >= ARRAY_SIZE(body_keys) ||
	    strcmp(key, body_keys[walk->n]))
		walk->in_order = false;
	walk->n++;
	return 0;
}

static void expect_the_keys_in_order(const struct keepalive_input *in)
{
	static const struct json_visitor visitor = {
		.open = walk_open,
		.close = walk_close,
		.key = walk_key,
	};
	struct key_walk walk = { .in_order = true };
	char body[KEEPALIVE_BODY_MAX];
	size_t len;

	ASSERT_EQ(keepalive_emit(in, body, sizeof(body), &len), 0);
	ASSERT_EQ(json_walk(body, len, &visitor, &walk), 0);
	EXPECT_EQ(walk.n, 23);
	EXPECT_EQ(walk.n, ARRAY_SIZE(body_keys));
	EXPECT_TRUE(walk.in_order);
}

static void body_has_every_key_in_order(void)
{
	struct keepalive_input with_tree = node_a_at_1_0_0();
	struct keepalive_input without = all_null();

	expect_the_keys_in_order(&with_tree);
	expect_the_keys_in_order(&without);
}

/*
 * The backend reads a counter by its place in the array: a counter is
 * appended to enum tamper_point and to this table, never put between two.
 */
static const char * const tamper_order[] = {
	"LoadNotLoader", "LoadUnsigned", "LoadUnverified", "LoadKeyringKind",
	"LoadKeyring", "MapCreate", "MapWrite", "MapFdWrite", "ProgRun",
	"ProgAttach", "ObjPin", "BpfCommand", "ExeIdentity", "KeyringWrite",
	"PinUnlink", "PinRename", "PinXattr", "BpffsUmount",
	"BpffsUmountAbove", "BpffsMount", "SealWrite", "SealUnlink",
	"SealRename", "SealSetattr", "SealXattr", "SealLabel", "SealPtrace",
	"SealPerf", "ExecTraced", "SealEntry", "PerfAttach", "PinEntry",
	"SealCopyUp", "Kexec", "TpmExtend", "ObjGet", "SealSignal",
	"SealCoreDump", "SealUprobe", "ExecShared", "XattrHandle", "SealRlimit",
	"TpmWrite",
};

/* The same for enum integrity_point. */
static const char * const integrity_order[] = {
	"ModuleSignature", "DevMem", "EfiTest", "KexecSignature", "PciAccess",
	"IoPort", "Msr", "AcpiTables", "DeviceTree", "PcmciaCis",
	"Tiocsserial", "ModuleParameters", "Mmiotrace", "Debugfs", "XmonWrite",
	"BpfWriteUser", "DbgWriteKernel", "RtasErrorInjection",
	"XenUserActions", "Kcore", "HibernateLocation", "Other",
};

static void tamper_counters_keep_their_places(void)
{
	size_t i;

	ASSERT_EQ(ARRAY_SIZE(tamper_order), 43);
	ASSERT_EQ(TAMPER_MAX, ARRAY_SIZE(tamper_order));
	EXPECT_EQ(TAMPER_LOAD_NOT_LOADER, 0);
	EXPECT_EQ(SHIRUDO_TAMPER_TPM_WRITE, TAMPER_MAX - 1);
	for (i = 0; i < ARRAY_SIZE(tamper_order); i++)
		EXPECT_STREQ(tamper_name(i), tamper_order[i]);
}

static void integrity_counters_keep_their_places(void)
{
	size_t i;

	ASSERT_EQ(ARRAY_SIZE(integrity_order), 22);
	ASSERT_EQ(INTEGRITY_MAX, ARRAY_SIZE(integrity_order));
	EXPECT_EQ(INTEGRITY_MODULE_SIGNATURE, 0);
	EXPECT_EQ(INTEGRITY_OTHER, INTEGRITY_MAX - 1);
	for (i = 0; i < ARRAY_SIZE(integrity_order); i++) {
		EXPECT_STREQ(integrity_name(i), integrity_order[i]);
		EXPECT_TRUE(strcmp(integrity_meaning(i), "?"));
	}
	EXPECT_STREQ(integrity_name(INTEGRITY_MAX), "?");
}

static void body_lists_the_counters_in_enum_order(void)
{
	struct keepalive_input in = node_a_at_1_0_0();
	__u64 integrity[INTEGRITY_MAX];
	__u64 tamper[TAMPER_MAX];
	size_t i;

	for (i = 0; i < TAMPER_MAX; i++)
		tamper[i] = i + 1;
	tamper[TAMPER_SEAL_SIGNAL] = ~0ULL;
	for (i = 0; i < INTEGRITY_MAX; i++)
		integrity[i] = 100 + i;
	integrity[INTEGRITY_KCORE] = ~0ULL;
	in.tamper = tamper;
	in.integrity = integrity;
	expect_member(&in, ",\"tamper\":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,"
		      "16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,"
		      "34,35,36,18446744073709551615,38,39,40,41,42,43],"
		      "\"integrity\":[100,101,102,103,104,105,106,107,108,109,"
		      "110,111,112,113,114,115,116,117,118,"
		      "18446744073709551615,120,121],\"tree_id\":");
}

static void body_refuses_a_missing_string(void)
{
	struct keepalive_input in = node_a_at_1_0_0();

	in.boot_id = NULL;
	expect_refused(&in, -EINVAL);
	in = node_a_at_1_0_0();
	in.kernel_release = NULL;
	expect_refused(&in, -EINVAL);
	in = node_a_at_1_0_0();
	in.verdict = NULL;
	expect_refused(&in, -EINVAL);
	in = node_a_at_1_0_0();
	in.tree_id = NULL;
	expect_refused(&in, -EINVAL);
}

static void body_refuses_what_is_no_hash(void)
{
	struct keepalive_input in = node_a_at_1_0_0();

	in.version_id = NULL;
	expect_refused(&in, -EINVAL);
	in.version_id = "";
	expect_refused(&in, -EINVAL);
	in.version_id = "sha256:" VERSION_ID;
	expect_refused(&in, -EINVAL);
	in.version_id = VERSION_ID "0";
	expect_refused(&in, -EINVAL);
	in.version_id =
		"D6D918AD22FF597579E6678BEF75ADCA84D30F9661E0B7BBDBF534EEBC138C1F";
	expect_refused(&in, -EINVAL);
	in = node_a_at_1_0_0();
	in.config_root = "1d8465c5";
	expect_refused(&in, -EINVAL);
	in = node_a_at_1_0_0();
	in.image_root = "g" VERSION_ID;
	expect_refused(&in, -EINVAL);
	in = node_a_at_1_0_0();
	in.base_root = "0";
	expect_refused(&in, -EINVAL);
	in = node_a_at_1_0_0();
	in.projection_root = "";
	expect_refused(&in, -EINVAL);
	in.projection_root = NULL;
	expect_refused(&in, -EINVAL);
	in = node_a_at_1_0_0();
	in.set_sha256 = NULL;
	expect_refused(&in, -EINVAL);
}

static void body_refuses_a_string_that_is_not_utf8(void)
{
	struct keepalive_input in = node_a_at_1_0_0();

	in.kernel_release = "7.4.2\xff";
	expect_refused(&in, -EILSEQ);
}

static void body_refuses_a_buffer_one_byte_short(void)
{
	struct keepalive_input in = node_a_at_1_0_0();
	char body[KEEPALIVE_BODY_MAX] = "left";
	size_t len, whole;

	ASSERT_EQ(keepalive_emit(&in, body, sizeof(body), &whole), 0);
	EXPECT_EQ(keepalive_emit(&in, body, whole, &len), -ENOSPC);
	EXPECT_STREQ(body, "");
	EXPECT_EQ(len, 0);
	EXPECT_EQ(keepalive_emit(&in, body, 1, &len), -ENOSPC);
	EXPECT_EQ(keepalive_emit(&in, NULL, 0, &len), -ENOSPC);
	ASSERT_EQ(keepalive_emit(&in, body, whole + 1, &len), 0);
	EXPECT_EQ(len, whole);
	EXPECT_EQ(strlen(body), whole);
}

static void body_of_the_largest_values_fits(void)
{
	char text[STRING_MAX + 1], mask[KEEPALIVE_MASK_B64_MAX];
	char body[KEEPALIVE_BODY_MAX];
	__u8 codes[KEEPALIVE_MASK_OPS];
	struct keepalive_input in = {
		.boot_id = text,
		.version_id = ONES,
		.config_root = ONES,
		.kernel_release = text,
		.image_id = text,
		.image_version = text,
		.image_root = ONES,
		.verdict = text,
		.cond = ~0,
		.flags = ~0U,
		.tree = true,
		.tree_id = text,
		.generation = ~0ULL,
		.base_seq = ~0ULL,
		.last_seq = ~0ULL,
		.base_root = ONES,
		.projection_root = ONES,
		.mask = mask,
		.set_sha256 = ONES,
		.count = ~0ULL,
		.not_ok = ~0ULL,
	};
	__u64 integrity[INTEGRITY_MAX];
	__u64 tamper[TAMPER_MAX];
	size_t whole, len, i;

	memset(text, 'x', STRING_MAX);
	text[STRING_MAX] = '\0';
	memset(codes, NOT_ATTACHED, sizeof(codes));
	ASSERT_EQ(keepalive_mask(codes, KEEPALIVE_MASK_OPS, mask,
				 sizeof(mask)), 0);
	for (i = 0; i < TAMPER_MAX; i++)
		tamper[i] = ~0ULL;
	for (i = 0; i < INTEGRITY_MAX; i++)
		integrity[i] = ~0ULL;
	in.tamper = tamper;
	in.integrity = integrity;

	ASSERT_EQ(keepalive_emit(&in, body, sizeof(body), &whole), 0);
	EXPECT_EQ(whole, 3900);
	EXPECT_LT(whole, KEEPALIVE_BODY_MAX);
	EXPECT_EQ(keepalive_emit(&in, body, whole, &len), -ENOSPC);
	EXPECT_EQ(keepalive_emit(&in, body, whole + 1, &len), 0);
}

/*
 * A node read by a snapshot. Each state read gives the next of seqs as
 * last_seq and the last one past the end, or with no seqs a last_seq
 * that moves on every read; each pending() call gives the next of
 * pending, false past the end.
 */
struct fake_node {
	const __s64	*seqs;
	int		n_seqs;
	const bool	*pending;
	int		n_pending;
	int		state_rc;
	int		collect_ret;
	int		reads;
	int		pending_calls;
	int		collects;
};

#define SEQS(...)	.seqs = (const __s64[]){ __VA_ARGS__ },		\
			.n_seqs = ARRAY_SIZE(((const __s64[]){ __VA_ARGS__ }))
#define PENDING(...)	.pending = (const bool[]){ __VA_ARGS__ },	\
			.n_pending = ARRAY_SIZE(((const bool[]){ __VA_ARGS__ }))

#define MOVING_FROM	100

static int fake_read_state(void *ctx, struct tree_state *state)
{
	struct fake_node *node = ctx;
	int read = node->reads++;

	*state = (struct tree_state){ .schema = 1, .generation = 1,
				      .head_seq = KEEPALIVE_MASK_OPS };
	strscpy(state->tree_id, "fleet-base", sizeof(state->tree_id));
	if (!node->n_seqs)
		state->last_seq = MOVING_FROM + read;
	else
		state->last_seq = node->seqs[min(read, node->n_seqs - 1)];
	return node->state_rc;
}

static bool fake_pending(void *ctx)
{
	struct fake_node *node = ctx;
	int call = node->pending_calls++;

	return call < node->n_pending && node->pending[call];
}

static int fake_collect(void *ctx, const struct tree_state *state,
			int state_rc)
{
	struct fake_node *node = ctx;

	node->collects++;
	return node->collect_ret;
}

static const struct keepalive_snapshot_ops fake_ops = {
	.read_state	= fake_read_state,
	.pending	= fake_pending,
	.collect	= fake_collect,
};

static __u32 snapshot_of(struct fake_node *node, struct tree_state *state)
{
	__u32 flags = 0;
	int state_rc;

	ASSERT_EQ(keepalive_snapshot(&fake_ops, node, state, &state_rc,
				     &flags), 0);
	EXPECT_EQ(state_rc, node->state_rc);
	return flags;
}

static void snapshot_of_a_still_tree_reads_it_twice(void)
{
	struct fake_node node = { SEQS(7) };
	struct tree_state state;

	EXPECT_UEQ(snapshot_of(&node, &state), 0);
	EXPECT_EQ(node.reads, 2);
	EXPECT_EQ(node.collects, 1);
	EXPECT_EQ(state.last_seq, 7);
}

static void snapshot_tries_again_after_a_state_that_moved(void)
{
	struct fake_node node = { SEQS(7, 8) };
	struct tree_state state;

	EXPECT_UEQ(snapshot_of(&node, &state), 0);
	EXPECT_EQ(node.reads, 4);
	EXPECT_EQ(node.collects, 2);
	EXPECT_EQ(state.last_seq, 8);
}

static void snapshot_gives_up_on_a_state_that_keeps_moving(void)
{
	struct fake_node node = {};
	struct tree_state state;

	EXPECT_UEQ(snapshot_of(&node, &state), KEEPALIVE_SNAPSHOT_UNSETTLED);
	EXPECT_EQ(node.reads, 2 * KEEPALIVE_SNAPSHOT_TRIES);
	EXPECT_EQ(node.collects, KEEPALIVE_SNAPSHOT_TRIES);
	/* The first read of the last try is what the body sends. */
	EXPECT_EQ(state.last_seq,
		  MOVING_FROM + 2 * (KEEPALIVE_SNAPSHOT_TRIES - 1));
}

static void snapshot_sees_a_pending_operation_before_it_reads(void)
{
	struct fake_node node = { SEQS(7), PENDING(true, false) };
	struct tree_state state;

	EXPECT_UEQ(snapshot_of(&node, &state), KEEPALIVE_TREE_OP_PENDING);
}

static void snapshot_sees_a_pending_operation_after_it_reads(void)
{
	struct fake_node node = { SEQS(7), PENDING(false, true) };
	struct tree_state state;

	EXPECT_UEQ(snapshot_of(&node, &state), KEEPALIVE_TREE_OP_PENDING);
}

static void snapshot_tells_the_pending_operation_of_its_last_try(void)
{
	struct fake_node node = { SEQS(7, 8), PENDING(true, true) };
	struct tree_state state;

	EXPECT_UEQ(snapshot_of(&node, &state), 0);
	EXPECT_EQ(node.pending_calls, 4);
}

static void snapshot_of_no_tree_settles(void)
{
	struct fake_node node = { .state_rc = -ENOENT };
	struct tree_state state;

	EXPECT_UEQ(snapshot_of(&node, &state), 0);
	EXPECT_EQ(node.collects, 1);
}

static void snapshot_stops_at_a_failed_collect(void)
{
	struct fake_node node = { SEQS(7), .collect_ret = -ENOMEM };
	struct tree_state state;
	__u32 flags = 0;
	int state_rc;

	EXPECT_EQ(keepalive_snapshot(&fake_ops, &node, &state, &state_rc,
				     &flags), -ENOMEM);
	EXPECT_EQ(node.reads, 1);
	EXPECT_UEQ(flags, 0);
}

static const struct unit_case cases[] = {
	UNIT_CASE(mask_of_one_operation),
	UNIT_CASE(mask_of_the_release_example),
	UNIT_CASE(mask_of_sixteen_operations),
	UNIT_CASE(mask_of_no_operation_is_empty),
	UNIT_CASE(mask_fills_a_byte_then_pads_the_next),
	UNIT_CASE(mask_of_a_full_window),
	UNIT_CASE(mask_refuses_a_code_past_two_bits),
	UNIT_CASE(mask_refuses_a_buffer_too_small),
	UNIT_CASE(cond_of_all_ok),
	UNIT_CASE(cond_of_a_config_warning),
	UNIT_CASE(cond_leaves_a_missing_condition_at_zero),
	UNIT_CASE(cond_places_each_status_by_name),
	UNIT_CASE(cond_follows_the_order_conditions_returns),
	UNIT_CASE(body_of_node_a_after_release_1_0_0),
	UNIT_CASE(body_of_node_a_after_release_1_1_0),
	UNIT_CASE(body_of_node_b_after_release_1_0_0),
	UNIT_CASE(body_of_node_b_after_release_1_1_0),
	UNIT_CASE(body_of_sixteen_operations),
	UNIT_CASE(body_with_every_nullable_key_null),
	UNIT_CASE(body_without_a_tree_ignores_the_tree_values),
	UNIT_CASE(body_gives_each_nullable_key_as_null),
	UNIT_CASE(body_tells_an_empty_mask_from_none),
	UNIT_CASE(body_has_every_key_in_order),
	UNIT_CASE(tamper_counters_keep_their_places),
	UNIT_CASE(integrity_counters_keep_their_places),
	UNIT_CASE(body_lists_the_counters_in_enum_order),
	UNIT_CASE(body_refuses_a_missing_string),
	UNIT_CASE(body_refuses_what_is_no_hash),
	UNIT_CASE(body_refuses_a_string_that_is_not_utf8),
	UNIT_CASE(body_refuses_a_buffer_one_byte_short),
	UNIT_CASE(body_of_the_largest_values_fits),
	UNIT_CASE(snapshot_of_a_still_tree_reads_it_twice),
	UNIT_CASE(snapshot_tries_again_after_a_state_that_moved),
	UNIT_CASE(snapshot_gives_up_on_a_state_that_keeps_moving),
	UNIT_CASE(snapshot_sees_a_pending_operation_before_it_reads),
	UNIT_CASE(snapshot_sees_a_pending_operation_after_it_reads),
	UNIT_CASE(snapshot_tells_the_pending_operation_of_its_last_try),
	UNIT_CASE(snapshot_of_no_tree_settles),
	UNIT_CASE(snapshot_stops_at_a_failed_collect),
	{}
};

UNIT_SUITE(keepalive, cases);
