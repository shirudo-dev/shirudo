// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <shirudo/string.h>

#include "attest.h"
#include "unit.h"

#define EVIDENCE "fuzz/corpus/attest/snapshot"

static void pcrs_are_a_list_up_to_23(void)
{
	__u32 mask;

	ASSERT_EQ(attest_parse_pcrs("0", &mask), 0);
	EXPECT_EQ(mask, 1U);
	ASSERT_EQ(attest_parse_pcrs("0,9,23", &mask), 0);
	EXPECT_EQ(mask, 1U | 1U << 9 | 1U << 23);
	ASSERT_EQ(attest_parse_pcrs("9,9", &mask), 0);
	EXPECT_EQ(mask, 1U << 9);
	EXPECT_EQ(attest_parse_pcrs("", &mask), -EINVAL);
	EXPECT_EQ(attest_parse_pcrs("24", &mask), -EINVAL);
	EXPECT_EQ(attest_parse_pcrs("1,,2", &mask), -EINVAL);
	EXPECT_EQ(attest_parse_pcrs(",1", &mask), -EINVAL);
	EXPECT_EQ(attest_parse_pcrs("1,", &mask), -EINVAL);
	EXPECT_EQ(attest_parse_pcrs("1,2,", &mask), -EINVAL);
	EXPECT_EQ(attest_parse_pcrs("1 ", &mask), -EINVAL);
	EXPECT_EQ(attest_parse_pcrs("+1", &mask), -EINVAL);
	EXPECT_EQ(attest_parse_pcrs("0x1", &mask), -EINVAL);
}

static void pcr_value_is_a_pcr_and_an_equals(void)
{
	const char *value;
	__u64 pcr;

	ASSERT_EQ(attest_parse_pcr_value("15=ab", &pcr, &value), 0);
	EXPECT_EQ(pcr, 15);
	EXPECT_STREQ(value, "ab");
	ASSERT_EQ(attest_parse_pcr_value("0=", &pcr, &value), 0);
	EXPECT_STREQ(value, "");
	EXPECT_EQ(attest_parse_pcr_value("24=ab", &pcr, &value), -EINVAL);
	EXPECT_EQ(attest_parse_pcr_value("=ab", &pcr, &value), -EINVAL);
	EXPECT_EQ(attest_parse_pcr_value("15", &pcr, &value), -EINVAL);
	EXPECT_EQ(attest_parse_pcr_value("1 5=ab", &pcr, &value), -EINVAL);
}

#define D64 "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

static void name_digest_is_a_name_and_64_digits(void)
{
	char name[UPATCH_NAME_MAX + 1], longest[UPATCH_NAME_MAX + 3 + 64];
	__u8 digest[32];

	ASSERT_EQ(attest_parse_name_digest("fix=" D64, name, digest), 0);
	EXPECT_STREQ(name, "fix");
	EXPECT_EQ(digest[1], 0x11);
	ASSERT_EQ(attest_parse_name_digest("a:b=" D64, name, digest), 0);
	EXPECT_STREQ(name, "a:b");
	EXPECT_EQ(attest_parse_name_digest("=" D64, name, digest), -EINVAL);
	EXPECT_EQ(attest_parse_name_digest("fix" D64, name, digest), -EINVAL);
	EXPECT_EQ(attest_parse_name_digest("fix=" D64 "0", name, digest),
		  -EINVAL);
	EXPECT_EQ(attest_parse_name_digest("fix==" D64, name, digest),
		  -EINVAL);
	memset(longest, 'n', UPATCH_NAME_MAX);
	ASSERT_TRUE(strscpy(longest + UPATCH_NAME_MAX, "=" D64,
			    sizeof(longest) - UPATCH_NAME_MAX) > 0);
	EXPECT_EQ(attest_parse_name_digest(longest, name, digest), 0);
	EXPECT_EQ(strlen(name), UPATCH_NAME_MAX);
	memset(longest, 'n', UPATCH_NAME_MAX + 1);
	ASSERT_TRUE(strscpy(longest + UPATCH_NAME_MAX + 1, "=" D64,
			    sizeof(longest) - UPATCH_NAME_MAX - 1) > 0);
	EXPECT_EQ(attest_parse_name_digest(longest, name, digest), -EINVAL);
}

/* make -C testing runs from testing/, and by hand from the top of the tree. */
static char *read_evidence(size_t *len)
{
	static char buf[1 << 16];
	FILE *f = fopen(EVIDENCE, "r");

	if (!f)
		f = fopen("testing/" EVIDENCE, "r");
	ASSERT_TRUE(f);
	*len = fread(buf, 1, sizeof(buf), f);
	fclose(f);
	return buf;
}

static void report_ends_its_last_line_at_any_size(void)
{
	static const __u8 nonce[16] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	};
	struct attest_expect expect = {
		.nonce = nonce,
		.nonce_len = sizeof(nonce),
	};
	static char report[ATTEST_REPORT_MAX];
	size_t len, full, cap, n;
	const char *doc;

	doc = read_evidence(&len);
	ASSERT_EQ(attest_verify(doc, len, &expect, report, sizeof(report)),
		  -EKEYREJECTED);
	full = strlen(report);
	ASSERT_TRUE(full && report[full - 1] == '\n');
	for (cap = 1; cap <= full; cap++) {
		EXPECT_EQ(attest_verify(doc, len, &expect, report, cap),
			  -EKEYREJECTED);
		n = strlen(report);
		EXPECT_TRUE(n < cap);
		EXPECT_TRUE(!n || report[n - 1] == '\n');
	}
}

/* A record without a digest has none: it takes no digest from the last. */
static void record_without_digest_is_refused(void)
{
	static const __u8 nonce[16] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	};
	struct attest_expect expect = {
		.nonce = nonce,
		.nonce_len = sizeof(nonce),
	};
	static const char key[] = "\"digest\":\"";
	static char doc[8192], report[ATTEST_REPORT_MAX];
	char *load, *digest = NULL, *at;
	const char *full;
	size_t len, cut;

	full = read_evidence(&len);
	ASSERT_TRUE(len < sizeof(doc));
	memcpy(doc, full, len);
	load = span_find(doc, len, "\"type\":\"upatch_load\"");
	ASSERT_TRUE(load);
	for (at = doc;
	     (at = span_find(at, len - (size_t)(at - doc), key)) && at < load;
	     at++)
		digest = at;
	ASSERT_TRUE(digest);
	cut = sizeof(key) - 1 + 64 + 2;
	memmove(digest, digest + cut, len - (size_t)(digest - doc) - cut);
	len -= cut;
	EXPECT_EQ(attest_verify(doc, len, &expect, report, sizeof(report)),
		  -EINVAL);
}

static const struct unit_case cases[] = {
	UNIT_CASE(pcrs_are_a_list_up_to_23),
	UNIT_CASE(pcr_value_is_a_pcr_and_an_equals),
	UNIT_CASE(name_digest_is_a_name_and_64_digits),
	UNIT_CASE(report_ends_its_last_line_at_any_size),
	UNIT_CASE(record_without_digest_is_refused),
	{}
};

UNIT_SUITE(attest, cases);
