// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "chain.h"
#include "crypto.h"
#include "unit.h"

static void sha256_2_hashes_the_concatenation(void)
{
	__u8 one[32], two[32];

	ASSERT_EQ(sha256_buffer("abc", 3, one), 0);
	ASSERT_EQ(sha256_2("ab", 2, "c", 1, two), 0);
	EXPECT_MEMEQ(two, one, sizeof(one));
	ASSERT_EQ(sha256_2("abc", 3, NULL, 0, two), 0);
	EXPECT_MEMEQ(two, one, sizeof(one));
}

/* A failure must be reported, not left to a zeroed digest to mismatch. */
static void sha256_2_reports_a_failure(void)
{
	__u8 out[32], zero[32] = {};

	memset(out, 0xff, sizeof(out));
	EXPECT_NE(sha256_2(NULL, 3, "c", 1, out), 0);
	EXPECT_MEMEQ(out, zero, sizeof(out));
}

static void chain_events_hash_their_documented_input(void)
{
	static const char tag[] = "shirudo-key-revoke";
	__u8 cert[32], buf[sizeof(tag) + 32], want[32], event[32];

	memset(cert, 0xa5, sizeof(cert));
	memcpy(buf, tag, sizeof(tag));
	memcpy(buf + sizeof(tag), cert, sizeof(cert));
	ASSERT_EQ(sha256_buffer(buf, sizeof(buf), want), 0);
	ASSERT_EQ(chain_key_event(tag, cert, event), 0);
	EXPECT_MEMEQ(event, want, sizeof(want));
}

/* Each payload type and direction has a tag of its own. */
static void upatch_tags_are_distinct(void)
{
	const char *const tags[] = {
		chain_upatch_tag(UPATCH_TYPE_BPF, true),
		chain_upatch_tag(UPATCH_TYPE_BPF, false),
		chain_upatch_tag(UPATCH_TYPE_JAVA, true),
		chain_upatch_tag(UPATCH_TYPE_JAVA, false),
	};

	EXPECT_STREQ(tags[0], "shirudo-upatch");
	EXPECT_STREQ(tags[1], "shirudo-unload");
	EXPECT_STREQ(tags[2], "shirudo-java");
	EXPECT_STREQ(tags[3], "shirudo-java-unload");
	EXPECT_FALSE(chain_upatch_tag(3, true));
}

/* The longest tag, with its NUL, the digest and a whole name. */
static void java_unload_event_hashes_its_documented_input(void)
{
	static const char tag[] = "shirudo-java-unload";
	__u8 payload[32], buf[sizeof(tag) + 32 + UPATCH_NAME_MAX];
	char name[UPATCH_NAME_MAX + 1];
	__u8 want[32], event[32];

	memset(payload, 0x3c, sizeof(payload));
	memset(name, 'n', UPATCH_NAME_MAX);
	name[UPATCH_NAME_MAX] = '\0';
	memcpy(buf, tag, sizeof(tag));
	memcpy(buf + sizeof(tag), payload, sizeof(payload));
	memcpy(buf + sizeof(tag) + 32, name, UPATCH_NAME_MAX);
	ASSERT_EQ(sha256_buffer(buf, sizeof(buf), want), 0);
	ASSERT_EQ(chain_upatch_event(tag, name, payload, event), 0);
	EXPECT_MEMEQ(event, want, sizeof(want));
}

static void chain_fold_extends_like_the_register(void)
{
	__u8 chain[32] = {}, event[32], cat[64] = {}, want[32];

	memset(event, 0x5a, sizeof(event));
	memcpy(cat + 32, event, sizeof(event));
	ASSERT_EQ(sha256_buffer(cat, sizeof(cat), want), 0);
	ASSERT_EQ(chain_fold(chain, event), 0);
	EXPECT_MEMEQ(chain, want, sizeof(want));
}

/* The anchor is appended to systemd's log in systemd's own record shape. */
static void chain_log_anchor_appends_a_systemd_record(void)
{
	static const char anchor[] = "nvpcr-init:shirudo:0x1818e00:000b01";
	char path[] = "/tmp/shirudo-unit-measure-XXXXXX", buf[2048] = {}, hex[65];
	const char *rec, *boot;
	struct stat st;
	__u8 digest[32];
	ssize_t n;
	int fd;

	fd = mkstemp(path);
	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(setenv("SYSTEMD_MEASURE_LOG_USERSPACE", path, 1), 0);
	ASSERT_EQ(sha256_buffer(anchor, strlen(anchor), digest), 0);
	hex_encode(digest, sizeof(digest), hex);
	ASSERT_EQ(chain_log_anchor(anchor, digest), 0);
	ASSERT_EQ(chain_log_anchor(anchor, digest), 0);
	n = read(fd, buf, sizeof(buf) - 1);
	ASSERT_TRUE(n > 0);
	EXPECT_EQ(buf[0], 0x1e);
	rec = strchr(buf + 1, 0x1e);
	ASSERT_TRUE(rec);
	EXPECT_EQ(rec[-1], '\n');
	EXPECT_TRUE(strstr(buf, "{\"pcr\":9,\"digests\":[{\"hashAlg\":"
			   "\"sha256\",\"digest\":\"") == buf + 1);
	EXPECT_TRUE(strstr(buf, hex));
	EXPECT_TRUE(strstr(buf, "\"content_type\":\"systemd\",\"content\":"
			   "{\"string\":\"nvpcr-init:shirudo:0x1818e00:"
			   "000b01\",\"bootId\":\""));
	EXPECT_TRUE(strstr(buf, "\"eventType\":\"nvpcr-init\"}}\n"));
	boot = strstr(buf, "\"bootId\":\"");
	ASSERT_TRUE(boot);
	EXPECT_EQ(strspn(boot + 10, "0123456789abcdef"), 32);
	ASSERT_EQ(fstat(fd, &st), 0);
	EXPECT_EQ(st.st_mode & 07777, 0600);

	/* A record cut short marks the log aborted: nothing more is appended. */
	ASSERT_EQ(fchmod(fd, 0600 | S_ISVTX), 0);
	EXPECT_EQ(chain_log_anchor(anchor, digest), -ESTALE);
	ASSERT_EQ(fstat(fd, &st), 0);
	EXPECT_EQ(st.st_size, n);
	/* Nothing that would need JSON escaping is written. */
	EXPECT_EQ(chain_log_anchor("nvpcr-init:\"x", digest), -EINVAL);
	close(fd);
	unlink(path);
	unsetenv("SYSTEMD_MEASURE_LOG_USERSPACE");
}

static const struct unit_case cases[] = {
	UNIT_CASE(sha256_2_hashes_the_concatenation),
	UNIT_CASE(sha256_2_reports_a_failure),
	UNIT_CASE(chain_events_hash_their_documented_input),
	UNIT_CASE(upatch_tags_are_distinct),
	UNIT_CASE(java_unload_event_hashes_its_documented_input),
	UNIT_CASE(chain_fold_extends_like_the_register),
	UNIT_CASE(chain_log_anchor_appends_a_systemd_record),
	{}
};

UNIT_SUITE(chain, cases);
