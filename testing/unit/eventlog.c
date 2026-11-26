// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <shirudo/string.h>
#include <shirudo/upatch.h>

#include "eventlog.h"
#include "io.h"
#include "json.h"
#include "measured.h"
#include "unit.h"

static char dir[4096], log_path[4200], pending_path[4200];

static void use_log(void)
{
	const char *tmp = getenv("TMPDIR");

	ASSERT_TRUE(strsprintf(dir, sizeof(dir),
			       "%s/shirudo-unit-eventlog-XXXXXX",
			       tmp && tmp[0] ? tmp : "/tmp") > 0);
	ASSERT_TRUE(mkdtemp(dir));
	ASSERT_TRUE(strsprintf(log_path, sizeof(log_path), "%s/eventlog",
			       dir) > 0);
	ASSERT_TRUE(strsprintf(pending_path, sizeof(pending_path),
			       "%s/pending", dir) > 0);
	ASSERT_EQ(setenv("SHIRUDO_EVENTLOG_PATH", log_path, 1), 0);
	ASSERT_EQ(setenv("SHIRUDO_EVENTLOG_PENDING_PATH", pending_path, 1), 0);
}

static void drop_log(void)
{
	unlink(log_path);
	unlink(pending_path);
	rmdir(dir);
}

static void record(char *buf, size_t cap, const char *type, __u8 fill)
{
	struct json_emit e = { .buf = buf, .cap = cap };
	__u8 digest[32];

	memset(digest, fill, sizeof(digest));
	eventlog_record_open(&e, type, digest);
	json_obj_close(&e);
	ASSERT_EQ(e.err, 0);
}

static void write_log(const char *text, size_t len)
{
	int fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(write_complete(fd, text, len), 0);
	ASSERT_EQ(close(fd), 0);
}

static void replay_of(const char *a, const char *b, __u8 out[32])
{
	char text[2048];
	int len;

	len = strsprintf(text, sizeof(text), "%s\n%s%s", a, b, b[0] ? "\n" : "");
	ASSERT_TRUE(len > 0);
	write_log(text, (size_t)len);
	ASSERT_EQ(eventlog_replay(out), 0);
}

/*
 * A record killed before its newline is no record yet: readers skip it,
 * and the next append drops it rather than run on from it.
 */
static void unfinished_append_is_no_record(void)
{
	char init[1024], load[1024], unload[1024], text[2048];
	__u8 alone[32], both[32], got[32];
	int len;

	use_log();
	record(init, sizeof(init), "init", 1);
	record(load, sizeof(load), "upatch_load", 2);
	record(unload, sizeof(unload), "upatch_unload", 3);
	replay_of(init, "", alone);
	replay_of(init, unload, both);

	len = strsprintf(text, sizeof(text), "%s\n%.*s", init,
			 (int)strlen(load) - 1, load);
	ASSERT_TRUE(len > 0);
	write_log(text, (size_t)len);
	ASSERT_EQ(eventlog_replay(got), 0);
	EXPECT_MEMEQ(got, alone, 32);

	len = strsprintf(text, sizeof(text), "%s\n%s", init, load);
	ASSERT_TRUE(len > 0);
	write_log(text, (size_t)len);
	ASSERT_EQ(eventlog_replay(got), 0);
	EXPECT_MEMEQ(got, alone, 32);
	ASSERT_EQ(eventlog_append_to(log_path, unload), 0);
	ASSERT_EQ(eventlog_replay(got), 0);
	EXPECT_MEMEQ(got, both, 32);
	drop_log();
}

/* A NUL would end the walk early and hide the records after it. */
static void nul_in_the_log_is_refused(void)
{
	char init[1024], unload[1024], text[2048];
	__u8 got[32];
	int len;

	use_log();
	record(init, sizeof(init), "init", 1);
	record(unload, sizeof(unload), "upatch_unload", 3);
	len = strsprintf(text, sizeof(text), "%s\n_%s\n", init, unload);
	ASSERT_TRUE(len > 0);
	text[strlen(init) + 1] = '\0';
	write_log(text, (size_t)len);
	EXPECT_EQ(eventlog_replay(got), -EINVAL);
	drop_log();
}

#define DIGEST_HEX "abababababababababababababababababababababababababababababababab"
#define OPERATION "sha256:" DIGEST_HEX

static void tree_record(char *buf, size_t cap, __s64 seq, const char *op)
{
	struct json_emit e = { .buf = buf, .cap = cap };
	__u8 digest[32];

	memset(digest, 7, sizeof(digest));
	eventlog_record_open(&e, "tree_op", digest);
	json_obj_open_key(&e, "tree");
	json_kv_int(&e, "seq", seq);
	json_kv_string(&e, "operation_digest", op);
	json_obj_close(&e);
	json_obj_close(&e);
	ASSERT_EQ(e.err, 0);
}

/*
 * Tree recovery asks whether an operation was measured this boot before
 * it applies the operation again, which would measure it twice.
 */
static void tree_op_measured_this_boot(void)
{
	char init[1024], tree[1024], text[2048];
	int len;

	use_log();
	record(init, sizeof(init), "init", 1);
	tree_record(tree, sizeof(tree), 3, OPERATION);
	EXPECT_EQ(eventlog_tree_op_measured(3, OPERATION), 0);
	len = strsprintf(text, sizeof(text), "%s\n%s\n", init, tree);
	ASSERT_TRUE(len > 0);
	write_log(text, (size_t)len);
	EXPECT_EQ(eventlog_tree_op_measured(3, OPERATION), 1);
	EXPECT_EQ(eventlog_tree_op_measured(4, OPERATION), 0);
	EXPECT_EQ(eventlog_tree_op_measured(3, OPERATION "0"), 0);
	len = strsprintf(text, sizeof(text), "%s\n", tree);
	ASSERT_TRUE(len > 0);
	write_log(text, (size_t)len);
	EXPECT_EQ(eventlog_tree_op_measured(3, OPERATION), 0);
	drop_log();
}

struct seen_upatches {
	int	inits;
	int	loads;
	char	last[64];
};

static int count_upatch(enum eventlog_upatch_event event, const char *name,
			const char *payload_hex, void *ctx)
{
	struct seen_upatches *s = ctx;

	if (event == EVENTLOG_UPATCH_INIT) {
		s->inits++;
		return 0;
	}
	s->loads += event == EVENTLOG_UPATCH_LOAD;
	ASSERT_TRUE(strscpy(s->last, name, sizeof(s->last)) > 0);
	return 0;
}

static void set_record(char *buf, size_t cap, const char *type,
		       const char *name)
{
	struct json_emit e = { .buf = buf, .cap = cap };
	__u8 digest[32];

	memset(digest, 2, sizeof(digest));
	eventlog_record_open(&e, type, digest);
	json_arr_open(&e, "set");
	json_obj_open(&e);
	json_kv_string(&e, "name", name);
	json_kv_string(&e, "payload_sha256", DIGEST_HEX);
	json_obj_close(&e);
	json_arr_close(&e);
	json_obj_close(&e);
	ASSERT_EQ(e.err, 0);
}

/* Only an init record's set says what boot restore loaded. */
static void set_counts_in_an_init_record_alone(void)
{
	char init[1024], other[1024], text[2048];
	struct seen_upatches s = {};
	int len;

	use_log();
	set_record(init, sizeof(init), "init", "fix");
	set_record(other, sizeof(other), "key_revoke", "ghost");
	len = strsprintf(text, sizeof(text), "%s\n%s\n", init, other);
	ASSERT_TRUE(len > 0);
	write_log(text, (size_t)len);
	ASSERT_EQ(eventlog_boot_upatches(count_upatch, &s), 0);
	EXPECT_EQ(s.inits, 1);
	EXPECT_EQ(s.loads, 1);
	EXPECT_STREQ(s.last, "fix");
	set_record(init, sizeof(init), "init", "../fix");
	len = strsprintf(text, sizeof(text), "%s\n", init);
	ASSERT_TRUE(len > 0);
	write_log(text, (size_t)len);
	EXPECT_EQ(eventlog_boot_upatches(count_upatch, &s), -EINVAL);
	drop_log();
}

static void upatch_record(char *buf, size_t cap, const char *type,
			  const char *name)
{
	struct json_emit e = { .buf = buf, .cap = cap };
	__u8 digest[32];

	memset(digest, 3, sizeof(digest));
	eventlog_record_open(&e, type, digest);
	json_obj_open_key(&e, "upatch");
	json_kv_string(&e, "name", name);
	json_kv_string(&e, "payload_sha256", DIGEST_HEX);
	json_obj_close(&e);
	json_obj_close(&e);
	ASSERT_EQ(e.err, 0);
}

static void upatch_records_name_type_and_direction(void)
{
	__u32 type = 0;
	bool load = false;

	EXPECT_STREQ(eventlog_upatch_record(UPATCH_TYPE_BPF, true),
		     "upatch_load");
	EXPECT_STREQ(eventlog_upatch_record(UPATCH_TYPE_JAVA, false),
		     "java_unload");
	EXPECT_FALSE(eventlog_upatch_record(3, true));
	EXPECT_TRUE(eventlog_upatch_record_parse("java_load", &type, &load));
	EXPECT_UEQ(type, UPATCH_TYPE_JAVA);
	EXPECT_TRUE(load);
	EXPECT_TRUE(eventlog_upatch_record_parse("upatch_unload", &type,
						 &load));
	EXPECT_UEQ(type, UPATCH_TYPE_BPF);
	EXPECT_FALSE(load);
	EXPECT_FALSE(eventlog_upatch_record_parse("java_loa", &type, &load));
	EXPECT_FALSE(eventlog_upatch_record_parse("upatch_load ", &type,
						  &load));
}

/* A Java load and unload count as upatch events like BPF ones. */
static void java_records_count_as_upatch_events(void)
{
	char init[1024], load[1024], unload[1024], text[4096];
	struct seen_upatches s = {};
	int len;

	use_log();
	set_record(init, sizeof(init), "init", "fix");
	upatch_record(load, sizeof(load), "java_load", "agent");
	upatch_record(unload, sizeof(unload), "java_unload", "agent");
	len = strsprintf(text, sizeof(text), "%s\n%s\n%s\n", init, load,
			 unload);
	ASSERT_TRUE(len > 0);
	write_log(text, (size_t)len);
	ASSERT_EQ(eventlog_boot_upatches(count_upatch, &s), 0);
	EXPECT_EQ(s.inits, 1);
	EXPECT_EQ(s.loads, 2);
	EXPECT_STREQ(s.last, "agent");
	drop_log();
}

#define PAYLOAD \
	"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

/* A set entry names its upatch itself, not through another member. */
static void set_entry_takes_only_its_own_fields(void)
{
	static const char init[] =
		"{\"type\":\"init\",\"upatch\":{\"name\":\"other\","
		"\"payload_sha256\":\"" PAYLOAD "\"},"
		"\"set\":[{\"payload_sha256\":\"" PAYLOAD "\"}]}";
	static const char named[] =
		"{\"type\":\"init\",\"set\":[{\"name\":\"fix\","
		"\"payload_sha256\":\"" PAYLOAD "\"}]}";
	struct seen_upatches s = {};

	EXPECT_EQ(eventlog_upatches_record(init, strlen(init), true,
					   count_upatch, &s), -EINVAL);
	EXPECT_EQ(s.loads, 0);
	EXPECT_EQ(eventlog_upatches_record(named, strlen(named), true,
					   count_upatch, &s), 0);
	EXPECT_EQ(s.loads, 1);
	EXPECT_STREQ(s.last, "fix");
}

#define MIXED_DIGEST_HEX "Abababababababababababababababababababababababababababababababab"

static void measured_set_uses_the_decoded_payload(void)
{
	static const char log[] =
		"{\"type\":\"init\"}\n"
		"{\"type\":\"upatch_load\",\"upatch\":{\"name\":\"fix\","
		"\"payload_sha256\":\"" MIXED_DIGEST_HEX "\"}}\n";
	struct measured_set *set;

	use_log();
	write_log(log, sizeof(log) - 1);
	ASSERT_EQ(measured_set_log(&set), 0);
	EXPECT_TRUE(measured_holds(set, "fix", DIGEST_HEX));
	measured_set_free(set);
	drop_log();
}

static const struct unit_case cases[] = {
	UNIT_CASE(measured_set_uses_the_decoded_payload),
	UNIT_CASE(unfinished_append_is_no_record),
	UNIT_CASE(nul_in_the_log_is_refused),
	UNIT_CASE(tree_op_measured_this_boot),
	UNIT_CASE(set_counts_in_an_init_record_alone),
	UNIT_CASE(upatch_records_name_type_and_direction),
	UNIT_CASE(java_records_count_as_upatch_events),
	UNIT_CASE(set_entry_takes_only_its_own_fields),
	{}
};

UNIT_SUITE(eventlog, cases);
