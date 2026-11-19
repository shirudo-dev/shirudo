// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

#include "java_agent.h"
#include "paths.h"
#include "unit.h"

static void agent_path_is_its_jar(void)
{
	char path[64];

	ASSERT_EQ(java_agent_path("rasp", path, sizeof(path)), 0);
	EXPECT_STREQ(path, JAVA_DIR "/rasp.jar");
	EXPECT_EQ(java_agent_path("rasp", path, 8), -ENAMETOOLONG);
}

static void options_name_each_agent_in_order(void)
{
	static const char *const names[] = { "a", "b.c" };
	char out[256];
	int len;

	len = java_tool_options(names, 2, out, sizeof(out));
	EXPECT_STREQ(out, "JAVA_TOOL_OPTIONS=\"${JAVA_TOOL_OPTIONS:+$JAVA_TOOL_OPTIONS }"
		     "-javaagent:" JAVA_DIR
		     "/a.jar -javaagent:" JAVA_DIR "/b.c.jar\"\n");
	EXPECT_EQ(len, (int)strlen(out));
	len = java_tool_options(names, 1, out, sizeof(out));
	EXPECT_STREQ(out, "JAVA_TOOL_OPTIONS=\"${JAVA_TOOL_OPTIONS:+$JAVA_TOOL_OPTIONS }"
		     "-javaagent:" JAVA_DIR
		     "/a.jar\"\n");
	EXPECT_EQ(len, (int)strlen(out));
}

/* A line cut short would hand every JVM a broken option. */
static void options_that_do_not_fit_are_refused(void)
{
	static const char *const names[] = { "a", "b" };
	char out[256];
	int full;

	full = java_tool_options(names, 2, out, sizeof(out));
	ASSERT_TRUE(full > 0);
	EXPECT_EQ(java_tool_options(names, 2, out, (size_t)full), -E2BIG);
	EXPECT_EQ(java_tool_options(names, 2, out, 4), -E2BIG);
}

static void agent_without_archive_is_not_loaded(void)
{
	EXPECT_FALSE(java_agent_loaded("shirudo-unit-no-such-upatch"));
}

static const struct unit_case cases[] = {
	UNIT_CASE(agent_path_is_its_jar),
	UNIT_CASE(options_name_each_agent_in_order),
	UNIT_CASE(options_that_do_not_fit_are_refused),
	UNIT_CASE(agent_without_archive_is_not_loaded),
	{}
};

UNIT_SUITE(java_agent, cases);
