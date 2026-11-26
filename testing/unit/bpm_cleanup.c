// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <shirudo/string.h>

#include "bpm_cleanup.h"
#include "bpm_state.h"
#include "upatch.h"
#include "unit.h"

static int calls;
static char order[4];
static bool refuse;

int upatch_remove_fd(const char *path, int fd)
{
	char byte;

	if (calls >= (int)sizeof(order) - 1 || pread(fd, &byte, 1, 0) != 1)
		return 1;
	order[calls++] = byte;
	return refuse;
}

struct package {
	char dir[PATH_MAX];
	struct bpm_state_entry st;
	int fd;
};

static void new_package(struct package *p)
{
	strscpy_literal(p->dir, "/tmp/shirudo-bpm-cleanup-XXXXXX");
	ASSERT_TRUE(mkdtemp(p->dir));
	p->fd = open(p->dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_TRUE(p->fd >= 0);
	strscpy_literal(p->st.name, "sample");
	strscpy_literal(p->st.version, "1");
	ASSERT_TRUE(strsprintf(p->st.path, sizeof(p->st.path), "%s/sample/1", p->dir) > 0);
	ASSERT_EQ(mkdirat(p->fd, "sample", 0700), 0);
	ASSERT_EQ(mkdirat(p->fd, "sample/1", 0700), 0);
	ASSERT_EQ(mkdirat(p->fd, "sample/1/upatches", 0700), 0);
	refuse = false;
	calls = 0;
	memset(order, 0, sizeof(order));
}

static void put_file(int parent, const char *name, char byte)
{
	int fd = openat(parent, name, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);

	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(write(fd, &byte, 1), 1);
	ASSERT_EQ(close(fd), 0);
}

static void finish_package(struct package *p)
{
	close(p->fd);
	ASSERT_EQ(rmdir(p->dir), 0);
}

static void uninstall_retires_all_versions_after_detach(void)
{
	struct package p = {};

	new_package(&p);
	put_file(p.fd, "sample/1/upatches/a.unload.upatch", 'a');
	put_file(p.fd, "sample/1/upatches/z.unload.upatch", 'z');
	put_file(p.fd, "sample/sample-1.bee", 'x');
	ASSERT_EQ(mkdirat(p.fd, "sample/2", 0700), 0);
	put_file(p.fd, "sample/2/old", 'k');

	refuse = true;
	EXPECT_EQ(bpm_uninstall_at(p.fd, &p.st), -EIO);
	EXPECT_EQ(faccessat(p.fd, "sample/1/upatches/a.unload.upatch", F_OK, 0), 0);
	EXPECT_EQ(faccessat(p.fd, "sample/sample-1.bee", F_OK, 0), 0);
	refuse = false;
	calls = 0;
	ASSERT_EQ(bpm_uninstall_at(p.fd, &p.st), 0);
	EXPECT_STREQ(order, "za");
	EXPECT_EQ(faccessat(p.fd, "sample", F_OK, 0), -1);
	EXPECT_EQ(errno, ENOENT);
	EXPECT_EQ(bpm_uninstall_at(p.fd, &p.st), 0);
	EXPECT_EQ(calls, 2);
	finish_package(&p);
}

static void load_without_directive_stops_uninstall(void)
{
	struct package p = {};

	new_package(&p);
	put_file(p.fd, "sample/1/upatches/a.upatch", 'l');
	put_file(p.fd, "sample/1/upatches/a.unload.upatch", 'a');
	put_file(p.fd, "sample/1/upatches/b.upatch", 'l');
	EXPECT_EQ(bpm_uninstall_at(p.fd, &p.st), -ENODATA);
	EXPECT_EQ(calls, 0);
	EXPECT_EQ(faccessat(p.fd, "sample/1/upatches/a.upatch", F_OK, 0), 0);
	EXPECT_EQ(faccessat(p.fd, "sample/1/upatches/b.upatch", F_OK, 0), 0);
	put_file(p.fd, "sample/1/upatches/b.unload.upatch", 'b');
	ASSERT_EQ(bpm_uninstall_at(p.fd, &p.st), 0);
	EXPECT_STREQ(order, "ba");
	finish_package(&p);
}

static void retry_finishes_a_partly_removed_package(void)
{
	struct package p = {};

	new_package(&p);
	put_file(p.fd, "sample/1/upatches/notes", 'n');
	ASSERT_EQ(bpm_uninstall_at(p.fd, &p.st), 0);
	EXPECT_EQ(calls, 0);
	finish_package(&p);

	new_package(&p);
	ASSERT_EQ(unlinkat(p.fd, "sample/1/upatches", AT_REMOVEDIR), 0);
	ASSERT_EQ(bpm_uninstall_at(p.fd, &p.st), 0);
	finish_package(&p);
}

static void cleanup_requires_a_single_child_directory(void)
{
	struct package p = {};

	new_package(&p);
	EXPECT_EQ(bpm_pkg_remove_at(p.fd, "."), -EINVAL);
	EXPECT_EQ(bpm_pkg_remove_at(p.fd, "../1"), -EINVAL);
	EXPECT_EQ(bpm_pkg_remove_at(p.fd, "sample/1/upatches"), -EINVAL);
	ASSERT_EQ(symlinkat("sample", p.fd, "alias"), 0);
	EXPECT_LT(bpm_pkg_remove_at(p.fd, "alias"), 0);
	EXPECT_EQ(faccessat(p.fd, "sample/1/upatches", F_OK, 0), 0);
	ASSERT_EQ(unlinkat(p.fd, "alias", 0), 0);
	ASSERT_EQ(bpm_pkg_remove_at(p.fd, "sample"), 0);
	finish_package(&p);
}

static const struct unit_case cases[] = {
	UNIT_CASE(uninstall_retires_all_versions_after_detach),
	UNIT_CASE(load_without_directive_stops_uninstall),
	UNIT_CASE(retry_finishes_a_partly_removed_package),
	UNIT_CASE(cleanup_requires_a_single_child_directory),
	{}
};

UNIT_SUITE(bpm_cleanup, cases);
