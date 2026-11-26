// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "archive_test.h"
#include "bpm_install.h"
#include "upatch.h"
#include "unit.h"

/*
 * What the loader was asked for: +x a load of the member whose file
 * starts with x, -x an unload. A member that starts with refuse fails.
 */
static char order[32];
static char refuse;

static int record(char op, int fd)
{
	size_t n = strlen(order);
	char byte;

	if (n + 3 > sizeof(order) || pread(fd, &byte, 1, 0) != 1)
		return 1;
	order[n] = op;
	order[n + 1] = byte;
	return byte == refuse;
}

int upatch_install_fd(const char *path, int fd)
{
	return record('+', fd);
}

int upatch_remove_fd(const char *path, int fd)
{
	return record('-', fd);
}

/* A directory that stands for the state root. */
static char root_dir[PATH_MAX];
static int root = -1;

static void new_root(void)
{
	strscpy_literal(root_dir, "/tmp/shirudo-bpm-install-XXXXXX");
	ASSERT_TRUE(mkdtemp(root_dir));
	root = open(root_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_TRUE(root >= 0);
	memset(order, 0, sizeof(order));
	refuse = 0;
}

static int remove_entry(const char *path, const struct stat *st, int type,
			struct FTW *ftw)
{
	return remove(path);
}

static void remove_root(void)
{
	close(root);
	ASSERT_EQ(nftw(root_dir, remove_entry, 16, FTW_DEPTH | FTW_PHYS), 0);
}

static void make_dir(const char *path)
{
	char buf[PATH_MAX], *slash;

	ASSERT_TRUE(strscpy(buf, path, sizeof(buf)) > 0);
	for (slash = strchr(buf, '/'); slash; slash = strchr(slash + 1, '/')) {
		*slash = '\0';
		ASSERT_TRUE(!mkdirat(root, buf, 0700) || errno == EEXIST);
		*slash = '/';
	}
	ASSERT_TRUE(!mkdirat(root, buf, 0700) || errno == EEXIST);
}

static void put_file(const char *path, char byte)
{
	int fd = openat(root, path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);

	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(write(fd, &byte, 1), 1);
	ASSERT_EQ(close(fd), 0);
}

static bool there(const char *path)
{
	return !faccessat(root, path, F_OK, AT_SYMLINK_NOFOLLOW);
}

static const struct archive_member version_2[] = {
	{ "sample-2/", '5', NULL },
	{ "sample-2/cert.der", '0', "C" },
	{ "sample-2/upatches/b.upatch", '0', "b" },
	{ "sample-2/upatches/b.unload.upatch", '0', "B" },
	{ "sample-2/upatches/a.upatch", '0', "a" },
	{ "sample-2/upatches/a.unload.upatch", '0', "A" },
	{ "sample-2/doc/notes/readme", '0', "n" },
};

static void open_and_extract(struct bpm_install *in)
{
	ASSERT_EQ(bpm_install_open(in, root, "sample", "2"), 0);
	archive_write(in->archive, version_2, ARRAY_SIZE(version_2));
	ASSERT_EQ(bpm_install_extract(in), 0);
}

/* Version 1, which loaded p and q and ships the directives P and Q. */
static void old_version(void)
{
	make_dir("bpm/packages/sample/1/upatches");
	put_file("bpm/packages/sample/1/upatches/a.upatch", 'p');
	put_file("bpm/packages/sample/1/upatches/a.unload.upatch", 'P');
	put_file("bpm/packages/sample/1/upatches/c.upatch", 'q');
	put_file("bpm/packages/sample/1/upatches/c.unload.upatch", 'Q');
}

static void install_loads_in_name_order_and_keeps_the_archive(void)
{
	struct bpm_install in;
	struct stat st;
	char byte = 0;
	int fd;

	new_root();
	ASSERT_EQ(bpm_install_open(&in, root, "sample", "2"), 0);
	EXPECT_TRUE(there("bpm/staging/sample-2.bee"));
	archive_write(in.archive, version_2, ARRAY_SIZE(version_2));
	ASSERT_EQ(bpm_install_extract(&in), 0);
	ASSERT_EQ(fstatat(root, "bpm/packages/sample/2/doc/notes/readme", &st, 0), 0);
	EXPECT_EQ(st.st_mode & 07777, 0644);
	fd = bpm_install_member(&in, "cert.der");
	ASSERT_TRUE(fd >= 0);
	EXPECT_EQ(read(fd, &byte, 1), 1);
	EXPECT_EQ(byte, 'C');
	close(fd);
	EXPECT_EQ(bpm_install_member(&in, "upatches/a.upatch"), -EINVAL);
	ASSERT_EQ(bpm_install_load(&in, NULL), 0);
	EXPECT_STREQ(order, "+a+b");
	ASSERT_EQ(bpm_install_close(&in, 0), 0);
	EXPECT_TRUE(there("bpm/packages/sample/sample-2.bee"));
	EXPECT_FALSE(there("bpm/staging/sample-2.bee"));
	remove_root();
}

static void a_version_already_there_is_left_as_it_is(void)
{
	struct bpm_install in;

	new_root();
	make_dir("bpm/packages/sample/2");
	put_file("bpm/packages/sample/2/keep", 'k');
	ASSERT_EQ(bpm_install_open(&in, root, "sample", "2"), 0);
	archive_write(in.archive, version_2, ARRAY_SIZE(version_2));
	EXPECT_EQ(bpm_install_extract(&in), -EEXIST);
	EXPECT_EQ(bpm_install_close(&in, -EEXIST), -EEXIST);
	EXPECT_TRUE(there("bpm/packages/sample/2/keep"));
	EXPECT_FALSE(there("bpm/staging/sample-2.bee"));
	remove_root();
}

static void a_name_that_is_no_single_entry_is_refused(void)
{
	struct bpm_install in;

	new_root();
	EXPECT_EQ(bpm_install_open(&in, root, "..", "2"), -EINVAL);
	EXPECT_EQ(bpm_install_close(&in, -EINVAL), -EINVAL);
	EXPECT_EQ(bpm_install_open(&in, root, "sample", "../2"), -EINVAL);
	EXPECT_EQ(bpm_install_close(&in, -EINVAL), -EINVAL);
	EXPECT_FALSE(there("bpm"));
	remove_root();
}

static void a_refused_load_is_undone_and_the_version_removed(void)
{
	struct bpm_install in;

	new_root();
	open_and_extract(&in);
	refuse = 'b';
	EXPECT_EQ(bpm_install_load(&in, NULL), -EIO);
	EXPECT_STREQ(order, "+a+b-A");
	EXPECT_EQ(bpm_install_close(&in, -EIO), -EIO);
	EXPECT_FALSE(there("bpm/packages/sample/2"));
	EXPECT_FALSE(there("bpm/staging/sample-2.bee"));
	EXPECT_TRUE(there("bpm/packages/sample"));
	remove_root();
}

static void an_upgrade_unloads_the_old_version_first(void)
{
	struct bpm_install in;

	new_root();
	old_version();
	open_and_extract(&in);
	ASSERT_EQ(bpm_install_load(&in, "1"), 0);
	EXPECT_STREQ(order, "-Q-P+a+b");
	memset(order, 0, sizeof(order));
	/* A version that is not there has nothing to unload. */
	ASSERT_EQ(bpm_install_load(&in, "0"), 0);
	EXPECT_STREQ(order, "+a+b");
	ASSERT_EQ(bpm_install_close(&in, 0), 0);
	EXPECT_TRUE(there("bpm/packages/sample/1/upatches/a.upatch"));
	remove_root();
}

static void a_failed_upgrade_loads_the_old_version_again(void)
{
	struct bpm_install in;

	new_root();
	old_version();
	open_and_extract(&in);
	refuse = 'b';
	EXPECT_EQ(bpm_install_load(&in, "1"), -EIO);
	EXPECT_STREQ(order, "-Q-P+a+b-A+p+q");
	/* A directive that fails leaves the ones after it alone. */
	memset(order, 0, sizeof(order));
	refuse = 'P';
	EXPECT_EQ(bpm_install_load(&in, "1"), -EIO);
	EXPECT_STREQ(order, "-Q-P+q");
	EXPECT_EQ(bpm_install_close(&in, -EIO), -EIO);
	EXPECT_TRUE(there("bpm/packages/sample/1/upatches/c.unload.upatch"));
	EXPECT_FALSE(there("bpm/packages/sample/2"));
	remove_root();
}

static void nothing_is_reached_through_a_symbolic_link(void)
{
	struct bpm_install in;
	struct stat st;

	new_root();
	make_dir("elsewhere");
	make_dir("bpm");
	ASSERT_EQ(symlinkat("../elsewhere", root, "bpm/staging"), 0);
	EXPECT_EQ(bpm_install_open(&in, root, "sample", "2"), -ELOOP);
	EXPECT_EQ(bpm_install_close(&in, -ELOOP), -ELOOP);
	ASSERT_EQ(unlinkat(root, "bpm/staging", 0), 0);

	make_dir("bpm/staging");
	put_file("elsewhere/archive", 'x');
	ASSERT_EQ(symlinkat("../../elsewhere/archive", root,
			    "bpm/staging/sample-2.bee"), 0);
	EXPECT_EQ(bpm_install_open(&in, root, "sample", "2"), -ELOOP);
	EXPECT_EQ(bpm_install_close(&in, -ELOOP), -ELOOP);
	ASSERT_EQ(fstatat(root, "elsewhere/archive", &st, 0), 0);
	EXPECT_EQ(st.st_size, 1);
	EXPECT_TRUE(there("bpm/staging/sample-2.bee"));
	remove_root();
}

static void bind_over(const char *from, const char *onto, char *target,
		      size_t size)
{
	char source[PATH_MAX];

	ASSERT_TRUE(strsprintf(source, sizeof(source), "%s/%s", root_dir, from) > 0);
	ASSERT_TRUE(strsprintf(target, size, "%s/%s", root_dir, onto) > 0);
	ASSERT_EQ(mount(source, target, NULL, MS_BIND, NULL), 0);
}

static void a_mount_below_the_state_root_is_refused(void)
{
	struct bpm_install in;
	char target[PATH_MAX];

	if (geteuid())
		unit_skip("needs root for a private bind mount");
	if (unshare(CLONE_NEWNS))
		unit_skip("cannot make a mount namespace");
	ASSERT_EQ(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL), 0);
	new_root();
	make_dir("elsewhere/upatches");
	put_file("elsewhere/upatches/z.upatch", 'z');
	make_dir("bpm/staging");
	bind_over("elsewhere", "bpm/staging", target, sizeof(target));
	EXPECT_EQ(bpm_install_open(&in, root, "sample", "2"), -EXDEV);
	EXPECT_EQ(bpm_install_close(&in, -EXDEV), -EXDEV);
	ASSERT_EQ(umount(target), 0);
	EXPECT_FALSE(there("elsewhere/sample-2.bee"));

	/* Placed once the version is extracted, it is not read either. */
	open_and_extract(&in);
	bind_over("elsewhere/upatches", "bpm/packages/sample/2/upatches", target,
		  sizeof(target));
	EXPECT_EQ(bpm_install_load(&in, NULL), -EXDEV);
	EXPECT_STREQ(order, "");
	ASSERT_EQ(umount(target), 0);

	/* Nor is one over a single member. */
	bind_over("elsewhere/upatches/z.upatch",
		  "bpm/packages/sample/2/upatches/b.upatch", target,
		  sizeof(target));
	EXPECT_EQ(bpm_install_load(&in, NULL), -EXDEV);
	EXPECT_STREQ(order, "+a-A");
	ASSERT_EQ(umount(target), 0);
	EXPECT_EQ(bpm_install_close(&in, -EXDEV), -EXDEV);
	EXPECT_FALSE(there("bpm/packages/sample/2"));
	remove_root();
}

static const struct unit_case cases[] = {
	UNIT_CASE(install_loads_in_name_order_and_keeps_the_archive),
	UNIT_CASE(a_version_already_there_is_left_as_it_is),
	UNIT_CASE(a_name_that_is_no_single_entry_is_refused),
	UNIT_CASE(a_refused_load_is_undone_and_the_version_removed),
	UNIT_CASE(an_upgrade_unloads_the_old_version_first),
	UNIT_CASE(a_failed_upgrade_loads_the_old_version_again),
	UNIT_CASE(nothing_is_reached_through_a_symbolic_link),
	UNIT_CASE(a_mount_below_the_state_root_is_refused),
	{}
};

UNIT_SUITE(bpm_install, cases);
