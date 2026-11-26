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

#include <shirudo/string.h>

#include "seal.h"
#include "unit.h"

/*
 * A directory that carries no label, as a state root does before the
 * first init: the helpers then check everything but the label.
 */
static char dir_path[PATH_MAX];
static int dir = -1;

static void new_dir(void)
{
	strscpy_literal(dir_path, "/tmp/shirudo-unit-seal-XXXXXX");
	ASSERT_TRUE(mkdtemp(dir_path));
	dir = open(dir_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_TRUE(dir >= 0);
}

static int remove_entry(const char *path, const struct stat *st, int type,
			struct FTW *ftw)
{
	return remove(path);
}

static void remove_dir(void)
{
	close(dir);
	ASSERT_EQ(nftw(dir_path, remove_entry, 16, FTW_DEPTH | FTW_PHYS), 0);
}

static off_t size_of(const char *name)
{
	struct stat st;

	ASSERT_EQ(fstatat(dir, name, &st, 0), 0);
	return st.st_size;
}

static void mkdir_child_makes_or_takes_one_directory(void)
{
	int fd;

	new_dir();
	fd = seal_mkdir_child(dir, "made", 0700, true);
	ASSERT_TRUE(fd >= 0);
	close(fd);
	EXPECT_EQ(seal_mkdir_child(dir, "made", 0700, true), -EEXIST);
	fd = seal_mkdir_child(dir, "made", 0700, false);
	EXPECT_TRUE(fd >= 0);
	close(fd);

	EXPECT_EQ(seal_mkdir_child(dir, "made/below", 0700, false), -EINVAL);
	EXPECT_EQ(seal_mkdir_child(dir, "..", 0700, false), -EINVAL);
	EXPECT_EQ(seal_mkdir_child(dir, "", 0700, false), -EINVAL);

	fd = openat(dir, "file", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
	ASSERT_TRUE(fd >= 0);
	close(fd);
	EXPECT_EQ(seal_mkdir_child(dir, "file", 0700, false), -ENOTDIR);
	ASSERT_EQ(symlinkat("made", dir, "link"), 0);
	EXPECT_EQ(seal_mkdir_child(dir, "link", 0700, false), -ELOOP);
	remove_dir();
}

static void create_child_makes_or_takes_one_regular_file(void)
{
	int fd;

	new_dir();
	EXPECT_EQ(seal_create_child(dir, "file", O_RDWR, 0600), -ENOENT);
	fd = seal_create_child(dir, "file", O_WRONLY | O_CREAT | O_EXCL, 0600);
	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(write(fd, "abc", 3), 3);
	close(fd);
	EXPECT_EQ(seal_create_child(dir, "file", O_WRONLY | O_CREAT | O_EXCL,
				    0600), -EEXIST);
	EXPECT_EQ(size_of("file"), 3);
	fd = seal_create_child(dir, "file", O_RDWR | O_CREAT, 0600);
	EXPECT_TRUE(fd >= 0);
	close(fd);
	EXPECT_EQ(size_of("file"), 3);
	fd = seal_create_child(dir, "file", O_RDWR | O_CREAT | O_TRUNC, 0600);
	EXPECT_TRUE(fd >= 0);
	close(fd);
	EXPECT_EQ(size_of("file"), 0);

	EXPECT_EQ(seal_create_child(dir, "a/b", O_RDWR | O_CREAT, 0600), -EINVAL);
	EXPECT_EQ(seal_create_child(dir, ".", O_RDONLY, 0600), -EINVAL);
	remove_dir();
}

/* What is under the name must be a regular file, and is not truncated first. */
static void create_child_takes_nothing_but_a_regular_file(void)
{
	int fd;

	new_dir();
	ASSERT_EQ(mkdirat(dir, "sub", 0700), 0);
	EXPECT_EQ(seal_create_child(dir, "sub", O_RDONLY, 0600), -EINVAL);
	EXPECT_EQ(seal_create_child(dir, "sub", O_RDWR | O_CREAT, 0600), -EISDIR);
	ASSERT_EQ(mkfifoat(dir, "fifo", 0600), 0);
	EXPECT_EQ(seal_create_child(dir, "fifo", O_RDONLY | O_CREAT | O_TRUNC,
				    0600), -EINVAL);

	fd = openat(dir, "target", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(write(fd, "abc", 3), 3);
	close(fd);
	ASSERT_EQ(symlinkat("target", dir, "link"), 0);
	EXPECT_EQ(seal_create_child(dir, "link", O_RDWR | O_CREAT | O_TRUNC,
				    0600), -ELOOP);
	EXPECT_EQ(size_of("target"), 3);
	ASSERT_EQ(symlinkat("missing", dir, "dangling"), 0);
	EXPECT_EQ(seal_create_child(dir, "dangling", O_RDWR | O_CREAT, 0600),
		  -ELOOP);
	EXPECT_EQ(faccessat(dir, "missing", F_OK, 0), -1);
	remove_dir();
}

static void a_child_on_another_mount_is_refused(void)
{
	char source[PATH_MAX], target[PATH_MAX];

	if (geteuid())
		unit_skip("needs root for a private bind mount");
	if (unshare(CLONE_NEWNS))
		unit_skip("cannot make a mount namespace");
	ASSERT_EQ(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL), 0);
	new_dir();
	ASSERT_EQ(mkdirat(dir, "source", 0700), 0);
	ASSERT_EQ(mkdirat(dir, "alias", 0700), 0);
	ASSERT_TRUE(strsprintf(source, sizeof(source), "%s/source", dir_path) > 0);
	ASSERT_TRUE(strsprintf(target, sizeof(target), "%s/alias", dir_path) > 0);
	ASSERT_EQ(mount(source, target, NULL, MS_BIND, NULL), 0);
	EXPECT_EQ(seal_mkdir_child(dir, "alias", 0700, false), -EXDEV);
	EXPECT_EQ(seal_mkdir_child(dir, "alias", 0700, true), -EEXIST);
	ASSERT_EQ(umount(target), 0);

	/* A file bound over a file is no more shirudo's than a directory. */
	close(seal_create_child(dir, "one", O_WRONLY | O_CREAT | O_EXCL, 0600));
	close(seal_create_child(dir, "two", O_WRONLY | O_CREAT | O_EXCL, 0600));
	ASSERT_TRUE(strsprintf(source, sizeof(source), "%s/one", dir_path) > 0);
	ASSERT_TRUE(strsprintf(target, sizeof(target), "%s/two", dir_path) > 0);
	ASSERT_EQ(mount(source, target, NULL, MS_BIND, NULL), 0);
	EXPECT_EQ(seal_create_child(dir, "two", O_RDWR | O_CREAT | O_TRUNC,
				    0600), -EXDEV);
	EXPECT_EQ(seal_open_child(dir, "two", O_RDONLY), -EXDEV);
	ASSERT_EQ(umount(target), 0);
	remove_dir();
}

static const struct unit_case cases[] = {
	UNIT_CASE(mkdir_child_makes_or_takes_one_directory),
	UNIT_CASE(create_child_makes_or_takes_one_regular_file),
	UNIT_CASE(create_child_takes_nothing_but_a_regular_file),
	UNIT_CASE(a_child_on_another_mount_is_refused),
	{}
};

UNIT_SUITE(seal, cases);
