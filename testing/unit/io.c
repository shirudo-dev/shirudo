// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <shirudo/string.h>

#include "../../util/paths.h"

/* The tree a case builds, and the part of it the check guards. */
static char etc_dir[4096], etc_prefix[4096];

#undef ETC_DIR
#define ETC_DIR etc_prefix

#include "../../util/io.c"

#include "unit.h"

static int log_with(const char *text, size_t len)
{
	const char *dir = getenv("TMPDIR");
	char path[4096];
	int fd;

	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/shirudo-unit-io-XXXXXX",
			       dir && dir[0] ? dir : "/tmp") > 0);
	fd = mkstemp(path);
	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(unlink(path), 0);
	ASSERT_EQ(fcntl(fd, F_SETFL, O_APPEND), 0);
	ASSERT_EQ(write_complete(fd, text, len), 0);
	return fd;
}

static void expect_log(int fd, const char *want)
{
	char buf[16384];
	ssize_t n = pread(fd, buf, sizeof(buf) - 1, 0);

	ASSERT_TRUE(n >= 0);
	buf[n] = '\0';
	EXPECT_STREQ(buf, want);
}

static void lines_len_ends_at_the_last_newline(void)
{
	EXPECT_EQ(lines_len("", 0), 0);
	EXPECT_EQ(lines_len("abc", 3), 0);
	EXPECT_EQ(lines_len("a\n", 2), 2);
	EXPECT_EQ(lines_len("a\nb", 3), 2);
	EXPECT_EQ(lines_len("a\nb\n", 4), 4);
	EXPECT_EQ(lines_len("\n\n", 2), 2);
}

static void append_line_adds_one_record(void)
{
	int fd = log_with("", 0);

	EXPECT_EQ(append_line(fd, "log", "x", 1), 0);
	EXPECT_EQ(append_line(fd, "log", "y\n", 2), 0);
	expect_log(fd, "x\ny\n");
	close(fd);
}

/*
 * A record killed before its newline would run into the next one on
 * its line, and every reader after would refuse the log.
 */
static void append_line_drops_what_did_not_finish(void)
{
	char text[12000];
	int fd;

	fd = log_with("x\n{\"half\":", 10);
	EXPECT_EQ(append_line(fd, "log", "z", 1), 0);
	expect_log(fd, "x\nz\n");
	close(fd);

	fd = log_with("{\"whole\":1}", 11);
	EXPECT_EQ(append_line(fd, "log", "z", 1), 0);
	expect_log(fd, "z\n");
	close(fd);

	memcpy(text, "x\n", 2);
	memset(text + 2, 'a', sizeof(text) - 2);
	fd = log_with(text, sizeof(text));
	EXPECT_EQ(append_line(fd, "log", "z", 1), 0);
	expect_log(fd, "x\nz\n");
	close(fd);
}

static void append_line_takes_one_line_alone(void)
{
	int fd = log_with("x\n", 2);

	EXPECT_EQ(append_line(fd, "log", "a\nb", 3), -EINVAL);
	EXPECT_EQ(append_line(fd, "log", "a\0b", 3), -EINVAL);
	expect_log(fd, "x\n");
	close(fd);
}

static void lock_exclusive_keeps_others_out(void)
{
	int fd = log_with("", 0), other;
	char path[64];

	ASSERT_TRUE(strsprintf(path, sizeof(path), "/proc/self/fd/%d", fd) > 0);
	other = open(path, O_RDONLY | O_CLOEXEC);
	ASSERT_TRUE(other >= 0);
	EXPECT_EQ(lock_exclusive(fd), 0);
	EXPECT_EQ(flock(other, LOCK_EX | LOCK_NB), -1);
	EXPECT_EQ(errno, EWOULDBLOCK);
	close(fd);
	EXPECT_EQ(lock_exclusive(other), 0);
	close(other);
}

static void kernel_dev_is_major_over_20_minor_bits(void)
{
	EXPECT_EQ(kernel_dev(makedev(8, 1)), 0x800001U);
	EXPECT_EQ(kernel_dev(makedev(253, 0x12345)), 253U << 20 | 0x12345U);
	EXPECT_EQ(kernel_dev(makedev(0xfff, 0xfffff)), 0xffffffffU);
}

static void bpffs_mounted_at_wants_the_root_of_a_bpffs(void)
{
	const char *dir = getenv("TMPDIR");

	EXPECT_EQ(bpffs_mounted_at(dir && dir[0] ? dir : "/tmp"), 0);
	EXPECT_EQ(bpffs_mounted_at("/"), 0);
	EXPECT_EQ(bpffs_mounted_at("/nonexistent/shirudo"), 0);
	EXPECT_EQ(bpffs_mounted_at("/dev/null"), -ENOTDIR);
}

static void open_beneath_same_mount_stops_at_proc(void)
{
	int root = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	int fd;

	ASSERT_TRUE(root >= 0);
	fd = open_beneath(root, "proc", O_RDONLY | O_DIRECTORY);
	ASSERT_TRUE(fd >= 0);
	close(fd);
	EXPECT_EQ(open_beneath_same_mount(root, "proc", O_RDONLY | O_DIRECTORY), -EXDEV);
	close(root);
}

static int etc_fd = -1;

static int remove_entry(const char *path, const struct stat *st, int type,
			struct FTW *ftw)
{
	return remove(path);
}

static void remove_etc(void)
{
	close(etc_fd);
	ASSERT_EQ(nftw(etc_dir, remove_entry, 16, FTW_DEPTH | FTW_PHYS), 0);
}

static void make_etc_in(const char *dir)
{
	ASSERT_TRUE(strsprintf(etc_dir, sizeof(etc_dir),
			       "%s/shirudo-unit-etc-XXXXXX", dir) > 0);
	ASSERT_TRUE(mkdtemp(etc_dir));
	ASSERT_TRUE(strscpy(etc_prefix, etc_dir, sizeof(etc_prefix)) > 0);
	etc_fd = open(etc_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_TRUE(etc_fd >= 0);
}

static void make_dir(const char *name, mode_t mode)
{
	ASSERT_EQ(mkdirat(etc_fd, name, 0700), 0);
	ASSERT_EQ(fchmodat(etc_fd, name, mode, 0), 0);
}

static void make_file(const char *name, mode_t mode)
{
	int fd = openat(etc_fd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
			0600);

	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(fchmod(fd, mode), 0);
	close(fd);
}

static void make_link(const char *target, const char *name)
{
	ASSERT_EQ(symlinkat(target, etc_fd, name), 0);
}

/*
 * check_trusted() of the file opened as one name and asked about as
 * another, and with secret check_secret() of a file that passed.
 */
static int trusted(const char *opened, const char *asked, bool secret)
{
	int fd = openat(etc_fd, opened, O_RDONLY | O_CLOEXEC), ret;
	char path[PATH_MAX];

	ASSERT_TRUE(fd >= 0);
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/%s", etc_dir, asked) > 0);
	ret = check_trusted(fd, path);
	if (!ret && secret)
		ret = check_secret(fd, path);
	close(fd);
	return ret;
}

/* The check walks up to /, so the tree goes where every directory passes it. */
static void make_etc(void)
{
	const char *dir = getenv("TMPDIR");

	make_etc_in(dir && dir[0] ? dir : "/tmp");
	make_file("probe", 0644);
	if (!trusted("probe", "probe", false))
		return;
	remove_etc();
	make_etc_in("/tmp");
}

/* As config managers write: the new file beside its name, renamed over it. */
static void replace_mode(const char *name, const char *text, mode_t mode)
{
	char tmp[PATH_MAX];
	int fd;

	ASSERT_TRUE(strsprintf(tmp, sizeof(tmp), "%s.tmp", name) > 0);
	fd = openat(etc_fd, tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		    0600);
	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(fchmod(fd, mode), 0);
	ASSERT_EQ(write_complete(fd, text, strlen(text)), 0);
	close(fd);
	ASSERT_EQ(renameat(etc_fd, tmp, etc_fd, name), 0);
}

/* The check guards only what lies below name, as a host's /etc/shirudo. */
static void trust_below(const char *name)
{
	ASSERT_TRUE(strsprintf(etc_prefix, sizeof(etc_prefix), "%s/%s",
			       etc_dir, name) > 0);
}

static void make_dir_once(const char *name, mode_t mode)
{
	if (mkdirat(etc_fd, name, 0700)) {
		ASSERT_EQ(errno, EEXIST);
		return;
	}
	ASSERT_EQ(fchmodat(etc_fd, name, mode, 0), 0);
}

/* Each directory of name that is missing yet, with mode. */
static void make_dirs(const char *name, mode_t mode)
{
	char path[PATH_MAX];
	size_t i;

	ASSERT_TRUE(strscpy(path, name, sizeof(path)) > 0);
	for (i = 1; path[i]; i++) {
		if (path[i] != '/')
			continue;
		path[i] = '\0';
		make_dir_once(path, mode);
		path[i] = '/';
	}
	make_dir_once(path, mode);
}

/* A link to a name of the tree, spelled from / as distributions write them. */
static void make_abs_link(const char *target, const char *name)
{
	char path[PATH_MAX];

	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/%s", etc_dir,
			       target) > 0);
	make_link(path, name);
}

static void give(const char *name, uid_t uid)
{
	ASSERT_EQ(fchownat(etc_fd, name, uid, uid, AT_SYMLINK_NOFOLLOW), 0);
}

static void replace(const char *name, const char *text)
{
	replace_mode(name, text, 0644);
}

static int open_in(const char *name)
{
	int fd = openat(etc_fd, name, O_RDONLY | O_CLOEXEC);

	ASSERT_TRUE(fd >= 0);
	return fd;
}

/* check_trusted() of what fd holds, asked about by a name of the tree. */
static int trusted_fd(int fd, const char *asked)
{
	char path[PATH_MAX];

	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/%s", etc_dir,
			       asked) > 0);
	return check_trusted(fd, path);
}

static void need_root(const char *reason)
{
	if (geteuid())
		unit_skip(reason);
}

#define NOBODY		65534
#define OTHER_USER	65533

static void check_trusted_takes_a_file_nobody_else_can_change(void)
{
	make_etc();
	make_dir("keys", 0755);
	make_file("keys/cert.der", 0644);
	EXPECT_EQ(trusted("keys/cert.der", "keys/cert.der", false), 0);
	EXPECT_EQ(trusted("keys/cert.der", "keys//./cert.der", false), 0);
	EXPECT_EQ(trusted("keys/cert.der", "keys/../keys/cert.der", false), 0);
	EXPECT_EQ(trusted("keys/cert.der", "keys/cert.der", true), -EPERM);
	ASSERT_EQ(fchmodat(etc_fd, "keys/cert.der", 0600, 0), 0);
	EXPECT_EQ(trusted("keys/cert.der", "keys/cert.der", true), 0);
	ASSERT_EQ(fchmodat(etc_fd, "keys/cert.der", 0664, 0), 0);
	EXPECT_EQ(trusted("keys/cert.der", "keys/cert.der", false), -EPERM);
	remove_etc();
}

static void check_trusted_refuses_a_directory_others_can_write(void)
{
	make_etc();
	make_dir("keys", 0775);
	make_file("keys/cert.der", 0644);
	EXPECT_EQ(trusted("keys/cert.der", "keys/cert.der", false), -EPERM);
	/* A sticky directory guards its entries only when it is root's. */
	ASSERT_EQ(fchmodat(etc_fd, "keys", 01777, 0), 0);
	EXPECT_EQ(trusted("keys/cert.der", "keys/cert.der", false),
		  geteuid() ? -EPERM : 0);
	remove_etc();
}

static void check_trusted_follows_a_link_nobody_else_made(void)
{
	char target[PATH_MAX];

	make_etc();
	make_dir("keys", 0700);
	make_file("keys/0a.der", 0644);
	ASSERT_TRUE(strsprintf(target, sizeof(target), "%s/keys/0a.der",
			       etc_dir) > 0);
	make_link(target, "keys/cert.der");
	EXPECT_EQ(trusted("keys/0a.der", "keys/cert.der", false), 0);
	make_link("../keys/0a.der", "keys/up.der");
	EXPECT_EQ(trusted("keys/0a.der", "keys/up.der", false), 0);
	make_link("keys", "current");
	EXPECT_EQ(trusted("keys/0a.der", "current/cert.der", false), 0);
	make_link("loop.der", "keys/loop.der");
	EXPECT_EQ(trusted("keys/0a.der", "keys/loop.der", false), -ELOOP);
	make_link("0a.der/more", "keys/past.der");
	EXPECT_EQ(trusted("keys/0a.der", "keys/past.der", false), -ENOTDIR);
	remove_etc();
}

static void check_trusted_refuses_a_link_others_can_replace(void)
{
	make_etc();
	make_dir("keys", 0700);
	make_file("keys/0a.der", 0644);
	make_dir("open", 0777);
	make_link("../keys/0a.der", "open/cert.der");
	EXPECT_EQ(trusted("keys/0a.der", "open/cert.der", false), -EPERM);
	make_file("open/0b.der", 0644);
	make_link("../open/0b.der", "keys/cert.der");
	EXPECT_EQ(trusted("open/0b.der", "keys/cert.der", false), -EPERM);
	/* In a sticky directory of root's a link is its owner's to replace. */
	if (!geteuid()) {
		ASSERT_EQ(fchmodat(etc_fd, "open", 01777, 0), 0);
		EXPECT_EQ(trusted("keys/0a.der", "open/cert.der", false), 0);
		ASSERT_EQ(fchownat(etc_fd, "open/cert.der", 65534, 65534,
				   AT_SYMLINK_NOFOLLOW), 0);
		EXPECT_EQ(trusted("keys/0a.der", "open/cert.der", false),
			  -EPERM);
	}
	remove_etc();
}

/* What a name swapped after the open leaves: one file open, another named. */
static void check_trusted_wants_the_file_the_path_names(void)
{
	make_etc();
	make_dir("keys", 0700);
	make_file("keys/cert.der", 0644);
	make_dir("open", 0777);
	make_file("open/cert.der", 0644);
	EXPECT_EQ(trusted("open/cert.der", "keys/cert.der", false), -ESTALE);
	EXPECT_EQ(trusted("keys/cert.der", "keys", false), -EISDIR);
	remove_etc();
}

/* A secret's readers are the file's own to say, where its name went or not. */
static void check_secret_asks_the_file_alone(void)
{
	char path[PATH_MAX];
	int fd;

	make_etc();
	make_dir("keys", 0700);
	replace_mode("keys/auth.conf", "a\n", 0600);
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/keys/auth.conf",
			       etc_dir) > 0);
	fd = openat(etc_fd, "keys/auth.conf", O_RDONLY | O_CLOEXEC);
	ASSERT_TRUE(fd >= 0);
	EXPECT_EQ(check_trusted(fd, path), 0);
	replace_mode("keys/auth.conf", "b\n", 0600);
	EXPECT_EQ(check_trusted(fd, path), -ESTALE);
	EXPECT_EQ(check_secret(fd, path), 0);
	ASSERT_EQ(fchmod(fd, 0640), 0);
	EXPECT_EQ(check_secret(fd, path), -EPERM);
	EXPECT_EQ(check_secret(fd, "/tmp/elsewhere.conf"), 0);
	close(fd);
	remove_etc();
}

/*
 * open_checked() with an open that renames a new file over the one it
 * opened, for its first race.renames opens: the race between the open
 * and the check, on cue.
 */
static struct race {
	const char *name;
	mode_t mode;
	int renames;
	int opens;
} race;

static int open_then_replace(const char *path, int flags)
{
	int fd = open_path(path, flags);

	if (fd >= 0 && race.opens++ < race.renames)
		replace_mode(race.name, "b\n", race.mode);
	return fd;
}

static int open_racing(const char *name, mode_t mode, int renames)
{
	char path[PATH_MAX];

	race = (struct race){ .name = name, .mode = mode, .renames = renames };
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/%s", etc_dir,
			       name) > 0);
	return open_checked(path, O_RDONLY, open_then_replace);
}

static void open_trusted_reopens_a_file_renamed_over(void)
{
	char text[4] = {};
	int fd;

	make_etc();
	make_dir("keys", 0755);
	replace_mode("keys/cert.der", "a\n", 0644);
	fd = open_racing("keys/cert.der", 0644, 1);
	ASSERT_TRUE(fd >= 0);
	EXPECT_EQ(race.opens, 2);
	EXPECT_EQ(pread(fd, text, sizeof(text) - 1, 0), 2);
	EXPECT_STREQ(text, "b\n");
	close(fd);
	fd = open_racing("keys/cert.der", 0644, TRUSTED_REOPENS);
	ASSERT_TRUE(fd >= 0);
	EXPECT_EQ(race.opens, TRUSTED_REOPENS + 1);
	close(fd);
	remove_etc();
}

static void open_trusted_gives_up_on_a_name_that_keeps_changing(void)
{
	make_etc();
	make_dir("keys", 0755);
	replace_mode("keys/cert.der", "a\n", 0644);
	EXPECT_EQ(open_racing("keys/cert.der", 0644,
			      TRUSTED_REOPENS + 1), -ESTALE);
	EXPECT_EQ(race.opens, TRUSTED_REOPENS + 1);
	remove_etc();
}

/* A reopen checks the new file in full, and only a rename is reopened. */
static void open_trusted_checks_each_file_it_opens(void)
{
	make_etc();
	make_dir("keys", 0755);
	replace_mode("keys/cert.der", "a\n", 0644);
	EXPECT_EQ(open_racing("keys/cert.der", 0664, 1), -EPERM);
	EXPECT_EQ(race.opens, 2);
	/* The file the rename left is group-writable. */
	EXPECT_EQ(open_racing("keys/cert.der", 0644, 0), -EPERM);
	EXPECT_EQ(race.opens, 1);
	remove_etc();
}

static void check_trusted_follows_link_chains_out_of_its_prefix(void)
{
	make_etc();
	make_dirs("etc/shirudo/bpm", 0755);
	make_dirs("srv", 0755);
	make_file("srv/shirudo.conf", 0644);
	trust_below("etc/shirudo");
	make_link("../../srv/shirudo.conf", "etc/shirudo/relative.conf");
	EXPECT_EQ(trusted("srv/shirudo.conf", "etc/shirudo/relative.conf",
			  false), 0);
	make_abs_link("srv/shirudo.conf", "etc/shirudo/absolute.conf");
	EXPECT_EQ(trusted("srv/shirudo.conf", "etc/shirudo/absolute.conf",
			  false), 0);
	make_link("relative.conf", "etc/shirudo/shirudo.conf");
	EXPECT_EQ(trusted("srv/shirudo.conf", "etc/shirudo/shirudo.conf",
			  false), 0);
	make_abs_link("etc/shirudo/shirudo.conf", "etc/shirudo/bpm/chain.conf");
	EXPECT_EQ(trusted("srv/shirudo.conf", "etc/shirudo/bpm/chain.conf",
			  false), 0);
	remove_etc();
}

/*
 * A CA certificate under /etc/shirudo linked to the distribution's: on
 * Debian each name in /etc/ssl/certs is an absolute link into
 * /usr/share/ca-certificates, on Fedora /etc/ssl/certs is a link to
 * ../pki/tls/certs, whose bundle is a link up into ca-trust.
 */
static void check_trusted_follows_a_distribution_s_ca_links(void)
{
	make_etc();
	make_dirs("etc/shirudo/bpm", 0755);
	make_dirs("etc/ssl/certs", 0755);
	make_dirs("usr/share/ca-certificates/mozilla", 0755);
	make_file("usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt", 0644);
	make_abs_link("usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt",
		      "etc/ssl/certs/ISRG_Root_X1.pem");
	make_abs_link("etc/ssl/certs/ISRG_Root_X1.pem", "etc/shirudo/bpm/ca.pem");
	trust_below("etc/shirudo");
	EXPECT_EQ(trusted("usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt",
			  "etc/shirudo/bpm/ca.pem", false), 0);
	remove_etc();

	make_etc();
	make_dirs("etc/shirudo/bpm", 0755);
	make_dirs("etc/pki/tls/certs", 0755);
	make_dirs("etc/pki/ca-trust/extracted/pem", 0755);
	make_file("etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", 0444);
	make_link("../../ca-trust/extracted/pem/tls-ca-bundle.pem",
		  "etc/pki/tls/certs/ca-bundle.crt");
	make_dirs("etc/ssl", 0755);
	make_link("../pki/tls/certs", "etc/ssl/certs");
	make_abs_link("etc/ssl/certs/ca-bundle.crt", "etc/shirudo/bpm/ca.pem");
	trust_below("etc/shirudo");
	EXPECT_EQ(trusted("etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
			  "etc/shirudo/bpm/ca.pem", false), 0);
	remove_etc();
}

/* /etc/shirudo kept elsewhere, a link in /etc to it. */
static void check_trusted_follows_its_prefix_linked_elsewhere(void)
{
	make_etc();
	make_dirs("etc", 0755);
	make_dirs("mnt/state/etc-shirudo", 0755);
	make_file("mnt/state/etc-shirudo/shirudo.conf", 0644);
	trust_below("etc/shirudo");
	make_abs_link("mnt/state/etc-shirudo", "etc/shirudo");
	EXPECT_EQ(trusted("mnt/state/etc-shirudo/shirudo.conf",
			  "etc/shirudo/shirudo.conf", false), 0);
	ASSERT_EQ(unlinkat(etc_fd, "etc/shirudo", 0), 0);
	make_link("../mnt/state/etc-shirudo", "etc/shirudo");
	EXPECT_EQ(trusted("mnt/state/etc-shirudo/shirudo.conf",
			  "etc/shirudo/shirudo.conf", false), 0);
	/* The directory that holds the link counts as the target's do. */
	ASSERT_EQ(fchmodat(etc_fd, "etc", 0775, 0), 0);
	EXPECT_EQ(trusted("mnt/state/etc-shirudo/shirudo.conf",
			  "etc/shirudo/shirudo.conf", false), -EPERM);
	ASSERT_EQ(fchmodat(etc_fd, "etc", 0755, 0), 0);
	ASSERT_EQ(fchmodat(etc_fd, "mnt", 0777, 0), 0);
	EXPECT_EQ(trusted("mnt/state/etc-shirudo/shirudo.conf",
			  "etc/shirudo/shirudo.conf", false), -EPERM);
	remove_etc();
}

static void open_beneath_same_mount_refuses_a_bind(void)
{
	char source[PATH_MAX], alias[PATH_MAX];
	int fd;

	need_root("needs root for a private bind mount");
	if (unshare(CLONE_NEWNS))
		unit_skip("cannot make a mount namespace");
	ASSERT_EQ(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL), 0);
	make_etc();
	make_dir("source", 0700);
	make_dir("alias", 0700);
	ASSERT_TRUE(strsprintf(source, sizeof(source), "%s/source", etc_dir) > 0);
	ASSERT_TRUE(strsprintf(alias, sizeof(alias), "%s/alias", etc_dir) > 0);
	ASSERT_EQ(mount(source, alias, NULL, MS_BIND, NULL), 0);
	fd = open_beneath(etc_fd, "alias", O_RDONLY | O_DIRECTORY);
	ASSERT_TRUE(fd >= 0);
	close(fd);
	EXPECT_EQ(open_beneath_same_mount(etc_fd, "alias", O_RDONLY | O_DIRECTORY), -EXDEV);
	ASSERT_EQ(umount(alias), 0);
	remove_etc();
}

/* The same, the directory linked to on a file system of its own. */
static void check_trusted_follows_its_prefix_onto_another_mount(void)
{
	char state[PATH_MAX];
	int fd;

	need_root("needs root to mount");
	if (unshare(CLONE_NEWNS))
		unit_skip("cannot make a mount namespace");
	ASSERT_EQ(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL), 0);
	make_etc();
	make_dirs("etc", 0755);
	make_dirs("mnt/state", 0755);
	ASSERT_TRUE(strsprintf(state, sizeof(state), "%s/mnt/state",
			       etc_dir) > 0);
	ASSERT_EQ(mount("tmpfs", state, "tmpfs", 0, "mode=0755"), 0);
	make_dirs("mnt/state/etc-shirudo", 0755);
	make_file("mnt/state/etc-shirudo/shirudo.conf", 0644);
	make_abs_link("mnt/state/etc-shirudo", "etc/shirudo");
	trust_below("etc/shirudo");
	fd = open_in("etc/shirudo/shirudo.conf");
	EXPECT_EQ(trusted_fd(fd, "etc/shirudo/shirudo.conf"), 0);
	close(fd);
	ASSERT_EQ(umount2(state, MNT_DETACH), 0);
	remove_etc();
}

/*
 * NixOS links /etc/shirudo to /etc/static/shirudo, /etc/static to the
 * system's etc in the store and each file there to a store path of its
 * own. The store is root's, writable by the build users' group, and
 * sticky. Switching to a new system renames a new /etc/static over the
 * old one.
 */
static void check_trusted_follows_nixos_etc_into_the_store(void)
{
	int fd;

	need_root("needs root to hand a file to another user");
	make_etc();
	make_dirs("etc", 0755);
	make_dirs("nix/store", 0755);
	ASSERT_EQ(fchownat(etc_fd, "nix/store", 0, 30000, 0), 0);
	ASSERT_EQ(fchmodat(etc_fd, "nix/store", 01775, 0), 0);
	make_file("nix/store/a-shirudo.conf", 0444);
	make_dirs("nix/store/b-etc/etc/shirudo", 0555);
	make_abs_link("nix/store/a-shirudo.conf",
		      "nix/store/b-etc/etc/shirudo/shirudo.conf");
	make_abs_link("nix/store/b-etc/etc", "etc/static");
	make_abs_link("etc/static/shirudo", "etc/shirudo");
	trust_below("etc/shirudo");
	fd = open_in("etc/shirudo/shirudo.conf");
	EXPECT_EQ(trusted_fd(fd, "etc/shirudo/shirudo.conf"), 0);

	make_file("nix/store/c-shirudo.conf", 0444);
	make_dirs("nix/store/d-etc/etc/shirudo", 0555);
	make_abs_link("nix/store/c-shirudo.conf",
		      "nix/store/d-etc/etc/shirudo/shirudo.conf");
	make_abs_link("nix/store/d-etc/etc", "etc/.static.tmp");
	ASSERT_EQ(renameat(etc_fd, "etc/.static.tmp", etc_fd, "etc/static"), 0);
	EXPECT_EQ(trusted_fd(fd, "etc/shirudo/shirudo.conf"), -ESTALE);
	close(fd);
	fd = open_in("etc/shirudo/shirudo.conf");
	EXPECT_EQ(trusted_fd(fd, "etc/shirudo/shirudo.conf"), 0);
	close(fd);

	ASSERT_EQ(fchmodat(etc_fd, "nix/store", 0775, 0), 0);
	EXPECT_EQ(trusted("nix/store/c-shirudo.conf",
			  "etc/shirudo/shirudo.conf", false), -EPERM);
	remove_etc();
}

/*
 * Ansible, Puppet and Chef write a file beside its name and rename it
 * over. A command that opened the old file is refused once, and the
 * next open takes the new one.
 */
static void check_trusted_takes_a_file_a_config_manager_renamed_over(void)
{
	int fd;

	make_etc();
	make_dirs("etc/shirudo", 0755);
	trust_below("etc/shirudo");
	replace("etc/shirudo/shirudo.conf", "eventlog.max_bytes = 1048576\n");
	fd = open_in("etc/shirudo/shirudo.conf");
	EXPECT_EQ(trusted_fd(fd, "etc/shirudo/shirudo.conf"), 0);
	replace("etc/shirudo/shirudo.conf", "eventlog.max_bytes = 2097152\n");
	EXPECT_EQ(trusted_fd(fd, "etc/shirudo/shirudo.conf"), -ESTALE);
	close(fd);
	fd = open_in("etc/shirudo/shirudo.conf");
	EXPECT_EQ(trusted_fd(fd, "etc/shirudo/shirudo.conf"), 0);
	close(fd);
	remove_etc();
}

/*
 * An operator who is not root keeps keys in a directory of its own, as
 * genkey allows for /var/lib/shirudo/keys, and links cert.der to the
 * current one.
 */
static void check_trusted_lets_a_user_follow_its_own_links(void)
{
	need_root("needs root to hand a file to another user");
	make_etc();
	ASSERT_EQ(fchmod(etc_fd, 0755), 0);
	make_dirs("var/lib/shirudo", 0755);
	make_dirs("var/lib/shirudo/keys", 0700);
	give("var/lib/shirudo/keys", NOBODY);
	make_file("var/lib/shirudo/keys/cert-1.der", 0600);
	give("var/lib/shirudo/keys/cert-1.der", NOBODY);
	make_link("cert-1.der", "var/lib/shirudo/keys/cert.der");
	give("var/lib/shirudo/keys/cert.der", NOBODY);
	make_abs_link("var/lib/shirudo/keys/cert-1.der",
		      "var/lib/shirudo/keys/root.der");
	make_link("cert-1.der", "var/lib/shirudo/keys/other.der");
	give("var/lib/shirudo/keys/other.der", OTHER_USER);
	trust_below("var/lib/shirudo");
	ASSERT_EQ(seteuid(NOBODY), 0);
	EXPECT_EQ(trusted("var/lib/shirudo/keys/cert-1.der",
			  "var/lib/shirudo/keys/cert.der", false), 0);
	EXPECT_EQ(trusted("var/lib/shirudo/keys/cert-1.der",
			  "var/lib/shirudo/keys/root.der", false), 0);
	EXPECT_EQ(trusted("var/lib/shirudo/keys/cert-1.der",
			  "var/lib/shirudo/keys/other.der", false), -EPERM);
	ASSERT_EQ(seteuid(0), 0);
	/* Root takes nothing from a directory another user owns. */
	EXPECT_EQ(trusted("var/lib/shirudo/keys/cert-1.der",
			  "var/lib/shirudo/keys/root.der", false), -EPERM);
	remove_etc();
}

static void check_trusted_refuses_a_link_another_user_owns(void)
{
	need_root("needs root to hand a file to another user");
	make_etc();
	make_dirs("etc/shirudo/bpm", 0755);
	make_dirs("etc/ssl/certs", 0755);
	make_dirs("srv/ca", 0755);
	make_file("srv/ca/ca.pem", 0644);
	trust_below("etc/shirudo");
	make_abs_link("srv/ca/ca.pem", "etc/shirudo/bpm/ca.pem");
	EXPECT_EQ(trusted("srv/ca/ca.pem", "etc/shirudo/bpm/ca.pem", false), 0);
	give("etc/shirudo/bpm/ca.pem", NOBODY);
	EXPECT_EQ(trusted("srv/ca/ca.pem", "etc/shirudo/bpm/ca.pem", false),
		  -EPERM);
	/* A link to a directory on the way counts as the last one does. */
	make_link("../../srv/ca", "etc/shirudo/ca");
	EXPECT_EQ(trusted("srv/ca/ca.pem", "etc/shirudo/ca/ca.pem", false), 0);
	give("etc/shirudo/ca", NOBODY);
	EXPECT_EQ(trusted("srv/ca/ca.pem", "etc/shirudo/ca/ca.pem", false),
		  -EPERM);
	/* So does one outside the prefix that a link inside leads to. */
	make_abs_link("srv/ca/ca.pem", "etc/ssl/certs/ca.pem");
	give("etc/ssl/certs/ca.pem", NOBODY);
	make_abs_link("etc/ssl/certs/ca.pem", "etc/shirudo/bpm/chain.pem");
	EXPECT_EQ(trusted("srv/ca/ca.pem", "etc/shirudo/bpm/chain.pem", false),
		  -EPERM);
	remove_etc();
}

#define RACE_READS	20000
#define RACE_REFUSALS	16

/*
 * Renames a new copy of name over it until killed, a or b in turn, with
 * a pause that leaves some reads the time to finish.
 */
static __noreturn void rename_over_until_killed(const char *name)
{
	const struct timespec pause = { .tv_nsec = 100000 };
	char tmp[PATH_MAX];
	bool b = false;
	int fd;

	if (prctl(PR_SET_PDEATHSIG, SIGKILL) ||
	    strsprintf(tmp, sizeof(tmp), "%s.tmp", name) < 0)
		_exit(1);
	for (;; b = !b) {
		fd = openat(etc_fd, tmp, O_WRONLY | O_CREAT | O_TRUNC |
			    O_CLOEXEC, 0644);
		if (fd < 0 || write_complete(fd, b ? "b\n" : "a\n", 2) ||
		    close(fd) || renameat(etc_fd, tmp, etc_fd, name))
			_exit(1);
		nanosleep(&pause, NULL);
	}
}

/*
 * A file renamed over while it is read, as config managers and sealed
 * state writes do: each read takes the old file or the new one whole.
 * Only a read whose every attempt found the name renamed over again is
 * refused, with -ESTALE, and none is refused for anything else.
 */
static void read_file_takes_a_file_renamed_over_or_refuses_it(void)
{
	int i, ret, refused = 0, other = 0, status;
	char path[PATH_MAX], *body;
	size_t len;
	pid_t pid;

	make_etc();
	make_dirs("etc/shirudo", 0755);
	trust_below("etc/shirudo");
	replace("etc/shirudo/shirudo.conf", "a\n");
	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/etc/shirudo/shirudo.conf",
			       etc_dir) > 0);
	pid = fork();
	ASSERT_TRUE(pid >= 0);
	if (!pid)
		rename_over_until_killed("etc/shirudo/shirudo.conf");
	for (i = 0; i < RACE_READS && refused < RACE_REFUSALS; i++) {
		ret = read_file(path, 16, &body, &len);
		if (ret == -ESTALE) {
			refused++;
			continue;
		}
		if (ret) {
			other++;
			continue;
		}
		if (len != 2 || (body[0] != 'a' && body[0] != 'b'))
			other++;
		xfree(body, len + 1);
	}
	ASSERT_EQ(kill(pid, SIGKILL), 0);
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_TRUE(WIFSIGNALED(status));
	EXPECT_EQ(other, 0);
	ASSERT_EQ(read_file(path, 16, &body, &len), 0);
	xfree(body, len + 1);
	remove_etc();
}

static const struct unit_case cases[] = {
	UNIT_CASE(open_beneath_same_mount_stops_at_proc),
	UNIT_CASE(open_beneath_same_mount_refuses_a_bind),
	UNIT_CASE(lines_len_ends_at_the_last_newline),
	UNIT_CASE(append_line_adds_one_record),
	UNIT_CASE(append_line_drops_what_did_not_finish),
	UNIT_CASE(append_line_takes_one_line_alone),
	UNIT_CASE(lock_exclusive_keeps_others_out),
	UNIT_CASE(kernel_dev_is_major_over_20_minor_bits),
	UNIT_CASE(bpffs_mounted_at_wants_the_root_of_a_bpffs),
	UNIT_CASE(check_trusted_takes_a_file_nobody_else_can_change),
	UNIT_CASE(check_trusted_refuses_a_directory_others_can_write),
	UNIT_CASE(check_trusted_follows_a_link_nobody_else_made),
	UNIT_CASE(check_trusted_refuses_a_link_others_can_replace),
	UNIT_CASE(check_trusted_wants_the_file_the_path_names),
	UNIT_CASE(check_secret_asks_the_file_alone),
	UNIT_CASE(open_trusted_reopens_a_file_renamed_over),
	UNIT_CASE(open_trusted_gives_up_on_a_name_that_keeps_changing),
	UNIT_CASE(open_trusted_checks_each_file_it_opens),
	UNIT_CASE(check_trusted_follows_link_chains_out_of_its_prefix),
	UNIT_CASE(check_trusted_follows_a_distribution_s_ca_links),
	UNIT_CASE(check_trusted_follows_its_prefix_linked_elsewhere),
	UNIT_CASE(check_trusted_follows_its_prefix_onto_another_mount),
	UNIT_CASE(check_trusted_follows_nixos_etc_into_the_store),
	UNIT_CASE(check_trusted_takes_a_file_a_config_manager_renamed_over),
	UNIT_CASE(check_trusted_lets_a_user_follow_its_own_links),
	UNIT_CASE(check_trusted_refuses_a_link_another_user_owns),
	UNIT_CASE(read_file_takes_a_file_renamed_over_or_refuses_it),
	{}
};

UNIT_SUITE(io, cases);
