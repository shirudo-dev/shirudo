// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Inode labelling for the bpf/seal.c filesystem-sealing LSM.
 */

#include <errno.h>
#include <ftw.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "log.h"
#include "paths.h"
#include "seal.h"

int shirudo_seal_label(const char *path)
{
	if (setxattr(path, SHIRUDO_XATTR_NAME, SHIRUDO_SEAL_LABEL,
		     sizeof(SHIRUDO_SEAL_LABEL) - 1, 0) != 0)
		return -errno;
	return 0;
}

/*
 * nftw is callback-only with no user pointer, so the root device is
 * passed via a file-scope variable -- shirudo init is single-threaded
 * and never walks two trees at once.
 */
static dev_t seal_root_dev;

static int seal_label_cb(const char *path, const struct stat *sb,
			 int typeflag, struct FTW *ftwbuf)
{
	(void)typeflag;
	(void)ftwbuf;
	/*
	 * Belt-and-suspenders with FTW_MOUNT: never label an inode on a
	 * different filesystem (the bpffs mount), which is bpf2's domain
	 * and uses a different xattr. Labelling it would make seal contend
	 * for those inodes.
	 */
	if (sb->st_dev != seal_root_dev)
		return 0;
	if (shirudo_seal_label(path) != 0)
		pr_warn("seal: label %s: %s", path, strerror(errno));
	return 0;	/* best-effort: keep walking */
}

int shirudo_seal_label_tree(void)
{
	char self[PATH_MAX];
	struct stat st;
	ssize_t n;

	/* Label the binary too: the seal protects it and marks its tasks. */
	n = readlink("/proc/self/exe", self, sizeof(self) - 1);
	if (n > 0) {
		self[n] = '\0';
		if (shirudo_seal_label(self) != 0)
			pr_warn("seal: label %s: %s", self, strerror(errno));
	}

	if (stat(SHIRUDO_VAR_LIB, &st) != 0)
		return -errno;
	seal_root_dev = st.st_dev;
	if (nftw(SHIRUDO_VAR_LIB, seal_label_cb, 16, FTW_PHYS | FTW_MOUNT) != 0)
		return -errno;
	return 0;
}
