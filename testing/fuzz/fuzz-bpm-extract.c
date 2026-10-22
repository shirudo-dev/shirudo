// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm_pkg_extract() taking a gzip'd package archive apart into a fresh
 * directory under $TMPDIR, removed again after each input.
 */

#include <ftw.h>
#include <limits.h>
#include <stdlib.h>

#include "bpm_package.h"
#include "fuzz.h"

static int remove_entry(const char *path, const struct stat *st, int type,
			struct FTW *ftw)
{
	(void)st;
	(void)type;
	(void)ftw;
	remove(path);
	return 0;
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	const char *tmp = getenv("TMPDIR");
	char path[64], dir[PATH_MAX], dest[PATH_MAX + 8];
	int fd;

	if (snprintf(dir, sizeof(dir), "%s/fuzz-extract-XXXXXX",
		     tmp && *tmp ? tmp : "/tmp") >= (int)sizeof(dir))
		return 0;
	fd = fuzz_gzip_file(data, size, path, sizeof(path));
	if (fd < 0)
		return 0;
	if (mkdtemp(dir)) {
		snprintf(dest, sizeof(dest), "%s/pkg", dir);
		bpm_pkg_extract(path, dest);
		nftw(dir, remove_entry, 16, FTW_DEPTH | FTW_PHYS);
	}
	close(fd);
	return 0;
}
