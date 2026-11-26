// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * A .bee as bpm install unpacks it and as the operator reads its
 * build-environment.json and certificate.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "bpm_package.h"
#include "fuzz.h"
#include "malloc.h"

static char base[64];
static char dest[sizeof(base) + 4];

/*
 * By readdir(), not nftw(): MemorySanitizer has no interceptor for
 * nftw() and takes the struct FTW it hands over as never written.
 */
static void empty_dir(const char *dir)
{
	char path[PATH_MAX];
	struct dirent *e;
	DIR *d;

	d = opendir(dir);
	if (!d)
		return;
	while ((e = readdir(d))) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..") ||
		    snprintf(path, sizeof(path), "%s/%s", dir,
			     e->d_name) >= (int)sizeof(path))
			continue;
		if (unlink(path) && errno == EISDIR) {
			empty_dir(path);
			rmdir(path);
		}
	}
	closedir(d);
}

static void empty_base(void)
{
	empty_dir(base);
}

static void remove_base(void)
{
	empty_base();
	rmdir(base);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	snprintf(base, sizeof(base), "/tmp/shirudo-fuzz-bpm-package-XXXXXX");
	if (!mkdtemp(base))
		abort();
	snprintf(dest, sizeof(dest), "%s/pkg", base);
	atexit(remove_base);
	return 0;
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct bpm_package_info info = {};
	char path[64];
	int fd, dir;

	fd = fuzz_gzip_file(data, size, path, sizeof(path));
	if (fd < 0)
		return 0;
	if (!bpm_pkg_load_info(path, &info))
		xfree(info.cert, info.cert_len + 1);
	dir = mkdir(dest, 0700) ? -1 :
	      open(dest, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dir >= 0) {
		bpm_pkg_extract(fd, dir);
		close(dir);
	}
	empty_base();
	close(fd);
	return 0;
}
