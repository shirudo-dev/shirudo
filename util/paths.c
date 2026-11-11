// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Path helpers complementing util/paths.h.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <shirudo/string.h>
#include <shirudo/upatch.h>

#include "paths.h"

const char *keys_dir_resolve(const char *keys_dir_arg)
{
	const char *env;

	if (keys_dir_arg)
		return keys_dir_arg;
	env = getenv(KEYS_DIR_ENV);
	if (env)
		return env;
	return KEYS_DIR;
}

int format_key_path(char *out, size_t out_sz,
		    const char *keys_dir, const char *file)
{
	const char *dir = keys_dir ? keys_dir : KEYS_DIR;
	const char *sep;

	if (!out || out_sz == 0 || !dir || !*dir || !file || !*file)
		return -EINVAL;

	sep = dir[strlen(dir) - 1] == '/' ? "" : "/";
	if (strsprintf(out, out_sz, "%s%s%s", dir, sep, file) < 0)
		return -ENAMETOOLONG;
	return 0;
}

int key_paths(const char *keys_dir,
	      char *pkey_path, size_t pkey_sz,
	      char *cert_path, size_t cert_sz)
{
	int ret;

	ret = format_key_path(pkey_path, pkey_sz, keys_dir,
			      SIGNING_KEY_FILE);
	if (ret)
		return ret;
	return format_key_path(cert_path, cert_sz, keys_dir,
			       CERT_FILE);
}

int upatch_pin_path(char *out, size_t cap, const char *name, ...)
{
	char bpffs_name[UPATCH_BPFFS_NAME_MAX + 1];
	const char *part;
	int n, ret = 0;
	size_t len;
	va_list ap;

	if (upatch_bpffs_name(bpffs_name, sizeof(bpffs_name), name))
		goto too_long;
	n = strsprintf(out, cap, "%s/%s", BPFFS_UPATCHES_DIR, bpffs_name);
	if (n < 0)
		goto too_long;
	len = n;
	va_start(ap, name);
	while ((part = va_arg(ap, const char *))) {
		n = strsprintf(out + len, cap - len, "/%s", part);
		if (n < 0) {
			ret = -ENAMETOOLONG;
			break;
		}
		len += n;
	}
	va_end(ap);
	if (!ret)
		return 0;
too_long:
	if (cap)
		out[0] = '\0';
	return -ENAMETOOLONG;
}

int path_join(char *out, size_t cap, const char *dir, const char *name)
{
	if (strsprintf(out, cap, "%s/%s", dir, name) >= 0)
		return 0;
	if (cap)
		out[0] = '\0';
	return -ENAMETOOLONG;
}

bool path_exists(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0;
}
