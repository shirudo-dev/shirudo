// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What the running kernel shows of the options the threat model assumes,
 * for the pre-flight checks of init.
 */

#include <stdbool.h>
#include <string.h>

#include <linux/btf.h>

#include <bpf/btf.h>

#include <shirudo/string.h>

#include "kernel_prereq.h"

static bool has_func(const struct btf *btf, const char *name)
{
	return btf__find_by_name_kind(btf, name, BTF_KIND_FUNC) > 0;
}

/*
 * Each name is a function only its option builds. Without the option
 * its stub, where it has one, is a static inline, which leaves no BTF
 * function.
 */
void kernel_prereq_options(const struct btf *btf, struct kernel_options *out)
{
	out->modules = has_func(btf, "__module_address");
	out->module_sig = has_func(btf, "mod_verify_sig");
	out->compat = has_func(btf, "compat_ptr_ioctl");
}

bool kernel_hibernation_resumes(const char *disk, const char *resume)
{
	if (!disk || str_contains(disk, "[disabled]"))
		return false;
	return resume && strcmp(resume, "0:0") != 0;
}

bool kernel_prereq_mount_source(const char *line, const char *path,
				size_t *depth, char *source, size_t cap)
{
	size_t pos = 0, start, mp_len, mp_start, path_len, n;

	path_len = strlen(path);
	n = token_next(line, strlen(line), " ", &pos, &start);
	if (!n || span_to_str(source, cap, line + start, n))
		return false;
	n = token_next(line, strlen(line), " ", &pos, &mp_start);
	if (!n)
		return false;
	mp_len = n;
	if (mp_len > path_len || memcmp(line + mp_start, path, mp_len))
		return false;
	if (mp_len < path_len && path[mp_len] != '/' &&
	    line[mp_start + mp_len - 1] != '/')
		return false;
	*depth = mp_len;
	return true;
}
