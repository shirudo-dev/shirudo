/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 */

#ifndef SHIRUDO_ELF_TARGET_H
#define SHIRUDO_ELF_TARGET_H

#include <shirudo/misc.h>
#include <shirudo/upatch.h>

struct elf_target {
	__u8		build_id[UPATCH_BUILD_ID_MAX];
	__u32		build_id_len;
	__u64		*offsets;
	__u32		nr_offsets;
	__u32		offsets_cap;
};

int elf_target_resolve(const char *path, const char *pattern,
		       struct elf_target *out);

/*
 * One file offset: func's plus offset, or offset itself when func is NULL,
 * inside the file at path. 0 or -errno; free with elf_target_free().
 */
int elf_target_resolve_func(const char *path, const char *func, __u64 offset,
			    struct elf_target *out);

int elf_build_id_fd(int fd,
		    __u8 build_id[UPATCH_BUILD_ID_MAX],
		    __u32 *build_id_len);

void elf_target_free(struct elf_target *target);

#endif /* SHIRUDO_ELF_TARGET_H */
