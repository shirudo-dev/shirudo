/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_BPF_POLICY_H
#define SHIRUDO_BPF_POLICY_H

#include "lsm.h"

#define SHIRUDO_MODE_ERROR SHIRUDO_PR_MODE_LEGACY_ERR
#define SHIRUDO_TASK_STORAGE_REQUIRED false

/* A label protects the target; the frozen executable authorizes the caller. */
static __always_inline bool shirudo_task_is_self(const struct shirudo_sb_id *id)
{
	return shirudo_task_matches_exe(id);
}

static __always_inline bool
shirudo_protected_filesystem(const struct shirudo_sb_id *id, __u32 dev)
{
	return dev == id->sb_dev;
}

/* Ordinary mode has no device-authority map to hide from observers. */
static __always_inline bool shirudo_private_map(struct bpf_map *map)
{
	return false;
}

/* Replacing the binary for an upgrade does not authorize its replacement. */
static __always_inline bool shirudo_replaceable_executable(struct inode *inode)
{
	struct shirudo_sb_id *id = shirudo_policy();

	return id && BPF_CORE_READ(inode, i_sb, s_dev) == id->exe_dev &&
	       BPF_CORE_READ(inode, i_ino) == id->exe_ino;
}

#endif /* SHIRUDO_BPF_POLICY_H */
