/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_LSM_H
#define SHIRUDO_LSM_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef EPERM
#define EPERM	1
#endif
#ifndef EACCES
#define EACCES	13
#endif
#ifndef ENOMEM
#define ENOMEM	12
#endif
#ifndef ENOSYS
#define ENOSYS	38
#endif
#ifndef FMODE_WRITE
#define FMODE_WRITE	0x2
#endif
#define LSM_UNSAFE_PTRACE	2
#define PR_SET_MM		35
#define PR_SET_MM_EXE_FILE	13
#define PR_SET_MM_MAP		14

#include "lib/shirudo_identity.h"
#include "../include/shirudo_enforcement.h"
#include "shirudo_tamper.h"

#define SHIRUDO_TASK_TRUSTED	1
#define SHIRUDO_TASK_BOOTSTRAP	2

struct shirudo_task_authority {
	__u8	trusted;
	__u8	candidate_valid;
	__u8	candidate_trusted;
	__u8	pad;
	__u32	pad2;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct shirudo_task_authority);
} shirudo_tasks SEC(".maps");

static __always_inline struct shirudo_sb_id *shirudo_policy(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
}

static __always_inline bool shirudo_marked(struct task_struct *task)
{
	struct shirudo_task_authority *authority;

	authority = bpf_task_storage_get(&shirudo_tasks, task, NULL, 0);
	return authority && authority->trusted;
}

#endif /* SHIRUDO_LSM_H */
