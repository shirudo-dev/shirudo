/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_LSM_H
#define SHIRUDO_LSM_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "errno.h"

#ifndef FMODE_WRITE
#define FMODE_WRITE	0x2
#endif
#ifndef S_IFMT
#define S_IFMT		00170000
#endif
#ifndef S_IFDIR
#define S_IFDIR		0040000
#endif
#define LSM_UNSAFE_PTRACE	2
/* include/linux/ptrace.h; a #define, so not in BTF. */
#define PTRACE_MODE_ATTACH	0x02
#define PR_SET_MM		35
#define PR_SET_MM_EXE_FILE	13
#define PR_SET_MM_MAP		14

#include <shirudo/enforcement.h>

#include "identity.h"
#include "integrity.h"
#include "policy.h"
#include "tamper.h"

#define TASK_TRUSTED	1
#define TASK_BOOTSTRAP	2

struct task_authority {
	__u8	trusted;
	__u8	candidate_valid;
	__u8	candidate_trusted;
	__u8	revoked;
	__u32	pad2;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_authority);
} shirudo_tasks SEC(".maps");

/* The caller holds this private bpffs directory open until it drops the grant. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u64);
} shirudo_unlink_grant SEC(".maps");

static __always_inline struct sb_id *shirudo_policy(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&shirudo_bpffs_sb, &zero);
}

static __always_inline bool shirudo_marked(struct task_struct *task)
{
	struct task_authority *authority;

	authority = bpf_task_storage_get(&shirudo_tasks, task, NULL, 0);
	return authority && authority->trusted;
}

#endif /* SHIRUDO_LSM_H */
