// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

/* Ordinary mode labels assets and recognizes the recorded executable. */
#include "policy.h"
#include "seal.h"

char _license[] SEC("license") = "Dual BSD/GPL";

/*
 * In ordinary mode the label marks processes for ptrace/perf protection. It
 * grants no permission to mutate files or BPF objects; those checks compare
 * the executable device/inode frozen at init. Stage the mark until commit.
 */
SEC("lsm.s/bprm_check_security")
int BPF_PROG(shirudo_seal_bprm_check_security,
	     struct linux_binprm *bprm, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct shirudo_task_authority *authority;
	struct seal_scratch *scratch;
	struct bpf_dynptr dp;
	int len;

	if (ret)
		return ret;
	if (!shirudo_policy())
		return -EACCES;
	scratch = seal_scratch_get(task);
	if (!scratch)
		return 0;
	bpf_dynptr_from_mem(scratch->target, LABEL_LEN, 0, &dp);
	len = bpf_get_file_xattr(bprm->file, SHIRUDO_XATTR, &dp);
	authority = bpf_task_storage_get(&shirudo_tasks, task, NULL,
					 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!authority)
		return 0;
	authority->candidate_trusted = len == LABEL_LEN;
	authority->candidate_valid = 1;
	return 0;
}
