// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

/* Image mode retains the writable-state label seal and trusts runtime execs. */
#include "verity_policy.h"
#include "seal.h"

char _license[] SEC("license") = "Dual BSD/GPL";

struct seccomp___shirudo {
	int mode;
} __attribute__((preserve_access_index));

/* CONFIG_SECCOMP=n leaves struct seccomp empty in the kernel BTF. */
static __always_inline bool shirudo_task_has_seccomp(struct task_struct *task)
{
	struct seccomp___shirudo *seccomp = (void *)&task->seccomp;

	return bpf_core_field_exists(seccomp->mode) &&
	       BPF_CORE_READ(seccomp, mode);
}

/*
 * Image mode grants authority only to a direct file on the verified runtime.
 * Overlay copies cannot qualify. Ptrace or seccomp supplied before exec must
 * not control the new trusted process. A failed exec retains the old mark.
 */
SEC("lsm.s/bprm_check_security")
int BPF_PROG(shirudo_seal_bprm_check_security,
	     struct linux_binprm *bprm, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct shirudo_task_authority *authority;
	struct inode *real_inode;
	bool trusted;

	if (ret)
		return ret;
	if (!shirudo_policy())
		return -EACCES;
	real_inode = bpf_real_data_inode(bprm->file);
	trusted = real_inode == BPF_CORE_READ(bprm, file, f_inode) &&
		  shirudo_file_runtime(bprm->file);
	if (trusted && (BPF_CORE_READ(task, ptrace) ||
			shirudo_task_has_seccomp(task)))
		return -EACCES;
	authority = bpf_task_storage_get(&shirudo_tasks, task, NULL,
					 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!authority)
		return -ENOMEM;
	authority->candidate_trusted = trusted;
	authority->candidate_valid = 1;
	return 0;
}

#define SHIRUDO_PROT_WRITE	2
#define SHIRUDO_PROT_EXEC	4
#define SHIRUDO_VM_EXEC		4

/* Executable mappings in a trusted process must come from its runtime image. */
SEC("lsm/mmap_file")
int BPF_PROG(shirudo_seal_mmap_file, struct file *file,
	     unsigned long reqprot, unsigned long prot,
	     unsigned long flags, int ret)
{
	struct shirudo_sb_id *id = shirudo_policy();

	if (ret)
		return ret;
	if (!id || !shirudo_task_is_self(id) ||
	    shirudo_bootstrap_task() || !(prot & SHIRUDO_PROT_EXEC))
		return 0;
	if ((prot & SHIRUDO_PROT_WRITE) || !shirudo_file_runtime(file))
		return -EACCES;
	return 0;
}

/* Disallow executable promotion of pages that could have been modified. */
SEC("lsm/file_mprotect")
int BPF_PROG(shirudo_seal_file_mprotect, struct vm_area_struct *vma,
	     unsigned long reqprot, unsigned long prot, int ret)
{
	struct shirudo_sb_id *id = shirudo_policy();
	unsigned long old_flags;

	if (ret)
		return ret;
	old_flags = BPF_CORE_READ(vma, vm_flags);
	if (!id || !shirudo_task_is_self(id) ||
	    shirudo_bootstrap_task())
		return 0;
	if ((old_flags & SHIRUDO_VM_EXEC) && (prot & SHIRUDO_PROT_WRITE))
		return -EACCES;
	if (!(prot & SHIRUDO_PROT_EXEC))
		return 0;
	if (!(old_flags & SHIRUDO_VM_EXEC) ||
	    !shirudo_file_runtime(BPF_CORE_READ(vma, vm_file)))
		return -EACCES;
	return 0;
}
