// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "Dual BSD/GPL";

/*
 * A kernel without CONFIG_FUNCTION_ERROR_INJECTION takes sleepable
 * programs of these kinds on the entry points of system calls alone,
 * which carry the architecture in their name.
 */
#if defined(__TARGET_ARCH_x86)
#define SYS_CHDIR "__x64_sys_chdir"
#elif defined(__TARGET_ARCH_arm64)
#define SYS_CHDIR "__arm64_sys_chdir"
#else
#error "no system call entry point known for this architecture"
#endif

#define EXDEV 18

/* A path that only t3120 passes to chdir(2) in the VM. */
static const char test_path[] = "/shirudo-test-sleepable";

enum {
	SEEN_ENTRY,
	SEEN_EXIT,
	NR_SEEN,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_SEEN);
	__type(key, __u32);
	__type(value, __u64);
} seen SEC(".maps");

static __always_inline void count(__u32 slot)
{
	__u64 *value = bpf_map_lookup_elem(&seen, &slot);

	if (value)
		__sync_fetch_and_add(value, 1);
}

/* bpf_copy_from_user() may sleep: the verifier refuses it anywhere else. */
static __always_inline bool is_test_path(const struct pt_regs *regs)
{
	const char *filename = (const char *)PT_REGS_PARM1_CORE_SYSCALL(regs);
	char path[sizeof(test_path)];
	__u32 i;

	if (bpf_copy_from_user(path, sizeof(path), filename))
		return false;
	for (i = 0; i < sizeof(path); i++) {
		if (path[i] != test_path[i])
			return false;
	}
	return true;
}

SEC("fentry.s/" SYS_CHDIR)
int BPF_PROG(enter_chdir, const struct pt_regs *regs)
{
	if (is_test_path(regs))
		count(SEEN_ENTRY);
	return 0;
}

SEC("fmod_ret.s/" SYS_CHDIR)
long BPF_PROG(refuse_chdir, const struct pt_regs *regs, long ret)
{
	if (is_test_path(regs))
		return -EXDEV;
	return 0;
}

SEC("fexit.s/" SYS_CHDIR)
int BPF_PROG(exit_chdir, const struct pt_regs *regs, long ret)
{
	if (ret == -EXDEV && is_test_path(regs))
		count(SEEN_EXIT);
	return 0;
}
