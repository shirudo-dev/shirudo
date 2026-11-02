// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The signed unload directive: loading it is the authorization, the
 * detach itself still runs in userspace.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define UPATCH_NAME_MAX	256
#define SHA256_LEN	32

struct unload_params {
	char	name[UPATCH_NAME_MAX];
	__u8	expected_sha256[SHA256_LEN];
};

volatile const struct unload_params shirudo_unload_params = {
	.name		 = "<unpatched>",
	.expected_sha256 = {},
};

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("syscall")
int shirudo_unload(void *ctx __attribute__((__unused__)))
{
	/*
	 * TODO: look up /run/shirudo/bpffs/upatches/<name>/link
	 * via bpf_sys_bpf(BPF_OBJ_GET), cross-check the loaded upatch's
	 * payload_sha256 against the signature-covered
	 * shirudo_unload_params.expected_sha256, then BPF_LINK_DETACH +
	 * BPF_OBJ_UNPIN from kernel context. Blocked on bpf_sys_bpf()
	 * gaining those ops; until then the detach and
	 * payload compare run in userspace.
	 */
	return 0;
}
