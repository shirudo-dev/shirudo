// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "shirudo_policy_map.h"

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/do_nanosleep")
int BPF_PROG(shirudo_test_policy_labels)
{
	return 0;
}

SEC("lsm.s/bprm_check_security")
int BPF_PROG(shirudo_test_policy_verdict,
	     struct linux_binprm *bprm __attribute__((__unused__)), int ret)
{
	struct shirudo_task_policy *policy;

	if (ret)
		return ret;
	policy = bpf_task_storage_get(&policy_map, bpf_get_current_task_btf(),
				      NULL, 0);
	return policy && (policy->candidate & 1) ? -13 : 0;
}

SEC("lsm.s/socket_connect")
int BPF_PROG(shirudo_test_socket_policy_verdict,
	     struct socket *sock,
	     struct sockaddr *address __attribute__((__unused__)),
	     int addrlen __attribute__((__unused__)),
	     int ret)
{
	struct shirudo_task_policy *policy;
	struct sock *sk;
	__u64 *socket_policy;

	if (ret || !sock)
		return ret;
	sk = sock->sk;
	if (!sk)
		return 0;
	socket_policy = bpf_sk_storage_get(&socket_policy_map, sk, NULL, 0);
	policy = bpf_task_storage_get(&policy_map, bpf_get_current_task_btf(),
				      NULL, 0);
	return (socket_policy && (*socket_policy & 16)) ||
	       (policy && (policy->active & 16)) ? -13 : 0;
}
