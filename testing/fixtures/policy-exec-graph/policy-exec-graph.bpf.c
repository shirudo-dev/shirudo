// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "shirudo_policy_map.h"

char _license[] SEC("license") = "Dual BSD/GPL";

#define SHIRUDO_POLICY_XATTR "security.bpf.shirudo.policy"
#define AF_INET 2
#ifndef ENODATA
#define ENODATA 61
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP 95
#endif

struct policy_exec_scratch {
	__u64 target;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct policy_exec_scratch);
} policy_exec_scratch SEC(".maps");

int bpf_get_file_xattr(struct file *file, const char *name__str,
		       struct bpf_dynptr *value_p) __ksym;

SEC("lsm.s/bprm_check_security")
int BPF_PROG(shirudo_test_policy_exec_graph,
	     struct linux_binprm *bprm, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct shirudo_task_policy *policy;
	struct policy_exec_scratch *scratch;
	struct bpf_dynptr value_ptr;
	__u64 target;
	int len;

	if (ret)
		return ret;
	if (!bprm || !bprm->file)
		return -13;
	scratch = bpf_task_storage_get(&policy_exec_scratch, task, NULL,
				       BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!scratch ||
	    bpf_dynptr_from_mem(&scratch->target, sizeof(scratch->target),
				0, &value_ptr))
		return -13;
	len = bpf_get_file_xattr(bprm->file, SHIRUDO_POLICY_XATTR,
				 &value_ptr);
	if (len == -ENODATA || len == -EOPNOTSUPP)
		target = 0;
	else if (len != sizeof(scratch->target))
		return -13;
	if (len == sizeof(scratch->target))
		target = scratch->target;
	policy = bpf_task_storage_get(&policy_map, task, NULL, 0);
	if (!policy)
		return -13;
	if ((!policy->active && (target == 0 || target == 1)) ||
	    (policy->active == 1 &&
	     (target == 2 || target == 8 || target == 16)))
		return 0;
	return -13;
}

SEC("lsm.s/socket_connect")
int BPF_PROG(shirudo_test_policy_socket_graph, struct socket *sock,
	     struct sockaddr *address, int addrlen, int ret)
{
	struct sockaddr_in sin = {};
	struct sock *sk;
	__u64 *socket_policy;
	__u16 family;

	if (ret)
		return ret;
	if (!address ||
	    bpf_probe_read_kernel(&family, sizeof(family),
				  &address->sa_family))
		return -13;
	if (family != AF_INET)
		return 0;
	if (addrlen < (int)sizeof(sin) ||
	    bpf_probe_read_kernel(&sin, sizeof(sin), address))
		return -13;
	if (bpf_ntohl(sin.sin_addr.s_addr) != 0x7f000001)
		return 0;
	if (!sock)
		return -13;
	sk = sock->sk;
	if (!sk)
		return -13;
	socket_policy = bpf_sk_storage_get(&socket_policy_map, sk, NULL, 0);
	if (!socket_policy)
		return -13;
	if (*socket_policy & 16)
		return -13;
	if (*socket_policy & 8)
		return 0;
	return -13;
}
