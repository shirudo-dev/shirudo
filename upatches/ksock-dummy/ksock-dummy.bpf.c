// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define AF_INET 2
#define EIO 5

#ifndef DEST_ADDR
#define DEST_ADDR 0x0a000202
#endif
#ifndef DEST_PORT
#define DEST_PORT 19090
#endif

extern struct bpf_ksock *
bpf_ksock_create(const struct bpf_ksock_create_opts *opts, __u32 opts__sz,
		 int *err__uninit) __ksym;
extern int
bpf_ksock_connect(struct bpf_ksock *ks, const union bpf_ksock_addr *addr, __u32 addr__sz) __ksym;
extern int bpf_ksock_send(struct bpf_ksock *ks, const void *data, __u32 data__sz) __ksym;
extern void bpf_ksock_release(struct bpf_ksock *ks) __ksym;

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("syscall")
int shirudo_test__ksock_dummy(void *ctx)
{
	struct bpf_ksock_create_opts opts = {
		.family = AF_INET,
		.type = SOCK_DGRAM,
		.protocol = IPPROTO_UDP,
	};
	char payload[] = "shirudo ksock dummy\n";
	union bpf_ksock_addr addr = {};
	struct bpf_ksock *ks;
	int ret, err;

	ks = bpf_ksock_create(&opts, sizeof(opts), &err);
	if (!ks)
		return err;
	addr.sin.sin_family = AF_INET;
	addr.sin.sin_port = bpf_htons(DEST_PORT);
	addr.sin.sin_addr.s_addr = bpf_htonl(DEST_ADDR);
	ret = bpf_ksock_connect(ks, &addr, sizeof(addr));
	if (ret)
		goto out;
	ret = bpf_ksock_send(ks, payload, sizeof(payload) - 1);
	if (ret >= 0)
		ret = ret == (int)sizeof(payload) - 1 ? 0 : -EIO;
out:
	bpf_ksock_release(ks);
	return ret;
}
