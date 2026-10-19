// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Check that an untrusted caller cannot detach or update a pinned upatch link.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <linux/bpf.h>

static long sys_bpf(int cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

int main(int argc, char **argv)
{
	union bpf_attr attr = {};
	int link_fd;
	int detach_errno, update_errno;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <pinned-link>\\n", argv[0]);
		return 2;
	}
	attr.pathname = (__u64)(uintptr_t)argv[1];
	link_fd = (int)sys_bpf(BPF_OBJ_GET, &attr);
	if (link_fd < 0) {
		fprintf(stderr, "BPF_OBJ_GET: %s\\n", strerror(errno));
		return 1;
	}
	memset(&attr, 0, sizeof(attr));
	attr.link_detach.link_fd = link_fd;
	if (sys_bpf(BPF_LINK_DETACH, &attr) == 0)
		return 1;
	detach_errno = errno;
	memset(&attr, 0, sizeof(attr));
	attr.link_update.link_fd = link_fd;
	attr.link_update.new_prog_fd = 0x7fffffff;
	if (sys_bpf(BPF_LINK_UPDATE, &attr) == 0)
		return 1;
	update_errno = errno;
	close(link_fd);
	printf("detach_errno=%d update_errno=%d\\n", detach_errno, update_errno);
	return detach_errno == EACCES && update_errno == EACCES ? 0 : 1;
}
