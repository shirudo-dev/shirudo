// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts, .flags = XDP_FLAGS_DRV_MODE);
	__u32 ifindex, id = 0, after = 0;
	int fd, ret;

	if (argc != 3)
		return 2;
	ifindex = if_nametoindex(argv[2]);
	if (!ifindex)
		return 2;
	ret = bpf_xdp_query_id((int)ifindex, XDP_FLAGS_DRV_MODE, &id);
	if (ret)
		return 2;
	if (!strcmp(argv[1], "query")) {
		printf("%u\n", id);
		return 0;
	}
	if (strcmp(argv[1], "denied") || !id)
		return 2;
	fd = bpf_prog_get_fd_by_id(id);
	if (fd >= 0) {
		close(fd);
		fprintf(stderr, "XDP program descriptor acquisition was allowed\n");
		return 1;
	}
	if (errno != EACCES ||
	    bpf_link_create(-1, (int)ifindex, BPF_XDP, &opts) != -EACCES ||
	    bpf_link_detach(-1) != -EACCES ||
	    bpf_xdp_detach((int)ifindex, XDP_FLAGS_DRV_MODE, NULL) != -EBUSY)
		return 1;
	if (bpf_xdp_query_id((int)ifindex, XDP_FLAGS_DRV_MODE, &after))
		return 1;
	return id == after ? 0 : 1;
}
