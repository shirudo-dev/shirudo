// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Issues one bpf() command by name with an all-zero attr through the raw
 * syscall and prints the outcome ("ok" or "errno=<n>"). shirudo's lsm/bpf
 * hook answers before the kernel looks at the attr, so a command the
 * policy denies reports EACCES whatever the attr says, and one it allows
 * reports whatever the kernel makes of an empty attr. No libbpf.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <linux/bpf.h>

#include <shirudo/misc.h>

static const struct {
	const char	*name;
	int		cmd;
} cmds[] = {
	{ "MAP_CREATE",			BPF_MAP_CREATE },
	{ "MAP_LOOKUP_ELEM",		BPF_MAP_LOOKUP_ELEM },
	{ "MAP_UPDATE_ELEM",		BPF_MAP_UPDATE_ELEM },
	{ "MAP_DELETE_ELEM",		BPF_MAP_DELETE_ELEM },
	{ "MAP_GET_NEXT_KEY",		BPF_MAP_GET_NEXT_KEY },
	{ "OBJ_PIN",			BPF_OBJ_PIN },
	{ "OBJ_GET",			BPF_OBJ_GET },
	{ "PROG_ATTACH",		BPF_PROG_ATTACH },
	{ "PROG_DETACH",		BPF_PROG_DETACH },
	{ "PROG_TEST_RUN",		BPF_PROG_TEST_RUN },
	{ "MAP_GET_NEXT_ID",		BPF_MAP_GET_NEXT_ID },
	{ "MAP_GET_FD_BY_ID",		BPF_MAP_GET_FD_BY_ID },
	{ "LINK_GET_FD_BY_ID",		BPF_LINK_GET_FD_BY_ID },
	{ "RAW_TRACEPOINT_OPEN",	BPF_RAW_TRACEPOINT_OPEN },
	{ "BTF_LOAD",			BPF_BTF_LOAD },
	{ "MAP_LOOKUP_AND_DELETE_ELEM",	BPF_MAP_LOOKUP_AND_DELETE_ELEM },
	{ "MAP_FREEZE",			BPF_MAP_FREEZE },
	{ "MAP_UPDATE_BATCH",		BPF_MAP_UPDATE_BATCH },
	{ "MAP_DELETE_BATCH",		BPF_MAP_DELETE_BATCH },
	{ "LINK_CREATE",		BPF_LINK_CREATE },
	{ "LINK_UPDATE",		BPF_LINK_UPDATE },
	{ "ITER_CREATE",		BPF_ITER_CREATE },
	{ "LINK_DETACH",		BPF_LINK_DETACH },
	{ "PROG_BIND_MAP",		BPF_PROG_BIND_MAP },
	{ "TOKEN_CREATE",		BPF_TOKEN_CREATE },
};

int main(int argc, char **argv)
{
	union bpf_attr attr = {};
	size_t i;
	int cmd;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <BPF_CMD name without prefix>\n",
			argv[0]);
		return 2;
	}
	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
		if (strcmp(cmds[i].name, argv[1]) == 0)
			break;
	}
	if (i == ARRAY_SIZE(cmds)) {
		fprintf(stderr, "%s: unknown command %s\n", argv[0], argv[1]);
		return 2;
	}
	cmd = cmds[i].cmd;
	if (syscall(__NR_bpf, cmd, &attr, sizeof(attr)) >= 0) {
		printf("ok\n");
		return 0;
	}
	printf("errno=%d\n", errno);
	return 0;
}
