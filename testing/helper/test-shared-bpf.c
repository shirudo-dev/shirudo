// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What a root task without runtime authority can do with bpf() in shared
 * enforcement, through the raw syscall; each command prints "ok", "fd" or
 * "errno=<n>". "own <pin>" creates, writes and pins a map and loads a
 * socket filter, both named shirudo_probe; "load lsm|fmodret|fentry"
 * loads such a program; "pin <path>" pins a new map there; "kernel-get
 * own|<map-id>" has a syscall program open a map by id from inside the
 * kernel; "objects" prints "map|prog <id> <name|errno=<n>>" for every id.
 * No libbpf.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <linux/bpf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

/* shirudo's own objects are told apart by record, never by name. */
#define OWN_NAME "shirudo_probe"

static int sys_bpf(int cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int fail(const char *step)
{
	printf("%s errno=%d\n", step, errno);
	return 1;
}

static int report(int fd)
{
	if (fd < 0) {
		printf("errno=%d\n", errno);
		return 1;
	}
	printf("ok\n");
	return 0;
}

static const struct bpf_insn return_zero[] = {
	{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0 },
	{ .code = BPF_JMP | BPF_EXIT },
};

/* bpf_sys_bpf(BPF_MAP_GET_FD_BY_ID) for the map id at the start of ctx. */
static const struct bpf_insn get_fd_by_id[] = {
	{ .code = BPF_ALU64 | BPF_MOV | BPF_X, .dst_reg = BPF_REG_6,
	  .src_reg = BPF_REG_1 },
	{ .code = BPF_ST | BPF_MEM | BPF_DW, .dst_reg = BPF_REG_10,
	  .off = -16 },
	{ .code = BPF_ST | BPF_MEM | BPF_DW, .dst_reg = BPF_REG_10,
	  .off = -8 },
	{ .code = BPF_LDX | BPF_MEM | BPF_W, .dst_reg = BPF_REG_7,
	  .src_reg = BPF_REG_6 },
	{ .code = BPF_STX | BPF_MEM | BPF_W, .dst_reg = BPF_REG_10,
	  .src_reg = BPF_REG_7, .off = -16 },
	{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_1,
	  .imm = BPF_MAP_GET_FD_BY_ID },
	{ .code = BPF_ALU64 | BPF_MOV | BPF_X, .dst_reg = BPF_REG_2,
	  .src_reg = BPF_REG_10 },
	{ .code = BPF_ALU64 | BPF_ADD | BPF_K, .dst_reg = BPF_REG_2,
	  .imm = -16 },
	{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_3,
	  .imm = 16 },
	{ .code = BPF_JMP | BPF_CALL, .imm = BPF_FUNC_sys_bpf },
	{ .code = BPF_JMP | BPF_EXIT },
};

static int load_insns(__u32 type, __u32 attach_type, __u32 btf_id,
		      __u32 flags, const struct bpf_insn *insns, __u32 count)
{
	union bpf_attr attr = {};

	attr.prog_type = type;
	attr.expected_attach_type = attach_type;
	attr.attach_btf_id = btf_id;
	attr.prog_flags = flags;
	attr.insns = ptr_to_u64(insns);
	attr.insn_cnt = count;
	attr.license = ptr_to_u64("GPL");
	strscpy_literal(attr.prog_name, OWN_NAME);
	return sys_bpf(BPF_PROG_LOAD, &attr);
}

static int load(__u32 type, __u32 attach_type, __u32 btf_id)
{
	return load_insns(type, attach_type, btf_id, 0, return_zero,
			  ARRAY_SIZE(return_zero));
}

static int map_create(void)
{
	union bpf_attr attr = {};

	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof(__u32);
	attr.value_size = sizeof(__u64);
	attr.max_entries = 1;
	strscpy_literal(attr.map_name, OWN_NAME);
	return sys_bpf(BPF_MAP_CREATE, &attr);
}

static int pin(int fd, const char *path)
{
	union bpf_attr attr = {};

	attr.pathname = ptr_to_u64(path);
	attr.bpf_fd = fd;
	return sys_bpf(BPF_OBJ_PIN, &attr);
}

static int own(const char *path)
{
	union bpf_attr attr = {};
	__u64 value = 7;
	__u32 key = 0;
	int map, got;

	map = map_create();
	if (map < 0)
		return fail("map_create");
	attr.map_fd = map;
	attr.key = ptr_to_u64(&key);
	attr.value = ptr_to_u64(&value);
	if (sys_bpf(BPF_MAP_UPDATE_ELEM, &attr))
		return fail("map_update");
	if (load(BPF_PROG_TYPE_SOCKET_FILTER, 0, 0) < 0)
		return fail("prog_load");
	if (pin(map, path))
		return fail("obj_pin");
	memset(&attr, 0, sizeof(attr));
	attr.pathname = ptr_to_u64(path);
	got = sys_bpf(BPF_OBJ_GET, &attr);
	unlink(path);
	if (got < 0)
		return fail("obj_get");
	printf("ok\n");
	return 0;
}

/* shirudo refuses the type before the verifier resolves the bogus id. */
static int load_kind(const char *kind)
{
	if (!strcmp(kind, "lsm"))
		return report(load(BPF_PROG_TYPE_LSM, BPF_LSM_MAC, 1));
	if (!strcmp(kind, "fmodret"))
		return report(load(BPF_PROG_TYPE_TRACING, BPF_MODIFY_RETURN, 1));
	if (!strcmp(kind, "fentry"))
		return report(load(BPF_PROG_TYPE_TRACING, BPF_TRACE_FENTRY, 1));
	return 2;
}

static int pin_new(const char *path)
{
	int map = map_create();

	if (map < 0)
		return fail("map_create");
	if (pin(map, path))
		return report(-1);
	unlink(path);
	return report(0);
}

static int map_id(int fd, __u32 *id)
{
	struct bpf_map_info info = {};
	union bpf_attr attr = {};

	attr.info.bpf_fd = fd;
	attr.info.info_len = sizeof(info);
	attr.info.info = ptr_to_u64(&info);
	if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr))
		return -1;
	*id = info.id;
	return 0;
}

static int target_id(const char *which, __u32 *id)
{
	__u64 given;
	int map;

	if (strcmp(which, "own")) {
		if (parse_u64(which, strlen(which), ~0U, &given))
			return -1;
		*id = given;
		return 0;
	}
	map = map_create();
	if (map < 0)
		return -1;
	return map_id(map, id);
}

static int kernel_get(const char *which)
{
	union bpf_attr attr = {};
	__u32 id;
	__s32 ret;
	int prog;

	if (target_id(which, &id))
		return fail("target_id");
	prog = load_insns(BPF_PROG_TYPE_SYSCALL, 0, 0, BPF_F_SLEEPABLE,
			  get_fd_by_id, ARRAY_SIZE(get_fd_by_id));
	if (prog < 0)
		return fail("syscall_load");
	attr.test.prog_fd = prog;
	attr.test.ctx_in = ptr_to_u64(&id);
	attr.test.ctx_size_in = sizeof(id);
	if (sys_bpf(BPF_PROG_TEST_RUN, &attr))
		return fail("test_run");
	ret = (__s32)attr.test.retval;
	if (ret < 0) {
		printf("errno=%d\n", -ret);
		return 1;
	}
	printf("fd\n");
	return 0;
}

static void object_name(int fd, bool is_map, char name[BPF_OBJ_NAME_LEN])
{
	struct bpf_prog_info prog = {};
	struct bpf_map_info map = {};
	union bpf_attr attr = {};

	attr.info.bpf_fd = fd;
	attr.info.info_len = is_map ? sizeof(map) : sizeof(prog);
	attr.info.info = is_map ? ptr_to_u64(&map) : ptr_to_u64(&prog);
	name[0] = 0;
	if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr))
		return;
	memcpy(name, is_map ? map.name : prog.name, BPF_OBJ_NAME_LEN);
	name[BPF_OBJ_NAME_LEN - 1] = 0;
}

static void walk(bool is_map)
{
	const char *kind = is_map ? "map" : "prog";
	char name[BPF_OBJ_NAME_LEN];
	union bpf_attr attr = {};
	__u32 id = 0;
	int fd;

	for (;;) {
		memset(&attr, 0, sizeof(attr));
		attr.start_id = id;
		if (sys_bpf(is_map ? BPF_MAP_GET_NEXT_ID : BPF_PROG_GET_NEXT_ID,
			    &attr))
			return;
		id = attr.next_id;
		memset(&attr, 0, sizeof(attr));
		if (is_map)
			attr.map_id = id;
		else
			attr.prog_id = id;
		fd = sys_bpf(is_map ? BPF_MAP_GET_FD_BY_ID :
				      BPF_PROG_GET_FD_BY_ID, &attr);
		if (fd < 0) {
			printf("%s %u errno=%d\n", kind, id, errno);
			continue;
		}
		object_name(fd, is_map, name);
		printf("%s %u %s\n", kind, id, name[0] ? name : "-");
		close(fd);
	}
}

int main(int argc, char **argv)
{
	if (argc == 3 && !strcmp(argv[1], "own"))
		return own(argv[2]);
	if (argc == 3 && !strcmp(argv[1], "load"))
		return load_kind(argv[2]);
	if (argc == 3 && !strcmp(argv[1], "pin"))
		return pin_new(argv[2]);
	if (argc == 3 && !strcmp(argv[1], "kernel-get"))
		return kernel_get(argv[2]);
	if (argc == 2 && !strcmp(argv[1], "objects")) {
		walk(true);
		walk(false);
		return 0;
	}
	fprintf(stderr,
		"usage: %s own <pin> | load lsm|fmodret|fentry | pin <path> | kernel-get own|<map-id> | objects\n",
		argv[0]);
	return 2;
}
