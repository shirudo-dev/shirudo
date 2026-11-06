/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_IMAGE_GUARDS_H
#define SHIRUDO_IMAGE_GUARDS_H

#include <shirudo/misc.h>

#include <stdint.h>

#define SEAL_HOOK_COUNT 27
#define IMAGE_SEAL_HOOK_COUNT 2
#define MOUNT_HOOK_COUNT 5
#define OBSERVER_HOOK_COUNT 9
#define IMAGE_OBSERVER_HOOK_COUNT 4

struct image_guard {
	const char *prog;
	const char *pin;
};

enum gate_guard {
	GUARD_UNLINK,
	GUARD_SETXATTR,
	GUARD_REMOVEXATTR,
	GUARD_KEY_PERMISSION,
	GUARD_TPM_COMMAND,
	GUARD_BPF_MAP,
	GUARD_BPF_PROG,
	GUARD_PROG_LOAD,
	GUARD_BPF,
	GATE_HOOK_COUNT,
};

enum guard_map_index {
	GUARD_IDENTITY,
	GUARD_TASKS,
	GUARD_DEVICES,
	GUARD_ROOTS,
	GUARD_TAMPER,
	GUARD_POLICY,
	GUARD_SOCKET_POLICY,
	GUARD_MAP_COUNT,
};

struct guard_map {
	const char *name;
	const char *pin;
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 flags;
};

extern const struct image_guard
	shirudo_seal_guards[SEAL_HOOK_COUNT];
extern const struct image_guard
	shirudo_image_seal_guards[IMAGE_SEAL_HOOK_COUNT];
extern const struct image_guard
	shirudo_image_observer_guards[IMAGE_OBSERVER_HOOK_COUNT];
extern const struct image_guard
	shirudo_mount_guards[MOUNT_HOOK_COUNT];
extern const struct image_guard
	shirudo_observer_guards[OBSERVER_HOOK_COUNT];
extern const struct image_guard
	shirudo_gate_guards[GATE_HOOK_COUNT];
extern const struct guard_map
	shirudo_guard_maps[GUARD_MAP_COUNT];

struct config_root_guard {
	int map_fd;
	int task_fd;
};

int config_root_begin(const __u8 root[32],
		      struct config_root_guard *guard);
int config_root_end(struct config_root_guard *guard);
int image_guards_ready(void);

#endif /* SHIRUDO_IMAGE_GUARDS_H */
