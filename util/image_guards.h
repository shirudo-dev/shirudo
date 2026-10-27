/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_IMAGE_GUARDS_H
#define SHIRUDO_IMAGE_GUARDS_H

#include <shirudo/misc.h>

#include <stdint.h>

#define SHIRUDO_SEAL_HOOK_COUNT 20
#define SHIRUDO_IMAGE_SEAL_HOOK_COUNT 2
#define SHIRUDO_MOUNT_HOOK_COUNT 5
#define SHIRUDO_OBSERVER_HOOK_COUNT 9
#define SHIRUDO_IMAGE_OBSERVER_HOOK_COUNT 4

struct shirudo_image_guard {
	const char *prog;
	const char *pin;
};

enum shirudo_gate_guard {
	SHIRUDO_GUARD_UNLINK,
	SHIRUDO_GUARD_SETXATTR,
	SHIRUDO_GUARD_REMOVEXATTR,
	SHIRUDO_GUARD_KEY_PERMISSION,
	SHIRUDO_GUARD_TPM_COMMAND,
	SHIRUDO_GUARD_BPF_MAP,
	SHIRUDO_GUARD_PROG_LOAD,
	SHIRUDO_GUARD_BPF,
	SHIRUDO_GATE_HOOK_COUNT,
};

enum shirudo_guard_map_index {
	SHIRUDO_GUARD_IDENTITY,
	SHIRUDO_GUARD_TASKS,
	SHIRUDO_GUARD_DEVICES,
	SHIRUDO_GUARD_ROOTS,
	SHIRUDO_GUARD_TAMPER,
	SHIRUDO_GUARD_MAP_COUNT,
};

struct shirudo_guard_map {
	const char *name;
	const char *pin;
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 flags;
};

extern const struct shirudo_image_guard
	shirudo_seal_guards[SHIRUDO_SEAL_HOOK_COUNT];
extern const struct shirudo_image_guard
	shirudo_image_seal_guards[SHIRUDO_IMAGE_SEAL_HOOK_COUNT];
extern const struct shirudo_image_guard
	shirudo_image_observer_guards[SHIRUDO_IMAGE_OBSERVER_HOOK_COUNT];
extern const struct shirudo_image_guard
	shirudo_mount_guards[SHIRUDO_MOUNT_HOOK_COUNT];
extern const struct shirudo_image_guard
	shirudo_observer_guards[SHIRUDO_OBSERVER_HOOK_COUNT];
extern const struct shirudo_image_guard
	shirudo_gate_guards[SHIRUDO_GATE_HOOK_COUNT];
extern const struct shirudo_guard_map
	shirudo_guard_maps[SHIRUDO_GUARD_MAP_COUNT];

struct shirudo_config_root_guard {
	int map_fd;
	int task_fd;
};

int shirudo_config_root_begin(const __u8 root[32],
			      struct shirudo_config_root_guard *guard);
int shirudo_config_root_end(struct shirudo_config_root_guard *guard);
int shirudo_image_guards_ready(void);

#endif /* SHIRUDO_IMAGE_GUARDS_H */
