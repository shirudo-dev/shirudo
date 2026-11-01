/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
#ifndef SHIRUDO_POLICY_MAP_H
#define SHIRUDO_POLICY_MAP_H

struct shirudo_task_policy {
	__u64	active;
	__u64	candidate;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct shirudo_task_policy);
} policy_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_CLONE);
	__type(key, int);
	__type(value, __u64);
} socket_policy_map SEC(".maps");

#endif
