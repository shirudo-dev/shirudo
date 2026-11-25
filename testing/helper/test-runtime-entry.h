/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef TEST_RUNTIME_ENTRY_H
#define TEST_RUNTIME_ENTRY_H

#include <shirudo/misc.h>

int __wrap_bpf_map_lookup_elem(int fd, const void *key, void *value);
int __wrap_bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);
int __wrap_bpf_map_freeze(int fd);

#endif /* TEST_RUNTIME_ENTRY_H */
