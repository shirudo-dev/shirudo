/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_RUNTIME_ENTRY_H
#define SHIRUDO_RUNTIME_ENTRY_H

#include <stdbool.h>
#include <sys/types.h>
#include <shirudo/misc.h>
#include <shirudo/runtime_entry.h>

struct dm_verity;

int shirudo_runtime_worker_open(int root, dev_t device, __u64 diskseq,
				struct shirudo_runtime_entry *entry);
int shirudo_runtime_entry_install(int map,
				  const struct shirudo_runtime_entry *entry);
int shirudo_runtime_entry_bind(const char *mountpoint,
			       const struct dm_verity *device);
int shirudo_runtime_entry_check(const char *mountpoint);

#endif /* SHIRUDO_RUNTIME_ENTRY_H */
