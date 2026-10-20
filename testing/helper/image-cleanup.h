/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_TEST_IMAGE_CLEANUP_H
#define SHIRUDO_TEST_IMAGE_CLEANUP_H

#include <unistd.h>

#include "util/dm_verity.h"

int __wrap_shirudo_dm_verity_remove(struct shirudo_dm_verity *device,
				    bool deferred);
int __wrap_usleep(useconds_t usec);

#endif /* SHIRUDO_TEST_IMAGE_CLEANUP_H */
