/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_TEST_IMAGE_CACHE_H
#define SHIRUDO_TEST_IMAGE_CACHE_H

#include <stddef.h>

int __wrap_fsetxattr(int fd, const char *name, const void *value, size_t size,
		     int flags);
int __wrap_seal_label(const char *path);

#endif /* SHIRUDO_TEST_IMAGE_CACHE_H */
