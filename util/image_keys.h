/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_IMAGE_KEYS_H
#define SHIRUDO_IMAGE_KEYS_H

#include <shirudo/misc.h>

#include <stdbool.h>
#include <stddef.h>

struct shirudo_trusted_set;

int shirudo_keys_validate_image_set(const char *primary, int root_fd,
				    struct shirudo_trusted_set *set);
int shirudo_keys_check_image_set(const struct shirudo_trusted_set *set);
int shirudo_keys_validate_image(int root_fd);

int shirudo_keys_apply_image(int root_fd, bool boot);
int shirudo_keys_revoke_image(const __u8 *der, size_t size, bool boot);

#endif /* SHIRUDO_IMAGE_KEYS_H */
