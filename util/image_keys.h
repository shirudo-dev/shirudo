/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_IMAGE_KEYS_H
#define SHIRUDO_IMAGE_KEYS_H

#include <shirudo/misc.h>

#include <stdbool.h>
#include <stddef.h>

struct trusted_set;

int keys_validate_image_set(const char *primary, int root_fd,
			    struct trusted_set *set);
int keys_check_image_set(const struct trusted_set *set);
int keys_validate_image(int root_fd);

/*
 * For an image with revocation records, keys_revoke_check(): whether
 * applying them could purge every archive. 0 without a record.
 */
int keys_check_image_purge(int root_fd);
int keys_apply_image(int root_fd, bool boot);
int keys_revoke_image(const __u8 *der, size_t size, bool boot);
int keys_revoke_check(void);

#endif /* SHIRUDO_IMAGE_KEYS_H */
