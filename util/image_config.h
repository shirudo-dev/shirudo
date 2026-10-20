/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_IMAGE_CONFIG_H
#define SHIRUDO_IMAGE_CONFIG_H

#include <shirudo/misc.h>

#include <stdbool.h>

struct shirudo_config;

enum shirudo_image_path {
	SHIRUDO_IMAGE_ETC,
	SHIRUDO_IMAGE_REGISTRIES,
	SHIRUDO_IMAGE_REPOSITORY_KEYS,
	SHIRUDO_IMAGE_TREE_CONF,
	SHIRUDO_IMAGE_NODE_LABELS,
	SHIRUDO_IMAGE_TRUSTED_KEYS,
	SHIRUDO_IMAGE_REVOKED_KEYS,
	SHIRUDO_IMAGE_PATH_COUNT,
};

bool shirudo_image_config_active(void);
int shirudo_image_config_get(struct shirudo_config *out);
int shirudo_image_config_set(const struct shirudo_config *bootstrap,
			     int root_fd);
int shirudo_image_config_validate(int root_fd);
void shirudo_image_config_clear(void);
const char *shirudo_image_path(enum shirudo_image_path which);
int shirudo_image_path_relative(char *out, __u64 cap, const char *path);
int shirudo_image_config_root_fd(void);

#endif /* SHIRUDO_IMAGE_CONFIG_H */
