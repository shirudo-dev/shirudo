/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_DM_VERITY_H
#define SHIRUDO_DM_VERITY_H

#include <limits.h>
#include <stdbool.h>
#include <sys/types.h>

#include "config_image.h"

struct shirudo_dm_verity {
	struct shirudo_config_image image;
	char name[128];
	char path[PATH_MAX];
	dev_t device;
	dev_t data_device;
	dev_t hash_device;
	int data_loop_fd;
	int hash_loop_fd;
};

typedef int (*shirudo_dm_verity_cb)(const char *name, dev_t device, void *ctx);

int shirudo_dm_verity_list(shirudo_dm_verity_cb callback, void *ctx);
int shirudo_dm_verity_create(const struct shirudo_config_image_open *image,
			     const char *name, struct shirudo_dm_verity *out);
/* Require the active readonly table to match the image parameters exactly. */
int shirudo_dm_verity_inspect(const char *name,
			      const struct shirudo_config_image *image,
			      struct shirudo_dm_verity *out);
/* Read every data block through the mapping bound to these retained files. */
int shirudo_dm_verity_verify(const struct shirudo_dm_verity *device,
			     const struct shirudo_config_image_open *image);
int shirudo_dm_verity_mount(const struct shirudo_dm_verity *device,
			    const char *mountpoint, bool executable);
int shirudo_dm_verity_remove(struct shirudo_dm_verity *device, bool deferred);
void shirudo_dm_verity_close(struct shirudo_dm_verity *device);

#endif /* SHIRUDO_DM_VERITY_H */
