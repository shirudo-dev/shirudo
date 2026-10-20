/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_IMAGE_RUNTIME_H
#define SHIRUDO_IMAGE_RUNTIME_H

#include <shirudo/misc.h>

#include <stdint.h>

struct shirudo_config_update;
struct shirudo_trusted_set;

int shirudo_image_bootstrap_load(void);
const __u8 *shirudo_image_runtime_root(void);
int shirudo_image_runtime_mount(void);
int shirudo_image_boot_keys(struct shirudo_trusted_set *set);
int shirudo_image_boot_keys_close(void);
int shirudo_image_boot(void);
int shirudo_image_boot_complete(void);
int shirudo_image_enter(const char *command, int argc, const char **argv);
void shirudo_image_leave(void);
int shirudo_image_update(const char *prefix);
int shirudo_image_status(void);

#endif /* SHIRUDO_IMAGE_RUNTIME_H */
