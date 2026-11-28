/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_IMAGE_RUNTIME_H
#define SHIRUDO_IMAGE_RUNTIME_H

#include <shirudo/misc.h>

#include <stdint.h>

struct config_update;
struct trusted_set;

struct config_update *image_update_context(void);
int image_bootstrap_load(void);
const __u8 *image_runtime_root(void);
int image_runtime_mount(void);
int image_boot_keys(struct trusted_set *set);
int image_boot_keys_close(void);
int image_boot(void);
int image_boot_complete(void);
int image_enter(const char *command, int argc, const char **argv);
void image_leave(void);
int image_update(const char *prefix);
int image_stage(const char *prefix);
int image_stage_cancel(void);
int image_status(bool json);

/*
 * The config state status reports: 0 with the selected config active,
 * -EINPROGRESS while an activation is pending, or the integrity error the
 * other commands refuse on; -ENODEV without activation state. root is the
 * selected or pending config's, zero when unknown.
 */
int image_config_state(__u8 root[32]);

__u32 shirudo_image_config_pcr(void);
__u32 shirudo_image_enforcement(void);

#endif /* SHIRUDO_IMAGE_RUNTIME_H */
