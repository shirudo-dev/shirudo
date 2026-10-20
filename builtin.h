/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Subcommand entry points dispatched from shirudo.c.
 */

#ifndef SHIRUDO_BUILTIN_H
#define SHIRUDO_BUILTIN_H

#include <stdbool.h>

/* Operator-side. */
int cmd_genkey(int argc, const char **argv);
int cmd_build(int argc, const char **argv);

/*
 * The operator package's helper: whether it is there, and the one exec
 * site, which returns only on failure.
 */
bool shirudo_build_available(void);
int shirudo_build_exec(const char *label, char **argv);

/* Target-side. */
int cmd_init(int argc, const char **argv);
int cmd_upatch(int argc, const char **argv);
int cmd_bpm(int argc, const char **argv);

int shirudo_upatch_apply(const char *path);
int shirudo_upatch_install(const char *path);
int shirudo_upatch_remove(const char *path);

/*
 * Detach, unpin and unarchive without a directive, because the key
 * that signed the upatch was revoked: 1 when the unload was measured,
 * 0 when only the archive went, -errno otherwise.
 */
int shirudo_upatch_purge(const char *name, const char *reason);

/*
 * Internal lifecycle result: the signed payload was valid, but its kprobe
 * target is unavailable because the backing module is not loaded.
 */
#define SHIRUDO_UPATCH_INSTALL_TARGET_MISSING 2

/* Either-side. */
int cmd_status(int argc, const char **argv);
int cmd_attest(int argc, const char **argv);
int cmd_version(int argc, const char **argv);
int cmd_keys(int argc, const char **argv);
int cmd_config(int argc, const char **argv);
int cmd_image(int argc, const char **argv);

#endif /* SHIRUDO_BUILTIN_H */
