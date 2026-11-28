/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Subcommand entry points dispatched from shirudo.c.
 */

#ifndef SHIRUDO_BUILTIN_H
#define SHIRUDO_BUILTIN_H

#include <stdbool.h>

/*
 * The status of a command that caught SIGINT and cleaned up. main() then
 * ends the process by the signal: a shell stops a script for a command
 * that SIGINT ended, and goes on after one that exited.
 */
#define EXIT_INTERRUPTED	130

/* Operator-side. */
int cmd_genkey(int argc, const char **argv);
int cmd_build(int argc, const char **argv);

/*
 * The operator package's helper: whether it is there, and the one exec
 * site, which returns only on failure.
 */
bool build_available(void);
int build_exec(const char *label, const char **argv);
/*
 * Run shirudo-build with words, up to their NULL, and then the argc
 * arguments at argv: the operator half of a command shirudo dispatches.
 */
int build_forward(const char *label, const char *const words[], int argc,
		  const char **argv);

/* Target-side. */
int cmd_init(int argc, const char **argv);
int cmd_upatch(int argc, const char **argv);
int cmd_bpm(int argc, const char **argv);

/* Either-side. */
int cmd_status(int argc, const char **argv);
int cmd_attest(int argc, const char **argv);
int cmd_version(int argc, const char **argv);
int cmd_keys(int argc, const char **argv);
int cmd_config(int argc, const char **argv);
int cmd_image(int argc, const char **argv);

#endif /* SHIRUDO_BUILTIN_H */
