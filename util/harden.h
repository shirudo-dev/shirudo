/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Process-hardening primitives applied at startup.
 */

#ifndef SHIRUDO_HARDEN_H
#define SHIRUDO_HARDEN_H

#include <stddef.h>

void harden_stdio(void);
int harden_self(void);

#endif /* SHIRUDO_HARDEN_H */
