/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */
#ifndef SHIRUDO_TEST_TPM_SESSION_H
#define SHIRUDO_TEST_TPM_SESSION_H

#include "identity.h"

extern int enforcing;

int __wrap_enforcement_active(void);
int __wrap_identity_read(struct identity *out);

#endif
