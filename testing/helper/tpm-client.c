// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include "tpm-session.h"

int enforcing;

/* Untrusted clients use the default; session tests select guarded states. */
int __wrap_enforcement_active(void)
{
	return enforcing;
}
