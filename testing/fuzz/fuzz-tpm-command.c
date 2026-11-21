// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <stdbool.h>
#include <string.h>
#include "fuzz.h"

#define SHIRUDO_TPM_COPY(out, in, size) (memcpy(out, in, size), 0)
#include <shirudo/tpm_command.h>

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	enum shirudo_tpm_access access;

	if (size > 4096)
		return 0;
	access = shirudo_tpm_access(data, size, 13);
	if (access == SHIRUDO_TPM_MALFORMED &&
	    shirudo_tpm_allowed(access, true))
		__builtin_trap();
	return 0;
}
