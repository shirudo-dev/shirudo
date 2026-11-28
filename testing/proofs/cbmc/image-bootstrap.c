// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bootstrap_parse() on every settings line of LEN bytes, a read failure,
 * and an initially empty state with the root flag and runtime presence
 * varied. These short lines cannot select a complete setting.
 */

#define PROOF_FILE	LEN
#define PROOF_MEMCPY_BYTEWISE
#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/io.c"
#include "../../../util/config_measure.c"

/* No recognized path setting fits in the short input. */
static ssize_t short_line_copy(char *dst, const char *src, size_t size)
{
	__CPROVER_assert(false, "a short line cannot reach a path copy");
	return -E2BIG;
}

#define strscpy short_line_copy
#include "../../../util/image_bootstrap.c"
#undef strscpy

static struct image_bootstrap boot;

void harness(void)
{
	bool initial, had_root, had_runtime;
	size_t i;
	FILE *f;

	proof_file_open();
	for (i = 0; i + 1 < LEN; i++)
		__CPROVER_assume(proof_file[i] != '\n');
	f = fopen("bootstrap", "r");
	__CPROVER_assume(f);
	boot.have_root = had_root;
	if (had_runtime) {
		boot.runtime[0] = '/';
		boot.runtime[1] = 'r';
	}
	if (bootstrap_parse(f, &boot, initial))
		return;
	__CPROVER_assert(boot.n_certificates == 0,
			 "a short line cannot add a certificate");
	__CPROVER_assert(!boot.have_pcr,
			 "a short line cannot set a PCR");
	__CPROVER_assert(boot.enforcement == ENFORCEMENT_STRICT,
			 "a short line cannot loosen enforcement");
	__CPROVER_assert(boot.have_root == had_root &&
			 !boot.runtime[0] == !had_runtime,
			 "a short line cannot change the runtime");
}
