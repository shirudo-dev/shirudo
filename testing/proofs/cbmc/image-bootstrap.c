// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bootstrap_parse() of util/image_bootstrap.c on every settings line of LEN
 * bytes, a read failure and whatever earlier lines set: what it accepts
 * holds a certificate under the runtime and a PCR measurements may use,
 * and only the initial read, the initrd's, sets the runtime image or its
 * root.
 */

#define PROOF_FILE	LEN
#define PROOF_MEMCPY_BYTEWISE
#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/io.c"
#include "../../../util/config_measure.c"
#include "../../../util/image_bootstrap.c"

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
	if (had_runtime)
		strscpy(boot.runtime, "/r", sizeof(boot.runtime));
	if (bootstrap_parse(f, &boot, initial))
		return;
	__CPROVER_assert(boot.n_certificates <= KEYS_MAX,
			 "bounded config verification certificate set");
	for (i = 0; i < boot.n_certificates; i++)
		__CPROVER_assert(!strncmp(boot.certificates[i],
					  RUNTIME_DIR "/", sizeof(RUNTIME_DIR)),
				 "a certificate under the runtime");
	__CPROVER_assert(!boot.have_pcr || !config_measure_pcr_valid(boot.pcr),
			 "a PCR measurements may use");
	if (!initial)
		__CPROVER_assert(boot.have_root == had_root &&
				 !boot.runtime[0] == !had_runtime,
				 "the runtime only from the initial read");
}
