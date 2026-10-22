// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

/*
 * Drives util/conditions.c for t0050 with the input `shirudo status`
 * derives from what it reads off the host.
 *
 *   test-conditions <lsm 0|1> <bpf|none> <serial> <pinned> \
 *                   <notpm|none|match|mismatch>
 *
 * serial is the live keyring's, -1 when it is absent; pinned the one init
 * froze, 0 when it froze none; the last word the register's replay, with
 * notpm for no TPM answering and none for no register bound.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <shirudo/string.h>

#include "util/conditions.h"
#include "util/macros.h"

static int arg_s64(const char *s, __s64 *out)
{
	return parse_s64(s, strlen(s), -1, INT32_MAX, out);
}

int main(int argc, char **argv)
{
	struct shirudo_condition conds[SHIRUDO_CONDITIONS_MAX];
	struct shirudo_conditions_input in = {};
	__s64 lsm, serial, pinned;
	char reason[160];
	const char *mode;
	size_t n, i;

	if (argc != 6 || arg_s64(argv[1], &lsm) || arg_s64(argv[3], &serial) ||
	    arg_s64(argv[4], &pinned)) {
		fprintf(stderr, "usage: test-conditions <lsm> <mode> <serial> "
			"<pinned> <notpm|none|match|mismatch>\n");
		return 2;
	}
	mode = argv[2];

	in.reachable = true;
	in.parsed = true;
	in.lsm_attached = lsm != 0;
	in.keyring_present = serial >= 0;
	in.keyring_mode = mode;
	in.keyring_serial = serial;
	in.keyring_serial_pinned = pinned;
	in.ks_seen = in.keyring_present;
	in.ksp_seen = pinned >= 1;
	in.ksm_seen = in.keyring_present && pinned >= 1;
	in.keyring_serial_matches = in.ksm_seen && serial == pinned;
	in.tpm_reachable = strcmp(argv[5], "notpm") != 0;
	in.chain_seen = in.tpm_reachable && strcmp(argv[5], "none") != 0;
	in.cm_seen = in.chain_seen;
	in.chain_matches = !strcmp(argv[5], "match");
	in.nv_index = "0x01818E00";

	status_reason(&in, reason, sizeof(reason));
	printf("status=%s\n", status_verdict(&in));
	printf("reason=%s\n", reason);
	n = conditions(&in, conds, ARRAY_SIZE(conds));
	for (i = 0; i < n; i++)
		printf("%s %s %s\n", conds[i].type, conds[i].status,
		       conds[i].detail);
	return 0;
}
