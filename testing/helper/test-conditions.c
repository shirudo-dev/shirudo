// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

/*
 * Drives util/conditions.c for t6004 with the input `shirudo status`
 * derives from what it reads off the host.
 *
 *   test-conditions <lsm 0|1> <bpf|none> <serial> <pinned> \
 *                   <notpm|none|match|mismatch>
 *
 * serial is the live keyring's, -1 when it is absent; pinned the one init
 * froze, 0 when it froze none; the last word the register's replay, with
 * notpm for no TPM answering and none for no register bound. The
 * dm-verity keyring follows the bpf one at serial 200 unless
 * SHIRUDO_TEST_DMV_SERIAL and SHIRUDO_TEST_DMV_PINNED say otherwise;
 * SHIRUDO_TEST_BPF_UNFROZEN and SHIRUDO_TEST_DMV_UNFROZEN count links
 * init did not freeze, and SHIRUDO_TEST_DMV_KEY=missing drops the config
 * key.
 */

#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shirudo/string.h>

#include "util/conditions.h"

static int arg_s64(const char *s, __s64 *out)
{
	return parse_s64(s, strlen(s), -1, INT32_MAX, out);
}

static __s64 env_s64(const char *name, __s64 def)
{
	const char *s = getenv(name);
	__s64 v;

	if (!s || arg_s64(s, &v))
		return def;
	return v;
}

int main(int argc, char **argv)
{
	struct condition conds[CONDITIONS_MAX];
	struct conditions_input in = {};
	__s64 lsm, serial, pinned;
	const char *mode, *config, *pins;
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
	in.ksp_seen = pinned >= 1;
	in.ksm_seen = in.keyring_present && pinned >= 1;
	in.keyring_serial_matches = in.ksm_seen && serial == pinned;
	in.bpf_unfrozen = (int)env_s64("SHIRUDO_TEST_BPF_UNFROZEN", 0);
	in.dmv_serial = env_s64("SHIRUDO_TEST_DMV_SERIAL",
				serial >= 0 ? 200 : -1);
	in.dmv_serial_pinned = env_s64("SHIRUDO_TEST_DMV_PINNED",
				       pinned >= 1 ? 200 : 0);
	in.dmv_present = in.dmv_serial >= 0;
	in.dmvp_seen = in.dmv_serial_pinned >= 1;
	in.dmvm_seen = in.dmv_present && in.dmvp_seen;
	in.dmv_serial_matches = in.dmvm_seen &&
				in.dmv_serial == in.dmv_serial_pinned;
	in.dmv_unfrozen = (int)env_s64("SHIRUDO_TEST_DMV_UNFROZEN", 0);
	config = getenv("SHIRUDO_TEST_DMV_KEY");
	in.dmv_key_missing = config && !strcmp(config, "missing");
	in.tpm_reachable = strcmp(argv[5], "notpm") != 0;
	in.chain_seen = in.tpm_reachable && strcmp(argv[5], "none") != 0;
	in.cm_seen = in.chain_seen;
	in.chain_matches = !strcmp(argv[5], "match");
	in.nv_index = "0x01818E00";
	config = getenv("SHIRUDO_TEST_CONFIG_STATE");
	in.config_seen = !config || strcmp(config, "none");
	in.config_state = !config ? 0 :
			  !strcmp(config, "pending") ? -EINPROGRESS :
			  !strcmp(config, "untrusted") ? -EUCLEAN :
			  !strcmp(config, "stale") ? -ESTALE : 0;
	in.config_root = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
	pins = getenv("SHIRUDO_TEST_PINS");
	if (pins && !strcmp(pins, "norecord")) {
		in.pins_rc = -ENOENT;
	} else if (pins && !strcmp(pins, "error")) {
		in.pins_rc = -EACCES;
	} else if (pins && str_skip_prefix(&pins, "unmeasured:")) {
		in.pins_detail = pins;
		in.pins_unmeasured = 1;
		for (pins = in.pins_detail; *pins; pins++)
			in.pins_unmeasured += *pins == ',';
	}

	printf("status=%s\n", status_verdict(&in));
	printf("reason=%s\n", status_reason(&in));
	n = conditions(&in, conds, ARRAY_SIZE(conds));
	for (i = 0; i < n; i++)
		printf("%s %s %s\n", conds[i].type, conds[i].status,
		       conds[i].detail);
	return 0;
}
