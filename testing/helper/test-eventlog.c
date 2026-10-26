// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Drives the eventlog's pending record, with the log and the pending
 * file redirected by SHIRUDO_EVENTLOG_PATH and
 * SHIRUDO_EVENTLOG_PENDING_PATH. Subcommand on argv[1]; prints what a
 * shell test asserts on.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <shirudo/misc.h>

#include "chain.h"
#include "eventlog.h"
#include "hex.h"
#include "json.h"
#include "paths.h"

/* An init record of this boot with fixed values, bound where told. */
static int append_init(const char *path, const char *bound_in,
		       __u32 reset_count)
{
	char writer_hex[2 * SHIRUDO_TPM_NV_RSA_BYTES + 1];
	__u8 modulus[SHIRUDO_TPM_NV_RSA_BYTES] = { [0] = 0x80, [383] = 1 };
	char buf[4096], ts[32], boot_id[64], nv_index[16], hex[65];
	struct shirudo_json_emit e = { .buf = buf, .cap = sizeof(buf) };
	char name_hex[2 * SHIRUDO_TPM_NAME_LEN + 1];
	__u8 zero[SHIRUDO_TPM_NAME_LEN] = {};

	eventlog_timestamp(ts, sizeof(ts));
	eventlog_boot_id(boot_id, sizeof(boot_id));
	snprintf(nv_index, sizeof(nv_index), "0x%08X", SHIRUDO_NV_INDEX);
	hex_encode(zero, 32, hex);
	hex_encode(zero, SHIRUDO_TPM_NAME_LEN, name_hex);
	hex_encode(modulus, sizeof(modulus), writer_hex);
	json_obj_open(&e);
	json_kv_int(&e, "schema", 2);
	json_kv_string(&e, "ts", ts);
	json_kv_string(&e, "nv_index", nv_index);
	json_kv_string(&e, "alg", "sha256");
	json_kv_string(&e, "digest", hex);
	json_kv_string(&e, "type", "init");
	json_kv_string(&e, "boot_id", boot_id);
	json_kv_int(&e, "tpm_reset_count", reset_count);
	json_kv_int(&e, "pcr", SHIRUDO_CHAIN_PCR);
	json_kv_string(&e, "pcr_before", hex);
	json_kv_int(&e, "phase_pcr", SHIRUDO_CHAIN_PHASE_PCR);
	json_kv_string(&e, "phase_before", hex);
	json_kv_string(&e, "bound_in", bound_in);
	json_kv_string(&e, "nv_name", name_hex);
	json_kv_string(&e, "nv_writer_public", writer_hex);
	json_kv_string(&e, "anchor", "shirudo-anchor:test");
	json_kv_string(&e, "anchor_digest", hex);
	json_kv_string(&e, "chain", hex);
	json_obj_close(&e);
	if (e.err)
		return e.err;
	return eventlog_append_to(path, buf);
}

static int count_lines(const char *line, size_t len, void *ctx)
{
	__u32 *n = ctx;

	(void)line;
	(void)len;
	(*n)++;
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s init log|pending <bound_in> "
			"[reset] | boot-init | lines | adopt\n", argv[0]);
		return 2;
	}
	if (strcmp(argv[1], "init") == 0 && (argc == 4 || argc == 5)) {
		const char *path = strcmp(argv[2], "pending") == 0 ?
				   eventlog_pending_path() :
				   eventlog_path();
		__u32 reset = 1;
		int rc;

		if (argc == 5)
			reset = (__u32)strtoul(argv[4], NULL, 10);
		rc = append_init(path, argv[3], reset);

		printf("rc=%d\n", rc);
		return rc ? 1 : 0;
	}
	if (strcmp(argv[1], "boot-init") == 0) {
		struct shirudo_eventlog_init rec;
		int rc = eventlog_boot_init(&rec);

		printf("rc=%d\n", rc);
		if (rc)
			return 1;
		printf("bound_in=%s\nrecords=%u\nreset_count=%u\n",
		       rec.initrd ? "initrd" : "root", rec.records,
		       rec.reset_count);
		return 0;
	}
	if (strcmp(argv[1], "lines") == 0) {
		__u32 n = 0;
		int rc = eventlog_boot_lines(count_lines, &n);

		printf("rc=%d\nlines=%u\n", rc, n);
		return rc ? 1 : 0;
	}
	if (strcmp(argv[1], "adopt") == 0) {
		int rc = eventlog_adopt_pending();

		printf("rc=%d\npending=%s\n", rc,
		       access(eventlog_pending_path(), F_OK) == 0 ?
		       "present" : "absent");
		return rc ? 1 : 0;
	}
	fprintf(stderr, "unknown subcommand\n");
	return 2;
}
