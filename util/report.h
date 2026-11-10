/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The JSON report of `upatch load` and `unload --report`: category and
 * phase tell a policy problem from a code problem, and the verifier
 * log comes verbatim.
 */

#ifndef SHIRUDO_REPORT_H
#define SHIRUDO_REPORT_H

#include <stdbool.h>

/* Keep enough room for verbose accepted-program verifier traces. */
#define VERIFIER_LOG_MAX	(16 * 1024 * 1024)

/*
 * Phase strings (failure-report ordering):
 *   pre_flight, parse, signed_loader_load, payload_load, link_create,
 *   pin, persist, tpm_extend, done
 * Category strings: ok, tampered, keyring_missing, lsm_denied,
 *   signature_rejected, verifier_rejected, parser_rejected,
 *   payload_mismatch, already_loaded, already_unloaded, detach_failed,
 *   tpm_error, not_initialized, xdp_multibuf_unsupported,
 *   xdp_driver_refused, unknown.
 */
struct op_report {
	bool		ok;
	const char	*op;		/* "upatch_load" / "upatch_unload" */
	const char	*phase;
	int		err;		/* errno (>0); 0 = none */
	const char	*category;
	char		message[256];
	char		*verifier_log;	/* heap, owned by the report; may be NULL */
	int		loader_return;
	const char	*path;
	const char	*name;
	char		payload_hex[65];
	bool		tpm_present;
	char		chain_after[65];
};

int report_emit(const char *path, const struct op_report *r);

void report_set_log(struct op_report *r, const char *log);
void report_free(struct op_report *r);

#endif /* SHIRUDO_REPORT_H */
