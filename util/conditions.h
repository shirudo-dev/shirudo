/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Shared local security-health conditions block. `shirudo status`
 * feeds the flat input shape and receives the verdict and human output.
 */

#ifndef SHIRUDO_CONDITIONS_H
#define SHIRUDO_CONDITIONS_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/misc.h>

/*
 * The *_seen flags say whether the JSON carried a non-null value,
 * since the parser leaves a null untouched.
 */
struct shirudo_conditions_input {
	bool		reachable;
	bool		parsed;
	const char	*unreach;	/* optional reason on !reachable */

	int		lsm_attached;	/* 0/1 */
	int		keyring_present;
	const char	*keyring_mode;	/* "bpf" or "none" */
	__s64		keyring_serial;
	__s64		keyring_serial_pinned;
	int		keyring_serial_matches;	/* 0/1 if ksm_seen */
	int		ks_seen, ksp_seen, ksm_seen;
	int		tpm_reachable;
	int		chain_seen;
	int		chain_matches;		/* 0/1 if cm_seen */
	int		cm_seen;
	const char	*nv_index;
};

struct shirudo_condition {
	const char	*type;		/* "LsmAttached" / "KeyringSealed" / ... */
	const char	*status;	/* "OK" / "WARN" / "ALERT" */
	char		detail[192];
};

/*
 * Maximum number of conditions returned today (LsmAttached,
 * KeyringSealed, ChainIntact, TpmMeasured); callers can size their
 * stack array off this.
 */
#define SHIRUDO_CONDITIONS_MAX	4

size_t conditions(const struct shirudo_conditions_input *in,
		  struct shirudo_condition *out, size_t cap);

void conditions_print(const struct shirudo_condition *c, size_t n);

/*
 * Single-word aggregate verdict (severity worst -> best):
 *   unreachable -> unparseable -> tampered -> lsm-off ->
 *   init-pending -> degraded -> ok
 * Used by the `Status:` line in `shirudo status` and its JSON output.
 */
const char *status_verdict(const struct shirudo_conditions_input *in);

void status_reason(const struct shirudo_conditions_input *in,
		   char *buf, size_t cap);

#endif /* SHIRUDO_CONDITIONS_H */
