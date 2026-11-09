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
struct conditions_input {
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
	int		bpf_unfrozen;	/* links init did not freeze */
	int		dmv_present;	/* the .dm-verity keyring exists */
	__s64		dmv_serial;
	__s64		dmv_serial_pinned;
	int		dmv_serial_matches;	/* 0/1 if dmvm_seen */
	int		dmvp_seen, dmvm_seen;
	int		dmv_unfrozen;
	int		dmv_key_missing;	/* a config key init froze is gone */
	int		tpm_reachable;
	int		chain_seen;
	int		chain_matches;		/* 0/1 if cm_seen */
	int		cm_seen;
	const char	*nv_index;
	int		config_seen;
	int		config_state;	/* image_config_state() */
	const char	*config_root;	/* hex, when config_seen */
	int		pins_rc;	/* 0 when the pins were checked, else -errno */
	int		pins_unmeasured;	/* pinned or archived without a record this boot */
	const char	*pins_detail;	/* their names, when any */
};

struct condition {
	const char	*type;		/* "LsmAttached" / "KeyringSealed" / ... */
	const char	*status;	/* "OK" / "WARN" / "ALERT" */
	char		detail[192];
};

/*
 * Maximum number of conditions returned today (LsmAttached,
 * KeyringSealed, ChainIntact, UpatchesMeasured, TpmMeasured,
 * ConfigActive); callers can size their stack array off this.
 */
#define CONDITIONS_MAX	6

size_t conditions(const struct conditions_input *in,
		  struct condition *out, size_t cap);

void conditions_print(const struct condition *c, size_t n);

/*
 * Single-word aggregate verdict (severity worst -> best):
 *   unreachable -> unparseable -> tampered -> lsm-off ->
 *   init-pending -> reboot-pending -> degraded -> ok
 * Used by the `Status:` line in `shirudo status` and its JSON output.
 */
const char *status_verdict(const struct conditions_input *in);

void status_reason(const struct conditions_input *in,
		   char *buf, size_t cap);

#endif /* SHIRUDO_CONDITIONS_H */
