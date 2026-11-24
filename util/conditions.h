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
	int		ksp_seen, ksm_seen;
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
	int		xdp_tampered;	/* loaded XDP upatches whose archive changed */
	const char	*xdp_tampered_detail;	/* their names, when any */
	int		links_lost;	/* loaded upatches missing a link */
	const char	*links_lost_detail;	/* their names, when any */
	int		checks_rc;	/* -errno of a link or archive check that could not run */
	int		xdp_uncovered;	/* selected devices an XDP upatch does not run on */
	const char	*xdp_uncovered_detail;	/* upatch, device and why, when any */
	int		xdp_coverage_rc;	/* -errno when that could not be checked */
};

struct condition {
	const char	*type;		/* "LsmAttached" / "KeyringSealed" / ... */
	const char	*status;	/* "OK" / "WARN" / "ALERT" */
	char		detail[192];
};

/*
 * Maximum number of conditions returned today (LsmAttached,
 * KeyringSealed, ChainIntact, UpatchesMeasured, TpmMeasured,
 * ConfigActive, XdpCovered); callers can size their stack array off this.
 */
#define CONDITIONS_MAX	7

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

/*
 * The reason for that verdict, in a sentence: a literal, or the unreach
 * of in, which lives as long as in does; "" when the host is ok.
 */
const char *status_reason(const struct conditions_input *in);

#endif /* SHIRUDO_CONDITIONS_H */
