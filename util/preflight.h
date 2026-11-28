/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Pre-flight infrastructure-prerequisite gate for `shirudo init`.
 */

#ifndef SHIRUDO_PREFLIGHT_H
#define SHIRUDO_PREFLIGHT_H

#include <stdbool.h>

#define PREFLIGHT_DETAIL_MAX	256

enum preflight_id {
	PRE_ROOT,
	PRE_BPF_LSM,
	PRE_BPFFS,
	PRE_SIGNED_LOADER_ABI,
	PRE_LSM_HOOKS,
	PRE_MODULE_SIG,
	PRE_COMPAT,
	PRE_RESUME,
	PRE_BDEV,
	PRE_CERT_ON_DISK,
	PRE_CERT_ALGORITHM,
	PRE_CERT_KERNEL_ALGO,
	PRE_KEYRING,
	PRE_EMBEDDED_LOADER,
	PRE_TPM,
	PRE__MAX,
};

struct preflight_check {
	enum preflight_id	id;
	const char			*name;
	bool				ok;
	char				detail[PREFLIGHT_DETAIL_MAX];
};

struct preflight_result {
	struct preflight_check	checks[PRE__MAX];
	int				n;
	int				n_failed;
};

/*
 * Every check runs and every one is hard: no opt-out for a missing TPM
 * or a classical certificate. Nothing is printed; the caller presents
 * the outcome.
 */
void preflight_run(struct preflight_result *out);

#endif /* SHIRUDO_PREFLIGHT_H */
