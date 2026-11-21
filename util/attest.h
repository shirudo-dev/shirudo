/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Attestation: the evidence a target emits, the prediction and the
 * verification an operator runs against it.
 */

#ifndef SHIRUDO_ATTEST_H
#define SHIRUDO_ATTEST_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/misc.h>

#include "chain.h"
#include "tpm_wire.h"

/* PCRs quoted by default: firmware and boot loader, kernel, initrd, systemd. */
#define ATTEST_PCR_DEFAULT	0x0000FAFFu
#define ATTEST_NONCE_MAX	64
#define ATTEST_MEMBERS_MAX	256
#define ATTEST_REPORT_MAX	8192

/*
 * A challenge an operator made with `shirudo attest challenge`: the
 * blob and the encrypted seed TPM2_ActivateCredential takes, for the
 * attestation key of the given name under the endorsement key of the
 * given type.
 */
struct attest_challenge {
	bool		ek_rsa;
	__u8		ak_name[TPM_NAME_LEN];
	__u8		blob[TPM_ID_OBJECT_LEN];
	size_t		blob_len;
	__u8		secret[256];
	size_t		secret_len;
};

#define ATTEST_CHALLENGE_MAX	(16 * 1024)

int attest_challenge_read(const char *path,
			  struct attest_challenge *out);

struct config_update;

/*
 * Target side. The buffer is xmalloc'd to *cap and NUL-terminated;
 * -ENXIO when no TPM answers, -ENODEV when no register is bound this
 * boot, -EKEYREJECTED when the TPM refuses the challenge, and what the
 * eventlog's reader returns when this boot's records cannot be read.
 */
int attest_evidence_config(const __u8 *nonce, size_t nonce_len,
			   __u32 pcr_mask,
			   const struct attest_challenge *c,
			   struct config_update *update,
			   char **out, size_t *len, size_t *cap);

/*
 * Operator side. The credential the target has to recover is handed
 * to the caller and kept nowhere else; ek_ca is a PEM bundle or NULL.
 * -EKEYREJECTED when a check failed and no challenge was made.
 */
struct attest_challenge_policy {
	const char	*ek_ca;		/* issuer bundle, or NULL */
	const __u8	*ak_name;	/* pinned attestation key, or NULL */
	const __u8	*ek_name;	/* pinned endorsement key, or NULL */
	bool		trust_presented; /* accept an unvouched endorsement key */
};

int attest_challenge_make(const char *evidence, size_t len,
			  const struct attest_challenge_policy *pol,
			  __u8 credential[TPM_CREDENTIAL_LEN],
			  char **out, size_t *out_len, size_t *cap,
			  char *report, size_t report_cap);

struct attest_expect {
	const __u8	*nonce;
	size_t		nonce_len;
	bool		have_ak_name;
	__u8		ak_name[TPM_NAME_LEN];
	bool		have_chain;
	__u8		chain[32];
	bool		have_init;	/* cert, set, tree root known */
	__u8		init_event[32];
	bool		allow_runtime_events;
	bool		strict_anchor;
	__u32		pcr_expect_mask;
	__u8		pcrs[24][32];
	bool		have_credential;
	__u8		credential[TPM_CREDENTIAL_LEN] __sensitive;
	bool		have_ek_name;
	__u8		ek_name[TPM_NAME_LEN];
	bool		require_initrd;	/* the binding must be the initrd's */
	__u32		bind_expect_mask;	/* PCR values at binding time */
	__u8		bind_values[24][32];
	bool		have_config_root;
	__u8		config_root[32];
	bool		have_config_pcr;
	__u32		config_pcr;
	bool		have_config_nvpcr_name;
	__u8		config_nvpcr_name[34];
};

/*
 * Operator side: 0 when every check passed, -EKEYREJECTED when one
 * failed, -EINVAL when the document is malformed.
 */
int attest_verify(const char *evidence, size_t len,
		  const struct attest_expect *expect,
		  char *report, size_t report_cap);

/* --pcrs: PCRs 0 to 23 apart by commas, into a mask. 0 or -EINVAL. */
int attest_parse_pcrs(const char *list, __u32 *mask);
/* "<pcr>=<value>": the PCR, below 24, and where its value starts. */
int attest_parse_pcr_value(const char *arg, __u64 *pcr, const char **value);
/*
 * "<name>=<digest>", as attest predict's --expect and the part of each
 * --event after its kind take it: a name of 1 to UPATCH_NAME_MAX bytes up
 * to the first equals sign, then 64 hex digits. 0 or -EINVAL.
 */
int attest_parse_name_digest(const char *spec, char name[UPATCH_NAME_MAX + 1],
			     __u8 digest[32]);

#endif /* SHIRUDO_ATTEST_H */
