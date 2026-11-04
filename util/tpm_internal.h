/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */
#ifndef SHIRUDO_TPM_INTERNAL_H
#define SHIRUDO_TPM_INTERNAL_H

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#include "tpm.h"

struct tpm {
	struct tpm_key		session_key;
	TSS2_TCTI_CONTEXT	*tcti;
	ESYS_CONTEXT		*esys;
	ESYS_TR			session;
	__u8			writer_seed[TPM_DIGEST_LEN];
	__u8			writer_public[TPM_NV_RSA_BYTES];
	bool			writer_set;
};

struct tpm_writer_authorization {
	TPM2B_NONCE	nonce;
	TPM2B_DIGEST	cphash;
	__u8		digest[TPM_DIGEST_LEN];
};

int tpm_policy_session_start(struct tpm *t, ESYS_TR *session);
int tpm_policy_session_finish(struct tpm *t, ESYS_TR session,
			      const __u8 expected[TPM_DIGEST_LEN]);
int tpm_writer_load(struct tpm *t,
		    const __u8 seed[TPM_DIGEST_LEN],
		    const __u8 expected_public[TPM_NV_RSA_BYTES],
		    ESYS_TR *key);
int tpm_writer_prepare(struct tpm *t, ESYS_TR session,
		       const __u8 name[TPM_NAME_LEN],
		       const __u8 event[TPM_DIGEST_LEN],
		       struct tpm_writer_authorization *authorization);
TSS2_RC tpm_writer_authorize(struct tpm *t, ESYS_TR key, ESYS_TR session,
			     const struct tpm_writer_authorization *authorization,
			     const __u8 signature[TPM_NV_RSA_BYTES]);

#endif /* SHIRUDO_TPM_INTERNAL_H */
