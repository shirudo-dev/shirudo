/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */
#ifndef SHIRUDO_TPM_INTERNAL_H
#define SHIRUDO_TPM_INTERNAL_H

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#include "tpm.h"

struct shirudo_tpm {
	TSS2_TCTI_CONTEXT	*tcti;
	ESYS_CONTEXT		*esys;
	__u8			writer_public[SHIRUDO_TPM_NV_RSA_BYTES];
	bool			writer_set;
};

struct tpm_writer_authorization {
	TPM2B_NONCE	nonce;
	TPM2B_DIGEST	cphash;
	__u8		digest[SHIRUDO_TPM_DIGEST_LEN];
};

int tpm_policy_session_start(struct shirudo_tpm *t, ESYS_TR *session);
int tpm_policy_session_finish(struct shirudo_tpm *t, ESYS_TR session,
			      const __u8 expected[SHIRUDO_TPM_DIGEST_LEN]);
int tpm_writer_load(struct shirudo_tpm *t,
		    const __u8 public[SHIRUDO_TPM_NV_RSA_BYTES], ESYS_TR *key);
int tpm_writer_prepare(struct shirudo_tpm *t, ESYS_TR session,
		       const __u8 name[SHIRUDO_TPM_NAME_LEN],
		       const __u8 event[SHIRUDO_TPM_DIGEST_LEN],
		       struct tpm_writer_authorization *authorization);
TSS2_RC tpm_writer_authorize(struct shirudo_tpm *t, ESYS_TR key, ESYS_TR session,
			     const struct tpm_writer_authorization *authorization,
			     const __u8 signature[SHIRUDO_TPM_NV_RSA_BYTES]);

#endif /* SHIRUDO_TPM_INTERNAL_H */
