// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <stdbool.h>
#include <linux/keyctl.h>
#include <stdio.h>
#include <string.h>

#include "tpm_internal.h"
#include "crypto.h"
#include "nv_writer.h"

#define TEST_NV_INDEX	0x01818E01u

enum signature_fault {
	SIGNATURE_VALID,
	SIGNATURE_REPLAY,
	SIGNATURE_CORRUPT,
};

static int tpm_failed(TSS2_RC rc, const char *operation)
{
	if (rc == TSS2_RC_SUCCESS)
		return 0;
	fprintf(stderr, "%s: rc=0x%08x\n", operation, (__u32)rc);
	return 1;
}

static int flush(ESYS_CONTEXT *esys, ESYS_TR *session)
{
	ESYS_TR handle = *session;

	if (handle == ESYS_TR_NONE)
		return 0;
	*session = ESYS_TR_NONE;
	return tpm_failed(Esys_FlushContext(esys, handle), "FlushContext");
}

static int read_value(ESYS_CONTEXT *esys, ESYS_TR nv, __u8 out[32])
{
	TPM2B_MAX_NV_BUFFER *data = NULL;
	int rc = 1;

	if (tpm_failed(Esys_NV_Read(esys, nv, nv, ESYS_TR_PASSWORD,
				    ESYS_TR_NONE, ESYS_TR_NONE, 32, 0, &data),
		       "NV_Read"))
		goto out;
	if (!data || data->size != 32) {
		fprintf(stderr, "NV_Read: expected a 32-byte value\n");
		goto out;
	}
	memcpy(out, data->buffer, 32);
	rc = 0;
out:
	Esys_Free(data);
	return rc;
}

static int authorize(struct shirudo_tpm *t, ESYS_TR writer, ESYS_TR nv,
		     key_serial_t key, const __u8 event[32], const __u8 policy[32],
		     ESYS_TR *session, __u8 saved[SHIRUDO_TPM_NV_RSA_BYTES],
		     enum signature_fault fault)
{
	struct tpm_writer_authorization authorization = {};
	__u8 signature[SHIRUDO_TPM_NV_RSA_BYTES];
	TPM2B_NAME *name = NULL;
	TSS2_RC trc;
	int rc = 1;

	if (tpm_policy_session_start(t, session) ||
	    tpm_failed(Esys_TRSess_SetAttributes(t->esys, *session,
						 TPMA_SESSION_CONTINUESESSION,
						 TPMA_SESSION_CONTINUESESSION),
		       "TRSess_SetAttributes") ||
	    tpm_failed(Esys_TR_GetName(t->esys, nv, &name), "TR_GetName"))
		goto out;
	if (!name || name->size != SHIRUDO_TPM_NAME_LEN) {
		fprintf(stderr, "NV index has an invalid Name\n");
		goto out;
	}
	if (tpm_writer_prepare(t, *session, name->name, event, &authorization))
		goto out;
	if (fault == SIGNATURE_REPLAY) {
		memcpy(signature, saved, sizeof(signature));
	} else {
		if (nv_writer_sign_key(key, authorization.digest, signature))
			goto out;
		if (fault == SIGNATURE_CORRUPT)
			signature[0] ^= 1;
	}
	trc = tpm_writer_authorize(t, writer, *session, &authorization, signature);
	if (fault != SIGNATURE_VALID) {
		if (trc != (TPM2_RC_SIGNATURE | TPM2_RC_P | TPM2_RC_5)) {
			fprintf(stderr, "PolicySigned: expected bad signature, got 0x%08x\n",
				(__u32)trc);
			goto out;
		}
		rc = 0;
		goto out;
	}
	if (tpm_failed(trc, "PolicySigned") || tpm_policy_session_finish(t, *session, policy))
		goto out;
	memcpy(saved, signature, sizeof(signature));
	rc = 0;
out:
	Esys_Free(name);
	return rc;
}

int main(void)
{
	TPM2B_MAX_NV_BUFFER event_a = { .size = 32, .buffer = {1} };
	TPM2B_MAX_NV_BUFFER event_b = { .size = 32, .buffer = {2} };
	__u8 signature[SHIRUDO_TPM_NV_RSA_BYTES] = {};
	__u8 writer_public[SHIRUDO_TPM_NV_RSA_BYTES];
	__u8 before[32], after[32], expected[32], fold[64];
	TPM2B_MAX_NV_BUFFER seed = { .size = 32 };
	ESYS_TR session = ESYS_TR_NONE;
	ESYS_TR writer = ESYS_TR_NONE;
	struct shirudo_tpm *t = NULL;
	ESYS_CONTEXT *esys = NULL;
	key_serial_t ring = 0, key = 0;
	ESYS_TR nv = ESYS_TR_NONE;
	__u8 policy[32], zero[32] = {};
	bool defined = false;
	int rc = 1, err;
	TSS2_RC trc;

	if (tpm_open(&t))
		goto out;
	esys = t->esys;
	err = nv_writer_create(&ring, &key, writer_public);
	if (err) {
		fprintf(stderr, "create kernel NV writer: %s\n", strerror(-err));
		goto out;
	}
	if (tpm_policy_signed(zero, writer_public, policy)) {
		fprintf(stderr, "cannot construct the scratch NV writer policy\n");
		goto out;
	}
	tpm_policy_command_code(policy, SHIRUDO_TPM_CC_NV_EXTEND, policy);
	if (tpm_writer_load(t, writer_public, &writer) ||
	    tpm_nv_define(t, TEST_NV_INDEX, policy, NULL, 0))
		goto out;
	defined = true;
	if (tpm_failed(Esys_TR_FromTPMPublic(esys, TEST_NV_INDEX, ESYS_TR_NONE,
					     ESYS_TR_NONE, ESYS_TR_NONE, &nv),
		       "TR_FromTPMPublic") ||
	    authorize(t, writer, nv, key, seed.buffer, policy,
		      &session, signature, SIGNATURE_VALID) ||
	    tpm_failed(Esys_NV_Extend(esys, nv, nv, session, ESYS_TR_NONE,
				      ESYS_TR_NONE, &seed), "NV_Extend(seed)") ||
	    flush(esys, &session) ||
	    tpm_failed(Esys_TR_Close(esys, &nv), "TR_Close(NV)") ||
	    tpm_failed(Esys_TR_FromTPMPublic(esys, TEST_NV_INDEX, ESYS_TR_NONE,
					     ESYS_TR_NONE, ESYS_TR_NONE, &nv),
		       "TR_FromTPMPublic") ||
	    read_value(esys, nv, before) ||
	    authorize(t, writer, nv, key, event_a.buffer, policy,
		      &session, signature, SIGNATURE_VALID))
		goto out;
	trc = Esys_NV_Extend(esys, nv, nv, session, ESYS_TR_NONE, ESYS_TR_NONE, &event_b);
	if (trc != (TPM2_RC_POLICY_FAIL | TPM2_RC_S | TPM2_RC_1)) {
		fprintf(stderr, "NV_Extend(B): expected session-1 policy failure, got 0x%08x\n",
			(__u32)trc);
		goto out;
	}
	if (flush(esys, &session) || read_value(esys, nv, after))
		goto out;
	if (memcmp(before, after, 32)) {
		fprintf(stderr, "rejected NV_Extend changed the scratch value\n");
		goto out;
	}
	if (authorize(t, writer, nv, key, event_a.buffer, policy,
		      &session, signature, SIGNATURE_REPLAY) ||
	    flush(esys, &session) ||
	    authorize(t, writer, nv, key, event_a.buffer, policy,
		      &session, signature, SIGNATURE_CORRUPT) ||
	    flush(esys, &session) || read_value(esys, nv, after))
		goto out;
	if (memcmp(before, after, 32)) {
		fprintf(stderr, "replayed or corrupt signature changed the scratch value\n");
		goto out;
	}
	if (authorize(t, writer, nv, key, event_a.buffer, policy,
		      &session, signature, SIGNATURE_VALID) ||
	    tpm_failed(Esys_NV_Extend(esys, nv, nv, session, ESYS_TR_NONE,
				      ESYS_TR_NONE, &event_a), "NV_Extend(A)") ||
	    flush(esys, &session) || read_value(esys, nv, after))
		goto out;
	memcpy(fold, before, 32);
	memcpy(fold + 32, event_a.buffer, 32);
	if (sha256_buffer(fold, sizeof(fold), expected) || memcmp(after, expected, 32)) {
		fprintf(stderr, "authorized NV_Extend did not produce SHA256(before || A)\n");
		goto out;
	}
	rc = 0;
out:
	if (esys) {
		if (flush(esys, &session))
			rc = 1;
		if (defined && tpm_nv_undefine(t, TEST_NV_INDEX, NULL, 0))
			rc = 1;
		if (flush(esys, &writer))
			rc = 1;
	}
	tpm_close(t);
	if (ring > 0) {
		err = keyring_unlink_key(KEY_SPEC_USER_KEYRING, ring);
		if (err) {
			fprintf(stderr, "unlink scratch writer keyring: %s\n", strerror(-err));
			rc = 1;
		}
	}
	if (!rc) {
		puts("PolicySigned: replay and corruption rejected; value unchanged");
		puts("cpHash: authorized A; rejected B unchanged; extended A; scratch index removed");
	}
	return rc;
}
