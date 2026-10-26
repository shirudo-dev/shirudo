// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * libtss2 wrappers for the measurement register and attestation.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "tpm_internal.h"

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "config.h"
#include "image_config.h"
#include "log.h"
#include "malloc.h"
#include "nv_writer.h"
#include "paths.h"

#define EK_CERT_NV_RSA		0x01C00002u
#define EK_CERT_NV_ECC		0x01C0000Au
#define NV_READ_CHUNK		512u

/*
 * The env, then the file, then /dev/tpmrm0. An override is for VMs,
 * CI and a software TPM; it cannot defeat the operator-side guarantee,
 * since evidence is signed by the key the operator pinned.
 */
int tpm_tcti(char *buf, size_t size)
{
	struct shirudo_config cfg = {};
	const char *tcti;
	ssize_t n;

	tcti = shirudo_image_config_active() ? NULL :
		getenv("SHIRUDO_TPM_TCTI");
	if ((!tcti || !*tcti) && config_load(&cfg) == 0 &&
	    cfg.tpm_tcti[0])
		tcti = cfg.tpm_tcti;
	if (!tcti || !*tcti)
		tcti = "device:/dev/tpmrm0";
	n = strscpy(buf, tcti, size);
	explicit_bzero(&cfg, sizeof(cfg));	/* scrub tpm_owner_auth */
	return n < 0 ? (int)n : 0;
}

static int open_tpm(struct shirudo_tpm **out, bool quiet)
{
	char tcti[SHIRUDO_TPM_TCTI_MAX];
	struct shirudo_tpm *t;
	TSS2_RC rc;
	int err;

	/*
	 * Quiet libtss2's own stderr logging (it screams ERROR on the
	 * expected "index not yet defined" probe during first-init).
	 * shirudo logs its own diagnostics via pr_*; an operator who
	 * sets TSS2_LOG keeps their setting (overwrite = 0).
	 */
	setenv("TSS2_LOG", "all+none", 0);

	err = tpm_tcti(tcti, sizeof(tcti));
	if (err) {
		if (!quiet)
			pr_err("tpm: the TCTI is longer than %d bytes",
			       SHIRUDO_TPM_TCTI_MAX - 1);
		return err;
	}

	t = xcalloc(1, sizeof(*t));
	if (!t)
		return -ENOMEM;
	rc = Tss2_TctiLdr_Initialize(tcti, &t->tcti);
	if (rc != TSS2_RC_SUCCESS) {
		if (!quiet)
			pr_err("tpm: TctiLdr_Initialize(%s): rc=0x%08x", tcti,
			       (__u32)rc);
		xfree(t, sizeof(*t));
		return -EIO;
	}
	rc = Esys_Initialize(&t->esys, t->tcti, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		if (!quiet)
			pr_err("tpm: Esys_Initialize: rc=0x%08x", (__u32)rc);
		Tss2_TctiLdr_Finalize(&t->tcti);
		xfree(t, sizeof(*t));
		return -EIO;
	}
	*out = t;
	return 0;
}

int tpm_open(struct shirudo_tpm **out)
{
	return open_tpm(out, false);
}

int tpm_open_quiet(struct shirudo_tpm **out)
{
	return open_tpm(out, true);
}

void tpm_close(struct shirudo_tpm *t)
{
	if (!t)
		return;
	if (t->esys)
		Esys_Finalize(&t->esys);
	if (t->tcti)
		Tss2_TctiLdr_Finalize(&t->tcti);
	xfree(t, sizeof(*t));
}

int tpm_nv_set_writer(struct shirudo_tpm *t,
		      const __u8 public[SHIRUDO_TPM_NV_RSA_BYTES])
{
	if (!t || !public) {
		pr_err("tpm: NV writer modulus is required");
		return -EACCES;
	}
	memcpy(t->writer_public, public, sizeof(t->writer_public));
	t->writer_set = true;
	return 0;
}

static bool rc_is(TSS2_RC rc, TSS2_RC code)
{
	if ((rc & 0xFFFF0000u) != 0)
		return false;	/* not a TPM-layer code */
	if (rc & TPM2_RC_FMT1)
		return (rc & 0x0BFu) == (code & 0x0BFu);
	return (rc & 0xFFFu) == code;
}

static bool rc_is_auth_failure(TSS2_RC rc)
{
	return rc_is(rc, TPM2_RC_BAD_AUTH) || rc_is(rc, TPM2_RC_AUTH_FAIL) ||
	       rc_is(rc, TPM2_RC_NV_AUTHORIZATION) ||
	       rc_is(rc, TPM2_RC_POLICY_FAIL);
}

static void pcr_selection(__u32 mask, TPML_PCR_SELECTION *sel)
{
	memset(sel, 0, sizeof(*sel));
	sel->count = 1;
	sel->pcrSelections[0].hash = TPM2_ALG_SHA256;
	sel->pcrSelections[0].sizeofSelect = SHIRUDO_TPM_PCR_SELECT_LEN;
	sel->pcrSelections[0].pcrSelect[0] = (__u8)mask;
	sel->pcrSelections[0].pcrSelect[1] = (__u8)(mask >> 8);
	sel->pcrSelections[0].pcrSelect[2] = (__u8)(mask >> 16);
}

int tpm_pcr_read(struct shirudo_tpm *t, __u32 pcr,
		 __u8 out[32])
{
	TPML_PCR_SELECTION sel;
	TPML_DIGEST *values = NULL;
	UINT32 counter;
	TSS2_RC rc;

	if (pcr >= 24)
		return -EINVAL;
	pcr_selection(1u << pcr, &sel);
	rc = Esys_PCR_Read(t->esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
			   &sel, &counter, NULL, &values);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: PCR_Read(%u): rc=0x%08x", pcr, (__u32)rc);
		return -EIO;
	}
	if (values->count != 1 || values->digests[0].size != 32) {
		pr_err("tpm: PCR %u has no SHA-256 bank", pcr);
		Esys_Free(values);
		return -ENOENT;
	}
	memcpy(out, values->digests[0].buffer, 32);
	Esys_Free(values);
	return 0;
}

int tpm_pcr_extend(struct shirudo_tpm *t, __u32 pcr,
		   const __u8 digest[32])
{
	TPML_DIGEST_VALUES dv = { .count = 1 };
	TSS2_RC rc;

	if (pcr >= 24)
		return -EINVAL;
	dv.digests[0].hashAlg = TPM2_ALG_SHA256;
	memcpy(dv.digests[0].digest.sha256, digest, 32);
	rc = Esys_PCR_Extend(t->esys, ESYS_TR_PCR0 + pcr, ESYS_TR_PASSWORD,
			     ESYS_TR_NONE, ESYS_TR_NONE, &dv);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: PCR_Extend(%u): rc=0x%08x", pcr, (__u32)rc);
		return -EIO;
	}
	return 0;
}

int shirudo_tpm_boot_identity(struct shirudo_tpm *t, __u32 *reset,
			      __u32 *restart)
{
	TPMS_TIME_INFO *info = NULL;
	TSS2_RC rc;

	if (!t || !reset || !restart)
		return -EINVAL;
	rc = Esys_ReadClock(t->esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
			    &info);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: ReadClock: rc=0x%08x", (__u32)rc);
		return -EIO;
	}
	*reset = info->clockInfo.resetCount;
	*restart = info->clockInfo.restartCount;
	Esys_Free(info);
	return 0;
}

int tpm_reset_count(struct shirudo_tpm *t, __u32 *out)
{
	TPMS_TIME_INFO *info = NULL;
	TSS2_RC rc;

	rc = Esys_ReadClock(t->esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
			    &info);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: ReadClock: rc=0x%08x", (__u32)rc);
		return -EIO;
	}
	*out = info->clockInfo.resetCount;
	Esys_Free(info);
	return 0;
}

static int nv_handle(struct shirudo_tpm *t, __u32 index, ESYS_TR *out)
{
	TSS2_RC rc;

	rc = Esys_TR_FromTPMPublic(t->esys, index, ESYS_TR_NONE, ESYS_TR_NONE,
				   ESYS_TR_NONE, out);
	if (rc_is(rc, TPM2_RC_HANDLE))
		return -ENOENT;		/* quiet: undefined is normal */
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: TR_FromTPMPublic(0x%08x): rc=0x%08x", index,
		       (__u32)rc);
		return -EIO;
	}
	return 0;
}

int tpm_nv_info(struct shirudo_tpm *t, __u32 index,
		struct tpm_nv_info *info)
{
	TPM2B_NV_PUBLIC *pub = NULL;
	TPM2B_NAME *name = NULL;
	ESYS_TR nv;
	TSS2_RC rc;
	int err;

	memset(info, 0, sizeof(*info));
	err = nv_handle(t, index, &nv);
	if (err == -ENOENT)
		return 0;
	if (err)
		return err;
	rc = Esys_NV_ReadPublic(t->esys, nv, ESYS_TR_NONE, ESYS_TR_NONE,
				ESYS_TR_NONE, &pub, &name);
	Esys_TR_Close(t->esys, &nv);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: NV_ReadPublic(0x%08x): rc=0x%08x", index,
		       (__u32)rc);
		return -EIO;
	}
	info->defined = true;
	info->written = (pub->nvPublic.attributes & TPMA_NV_WRITTEN) != 0;
	info->attrs = pub->nvPublic.attributes;
	info->data_size = pub->nvPublic.dataSize;
	if (pub->nvPublic.authPolicy.size == 32)
		memcpy(info->policy, pub->nvPublic.authPolicy.buffer, 32);
	if (name->size <= sizeof(info->name)) {
		memcpy(info->name, name->name, name->size);
		info->name_len = name->size;
	}
	Esys_Free(pub);
	Esys_Free(name);
	return 0;
}

static int owner_auth_set(struct shirudo_tpm *t, const void *auth, size_t len)
{
	TPM2B_AUTH owner = {};
	TSS2_RC rc;

	if (len > sizeof(owner.buffer))
		return -EINVAL;
	if (len) {
		memcpy(owner.buffer, auth, len);
		owner.size = (__u16)len;
	}
	rc = Esys_TR_SetAuth(t->esys, ESYS_TR_RH_OWNER, &owner);
	explicit_bzero(owner.buffer, sizeof(owner.buffer));
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: TR_SetAuth(owner): rc=0x%08x", (__u32)rc);
		return -EIO;
	}
	return 0;
}

static void owner_auth_clear(struct shirudo_tpm *t)
{
	TPM2B_AUTH empty = {};

	Esys_TR_SetAuth(t->esys, ESYS_TR_RH_OWNER, &empty);
}

static int owner_auth_error(const char *op, __u32 index, TSS2_RC rc)
{
	if (rc_is_auth_failure(rc)) {
		pr_err("tpm: %s(0x%08x): owner-hierarchy authorization "
		       "failed (rc=0x%08x). This TPM has owner auth set; "
		       "supply it via tpm.owner_auth in %s (or "
		       "SHIRUDO_TPM_OWNER_AUTH), or clear the TPM owner "
		       "auth.", op, index, (__u32)rc, SHIRUDO_CONF_PATH);
		return -EACCES;
	}
	pr_err("tpm: %s(0x%08x): rc=0x%08x", op, index, (__u32)rc);
	return -EIO;
}

int tpm_nv_define(struct shirudo_tpm *t, __u32 index,
		  const __u8 policy[32],
		  const void *owner_auth, size_t owner_auth_len)
{
	TPM2B_NV_PUBLIC pub = {};
	TPM2B_AUTH nv_auth = {};
	ESYS_TR nv = ESYS_TR_NONE;
	TSS2_RC rc;
	int err;

	err = owner_auth_set(t, owner_auth, owner_auth_len);
	if (err)
		return err;
	pub.nvPublic.nvIndex = index;
	pub.nvPublic.nameAlg = TPM2_ALG_SHA256;
	pub.nvPublic.attributes = SHIRUDO_TPM_REGISTER_ATTRS;
	pub.nvPublic.authPolicy.size = 32;
	memcpy(pub.nvPublic.authPolicy.buffer, policy, 32);
	pub.nvPublic.dataSize = SHIRUDO_TPM_NV_DIGEST_LEN;
	rc = Esys_NV_DefineSpace(t->esys, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
				 ESYS_TR_NONE, ESYS_TR_NONE, &nv_auth, &pub,
				 &nv);
	owner_auth_clear(t);
	if (rc != TSS2_RC_SUCCESS)
		return owner_auth_error("NV_DefineSpace", index, rc);
	Esys_TR_Close(t->esys, &nv);
	return 0;
}

int tpm_nv_undefine(struct shirudo_tpm *t, __u32 index,
		    const void *owner_auth, size_t owner_auth_len)
{
	ESYS_TR nv;
	TSS2_RC rc;
	int err;

	err = nv_handle(t, index, &nv);
	if (err)
		return err;
	err = owner_auth_set(t, owner_auth, owner_auth_len);
	if (err)
		return err;
	rc = Esys_NV_UndefineSpace(t->esys, ESYS_TR_RH_OWNER, nv,
				   ESYS_TR_PASSWORD, ESYS_TR_NONE,
				   ESYS_TR_NONE);
	owner_auth_clear(t);
	if (rc != TSS2_RC_SUCCESS)
		return owner_auth_error("NV_UndefineSpace", index, rc);
	return 0;
}

int tpm_nv_read(struct shirudo_tpm *t, __u32 index, __u8 out[32])
{
	TPM2B_MAX_NV_BUFFER *data = NULL;
	ESYS_TR nv;
	TSS2_RC rc;
	int err;

	err = nv_handle(t, index, &nv);
	if (err)
		return err;
	rc = Esys_NV_Read(t->esys, nv, nv, ESYS_TR_PASSWORD, ESYS_TR_NONE,
			  ESYS_TR_NONE, SHIRUDO_TPM_NV_DIGEST_LEN, 0, &data);
	Esys_TR_Close(t->esys, &nv);
	if (rc_is(rc, TPM2_RC_NV_UNINITIALIZED))
		return -ENODATA;	/* quiet: nothing written this boot */
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: NV_Read(0x%08x): rc=0x%08x", index, (__u32)rc);
		return -EIO;
	}
	if (data->size != SHIRUDO_TPM_NV_DIGEST_LEN) {
		pr_err("tpm: NV_Read returned %u bytes, expected %u",
		       data->size, SHIRUDO_TPM_NV_DIGEST_LEN);
		Esys_Free(data);
		return -EIO;
	}
	memcpy(out, data->buffer, SHIRUDO_TPM_NV_DIGEST_LEN);
	Esys_Free(data);
	return 0;
}

int tpm_policy_session_start(struct shirudo_tpm *t, ESYS_TR *session)
{
	TPMT_SYM_DEF sym = { .algorithm = TPM2_ALG_NULL };
	TSS2_RC rc;

	rc = Esys_StartAuthSession(t->esys, ESYS_TR_NONE, ESYS_TR_NONE,
				   ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
				   NULL, TPM2_SE_POLICY, &sym, TPM2_ALG_SHA256,
				   session);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: StartAuthSession: rc=0x%08x", (__u32)rc);
		return -EIO;
	}
	return 0;
}

static void session_flush(struct shirudo_tpm *t, ESYS_TR session)
{
	if (session != ESYS_TR_NONE)
		Esys_FlushContext(t->esys, session);
}

int tpm_writer_prepare(struct shirudo_tpm *t, ESYS_TR session,
		       const __u8 name[SHIRUDO_TPM_NAME_LEN],
		       const __u8 event[SHIRUDO_TPM_DIGEST_LEN],
		       struct tpm_writer_authorization *authorization)
{
	TPM2B_NONCE *nonce = NULL;
	TSS2_RC rc;
	int err;

	authorization->cphash.size = SHIRUDO_TPM_DIGEST_LEN;
	err = tpm_nv_extend_cphash(name, event, authorization->cphash.buffer);
	if (err) {
		pr_err("tpm: compute NV_Extend command hash: %s", strerror(-err));
		return err;
	}
	rc = Esys_TRSess_GetNonceTPM(t->esys, session, &nonce);
	if (rc != TSS2_RC_SUCCESS || !nonce) {
		pr_err("tpm: NV writer PolicySigned: rc=0x%08x", (__u32)rc);
		Esys_Free(nonce);
		return -EACCES;
	}
	authorization->nonce = *nonce;
	Esys_Free(nonce);
	err = tpm_writer_auth_hash(authorization->nonce.buffer, authorization->nonce.size,
				   authorization->cphash.buffer, authorization->digest);
	if (err)
		pr_err("tpm: compute NV writer authorization: %s", strerror(-err));
	return err;
}

int tpm_writer_load(struct shirudo_tpm *t,
		    const __u8 public_key[SHIRUDO_TPM_NV_RSA_BYTES], ESYS_TR *key)
{
	__u8 public_area[SHIRUDO_TPM_NV_RSA_PUBLIC_AREA_LEN];
	__u8 expected[SHIRUDO_TPM_NAME_LEN];
	TPM2B_PUBLIC public = {};
	TPMT_PUBLIC *p = &public.publicArea;
	TPM2B_NAME *name = NULL;
	TSS2_RC rc;
	int err;

	*key = ESYS_TR_NONE;
	p->type = TPM2_ALG_RSA;
	p->nameAlg = TPM2_ALG_SHA256;
	p->objectAttributes = TPMA_OBJECT_SIGN_ENCRYPT;
	p->parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
	p->parameters.rsaDetail.scheme.scheme = TPM2_ALG_RSASSA;
	p->parameters.rsaDetail.scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;
	p->parameters.rsaDetail.keyBits = 3072;
	p->parameters.rsaDetail.exponent = 65537;
	p->unique.rsa.size = SHIRUDO_TPM_NV_RSA_BYTES;
	memcpy(p->unique.rsa.buffer, public_key, SHIRUDO_TPM_NV_RSA_BYTES);
	rc = Esys_LoadExternal(t->esys, ESYS_TR_NONE, ESYS_TR_NONE,
			       ESYS_TR_NONE, NULL, &public, ESYS_TR_RH_NULL, key);
	if (rc != TSS2_RC_SUCCESS)
		goto tss_error;
	rc = Esys_TR_GetName(t->esys, *key, &name);
	if (rc != TSS2_RC_SUCCESS || !name)
		goto tss_error;
	tpm_writer_public(public_key, public_area);
	err = tpm_object_name(public_area, sizeof(public_area), expected);
	if (err || name->size != sizeof(expected) ||
	    memcmp(name->name, expected, sizeof(expected))) {
		pr_err("tpm: loaded NV writer Name differs from its public area");
		err = -EPROTO;
		goto out;
	}
	err = 0;
	goto out;
tss_error:
	pr_err("tpm: NV writer PolicySigned: rc=0x%08x", (__u32)rc);
	err = -EACCES;
out:
	Esys_Free(name);
	if (err) {
		session_flush(t, *key);
		*key = ESYS_TR_NONE;
	}
	return err;
}

TSS2_RC tpm_writer_authorize(struct shirudo_tpm *t, ESYS_TR key, ESYS_TR session,
			     const struct tpm_writer_authorization *authorization,
			     const __u8 signature[SHIRUDO_TPM_NV_RSA_BYTES])
{
	TPM2B_NONCE ref = { .size = sizeof(SHIRUDO_TPM_NV_POLICY_REF) - 1 };
	TPMT_SIGNATURE sig = { .sigAlg = TPM2_ALG_RSASSA };
	TPM2B_TIMEOUT *timeout = NULL;
	TPMT_TK_AUTH *ticket = NULL;
	TSS2_RC rc;

	sig.signature.rsassa.hash = TPM2_ALG_SHA256;
	sig.signature.rsassa.sig.size = SHIRUDO_TPM_NV_RSA_BYTES;
	memcpy(sig.signature.rsassa.sig.buffer, signature, SHIRUDO_TPM_NV_RSA_BYTES);
	memcpy(ref.buffer, SHIRUDO_TPM_NV_POLICY_REF, ref.size);
	rc = Esys_PolicySigned(t->esys, key, session, ESYS_TR_NONE,
			       ESYS_TR_NONE, ESYS_TR_NONE, &authorization->nonce,
			       &authorization->cphash, &ref, 0, &sig, &timeout, &ticket);
	Esys_Free(timeout);
	Esys_Free(ticket);
	return rc;
}

static int policy_writer_signed(struct shirudo_tpm *t, ESYS_TR session,
				__u32 index, const __u8 event[32])
{
	struct tpm_writer_authorization authorization = {};
	__u8 signature[SHIRUDO_TPM_NV_RSA_BYTES];
	ESYS_TR key = ESYS_TR_NONE;
	struct tpm_nv_info nv;
	TSS2_RC rc;
	int err;

	err = tpm_nv_info(t, index, &nv);
	if (err)
		return err;
	if (!nv.defined || nv.name_len != SHIRUDO_TPM_NAME_LEN) {
		pr_err("tpm: NV writer requires a defined register");
		return -ENODEV;
	}
	err = tpm_writer_prepare(t, session, nv.name, event, &authorization);
	if (err)
		return err;
	err = nv_writer_sign(authorization.digest, signature);
	if (err)
		return err;
	err = tpm_writer_load(t, t->writer_public, &key);
	if (err)
		return err;
	rc = tpm_writer_authorize(t, key, session, &authorization, signature);
	session_flush(t, key);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: NV writer PolicySigned: rc=0x%08x", (__u32)rc);
		return -EACCES;
	}
	return 0;
}

int tpm_policy_session_finish(struct shirudo_tpm *t, ESYS_TR session,
			      const __u8 expected[SHIRUDO_TPM_DIGEST_LEN])
{
	TPM2B_DIGEST *digest = NULL;
	TSS2_RC rc;
	int err = 0;

	rc = Esys_PolicyCommandCode(t->esys, session, ESYS_TR_NONE,
				    ESYS_TR_NONE, ESYS_TR_NONE, TPM2_CC_NV_Extend);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: register policy assertion: rc=0x%08x", (__u32)rc);
		return -EACCES;
	}
	rc = Esys_PolicyGetDigest(t->esys, session, ESYS_TR_NONE,
				  ESYS_TR_NONE, ESYS_TR_NONE, &digest);
	if (rc != TSS2_RC_SUCCESS || !digest || digest->size != SHIRUDO_TPM_DIGEST_LEN ||
	    memcmp(digest->buffer, expected, SHIRUDO_TPM_DIGEST_LEN)) {
		pr_err("tpm: register policy digest does not match the "
		       "computed policy (rc=0x%08x)", (__u32)rc);
		err = -EPROTO;
	}
	Esys_Free(digest);
	return err;
}

/*
 * Walk one branch of the register's write policy in a real session and
 * authorize the exact NV_Extend with the kernel-held writer after PolicyOR.
 * Compare the session digest with the software policy to detect drift.
 */
static int policy_session_register(struct shirudo_tpm *t, bool init,
				   __u32 index, const __u8 event[32],
				   __u32 pcr_mask,
				   const __u8 branch_written[32],
				   const __u8 branch_init[32],
				   ESYS_TR *session)
{
	TPML_DIGEST branches = { .count = 2 };
	__u8 expected[32];
	TSS2_RC rc;
	int err;

	if (!t->writer_set) {
		pr_err("tpm: register policy requires the NV writer public key");
		return -EACCES;
	}
	err = tpm_policy_session_start(t, session);
	if (err)
		return err;
	rc = Esys_PolicyNvWritten(t->esys, *session, ESYS_TR_NONE, ESYS_TR_NONE,
				  ESYS_TR_NONE, init ? TPM2_NO : TPM2_YES);
	if (rc == TSS2_RC_SUCCESS && init) {
		TPM2B_DIGEST live = {};
		TPML_PCR_SELECTION sel;

		pcr_selection(pcr_mask, &sel);
		rc = Esys_PolicyPCR(t->esys, *session, ESYS_TR_NONE,
				    ESYS_TR_NONE, ESYS_TR_NONE, &live, &sel);
	}
	if (rc == TSS2_RC_SUCCESS) {
		branches.digests[0].size = 32;
		memcpy(branches.digests[0].buffer, branch_written, 32);
		branches.digests[1].size = 32;
		memcpy(branches.digests[1].buffer, branch_init, 32);
		rc = Esys_PolicyOR(t->esys, *session, ESYS_TR_NONE,
				   ESYS_TR_NONE, ESYS_TR_NONE, &branches);
	}
	if (rc == TSS2_RC_SUCCESS) {
		err = policy_writer_signed(t, *session, index, event);
		if (err) {
			session_flush(t, *session);
			*session = ESYS_TR_NONE;
			return err;
		}
	}
	if (rc != TSS2_RC_SUCCESS) {
		if (rc_is(rc, TPM2_RC_VALUE) && init)
			pr_err("tpm: the anchoring PCR moved; the register "
			       "can only be initialised in the boot window");
		else
			pr_err("tpm: register policy assertion: rc=0x%08x",
			       (__u32)rc);
		session_flush(t, *session);
		*session = ESYS_TR_NONE;
		return -EACCES;
	}
	err = tpm_register_policy_final(branch_written, branch_init, t->writer_public, expected);
	if (err)
		pr_err("tpm: compute signed register policy: %s", strerror(-err));
	else
		err = tpm_policy_session_finish(t, *session, expected);
	if (err) {
		session_flush(t, *session);
		*session = ESYS_TR_NONE;
	}
	return err;
}

static int nv_extend_session(struct shirudo_tpm *t, __u32 index,
			     ESYS_TR session, const __u8 event[32])
{
	TPM2B_MAX_NV_BUFFER data = { .size = SHIRUDO_TPM_NV_DIGEST_LEN };
	ESYS_TR nv;
	TSS2_RC rc;
	int err;

	err = nv_handle(t, index, &nv);
	if (err)
		return err;
	memcpy(data.buffer, event, SHIRUDO_TPM_NV_DIGEST_LEN);
	rc = Esys_NV_Extend(t->esys, nv, nv, session, ESYS_TR_NONE,
			    ESYS_TR_NONE, &data);
	Esys_TR_Close(t->esys, &nv);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: NV_Extend(0x%08x): rc=0x%08x", index,
		       (__u32)rc);
		return rc_is_auth_failure(rc) ? -EACCES : -EIO;
	}
	return 0;
}

int tpm_nv_extend_first(struct shirudo_tpm *t, __u32 index,
			__u32 pcr_mask,
			const __u8 branch_written[32],
			const __u8 branch_init[32],
			const __u8 event[32])
{
	ESYS_TR session = ESYS_TR_NONE;
	int err;

	err = policy_session_register(t, true, index, event, pcr_mask, branch_written,
				      branch_init, &session);
	if (err)
		return err;
	err = nv_extend_session(t, index, session, event);
	session_flush(t, session);
	return err;
}

int tpm_nv_extend(struct shirudo_tpm *t, __u32 index,
		  const __u8 branch_written[32],
		  const __u8 branch_init[32],
		  const __u8 event[32])
{
	ESYS_TR session = ESYS_TR_NONE;
	int err;

	err = policy_session_register(t, false, index, event, 0, branch_written,
				      branch_init, &session);
	if (err)
		return err;
	err = nv_extend_session(t, index, session, event);
	session_flush(t, session);
	return err;
}

static int public_from_tss(const TPMT_PUBLIC *p, __u8 *out, size_t cap,
			   size_t *len)
{
	struct shirudo_tpm_public pub = {};

	if (p->nameAlg != TPM2_ALG_SHA256 || p->authPolicy.size > 32)
		return -EINVAL;
	pub.type = p->type;
	pub.attrs = p->objectAttributes;
	pub.policy_len = p->authPolicy.size;
	memcpy(pub.policy, p->authPolicy.buffer, pub.policy_len);
	if (p->type == TPM2_ALG_ECC) {
		const TPMS_ECC_PARMS *ecc = &p->parameters.eccDetail;

		pub.sym_alg = ecc->symmetric.algorithm;
		if (pub.sym_alg != TPM2_ALG_NULL) {
			pub.sym_bits = ecc->symmetric.keyBits.aes;
			pub.sym_mode = ecc->symmetric.mode.aes;
		}
		pub.scheme = ecc->scheme.scheme;
		if (pub.scheme != TPM2_ALG_NULL)
			pub.scheme_hash = ecc->scheme.details.anySig.hashAlg;
		pub.curve = ecc->curveID;
		if (ecc->kdf.scheme != TPM2_ALG_NULL ||
		    p->unique.ecc.x.size != 32 || p->unique.ecc.y.size != 32)
			return -EINVAL;
		memcpy(pub.x, p->unique.ecc.x.buffer, 32);
		memcpy(pub.y, p->unique.ecc.y.buffer, 32);
	} else if (p->type == TPM2_ALG_RSA) {
		const TPMS_RSA_PARMS *rsa = &p->parameters.rsaDetail;

		pub.sym_alg = rsa->symmetric.algorithm;
		if (pub.sym_alg != TPM2_ALG_NULL) {
			pub.sym_bits = rsa->symmetric.keyBits.aes;
			pub.sym_mode = rsa->symmetric.mode.aes;
		}
		pub.scheme = rsa->scheme.scheme;
		if (pub.scheme != TPM2_ALG_NULL)
			pub.scheme_hash = rsa->scheme.details.anySig.hashAlg;
		pub.rsa_bits = rsa->keyBits;
		pub.rsa_exponent = rsa->exponent;
		if (p->unique.rsa.size > sizeof(pub.n))
			return -EINVAL;
		pub.n_len = p->unique.rsa.size;
		memcpy(pub.n, p->unique.rsa.buffer, pub.n_len);
	} else {
		return -EPROTONOSUPPORT;
	}
	return tpm_public_marshal(&pub, out, cap, len);
}

static int marshal_signature(const TPMT_SIGNATURE *sig, __u8 *out,
			     size_t cap, size_t *len)
{
	const TPMS_SIGNATURE_ECDSA *e = &sig->signature.ecdsa;
	size_t off = 0;

	if (sig->sigAlg != TPM2_ALG_ECDSA || e->signatureR.size > 64 ||
	    e->signatureS.size > 64 || cap < 8u + 128u)
		return -EINVAL;
	tpm_put16(out + off, sig->sigAlg);
	off += 2;
	tpm_put16(out + off, e->hash);
	off += 2;
	off += tpm_put2b(out + off, e->signatureR.buffer, e->signatureR.size);
	off += tpm_put2b(out + off, e->signatureS.buffer, e->signatureS.size);
	*len = off;
	return 0;
}

/*
 * Create a primary under the endorsement hierarchy and take its
 * marshalled public area and its name, the latter checked against the
 * area so that what the evidence carries is what the TPM named.
 */
static int endorsement_primary(struct shirudo_tpm *t,
			       const TPM2B_PUBLIC *in_pub, const char *what,
			       struct shirudo_tpm_key *key)
{
	TPM2B_SENSITIVE_CREATE sensitive = {};
	TPML_PCR_SELECTION creation_pcr = {};
	TPM2B_PUBLIC *out_pub = NULL;
	TPM2B_NAME *name = NULL;
	TPM2B_DATA outside = {};
	__u8 computed[SHIRUDO_TPM_NAME_LEN];
	ESYS_TR handle;
	TSS2_RC rc;
	int err;

	memset(key, 0, sizeof(*key));
	rc = Esys_CreatePrimary(t->esys, ESYS_TR_RH_ENDORSEMENT,
				ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
				&sensitive, in_pub, &outside, &creation_pcr,
				&handle, &out_pub, NULL, NULL, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		if (rc_is_auth_failure(rc))
			pr_err("tpm: CreatePrimary(%s): the endorsement "
			       "hierarchy has an auth value (rc=0x%08x)", what,
			       (__u32)rc);
		else
			pr_err("tpm: CreatePrimary(%s): rc=0x%08x", what,
			       (__u32)rc);
		return -EIO;
	}
	key->handle = handle;
	err = public_from_tss(&out_pub->publicArea, key->public,
			      sizeof(key->public), &key->public_len);
	Esys_Free(out_pub);
	if (!err)
		err = tpm_object_name(key->public, key->public_len,
				      computed);
	if (!err) {
		rc = Esys_TR_GetName(t->esys, handle, &name);
		if (rc != TSS2_RC_SUCCESS || name->size != sizeof(computed) ||
		    memcmp(name->name, computed, sizeof(computed)) != 0) {
			pr_err("tpm: %s name does not match its marshalled "
			       "public area", what);
			err = -EPROTO;
		} else {
			memcpy(key->name, name->name, name->size);
			key->name_len = name->size;
		}
		Esys_Free(name);
	}
	if (err)
		tpm_key_flush(t, key);
	return err;
}

int tpm_ak_create(struct shirudo_tpm *t, struct shirudo_tpm_key *ak)
{
	TPM2B_PUBLIC in_pub = {};

	in_pub.publicArea.type = TPM2_ALG_ECC;
	in_pub.publicArea.nameAlg = TPM2_ALG_SHA256;
	in_pub.publicArea.objectAttributes =
		TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
		TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
		TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT;
	in_pub.publicArea.parameters.eccDetail.symmetric.algorithm =
		TPM2_ALG_NULL;
	in_pub.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDSA;
	in_pub.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg =
		TPM2_ALG_SHA256;
	in_pub.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
	in_pub.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
	return endorsement_primary(t, &in_pub, "attestation key", ak);
}

int tpm_ek_create(struct shirudo_tpm *t, bool rsa,
		  struct shirudo_tpm_key *ek)
{
	TPM2B_PUBLIC in_pub = {};
	TPMT_PUBLIC *pub = &in_pub.publicArea;

	pub->type = rsa ? TPM2_ALG_RSA : TPM2_ALG_ECC;
	pub->nameAlg = TPM2_ALG_SHA256;
	pub->objectAttributes = SHIRUDO_TPM_EK_ATTRS;
	pub->authPolicy.size = 32;
	memcpy(pub->authPolicy.buffer, shirudo_tpm_ek_policy, 32);
	if (rsa) {
		TPMS_RSA_PARMS *p = &pub->parameters.rsaDetail;

		p->symmetric.algorithm = TPM2_ALG_AES;
		p->symmetric.keyBits.aes = 128;
		p->symmetric.mode.aes = TPM2_ALG_CFB;
		p->scheme.scheme = TPM2_ALG_NULL;
		p->keyBits = 2048;
		p->exponent = 0;
		pub->unique.rsa.size = 256;
	} else {
		TPMS_ECC_PARMS *p = &pub->parameters.eccDetail;

		p->symmetric.algorithm = TPM2_ALG_AES;
		p->symmetric.keyBits.aes = 128;
		p->symmetric.mode.aes = TPM2_ALG_CFB;
		p->scheme.scheme = TPM2_ALG_NULL;
		p->curveID = TPM2_ECC_NIST_P256;
		p->kdf.scheme = TPM2_ALG_NULL;
		pub->unique.ecc.x.size = 32;
		pub->unique.ecc.y.size = 32;
	}
	return endorsement_primary(t, &in_pub, "endorsement key", ek);
}

void tpm_key_flush(struct shirudo_tpm *t, struct shirudo_tpm_key *key)
{
	if (key->handle != ESYS_TR_NONE && key->handle != 0)
		Esys_FlushContext(t->esys, key->handle);
	explicit_bzero(key, sizeof(*key));
	key->handle = ESYS_TR_NONE;
}

static int attestation_copy(const TPM2B_ATTEST *attest,
			    const TPMT_SIGNATURE *sig,
			    struct shirudo_tpm_attestation *out)
{
	if (attest->size > sizeof(out->attest))
		return -E2BIG;
	memcpy(out->attest, attest->attestationData, attest->size);
	out->attest_len = attest->size;
	return marshal_signature(sig, out->signature, sizeof(out->signature),
				 &out->signature_len);
}

int tpm_quote(struct shirudo_tpm *t, const struct shirudo_tpm_key *ak,
	      const __u8 *nonce, size_t nonce_len, __u32 pcr_mask,
	      struct shirudo_tpm_attestation *out)
{
	TPMT_SIG_SCHEME scheme = { .scheme = TPM2_ALG_NULL };
	TPMT_SIGNATURE *sig = NULL;
	TPM2B_ATTEST *quoted = NULL;
	TPML_PCR_SELECTION sel;
	TPM2B_DATA qual = {};
	TSS2_RC rc;
	int err;

	if (nonce_len > sizeof(qual.buffer))
		return -EINVAL;
	memcpy(qual.buffer, nonce, nonce_len);
	qual.size = (__u16)nonce_len;
	pcr_selection(pcr_mask, &sel);
	rc = Esys_Quote(t->esys, ak->handle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
			ESYS_TR_NONE, &qual, &scheme, &sel, &quoted, &sig);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: Quote: rc=0x%08x", (__u32)rc);
		return -EIO;
	}
	err = attestation_copy(quoted, sig, out);
	Esys_Free(quoted);
	Esys_Free(sig);
	return err;
}

int tpm_nv_certify(struct shirudo_tpm *t,
		   const struct shirudo_tpm_key *ak, __u32 index,
		   const __u8 *nonce, size_t nonce_len,
		   struct shirudo_tpm_attestation *out)
{
	TPMT_SIG_SCHEME scheme = { .scheme = TPM2_ALG_NULL };
	TPMT_SIGNATURE *sig = NULL;
	TPM2B_ATTEST *info = NULL;
	TPM2B_DATA qual = {};
	ESYS_TR nv;
	TSS2_RC rc;
	int err;

	if (nonce_len > sizeof(qual.buffer))
		return -EINVAL;
	memcpy(qual.buffer, nonce, nonce_len);
	qual.size = (__u16)nonce_len;
	err = nv_handle(t, index, &nv);
	if (err)
		return err;
	rc = Esys_NV_Certify(t->esys, ak->handle, nv, nv, ESYS_TR_PASSWORD,
			     ESYS_TR_PASSWORD, ESYS_TR_NONE, &qual, &scheme,
			     SHIRUDO_TPM_NV_DIGEST_LEN, 0, &info, &sig);
	Esys_TR_Close(t->esys, &nv);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: NV_Certify(0x%08x): rc=0x%08x", index,
		       (__u32)rc);
		return rc_is(rc, TPM2_RC_NV_UNINITIALIZED) ? -ENODATA : -EIO;
	}
	err = attestation_copy(info, sig, out);
	Esys_Free(info);
	Esys_Free(sig);
	return err;
}

int tpm_activate_credential(struct shirudo_tpm *t,
			    const struct shirudo_tpm_key *ak,
			    const struct shirudo_tpm_key *ek,
			    const __u8 *blob, size_t blob_len,
			    const __u8 *secret, size_t secret_len,
			    __u8 *out, size_t cap, size_t *out_len)
{
	TPM2B_ENCRYPTED_SECRET sec = {};
	TPM2B_DIGEST *cert_info = NULL;
	ESYS_TR session = ESYS_TR_NONE;
	TPM2B_ID_OBJECT id = {};
	TSS2_RC rc;
	int err;

	if (blob_len > sizeof(id.credential) || secret_len > sizeof(sec.secret))
		return -EINVAL;
	id.size = (__u16)blob_len;
	memcpy(id.credential, blob, blob_len);
	sec.size = (__u16)secret_len;
	memcpy(sec.secret, secret, secret_len);
	err = tpm_policy_session_start(t, &session);
	if (err)
		return err;
	/* The endorsement key's policy: the hierarchy's own authorisation. */
	rc = Esys_PolicySecret(t->esys, ESYS_TR_RH_ENDORSEMENT, session,
			       ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
			       NULL, NULL, NULL, 0, NULL, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: PolicySecret(endorsement): rc=0x%08x",
		       (__u32)rc);
		session_flush(t, session);
		return -EACCES;
	}
	rc = Esys_ActivateCredential(t->esys, ak->handle, ek->handle,
				     ESYS_TR_PASSWORD, session, ESYS_TR_NONE,
				     &id, &sec, &cert_info);
	session_flush(t, session);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: ActivateCredential: rc=0x%08x", (__u32)rc);
		return (rc & 0xFFFF0000u) == 0 ? -EKEYREJECTED : -EIO;
	}
	if (cert_info->size > cap) {
		Esys_Free(cert_info);
		return -E2BIG;
	}
	memcpy(out, cert_info->buffer, cert_info->size);
	*out_len = cert_info->size;
	Esys_Free(cert_info);
	return 0;
}

static int nv_read_all(struct shirudo_tpm *t, __u32 index, __u8 *out,
		       size_t cap, size_t *len)
{
	TPM2B_NV_PUBLIC *pub = NULL;
	size_t off = 0, total;
	ESYS_TR nv;
	TSS2_RC rc;
	int err;

	err = nv_handle(t, index, &nv);
	if (err)
		return err;
	rc = Esys_NV_ReadPublic(t->esys, nv, ESYS_TR_NONE, ESYS_TR_NONE,
				ESYS_TR_NONE, &pub, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		Esys_TR_Close(t->esys, &nv);
		return -EIO;
	}
	total = pub->nvPublic.dataSize;
	Esys_Free(pub);
	if (total > cap) {
		Esys_TR_Close(t->esys, &nv);
		return -E2BIG;
	}
	while (off < total) {
		TPM2B_MAX_NV_BUFFER *data = NULL;
		size_t want = total - off;

		if (want > NV_READ_CHUNK)
			want = NV_READ_CHUNK;
		rc = Esys_NV_Read(t->esys, nv, nv, ESYS_TR_PASSWORD,
				  ESYS_TR_NONE, ESYS_TR_NONE, (UINT16)want,
				  (UINT16)off, &data);
		if (rc != TSS2_RC_SUCCESS) {
			Esys_TR_Close(t->esys, &nv);
			return -EIO;
		}
		if (data->size == 0 || data->size > want) {
			Esys_Free(data);
			Esys_TR_Close(t->esys, &nv);
			return -EIO;
		}
		memcpy(out + off, data->buffer, data->size);
		off += data->size;
		Esys_Free(data);
	}
	Esys_TR_Close(t->esys, &nv);
	*len = total;
	return 0;
}

int tpm_ek_certificate(struct shirudo_tpm *t, __u8 *out,
		       size_t cap, size_t *len, bool *rsa)
{
	int err;

	*rsa = false;
	err = nv_read_all(t, EK_CERT_NV_ECC, out, cap, len);
	if (err == -ENOENT) {
		err = nv_read_all(t, EK_CERT_NV_RSA, out, cap, len);
		*rsa = err == 0;
	}
	return err;
}
