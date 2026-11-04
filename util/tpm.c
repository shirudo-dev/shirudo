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
#include "identity.h"
#include "log.h"
#include "malloc.h"
#include "nv_writer.h"
#include "paths.h"

#define EK_CERT_NV_RSA		0x01C00002u
#define EK_CERT_NV_ECC		0x01C0000Au
#define NV_READ_CHUNK		512u

/* Reads without an authorization handle require an audit session for HMACs. */
static int session_start(struct tpm *t, TPM2_SE type, ESYS_TR *session)
{
	TPMT_SYM_DEF sym = { .algorithm = TPM2_ALG_NULL };
	TPMA_SESSION attrs = TPMA_SESSION_CONTINUESESSION;
	TSS2_RC ret;

	if (type == TPM2_SE_HMAC)
		attrs |= TPMA_SESSION_AUDIT;
	ret = Esys_StartAuthSession(t->esys, t->session_key.handle, ESYS_TR_NONE,
				    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
				    NULL, type, &sym, TPM2_ALG_SHA256, session);
	if (ret == TSS2_RC_SUCCESS)
		ret = Esys_TRSess_SetAttributes(t->esys, *session, attrs, 0xff);
	if (ret != TSS2_RC_SUCCESS) {
		pr_err("tpm: start salted session: rc=0x%08x", (__u32)ret);
		if (*session != ESYS_TR_NONE) {
			Esys_FlushContext(t->esys, *session);
			*session = ESYS_TR_NONE;
		}
		return -EIO;
	}
	return 0;
}

static int session_setup(struct tpm *t, bool active)
{
	struct identity id = {};
	int ret;

	if (active) {
		ret = identity_read(&id);
		if (ret) {
			pr_err("tpm: frozen identity unreadable: %s", strerror(-ret));
			return ret;
		}
		if (id.ek_name[0] || id.ek_name[1] != TPM2_ALG_SHA256) {
			pr_err("tpm: no frozen session key; trusted reboot required");
			return -EACCES;
		}
	}
	ret = tpm_ek_create(t, false, &t->session_key);
	if (ret)
		return ret;
	if (t->session_key.name_len != TPM_NAME_LEN ||
	    (active && memcmp(t->session_key.name, id.ek_name, TPM_NAME_LEN))) {
		pr_err("tpm: not the TPM init bound (session key name differs)");
		return -EACCES;
	}
	return session_start(t, TPM2_SE_HMAC, &t->session);
}

/*
 * Before an authenticated image is active, tests can select a software
 * TPM. Once active, require a device TCTI. The configured device path
 * still needs protection by the deployment.
 */
int tpm_tcti(char *buf, size_t size)
{
	struct config cfg __cleanup(config_clear) = {};
	const char *tcti;
	ssize_t n;

	tcti = image_config_active() ? NULL :
		getenv("SHIRUDO_TPM_TCTI");
	if ((!tcti || !*tcti) && config_load(&cfg) == 0 &&
	    cfg.tpm_tcti[0])
		tcti = cfg.tpm_tcti;
	if (!tcti || !*tcti)
		tcti = "device:/dev/tpmrm0";
	if (image_config_active() && strncmp(tcti, "device:", 7))
		return -EACCES;
	n = strscpy(buf, tcti, size);
	return n < 0 ? (int)n : 0;
}

/* libtss2 debug logs can expose session keys, even during bootstrap. */
static int open_tpm(struct tpm **out, bool quiet)
{
	char tcti[TPM_TCTI_MAX];
	int active, err;
	struct tpm *t;
	TSS2_RC ret;

	active = enforcement_active();
	if (active < 0) {
		pr_err("tpm: cannot determine enforcement state: %s", strerror(-active));
		return active;
	}
	if (setenv("TSS2_LOG", "all+none", 1) || unsetenv("TSS2_LOGFILE")) {
		err = -errno;
		pr_err("tpm: cannot disable library logging: %s", strerror(-err));
		return err;
	}

	err = tpm_tcti(tcti, sizeof(tcti));
	if (err) {
		if (!quiet && err == -EACCES)
			pr_err("tpm: authenticated runtime requires a device TCTI");
		else if (!quiet)
			pr_err("tpm: the TCTI is longer than %d bytes",
			       TPM_TCTI_MAX - 1);
		return err;
	}

	t = xcalloc(1, sizeof(*t));
	if (!t)
		return -ENOMEM;
	t->session = ESYS_TR_NONE;
	t->session_key.handle = ESYS_TR_NONE;
	ret = Tss2_TctiLdr_Initialize(tcti, &t->tcti);
	if (ret != TSS2_RC_SUCCESS) {
		if (!quiet)
			pr_err("tpm: TctiLdr_Initialize(%s): rc=0x%08x", tcti,
			       (__u32)ret);
		xfree(t, sizeof(*t));
		return -EIO;
	}
	ret = Esys_Initialize(&t->esys, t->tcti, NULL);
	if (ret != TSS2_RC_SUCCESS) {
		if (!quiet)
			pr_err("tpm: Esys_Initialize: rc=0x%08x", (__u32)ret);
		Tss2_TctiLdr_Finalize(&t->tcti);
		xfree(t, sizeof(*t));
		return -EIO;
	}
	err = session_setup(t, active);
	if (err) {
		tpm_close(t);
		return err;
	}
	*out = t;
	return 0;
}

int tpm_open(struct tpm **out)
{
	return open_tpm(out, false);
}

int tpm_open_quiet(struct tpm **out)
{
	return open_tpm(out, true);
}

void tpm_close(struct tpm *t)
{
	if (!t)
		return;
	if (t->esys) {
		if (t->session != ESYS_TR_NONE)
			Esys_FlushContext(t->esys, t->session);
		tpm_key_flush(t, &t->session_key);
		Esys_Finalize(&t->esys);
	}
	if (t->tcti)
		Tss2_TctiLdr_Finalize(&t->tcti);
	xfree(t, sizeof(*t));
}

void tpm_ek_name(struct tpm *t, __u8 out[TPM_NAME_LEN])
{
	memcpy(out, t->session_key.name, TPM_NAME_LEN);
}

int tpm_nv_set_writer(struct tpm *t,
		      const __u8 seed[TPM_DIGEST_LEN],
		      const __u8 public[TPM_NV_RSA_BYTES])
{
	if (!t || !seed || !public || !(public[0] & 0x80)) {
		pr_err("tpm: NV writer identity is required");
		return -EACCES;
	}
	memcpy(t->writer_seed, seed, sizeof(t->writer_seed));
	memcpy(t->writer_public, public, sizeof(t->writer_public));
	t->writer_set = true;
	return 0;
}

static bool rc_is(TSS2_RC ret, TSS2_RC code)
{
	if ((ret & 0xFFFF0000u) != 0)
		return false;	/* not a TPM-layer code */
	if (ret & TPM2_RC_FMT1)
		return (ret & 0x0BFu) == (code & 0x0BFu);
	return (ret & 0xFFFu) == code;
}

static bool rc_is_auth_failure(TSS2_RC ret)
{
	return rc_is(ret, TPM2_RC_BAD_AUTH) || rc_is(ret, TPM2_RC_AUTH_FAIL) ||
	       rc_is(ret, TPM2_RC_NV_AUTHORIZATION) ||
	       rc_is(ret, TPM2_RC_POLICY_FAIL);
}

static void pcr_selection(__u32 mask, TPML_PCR_SELECTION *sel)
{
	memset(sel, 0, sizeof(*sel));
	sel->count = 1;
	sel->pcrSelections[0].hash = TPM2_ALG_SHA256;
	sel->pcrSelections[0].sizeofSelect = TPM_PCR_SELECT_LEN;
	sel->pcrSelections[0].pcrSelect[0] = (__u8)mask;
	sel->pcrSelections[0].pcrSelect[1] = (__u8)(mask >> 8);
	sel->pcrSelections[0].pcrSelect[2] = (__u8)(mask >> 16);
}

int tpm_pcr_read(struct tpm *t, __u32 pcr,
		 __u8 out[32])
{
	TPML_PCR_SELECTION sel;
	TPML_DIGEST *values = NULL;
	UINT32 counter;
	TSS2_RC ret;

	if (pcr >= 24)
		return -EINVAL;
	pcr_selection(1u << pcr, &sel);
	ret = Esys_PCR_Read(t->esys, t->session, ESYS_TR_NONE, ESYS_TR_NONE,
			    &sel, &counter, NULL, &values);
	if (ret != TSS2_RC_SUCCESS) {
		pr_err("tpm: PCR_Read(%u): rc=0x%08x", pcr, (__u32)ret);
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

int tpm_pcr_extend(struct tpm *t, __u32 pcr,
		   const __u8 digest[32])
{
	TPML_DIGEST_VALUES dv = { .count = 1 };
	TSS2_RC ret;

	if (pcr >= 24)
		return -EINVAL;
	dv.digests[0].hashAlg = TPM2_ALG_SHA256;
	memcpy(dv.digests[0].digest.sha256, digest, 32);
	ret = Esys_PCR_Extend(t->esys, ESYS_TR_PCR0 + pcr, t->session,
			      ESYS_TR_NONE, ESYS_TR_NONE, &dv);
	if (ret != TSS2_RC_SUCCESS) {
		pr_err("tpm: PCR_Extend(%u): rc=0x%08x", pcr, (__u32)ret);
		return -EIO;
	}
	return 0;
}

int tpm_boot_identity(struct tpm *t, __u32 *reset,
		      __u32 *restart)
{
	TPMS_TIME_INFO *info = NULL;
	TSS2_RC ret;

	if (!t || !reset || !restart)
		return -EINVAL;
	ret = Esys_ReadClock(t->esys, t->session, ESYS_TR_NONE, ESYS_TR_NONE,
			     &info);
	if (ret != TSS2_RC_SUCCESS) {
		pr_err("tpm: ReadClock: rc=0x%08x", (__u32)ret);
		return -EIO;
	}
	*reset = info->clockInfo.resetCount;
	*restart = info->clockInfo.restartCount;
	Esys_Free(info);
	return 0;
}

int tpm_reset_count(struct tpm *t, __u32 *out)
{
	TPMS_TIME_INFO *info = NULL;
	TSS2_RC ret;

	ret = Esys_ReadClock(t->esys, t->session, ESYS_TR_NONE, ESYS_TR_NONE,
			     &info);
	if (ret != TSS2_RC_SUCCESS) {
		pr_err("tpm: ReadClock: rc=0x%08x", (__u32)ret);
		return -EIO;
	}
	*out = info->clockInfo.resetCount;
	Esys_Free(info);
	return 0;
}

static int nv_handle(struct tpm *t, __u32 index, ESYS_TR *out)
{
	TSS2_RC ret;

	ret = Esys_TR_FromTPMPublic(t->esys, index, t->session, ESYS_TR_NONE,
				    ESYS_TR_NONE, out);
	if (rc_is(ret, TPM2_RC_HANDLE))
		return -ENOENT;		/* quiet: undefined is normal */
	if (ret != TSS2_RC_SUCCESS) {
		pr_err("tpm: TR_FromTPMPublic(0x%08x): rc=0x%08x", index,
		       (__u32)ret);
		return -EIO;
	}
	return 0;
}

int tpm_nv_info(struct tpm *t, __u32 index,
		struct tpm_nv_info *info)
{
	TPM2B_NV_PUBLIC *pub = NULL;
	TPM2B_NAME *name = NULL;
	ESYS_TR nv;
	TSS2_RC ret;
	int err;

	memset(info, 0, sizeof(*info));
	err = nv_handle(t, index, &nv);
	if (err == -ENOENT)
		return 0;
	if (err)
		return err;
	ret = Esys_NV_ReadPublic(t->esys, nv, t->session, ESYS_TR_NONE,
				 ESYS_TR_NONE, &pub, &name);
	Esys_TR_Close(t->esys, &nv);
	if (ret != TSS2_RC_SUCCESS) {
		pr_err("tpm: NV_ReadPublic(0x%08x): rc=0x%08x", index,
		       (__u32)ret);
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

static int owner_auth_set(struct tpm *t, const void *auth, size_t len)
{
	TPM2B_AUTH owner = {};
	TSS2_RC ret;

	if (len > sizeof(owner.buffer))
		return -EINVAL;
	if (len) {
		memcpy(owner.buffer, auth, len);
		owner.size = (__u16)len;
	}
	ret = Esys_TR_SetAuth(t->esys, ESYS_TR_RH_OWNER, &owner);
	memzero_explicit(owner.buffer, sizeof(owner.buffer));
	if (ret != TSS2_RC_SUCCESS) {
		pr_err("tpm: TR_SetAuth(owner): rc=0x%08x", (__u32)ret);
		return -EIO;
	}
	return 0;
}

static void owner_auth_clear(struct tpm *t)
{
	TPM2B_AUTH empty = {};

	Esys_TR_SetAuth(t->esys, ESYS_TR_RH_OWNER, &empty);
}

static int owner_auth_error(const char *op, __u32 index, TSS2_RC ret)
{
	if (rc_is_auth_failure(ret)) {
		pr_err("tpm: %s(0x%08x): owner-hierarchy authorization "
		       "failed (rc=0x%08x). This TPM has owner auth set; "
		       "supply it via tpm.owner_auth in %s (or "
		       "SHIRUDO_TPM_OWNER_AUTH), or clear the TPM owner "
		       "auth.", op, index, (__u32)ret, CONF_PATH);
		return -EACCES;
	}
	pr_err("tpm: %s(0x%08x): rc=0x%08x", op, index, (__u32)ret);
	return -EIO;
}

int tpm_nv_define(struct tpm *t, __u32 index,
		  const __u8 policy[32],
		  const void *owner_auth, size_t owner_auth_len)
{
	TPM2B_NV_PUBLIC pub = {};
	TPM2B_AUTH nv_auth = {};
	ESYS_TR nv = ESYS_TR_NONE;
	TSS2_RC ret;
	int err;

	err = owner_auth_set(t, owner_auth, owner_auth_len);
	if (err)
		return err;
	pub.nvPublic.nvIndex = index;
	pub.nvPublic.nameAlg = TPM2_ALG_SHA256;
	pub.nvPublic.attributes = TPM_REGISTER_ATTRS;
	pub.nvPublic.authPolicy.size = 32;
	memcpy(pub.nvPublic.authPolicy.buffer, policy, 32);
	pub.nvPublic.dataSize = TPM_NV_DIGEST_LEN;
	ret = Esys_NV_DefineSpace(t->esys, ESYS_TR_RH_OWNER, t->session,
				  ESYS_TR_NONE, ESYS_TR_NONE, &nv_auth, &pub,
				  &nv);
	owner_auth_clear(t);
	if (ret != TSS2_RC_SUCCESS)
		return owner_auth_error("NV_DefineSpace", index, ret);
	Esys_TR_Close(t->esys, &nv);
	return 0;
}

int tpm_nv_undefine(struct tpm *t, __u32 index,
		    const void *owner_auth, size_t owner_auth_len)
{
	ESYS_TR nv;
	TSS2_RC ret;
	int err;

	err = nv_handle(t, index, &nv);
	if (err)
		return err;
	err = owner_auth_set(t, owner_auth, owner_auth_len);
	if (err) {
		Esys_TR_Close(t->esys, &nv);
		return err;
	}
	ret = Esys_NV_UndefineSpace(t->esys, ESYS_TR_RH_OWNER, nv,
				    t->session, ESYS_TR_NONE,
				    ESYS_TR_NONE);
	owner_auth_clear(t);
	if (ret != TSS2_RC_SUCCESS) {
		Esys_TR_Close(t->esys, &nv);
		return owner_auth_error("NV_UndefineSpace", index, ret);
	}
	return 0;
}

int tpm_nv_read(struct tpm *t, __u32 index, __u8 out[32])
{
	TPM2B_MAX_NV_BUFFER *data = NULL;
	ESYS_TR nv;
	TSS2_RC ret;
	int err;

	err = nv_handle(t, index, &nv);
	if (err)
		return err;
	ret = Esys_NV_Read(t->esys, nv, nv, t->session, ESYS_TR_NONE,
			   ESYS_TR_NONE, TPM_NV_DIGEST_LEN, 0, &data);
	Esys_TR_Close(t->esys, &nv);
	if (rc_is(ret, TPM2_RC_NV_UNINITIALIZED))
		return -ENODATA;	/* quiet: nothing written this boot */
	if (ret != TSS2_RC_SUCCESS) {
		pr_err("tpm: NV_Read(0x%08x): rc=0x%08x", index, (__u32)ret);
		return -EIO;
	}
	if (data->size != TPM_NV_DIGEST_LEN) {
		pr_err("tpm: NV_Read returned %u bytes, expected %u",
		       data->size, TPM_NV_DIGEST_LEN);
		Esys_Free(data);
		return -EIO;
	}
	memcpy(out, data->buffer, TPM_NV_DIGEST_LEN);
	Esys_Free(data);
	return 0;
}

int tpm_policy_session_start(struct tpm *t, ESYS_TR *session)
{
	return session_start(t, TPM2_SE_POLICY, session);
}

static void session_flush(struct tpm *t, ESYS_TR session)
{
	if (session != ESYS_TR_NONE)
		Esys_FlushContext(t->esys, session);
}

int tpm_writer_prepare(struct tpm *t, ESYS_TR session,
		       const __u8 name[TPM_NAME_LEN],
		       const __u8 event[TPM_DIGEST_LEN],
		       struct tpm_writer_authorization *authorization)
{
	TPM2B_NONCE *nonce = NULL;
	TSS2_RC ret;
	int err;

	authorization->cphash.size = TPM_DIGEST_LEN;
	err = tpm_nv_extend_cphash(name, event, authorization->cphash.buffer);
	if (err) {
		pr_err("tpm: compute NV_Extend command hash: %s", strerror(-err));
		return err;
	}
	ret = Esys_TRSess_GetNonceTPM(t->esys, session, &nonce);
	if (ret != TSS2_RC_SUCCESS || !nonce) {
		pr_err("tpm: NV writer PolicySigned: rc=0x%08x", (__u32)ret);
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

/*
 * The salt varies the owner primary each boot. The TPM's owner seed
 * reproduces that key after a reset, while the frozen modulus refuses
 * a replacement made under a different owner seed.
 */
static int tpm_writer_primary(struct tpm *t,
			      const __u8 seed[TPM_DIGEST_LEN],
			      const __u8 expected[TPM_NV_RSA_BYTES],
			      __u8 public[TPM_NV_RSA_BYTES],
			      ESYS_TR *key)
{
	__u8 public_area[TPM_NV_RSA_PUBLIC_AREA_LEN];
	__u8 computed[TPM_NAME_LEN];
	TPML_PCR_SELECTION creation_pcr = {};
	TPM2B_SENSITIVE_CREATE sensitive = {};
	TPM2B_PUBLIC *out_pub = NULL;
	struct config cfg __cleanup(config_clear) = {};
	TPM2B_PUBLIC in_pub = {};
	TPM2B_NAME *name = NULL;
	TPM2B_DATA outside = {};
	TPMT_PUBLIC *p;
	TSS2_RC ret;
	int err;

	*key = ESYS_TR_NONE;
	p = &in_pub.publicArea;
	p->type = TPM2_ALG_RSA;
	p->nameAlg = TPM2_ALG_SHA256;
	p->objectAttributes = TPM_WRITER_ATTRS;
	p->parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
	p->parameters.rsaDetail.scheme.scheme = TPM2_ALG_RSASSA;
	p->parameters.rsaDetail.scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;
	p->parameters.rsaDetail.keyBits = 3072;
	p->parameters.rsaDetail.exponent = 65537;
	p->unique.rsa.size = TPM_DIGEST_LEN;
	memcpy(p->unique.rsa.buffer, seed, TPM_DIGEST_LEN);

	err = config_load(&cfg);
	if (!err)
		err = owner_auth_set(t, cfg.tpm_owner_auth, cfg.tpm_owner_auth_len);
	memzero_explicit(&cfg, sizeof(cfg));
	if (err)
		return err;
	ret = Esys_CreatePrimary(t->esys, ESYS_TR_RH_OWNER,
				 t->session, ESYS_TR_NONE, ESYS_TR_NONE,
				 &sensitive, &in_pub, &outside, &creation_pcr,
				 key, &out_pub, NULL, NULL, NULL);
	owner_auth_clear(t);
	if (ret != TSS2_RC_SUCCESS) {
		pr_err("tpm: CreatePrimary(NV writer): rc=0x%08x", (__u32)ret);
		err = rc_is_auth_failure(ret) ? -EACCES : -EIO;
		goto cleanup;
	}
	if (!out_pub) {
		err = -EPROTO;
		goto out;
	}
	p = &out_pub->publicArea;
	if (p->type != TPM2_ALG_RSA || p->nameAlg != TPM2_ALG_SHA256 ||
	    p->objectAttributes != TPM_WRITER_ATTRS ||
	    p->authPolicy.size ||
	    p->parameters.rsaDetail.symmetric.algorithm != TPM2_ALG_NULL ||
	    p->parameters.rsaDetail.scheme.scheme != TPM2_ALG_RSASSA ||
	    p->parameters.rsaDetail.scheme.details.rsassa.hashAlg != TPM2_ALG_SHA256 ||
	    p->parameters.rsaDetail.keyBits != 3072 ||
	    p->parameters.rsaDetail.exponent != 65537 ||
	    p->unique.rsa.size != TPM_NV_RSA_BYTES) {
		err = -EPROTO;
		goto out;
	}
	memcpy(public, p->unique.rsa.buffer, TPM_NV_RSA_BYTES);
	if (expected && memcmp(public, expected, TPM_NV_RSA_BYTES)) {
		err = -EKEYREJECTED;
		goto out;
	}
	tpm_writer_public(public, public_area);
	err = tpm_object_name(public_area, sizeof(public_area), computed);
	if (err)
		goto out;
	ret = Esys_TR_GetName(t->esys, *key, &name);
	if (ret != TSS2_RC_SUCCESS || !name ||
	    name->size != sizeof(computed) ||
	    memcmp(name->name, computed, sizeof(computed)))
		err = -EPROTO;
out:
	if (err)
		pr_err("tpm: NV writer public key differs from the expected key");
cleanup:
	Esys_Free(name);
	Esys_Free(out_pub);
	if (err) {
		session_flush(t, *key);
		*key = ESYS_TR_NONE;
	}
	return err;
}

int tpm_writer_load(struct tpm *t,
		    const __u8 seed[TPM_DIGEST_LEN],
		    const __u8 expected_public[TPM_NV_RSA_BYTES],
		    ESYS_TR *key)
{
	__u8 public[TPM_NV_RSA_BYTES];

	return tpm_writer_primary(t, seed, expected_public, public, key);
}

int tpm_writer_create(struct tpm *t,
		      const __u8 seed[TPM_DIGEST_LEN],
		      __u8 public[TPM_NV_RSA_BYTES])
{
	ESYS_TR key = ESYS_TR_NONE;
	int err;

	err = tpm_writer_primary(t, seed, NULL, public, &key);
	session_flush(t, key);
	return err;
}

static int tpm_writer_sign(struct tpm *t, ESYS_TR key,
			   const __u8 hash[TPM_DIGEST_LEN],
			   __u8 out[TPM_NV_RSA_BYTES])
{
	TPMT_TK_HASHCHECK validation = {
		.tag = TPM2_ST_HASHCHECK,
		.hierarchy = TPM2_RH_NULL,
	};
	TPMT_SIG_SCHEME scheme = { .scheme = TPM2_ALG_RSASSA };
	TPMT_SIGNATURE *signature = NULL;
	TPM2B_DIGEST digest = {
		.size = TPM_DIGEST_LEN,
	};
	TSS2_RC ret;
	int err = 0;

	memcpy(digest.buffer, hash, TPM_DIGEST_LEN);
	scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;
	ret = Esys_Sign(t->esys, key, t->session, ESYS_TR_NONE,
			ESYS_TR_NONE, &digest, &scheme, &validation, &signature);
	if (ret != TSS2_RC_SUCCESS) {
		pr_err("tpm: Sign(NV writer): rc=0x%08x", (__u32)ret);
		err = -EACCES;
	} else if (!signature || signature->sigAlg != TPM2_ALG_RSASSA ||
		   signature->signature.rsassa.hash != TPM2_ALG_SHA256 ||
		   signature->signature.rsassa.sig.size != TPM_NV_RSA_BYTES) {
		err = -EPROTO;
	} else {
		memcpy(out, signature->signature.rsassa.sig.buffer,
		       TPM_NV_RSA_BYTES);
	}
	Esys_Free(signature);
	return err;
}

TSS2_RC tpm_writer_authorize(struct tpm *t, ESYS_TR key, ESYS_TR session,
			     const struct tpm_writer_authorization *authorization,
			     const __u8 signature[TPM_NV_RSA_BYTES])
{
	TPM2B_NONCE ref = { .size = sizeof(TPM_NV_POLICY_REF) - 1 };
	TPMT_SIGNATURE sig = { .sigAlg = TPM2_ALG_RSASSA };
	TPM2B_TIMEOUT *timeout = NULL;
	TPMT_TK_AUTH *ticket = NULL;
	TSS2_RC ret;

	sig.signature.rsassa.hash = TPM2_ALG_SHA256;
	sig.signature.rsassa.sig.size = TPM_NV_RSA_BYTES;
	memcpy(sig.signature.rsassa.sig.buffer, signature, TPM_NV_RSA_BYTES);
	memcpy(ref.buffer, TPM_NV_POLICY_REF, ref.size);
	ret = Esys_PolicySigned(t->esys, key, session, ESYS_TR_NONE,
				ESYS_TR_NONE, ESYS_TR_NONE, &authorization->nonce,
				&authorization->cphash, &ref, 0, &sig, &timeout, &ticket);
	Esys_Free(timeout);
	Esys_Free(ticket);
	return ret;
}

static int policy_writer_signed(struct tpm *t, ESYS_TR session,
				__u32 index, const __u8 event[32])
{
	struct tpm_writer_authorization authorization = {};
	__u8 signature[TPM_NV_RSA_BYTES] = {};
	__u8 public[TPM_NV_RSA_BYTES];
	ESYS_TR key = ESYS_TR_NONE;
	struct tpm_nv_info nv;
	TSS2_RC ret;
	int err;

	if (!t->writer_set)
		return -EKEYREJECTED;
	err = tpm_nv_info(t, index, &nv);
	if (err)
		return err;
	if (!nv.defined || nv.name_len != TPM_NAME_LEN) {
		pr_err("tpm: NV writer requires a defined register");
		return -ENODEV;
	}
	err = tpm_writer_prepare(t, session, nv.name, event, &authorization);
	if (err)
		return err;
	err = tpm_writer_primary(t, t->writer_seed, t->writer_public, public, &key);
	if (err)
		return err;
	err = tpm_writer_sign(t, key, authorization.digest, signature);
	if (err)
		goto out;
	ret = tpm_writer_authorize(t, key, session, &authorization, signature);
	if (ret != TSS2_RC_SUCCESS) {
		pr_err("tpm: NV writer PolicySigned: rc=0x%08x", (__u32)ret);
		err = -EACCES;
	}
out:
	session_flush(t, key);
	memzero_explicit(signature, sizeof(signature));
	return err;
}

int tpm_policy_session_finish(struct tpm *t, ESYS_TR session,
			      const __u8 expected[TPM_DIGEST_LEN])
{
	TPM2B_DIGEST *digest = NULL;
	TSS2_RC ret;
	int err = 0;

	ret = Esys_PolicyCommandCode(t->esys, session, ESYS_TR_NONE,
				     ESYS_TR_NONE, ESYS_TR_NONE, TPM2_CC_NV_Extend);
	if (ret != TSS2_RC_SUCCESS) {
		pr_err("tpm: register policy assertion: rc=0x%08x", (__u32)ret);
		return -EACCES;
	}
	ret = Esys_PolicyGetDigest(t->esys, session, t->session,
				   ESYS_TR_NONE, ESYS_TR_NONE, &digest);
	if (ret != TSS2_RC_SUCCESS || !digest || digest->size != TPM_DIGEST_LEN ||
	    memcmp(digest->buffer, expected, TPM_DIGEST_LEN)) {
		pr_err("tpm: register policy digest does not match the "
		       "computed policy (rc=0x%08x)", (__u32)ret);
		err = -EPROTO;
	}
	Esys_Free(digest);
	return err;
}

/*
 * Walk one branch of the register's write policy in a real session and
 * authorize the exact NV_Extend with the TPM-held writer after PolicyOR.
 * Compare the session digest with the software policy to detect drift.
 */
static int policy_session_register(struct tpm *t, bool init,
				   __u32 index, const __u8 event[32],
				   __u32 pcr_mask,
				   const __u8 branch_written[32],
				   const __u8 branch_init[32],
				   ESYS_TR *session)
{
	TPML_DIGEST branches = { .count = 2 };
	__u8 expected[32];
	TSS2_RC ret;
	int err;

	if (!t->writer_set) {
		pr_err("tpm: register policy requires the NV writer public key");
		return -EACCES;
	}
	err = tpm_policy_session_start(t, session);
	if (err)
		return err;
	ret = Esys_PolicyNvWritten(t->esys, *session, ESYS_TR_NONE, ESYS_TR_NONE,
				   ESYS_TR_NONE, init ? TPM2_NO : TPM2_YES);
	if (ret == TSS2_RC_SUCCESS && init) {
		TPM2B_DIGEST live = {};
		TPML_PCR_SELECTION sel;

		pcr_selection(pcr_mask, &sel);
		ret = Esys_PolicyPCR(t->esys, *session, ESYS_TR_NONE,
				     ESYS_TR_NONE, ESYS_TR_NONE, &live, &sel);
	}
	if (ret == TSS2_RC_SUCCESS) {
		branches.digests[0].size = 32;
		memcpy(branches.digests[0].buffer, branch_written, 32);
		branches.digests[1].size = 32;
		memcpy(branches.digests[1].buffer, branch_init, 32);
		ret = Esys_PolicyOR(t->esys, *session, ESYS_TR_NONE,
				    ESYS_TR_NONE, ESYS_TR_NONE, &branches);
	}
	if (ret == TSS2_RC_SUCCESS) {
		err = policy_writer_signed(t, *session, index, event);
		if (err) {
			session_flush(t, *session);
			*session = ESYS_TR_NONE;
			return err;
		}
	}
	if (ret != TSS2_RC_SUCCESS) {
		if (rc_is(ret, TPM2_RC_VALUE) && init)
			pr_err("tpm: the anchoring PCR moved; the register "
			       "can only be initialised in the boot window");
		else
			pr_err("tpm: register policy assertion: rc=0x%08x",
			       (__u32)ret);
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

static int nv_extend_session(struct tpm *t, __u32 index,
			     ESYS_TR session, const __u8 event[32])
{
	TPM2B_MAX_NV_BUFFER data = { .size = TPM_NV_DIGEST_LEN };
	ESYS_TR nv;
	TSS2_RC ret;
	int err;

	err = nv_handle(t, index, &nv);
	if (err)
		return err;
	memcpy(data.buffer, event, TPM_NV_DIGEST_LEN);
	ret = Esys_NV_Extend(t->esys, nv, nv, session, ESYS_TR_NONE,
			     ESYS_TR_NONE, &data);
	Esys_TR_Close(t->esys, &nv);
	if (ret != TSS2_RC_SUCCESS) {
		pr_err("tpm: NV_Extend(0x%08x): rc=0x%08x", index,
		       (__u32)ret);
		return rc_is_auth_failure(ret) ? -EACCES : -EIO;
	}
	return 0;
}

int tpm_nv_extend_first(struct tpm *t, __u32 index,
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

int tpm_nv_extend(struct tpm *t, __u32 index,
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
	struct tpm_public pub = {};

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
	put_be16(out + off, sig->sigAlg);
	off += 2;
	put_be16(out + off, e->hash);
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
static int endorsement_primary(struct tpm *t,
			       const TPM2B_PUBLIC *in_pub, const char *what,
			       struct tpm_key *key)
{
	TPM2B_SENSITIVE_CREATE sensitive = {};
	TPML_PCR_SELECTION creation_pcr = {};
	TPM2B_PUBLIC *out_pub = NULL;
	TPM2B_NAME *name = NULL;
	TPM2B_DATA outside = {};
	__u8 computed[TPM_NAME_LEN];
	ESYS_TR handle;
	TSS2_RC ret;
	int err;

	memset(key, 0, sizeof(*key));
	ret = Esys_CreatePrimary(t->esys, ESYS_TR_RH_ENDORSEMENT,
				 t->session == ESYS_TR_NONE ?
					 ESYS_TR_PASSWORD : t->session,
				 ESYS_TR_NONE, ESYS_TR_NONE,
				 &sensitive, in_pub, &outside, &creation_pcr,
				 &handle, &out_pub, NULL, NULL, NULL);
	if (ret != TSS2_RC_SUCCESS) {
		if (rc_is_auth_failure(ret))
			pr_err("tpm: CreatePrimary(%s): the endorsement "
			       "hierarchy has an auth value (rc=0x%08x)", what,
			       (__u32)ret);
		else
			pr_err("tpm: CreatePrimary(%s): rc=0x%08x", what,
			       (__u32)ret);
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
		ret = Esys_TR_GetName(t->esys, handle, &name);
		if (ret != TSS2_RC_SUCCESS || name->size != sizeof(computed) ||
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

int tpm_ak_create(struct tpm *t, struct tpm_key *ak)
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

int tpm_ek_create(struct tpm *t, bool rsa,
		  struct tpm_key *ek)
{
	TPM2B_PUBLIC in_pub = {};
	TPMT_PUBLIC *pub = &in_pub.publicArea;

	pub->type = rsa ? TPM2_ALG_RSA : TPM2_ALG_ECC;
	pub->nameAlg = TPM2_ALG_SHA256;
	pub->objectAttributes = TPM_EK_ATTRS;
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

void tpm_key_flush(struct tpm *t, struct tpm_key *key)
{
	if (key->handle != ESYS_TR_NONE && key->handle != 0)
		Esys_FlushContext(t->esys, key->handle);
	memzero_explicit(key, sizeof(*key));
	key->handle = ESYS_TR_NONE;
}

static int attestation_copy(const TPM2B_ATTEST *attest,
			    const TPMT_SIGNATURE *sig,
			    struct tpm_attestation *out)
{
	if (attest->size > sizeof(out->attest))
		return -E2BIG;
	memcpy(out->attest, attest->attestationData, attest->size);
	out->attest_len = attest->size;
	return marshal_signature(sig, out->signature, sizeof(out->signature),
				 &out->signature_len);
}

int tpm_quote(struct tpm *t, const struct tpm_key *ak,
	      const __u8 *nonce, size_t nonce_len, __u32 pcr_mask,
	      struct tpm_attestation *out)
{
	TPMT_SIG_SCHEME scheme = { .scheme = TPM2_ALG_NULL };
	TPMT_SIGNATURE *sig = NULL;
	TPM2B_ATTEST *quoted = NULL;
	TPML_PCR_SELECTION sel;
	TPM2B_DATA qual = {};
	TSS2_RC ret;
	int err;

	if (nonce_len > sizeof(qual.buffer))
		return -EINVAL;
	memcpy(qual.buffer, nonce, nonce_len);
	qual.size = (__u16)nonce_len;
	pcr_selection(pcr_mask, &sel);
	ret = Esys_Quote(t->esys, ak->handle, t->session, ESYS_TR_NONE,
			 ESYS_TR_NONE, &qual, &scheme, &sel, &quoted, &sig);
	if (ret != TSS2_RC_SUCCESS) {
		pr_err("tpm: Quote: rc=0x%08x", (__u32)ret);
		return -EIO;
	}
	err = attestation_copy(quoted, sig, out);
	Esys_Free(quoted);
	Esys_Free(sig);
	return err;
}

int tpm_nv_certify(struct tpm *t,
		   const struct tpm_key *ak, __u32 index,
		   const __u8 *nonce, size_t nonce_len,
		   struct tpm_attestation *out)
{
	TPMT_SIG_SCHEME scheme = { .scheme = TPM2_ALG_NULL };
	TPMT_SIGNATURE *sig = NULL;
	TPM2B_ATTEST *info = NULL;
	TPM2B_DATA qual = {};
	ESYS_TR nv;
	TSS2_RC ret;
	int err;

	if (nonce_len > sizeof(qual.buffer))
		return -EINVAL;
	memcpy(qual.buffer, nonce, nonce_len);
	qual.size = (__u16)nonce_len;
	err = nv_handle(t, index, &nv);
	if (err)
		return err;
	ret = Esys_NV_Certify(t->esys, ak->handle, nv, nv, t->session,
			      ESYS_TR_PASSWORD, ESYS_TR_NONE, &qual, &scheme,
			      TPM_NV_DIGEST_LEN, 0, &info, &sig);
	Esys_TR_Close(t->esys, &nv);
	if (ret != TSS2_RC_SUCCESS) {
		pr_err("tpm: NV_Certify(0x%08x): rc=0x%08x", index,
		       (__u32)ret);
		return rc_is(ret, TPM2_RC_NV_UNINITIALIZED) ? -ENODATA : -EIO;
	}
	err = attestation_copy(info, sig, out);
	Esys_Free(info);
	Esys_Free(sig);
	return err;
}

int tpm_activate_credential(struct tpm *t,
			    const struct tpm_key *ak,
			    const struct tpm_key *ek,
			    const __u8 *blob, size_t blob_len,
			    const __u8 *secret, size_t secret_len,
			    __u8 *out, size_t cap, size_t *out_len)
{
	TPM2B_ENCRYPTED_SECRET sec = {};
	TPM2B_DIGEST *cert_info = NULL;
	ESYS_TR session = ESYS_TR_NONE;
	TPM2B_ID_OBJECT id = {};
	TSS2_RC ret;
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
	ret = Esys_PolicySecret(t->esys, ESYS_TR_RH_ENDORSEMENT, session,
				t->session, ESYS_TR_NONE, ESYS_TR_NONE,
				NULL, NULL, NULL, 0, NULL, NULL);
	if (ret != TSS2_RC_SUCCESS) {
		pr_err("tpm: PolicySecret(endorsement): rc=0x%08x",
		       (__u32)ret);
		session_flush(t, session);
		return -EACCES;
	}
	ret = Esys_ActivateCredential(t->esys, ak->handle, ek->handle,
				      t->session, session, ESYS_TR_NONE,
				      &id, &sec, &cert_info);
	session_flush(t, session);
	if (ret != TSS2_RC_SUCCESS) {
		pr_err("tpm: ActivateCredential: rc=0x%08x", (__u32)ret);
		return (ret & 0xFFFF0000u) == 0 ? -EKEYREJECTED : -EIO;
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

static int nv_read_all(struct tpm *t, __u32 index, __u8 *out,
		       size_t cap, size_t *len)
{
	TPM2B_NV_PUBLIC *pub = NULL;
	size_t off = 0, total;
	ESYS_TR nv;
	TSS2_RC ret;
	int err;

	err = nv_handle(t, index, &nv);
	if (err)
		return err;
	ret = Esys_NV_ReadPublic(t->esys, nv, t->session, ESYS_TR_NONE,
				 ESYS_TR_NONE, &pub, NULL);
	if (ret != TSS2_RC_SUCCESS) {
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
		ret = Esys_NV_Read(t->esys, nv, nv, t->session,
				   ESYS_TR_NONE, ESYS_TR_NONE, (UINT16)want,
				   (UINT16)off, &data);
		if (ret != TSS2_RC_SUCCESS) {
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

int tpm_ek_certificate(struct tpm *t, __u8 *out,
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
