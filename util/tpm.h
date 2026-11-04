/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * libtss2 wrappers for the measurement register and attestation.
 */

#ifndef SHIRUDO_TPM_H
#define SHIRUDO_TPM_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/misc.h>

#include "tpm_wire.h"

#define TPM_NV_DIGEST_LEN	TPM_DIGEST_LEN
#define TPM_PUBLIC_MAX		512
#define TPM_ATTEST_MAX		1024
#define TPM_SIGNATURE_MAX	160

struct tpm;

int tpm_tcti(char *buf, size_t size);
int tpm_open(struct tpm **out);
int tpm_open_quiet(struct tpm **out);
void tpm_close(struct tpm *t);
void tpm_ek_name(struct tpm *t, __u8 out[TPM_NAME_LEN]);

int tpm_writer_create(struct tpm *t,
		      const __u8 seed[TPM_DIGEST_LEN],
		      __u8 public[TPM_NV_RSA_BYTES]);
int tpm_nv_set_writer(struct tpm *t,
		      const __u8 seed[TPM_DIGEST_LEN],
		      const __u8 public[TPM_NV_RSA_BYTES]);

int tpm_pcr_read(struct tpm *t, __u32 pcr,
		 __u8 out[TPM_DIGEST_LEN]);
int tpm_pcr_extend(struct tpm *t, __u32 pcr,
		   const __u8 digest[TPM_DIGEST_LEN]);

/*
 * The TPM's reset count, a new value at every TPM reset: the identity
 * of the period a clear-on-reset index lives through.
 */
int tpm_reset_count(struct tpm *t, __u32 *out);
int tpm_boot_identity(struct tpm *t, __u32 *reset,
		      __u32 *restart);

struct tpm_nv_info {
	bool		defined;
	bool		written;
	__u32		attrs;
	__u16		data_size;
	__u8		policy[TPM_DIGEST_LEN];
	__u8		name[TPM_NAME_LEN];
	size_t		name_len;
};

/*
 * The measurement register is an NV index with the attributes and the
 * write policy from tpm_wire.h. Defining and undefining it is owner
 * authorised; owner_auth/owner_auth_len carry that hierarchy's
 * password when set, NULL/0 for the empty default. Reads need no
 * authorisation. Extends present one of the two policy branches:
 * the first write of a boot the init branch, which TPM2_PolicyPCR
 * only satisfies while the anchoring PCR still holds the value the
 * policy was computed from, every later one the written branch.
 * Both branches require the TPM writer's command-bound signature;
 * extending requires nv_set_writer first.
 */
int tpm_nv_info(struct tpm *t, __u32 index,
		struct tpm_nv_info *info);
int tpm_nv_define(struct tpm *t, __u32 index,
		  const __u8 policy[TPM_DIGEST_LEN],
		  const void *owner_auth, size_t owner_auth_len);
int tpm_nv_undefine(struct tpm *t, __u32 index,
		    const void *owner_auth, size_t owner_auth_len);
/* -ENOENT: not defined; -ENODATA: defined but not written this boot. */
int tpm_nv_read(struct tpm *t, __u32 index,
		__u8 out[TPM_DIGEST_LEN]);
int tpm_nv_extend_first(struct tpm *t, __u32 index,
			__u32 pcr_mask,
			const __u8 branch_written[32],
			const __u8 branch_init[32],
			const __u8 event[32]);
int tpm_nv_extend(struct tpm *t, __u32 index,
		  const __u8 branch_written[32],
		  const __u8 branch_init[32],
		  const __u8 event[32]);

/*
 * The attestation key: a restricted P-256 ECDSA primary under the
 * endorsement hierarchy with a fixed template, so the same TPM always
 * yields the same key and an operator can pin it by name.
 */
struct tpm_key {
	__u32		handle;
	__u8		public[TPM_PUBLIC_MAX];
	size_t		public_len;
	__u8		name[TPM_NAME_LEN];
	size_t		name_len;
};

struct tpm_attestation {
	__u8		attest[TPM_ATTEST_MAX];
	size_t		attest_len;
	__u8		signature[TPM_SIGNATURE_MAX];
	size_t		signature_len;
};

int tpm_ak_create(struct tpm *t, struct tpm_key *ak);

/*
 * The endorsement key from the TCG default template of the given
 * type, the key the TPM's endorsement certificate describes.
 */
int tpm_ek_create(struct tpm *t, bool rsa,
		  struct tpm_key *ek);

/*
 * TPM2_ActivateCredential: recover the credential an operator
 * protected for the key ak under the endorsement key ek.
 * -EKEYREJECTED when the TPM refuses it, as it does for a blob made
 * for another key or another TPM.
 */
int tpm_activate_credential(struct tpm *t,
			    const struct tpm_key *ak,
			    const struct tpm_key *ek,
			    const __u8 *blob, size_t blob_len,
			    const __u8 *secret, size_t secret_len,
			    __u8 *out, size_t cap, size_t *out_len);
void tpm_key_flush(struct tpm *t, struct tpm_key *key);
int tpm_quote(struct tpm *t, const struct tpm_key *ak,
	      const __u8 *nonce, size_t nonce_len, __u32 pcr_mask,
	      struct tpm_attestation *out);
int tpm_nv_certify(struct tpm *t,
		   const struct tpm_key *ak, __u32 index,
		   const __u8 *nonce, size_t nonce_len,
		   struct tpm_attestation *out);

/*
 * The endorsement key certificate from its TCG NV index, the ECC one
 * first; *rsa tells which key it describes. -ENOENT if none.
 */
int tpm_ek_certificate(struct tpm *t, __u8 *out,
		       size_t cap, size_t *len, bool *rsa);

#endif /* SHIRUDO_TPM_H */
