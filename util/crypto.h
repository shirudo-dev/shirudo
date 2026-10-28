/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The crypto interface of both profiles, on OpenSSL alone, so every key
 * algorithm the kernel verifies and the hybrid key exchange come from
 * one implementation.
 */

#ifndef SHIRUDO_CRYPTO_H
#define SHIRUDO_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>

#include <curl/curl.h>

#include <shirudo/misc.h>

#define SHIRUDO_CRYPTO_SHA256_LEN 32

struct shirudo_sha256_ctx {
	void *impl;
};

int sha256_init(struct shirudo_sha256_ctx *ctx);
int sha256_update(struct shirudo_sha256_ctx *ctx,
		  const void *data, size_t len);
int sha256_final(struct shirudo_sha256_ctx *ctx,
		 __u8 out[SHIRUDO_CRYPTO_SHA256_LEN]);
void sha256_free(struct shirudo_sha256_ctx *ctx);
int sha256_buffer(const void *data, size_t len,
		  __u8 out[SHIRUDO_CRYPTO_SHA256_LEN]);
int base64_encode(const __u8 *data, size_t len,
		  char *out, size_t out_sz);

/* 0 when valid, -EKEYREJECTED when not. */
int ecdsa_p256_verify(const __u8 x[32], const __u8 y[32],
		      const __u8 digest[SHIRUDO_CRYPTO_SHA256_LEN],
		      const __u8 r[32], const __u8 s[32]);

struct shirudo_cert {
	void *impl;
};

int cert_read_file(const char *path, struct shirudo_cert *cert);
void cert_free(struct shirudo_cert *cert);
int cert_pubkey_digest(const struct shirudo_cert *cert,
		       __u8 out[SHIRUDO_CRYPTO_SHA256_LEN]);
/* The provider's name for the cert's public key, e.g. "ML-DSA-87". */
int cert_key_algorithm(const struct shirudo_cert *cert,
		       char *out, size_t out_sz);
int verify_detached(const __u8 *payload, size_t payload_len,
		    const __u8 *signature, size_t signature_len,
		    const struct shirudo_cert *cert);
/*
 * Whether a signer of the CMS blob names this certificate, by key id
 * or by issuer and serial: 1 when one does, 0 when none, -EINVAL when
 * the blob does not parse. Says nothing about the signature's validity.
 */
int cms_signed_by(const __u8 *signature, size_t signature_len,
		  const struct shirudo_cert *cert);

struct shirudo_tls_ca {
	const char *path;
	void *impl;
};

void tls_ca_cleanup(struct shirudo_tls_ca *ca);

/*
 * shirudo's TLS policy for every libcurl handle it opens: TLS 1.3 only
 * and hybrid ML-KEM key exchange by default. Exact hosts in
 * tls.classical_hosts may also negotiate classical groups, from the
 * immutable runtime config on targets or root-managed host config on
 * operator commands. This setting does not change certificate
 * verification. ca may be NULL; otherwise it
 * is the extra trust anchor fed to the SSL_CTX callback. Returns 0 or a
 * negative errno; callers must not connect when it fails.
 */
int tls_curl_policy(CURL *curl, struct shirudo_tls_ca *ca);

int hmac_sha256(const __u8 *key, size_t key_len,
		const void *data, size_t len,
		__u8 out[SHIRUDO_CRYPTO_SHA256_LEN]);

/* AES-128 in CFB mode with a zero IV and no padding. */
int aes128_cfb_encrypt(const __u8 key[16], const __u8 *in,
		       size_t len, __u8 *out);

/*
 * RSA-OAEP with SHA-256, MGF1-SHA-256 and the given label to the
 * modulus n with the public exponent e (0 for 65537).
 */
int rsa_oaep_encrypt(const __u8 *n, size_t n_len, __u32 e,
		     const void *label, size_t label_len,
		     const __u8 *in, size_t in_len,
		     __u8 *out, size_t cap, size_t *out_len);

/*
 * One ephemeral P-256 ECDH against the point (x, y): the ephemeral
 * public point and the shared secret's x coordinate.
 */
int ecdh_p256_ephemeral(const __u8 x[32], const __u8 y[32],
			__u8 eph_x[32], __u8 eph_y[32],
			__u8 z[32]);

int base64_decode(const char *in, size_t in_len, __u8 *out,
		  size_t cap, size_t *out_len);

int cert_read_der(const __u8 *der, size_t len,
		  struct shirudo_cert *cert);

struct cert_pubkey {
	bool		rsa;
	__u8		n[512];
	size_t		n_len;
	__u32		e;
	__u8		x[32];
	__u8		y[32];
};

int cert_pubkey(const struct shirudo_cert *cert,
		struct cert_pubkey *out);

/*
 * Chain the certificate to the PEM bundle of trusted issuers at path.
 * -EKEYREJECTED when it does not chain, with *reason set to libcrypto's
 * static explanation; -EINVAL when the bundle cannot be loaded.
 */
int cert_verify_chain(const struct shirudo_cert *cert,
		      const char *bundle_path, const char **reason);

/* Log libcrypto's last error under where. */
void openssl_complain(const char *where);

#endif /* SHIRUDO_CRYPTO_H */
