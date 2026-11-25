// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "crypto.h"
#include "hex.h"
#include "malloc.h"
#include "unit.h"

static void sha256_matches_fips_180_vector(void)
{
	static const char want[] =
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
	char hex[2 * CRYPTO_SHA256_LEN + 1];
	__u8 d[CRYPTO_SHA256_LEN];

	ASSERT_EQ(sha256_buffer("abc", 3, d), 0);
	hex_encode(d, sizeof(d), hex);
	EXPECT_STREQ(hex, want);
}

static void sha256_buffer_zeroes_a_failed_digest(void)
{
	__u8 out[CRYPTO_SHA256_LEN], zero[CRYPTO_SHA256_LEN] = {};

	memset(out, 0xff, sizeof(out));
	EXPECT_NE(sha256_buffer(NULL, 3, out), 0);
	EXPECT_MEMEQ(out, zero, sizeof(out));
}

static EVP_PKEY *keygen(const char *alg)
{
	EVP_PKEY *key;

	if (!strcmp(alg, "EC"))
		key = EVP_EC_gen("P-256");
	else
		key = EVP_PKEY_Q_keygen(NULL, NULL, alg);
	ASSERT_TRUE(key);
	return key;
}

/* With a subject key identifier, which a keyid signer is named by. */
static X509 *self_signed(EVP_PKEY *key)
{
	const EVP_MD *md = EVP_PKEY_is_a(key, "EC") ? EVP_sha256() : NULL;
	X509V3_CTX ctx = {};
	X509 *x = X509_new();
	X509_EXTENSION *ski;
	X509_NAME *name;

	ASSERT_TRUE(x);
	ASSERT_EQ(X509_set_version(x, X509_VERSION_3), 1);
	ASSERT_EQ(ASN1_INTEGER_set(X509_get_serialNumber(x), 1), 1);
	ASSERT_TRUE(X509_gmtime_adj(X509_getm_notBefore(x), 0));
	ASSERT_TRUE(X509_gmtime_adj(X509_getm_notAfter(x), 86400));
	ASSERT_EQ(X509_set_pubkey(x, key), 1);
	name = X509_get_subject_name(x);
	ASSERT_EQ(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
					     (const __u8 *)"unit", -1, -1, 0), 1);
	ASSERT_EQ(X509_set_issuer_name(x, name), 1);
	X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
	ski = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier,
				  "hash");
	ASSERT_TRUE(ski);
	ASSERT_EQ(X509_add_ext(x, ski, -1), 1);
	X509_EXTENSION_free(ski);
	ASSERT_TRUE(X509_sign(x, key, md) > 0);
	return x;
}

/* The DER of x, which the caller frees with OPENSSL_free(). */
static size_t der_of(X509 *x, __u8 **der)
{
	int len;

	*der = NULL;
	len = i2d_X509(x, der);
	ASSERT_TRUE(len > 0);
	return (size_t)len;
}

static void read_cert(X509 *x, struct cert *cert)
{
	__u8 *der;
	size_t len;

	len = der_of(x, &der);
	ASSERT_EQ(cert_read_der(der, len, cert), 0);
	OPENSSL_free(der);
}

/* cert_der_require_mldsa87() on a self-signed certificate of alg. */
static int require_mldsa87(const char *alg, char *name, size_t name_sz)
{
	EVP_PKEY *key = keygen(alg);
	X509 *x = self_signed(key);
	__u8 *der;
	size_t len;
	int ret;

	len = der_of(x, &der);
	ret = cert_der_require_mldsa87(der, len, name, name_sz);
	OPENSSL_free(der);
	X509_free(x);
	EVP_PKEY_free(key);
	return ret;
}

static void cert_require_mldsa87_accepts_ml_dsa_87_only(void)
{
	static const struct {
		const char	*alg;
		int		ret;
	} keys[] = {
		{ "ML-DSA-87", 0 },
		{ "ML-DSA-65", -EKEYREJECTED },
		{ "EC", -EKEYREJECTED },
	};
	size_t i;

	EXPECT_EQ(cert_require_mldsa87(NULL, NULL, 0), -EKEYREJECTED);
	EXPECT_EQ(cert_require_mldsa87(NULL, NULL, 32), -EKEYREJECTED);
	for (i = 0; i < ARRAY_SIZE(keys); i++) {
		EVP_PKEY *key = keygen(keys[i].alg);
		X509 *x = self_signed(key);
		struct cert cert = {};

		read_cert(x, &cert);
		EXPECT_EQ(cert_require_mldsa87(&cert, NULL, 0), keys[i].ret);
		cert_free(&cert);
		X509_free(x);
		EVP_PKEY_free(key);
	}
}

static void cert_der_require_mldsa87_names_a_refused_algorithm(void)
{
	static const __u8 no_cert[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
	char name[32] = {};
	int ret;

	EXPECT_EQ(require_mldsa87("ML-DSA-87", name, sizeof(name)), 0);
	EXPECT_STREQ(name, "");
	EXPECT_EQ(require_mldsa87("ML-DSA-65", name, sizeof(name)),
		  -EKEYREJECTED);
	EXPECT_STREQ(name, "ML-DSA-65");
	EXPECT_EQ(require_mldsa87("EC", name, sizeof(name)), -EKEYREJECTED);
	EXPECT_STREQ(name, "EC");
	ret = cert_der_require_mldsa87(no_cert, sizeof(no_cert), name,
				       sizeof(name));
	EXPECT_NE(ret, 0);
	EXPECT_NE(ret, -EKEYREJECTED);
}

static void cert_encode_der_encodes_a_pem_certificate(void)
{
	EVP_PKEY *key = keygen("ML-DSA-87");
	struct cert empty = {}, cert = {};
	BIO *pem = BIO_new(BIO_s_mem());
	__u8 *want = NULL, *got = NULL;
	size_t want_len, got_len = 0;
	X509 *x = self_signed(key);
	char *pem_data = NULL;
	long pem_len;

	ASSERT_TRUE(pem);
	ASSERT_EQ(PEM_write_bio_X509(pem, x), 1);
	pem_len = BIO_get_mem_data(pem, &pem_data);
	ASSERT_TRUE(pem_len > 0);
	ASSERT_EQ(cert_read_memory((const __u8 *)pem_data, (size_t)pem_len,
				   &cert), 0);

	EXPECT_EQ(cert_encode_der(NULL, &got, &got_len), -EINVAL);
	EXPECT_EQ(cert_encode_der(&empty, &got, &got_len), -EINVAL);
	EXPECT_EQ(cert_encode_der(&cert, NULL, &got_len), -EINVAL);
	EXPECT_EQ(cert_encode_der(&cert, &got, NULL), -EINVAL);

	want_len = der_of(x, &want);
	ASSERT_EQ(cert_encode_der(&cert, &got, &got_len), 0);
	EXPECT_EQ(got_len, want_len);
	EXPECT_MEMEQ(got, want, want_len);

	xfree(got, got_len);
	OPENSSL_free(want);
	cert_free(&cert);
	BIO_free(pem);
	X509_free(x);
	EVP_PKEY_free(key);
}

static const char payload[] = "an index or a tree publication";

/* A detached CMS signature over payload, with SHA-512 signed attributes. */
static int sign_payload(EVP_PKEY *key, X509 *x, __u8 **sig)
{
	BIO *data = BIO_new_mem_buf(payload, sizeof(payload) - 1);
	CMS_ContentInfo *cms;
	int len;

	ASSERT_TRUE(data);
	cms = CMS_sign(NULL, NULL, NULL, NULL,
		       CMS_BINARY | CMS_DETACHED | CMS_PARTIAL);
	ASSERT_TRUE(cms);
	ASSERT_TRUE(CMS_add1_signer(cms, x, key, EVP_sha512(),
				    CMS_BINARY | CMS_NOCERTS |
				    CMS_NOSMIMECAP | CMS_USE_KEYID));
	ASSERT_EQ(CMS_final(cms, data, NULL, CMS_BINARY | CMS_DETACHED), 1);
	*sig = NULL;
	len = i2d_CMS_ContentInfo(cms, sig);
	ASSERT_TRUE(len > 0);
	CMS_ContentInfo_free(cms);
	BIO_free(data);
	return len;
}

static bool openssl_verifies(X509 *x, const __u8 *sig, int sig_len)
{
	BIO *data = BIO_new_mem_buf(payload, sizeof(payload) - 1);
	const __u8 *p = sig;
	CMS_ContentInfo *cms;
	bool ok;

	ASSERT_TRUE(data);
	cms = d2i_CMS_ContentInfo(NULL, &p, sig_len);
	ASSERT_TRUE(cms);
	ASSERT_EQ(CMS_add1_cert(cms, x), 1);
	ok = CMS_verify(cms, NULL, NULL, data, NULL,
			CMS_BINARY | CMS_DETACHED |
			CMS_NO_SIGNER_CERT_VERIFY) == 1;
	CMS_ContentInfo_free(cms);
	BIO_free(data);
	return ok;
}

/* verify_detached() with the signer's own cert, after signing with key. */
static int verify_signed_by(const char *alg, bool *sound)
{
	EVP_PKEY *key = keygen(alg);
	X509 *x = self_signed(key);
	struct cert cert = {};
	__u8 *sig = NULL;
	int sig_len, ret;

	read_cert(x, &cert);
	sig_len = sign_payload(key, x, &sig);
	*sound = openssl_verifies(x, sig, sig_len);
	ret = verify_detached((const __u8 *)payload, sizeof(payload) - 1,
			      sig, (size_t)sig_len, &cert);
	OPENSSL_free(sig);
	cert_free(&cert);
	X509_free(x);
	EVP_PKEY_free(key);
	return ret;
}

static void verify_detached_accepts_an_ml_dsa_87_signer(void)
{
	bool sound = false;

	EXPECT_EQ(verify_signed_by("ML-DSA-87", &sound), 0);
	EXPECT_TRUE(sound);
}

static void verify_detached_refuses_a_classical_signer(void)
{
	bool sound = false;

	EXPECT_EQ(verify_signed_by("EC", &sound), -EKEYREJECTED);
	EXPECT_TRUE(sound);
}

static const struct unit_case cases[] = {
	UNIT_CASE(sha256_matches_fips_180_vector),
	UNIT_CASE(sha256_buffer_zeroes_a_failed_digest),
	UNIT_CASE(cert_require_mldsa87_accepts_ml_dsa_87_only),
	UNIT_CASE(cert_der_require_mldsa87_names_a_refused_algorithm),
	UNIT_CASE(cert_encode_der_encodes_a_pem_certificate),
	UNIT_CASE(verify_detached_accepts_an_ml_dsa_87_signer),
	UNIT_CASE(verify_detached_refuses_a_classical_signer),
	{}
};

UNIT_SUITE(crypto_openssl, cases);
