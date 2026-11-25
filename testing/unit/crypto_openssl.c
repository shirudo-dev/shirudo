// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "crypto.h"
#include "hex.h"
#include "unit.h"

static X509 *make_self_signed(EVP_PKEY *pkey, __u8 **der_out, size_t *len_out)
{
	X509_EXTENSION *ext;
	X509_NAME *subj;
	X509V3_CTX v3;
	int der_len;
	X509 *x509;

	x509 = X509_new();
	subj = X509_NAME_new();
	ASSERT_TRUE(x509 && subj);
	ASSERT_EQ(X509_set_version(x509, 2), 1);
	ASSERT_EQ(ASN1_INTEGER_set(X509_get_serialNumber(x509), 1), 1);
	ASSERT_TRUE(X509_gmtime_adj(X509_getm_notBefore(x509), 0));
	ASSERT_TRUE(X509_gmtime_adj(X509_getm_notAfter(x509), 86400));
	ASSERT_EQ(X509_set_pubkey(x509, pkey), 1);
	ASSERT_EQ(X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_UTF8,
					     (const __u8 *)"unit", -1, -1, 0),
		  1);
	ASSERT_EQ(X509_set_subject_name(x509, subj), 1);
	ASSERT_EQ(X509_set_issuer_name(x509, subj), 1);
	X509_NAME_free(subj);

	X509V3_set_ctx_nodb(&v3);
	X509V3_set_ctx(&v3, x509, x509, NULL, NULL, 0);
	ext = X509V3_EXT_conf_nid(NULL, &v3, NID_subject_key_identifier,
				  "hash");
	ASSERT_TRUE(ext);
	ASSERT_EQ(X509_add_ext(x509, ext, -1), 1);
	X509_EXTENSION_free(ext);
	ASSERT_TRUE(X509_sign(x509, pkey, NULL) > 0);

	*der_out = NULL;
	der_len = i2d_X509(x509, der_out);
	ASSERT_TRUE(der_len > 0);
	*len_out = (size_t)der_len;
	return x509;
}

static void sign_detached_cms(X509 *x509, EVP_PKEY *pkey, const __u8 *msg,
			      size_t msg_len, __u8 **sig_out, size_t *len_out)
{
	__u32 flags = CMS_NOCERTS | CMS_BINARY | CMS_NOSMIMECAP |
		      CMS_NO_SIGNING_TIME | CMS_USE_KEYID;
	const EVP_MD *md = EVP_sha256();
	CMS_ContentInfo *cms;
	int sig_len;
	BIO *in;

#if OPENSSL_VERSION_MAJOR == 3
	if (EVP_PKEY_is_a(pkey, "ML-DSA-87") == 1 ||
	    EVP_PKEY_is_a(pkey, "ML-DSA-65") == 1)
		md = EVP_sha512();
	else
		flags |= CMS_NOATTR;
#else
	flags |= CMS_NOATTR;
#endif
	in = BIO_new_mem_buf(msg, (int)msg_len);
	cms = CMS_sign(NULL, NULL, NULL, NULL,
		       CMS_NOCERTS | CMS_PARTIAL | CMS_BINARY | CMS_DETACHED |
		       CMS_STREAM);
	ASSERT_TRUE(in && cms);
	ASSERT_TRUE(CMS_add1_signer(cms, x509, pkey, md, flags));
	ASSERT_EQ(CMS_final(cms, in, NULL,
			    CMS_NOCERTS | CMS_BINARY | CMS_DETACHED), 1);
	*sig_out = NULL;
	sig_len = i2d_CMS_ContentInfo(cms, sig_out);
	ASSERT_TRUE(sig_len > 0);
	*len_out = (size_t)sig_len;
	CMS_ContentInfo_free(cms);
	BIO_free(in);
}

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

static void classical_certificate_and_cms_are_refused(void)
{
	static const __u8 msg[] = "index";
	size_t der_len = 0, sig_len = 0;
	__u8 *der = NULL, *sig = NULL;
	struct cert cert = {};
	EVP_PKEY *pkey;
	X509 *x509;

	EXPECT_FALSE(cert_is_mldsa87(NULL));
	EXPECT_FALSE(cert_is_mldsa87(&cert));
	EXPECT_FALSE(cert_der_is_mldsa87((const __u8 *)"bad", 3));

	pkey = EVP_EC_gen("P-256");
	ASSERT_TRUE(pkey);
	x509 = make_self_signed(pkey, &der, &der_len);
	ASSERT_EQ(cert_read_der(der, der_len, &cert), 0);
	EXPECT_FALSE(cert_is_mldsa87(&cert));
	EXPECT_FALSE(cert_der_is_mldsa87(der, der_len));

	sign_detached_cms(x509, pkey, msg, sizeof(msg) - 1, &sig, &sig_len);
	EXPECT_EQ(cms_signed_by(sig, sig_len, &cert), 1);
	EXPECT_EQ(verify_detached(msg, sizeof(msg) - 1, sig, sig_len, &cert),
		  -EKEYREJECTED);

	cert_free(&cert);
	OPENSSL_free(sig);
	OPENSSL_free(der);
	X509_free(x509);
	EVP_PKEY_free(pkey);
}

static void only_mldsa87_verifies_detached_cms(void)
{
	static const __u8 msg[] = "publication", other[] = "forged";
	size_t der87_len = 0, sig87_len = 0, der65_len = 0, sig65_len = 0;
	__u8 *der87 = NULL, *sig87 = NULL, *der65 = NULL, *sig65 = NULL;
	struct cert cert87 = {}, cert65 = {};
	EVP_PKEY *k87, *k65;
	X509 *x87, *x65;

	k87 = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-87");
	if (!k87) {
		ERR_clear_error();
		unit_skip("OpenSSL without ML-DSA");
	}
	k65 = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-65");
	ASSERT_TRUE(k65);

	x87 = make_self_signed(k87, &der87, &der87_len);
	ASSERT_EQ(cert_read_der(der87, der87_len, &cert87), 0);
	EXPECT_TRUE(cert_is_mldsa87(&cert87));
	EXPECT_TRUE(cert_der_is_mldsa87(der87, der87_len));
	sign_detached_cms(x87, k87, msg, sizeof(msg) - 1, &sig87, &sig87_len);
	EXPECT_EQ(verify_detached(msg, sizeof(msg) - 1, sig87, sig87_len,
				  &cert87), 0);
	EXPECT_EQ(verify_detached(other, sizeof(other) - 1, sig87, sig87_len,
				  &cert87), -EINVAL);

	x65 = make_self_signed(k65, &der65, &der65_len);
	ASSERT_EQ(cert_read_der(der65, der65_len, &cert65), 0);
	EXPECT_FALSE(cert_is_mldsa87(&cert65));
	EXPECT_FALSE(cert_der_is_mldsa87(der65, der65_len));
	sign_detached_cms(x65, k65, msg, sizeof(msg) - 1, &sig65, &sig65_len);
	EXPECT_EQ(cms_signed_by(sig65, sig65_len, &cert65), 1);
	EXPECT_EQ(verify_detached(msg, sizeof(msg) - 1, sig65, sig65_len,
				  &cert65), -EKEYREJECTED);

	cert_free(&cert65);
	cert_free(&cert87);
	OPENSSL_free(sig65);
	OPENSSL_free(der65);
	OPENSSL_free(sig87);
	OPENSSL_free(der87);
	X509_free(x65);
	X509_free(x87);
	EVP_PKEY_free(k65);
	EVP_PKEY_free(k87);
}

static const struct unit_case cases[] = {
	UNIT_CASE(sha256_matches_fips_180_vector),
	UNIT_CASE(sha256_buffer_zeroes_a_failed_digest),
	UNIT_CASE(classical_certificate_and_cms_are_refused),
	UNIT_CASE(only_mldsa87_verifies_detached_cms),
	{}
};

UNIT_SUITE(crypto_openssl, cases);
