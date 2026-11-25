// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <shirudo/string.h>

#include "keys.h"
#include "unit.h"

/* One more than keys.c's store of kept certificates, der_store, holds. */
#define REFUSED_LOADS	(8 * KEYS_MAX + 1)

static struct trusted_set set;
static char keys_dir[4096], cert_path[4096];

static void member_is_found_by_fingerprint(void)
{
	__u8 absent[32];

	memset(&set, 0, sizeof(set));
	set.n = 2;
	memset(set.certs[0].fingerprint, 0x11, 32);
	memset(set.certs[1].fingerprint, 0x22, 32);
	memset(absent, 0x33, sizeof(absent));

	EXPECT_TRUE(keys_member(&set, set.certs[1].fingerprint) ==
		    &set.certs[1]);
	EXPECT_TRUE(!keys_member(&set, absent));
}

/* Entries past n are a stale tail, not members. */
static void member_past_the_count_is_none(void)
{
	__u8 stale[32];

	memset(&set, 0, sizeof(set));
	set.n = 1;
	memset(set.certs[1].fingerprint, 0x22, 32);
	memset(stale, 0x22, sizeof(stale));

	EXPECT_TRUE(!keys_member(&set, stale));
}

static void write_cert(const char *alg)
{
	EVP_PKEY *key = !strcmp(alg, "EC") ? EVP_EC_gen("P-256") :
			EVP_PKEY_Q_keygen(NULL, NULL, alg);
	const EVP_MD *md = !strcmp(alg, "EC") ? EVP_sha256() : NULL;
	X509 *x = X509_new();
	BIO *out;

	ASSERT_TRUE(key && x);
	ASSERT_EQ(ASN1_INTEGER_set(X509_get_serialNumber(x), 1), 1);
	ASSERT_TRUE(X509_gmtime_adj(X509_getm_notBefore(x), 0));
	ASSERT_TRUE(X509_gmtime_adj(X509_getm_notAfter(x), 86400));
	ASSERT_EQ(X509_set_pubkey(x, key), 1);
	ASSERT_TRUE(X509_sign(x, key, md) > 0);
	out = BIO_new_file(cert_path, "wb");
	ASSERT_TRUE(out);
	ASSERT_EQ(i2d_X509_bio(out, x), 1);
	BIO_free(out);
	X509_free(x);
	EVP_PKEY_free(key);
}

/*
 * A refused certificate is not kept, so a process that loads many sets,
 * as a long-running one would, still loads a good one after them.
 */
static void refused_certificates_are_not_kept(void)
{
	const char *tmp = getenv("TMPDIR");
	int i;

	ASSERT_TRUE(strsprintf(keys_dir, sizeof(keys_dir),
			       "%s/shirudo-unit-keys-XXXXXX",
			       tmp && tmp[0] ? tmp : "/tmp") > 0);
	ASSERT_TRUE(mkdtemp(keys_dir));
	ASSERT_TRUE(strsprintf(cert_path, sizeof(cert_path), "%s/cert.der",
			       keys_dir) > 0);
	for (i = 0; i < REFUSED_LOADS; i++) {
		write_cert("EC");
		ASSERT_EQ(keys_load(keys_dir, NULL, false, &set),
			  -EKEYREJECTED);
	}
	EXPECT_STREQ(set.refused, cert_path);
	EXPECT_STREQ(set.refused_algorithm, "EC");
	write_cert("ML-DSA-87");
	EXPECT_EQ(keys_load(keys_dir, NULL, false, &set), 0);
	EXPECT_UEQ(set.n, 1);
	EXPECT_STREQ(set.refused, "");
	unlink(cert_path);
	rmdir(keys_dir);
}

static const struct unit_case cases[] = {
	UNIT_CASE(member_is_found_by_fingerprint),
	UNIT_CASE(member_past_the_count_is_none),
	UNIT_CASE(refused_certificates_are_not_kept),
	{}
};

UNIT_SUITE(keys, cases);
