// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "hex.h"
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

/* The existing corpus entry holds a certificate and its detached CMS. */
static void signers_need_a_complete_envelope(void)
{
	const char *path = "fuzz/corpus/cms/cert-and-signature";
	static __u8 data[32768];
	struct cert cert = {};
	size_t size, der_len, sig_len;
	__u8 *sig;
	FILE *f;

	f = fopen(path, "rb");
	if (!f)
		f = fopen("testing/fuzz/corpus/cms/cert-and-signature", "rb");
	ASSERT_TRUE(f);
	size = fread(data, 1, sizeof(data), f);
	fclose(f);
	ASSERT_TRUE(size > 2 && size < sizeof(data));
	der_len = data[0] | (size_t)data[1] << 8;
	ASSERT_TRUE(der_len < size - 2);
	ASSERT_EQ(cert_read_der(data + 2, der_len, &cert), 0);
	sig = data + 2 + der_len;
	sig_len = size - 2 - der_len;
	EXPECT_EQ(cms_check_signers(sig, sig_len), 0);
	EXPECT_EQ(cms_signed_by(sig, sig_len, &cert), 1);
	data[size] = 0;
	EXPECT_EQ(cms_check_signers(sig, sig_len + 1), -EBADMSG);
	EXPECT_EQ(cms_signed_by(sig, sig_len + 1, &cert), -EINVAL);
	cert_free(&cert);
}

static const struct unit_case cases[] = {
	UNIT_CASE(signers_need_a_complete_envelope),
	UNIT_CASE(sha256_matches_fips_180_vector),
	UNIT_CASE(sha256_buffer_zeroes_a_failed_digest),
	{}
};

UNIT_SUITE(crypto_openssl, cases);
