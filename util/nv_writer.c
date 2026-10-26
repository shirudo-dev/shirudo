// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <linux/keyctl.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <shirudo/string.h>

#include "crypto.h"
#include "identity.h"
#include "log.h"
#include "malloc.h"
#include "nv_writer.h"

#define KEY_USR_VIEW	0x00010000
#define KEY_USR_READ	0x00020000
#define KEY_USR_WRITE	0x00040000
#define KEY_USR_SEARCH	0x00080000
#define KEY_USR_SETATTR	0x00200000
#define KEY_POS_VIEW	0x01000000
#define KEY_POS_READ	0x02000000
#define KEY_POS_WRITE	0x04000000
#define KEY_POS_SEARCH	0x08000000
#define KEY_POS_LINK	0x10000000
#define KEY_POS_SETATTR	0x20000000

#define NV_RING_READ	(KEY_POS_VIEW | KEY_POS_READ | KEY_POS_SEARCH | \
			 KEY_USR_VIEW | KEY_USR_READ | KEY_USR_SEARCH)
#define NV_RING_WRITE	(NV_RING_READ | KEY_POS_WRITE | KEY_POS_LINK | KEY_POS_SETATTR | \
			 KEY_USR_WRITE | KEY_USR_SETATTR)

#define NV_WRITER_SIGN_INFO	"enc=pkcs1 hash=sha256"

int nv_writer_create(key_serial_t *ring, key_serial_t *writer,
		     __u8 public[SHIRUDO_TPM_NV_RSA_BYTES])
{
	PKCS8_PRIV_KEY_INFO *info = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	int len = 0, rc = -EIO;
	char description[64];
	EVP_PKEY *key = NULL;
	__u8 *der = NULL, *p;
	BIGNUM *n = NULL;
	ssize_t got;
	__u64 nonce;
	long ret;

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072) <= 0 ||
	    EVP_PKEY_keygen(ctx, &key) <= 0 ||
	    EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n) <= 0 ||
	    BN_bn2binpad(n, public, SHIRUDO_TPM_NV_RSA_BYTES) != SHIRUDO_TPM_NV_RSA_BYTES) {
		openssl_complain("generate RSA-3072 NV writer");
		goto out;
	}
	info = EVP_PKEY2PKCS8(key);
	if (!info)
		goto out;
	len = i2d_PKCS8_PRIV_KEY_INFO(info, NULL);
	if (len <= 0)
		goto out;
	der = xmalloc(len);
	if (!der) {
		rc = -ENOMEM;
		goto out;
	}
	p = der;
	if (i2d_PKCS8_PRIV_KEY_INFO(info, &p) != len)
		goto out;
	do {
		got = getrandom(&nonce, sizeof(nonce), 0);
	} while (got < 0 && errno == EINTR);
	if (got != sizeof(nonce)) {
		rc = got < 0 ? -errno : -EIO;
		goto out;
	}
	rc = strsprintf(description, sizeof(description), "shirudo.nv-writer.%016llx", nonce);
	if (rc < 0)
		goto out;
	ret = syscall(__NR_add_key, "keyring", description, NULL, 0,
		      KEY_SPEC_SESSION_KEYRING);
	if (ret < 0)
		goto key_error;
	*ring = (key_serial_t)ret;
	if (syscall(__NR_keyctl, KEYCTL_SETPERM, *ring, NV_RING_WRITE, 0, 0) < 0 ||
	    syscall(__NR_keyctl, KEYCTL_LINK, *ring, KEY_SPEC_USER_KEYRING, 0, 0) < 0)
		goto key_error;
	ret = syscall(__NR_add_key, "asymmetric", "shirudo.nv-writer",
		      der, (size_t)len, *ring);
	if (ret < 0)
		goto key_error;
	*writer = (key_serial_t)ret;
	if (syscall(__NR_keyctl, KEYCTL_SETPERM, *writer,
		    KEY_USR_VIEW | KEY_USR_SEARCH, 0, 0) < 0 ||
	    syscall(__NR_keyctl, KEYCTL_RESTRICT_KEYRING, *ring, 0, 0, 0) < 0 ||
	    syscall(__NR_keyctl, KEYCTL_SETPERM, *ring, NV_RING_READ, 0, 0) < 0)
		goto key_error;
	rc = 0;
	goto out;
key_error:
	rc = -errno;
out:
	xfree(der, len > 0 ? (size_t)len : 0);
	PKCS8_PRIV_KEY_INFO_free(info);
	BN_free(n);
	EVP_PKEY_free(key);
	EVP_PKEY_CTX_free(ctx);
	return rc;
}

int nv_writer_read(__u8 public[SHIRUDO_TPM_NV_RSA_BYTES])
{
	struct shirudo_identity id = {};
	int rc;

	rc = identity_read(&id);
	if (rc)
		goto fail;
	if (id.nv_writer_ring <= 0 || id.nv_writer_key <= 0) {
		rc = -EKEYREJECTED;
		goto fail;
	}
	memcpy(public, id.nv_writer_public, sizeof(id.nv_writer_public));
	return 0;
fail:
	pr_err("nv writer: public key lookup failed: %s", strerror(-rc));
	return rc;
}

int nv_writer_sign_key(key_serial_t key,
		       const __u8 digest[SHIRUDO_TPM_DIGEST_LEN],
		       __u8 signature[SHIRUDO_TPM_NV_RSA_BYTES])
{
	struct keyctl_pkey_params params = {
		.key_id = key,
		.in_len = SHIRUDO_TPM_DIGEST_LEN,
		.out_len = SHIRUDO_TPM_NV_RSA_BYTES,
	};
	long ret;
	int rc;

	ret = syscall(__NR_keyctl, KEYCTL_PKEY_SIGN, &params,
		      NV_WRITER_SIGN_INFO, digest, signature);
	if (ret == SHIRUDO_TPM_NV_RSA_BYTES)
		return 0;
	rc = ret < 0 ? -errno : -EPROTO;
	pr_err("nv writer: kernel signing failed: %s", strerror(-rc));
	return rc;
}

int nv_writer_sign(const __u8 digest[SHIRUDO_TPM_DIGEST_LEN],
		   __u8 signature[SHIRUDO_TPM_NV_RSA_BYTES])
{
	struct shirudo_identity id = {};
	int rc;

	rc = identity_read(&id);
	if (rc)
		goto fail;
	if (id.nv_writer_key <= 0) {
		rc = -EKEYREJECTED;
		goto fail;
	}
	return nv_writer_sign_key(id.nv_writer_key, digest, signature);
fail:
	pr_err("nv writer: kernel signing failed: %s", strerror(-rc));
	return rc;
}
