// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>
#include <sys/random.h>

#include "identity.h"
#include "log.h"
#include "nv_writer.h"
#include "tpm.h"

int nv_writer_create(__u8 seed[SHIRUDO_TPM_DIGEST_LEN],
		     __u8 public[SHIRUDO_TPM_NV_RSA_BYTES])
{
	struct shirudo_tpm *t = NULL;
	size_t off = 0;
	ssize_t got;
	int err;

	while (off < SHIRUDO_TPM_DIGEST_LEN) {
		got = getrandom(seed + off, SHIRUDO_TPM_DIGEST_LEN - off, 0);
		if (got < 0 && errno == EINTR)
			continue;
		if (got <= 0) {
			err = got < 0 ? -errno : -EIO;
			goto fail;
		}
		off += (size_t)got;
	}
	err = tpm_open(&t);
	if (!err)
		err = tpm_writer_create(t, seed, public);
	tpm_close(t);
	if (!err)
		return 0;
fail:
	pr_err("nv writer: TPM key creation failed: %s", strerror(-err));
	explicit_bzero(seed, SHIRUDO_TPM_DIGEST_LEN);
	memset(public, 0, SHIRUDO_TPM_NV_RSA_BYTES);
	return err;
}

int nv_writer_read(__u8 seed[SHIRUDO_TPM_DIGEST_LEN],
		   __u8 public[SHIRUDO_TPM_NV_RSA_BYTES])
{
	struct shirudo_identity id = {};
	int err;

	err = identity_read(&id);
	if (err)
		goto fail;
	if (!(id.nv_writer_public[0] & 0x80)) {
		err = -EKEYREJECTED;
		goto fail;
	}
	memcpy(seed, id.nv_writer_seed, SHIRUDO_TPM_DIGEST_LEN);
	memcpy(public, id.nv_writer_public, SHIRUDO_TPM_NV_RSA_BYTES);
	return 0;
fail:
	pr_err("nv writer: public key lookup failed: %s", strerror(-err));
	return err;
}
