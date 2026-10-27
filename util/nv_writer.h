/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */
#ifndef SHIRUDO_NV_WRITER_H
#define SHIRUDO_NV_WRITER_H

#include "keyring.h"
#include "tpm_wire.h"

int nv_writer_create(key_serial_t *ring, key_serial_t *writer,
		     __u8 public[SHIRUDO_TPM_NV_RSA_BYTES]);
void nv_writer_destroy(key_serial_t ring);
int nv_writer_read(__u8 public[SHIRUDO_TPM_NV_RSA_BYTES]);
int nv_writer_sign(const __u8 digest[SHIRUDO_TPM_DIGEST_LEN],
		   __u8 signature[SHIRUDO_TPM_NV_RSA_BYTES]);
int nv_writer_sign_key(key_serial_t key,
		       const __u8 digest[SHIRUDO_TPM_DIGEST_LEN],
		       __u8 signature[SHIRUDO_TPM_NV_RSA_BYTES]);

#endif /* SHIRUDO_NV_WRITER_H */
