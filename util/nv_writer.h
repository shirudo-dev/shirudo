/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */
#ifndef SHIRUDO_NV_WRITER_H
#define SHIRUDO_NV_WRITER_H

#include "tpm_wire.h"

int nv_writer_create(__u8 seed[SHIRUDO_TPM_DIGEST_LEN],
		     __u8 public[SHIRUDO_TPM_NV_RSA_BYTES]);
int nv_writer_read(__u8 seed[SHIRUDO_TPM_DIGEST_LEN],
		   __u8 public[SHIRUDO_TPM_NV_RSA_BYTES]);

#endif /* SHIRUDO_NV_WRITER_H */
