/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */
#ifndef SHIRUDO_TPM_TYPES_H
#define SHIRUDO_TPM_TYPES_H

#define SHIRUDO_TPM_NV_RSA_BYTES		384
#define SHIRUDO_TPM_NAME_LEN			34	/* nameAlg and a SHA-256 */
#define SHIRUDO_TPM_CC_NV_EXTEND		0x00000136u
#define SHIRUDO_TPM_NV_RSA_PUBLIC_AREA_LEN	(24 + SHIRUDO_TPM_NV_RSA_BYTES)

#endif /* SHIRUDO_TPM_TYPES_H */
