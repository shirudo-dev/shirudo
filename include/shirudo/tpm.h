/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */
#ifndef SHIRUDO_TPM_TYPES_H
#define SHIRUDO_TPM_TYPES_H

#define TPM_NV_RSA_BYTES		384
#define TPM_NAME_LEN			34	/* nameAlg and a SHA-256 */
#define TPM_CC_NV_EXTEND		0x00000136u
#define TPM_NV_RSA_PUBLIC_AREA_LEN	(24 + TPM_NV_RSA_BYTES)
/*
 * The config NvPCR: systemd defines it in the initrd from its .nvpcr file,
 * before the guards attach, and only Shirudo extends it afterwards.
 */
#define TPM_CONFIG_NVPCR_INDEX		0x01818e04u
#define TPM_CONFIG_NVPCR_NAME		"shirudo-config"

#endif /* SHIRUDO_TPM_TYPES_H */
