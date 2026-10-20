/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_TEST_IMAGE_FAULT_H
#define SHIRUDO_TEST_IMAGE_FAULT_H

#include <shirudo/misc.h>

#include <tss2/tss2_esys.h>

#include "util/image_guards.h"

int __real_shirudo_config_root_begin(const __u8 root[32],
				     struct shirudo_config_root_guard *guard);
int __wrap_shirudo_config_root_begin(const __u8 root[32],
				     struct shirudo_config_root_guard *guard);
int __real_shirudo_config_root_end(struct shirudo_config_root_guard *guard);
int __wrap_shirudo_config_root_end(struct shirudo_config_root_guard *guard);

int __real_main(int argc, const char **argv);
int __wrap_main(int argc, const char **argv);
TSS2_RC __real_Esys_PCR_Extend(ESYS_CONTEXT *context, ESYS_TR pcr,
			       ESYS_TR first, ESYS_TR second, ESYS_TR third,
			       const TPML_DIGEST_VALUES *digests);
TSS2_RC __wrap_Esys_PCR_Extend(ESYS_CONTEXT *context, ESYS_TR pcr,
			       ESYS_TR first, ESYS_TR second, ESYS_TR third,
			       const TPML_DIGEST_VALUES *digests);

#endif /* SHIRUDO_TEST_IMAGE_FAULT_H */
