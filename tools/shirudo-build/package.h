/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * gen_loader + CMS sign + .upatch container writer.
 */

#ifndef SHIRUDO_BUILD_PACKAGE_H
#define SHIRUDO_BUILD_PACKAGE_H

#include <shirudo/misc.h>

struct shirudo_upatch_policy_label_entry;

int build_package_load(const char *bpf_o, const char *src_path,
		       const char *out_upatch, const char *upatch_name,
		       const struct shirudo_upatch_policy_label_entry *policies,
		       __u32 nr_policies,
		       const char *pkey_path, const char *cert_path);

int build_package_unload(const char *name,
			 const __u8 payload_sha256[32],
			 const char *out_upatch,
			 const char *pkey_path,
			 const char *cert_path);

int build_package_patch_rodata(const char *input, const char *output,
			       const char *symbol, const __u8 *value,
				      size_t value_len, const char *pkey_path,
				      const char *cert_path);
int build_package_verify(const char *input, const char *cert_path);
int build_upatch_cli(int argc, char **argv);

#endif /* SHIRUDO_BUILD_PACKAGE_H */
