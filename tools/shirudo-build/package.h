/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * gen_loader + CMS sign + .upatch container writer.
 */

#ifndef SHIRUDO_BUILD_PACKAGE_H
#define SHIRUDO_BUILD_PACKAGE_H

#include <shirudo/misc.h>

struct shirudo_data_range {
	__u32 offset;
	__u32 length;
};

int shirudo_build_package_load(const char *bpf_o, const char *src_path,
			       const char *out_upatch, const char *upatch_name,
			       const char *pkey_path, const char *cert_path);

int shirudo_build_package_unload(const char *name,
				 const __u8 payload_sha256[32],
				 const char *out_upatch,
				 const char *pkey_path,
				 const char *cert_path);

int shirudo_build_package_resign(const char *original,
				 const char *modified, const char *output,
				 const struct shirudo_data_range *ranges,
				 size_t nr_ranges, const char *pkey_path,
				 const char *cert_path);
int shirudo_build_upatch_cli(int argc, char **argv);

#endif /* SHIRUDO_BUILD_PACKAGE_H */
