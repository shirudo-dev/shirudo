/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_IMAGE_BOOTSTRAP_H
#define SHIRUDO_IMAGE_BOOTSTRAP_H

#include <shirudo/misc.h>

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

struct shirudo_image_bootstrap {
	char runtime[PATH_MAX];
	char config[PATH_MAX];
	char certificate[PATH_MAX];
	__u8 runtime_root[32];
	__u32 pcr;
	bool have_root;
	bool have_pcr;
};

bool shirudo_image_path_valid(const char *path);
/* Only the authenticated initrd may supply runtime.image and root_hash. */
int shirudo_image_bootstrap_read(const char *path,
				 struct shirudo_image_bootstrap *boot,
				 bool initial);

#endif /* SHIRUDO_IMAGE_BOOTSTRAP_H */
