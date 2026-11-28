/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_IMAGE_BOOTSTRAP_H
#define SHIRUDO_IMAGE_BOOTSTRAP_H

#include <shirudo/misc.h>

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#include "keys.h"

struct image_bootstrap {
	char runtime[PATH_MAX];
	char config[PATH_MAX];
	char certificates[KEYS_MAX][PATH_MAX];
	size_t n_certificates;
	__u8 runtime_root[32];
	__u32 pcr;
	__u32 enforcement;	/* ENFORCEMENT_STRICT or _SHARED */
	bool have_root;
	bool have_pcr;
	bool have_enforcement;
};

bool image_path_valid(const char *path);
/* Only the authenticated initrd may supply runtime.image and root_hash. */
int image_bootstrap_read(const char *path,
			 struct image_bootstrap *boot,
			 bool initial);
int image_bootstrap_read_fd(int fd,
			    struct image_bootstrap *boot,
			    bool initial);

#endif /* SHIRUDO_IMAGE_BOOTSTRAP_H */
