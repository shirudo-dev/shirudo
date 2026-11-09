/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_IMAGE_CACHE_H
#define SHIRUDO_IMAGE_CACHE_H

struct config_update_target;
struct config_image_open;

typedef int (*image_cache_verify_fn)(const struct config_image_open *image,
				     void *ctx);

/*
 * The caller holds the update lock and owns the sealed cache directory.
 * verify authenticates the root before a kernel mapping is created.
 */
int image_cache_fetch(const char *source,
		      struct config_update_target *target,
		      image_cache_verify_fn verify, void *ctx);

#endif /* SHIRUDO_IMAGE_CACHE_H */
