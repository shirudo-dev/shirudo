/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_IMAGE_CACHE_H
#define SHIRUDO_IMAGE_CACHE_H

struct config_update_target;
struct config_image_open;

typedef int (*image_cache_verify_fn)(const struct config_image_open *image,
				     void *ctx);

/*
 * The caller holds the update lock and owns the sealed cache directory,
 * where a fetch first removes the staging and the mapping of a fetch that
 * was killed. verify authenticates the root before a kernel mapping is
 * created.
 * -EINTR when SIGINT stopped an HTTPS transfer. A failed HTTPS fetch can
 * leave libcurl's resolver thread running (CURLOPT_QUICK_EXIT), so the
 * caller exits after a failure instead of fetching again.
 */
int image_cache_fetch(const char *source,
		      struct config_update_target *target,
		      image_cache_verify_fn verify, void *ctx);

#endif /* SHIRUDO_IMAGE_CACHE_H */
