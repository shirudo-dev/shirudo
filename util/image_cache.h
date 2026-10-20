/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_IMAGE_CACHE_H
#define SHIRUDO_IMAGE_CACHE_H

struct shirudo_config_update_target;

/* The caller holds the update lock and owns the sealed cache directory. */
int shirudo_image_cache_fetch(const char *source,
			      struct shirudo_config_update_target *target);

#endif /* SHIRUDO_IMAGE_CACHE_H */
