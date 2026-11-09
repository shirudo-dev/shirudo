/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_TEST_IMAGE_CLI_H
#define SHIRUDO_TEST_IMAGE_CLI_H

#include "util/bpm_package.h"
#include "util/keys.h"

int __wrap_bpm_tree_fetch_publication(struct bpm_oci_client *client,
				      const char *repository,
				      const char *reference,
				      const char *certificate,
				      const struct trusted_set *trusted,
				      struct tree_publication *pub,
				      char *digest, size_t capacity);
int __wrap_keys_load_image_root(const char *primary, int root_fd,
				bool with_trusted, struct trusted_set *set);
int __wrap_keys_check_image_set(const struct trusted_set *set);

#endif /* SHIRUDO_TEST_IMAGE_CLI_H */
