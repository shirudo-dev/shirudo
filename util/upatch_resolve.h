/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The hook string and load time of a loaded upatch, from its pin.
 */

#ifndef SHIRUDO_UTIL_UPATCH_RESOLVE_H
#define SHIRUDO_UTIL_UPATCH_RESOLVE_H

#include <stddef.h>

#include <shirudo/types.h>

struct bpf_link_info;
struct btf;

#define UPATCH_LOCATION_MAX	160

/*
 * Open the first pinned link for an upatch. Single-program upatches use
 * "link"; multi-program upatches use "link_0", "link_1", ...
 * Returns a link fd on success, negative errno on failure.
 */
int upatch_open_first_link(const char *name);

/*
 * As upatch_each_link(), with what the kernel says of each link; a link
 * whose pin cannot be opened or read ends the walk with its -errno.
 */
int upatch_each_link_info(const char *name,
			  int (*cb)(__u32 index, const char *pin,
				    const struct bpf_link_info *info, void *ctx),
			  void *ctx);

/* From the first link, or from an XDP program pin when it has none. */
int upatch_first_prog_id(const char *name, __u32 *out);

/* vbtf may be NULL; the location then degrades to the bare prefix. */
int upatch_resolve_location(struct btf *vbtf, const char *name,
			    char *out, size_t cap);

void upatch_loaded_at(const char *name, char *out, size_t cap);

/* Empty on any failure. */
void upatch_payload_sha256(const char *name, char *out, size_t cap);

#endif /* SHIRUDO_UTIL_UPATCH_RESOLVE_H */
