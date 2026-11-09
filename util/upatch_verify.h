/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Whether the archive of a loaded upatch is still what was loaded.
 */

#ifndef SHIRUDO_UTIL_UPATCH_VERIFY_H
#define SHIRUDO_UTIL_UPATCH_VERIFY_H

#include <shirudo/types.h>
#include <shirudo/upatch.h>

struct upatch;

/*
 * 0 with the artifact open in *out, -ESTALE when it is not what payload
 * names, or another negative errno when the check itself could not run.
 * The bytes are hashed, not the header's claim about them.
 */
int upatch_verify_fd(int fd, const __u8 payload[UPATCH_PAYLOAD_HASH_LEN],
		     struct upatch *out);
int upatch_archive_verify(const char *name,
			  const __u8 payload[UPATCH_PAYLOAD_HASH_LEN],
			  struct upatch *out);

/*
 * 1 when every link the signed metadata of the archive at path implies is
 * pinned for name, 0 when one is missing, or a negative errno when that
 * cannot be told.
 */
int upatch_links_complete(const char *name, const char *path);

struct measured_set;

/*
 * The XDP upatches the set holds whose archive is not what was loaded. cb
 * runs for each and a non-zero return ends the walk with that value. The
 * number found, or -errno when the pins cannot be read. A check that
 * could not run counts as nothing found.
 */
int upatch_xdp_archives_changed(const struct measured_set *s,
				int (*cb)(const char *name, void *ctx),
				void *ctx);

/* As upatch_xdp_archives_changed(), for upatches that have lost a link. */
int upatch_links_lost(const struct measured_set *s,
		      int (*cb)(const char *name, void *ctx), void *ctx);

#endif /* SHIRUDO_UTIL_UPATCH_VERIFY_H */
