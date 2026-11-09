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

#endif /* SHIRUDO_UTIL_UPATCH_VERIFY_H */
