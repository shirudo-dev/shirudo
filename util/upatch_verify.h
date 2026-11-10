/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Whether the archive of a loaded upatch is still what was loaded.
 */

#ifndef SHIRUDO_UTIL_UPATCH_VERIFY_H
#define SHIRUDO_UTIL_UPATCH_VERIFY_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/types.h>
#include <shirudo/upatch.h>

struct prog_spec;
struct upatch;
struct xdp_device;

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
 * pinned for name, 0 when one is missing, -ESTALE when the archive is gone
 * or unusable, or another negative errno when that cannot be told.
 */
int upatch_links_complete(const char *name, const char *path);

/*
 * As upatch_archive_verify(), with the signed attach metadata of every
 * program in *specs, which prog_specs_free() releases.
 */
int upatch_archive_specs(const char *name,
			 const __u8 payload[UPATCH_PAYLOAD_HASH_LEN],
			 struct upatch *u, struct prog_spec **specs);

/* The fd of XDP program index pinned for name, its id in *id, or -errno. */
int upatch_xdp_prog_open(const char *name, __u32 index, __u32 *id);

/*
 * Calls cb for each device an XDP program of name selects and that does not
 * run it, with what the device runs instead as devices were read, 0 for
 * nothing. A non-zero return of cb ends the walk with that value, and a
 * program pin that cannot be opened ends it with its -errno.
 */
int upatch_xdp_each_uncovered(const char *name, const struct prog_spec *specs,
			      __u32 nr_progs, const struct xdp_device *devices,
			      size_t count,
			      int (*cb)(int prog_fd, const struct prog_spec *spec,
					const struct xdp_device *dev,
					__u32 attached, void *ctx),
			      void *ctx);

struct measured_set;

/*
 * Whether the set holds name with the payload its pin directory records,
 * which is left in payload when the directory records one.
 */
bool upatch_pin_measured(const struct measured_set *s, const char *name,
			 __u8 payload[UPATCH_PAYLOAD_HASH_LEN]);

/*
 * The XDP upatches the set holds whose archive is not what was loaded. cb
 * runs for each and a non-zero return ends the walk with that value. The
 * number found. The first check that could not run leaves its -errno in
 * *check_err, unless that already holds one.
 */
int upatch_xdp_archives_changed(const struct measured_set *s,
				int (*cb)(const char *name, void *ctx),
				void *ctx, int *check_err);

/* As upatch_xdp_archives_changed(), for a lost link or an unusable archive. */
int upatch_links_lost(const struct measured_set *s,
		      int (*cb)(const char *name, void *ctx), void *ctx,
		      int *check_err);

/*
 * The devices an XDP upatch the set holds selects and that do not run it.
 * cb runs for each with the upatch, the device and why. The number found,
 * with *check_err as above.
 */
int upatch_xdp_uncovered(const struct measured_set *s,
			 int (*cb)(const char *name, const char *dev,
				   const char *why, void *ctx),
			 void *ctx, int *check_err);

#endif /* SHIRUDO_UTIL_UPATCH_VERIFY_H */
