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
 * SHA-256 of the loader's instructions, then the data: what a header's
 * payload_sha256 claims and the pin directory, the register and an
 * unload directive record. 0, or a negative errno with out zeroed.
 */
int upatch_payload_digest(const struct upatch *u,
			  __u8 out[UPATCH_PAYLOAD_HASH_LEN]) __must_check;

/*
 * What the kernel checks of a BPF upatch, checked in userspace for a Java
 * one, which has no loader: the signed type and name, the section its
 * direction needs, the payload digest, and the signature over the data
 * under a certificate of the runtime's set that the .bpf keyring still
 * holds. -EBADMSG for a malformed or mismatched upatch, -EKEYREJECTED
 * for a signature no such certificate made, or another negative errno
 * when the check could not run.
 */
int java_upatch_verify(const struct upatch *u) __must_check;

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
 * The payload loaded under name: the one its pins record, else the
 * archived one of a Java upatch whose jar is installed as archived.
 * -ENOENT when neither, -ESTALE for a Java load whose jar is missing or
 * another, or another negative errno when that cannot be told.
 */
int upatch_loaded_payload(const char *name,
			  __u8 payload[UPATCH_PAYLOAD_HASH_LEN]) __must_check;

/*
 * The upatches the set holds that do not run: no pin directory, and for a
 * Java one no jar installed as archived; a BPF one is detached with no
 * unload of record, which only a task with runtime authority does. cb runs
 * for each; the number found, or -errno when a pin cannot be looked up.
 */
int upatch_unpinned(const struct measured_set *s,
		    int (*cb)(const char *name, void *ctx), void *ctx);

/*
 * Whether the set holds name with the payload its pin directory records,
 * which is left in payload when the directory records one.
 */
bool upatch_pin_measured(const struct measured_set *s, const char *name,
			 __u8 payload[UPATCH_PAYLOAD_HASH_LEN]);

/*
 * The checks status makes of the upatches the set holds, in one walk that
 * reads and hashes each XDP archive once. Each callback that is not NULL
 * runs for a hit, and a non-zero return ends the walk.
 * changed: an XDP upatch whose archive is not what was loaded.
 * lost: an upatch missing a link, or whose archive is gone or unusable.
 * uncovered: a device an XDP upatch selects that does not run it, and why.
 */
struct upatch_checks {
	int			(*changed)(const char *name, void *ctx);
	void			*changed_ctx;
	int			(*lost)(const char *name, void *ctx);
	void			*lost_ctx;
	int			(*uncovered)(const char *name, const char *dev,
					     const char *why, void *ctx);
	void			*uncovered_ctx;
	int			nr_changed;
	int			nr_lost;
	int			nr_uncovered;
	/* The first changed or lost check that could not run. */
	int			check_err;
	/* The first coverage check that could not run. */
	int			coverage_err;
};

/* The counts hold what was found even when a callback ends the walk. */
void upatch_checks_run(const struct measured_set *s, struct upatch_checks *c);

#endif /* SHIRUDO_UTIL_UPATCH_VERIFY_H */
