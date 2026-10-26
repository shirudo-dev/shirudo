/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * /var/lib/shirudo/eventlog appender and per-boot replay.
 */

#ifndef SHIRUDO_EVENTLOG_H
#define SHIRUDO_EVENTLOG_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/misc.h>

#include "tpm_wire.h"

/*
 * Conservative upper bound on one appended JSON line (the emit buffers
 * are this size); used by would_exceed to honour "would exceed".
 */
#define SHIRUDO_EVENTLOG_LINE_MAX	4096

/* The on-disk path; SHIRUDO_EVENTLOG_PATH in the environment overrides it. */
const char *eventlog_path(void);

/*
 * Where an init run from the initrd leaves its record until the root
 * file system's init adopts it; SHIRUDO_EVENTLOG_PENDING_PATH in the
 * environment overrides it. Every reader below sees a pending record
 * as part of this boot's log.
 */
const char *eventlog_pending_path(void);

int eventlog_append(const char *json_line);
int eventlog_append_to(const char *path, const char *json_line);

/* 0 when nothing was pending. */
int eventlog_adopt_pending(void);

/*
 * Replay this boot's records, from its last "init" record on, the way
 * the register accumulates them. -ENOENT when this boot has no init
 * record, -EINVAL on a malformed line.
 */
int eventlog_replay(__u8 out[SHIRUDO_TPM_DIGEST_LEN]);

/*
 * What the last init record of this boot says about the register, and
 * how many init records the boot holds: more than one for the TPM reset
 * the last one names means the register was bound again.
 */
struct shirudo_eventlog_init {
	__u8		writer_public[SHIRUDO_TPM_NV_RSA_BYTES];
	__u32		pcr;
	bool		initrd;		/* bound while the initrd ran */
	__u8		pcr_before[SHIRUDO_TPM_DIGEST_LEN];
	__u8		phase_before[SHIRUDO_TPM_DIGEST_LEN];
	__u8		name[SHIRUDO_TPM_NAME_LEN];
	size_t		name_len;
	__u8		anchor_digest[SHIRUDO_TPM_DIGEST_LEN];
	bool		have_reset_count;
	__u32		reset_count;
	__u32		records;	/* init records this boot */
	__u32		records_epoch;	/* for this reset count */
};

int eventlog_boot_init(struct shirudo_eventlog_init *out);

int eventlog_boot_lines(int (*cb)(const char *line, size_t len,
				  void *ctx), void *ctx);

/*
 * 1 if appending one more event would push the eventlog past max_bytes;
 * 0 if it fits or max_bytes is 0 (unlimited). The register and the log
 * must stay in lockstep, so a caller refuses the whole operation (no
 * PROG_LOAD, no extend, no append) when this returns 1.
 */
int eventlog_would_exceed(__u64 max_bytes);

void eventlog_timestamp(char *out, size_t cap);	/* ISO-8601 UTC */
void eventlog_boot_id(char *out, size_t cap);	/* /proc boot_id */

#endif /* SHIRUDO_EVENTLOG_H */
