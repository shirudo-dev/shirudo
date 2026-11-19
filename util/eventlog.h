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
#define EVENTLOG_LINE_MAX	4096

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
 * Held by a load or an unload from before it touches the pins to its
 * append, by every other measuring path from the extend to the append;
 * -errno when not taken.
 */
int eventlog_lock(void);
void eventlog_unlock(int fd);

/*
 * Replay this boot's records, from its last "init" record on, the way
 * the register accumulates them. -ENOENT when this boot has no init
 * record, -EINVAL on a malformed line.
 */
int eventlog_replay(__u8 out[TPM_DIGEST_LEN]);

/*
 * What the last init record of this boot says about the register, and
 * how many init records the boot holds: more than one for the TPM reset
 * the last one names means the register was bound again.
 */
struct eventlog_init {
	__u8		writer_public[TPM_NV_RSA_BYTES];
	__u32		pcr;
	bool		initrd;		/* bound while the initrd ran */
	__u8		pcr_before[TPM_DIGEST_LEN];
	__u8		phase_before[TPM_DIGEST_LEN];
	__u8		name[TPM_NAME_LEN];
	size_t		name_len;
	__u8		anchor_digest[TPM_DIGEST_LEN];
	bool		have_reset_count;
	__u32		reset_count;
	__u32		records;	/* init records this boot */
	__u32		records_epoch;	/* for this reset count */
};

int eventlog_boot_init(struct eventlog_init *out);

int eventlog_boot_lines(int (*cb)(const char *line, size_t len,
				  void *ctx), void *ctx);

/*
 * Whether this boot's records hold the tree_op of operation seq with
 * operation_digest: 1, 0, or -errno when the log cannot be read. A boot
 * without an init record holds none.
 */
int eventlog_tree_op_measured(__s64 seq, const char *operation_digest);

enum eventlog_upatch_event {
	EVENTLOG_UPATCH_INIT,
	EVENTLOG_UPATCH_LOAD,
	EVENTLOG_UPATCH_UNLOAD,
};

/*
 * The record type of an upatch load or unload of a payload of type:
 * "upatch_load" and "upatch_unload" for BPF, "java_load" and
 * "java_unload" for Java. NULL for a type with none.
 */
const char *eventlog_upatch_record(__u32 type, bool load);
/*
 * Whether record is one eventlog_upatch_record() gives, and if so the
 * payload type and direction it records.
 */
bool eventlog_upatch_record_parse(const char *record, __u32 *type,
				  bool *load);
/*
 * As eventlog_upatch_record_parse(), for the len bytes at kind that
 * attest predict --event spells the record with: "load", "unload",
 * "java-load" or "java-unload".
 */
bool eventlog_upatch_kind_parse(const char *kind, size_t len, __u32 *type,
				bool *load);

/*
 * The loads and unloads the records measure, in order: this boot's, or
 * every boot's since the log began. An init record gives
 * EVENTLOG_UPATCH_INIT with no name, which starts the set over, then
 * each upatch of its set as a load.
 */
int eventlog_boot_upatches(int (*cb)(enum eventlog_upatch_event event,
				     const char *name,
				     const char *payload_hex, void *ctx),
			   void *ctx);
int eventlog_upatches(int (*cb)(enum eventlog_upatch_event event,
				const char *name, const char *payload_hex,
				void *ctx),
		      void *ctx);

/*
 * The sealed log and the pending record after it, xmalloc'd to *len + 1
 * bytes, for a reader that checks each record against the register.
 */
int eventlog_read(char **out, size_t *len);
/* One record of that log to cb, as eventlog_upatches() would give it. */
int eventlog_upatches_record(const char *line, size_t len, bool is_init,
			     int (*cb)(enum eventlog_upatch_event event,
				       const char *name,
				       const char *payload_hex, void *ctx),
			     void *ctx);

/*
 * 1 if appending one more event would push the eventlog past max_bytes;
 * 0 if it fits or max_bytes is 0 (unlimited). The register and the log
 * must stay in lockstep, so a caller refuses the whole operation (no
 * PROG_LOAD, no extend, no append) when this returns 1.
 */
int eventlog_would_exceed(__u64 max_bytes);

void eventlog_timestamp(char *out, size_t cap);	/* ISO-8601 UTC */
void eventlog_boot_id(char *out, size_t cap);	/* /proc boot_id */

struct json_emit;

/*
 * Open a record and write the fields every record starts with, through
 * boot_id; the caller adds its own and closes the object. A failure
 * lands in e->err like any other.
 */
void eventlog_record_open(struct json_emit *e, const char *type,
			  const __u8 digest[32]);

#endif /* SHIRUDO_EVENTLOG_H */
