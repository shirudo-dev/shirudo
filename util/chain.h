/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The measurement register: a per-boot NV extend index anchored in a
 * PCR, plus the digest helpers every measuring path shares.
 */

#ifndef SHIRUDO_CHAIN_H
#define SHIRUDO_CHAIN_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/misc.h>

#include "eventlog.h"
#include "hex.h"
#include "tpm_wire.h"
#include "upatch.h"

#define CHAIN_DIGEST_LEN	32
#define CHAIN_NAME		"shirudo"
/*
 * The register binds to PCR 9, which holds the initrd and nothing
 * measured after it, and to PCR 11, which systemd extends with the
 * boot phase: bound while the initrd runs, the init branch closes at
 * "leave-initrd" and no later process can bind. PCR 9 also takes the
 * anchor, so it stays exact afterwards.
 */
#define CHAIN_PCR		9u
#define CHAIN_PHASE_PCR		11u
#define CHAIN_PCR_MASK		((1u << CHAIN_PCR) | \
					 (1u << CHAIN_PHASE_PCR))
#define CHAIN_ANCHOR_MAX	128

int sha256_calc(const void *data, size_t len,
		__u8 out[CHAIN_DIGEST_LEN]) __must_check;

int sha256_2(const void *a, size_t a_len,
	     const void *b, size_t b_len,
	     __u8 out[CHAIN_DIGEST_LEN]) __must_check;

struct measured_upatch {
	char	name[UPATCH_NAME_MAX + 1];
	char	payload_hex[2 * UPATCH_PAYLOAD_HASH_LEN + 1];
};

/*
 * The event digests every measuring path and the predictor share.
 * The set is sorted by name before hashing.
 */
int chain_init_event(const __u8 cert_sha[32],
		     struct measured_upatch *set, size_t n,
		     const __u8 tree_root[32],
		     __u8 set_digest[32], __u8 event[32]) __must_check;
/* SHA256(tag || NUL || cert_sha256), tag "shirudo-key-revoke". */
int chain_key_event(const char *tag, const __u8 cert_sha[32],
		    __u8 event[32]) __must_check;
int chain_upatch_event(const char *tag, const char *name,
		       const __u8 payload[32], __u8 event[32]) __must_check;
int chain_tree_event(__s64 seq, const __u8 operation_digest[32],
		     __u8 event[32]) __must_check;
int chain_fold(__u8 chain[32], const __u8 event[32]) __must_check;

/* The PCR record anchoring a register name: nvpcr-init:shirudo:0x..:<name>. */
int chain_anchor(const __u8 name[TPM_NAME_LEN],
		 char *out, size_t cap) __must_check;

struct chain_init_info {
	__u8		writer_public[TPM_NV_RSA_BYTES];
	bool		reused;		/* written and on record */
	bool		initrd;		/* bound while the initrd ran */
	__u32		reset_count;	/* the TPM's, for the record */
	__u8		value[CHAIN_DIGEST_LEN];
	__u8		pcr_before[CHAIN_DIGEST_LEN];
	__u8		phase_before[CHAIN_DIGEST_LEN];
	__u8		name[TPM_NAME_LEN];
	size_t		name_len;
	char		anchor[CHAIN_ANCHOR_MAX];
	__u8		anchor_digest[CHAIN_DIGEST_LEN];
};

/*
 * Bind the register to this boot and write the init event. A register
 * written this boot and on record is reused; a record whose index is
 * gone, unwritten or renamed is -EEXIST, since binding again would
 * restart the history it vouches for. -ENODEV without a TPM, -EACCES
 * when the owner hierarchy refuses, -EPROTO when the TPM's name is not
 * the computed one.
 */
int chain_init(const __u8 event[CHAIN_DIGEST_LEN],
	       struct chain_init_info *info);

/*
 * Extend this boot's register by one event through the written
 * branch. -ENODEV when there is no register this boot (no TPM, no
 * init record, index unwritten), -EACCES when the index on the TPM is
 * not the one init recorded (recreated), -EIO on a TPM failure.
 */
int chain_extend(const __u8 event[CHAIN_DIGEST_LEN],
		 __u8 out_chain[CHAIN_DIGEST_LEN]);

/* The live value; -ENODEV when no register is written this boot. */
int chain_read(__u8 out[CHAIN_DIGEST_LEN]);

/* For a probe: a TPM that does not answer is not logged. */
bool chain_bound(void);

struct chain_status {
	bool		tpm;		/* a TPM answered */
	bool		defined;
	bool		written;
	bool		logged;		/* init record this boot */
	bool		anchored;	/* recorded name, same reset */
	bool		rebound;	/* two records for one reset */
	__u8		value[CHAIN_DIGEST_LEN];
	__u8		name[TPM_NAME_LEN];
	size_t		name_len;
	struct eventlog_init init;
};

int chain_status(struct chain_status *st);

#endif /* SHIRUDO_CHAIN_H */
