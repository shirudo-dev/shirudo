/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The identity init froze into the kernel, read back from its bpffs pin.
 */

#ifndef SHIRUDO_UTIL_IDENTITY_H
#define SHIRUDO_UTIL_IDENTITY_H

#include <shirudo/misc.h>

/* The keyring kinds the kernel names in a verdict (enum bpf_sig_keyring). */
#define SHIRUDO_SIG_KEYRING_BPF		5

/* The most keys the anchor keyring holds; util/keys.h bounds the set. */
#define SHIRUDO_IDENTITY_KEYS_MAX	16

/* The frozen ABI shared with bpf/lib/shirudo_identity.h. */
struct shirudo_identity {
	__u32	sb_dev;
	__u32	run_dev;
	__s32	keyring_serial;
	__u32	keyring_type;
	__u32	n_keys;
	__s32	key_serials[SHIRUDO_IDENTITY_KEYS_MAX];
	__u8	runtime_root[32];
};

#define SHIRUDO_TASK_TRUSTED	1
#define SHIRUDO_TASK_BOOTSTRAP	2

#define SHIRUDO_DEVICE_RUNTIME	1
#define SHIRUDO_DEVICE_CONFIG	2

struct shirudo_device_authority {
	__u32	dev;
	__u32	kind;
	__u8		root[32];
	__u64	diskseq;
};

/* Image-only task storage for one config mapping preparation. */
struct shirudo_expected_root {
	__u8	root[32];
	__u32 valid;
};

_Static_assert(sizeof(struct shirudo_expected_root) == 36,
	       "expected config root ABI");

struct shirudo_task_authority {
	__u8	trusted;
	__u8	candidate_valid;
	__u8	candidate_trusted;
	__u8	pad;
	__u32	pad2;
};

_Static_assert(sizeof(struct shirudo_device_authority) == 48,
	       "device authority ABI");
_Static_assert(sizeof(struct shirudo_task_authority) == 8,
	       "task authority ABI");
_Static_assert(sizeof(struct shirudo_identity) == 116,
	       "frozen identity ABI");

/*
 * The identity map init populated, froze and pinned this boot. -ENOENT
 * when init has not run, another -errno when the pin cannot be read.
 */
/* 1 when enforcement is active, 0 before init, otherwise -errno. */
int shirudo_enforcement_active(void);
int identity_read(struct shirudo_identity *out);

#endif /* SHIRUDO_UTIL_IDENTITY_H */
