/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The identity init froze into the kernel, read back from its bpffs pin.
 */

#ifndef SHIRUDO_UTIL_IDENTITY_H
#define SHIRUDO_UTIL_IDENTITY_H

#include <shirudo/misc.h>
#include <shirudo/tpm.h>

/* The keyring kinds the kernel names in a verdict (enum bpf_sig_keyring). */
#define SIG_KEYRING_BPF		5

/* The most keys the anchor keyring holds; util/keys.h bounds the set. */
#define IDENTITY_KEYS_MAX	16u

/* The frozen ABI shared with bpf/lib/identity.h. */
struct identity {
	__u32	sb_dev;
	__u32	run_dev;
	__s32	keyring_serial;
	__u32	keyring_type;
	__u32	n_keys;
	__s32	key_serials[IDENTITY_KEYS_MAX];
	__u8	runtime_root[32];
	__u8	nv_writer_seed[32];
	__u8	nv_writer_public[TPM_NV_RSA_BYTES];
	__u8	ak_name[TPM_NAME_LEN];
	__u32	ak_name_len;
	__s32	dm_verity_ring;
	__s32	dm_verity_key;
	__u32	nv_index;
};

#define TASK_TRUSTED	1
#define TASK_BOOTSTRAP	2

#define DEVICE_RUNTIME	1
#define DEVICE_CONFIG	2

struct device_authority {
	__u32	dev;
	__u32	kind;
	__u8		root[32];
	__u64	diskseq;
};

/* Task storage for one config mapping preparation. */
struct expected_root {
	__u8	root[32];
	__u32 valid;
};

BUILD_BUG_ON(sizeof(struct expected_root) != 36);

struct task_authority {
	__u8	trusted;
	__u8	candidate_valid;
	__u8	candidate_trusted;
	__u8	pad;
	__u32	pad2;
};

BUILD_BUG_ON(sizeof(struct device_authority) != 48);
BUILD_BUG_ON(sizeof(struct task_authority) != 8);
BUILD_BUG_ON(sizeof(struct identity) != 584);

struct shirudo_task_policy {
	__u64	active;
	__u64	candidate;
};

_Static_assert(sizeof(struct shirudo_task_policy) == 16,
	       "task policy ABI");

/* The bpffs mount init made, which the unmount guard keeps mounted. */
struct mount_record {
	__u64	mount;
};

BUILD_BUG_ON(sizeof(struct mount_record) != 8);

/*
 * The identity map init populated, froze and pinned this boot. -ENOENT
 * when init has not run, another -errno when the pin cannot be read.
 */
/* 1 when enforcement is active, 0 before init, otherwise -errno. */
int enforcement_active(void);
int identity_read(struct identity *out);

#endif /* SHIRUDO_UTIL_IDENTITY_H */
