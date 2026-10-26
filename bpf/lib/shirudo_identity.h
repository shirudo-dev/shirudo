/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_BPF_IDENTITY_H
#define SHIRUDO_BPF_IDENTITY_H

#include <shirudo/tpm.h>

/* Frozen ABI shared with struct shirudo_identity in util/identity.h. */
#define SHIRUDO_IDENTITY_KEYS_MAX	16

struct shirudo_sb_id {
	__u32	sb_dev;
	__u32	run_dev;
	__s32	keyring_serial;
	__u32	keyring_type;
	__u32	n_keys;
	__s32	key_serials[SHIRUDO_IDENTITY_KEYS_MAX];
	__u8	runtime_root[32];
	__s32	nv_writer_ring;
	__s32	nv_writer_key;
	__u8	nv_writer_public[SHIRUDO_TPM_NV_RSA_BYTES];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct shirudo_sb_id);
} shirudo_bpffs_sb SEC(".maps");

#endif /* SHIRUDO_BPF_IDENTITY_H */
