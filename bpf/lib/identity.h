/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_BPF_IDENTITY_H
#define SHIRUDO_BPF_IDENTITY_H

#include <shirudo/tpm.h>

/* Frozen ABI shared with struct identity in util/identity.h. */
#define IDENTITY_KEYS_MAX	16u

struct sb_id {
	__u32	sb_dev;
	__u32	run_dev;
	__s32	keyring_serial;
	__u32	keyring_type;
	__u32	n_keys;
	__s32	key_serials[IDENTITY_KEYS_MAX];
	__u8	runtime_root[32];
	__u8	nv_writer_seed[32];
	__u8	nv_writer_public[TPM_NV_RSA_BYTES];
	__u8	ek_name[TPM_NAME_LEN];
	__s32	dm_verity_ring;
	__u32	n_dm_verity_keys;
	__s32	dm_verity_keys[IDENTITY_KEYS_MAX];
	__u32	nv_index;
	__u32	config_pcr;
	__u64	state_dev;
	__u64	state_ino;
	__u32	enforcement;	/* ENFORCEMENT_STRICT or _SHARED */
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct sb_id);
} shirudo_bpffs_sb SEC(".maps");

/* The bpffs mount of init's namespace, as the unmount guard keeps it. */
struct mount_record {
	__u64	mount;
	__u64	mount_ns;
	__u64	initrd_root_id;
	__u64	sysroot_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct mount_record);
} shirudo_mnt_rec SEC(".maps");

#endif /* SHIRUDO_BPF_IDENTITY_H */
