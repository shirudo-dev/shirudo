/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The identity init froze into the kernel, read back from its bpffs pin,
 * and the shape of every map init pins beside it.
 */

#ifndef SHIRUDO_UTIL_IDENTITY_H
#define SHIRUDO_UTIL_IDENTITY_H

#include <stdbool.h>

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
	__u8	ek_name[TPM_NAME_LEN];
	__s32	dm_verity_ring;
	__u32	n_dm_verity_keys;
	__s32	dm_verity_keys[IDENTITY_KEYS_MAX];
	__u32	nv_index;
	__u32	config_pcr;
	__u64	state_dev;
	__u64	state_ino;
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
	__u8	revoked;
	__u32	pad2;
};

struct task_policy {
	__u64	active;
	__u64	candidate;
};

BUILD_BUG_ON(sizeof(struct device_authority) != 48);
BUILD_BUG_ON(sizeof(struct task_authority) != 8);
BUILD_BUG_ON(sizeof(struct identity) != 664);
BUILD_BUG_ON(sizeof(struct task_policy) != 16);

/* The bpffs mount init made, which the unmount guard keeps mounted. */
struct mount_record {
	__u64	mount;
	__u64	mount_ns;
	__u64	initrd_root_id;
	__u64	sysroot_id;
};

BUILD_BUG_ON(sizeof(struct mount_record) != 32);

enum guard_map_index {
	GUARD_IDENTITY,
	GUARD_TASKS,
	GUARD_DEVICES,
	GUARD_ROOTS,
	GUARD_TAMPER,
	GUARD_POLICY,
	GUARD_SOCKET_POLICY,
	GUARD_INTEGRITY,
	GUARD_UNLINK_GRANT,
	GUARD_MAP_COUNT,
};

struct guard_map {
	const char *name;
	const char *pin;
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 flags;
};

extern const struct guard_map
	shirudo_guard_maps[GUARD_MAP_COUNT];

/*
 * Whether name, as the kernel reports an object's, is the one it keeps of
 * an object created as full, which is its first BPF_OBJ_NAME_LEN - 1
 * bytes.
 */
bool guard_name_matches(const char *name, const char *full);

/*
 * 0 when the map behind fd has the type, sizes, flags and name expected
 * gives it, -EPROTO when it has not, or the kernel's error; *id, unless
 * NULL, then holds the map's id.
 */
int guard_map_check(int fd, const struct guard_map *expected, __u32 *id);

/* 1 when enforcement is active, 0 before init, otherwise -errno. */
int enforcement_active(void);

/*
 * The identity map init populated, froze and pinned this boot. -ENOENT
 * when init has not run, another -errno when the pin cannot be read.
 * identity_read_at() takes the pin's name relative to dirfd, as openat()
 * does.
 */
int identity_read(struct identity *out);
int identity_read_at(int dirfd, const char *name, struct identity *out);

/*
 * The root of the private bpffs init mounted this boot, as a directory
 * descriptor. -ENOENT when init has not run, -EXDEV when BPFFS_DIR is
 * not on that bpffs, another -errno when it cannot be opened or read.
 */
int bpffs_root_open(void);
/* The sealed state directory whose device and inode init froze this boot. */
int state_root_open(void);
int identity_check_state_root(const struct identity *id, int fd);

#endif /* SHIRUDO_UTIL_IDENTITY_H */
