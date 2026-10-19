/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The identity init froze into the kernel, read back from its bpffs pin.
 */

#ifndef SHIRUDO_UTIL_IDENTITY_H
#define SHIRUDO_UTIL_IDENTITY_H

#include <stdint.h>

/* The keyring kinds the kernel names in a verdict (enum bpf_sig_keyring). */
#define SHIRUDO_SIG_KEYRING_USER	4
#define SHIRUDO_SIG_KEYRING_BPF		5

/* The most keys the anchor keyring holds; util/keys.h bounds the set. */
#define SHIRUDO_IDENTITY_KEYS_MAX	16

/*
 * Must match struct shirudo_sb_id in bpf/lib/shirudo_identity.h byte for
 * byte. exe is the binary that keeps running the target; alt_exe, when
 * set, the initrd's copy that ran init and is gone after the switch to
 * the root. key_serials are the anchor keyring's keys, which
 * lsm/key_permission guards with the keyring itself.
 */
struct shirudo_identity {
	uint32_t	sb_dev;
	uint32_t	exe_dev;
	uint64_t	exe_ino;
	int32_t		keyring_serial;
	uint32_t	keyring_type;
	uint32_t	alt_exe_dev;
	uint32_t	pad;
	uint64_t	alt_exe_ino;
	uint32_t	n_keys;
	uint32_t	pad2;
	int32_t		key_serials[SHIRUDO_IDENTITY_KEYS_MAX];
};

/*
 * The identity map init populated, froze and pinned this boot. -ENOENT
 * when init has not run, another -errno when the pin cannot be read.
 */
int shirudo_identity_read(struct shirudo_identity *out);

#endif /* SHIRUDO_UTIL_IDENTITY_H */
