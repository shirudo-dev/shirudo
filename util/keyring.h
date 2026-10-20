/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Raw add_key(2)/keyctl(2) wrappers; no libkeyutils.
 */

#ifndef SHIRUDO_KEYRING_H
#define SHIRUDO_KEYRING_H

#include <stddef.h>

#include <shirudo/misc.h>

typedef __s32 key_serial_t;

typedef void (*shirudo_keyring_cb)(key_serial_t serial,
				   const char *type,
				   const char *description,
				   void *ud);

/* -ENOKEY if absent. */
key_serial_t keyring_find(const char *name);

/*
 * As above, but adds the keyring to @u if absent.
 */
key_serial_t keyring_open_or_create(const char *name);

/*
 * Unlink a keyring from @u so init can replace an incomplete stale keyring.
 */
int keyring_unlink_from_user(key_serial_t keyring);

key_serial_t keyring_add_cert(key_serial_t keyring,
			      const void *cert, size_t cert_len);

/*
 * Freeze a keyring for the rest of the boot: drop write/link/setattr
 * (keeping view/read/search) so no key can be added or unlinked and the
 * permissions cannot be relaxed again -- dropping SETATTR makes it a
 * one-way change. The kernel can still find the cert at BPF_PROG_LOAD.
 * Returns 0 or -errno.
 */
int keyring_seal(key_serial_t keyring);

/*
 * Whether <keyring> holds the certificate <der>: 1 when one of its
 * keys is that certificate, 0 when none is, -errno otherwise. The
 * kernel names an asymmetric key after the certificate it parsed, so
 * the comparison is between the description a throwaway instance of
 * the certificate gets on the thread keyring and those of the keys in
 * <keyring>; no key material leaves the kernel.
 */
int keyring_holds_cert(key_serial_t keyring,
		       const __u8 *der, size_t der_len);

/* The serial of <keyring>'s key for the certificate, -ENOKEY, -errno. */
key_serial_t keyring_find_cert(key_serial_t keyring,
			       const __u8 *der,
			       size_t der_len);

/* Unlink <key> from <keyring>; sealing does not stop this, the LSM may. */
int keyring_unlink_key(key_serial_t keyring, key_serial_t key);

int keyring_list(key_serial_t keyring,
		 shirudo_keyring_cb cb, void *ud);

/*
 * The kernel's bpf keyring, the trust anchor a signed loader names with
 * KEY_SPEC_BPF_KEYRING. Sealed empty at boot unless the kernel was
 * booted with bpf.keyring_unsealed=1, in which case it takes keys until
 * userspace seals it; from then on the kernel refuses every
 * caller-supplied keyring for signature verification.
 */
#ifndef KEY_SPEC_BPF_KEYRING
#define KEY_SPEC_BPF_KEYRING	(-9)
#endif

/* Its serial, or -errno on a kernel without one. */
key_serial_t keyring_bpf_serial(void);
/* Enrol a DER certificate; -EPERM once the keyring is sealed. */
key_serial_t keyring_bpf_add_cert(const __u8 *cert,
				  size_t cert_len);
/* Seal it for the rest of the boot: no key can be linked afterwards. */
int keyring_bpf_seal(void);

/* The kernel-owned config trust anchor, populated only by trusted initrd. */
#ifndef KEY_SPEC_DM_VERITY_KEYRING
#define KEY_SPEC_DM_VERITY_KEYRING	(-10)
#endif

/* Resolve the special ID; never fall back to a same-named user keyring. */
key_serial_t shirudo_keyring_dm_verity_serial(void);
key_serial_t shirudo_keyring_dm_verity_add_cert(const __u8 *cert,
						size_t cert_len);
int shirudo_keyring_dm_verity_seal(void);

#endif /* SHIRUDO_KEYRING_H */
