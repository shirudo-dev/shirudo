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

#define KEYRING_DESC_MAX	512

typedef void (*shirudo_keyring_cb)(key_serial_t serial,
				   const char *type,
				   const char *description,
				   void *ud);

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

struct keyring_cert {
	const __u8	*der;
	size_t		len;
};

/*
 * Whether <keyring> holds exactly the <n> certificates and nothing
 * else: 1 if so, 0 if not, -errno. Two certificates the kernel
 * describes alike cannot both be held; the later link replaces the
 * earlier one.
 */
int keyring_holds_exactly(key_serial_t keyring,
			  const struct keyring_cert *certs, size_t n);

/* The serial of <keyring>'s key for the certificate, -ENOKEY, -errno. */
key_serial_t keyring_find_cert(key_serial_t keyring,
			       const __u8 *der,
			       size_t der_len);

/* Unlink <key> from <keyring>; sealing does not stop this, the LSM may. */
int keyring_unlink_key(key_serial_t keyring, key_serial_t key);

int keyring_list(key_serial_t keyring,
		 shirudo_keyring_cb cb, void *ud);

struct keyring_link {
	key_serial_t	serial;
	int		err;		/* 0, or why it cannot be described */
	char		type[64];
	char		description[KEYRING_DESC_MAX];
};

/*
 * Every link of <keyring>, unlike keyring_list() also those it cannot
 * describe: a key hidden from view still verifies. Freed with
 * xfree(*links, *n * sizeof(**links)). A keyring that keeps gaining
 * links while it is read is -EAGAIN rather than a short list.
 */
int keyring_links(key_serial_t keyring, struct keyring_link **links,
		  size_t *n);

/*
 * The description the kernel gives the asymmetric key it parses from
 * <der>, the one identity a key in a keyring shows.
 */
int keyring_cert_description(const __u8 *der, size_t der_len,
			     char out[KEYRING_DESC_MAX]);

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
key_serial_t keyring_dm_verity_serial(void);
key_serial_t keyring_dm_verity_add_cert(const __u8 *cert,
					size_t cert_len);
int keyring_dm_verity_seal(void);

#endif /* SHIRUDO_KEYRING_H */
