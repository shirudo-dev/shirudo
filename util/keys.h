/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The certificates a target trusts: the primary one and the trusted set.
 */

#ifndef SHIRUDO_UTIL_KEYS_H
#define SHIRUDO_UTIL_KEYS_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

#include <shirudo/misc.h>

#define KEYS_MAX	16
#define KEYS_DER_MAX	(1024 * 1024)

/*
 * A vouch is a detached CMS signature by a member's key over this
 * prefix, NUL included, followed by the vouched certificate's DER.
 */
#define KEYS_VOUCH_PREFIX	"shirudo-key-vouch"

/* voucher is the admitting member's fingerprint, zero for the primary. */
struct trusted_cert {
	char		path[PATH_MAX];
	__u8		sha256[32];		/* of the DER file */
	__u8		fingerprint[32];	/* of the public key */
	__u8		voucher[32];
	bool		primary;		/* cert.der */
};

/*
 * The set is sorted by DER digest and holds each public key once. A
 * trusted certificate is a member only with a vouch beside it that
 * verifies under the primary or under a member admitted before it;
 * one without is counted in n_unvouched and is not a member, nor is
 * one whose fingerprint the revoked directory names. n_revoked counts
 * that directory's certificates. A load that meets a certificate whose
 * key is not ML-DSA-87 refuses the whole set and names that certificate
 * in refused and its algorithm in refused_algorithm.
 */
struct trusted_set {
	struct trusted_cert	certs[KEYS_MAX];
	size_t				n;
	size_t				n_revoked;
	size_t				n_unvouched;
	char				refused[PATH_MAX];
	char				refused_algorithm[32];
};

/*
 * Load cert.der and, when with_trusted, trusted/<fingerprint>.der from
 * the keys directory, leaving out the keys revoked_dir names; NULL
 * means revoked/ beside them. -ENOENT when there is no cert.der, and
 * -EKEYREJECTED only when a certificate is not ML-DSA-87.
 */
int keys_load(const char *keys_dir, const char *revoked_dir,
	      bool with_trusted, struct trusted_set *set);

/*
 * The set of a config image, read through its root descriptor; historical
 * vouches are validated before revoked signing keys are excluded. Fails
 * as keys_load() does.
 */
int keys_load_image_at(const char *primary, int keys_fd,
		       bool with_trusted,
		       struct trusted_set *set);
/* The same from the image root, whose keys directory is opened beneath it. */
int keys_load_image_root(const char *primary, int root_fd,
			 bool with_trusted,
			 struct trusted_set *set);

struct cert;

/*
 * A member's DER as the loader read it, owned by the store, or its
 * parsed certificate; -ENOKEY for a member no loader of this process
 * admitted.
 */
int keys_cert_der(const struct trusted_cert *c, const __u8 **der,
		  size_t *len);
/* The member with that fingerprint, or NULL. */
const struct trusted_cert *keys_member(const struct trusted_set *set,
				       const __u8 fingerprint[32]);
int keys_cert_read(const struct trusted_cert *c,
		   struct cert *cert);

/* A whole file of at most KEYS_DER_MAX bytes, xmalloc'd. */
int keys_read_der(const char *path, __u8 **out,
		  size_t *out_sz);
int keys_read_der_fd(int fd, __u8 **out, size_t *out_sz);

int keys_digest_der(const __u8 *der, size_t der_sz,
		    __u8 sha256[32], __u8 fingerprint[32]);
int keys_digest_file(const char *path, __u8 sha256[32],
		     __u8 fingerprint[32]);

/*
 * The digest the init event covers: the one certificate's digest, or
 * the SHA-256 over the sorted digests of several. The same function
 * serves the operator predicting a register for a set.
 */
int keys_anchor_digest(const __u8 sha256[][32], size_t n,
		       __u8 out[32]);
int keys_set_digest(const struct trusted_set *set,
		    __u8 out[32]);

bool keys_is_revoked(const char *revoked_dir,
		     const __u8 fingerprint[32]);

/* The bytes a vouch signs: the prefix and the certificate, xmalloc'd. */
int keys_vouch_payload(const __u8 *der, size_t der_sz,
		       __u8 **out, size_t *out_sz);

/* Verify a detached signature under a member; signer may be NULL. */
int keys_verify_signature(const struct trusted_set *set,
			  const __u8 *payload, size_t payload_sz,
			  const __u8 *sig, size_t sig_sz,
			  __u8 signer[32]);

/*
 * Whether a member of the set signed the vouch for this certificate:
 * 0 with the member's fingerprint in voucher, -EKEYREJECTED when none did.
 */
int keys_verify_vouch(const struct trusted_set *set,
		      const __u8 *der, size_t der_sz,
		      const __u8 *sig, size_t sig_sz,
		      __u8 voucher[32]);

/*
 * Write the certificate and its vouch under <keys_dir>/trusted, named
 * by fingerprint, the vouch first so a visible certificate always has
 * one. out gets the certificate's path.
 */
int keys_install(const char *keys_dir, const __u8 *der,
		 size_t der_sz, const __u8 *sig,
		 size_t sig_sz, char *out, size_t cap);

#endif /* SHIRUDO_UTIL_KEYS_H */
