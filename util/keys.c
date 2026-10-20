// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The certificates a target trusts: the primary one and the trusted set.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "crypto.h"
#include "hex.h"
#include "io.h"
#include "keys.h"
#include "malloc.h"
#include "paths.h"
#include "seal.h"

/* Files under trusted/ a load looks at, members or not. */
#define KEYS_SCAN_MAX	64

struct keys_candidate {
	char		path[PATH_MAX];
	unsigned char	*der;
	size_t		der_sz;
	uint8_t		sha256[32];
	uint8_t		fingerprint[32];
	bool		done;
};

int shirudo_keys_read_der(const char *path, unsigned char **out,
			  size_t *out_sz)
{
	unsigned char *buf;
	struct stat st;
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) < 0) {
		int rc = -errno;

		close(fd);
		return rc;
	}
	if (!S_ISREG(st.st_mode) || st.st_size <= 0 ||
	    st.st_size > SHIRUDO_KEYS_DER_MAX) {
		close(fd);
		return -EINVAL;
	}
	buf = xmalloc((size_t)st.st_size);
	if (!buf) {
		close(fd);
		return -ENOMEM;
	}
	n = read(fd, buf, (size_t)st.st_size);
	close(fd);
	if (n != st.st_size) {
		xfree(buf, (size_t)st.st_size);
		return -EIO;
	}
	*out = buf;
	*out_sz = (size_t)st.st_size;
	return 0;
}

int shirudo_keys_digest_der(const unsigned char *der, size_t der_sz,
			    uint8_t sha256[32], uint8_t fingerprint[32])
{
	struct shirudo_cert cert = {};
	int rc;

	rc = shirudo_sha256_buffer(der, der_sz, sha256);
	if (rc)
		return rc;
	rc = shirudo_cert_read_der(der, der_sz, &cert);
	if (rc)
		return rc;
	rc = shirudo_cert_pubkey_digest(&cert, fingerprint);
	shirudo_cert_free(&cert);
	return rc;
}

int shirudo_keys_digest_file(const char *path, uint8_t sha256[32],
			     uint8_t fingerprint[32])
{
	unsigned char *der = NULL;
	size_t der_sz = 0;
	int rc;

	rc = shirudo_keys_read_der(path, &der, &der_sz);
	if (rc)
		return rc;
	rc = shirudo_keys_digest_der(der, der_sz, sha256, fingerprint);
	xfree(der, der_sz);
	return rc;
}

int shirudo_keys_path_for(const char *dir, const uint8_t fingerprint[32],
			  const char *suffix, char *out, size_t cap)
{
	char hex[65];

	shirudo_hex_encode(fingerprint, 32, hex);
	if ((size_t)snprintf(out, cap, "%s/%s%s", dir, hex, suffix) >= cap)
		return -ENAMETOOLONG;
	return 0;
}

bool shirudo_keys_is_revoked(const char *revoked_dir,
			     const uint8_t fingerprint[32])
{
	char path[PATH_MAX];

	if (shirudo_keys_path_for(revoked_dir, fingerprint, ".der", path,
				  sizeof(path)))
		return false;
	return access(path, F_OK) == 0;
}

int shirudo_keys_vouch_payload(const unsigned char *der, size_t der_sz,
			       unsigned char **out, size_t *out_sz)
{
	size_t n = sizeof(SHIRUDO_KEYS_VOUCH_PREFIX) + der_sz;
	unsigned char *buf = xmalloc(n);

	if (!buf)
		return -ENOMEM;
	memcpy(buf, SHIRUDO_KEYS_VOUCH_PREFIX,
	       sizeof(SHIRUDO_KEYS_VOUCH_PREFIX));
	memcpy(buf + sizeof(SHIRUDO_KEYS_VOUCH_PREFIX), der, der_sz);
	*out = buf;
	*out_sz = n;
	return 0;
}

int shirudo_keys_verify_vouch(const struct shirudo_trusted_set *set,
			      const unsigned char *der, size_t der_sz,
			      const unsigned char *sig, size_t sig_sz,
			      uint8_t voucher[32])
{
	unsigned char *payload = NULL;
	size_t payload_sz = 0, i;
	int rc;

	rc = shirudo_keys_vouch_payload(der, der_sz, &payload, &payload_sz);
	if (rc)
		return rc;
	rc = -EKEYREJECTED;
	for (i = 0; i < set->n && rc; i++) {
		struct shirudo_cert cert = {};

		if (shirudo_cert_read_file(set->certs[i].path, &cert))
			continue;
		if (shirudo_verify_detached(payload, payload_sz, sig, sig_sz,
					    &cert) == 0) {
			memcpy(voucher, set->certs[i].fingerprint, 32);
			rc = 0;
		}
		shirudo_cert_free(&cert);
	}
	xfree(payload, payload_sz);
	return rc;
}

static int cert_cmp(const void *a, const void *b)
{
	return memcmp(((const struct shirudo_trusted_cert *)a)->sha256,
		      ((const struct shirudo_trusted_cert *)b)->sha256, 32);
}

static bool set_holds(const struct shirudo_trusted_set *set,
		      const uint8_t fingerprint[32])
{
	size_t i;

	for (i = 0; i < set->n; i++)
		if (memcmp(set->certs[i].fingerprint, fingerprint, 32) == 0)
			return true;
	return false;
}

static int set_add(struct shirudo_trusted_set *set, const char *path,
		   const uint8_t sha256[32], const uint8_t fingerprint[32],
		   const uint8_t voucher[32])
{
	struct shirudo_trusted_cert *c;

	if (set->n >= SHIRUDO_KEYS_MAX)
		return -E2BIG;
	c = &set->certs[set->n];
	memset(c, 0, sizeof(*c));
	if (snprintf(c->path, sizeof(c->path), "%s", path) >=
	    (int)sizeof(c->path))
		return -ENAMETOOLONG;
	memcpy(c->sha256, sha256, 32);
	memcpy(c->fingerprint, fingerprint, 32);
	if (voucher)
		memcpy(c->voucher, voucher, 32);
	else
		c->primary = true;
	set->n++;
	return 0;
}

static int select_der(const struct dirent *e)
{
	size_t n = strlen(e->d_name);

	return n > 4 && strcmp(e->d_name + n - 4, ".der") == 0;
}

static size_t count_der(const char *dir)
{
	struct dirent **names = NULL;
	int n, i;

	n = scandir(dir, &names, select_der, NULL);
	if (n < 0)
		return 0;
	for (i = 0; i < n; i++)
		shirudo_libc_free(names[i]);	/* scandir-owned */
	shirudo_libc_free(names);		/* scandir-owned */
	return (size_t)n;
}

/* <name>.der has its vouch at <name>.vouch. */
static int vouch_path_for(const char *der_path, char *out, size_t cap)
{
	size_t n = strlen(der_path) - 4;

	if ((size_t)snprintf(out, cap, "%.*s.vouch", (int)n, der_path) >= cap)
		return -ENAMETOOLONG;
	return 0;
}

/*
 * Admit the candidates whose vouch verifies under a member, in rounds,
 * so a certificate vouched for by one admitted later still joins.
 */
static int admit_vouched(struct shirudo_trusted_set *set,
			 struct keys_candidate *cand, size_t n_cand)
{
	bool progress = true;
	size_t i;

	while (progress) {
		progress = false;
		for (i = 0; i < n_cand; i++) {
			struct keys_candidate *c = &cand[i];
			unsigned char *sig = NULL;
			char vouch[PATH_MAX];
			uint8_t voucher[32];
			size_t sig_sz = 0;
			int rc;

			if (c->done)
				continue;
			if (set_holds(set, c->fingerprint)) {
				c->done = true;
				continue;
			}
			if (vouch_path_for(c->path, vouch, sizeof(vouch)) ||
			    shirudo_keys_read_der(vouch, &sig, &sig_sz))
				continue;
			rc = shirudo_keys_verify_vouch(set, c->der, c->der_sz,
						       sig, sig_sz, voucher);
			xfree(sig, sig_sz);
			if (rc)
				continue;
			rc = set_add(set, c->path, c->sha256, c->fingerprint,
				     voucher);
			if (rc)
				return rc;
			c->done = true;
			progress = true;
		}
	}
	for (i = 0; i < n_cand; i++)
		if (!cand[i].done)
			set->n_unvouched++;
	return 0;
}

static void candidates_free(struct keys_candidate *cand, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (cand[i].der)
			xfree(cand[i].der, cand[i].der_sz);
	xfree(cand, KEYS_SCAN_MAX * sizeof(*cand));
}

/*
 * Read every .der under trusted/: the ones not revoked become
 * candidates for admission, which needs the whole list first.
 */
static int scan_trusted(const char *keys_dir, const char *revoked_dir,
			struct shirudo_trusted_set *set,
			struct keys_candidate *cand, size_t *n_cand)
{
	struct dirent **names = NULL;
	char dir[PATH_MAX];
	int n, i, rc = 0;

	if (snprintf(dir, sizeof(dir), "%s/trusted", keys_dir) >=
	    (int)sizeof(dir))
		return -ENAMETOOLONG;
	n = scandir(dir, &names, select_der, alphasort);
	if (n < 0)
		return errno == ENOENT ? 0 : -errno;
	for (i = 0; i < n && !rc; i++) {
		struct keys_candidate *c = &cand[*n_cand];

		if (*n_cand >= KEYS_SCAN_MAX) {
			rc = -E2BIG;
			break;
		}
		if (snprintf(c->path, sizeof(c->path), "%s/%s", dir,
			     names[i]->d_name) >= (int)sizeof(c->path)) {
			rc = -ENAMETOOLONG;
			break;
		}
		rc = shirudo_keys_read_der(c->path, &c->der, &c->der_sz);
		if (rc)
			break;
		rc = shirudo_keys_digest_der(c->der, c->der_sz, c->sha256,
					     c->fingerprint);
		if (rc) {
			xfree(c->der, c->der_sz);
			c->der = NULL;
			break;
		}
		if (shirudo_keys_is_revoked(revoked_dir, c->fingerprint)) {
			xfree(c->der, c->der_sz);
			c->der = NULL;
			continue;
		}
		(*n_cand)++;
	}
	for (i = 0; i < n; i++)
		shirudo_libc_free(names[i]);	/* scandir-owned */
	shirudo_libc_free(names);		/* scandir-owned */
	return rc;
}

int shirudo_keys_load(const char *keys_dir, const char *revoked_dir,
		      bool with_trusted, struct shirudo_trusted_set *set)
{
	struct keys_candidate *cand = NULL;
	uint8_t sha256[32], fingerprint[32];
	char revoked[PATH_MAX];
	char path[PATH_MAX];
	size_t n_cand = 0;
	int rc;

	memset(set, 0, sizeof(*set));
	if (!revoked_dir) {
		if (snprintf(revoked, sizeof(revoked), "%s/revoked",
			     keys_dir) >= (int)sizeof(revoked))
			return -ENAMETOOLONG;
		revoked_dir = revoked;
	}
	if (snprintf(path, sizeof(path), "%s/%s", keys_dir,
		     SHIRUDO_CERT_FILE) >= (int)sizeof(path))
		return -ENAMETOOLONG;
	rc = shirudo_keys_digest_file(path, sha256, fingerprint);
	if (rc)
		return rc;
	if (!shirudo_keys_is_revoked(revoked_dir, fingerprint))
		set_add(set, path, sha256, fingerprint, NULL);
	set->n_revoked = count_der(revoked_dir);
	if (!with_trusted)
		return 0;

	cand = xcalloc(KEYS_SCAN_MAX, sizeof(*cand));
	if (!cand)
		return -ENOMEM;
	rc = scan_trusted(keys_dir, revoked_dir, set, cand, &n_cand);
	if (!rc)
		rc = admit_vouched(set, cand, n_cand);
	candidates_free(cand, n_cand);
	if (rc)
		return rc;
	if (set->n > 1)
		qsort(set->certs, set->n, sizeof(set->certs[0]), cert_cmp);
	return 0;
}

static int digest_cmp(const void *a, const void *b)
{
	return memcmp(a, b, 32);
}

void shirudo_keys_anchor_digest(const uint8_t (*sha256)[32], size_t n,
				uint8_t out[32])
{
	uint8_t sorted[SHIRUDO_KEYS_MAX][32];
	size_t i;

	if (n == 1) {
		memcpy(out, sha256[0], 32);
		return;
	}
	if (n == 0 || n > SHIRUDO_KEYS_MAX) {
		memset(out, 0, 32);
		return;
	}
	for (i = 0; i < n; i++)
		memcpy(sorted[i], sha256[i], 32);
	qsort(sorted, n, 32, digest_cmp);
	shirudo_sha256_buffer(sorted, n * 32, out);
}

void shirudo_keys_set_digest(const struct shirudo_trusted_set *set,
			     uint8_t out[32])
{
	uint8_t sha[SHIRUDO_KEYS_MAX][32];
	size_t i;

	for (i = 0; i < set->n; i++)
		memcpy(sha[i], set->certs[i].sha256, 32);
	shirudo_keys_anchor_digest(sha, set->n, out);
}

/* Write whole, then rename into place; a stale .tmp is overwritten. */
int shirudo_keys_write_file(const char *path, const void *data, size_t len)
{
	return shirudo_seal_write_file(path, data, len, 0644);
}

int shirudo_keys_install(const char *keys_dir, const unsigned char *der,
			 size_t der_sz, const unsigned char *sig,
			 size_t sig_sz, char *out, size_t cap)
{
	uint8_t sha256[32], fingerprint[32];
	char vouch[PATH_MAX];
	char dir[PATH_MAX];
	int rc;

	rc = shirudo_keys_digest_der(der, der_sz, sha256, fingerprint);
	if (rc)
		return rc;
	if (snprintf(dir, sizeof(dir), "%s/trusted", keys_dir) >=
	    (int)sizeof(dir))
		return -ENAMETOOLONG;
	rc = shirudo_seal_mkdir_p(dir, 0700);
	if (rc)
		return rc;
	rc = shirudo_keys_path_for(dir, fingerprint, ".der", out, cap);
	if (!rc)
		rc = shirudo_keys_path_for(dir, fingerprint, ".vouch", vouch,
					   sizeof(vouch));
	if (rc)
		return rc;
	rc = shirudo_keys_write_file(vouch, sig, sig_sz);
	if (rc)
		return rc;
	rc = shirudo_keys_write_file(out, der, der_sz);
	if (rc)
		unlink(vouch);
	return rc;
}
