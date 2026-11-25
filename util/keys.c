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

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include "crypto.h"
#include "hex.h"
#include "io.h"
#include "log.h"
#include "keys.h"
#include "malloc.h"
#include "paths.h"
#include "seal.h"

/* Files under trusted/ a load looks at, members or not. */
#define KEYS_SCAN_MAX	64

struct keys_candidate {
	char		path[PATH_MAX];
	char		name[256];	/* in dirfd, when that is not -1 */
	__u8		*der;
	size_t		der_sz;
	__u8		sha256[32];
	__u8		fingerprint[32];
	int		dirfd;
	bool		done;
};

int keys_read_der_fd(int fd, __u8 **out, size_t *out_sz)
{
	int ret = read_fd(fd, "certificate", KEYS_DER_MAX, out, out_sz);

	if (!ret && !*out_sz) {
		xfree(*out, 1);
		*out = NULL;
		return -EINVAL;
	}
	return ret;
}

static int keys_read_der_at(int dirfd, const char *name, __u8 **out,
			    size_t *out_sz)
{
	int fd, ret;

	fd = open_beneath(dirfd, name, O_RDONLY);
	if (fd < 0)
		return fd;
	ret = keys_read_der_fd(fd, out, out_sz);
	close(fd);
	return ret;
}

int keys_read_der(const char *path, __u8 **out,
		  size_t *out_sz)
{
	struct stat st;
	__u8 *buf;
	ssize_t n;
	int fd;

	fd = open_trusted(path, O_RDONLY);
	if (fd < 0)
		return fd;
	if (fstat(fd, &st) < 0) {
		int ret = -errno;

		close(fd);
		return ret;
	}
	if (!S_ISREG(st.st_mode) || st.st_size <= 0 ||
	    st.st_size > KEYS_DER_MAX) {
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

int keys_digest_der(const __u8 *der, size_t der_sz,
		    __u8 sha256[32], __u8 fingerprint[32])
{
	struct cert cert = {};
	int ret;

	ret = sha256_buffer(der, der_sz, sha256);
	if (ret)
		return ret;
	ret = cert_read_der(der, der_sz, &cert);
	if (ret)
		return ret;
	ret = cert_pubkey_digest(&cert, fingerprint);
	cert_free(&cert);
	return ret;
}

/*
 * The DER of every certificate a set took, by its digest. Whoever needs
 * the bytes later, to enrol, to look in the keyring or to check a vouch,
 * takes them from here: a path reopened then may name other bytes, and
 * a member read from a config image has no path at all.
 */
struct der_entry {
	__u8	sha256[32];
	__u8	*der;
	size_t	len;
};

static struct der_entry der_store[8 * KEYS_MAX];
static size_t der_stored;

static int der_keep(const __u8 sha256[32], const __u8 *der, size_t len)
{
	struct der_entry *e;
	size_t i;

	for (i = 0; i < der_stored; i++) {
		if (!memcmp(der_store[i].sha256, sha256, 32))
			return 0;
	}
	if (der_stored >= ARRAY_SIZE(der_store))
		return -E2BIG;
	e = &der_store[der_stored];
	e->der = xmalloc(len);
	if (!e->der)
		return -ENOMEM;
	memcpy(e->der, der, len);
	memcpy(e->sha256, sha256, 32);
	e->len = len;
	der_stored++;
	return 0;
}

int keys_cert_der(const struct trusted_cert *c, const __u8 **der,
		  size_t *len)
{
	size_t i;

	for (i = 0; i < der_stored; i++) {
		if (!memcmp(der_store[i].sha256, c->sha256, 32)) {
			*der = der_store[i].der;
			*len = der_store[i].len;
			return 0;
		}
	}
	return -ENOKEY;
}

const struct trusted_cert *keys_member(const struct trusted_set *set,
				       const __u8 fingerprint[32])
{
	size_t i;

	for (i = 0; i < set->n; i++) {
		if (!memcmp(set->certs[i].fingerprint, fingerprint, 32))
			return &set->certs[i];
	}
	return NULL;
}

int keys_cert_read(const struct trusted_cert *c,
		   struct cert *cert)
{
	const __u8 *der;
	size_t len;
	int ret;

	ret = keys_cert_der(c, &der, &len);
	return ret ? ret : cert_read_der(der, len, cert);
}

/*
 * The kernel verifies a loader under any algorithm it can parse, and
 * init enrols the set in .bpf, so a certificate of another kind would
 * let a classical signature load BPF: it refuses the whole set. The
 * check comes before der_keep(), whose store is never emptied and
 * would otherwise fill up with what no set took.
 */
static int set_require_mldsa87(struct trusted_set *set, const char *path,
			       const __u8 *der, size_t der_sz)
{
	int ret;

	ret = cert_der_require_mldsa87(der, der_sz, set->refused_algorithm,
				       sizeof(set->refused_algorithm));
	if (ret != -EKEYREJECTED)
		return ret;
	if (strscpy(set->refused, path, sizeof(set->refused)) < 0)
		return -ENAMETOOLONG;
	pr_err("%s is %s; shirudo accepts only ML-DSA-87", path,
	       set->refused_algorithm);
	return ret;
}

/* The certificate at path, its digests, and its bytes kept for the set. */
static int keys_take_file(struct trusted_set *set, const char *path,
			  __u8 sha256[32], __u8 fingerprint[32])
{
	size_t der_sz = 0;
	__u8 *der = NULL;
	int ret;

	ret = keys_read_der(path, &der, &der_sz);
	if (ret)
		return ret;
	ret = keys_digest_der(der, der_sz, sha256, fingerprint);
	if (!ret)
		ret = set_require_mldsa87(set, path, der, der_sz);
	if (!ret)
		ret = der_keep(sha256, der, der_sz);
	xfree(der, der_sz);
	return ret;
}

int keys_digest_file(const char *path, __u8 sha256[32],
		     __u8 fingerprint[32])
{
	size_t der_sz = 0;
	__u8 *der = NULL;
	int ret;

	ret = keys_read_der(path, &der, &der_sz);
	if (ret)
		return ret;
	ret = keys_digest_der(der, der_sz, sha256, fingerprint);
	xfree(der, der_sz);
	return ret;
}

/* <dir>/<fingerprint hex><suffix>, the name a certificate has in a set. */
static int keys_path_for(const char *dir, const __u8 fingerprint[32],
			 const char *suffix, char *out, size_t cap)
{
	char hex[65];

	hex_encode(fingerprint, 32, hex);
	if (strsprintf(out, cap, "%s/%s%s", dir, hex, suffix) < 0)
		return -ENAMETOOLONG;
	return 0;
}

bool keys_is_revoked(const char *revoked_dir,
		     const __u8 fingerprint[32])
{
	char path[PATH_MAX];

	if (!revoked_dir ||
	    keys_path_for(revoked_dir, fingerprint, ".der", path,
			  sizeof(path)))
		return false;
	return access(path, F_OK) == 0;
}

static bool keys_is_revoked_at(int revoked_fd, const __u8 fingerprint[32])
{
	char name[64 + sizeof(".der")];

	if (revoked_fd < 0)
		return false;
	hex_encode(fingerprint, 32, name);
	memcpy(name + 64, ".der", sizeof(".der"));
	return faccessat(revoked_fd, name, F_OK, 0) == 0;
}

int keys_vouch_payload(const __u8 *der, size_t der_sz,
		       __u8 **out, size_t *out_sz)
{
	size_t n = size_add(sizeof(KEYS_VOUCH_PREFIX), der_sz);
	__u8 *buf = xmalloc(n);

	if (!buf)
		return -ENOMEM;
	memcpy(buf, KEYS_VOUCH_PREFIX,
	       sizeof(KEYS_VOUCH_PREFIX));
	memcpy(buf + sizeof(KEYS_VOUCH_PREFIX), der, der_sz);
	*out = buf;
	*out_sz = n;
	return 0;
}

int keys_verify_signature(const struct trusted_set *set,
			  const __u8 *payload, size_t payload_sz,
			  const __u8 *sig, size_t sig_sz,
			  __u8 signer[32])
{
	size_t i;

	for (i = 0; i < set->n; i++) {
		struct cert cert = {};
		int ret;

		ret = keys_cert_read(&set->certs[i], &cert);
		if (ret)
			return ret;
		ret = verify_detached(payload, payload_sz, sig, sig_sz, &cert);
		cert_free(&cert);
		if (!ret) {
			if (signer)
				memcpy(signer, set->certs[i].fingerprint, 32);
			return 0;
		}
	}
	return -EKEYREJECTED;
}

int keys_verify_vouch(const struct trusted_set *set,
		      const __u8 *der, size_t der_sz,
		      const __u8 *sig, size_t sig_sz,
		      __u8 voucher[32])
{
	size_t payload_sz = 0;
	__u8 *payload = NULL;
	int ret;

	ret = keys_vouch_payload(der, der_sz, &payload, &payload_sz);
	if (ret)
		return ret;
	ret = keys_verify_signature(set, payload, payload_sz, sig, sig_sz,
				    voucher);
	xfree(payload, payload_sz);
	return ret;
}

static int cert_cmp(const void *a, const void *b)
{
	return memcmp(((const struct trusted_cert *)a)->sha256,
		      ((const struct trusted_cert *)b)->sha256, 32);
}

static bool set_holds(const struct trusted_set *set,
		      const __u8 fingerprint[32])
{
	size_t i;

	for (i = 0; i < set->n; i++) {
		if (memcmp(set->certs[i].fingerprint, fingerprint, 32) == 0)
			return true;
	}
	return false;
}

static int set_add(struct trusted_set *set, const char *path,
		   const __u8 sha256[32], const __u8 fingerprint[32],
		   const __u8 voucher[32], const __u8 *der, size_t der_sz)
{
	struct trusted_cert *c;
	int ret;

	if (set->n >= KEYS_MAX)
		return -E2BIG;
	if (der) {
		ret = set_require_mldsa87(set, path, der, der_sz);
		if (!ret)
			ret = der_keep(sha256, der, der_sz);
		if (ret)
			return ret;
	}
	c = &set->certs[set->n];
	memset(c, 0, sizeof(*c));
	if (strscpy(c->path, path, sizeof(c->path)) < 0)
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
	return name_has_suffix(e->d_name, strlen(e->d_name), ".der");
}

static size_t count_der(const char *dir)
{
	struct dirent **names = NULL;
	int n, i;

	n = scandir(dir, &names, select_der, NULL);
	if (n < 0)
		return 0;
	for (i = 0; i < n; i++)
		libc_free(names[i]);
	libc_free(names);
	return (size_t)n;
}

static size_t count_der_at(int dirfd)
{
	struct dirent **names = NULL;
	int n, i;

	if (dirfd < 0)
		return 0;
	n = scandirat(dirfd, ".", &names, select_der, NULL);
	if (n < 0)
		return 0;
	for (i = 0; i < n; i++)
		libc_free(names[i]);
	libc_free(names);
	return (size_t)n;
}

static int vouch_path_for(const char *der_path, char *out, size_t cap)
{
	size_t n = strlen(der_path) - 4;

	if (strsprintf(out, cap, "%.*s.vouch", (int)n, der_path) < 0)
		return -ENAMETOOLONG;
	return 0;
}

/*
 * Admit the candidates whose vouch verifies under a member, in rounds,
 * so a certificate vouched for by one admitted later still joins.
 */
static int admit_vouched(struct trusted_set *set,
			 struct keys_candidate *cand, size_t n_cand)
{
	bool progress = true;
	size_t i;

	while (progress) {
		progress = false;
		for (i = 0; i < n_cand; i++) {
			struct keys_candidate *c = &cand[i];
			char vouch[PATH_MAX];
			size_t sig_sz = 0;
			__u8 *sig = NULL;
			__u8 voucher[32];
			int ret;

			if (c->done)
				continue;
			if (set_holds(set, c->fingerprint)) {
				c->done = true;
				continue;
			}
			if (vouch_path_for(c->dirfd >= 0 ? c->name : c->path,
					   vouch, sizeof(vouch)) ||
			    (c->dirfd >= 0 ?
			     keys_read_der_at(c->dirfd, vouch, &sig, &sig_sz) :
			     keys_read_der(vouch, &sig, &sig_sz)))
				continue;
			ret = keys_verify_vouch(set, c->der, c->der_sz,
						sig, sig_sz, voucher);
			xfree(sig, sig_sz);
			if (ret)
				continue;
			ret = set_add(set, c->path, c->sha256, c->fingerprint,
				      voucher, c->der, c->der_sz);
			if (ret)
				return ret;
			c->done = true;
			progress = true;
		}
	}
	for (i = 0; i < n_cand; i++) {
		if (!cand[i].done)
			set->n_unvouched++;
	}
	return 0;
}

static void candidates_free(struct keys_candidate *cand, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		xfree(cand[i].der, cand[i].der_sz);
	}
	xfree(cand, KEYS_SCAN_MAX * sizeof(*cand));
}

/*
 * Read every .der under trusted/: the ones not revoked become
 * candidates for admission, which needs the whole list first.
 */
static int scan_trusted(const char *keys_dir, const char *revoked_dir,
			struct trusted_set *set,
			struct keys_candidate *cand, size_t *n_cand)
{
	struct dirent **names = NULL;
	char dir[PATH_MAX];
	int n, i, ret = 0;

	if (strsprintf(dir, sizeof(dir), "%s/trusted", keys_dir) < 0)
		return -ENAMETOOLONG;
	n = scandir(dir, &names, select_der, alphasort);
	if (n < 0)
		return errno == ENOENT ? 0 : -errno;
	for (i = 0; i < n && !ret; i++) {
		struct keys_candidate *c = &cand[*n_cand];

		if (*n_cand >= KEYS_SCAN_MAX) {
			ret = -E2BIG;
			break;
		}
		c->dirfd = -1;
		if (strsprintf(c->path, sizeof(c->path), "%s/%s", dir,
			       names[i]->d_name) < 0) {
			ret = -ENAMETOOLONG;
			break;
		}
		ret = keys_read_der(c->path, &c->der, &c->der_sz);
		if (ret)
			break;
		ret = keys_digest_der(c->der, c->der_sz, c->sha256,
				      c->fingerprint);
		if (ret) {
			xfree(c->der, c->der_sz);
			c->der = NULL;
			break;
		}
		if (keys_is_revoked(revoked_dir, c->fingerprint)) {
			xfree(c->der, c->der_sz);
			c->der = NULL;
			continue;
		}
		(*n_cand)++;
	}
	for (i = 0; i < n; i++)
		libc_free(names[i]);
	libc_free(names);
	return ret;
}

/*
 * The same scan from the descriptor of the keys directory, which the
 * trusted directory's descriptor outlives into admit_vouched: the
 * caller closes it after.
 */
static int scan_trusted_at(int keys_fd, const char *display,
			   struct keys_candidate *cand, size_t *n_cand,
			   int *trusted_fd)
{
	struct dirent **names = NULL;
	int n, i, ret = 0;

	*trusted_fd = open_beneath(keys_fd, "trusted", O_RDONLY | O_DIRECTORY);
	if (*trusted_fd == -ENOENT)
		return 0;
	if (*trusted_fd < 0)
		return *trusted_fd;
	n = scandirat(*trusted_fd, ".", &names, select_der, alphasort);
	if (n < 0)
		return -errno;
	for (i = 0; i < n && !ret; i++) {
		struct keys_candidate *c = &cand[*n_cand];

		if (*n_cand >= KEYS_SCAN_MAX) {
			ret = -E2BIG;
			break;
		}
		c->dirfd = *trusted_fd;
		if (strscpy(c->name, names[i]->d_name, sizeof(c->name)) < 0 ||
		    strsprintf(c->path, sizeof(c->path), "%s/trusted/%s",
			       display, names[i]->d_name) < 0) {
			ret = -ENAMETOOLONG;
			break;
		}
		ret = keys_read_der_at(*trusted_fd, c->name, &c->der,
				       &c->der_sz);
		if (ret)
			break;
		ret = keys_digest_der(c->der, c->der_sz, c->sha256,
				      c->fingerprint);
		if (ret) {
			xfree(c->der, c->der_sz);
			c->der = NULL;
			break;
		}
		(*n_cand)++;
	}
	for (i = 0; i < n; i++)
		libc_free(names[i]);
	libc_free(names);
	return ret;
}

static int load_set(const char *primary, const char *keys_dir,
		    const char *revoked_dir, bool with_trusted,
		    struct trusted_set *set)
{
	struct keys_candidate *cand = NULL;
	__u8 sha256[32], fingerprint[32];
	char revoked[PATH_MAX];
	size_t n_cand = 0;
	int ret;

	memset(set, 0, sizeof(*set));
	if (!revoked_dir) {
		if (strsprintf(revoked, sizeof(revoked), "%s/revoked",
			       keys_dir) < 0)
			return -ENAMETOOLONG;
		revoked_dir = revoked;
	}
	ret = keys_take_file(set, primary, sha256, fingerprint);
	if (ret)
		return ret;
	if (!keys_is_revoked(revoked_dir, fingerprint)) {
		ret = set_add(set, primary, sha256, fingerprint, NULL, NULL, 0);
		if (ret)
			return ret;
	}
	set->n_revoked = count_der(revoked_dir);
	if (!with_trusted)
		goto sort;

	cand = xcalloc(KEYS_SCAN_MAX, sizeof(*cand));
	if (!cand)
		return -ENOMEM;
	ret = scan_trusted(keys_dir, revoked_dir, set, cand, &n_cand);
	if (!ret)
		ret = admit_vouched(set, cand, n_cand);
	candidates_free(cand, n_cand);
	if (ret)
		return ret;
sort:
	if (set->n > 1)
		qsort(set->certs, set->n, sizeof(set->certs[0]), cert_cmp);
	return 0;
}

/*
 * A config image's set: the primary and every vouched certificate under
 * keys/trusted, less what keys/revoked names, all read through the
 * image's descriptor. Historical vouches count before revocation, so a
 * revoked certificate's vouch for another still admits it.
 */
static int load_set_at(const char *primary, int keys_fd, const char *display,
		       bool with_trusted, struct trusted_set *set)
{
	struct keys_candidate *cand = NULL;
	__u8 sha256[32], fingerprint[32];
	int revoked_fd, trusted_fd = -1;
	size_t n_cand = 0, i, kept = 0;
	int ret;

	memset(set, 0, sizeof(*set));
	ret = keys_take_file(set, primary, sha256, fingerprint);
	if (ret)
		return ret;
	ret = set_add(set, primary, sha256, fingerprint, NULL, NULL, 0);
	if (ret)
		return ret;
	if (keys_fd == -ENOENT)
		return 0;
	revoked_fd = open_beneath(keys_fd, "revoked", O_RDONLY | O_DIRECTORY);
	set->n_revoked = count_der_at(revoked_fd);
	if (with_trusted) {
		cand = xcalloc(KEYS_SCAN_MAX, sizeof(*cand));
		if (!cand) {
			ret = -ENOMEM;
			goto out;
		}
		ret = scan_trusted_at(keys_fd, display, cand, &n_cand,
				      &trusted_fd);
		if (!ret)
			ret = admit_vouched(set, cand, n_cand);
		candidates_free(cand, n_cand);
		if (ret)
			goto out;
	}
	for (i = 0; i < set->n; i++)
		if (!keys_is_revoked_at(revoked_fd, set->certs[i].fingerprint))
			set->certs[kept++] = set->certs[i];
	set->n = kept;
	if (set->n > 1)
		qsort(set->certs, set->n, sizeof(set->certs[0]), cert_cmp);
out:
	if (trusted_fd >= 0)
		close(trusted_fd);
	if (revoked_fd >= 0)
		close(revoked_fd);
	return ret;
}

int keys_load_image_at(const char *primary, int keys_fd,
		       bool with_trusted,
		       struct trusted_set *set)
{
	return load_set_at(primary, keys_fd, "keys", with_trusted, set);
}

int keys_load_image_root(const char *primary, int root_fd,
			 bool with_trusted,
			 struct trusted_set *set)
{
	int keys_fd, ret;

	keys_fd = open_beneath(root_fd, "keys", O_RDONLY | O_DIRECTORY);
	if (keys_fd < 0 && keys_fd != -ENOENT) {
		pr_err("image trust set: open config image keys/: %s",
		       strerror(-keys_fd));
		return keys_fd;
	}
	ret = keys_load_image_at(primary, keys_fd, with_trusted, set);
	if (keys_fd >= 0)
		close(keys_fd);
	return ret;
}

int keys_load(const char *keys_dir, const char *revoked_dir,
	      bool with_trusted, struct trusted_set *set)
{
	char primary[PATH_MAX];

	if (image_config_root_fd() >= 0 &&
	    (!strcmp(keys_dir, KEYS_DIR) ||
	     !strcmp(keys_dir, RUNTIME_DIR "/keys")))
		return keys_load_image_root(RUNTIME_CERT_PATH,
					    image_config_root_fd(),
					    with_trusted, set);
	if (strsprintf(primary, sizeof(primary), "%s/%s", keys_dir, CERT_FILE) < 0)
		return -ENAMETOOLONG;
	return load_set(primary, keys_dir, revoked_dir, with_trusted, set);
}

static int digest_cmp(const void *a, const void *b)
{
	return memcmp(a, b, 32);
}

int keys_anchor_digest(const __u8 sha256[][32], size_t n,
		       __u8 out[32])
{
	__u8 sorted[KEYS_MAX][32];
	size_t i;
	int ret;

	if (n == 1) {
		memcpy(out, sha256[0], 32);
		return 0;
	}
	memset(out, 0, 32);
	if (n == 0 || n > KEYS_MAX)
		return -EINVAL;
	for (i = 0; i < n; i++)
		memcpy(sorted[i], sha256[i], 32);
	qsort(sorted, n, 32, digest_cmp);
	ret = sha256_buffer(sorted, n * 32, out);
	if (ret)
		memset(out, 0, 32);
	return ret;
}

int keys_set_digest(const struct trusted_set *set,
		    __u8 out[32])
{
	__u8 sha[KEYS_MAX][32];
	size_t i;

	for (i = 0; i < set->n; i++)
		memcpy(sha[i], set->certs[i].sha256, 32);
	return keys_anchor_digest(sha, set->n, out);
}

static int keys_write_file(const char *path, const void *data, size_t len)
{
	return seal_write_file(path, data, len, 0644);
}

int keys_install(const char *keys_dir, const __u8 *der,
		 size_t der_sz, const __u8 *sig,
		 size_t sig_sz, char *out, size_t cap)
{
	__u8 sha256[32], fingerprint[32];
	char vouch[PATH_MAX];
	char dir[PATH_MAX];
	int ret;

	ret = keys_digest_der(der, der_sz, sha256, fingerprint);
	if (ret)
		return ret;
	if (strsprintf(dir, sizeof(dir), "%s/trusted", keys_dir) < 0)
		return -ENAMETOOLONG;
	ret = seal_mkdir_p(dir, 0700);
	if (ret)
		return ret;
	ret = keys_path_for(dir, fingerprint, ".der", out, cap);
	if (!ret)
		ret = keys_path_for(dir, fingerprint, ".vouch", vouch,
				    sizeof(vouch));
	if (ret)
		return ret;
	ret = keys_write_file(vouch, sig, sig_sz);
	if (ret)
		return ret;
	ret = keys_write_file(out, der, der_sz);
	if (ret)
		unlink(vouch);
	return ret;
}
