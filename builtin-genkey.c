// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Generate the shirudo X.509 self-signed signing cert.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <shirudo/misc.h>

#include "builtin.h"
#include "util/help.h"
#include "util/log.h"
#include "util/macros.h"
#include "util/crypto.h"
#include "util/paths.h"
#include "util/seal.h"

#define VALIDITY_DAYS	(10L * 365L)
#define CERT_CN		"shirudo"

/*
 * ML-DSA-87 (FIPS 204, NIST category 5) is the only key type: the
 * kernel verifies it natively (CONFIG_CRYPTO_MLDSA) and the largest
 * parameter set gives a fleet-wide trust anchor that must outlive
 * hardware generations the most margin for about 2 KiB per signature.
 * Neither the smaller sets nor a classical algorithm are offered.
 */
#define GENKEY_ALG	"ML-DSA-87"

static int ensure_keys_dir(const char *keys_dir)
{
	int rc;

	if (!strcmp(keys_dir, "/")) {
		pr_err("keys dir cannot be /");
		return -EINVAL;
	}
	rc = seal_mkdir_p(keys_dir, 0700);
	if (rc)
		pr_err("mkdir %s: %s", keys_dir, strerror(-rc));
	return rc;
}

static int check_user_keys_dir(const char *keys_dir)
{
	char component[NAME_MAX + 1];
	struct stat st;
	const char *p, *end;
	int dirfd, nextfd, rc = 0;

	if (keys_dir[0] != '/')
		return -EINVAL;
	dirfd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dirfd < 0)
		return -errno;
	if (fstat(dirfd, &st) != 0) {
		rc = -errno;
		close(dirfd);
		return rc;
	}
	if (st.st_uid != 0 || (st.st_mode & 0022)) {
		close(dirfd);
		return -EPERM;
	}
	for (p = keys_dir + 1; *p; p = end ? end + 1 : p + strlen(p)) {
		size_t len;
		int final;

		end = strchr(p, '/');
		len = end ? (size_t)(end - p) : strlen(p);
		if (!len)
			continue;
		if (len > NAME_MAX) {
			rc = -ENAMETOOLONG;
			break;
		}
		memcpy(component, p, len);
		component[len] = '\0';
		nextfd = openat(dirfd, component,
				O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
		if (nextfd < 0) {
			rc = -errno;
			break;
		}
		if (fstat(nextfd, &st) != 0) {
			rc = -errno;
			close(nextfd);
			break;
		}
		final = !end || end[1] == '\0';
		if ((st.st_uid != 0 && st.st_uid != geteuid()) ||
		    (final && st.st_uid != geteuid()) ||
		    (st.st_mode & 0022)) {
			rc = -EPERM;
			close(nextfd);
			break;
		}
		close(dirfd);
		dirfd = nextfd;
		if (final)
			break;
	}
	close(dirfd);
	return rc;
}

static EVP_PKEY *gen_keypair(void)
{
	EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, GENKEY_ALG);

	if (!k) {
		openssl_complain("EVP_PKEY_Q_keygen");
		if (OPENSSL_version_major() < 3 ||
		    (OPENSSL_version_major() == 3 &&
		     OPENSSL_version_minor() < 5))
			pr_err("genkey: %s needs OpenSSL 3.5 or newer "
			       "(running %s); upgrade libcrypto",
			       GENKEY_ALG, OpenSSL_version(OPENSSL_VERSION));
	}
	return k;
}

static int set_subject_and_issuer(X509 *c)
{
	X509_NAME *name = X509_get_subject_name(c);

	if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
				       (const __u8 *)CERT_CN,
				       -1, -1, 0) != 1) {
		openssl_complain("X509_NAME_add_entry_by_txt");
		return -1;
	}
	if (X509_set_issuer_name(c, name) != 1) {
		openssl_complain("X509_set_issuer_name");
		return -1;
	}
	return 0;
}

static int add_ext(X509 *c, int nid, const char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	int rc;

	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, c, c, NULL, NULL, 0);

	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex) {
		openssl_complain("X509V3_EXT_conf_nid");
		return -1;
	}
	rc = X509_add_ext(c, ex, -1);
	X509_EXTENSION_free(ex);
	if (rc != 1) {
		openssl_complain("X509_add_ext");
		return -1;
	}
	return 0;
}

static int build_serial(X509 *c)
{
	if (ASN1_INTEGER_set(X509_get_serialNumber(c), 1) != 1) {
		openssl_complain("ASN1_INTEGER_set");
		return -1;
	}
	return 0;
}

static int build_validity(X509 *c)
{
	if (!X509_gmtime_adj(X509_getm_notBefore(c), 0)) {
		openssl_complain("X509_gmtime_adj notBefore");
		return -1;
	}
	if (!X509_gmtime_adj(X509_getm_notAfter(c),
			     VALIDITY_DAYS * 24L * 60L * 60L)) {
		openssl_complain("X509_gmtime_adj notAfter");
		return -1;
	}
	return 0;
}

/* ML-DSA hashes the message internally; OpenSSL requires a NULL digest. */
static int build_cert(X509 *c, EVP_PKEY *pkey)
{
	if (X509_set_version(c, 2) != 1) {	/* X.509 v3 */
		openssl_complain("X509_set_version");
		return -1;
	}
	if (build_serial(c) != 0)
		return -1;
	if (build_validity(c) != 0)
		return -1;
	if (X509_set_pubkey(c, pkey) != 1) {
		openssl_complain("X509_set_pubkey");
		return -1;
	}
	if (set_subject_and_issuer(c) != 0)
		return -1;

	if (add_ext(c, NID_basic_constraints, "critical,CA:FALSE") != 0)
		return -1;
	if (add_ext(c, NID_key_usage, "digitalSignature") != 0)
		return -1;
	if (add_ext(c, NID_subject_key_identifier, "hash") != 0)
		return -1;
	if (add_ext(c, NID_authority_key_identifier, "keyid:always") != 0)
		return -1;

	if (X509_sign(c, pkey, NULL) == 0) {
		openssl_complain("X509_sign");
		return -1;
	}
	return 0;
}

static int write_private_pem(EVP_PKEY *pkey, const char *path)
{
	int fd, rc = -1;
	FILE *fp = NULL;

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		pr_err("open %s: %s", path, strerror(errno));
		return -1;
	}
	if (fchmod(fd, 0600) != 0) {
		pr_err("fchmod %s: %s", path, strerror(errno));
		goto out;
	}
	fp = fdopen(fd, "w");
	if (!fp) {
		pr_err("fdopen %s: %s", path, strerror(errno));
		goto out;
	}
	fd = -1;	/* now owned by fp */
	if (PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
		openssl_complain("PEM_write_PrivateKey");
		goto out;
	}
	if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
		pr_err("flush %s: %s", path, strerror(errno));
		goto out;
	}
	rc = 0;
out:
	if (fp)
		fclose(fp);
	else if (fd >= 0)
		close(fd);
	if (rc != 0)
		unlink(path);
	return rc;
}

static int write_cert_der(X509 *c, const char *path)
{
	int fd, rc = -1;
	BIO *bio = NULL;

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		pr_err("open %s: %s", path, strerror(errno));
		return -1;
	}
	if (fchmod(fd, 0600) != 0) {
		pr_err("fchmod %s: %s", path, strerror(errno));
		goto out;
	}
	bio = BIO_new_fd(fd, BIO_NOCLOSE);
	if (!bio) {
		openssl_complain("BIO_new_fd");
		goto out;
	}
	if (i2d_X509_bio(bio, c) != 1) {
		openssl_complain("i2d_X509_bio");
		goto out;
	}
	if (fsync(fd) != 0) {
		pr_err("fsync %s: %s", path, strerror(errno));
		goto out;
	}
	rc = 0;
out:
	if (bio)
		BIO_free(bio);
	if (fd >= 0)
		close(fd);
	if (rc != 0)
		unlink(path);
	return rc;
}

static const struct shirudo_help_item genkey_options[] = {
	{ "--force, -f",      "overwrite an existing key/cert (refused otherwise)" },
	{ "--keys-dir <dir>", "write signing_key.pem + cert.der under <dir> "
			      "instead of the default" },
};

static const struct shirudo_help_section genkey_help_sections[] = {
	{ "options:", genkey_options,
	  ARRAY_SIZE(genkey_options) },
};

static const struct shirudo_help genkey_help = {
	.usage   = "shirudo genkey [--force] [--keys-dir <dir>]",
	.summary = "Generate a self-signed X.509 cert + ML-DSA-87 (FIPS 204) "
		   "private key\nfor signing .upatch loader bytes. "
		   "Operator-only; needs OpenSSL >= 3.5.",
	.sections   = genkey_help_sections,
	.n_sections = ARRAY_SIZE(genkey_help_sections),
	.footer  = "Default output paths:\n"
		   "  " SHIRUDO_SIGNING_KEY_PATH "\n"
		   "  " SHIRUDO_CERT_PATH "\n"
		   "If unset on the command line, the " SHIRUDO_KEYS_DIR_ENV
		   " environment variable\noverrides the default directory.",
};

static void usage(void)
{
	fprintf(stderr, "usage: %s\n", genkey_help.usage);
}

int cmd_genkey(int argc, const char **argv)
{
	const char *keys_dir_arg = NULL;
	char pkey_path[PATH_MAX];
	char cert_path[PATH_MAX];
	EVP_PKEY *pkey = NULL;
	const char *keys_dir;
	X509 *cert = NULL;
	int force = 0;
	int rc = 1;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--force") == 0 ||
		    strcmp(argv[i], "-f") == 0) {
			force = 1;
		} else if (strcmp(argv[i], "--keys-dir") == 0 &&
			   i + 1 < argc) {
			keys_dir_arg = argv[++i];
		} else if (strncmp(argv[i], "--keys-dir=", 11) == 0) {
			keys_dir_arg = argv[i] + 11;
		} else if (is_help(argv[i])) {
			print_help(&genkey_help);
			return 0;
		} else {
			pr_err("genkey: unknown option '%s'", argv[i]);
			usage();
			return 2;
		}
	}

	keys_dir = keys_dir_resolve(keys_dir_arg);

	rc = key_paths(keys_dir, pkey_path, sizeof(pkey_path),
		       cert_path, sizeof(cert_path));
	if (rc) {
		pr_err("genkey: invalid keys dir %s: %s",
		       keys_dir, strerror(-rc));
		return 1;
	}

	if (ensure_keys_dir(keys_dir) != 0)
		return 1;
	if (geteuid() != 0 && strcmp(keys_dir, SHIRUDO_KEYS_DIR) == 0) {
		rc = check_user_keys_dir(keys_dir);
		if (rc) {
			pr_err("genkey: default keys dir %s is not safe for user key "
			       "generation: %s", SHIRUDO_KEYS_DIR,
			       strerror(-rc));
			pr_err("it must be owned by the current user and not writable "
			       "by group or others");
			pr_err("rerun with sudo or pass --keys-dir <dir>");
			return 1;
		}
	}
	rc = 1;

	if (!force && (path_exists(pkey_path) ||
		       path_exists(cert_path))) {
		pr_err("genkey: %s or %s already exists; pass --force",
		       pkey_path, cert_path);
		return 1;
	}

	pkey = gen_keypair();
	if (!pkey)
		goto out;
	cert = X509_new();
	if (!cert) {
		openssl_complain("X509_new");
		goto out;
	}
	if (build_cert(cert, pkey) != 0)
		goto out;

	if (force) {
		/* Make way for the O_EXCL writes only once a new pair exists. */
		unlink(pkey_path);
		unlink(cert_path);
	}

	if (write_private_pem(pkey, pkey_path) != 0)
		goto out;
	if (write_cert_der(cert, cert_path) != 0) {
		unlink(pkey_path);
		goto out;
	}

	pr_info("wrote %s (%s, mode 0600)", pkey_path, GENKEY_ALG);
	pr_info("wrote %s (X.509 self-signed, %ld-day validity)",
		cert_path, VALIDITY_DAYS);
	pr_audit("genkey: created shirudo %s signing material at %s",
		 GENKEY_ALG, keys_dir);
	rc = 0;
out:
	if (cert)
		X509_free(cert);
	if (pkey)
		EVP_PKEY_free(pkey);
	return rc;
}
