// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Inspect the cert / keyring material this host holds.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "builtin.h"
#include "util/chain.h"
#include "util/crypto.h"
#include "util/eventlog.h"
#include "util/help.h"
#include "util/hex.h"
#include "util/identity.h"
#include "util/io.h"
#include "util/json.h"
#include "util/keyring.h"
#include "util/keys.h"
#include "util/log.h"
#include "util/macros.h"
#include "util/malloc.h"
#include "util/paths.h"
#include "util/seal.h"
#include "util/upatch.h"

static X509 *read_cert_der(const char *path)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	BIO *bio;
	X509 *c;

	if (fd < 0) {
		pr_err("open %s: %s", path, strerror(errno));
		return NULL;
	}
	if (check_trusted(fd, path, false)) {
		close(fd);
		return NULL;
	}
	bio = BIO_new_fd(fd, BIO_CLOSE);
	if (!bio) {
		close(fd);
		openssl_complain("BIO_new_fd");
		return NULL;
	}
	c = d2i_X509_bio(bio, NULL);
	BIO_free(bio);
	if (!c)
		openssl_complain("d2i_X509_bio");
	return c;
}

static EVP_PKEY *read_priv_pem(const char *path)
{
	EVP_PKEY *k;
	FILE *fp;

	fp = fopen(path, "r");
	if (!fp) {
		pr_err("open %s: %s", path, strerror(errno));
		return NULL;
	}
	k = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	if (!k)
		openssl_complain("PEM_read_PrivateKey");
	return k;
}

static void name_to_str(X509_NAME *name, char *out, size_t out_sz)
{
	if (!X509_NAME_oneline(name, out, (int)out_sz)) {
		snprintf(out, out_sz, "(parse error)");
		return;
	}
}

static void asn1_time_to_iso(const ASN1_TIME *t, char *out, size_t out_sz)
{
	struct tm tm;

	if (!ASN1_TIME_to_tm(t, &tm)) {
		snprintf(out, out_sz, "(unparseable)");
		return;
	}
	if (!strftime(out, out_sz, "%Y-%m-%dT%H:%M:%SZ", &tm))
		snprintf(out, out_sz, "(format error)");
}

static long days_remaining(const ASN1_TIME *not_after)
{
	int days, secs;

	if (!ASN1_TIME_diff(&days, &secs, NULL, not_after))
		return -1;
	return days;
}

static void format_expires_in(long days, char *out, size_t out_sz)
{
	if (days < 0) {
		snprintf(out, out_sz, "EXPIRED %ld days ago", -days);
		return;
	}
	if (days >= 365)
		snprintf(out, out_sz, "%ldy %ldd", days / 365, days % 365);
	else
		snprintf(out, out_sz, "%ldd", days);
}

static int compute_cert_fpr(X509 *c, __u8 fpr[SHA256_DIGEST_LENGTH])
{
	__u32 n = SHA256_DIGEST_LENGTH;

	if (X509_digest(c, EVP_sha256(), fpr, &n) != 1) {
		openssl_complain("X509_digest");
		return -1;
	}
	return 0;
}

/* SHA-256 over the SPKI; comparable across a cert and its key. */
static int compute_spki_fpr(EVP_PKEY *pkey,
			    __u8 fpr[SHA256_DIGEST_LENGTH])
{
	__u32 n = SHA256_DIGEST_LENGTH;
	__u8 *der = NULL;
	int der_len;
	int rc = -1;

	der_len = i2d_PUBKEY(pkey, &der);
	if (der_len <= 0) {
		openssl_complain("i2d_PUBKEY");
		return -1;
	}
	if (EVP_Digest(der, (size_t)der_len, fpr, &n,
		       EVP_sha256(), NULL) != 1) {
		openssl_complain("EVP_Digest");
		goto out;
	}
	rc = 0;
out:
	OPENSSL_free(der);
	return rc;
}

static void print_fpr(const char *label, const __u8 *fpr)
{
	printf("  %-22s SHA256:", label);
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", fpr[i]);
	printf("\n");
}

/*
 * "RSA-2048" / "EC-256" for the classical families, otherwise the
 * provider's own name ("ML-DSA-87"), whose parameter set already says
 * everything a bit count would.
 */
static void format_pkey_algorithm(EVP_PKEY *pkey, char *out, size_t out_sz)
{
	const char *name = EVP_PKEY_get0_type_name(pkey);
	int id = EVP_PKEY_get_base_id(pkey);

	if (!name)
		name = "unknown";
	if (id == EVP_PKEY_RSA || id == EVP_PKEY_EC)
		snprintf(out, out_sz, "%s-%d", name, EVP_PKEY_get_bits(pkey));
	else
		strscpy(out, name, out_sz);
}

static int dump_operator_cert(X509 *cert, const char *cert_path,
			      const __u8 cert_spki_fpr[SHA256_DIGEST_LENGTH])
{
	X509_NAME *subj = X509_get_subject_name(cert);
	X509_NAME *iss  = X509_get_issuer_name(cert);
	const ASN1_TIME *nb = X509_get0_notBefore(cert);
	const ASN1_TIME *na = X509_get0_notAfter(cert);
	EVP_PKEY *pub = X509_get0_pubkey(cert);
	char subj_s[256], iss_s[256], nb_s[32], na_s[32], exp_s[48];
	__u8 fpr[SHA256_DIGEST_LENGTH];
	char alg_s[64];
	int self_signed;
	long left;

	name_to_str(subj, subj_s, sizeof(subj_s));
	name_to_str(iss, iss_s, sizeof(iss_s));
	asn1_time_to_iso(nb, nb_s, sizeof(nb_s));
	asn1_time_to_iso(na, na_s, sizeof(na_s));
	left = days_remaining(na);
	format_expires_in(left, exp_s, sizeof(exp_s));
	self_signed = (X509_NAME_cmp(subj, iss) == 0);

	printf("Cert (%s):\n", cert_path);
	printf("  %-22s %s\n", "Subject:", subj_s);
	printf("  %-22s %s%s\n", "Issuer:", iss_s,
	       self_signed ? "  (self-signed)" : "");
	if (pub) {
		format_pkey_algorithm(pub, alg_s, sizeof(alg_s));
		printf("  %-22s %s\n", "Public-key:", alg_s);
	}
	if (compute_cert_fpr(cert, fpr) == 0)
		print_fpr("Fingerprint:", fpr);
	print_fpr("SPKI fingerprint:", cert_spki_fpr);
	printf("  %-22s %s\n", "Valid from:", nb_s);
	printf("  %-22s %s\n", "Valid until:", na_s);
	printf("  %-22s %s\n", "Expires in:", exp_s);
	return 0;
}

static int dump_signing_key(const char *pkey_path,
			    const __u8 cert_spki_fpr[SHA256_DIGEST_LENGTH])
{
	__u8 fpr_priv[SHA256_DIGEST_LENGTH];
	char alg_s[64];
	EVP_PKEY *priv;
	int rc = 0;

	if (!path_exists(pkey_path)) {
		printf("Signing key (%s):\n", pkey_path);
		printf("  %-22s %s\n", "Present:",
		       "no  (target host -- private key lives on the operator)");
		return 0;
	}

	priv = read_priv_pem(pkey_path);
	if (!priv)
		return -1;

	printf("Signing key (%s):\n", pkey_path);
	printf("  %-22s %s\n", "Present:", "yes");
	format_pkey_algorithm(priv, alg_s, sizeof(alg_s));
	printf("  %-22s %s\n", "Algorithm:", alg_s);

	if (compute_spki_fpr(priv, fpr_priv) != 0) {
		rc = -1;
		goto out;
	}
	print_fpr("SPKI fingerprint:", fpr_priv);

	if (memcmp(fpr_priv, cert_spki_fpr, SHA256_DIGEST_LENGTH) == 0) {
		printf("  %-22s %s\n", "Cert match:",
		       "OK  (signing key matches cert)");
	} else {
		printf("  %-22s %s\n", "Cert match:",
		       "MISMATCH  (private key does NOT match cert)");
		pr_warn("keys: private key and cert have different public keys");
		rc = -1;
	}
out:
	EVP_PKEY_free(priv);
	return rc;
}

static int keys_dump_disk_material(const char *cert_path,
				   const char *pkey_path)
{
	X509 *cert;
	EVP_PKEY *pub;
	__u8 cert_spki_fpr[SHA256_DIGEST_LENGTH];
	int rc;

	cert = read_cert_der(cert_path);
	if (!cert)
		return 1;

	pub = X509_get0_pubkey(cert);
	if (!pub) {
		X509_free(cert);
		return 1;
	}
	if (compute_spki_fpr(pub, cert_spki_fpr) != 0) {
		X509_free(cert);
		return 1;
	}

	rc = dump_operator_cert(cert, cert_path, cert_spki_fpr);
	if (rc == 0) {
		printf("\n");
		rc = dump_signing_key(pkey_path, cert_spki_fpr);
	}
	X509_free(cert);
	return rc ? 1 : 0;
}

struct list_row {
	key_serial_t	serial;
	char		*type;
	char		*description;
};

#define LIST_ROW_CAP	256

struct list_ctx {
	struct list_row	rows[LIST_ROW_CAP];
	int		count;
};

static void collect_key(key_serial_t serial, const char *type,
			const char *description, void *ud)
{
	struct list_ctx *c = ud;

	if (c->count >= LIST_ROW_CAP)
		return;
	c->rows[c->count].serial = serial;
	c->rows[c->count].type = xstrdup(type);
	c->rows[c->count].description = xstrdup(description);
	c->count++;
}

static int keys_list_keyring(key_serial_t ring, const char *label,
			     const struct shirudo_identity *id, int id_rc)
{
	struct list_ctx c = {};
	int rc, i;

	printf("Keyring (%s):\n", label);
	printf("  %-22s %d\n", "Serial:", (int)ring);

	if (id_rc == 0) {
		const char *match = id->keyring_serial == ring ?
				    "matches" : "MISMATCH";

		printf("  %-22s %d  (%s)\n", "Frozen serial:",
		       (int)id->keyring_serial, match);
		if (id->keyring_serial != ring)
			pr_warn("keyring serial %d != frozen %d (swap?)",
				(int)ring, (int)id->keyring_serial);
	} else if (id_rc == -ENOENT) {
		printf("  %-22s %s\n", "Frozen serial:",
		       "(none this boot)");
	} else {
		printf("  %-22s unreadable: %s\n", "Frozen serial:",
		       strerror(-id_rc));
	}

	rc = keyring_list(ring, collect_key, &c);
	if (rc) {
		pr_err("keyring list: %s", strerror(-rc));
		goto out;
	}
	printf("  Members (%d):\n", c.count);
	if (c.count == 0)
		printf("    (empty)\n");
	for (i = 0; i < c.count; i++)
		printf("    serial=%-10d  type=%-10s  %s\n",
		       (int)c.rows[i].serial,
		       c.rows[i].type ? c.rows[i].type : "?",
		       c.rows[i].description ? c.rows[i].description : "?");
out:
	for (i = 0; i < c.count; i++) {
		xstrfree(c.rows[i].type);
		xstrfree(c.rows[i].description);
	}
	return rc ? 1 : 0;
}

static void keyring_absent(const char *label, key_serial_t rc,
			   const struct shirudo_identity *id, int id_rc)
{
	printf("Keyring (%s):\n", label);
	if (rc != (key_serial_t)-ENOKEY)
		printf("  %-22s lookup error: %s\n", "Present:",
		       strerror(-rc));
	else if (id_rc == 0)
		printf("  %-22s no  (gone: init froze serial %d this boot)\n",
		       "Present:", (int)id->keyring_serial);
	else if (id_rc == -ENOENT)
		printf("  %-22s %s\n", "Present:",
		       "no  (operator host, or `shirudo init` not yet run)");
	else
		printf("  %-22s unknown  (frozen identity unreadable: %s)\n",
		       "Present:", strerror(-id_rc));
}

static const struct shirudo_help_item keys_subcmds[] = {
	{ "add", "trust a certificate an enrolled key vouched for (target)" },
	{ "revoke", "stop trusting a certificate now and for good (target)" },
	{ "vouch", "sign a vouch for a certificate (operator)" },
};

static const struct shirudo_help_item keys_options[] = {
	{ "--keys-dir <dir>", "read signing_key.pem + cert.der from <dir>" },
};

static const struct shirudo_help_section keys_help_sections[] = {
	{ "subcommands:", keys_subcmds, ARRAY_SIZE(keys_subcmds) },
	{ "options:", keys_options,
	  ARRAY_SIZE(keys_options) },
};

static const struct shirudo_help keys_help = {
	.usage   = "shirudo keys [--keys-dir <dir>]\n"
		   "       shirudo keys add <cert.der> --vouch <file>\n"
		   "       shirudo keys revoke <fingerprint> [--promote <fp>]\n"
		   "       shirudo keys vouch <cert.der> [-o <file>]",
	.summary = "Inspect the shirudo key material this host holds: the "
		   "on-disk cert and\nsigning key (if present), the trusted "
		   "set a target enrols, and the kernel\nkeyring holding it "
		   "(if init'd). Local-only on either side.",
	.sections   = keys_help_sections,
	.n_sections = ARRAY_SIZE(keys_help_sections),
	.footer  = "Default paths:\n"
		   "  " SHIRUDO_CERT_PATH "\n"
		   "  " SHIRUDO_SIGNING_KEY_PATH "\n\n"
		   "Or set the " SHIRUDO_KEYS_DIR_ENV
		   " environment variable.",
};

static void usage(void)
{
	fprintf(stderr, "usage: %s\n", keys_help.usage);
}

static const struct shirudo_help_item keys_add_options[] = {
	{ "--vouch <file>", "the vouch an enrolled key signed for the certificate" },
	{ "--keys-dir <dir>", "the keys directory (default " SHIRUDO_KEYS_DIR ")" },
};

static const struct shirudo_help_section keys_add_sections[] = {
	{ "options:", keys_add_options, ARRAY_SIZE(keys_add_options) },
};

static const struct shirudo_help keys_add_help = {
	.usage   = "shirudo keys add <cert.der> --vouch <file> [--keys-dir <dir>]",
	.summary = "Add a certificate to the trusted set this target enrols at "
		   "its next boot.\nThe vouch must verify under a certificate "
		   "already in the set; regenerate\nthe initrd afterwards "
		   "(shirudo-gen-initrd). Prints the fingerprint.",
	.sections   = keys_add_sections,
	.n_sections = ARRAY_SIZE(keys_add_sections),
};

static const struct shirudo_help_item keys_vouch_options[] = {
	{ "-o <file>", "where to write the vouch (default <cert.der>.vouch)" },
	{ "--keys-dir <dir>", "read signing_key.pem + cert.der from <dir>" },
	{ "--key <pem>", "the signing key (overrides --keys-dir)" },
	{ "--cert <der>", "the signing certificate (overrides --keys-dir)" },
};

static const struct shirudo_help_section keys_vouch_sections[] = {
	{ "options:", keys_vouch_options, ARRAY_SIZE(keys_vouch_options) },
};

static const struct shirudo_help keys_vouch_help = {
	.usage   = "shirudo keys vouch <cert.der> [-o <file>] [--keys-dir <dir>]",
	.summary = "Sign a vouch for another operator's certificate with this "
		   "operator's key,\nfor `shirudo keys add --vouch` on the "
		   "targets that enrol this key.\nPrints the vouched "
		   "certificate's fingerprint.",
	.sections   = keys_vouch_sections,
	.n_sections = ARRAY_SIZE(keys_vouch_sections),
};

/* The public key must be one the kernel verifies loaders with. */
static int check_cert_algorithm(const __u8 *der, size_t der_sz,
				const char *what)
{
	struct shirudo_cert cert = {};
	char name[64] = {};
	int rc;

	rc = cert_read_der(der, der_sz, &cert);
	if (rc) {
		pr_err("keys add: %s is not a certificate", what);
		return rc;
	}
	rc = cert_key_algorithm(&cert, name, sizeof(name));
	cert_free(&cert);
	if (rc || strcmp(name, "ML-DSA-87")) {
		pr_err("keys add: %s is %s; shirudo accepts only ML-DSA-87",
		       what, rc ? "of an unknown algorithm" : name);
		return -EKEYREJECTED;
	}
	return 0;
}

/*
 * The vouching certificate must be one the kernel verifies against
 * right now, not only one on disk, when the live target's set is the
 * one being extended.
 */
static int check_voucher_live(const struct shirudo_trusted_set *set,
			      const __u8 voucher[32])
{
	struct shirudo_identity id;
	key_serial_t ring;
	size_t der_sz = 0;
	__u8 *der = NULL;
	int rc = 0;
	size_t i;

	if (identity_read(&id) ||
	    id.keyring_type != SHIRUDO_SIG_KEYRING_BPF)
		return 0;
	ring = keyring_bpf_serial();
	if (ring <= 0)
		return 0;
	for (i = 0; i < set->n; i++) {
		if (memcmp(set->certs[i].fingerprint, voucher, 32) == 0)
			break;
	}
	if (i == set->n)
		return -ENOKEY;
	rc = keys_read_der(set->certs[i].path, &der, &der_sz);
	if (rc)
		return rc;
	rc = keyring_holds_cert(ring, der, der_sz);
	xfree(der, der_sz);
	if (rc < 0)
		return rc;
	return rc ? 0 : -ENOKEY;
}

static int keys_add(int argc, const char **argv)
{
	const char *keys_dir_arg = NULL, *vouch_path = NULL, *cert = NULL;
	__u8 *der = NULL, *sig = NULL;
	__u8 sha256[32], fp[32], by[32];
	struct shirudo_trusted_set set;
	char fp_hex[65], by_hex[65];
	size_t der_sz = 0, sig_sz = 0;
	char revoked[PATH_MAX];
	const char *keys_dir;
	char out[PATH_MAX];
	int rc = 1;
	size_t i;

	for (int a = 1; a < argc; a++) {
		if (!strcmp(argv[a], "--vouch") && a + 1 < argc) {
			vouch_path = argv[++a];
		} else if (!strncmp(argv[a], "--vouch=", 8)) {
			vouch_path = argv[a] + 8;
		} else if (!strcmp(argv[a], "--keys-dir") && a + 1 < argc) {
			keys_dir_arg = argv[++a];
		} else if (!strncmp(argv[a], "--keys-dir=", 11)) {
			keys_dir_arg = argv[a] + 11;
		} else if (is_help(argv[a])) {
			print_help(&keys_add_help);
			return 0;
		} else if (argv[a][0] == '-') {
			pr_err("keys add: unknown option '%s'", argv[a]);
			return 2;
		} else if (!cert) {
			cert = argv[a];
		} else {
			pr_err("keys add: unexpected argument '%s'", argv[a]);
			return 2;
		}
	}
	if (!cert || !vouch_path) {
		print_help(&keys_add_help);
		return 2;
	}
	keys_dir = keys_dir_resolve(keys_dir_arg);
	if (strsprintf(revoked, sizeof(revoked), "%s/revoked", keys_dir) < 0) {
		pr_err("keys add: keys directory path too long");
		return 2;
	}

	rc = keys_read_der(cert, &der, &der_sz);
	if (rc) {
		pr_err("keys add: read %s: %s", cert, strerror(-rc));
		return 1;
	}
	rc = keys_digest_der(der, der_sz, sha256, fp);
	if (rc) {
		pr_err("keys add: %s is not a certificate", cert);
		goto out;
	}
	rc = check_cert_algorithm(der, der_sz, cert);
	if (rc)
		goto out;
	hex_encode(fp, 32, fp_hex);

	rc = keys_load(keys_dir, NULL, true, &set);
	if (rc) {
		pr_err("keys add: no trusted set under %s: %s (install the "
		       "primary certificate first)", keys_dir, strerror(-rc));
		goto out;
	}
	if (keys_is_revoked(revoked, fp)) {
		pr_err("keys add: %s was revoked on this target", fp_hex);
		rc = -EKEYREVOKED;
		goto out;
	}
	rc = keys_read_der(vouch_path, &sig, &sig_sz);
	if (rc) {
		pr_err("keys add: read %s: %s", vouch_path, strerror(-rc));
		goto out;
	}
	rc = keys_verify_vouch(&set, der, der_sz, sig, sig_sz, by);
	if (rc) {
		pr_err("keys add: %s does not vouch for %s under any of the "
		       "%zu trusted certificate%s", vouch_path, fp_hex, set.n,
		       set.n == 1 ? "" : "s");
		goto out;
	}
	hex_encode(by, 32, by_hex);
	if (!strcmp(keys_dir, SHIRUDO_KEYS_DIR)) {
		rc = check_voucher_live(&set, by);
		if (rc) {
			pr_err("keys add: the vouching certificate %s is not "
			       "in the bpf keyring this boot%s%s", by_hex,
			       rc == -ENOKEY ? "" : ": ",
			       rc == -ENOKEY ? "" : strerror(-rc));
			goto out;
		}
	}
	for (i = 0; i < set.n; i++) {
		if (memcmp(set.certs[i].fingerprint, fp, 32))
			continue;
		pr_info("keys add: %s is already trusted", fp_hex);
		printf("%s\n", fp_hex);
		rc = 0;
		goto out;
	}
	/* A set past the limit would fail to load at all, init included. */
	if (set.n >= SHIRUDO_KEYS_MAX) {
		pr_err("keys add: the trusted set holds %d certificates, the "
		       "most a target enrols", SHIRUDO_KEYS_MAX);
		rc = -E2BIG;
		goto out;
	}
	rc = keys_install(keys_dir, der, der_sz, sig, sig_sz, out,
			  sizeof(out));
	if (rc) {
		pr_err("keys add: install under %s/trusted: %s", keys_dir,
		       strerror(-rc));
		goto out;
	}
	pr_audit("keys add: fingerprint=%s vouched_by=%s path=%s", fp_hex,
		 by_hex, out);
	pr_info("keys add: %s joins the set at the next boot; regenerate "
		"the initrd (shirudo-gen-initrd)", fp_hex);
	printf("%s\n", fp_hex);
out:
	if (sig)
		xfree(sig, sig_sz);
	xfree(der, der_sz);
	return rc ? 1 : 0;
}

static const struct shirudo_help_item keys_revoke_options[] = {
	{ "--promote <fingerprint>",
	  "the member that becomes the primary when the primary goes" },
	{ "--force",
	  "revoke the last certificate; nothing verifies until a reboot with a new one" },
};

static const struct shirudo_help_section keys_revoke_sections[] = {
	{ "options:", keys_revoke_options, ARRAY_SIZE(keys_revoke_options) },
};

static const struct shirudo_help keys_revoke_help = {
	.usage   = "shirudo keys revoke <fingerprint> [--promote <fingerprint>] [--force]",
	.summary = "Stop trusting a certificate: unlink its key from the bpf "
		   "keyring so the kernel\naccepts nothing it signed from now "
		   "on, unload and purge every archived upatch\nit signed, "
		   "and keep it out of the set for good. Measured into the "
		   "register.",
	.sections   = keys_revoke_sections,
	.n_sections = ARRAY_SIZE(keys_revoke_sections),
};

static int append_key_event(const char *type, const char *fp_hex,
			    const char *sha_hex, const __u8 event[32])
{
	char buf[1024];
	struct shirudo_json_emit e = { .buf = buf, .cap = sizeof(buf) };
	char ts[32], boot_id[64], nv_index[16], digest_hex[65];

	eventlog_timestamp(ts, sizeof(ts));
	eventlog_boot_id(boot_id, sizeof(boot_id));
	snprintf(nv_index, sizeof(nv_index), "0x%08X", SHIRUDO_NV_INDEX);
	hex_encode(event, 32, digest_hex);

	json_obj_open(&e);
	json_kv_int(&e, "schema", 2);
	json_kv_string(&e, "ts", ts);
	json_kv_string(&e, "nv_index", nv_index);
	json_kv_string(&e, "alg", "sha256");
	json_kv_string(&e, "digest", digest_hex);
	json_kv_string(&e, "type", type);
	json_kv_string(&e, "boot_id", boot_id);
	json_obj_open_key(&e, "key");
	json_kv_string(&e, "fingerprint", fp_hex);
	json_kv_string(&e, "cert_sha256", sha_hex);
	json_obj_close(&e);
	json_obj_close(&e);
	if (e.err) {
		pr_err("eventlog: %s entry encode failed: %s", type,
		       strerror(-e.err));
		return e.err;
	}
	return eventlog_append(buf);
}

/*
 * The register learns of the revocation before anything else changes
 * in the archive, so evidence taken at any point names it. The same
 * fail-closed treatment as a upatch event: no TPM is an error, not an
 * unmeasured success.
 */
static int measure_revoke(const struct shirudo_trusted_cert *c,
			  const char *fp_hex)
{
	__u8 event[32], chain[32];
	char sha_hex[65], chain_hex[65];
	int rc;

	chain_key_event("shirudo-key-revoke", c->sha256, event);
	rc = eventlog_lock(true);
	if (rc)
		return rc;
	rc = chain_extend(event, chain);
	if (rc) {
		pr_err("keys revoke: register %s (category: %s); the key is "
		       "revoked but the revocation is NOT measured; operator "
		       "must reconcile",
		       rc == -ENODEV ? "unavailable" :
		       rc == -EACCES ? "is not the one init bound" :
		       "extend failed",
		       rc == -EACCES ? "tampered" : "tpm_error");
		goto out;
	}
	hex_encode(c->sha256, 32, sha_hex);
	rc = append_key_event("key_revoke", fp_hex, sha_hex, event);
	if (rc) {
		pr_err("keys revoke: eventlog append failed after extend -- "
		       "chain/log desync; operator must reconcile");
		goto out;
	}
	hex_encode(chain, 32, chain_hex);
	pr_audit("key revoke measured: fingerprint=%s chain=%s", fp_hex,
		 chain_hex);
out:
	eventlog_unlock();
	return rc;
}

/*
 * Every archived upatch the revoked certificate signed goes: the kernel
 * would refuse to restore it at the next boot, and keeping it loaded
 * would keep running what a key nobody trusts any more authorised. The
 * rest are still tried when one fails.
 */
static int purge_signed_by(const __u8 *der, size_t der_sz,
			   size_t *unloaded)
{
	struct shirudo_cert cert = {};
	struct dirent **names = NULL;
	int n, i, rc = 0, purged = 0;

	*unloaded = 0;
	if (cert_read_der(der, der_sz, &cert))
		return -EINVAL;
	n = scandir(SHIRUDO_UPATCHES_DIR, &names, upatch_select,
		    alphasort);
	if (n < 0) {
		cert_free(&cert);
		return errno == ENOENT ? 0 : -errno;
	}
	for (i = 0; i < n; i++) {
		char name[SHIRUDO_UPATCH_NAME_MAX + 1];
		struct shirudo_upatch u;
		char path[PATH_MAX];
		int signed_by, prc;

		if (strsprintf(path, sizeof(path), "%s/%s", SHIRUDO_UPATCHES_DIR,
			       names[i]->d_name) < 0)
			continue;
		if (upatch_open(path, &u))
			continue;
		signed_by = cms_signed_by(upatch_signature(&u),
					  u.hdr.signature_len, &cert);
		memcpy(name, u.hdr.name, SHIRUDO_UPATCH_NAME_MAX);
		name[SHIRUDO_UPATCH_NAME_MAX] = '\0';
		upatch_close(&u);
		if (signed_by != 1)
			continue;
		prc = shirudo_upatch_purge(name, "key_revoke");
		if (prc < 0) {
			pr_err("keys revoke: purge %s: %s", name,
			       strerror(-prc));
			rc = prc;
			continue;
		}
		pr_info("keys revoke: %s %s", name, prc ? "unloaded and purged" :
			"purged from the archive");
		purged++;
		*unloaded += prc;
	}
	for (i = 0; i < n; i++)
		libc_free(names[i]);
	libc_free(names);
	cert_free(&cert);
	return rc ? rc : purged;
}

static int promote(const struct shirudo_trusted_cert *c)
{
	char vouch[PATH_MAX];
	size_t der_sz = 0;
	__u8 *der = NULL;
	int rc;

	rc = keys_read_der(c->path, &der, &der_sz);
	if (rc)
		return rc;
	rc = keys_write_file(SHIRUDO_CERT_PATH, der, der_sz);
	xfree(der, der_sz);
	if (rc)
		return rc;
	if (strsprintf(vouch, sizeof(vouch), "%.*s.vouch",
		       (int)(strlen(c->path) - 4), c->path) >= 0)
		unlink(vouch);
	unlink(c->path);
	return 0;
}

static const struct shirudo_trusted_cert *
set_find(const struct shirudo_trusted_set *set, const __u8 fp[32])
{
	size_t i;

	for (i = 0; i < set->n; i++) {
		if (memcmp(set->certs[i].fingerprint, fp, 32) == 0)
			return &set->certs[i];
	}
	return NULL;
}

struct revoke_seen {
	const char	*fp_hex;
	bool		found;
};

static int revoke_logged(const char *line, size_t len, void *ctx)
{
	struct revoke_seen *r = ctx;
	char type[32] = {}, fp[65] = {};
	struct shirudo_json_field key[] = {
		{ "fingerprint", SHIRUDO_JSON_T_STRING, fp, sizeof(fp), 0,
		  NULL, 0 },
	};
	struct shirudo_json_field f[] = {
		{ "type", SHIRUDO_JSON_T_STRING, type, sizeof(type), 0, NULL,
		  0 },
		{ "key", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, key,
		  ARRAY_SIZE(key) },
	};

	if (!json_parse(line, len, f, ARRAY_SIZE(f)) &&
	    !strcmp(type, "key_revoke") && !strcmp(fp, r->fp_hex))
		r->found = true;
	return 0;
}

/*
 * A revocation left unmeasured: its marker is from this boot and this
 * boot's log does not hold it. One from an earlier boot never had its
 * key enrolled in this one, so there is nothing to measure.
 */
static bool revoke_unmeasured(const char *marker, const char *fp_hex)
{
	struct revoke_seen r = { .fp_hex = fp_hex };
	struct timespec up;
	struct stat st;

	if (stat(marker, &st) || clock_gettime(CLOCK_BOOTTIME, &up))
		return true;
	if (st.st_mtime < time(NULL) - up.tv_sec)
		return false;
	return eventlog_boot_lines(revoke_logged, &r) || !r.found;
}

/* The certificate a revoked marker holds, as a member it once was. */
static int revoked_cert(const __u8 fp[32], const char *marker,
			struct shirudo_trusted_cert *c, __u8 **der,
			size_t *der_sz)
{
	char trusted[PATH_MAX];
	int rc;

	rc = keys_read_der(marker, der, der_sz);
	if (rc)
		return rc;
	memset(c, 0, sizeof(*c));
	rc = keys_digest_der(*der, *der_sz, c->sha256, c->fingerprint);
	if (!rc && memcmp(c->fingerprint, fp, 32))
		rc = -EKEYREJECTED;
	if (!rc)
		rc = keys_path_for(SHIRUDO_KEYS_DIR "/trusted", fp,
				   ".der", trusted, sizeof(trusted));
	if (rc) {
		xfree(*der, *der_sz);
		*der = NULL;
		return rc;
	}
	strscpy(c->path, trusted, sizeof(c->path));
	return 0;
}

static int keys_revoke(int argc, const char **argv)
{
	const struct shirudo_trusted_cert *victim, *heir = NULL;
	const char *fp_arg = NULL, *promote_arg = NULL;
	struct shirudo_trusted_cert gone;
	__u8 fp[32], promote_fp[32];
	struct shirudo_trusted_set set;
	__u8 *der = NULL;
	struct shirudo_identity id;
	char revoked[PATH_MAX];
	key_serial_t ring, key;
	size_t der_sz = 0, n_unloaded = 0;
	bool force = false, resume = false;
	char fp_hex[65];
	int rc, purged;

	for (int a = 1; a < argc; a++) {
		if (!strcmp(argv[a], "--force")) {
			force = true;
		} else if (!strcmp(argv[a], "--promote") && a + 1 < argc) {
			promote_arg = argv[++a];
		} else if (!strncmp(argv[a], "--promote=", 10)) {
			promote_arg = argv[a] + 10;
		} else if (is_help(argv[a])) {
			print_help(&keys_revoke_help);
			return 0;
		} else if (argv[a][0] == '-') {
			pr_err("keys revoke: unknown option '%s'", argv[a]);
			return 2;
		} else if (!fp_arg) {
			fp_arg = argv[a];
		} else {
			pr_err("keys revoke: unexpected argument '%s'",
			       argv[a]);
			return 2;
		}
	}
	if (!fp_arg) {
		print_help(&keys_revoke_help);
		return 2;
	}
	if (strlen(fp_arg) != 64 || hex_decode(fp_arg, fp, 32)) {
		pr_err("keys revoke: a fingerprint is 64 hex digits (see "
		       "`shirudo keys`)");
		return 2;
	}
	if (promote_arg && (strlen(promote_arg) != 64 ||
			    hex_decode(promote_arg, promote_fp, 32))) {
		pr_err("keys revoke: --promote takes a fingerprint");
		return 2;
	}
	hex_encode(fp, 32, fp_hex);

	/*
	 * Only the bpf keyring can lose one key and keep the others; the
	 * staging keyring holds the primary alone and the rotation guide
	 * is the way out of it.
	 */
	if (identity_read(&id) ||
	    id.keyring_type != SHIRUDO_SIG_KEYRING_BPF) {
		pr_err("keys revoke: the certificates are not enrolled in the "
		       "bpf keyring this boot; rotate the key instead");
		return 1;
	}
	ring = keyring_bpf_serial();
	if (ring <= 0) {
		pr_err("keys revoke: no bpf keyring: %s", strerror(-ring));
		return 1;
	}
	rc = keys_load(SHIRUDO_KEYS_DIR, NULL, true, &set);
	if (rc) {
		pr_err("keys revoke: read the trusted set: %s", strerror(-rc));
		return 1;
	}
	victim = set_find(&set, fp);
	if (!victim && !keys_is_revoked(SHIRUDO_KEYS_REVOKED_DIR, fp)) {
		pr_err("keys revoke: %s is not a trusted certificate", fp_hex);
		return 1;
	}
	if (!victim) {
		/*
		 * Revoked before: a run that failed after the marker left
		 * the unlink, the measurement or the purge to this one.
		 */
		rc = keys_path_for(SHIRUDO_KEYS_REVOKED_DIR, fp,
				   ".der", revoked, sizeof(revoked));
		if (!rc)
			rc = revoked_cert(fp, revoked, &gone, &der, &der_sz);
		if (rc) {
			pr_err("keys revoke: read the revoked certificate: %s",
			       strerror(-rc));
			return 1;
		}
		pr_info("keys revoke: %s is already revoked; finishing it",
			fp_hex);
		victim = &gone;
		resume = true;
		goto finish;
	}
	if (set.n == 1 && !force) {
		pr_err("keys revoke: %s is the only certificate; revoking it "
		       "leaves nothing to verify against until a reboot with a "
		       "new one (--force to do it anyway)", fp_hex);
		return 1;
	}
	if (victim->primary && set.n > 1) {
		heir = promote_arg ? set_find(&set, promote_fp) : NULL;
		if (!heir || heir == victim) {
			pr_err("keys revoke: %s is the primary certificate; "
			       "name another member to take its place with "
			       "--promote <fingerprint>", fp_hex);
			return 1;
		}
	}
	rc = keys_read_der(victim->path, &der, &der_sz);
	if (rc) {
		pr_err("keys revoke: read %s: %s", victim->path, strerror(-rc));
		return 1;
	}

	/* The marker first: whatever happens next, no boot enrols it again. */
	rc = seal_mkdir_p(SHIRUDO_KEYS_REVOKED_DIR, 0700);
	if (rc) {
		pr_err("keys revoke: mkdir %s: %s", SHIRUDO_KEYS_REVOKED_DIR,
		       strerror(-rc));
		goto out;
	}
	rc = keys_path_for(SHIRUDO_KEYS_REVOKED_DIR, fp, ".der",
			   revoked, sizeof(revoked));
	if (!rc)
		rc = keys_write_file(revoked, der, der_sz);
	if (rc) {
		pr_err("keys revoke: write %s: %s", revoked, strerror(-rc));
		goto out;
	}
	if (heir) {
		rc = promote(heir);
		if (rc) {
			pr_err("keys revoke: promote: %s", strerror(-rc));
			goto out;
		}
	}

finish:
	/* The kernel: from this moment nothing it signed verifies. */
	key = keyring_find_cert(ring, der, der_sz);
	if (key == -ENOKEY) {
		pr_warn("keys revoke: %s is not in the bpf keyring this boot",
			fp_hex);
	} else if (key < 0) {
		pr_err("keys revoke: find the key in the bpf keyring: %s",
		       strerror(-key));
		rc = key;
		goto out;
	} else {
		rc = keyring_unlink_key(ring, key);
		if (rc) {
			pr_err("keys revoke: unlink key %d from the bpf "
			       "keyring %d: %s; the key is marked revoked and "
			       "leaves at the next boot", (int)key, (int)ring,
			       strerror(-rc));
			goto out;
		}
		pr_info("keys revoke: key %d unlinked from the bpf keyring",
			(int)key);
	}

	if (!resume || revoke_unmeasured(revoked, fp_hex)) {
		rc = measure_revoke(victim, fp_hex);
		if (rc)
			goto out;
	}

	/* The archive, then the files the set was read from. */
	purged = purge_signed_by(der, der_sz, &n_unloaded);
	if (purged < 0) {
		rc = purged;
		pr_err("keys revoke: not every upatch it signed could be "
		       "purged; run `shirudo upatch list`");
	}
	if (!victim->primary) {
		char vouch[PATH_MAX];

		if (strsprintf(vouch, sizeof(vouch), "%.*s.vouch",
			       (int)(strlen(victim->path) - 4), victim->path) >= 0)
			unlink(vouch);
		unlink(victim->path);
	}
	pr_audit("keys revoke: fingerprint=%s unloaded=%zu purged=%d "
		 "promoted=%s", fp_hex, n_unloaded, purged < 0 ? -1 : purged,
		 heir ? promote_arg : "-");
	printf("revoked %s\n", fp_hex);
	if (purged > 0)
		printf("purged %d upatch%s it signed, %zu of them loaded\n",
		       purged, purged == 1 ? "" : "es", n_unloaded);
	if (heir)
		printf("primary is now %s\n", promote_arg);
	pr_info("keys revoke: regenerate the initrd (shirudo-gen-initrd) so "
		"the next boot enrols the set without it");
out:
	xfree(der, der_sz);
	return rc ? 1 : 0;
}

/* Signing needs the private key, so the operator helper does it. */
static int keys_vouch(int argc, const char **argv)
{
	const char **helper_argv;
	size_t sz;
	int rc;

	if (argc >= 2 && is_help(argv[1])) {
		print_help(&keys_vouch_help);
		return 0;
	}
	sz = ((size_t)argc + 3) * sizeof(*helper_argv);
	helper_argv = xcalloc((size_t)argc + 3, sizeof(*helper_argv));
	if (!helper_argv)
		return 1;
	helper_argv[1] = "keys";
	helper_argv[2] = "vouch";
	for (int i = 1; i < argc; i++)
		helper_argv[i + 2] = argv[i];
	rc = shirudo_build_exec("keys vouch", (char **)helper_argv);
	xfree(helper_argv, sz);
	return rc;
}

static int keys_show(int argc, const char **argv);

int cmd_keys(int argc, const char **argv)
{
	const char *sub;

	if (argc < 2 || argv[1][0] == '-' || is_help(argv[1]))
		return keys_show(argc, argv);
	sub = resolve_subcommand("shirudo keys", argv[1], keys_subcmds,
				 ARRAY_SIZE(keys_subcmds));
	if (!sub)
		return 2;
	if (!strcmp(sub, "add"))
		return keys_add(argc - 1, argv + 1);
	if (!strcmp(sub, "revoke"))
		return keys_revoke(argc - 1, argv + 1);
	return keys_vouch(argc - 1, argv + 1);
}

static int keys_show(int argc, const char **argv)
{
	const char *keys_dir_arg = NULL;
	struct shirudo_trusted_set set;
	struct shirudo_identity id;
	const char *keys_dir;
	char pkey_path[PATH_MAX];
	char cert_path[PATH_MAX];
	bool shown = false;
	key_serial_t ring;
	const char *label;
	int rc = 0, id_rc;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--keys-dir") == 0 &&
		    i + 1 < argc) {
			keys_dir_arg = argv[++i];
		} else if (strncmp(argv[i], "--keys-dir=", 11) == 0) {
			keys_dir_arg = argv[i] + 11;
		} else if (is_help(argv[i])) {
			print_help(&keys_help);
			return 0;
		} else if (is_list_cmds(argv[i])) {
			print_subcmd_list(keys_subcmds,
					  ARRAY_SIZE(keys_subcmds));
			return 0;
		} else {
			pr_err("keys: unknown option '%s'", argv[i]);
			usage();
			return 2;
		}
	}

	keys_dir = keys_dir_resolve(keys_dir_arg);

	rc = key_paths(keys_dir, pkey_path, sizeof(pkey_path),
		       cert_path, sizeof(cert_path));
	if (rc) {
		pr_err("keys: invalid keys dir %s: %s",
		       keys_dir, strerror(-rc));
		return 2;
	}

	/*
	 * Both roles can coexist on one host (cert.der is held by the
	 * target as well as the operator), so report whatever is present
	 * rather than picking one mode: the on-disk cert + signing key,
	 * then the kernel keyring once `shirudo init` has populated one.
	 */
	if (path_exists(cert_path)) {
		if (keys_dump_disk_material(cert_path, pkey_path))
			rc = 1;
		shown = true;
	}

	if (keys_load(keys_dir, NULL, true, &set) == 0 &&
	    (set.n > 1 || set.n_revoked || set.n_unvouched)) {
		size_t i;

		printf("%sTrusted set (%zu member%s, %zu revoked, "
		       "%zu unvouched):\n", shown ? "\n" : "", set.n,
		       set.n == 1 ? "" : "s", set.n_revoked, set.n_unvouched);
		for (i = 0; i < set.n; i++) {
			char fp[65], sha[65];

			hex_encode(set.certs[i].fingerprint, 32, fp);
			hex_encode(set.certs[i].sha256, 32, sha);
			printf("  %s%s\n    sha256 %s\n", fp,
			       set.certs[i].primary ? "  (primary)" : "", sha);
			if (set.certs[i].primary)
				continue;
			hex_encode(set.certs[i].voucher, 32, fp);
			printf("    vouched by %s\n", fp);
		}
		shown = true;
	}

	id_rc = identity_read(&id);
	if (id_rc == 0 && id.keyring_type == SHIRUDO_SIG_KEYRING_BPF) {
		label = ".bpf";
		ring = keyring_bpf_serial();
	} else {
		label = SHIRUDO_KEYRING_NAME;
		ring = keyring_find(SHIRUDO_KEYRING_NAME);
	}
	if (ring >= 0) {
		if (shown)
			printf("\n");
		if (keys_list_keyring(ring, label, &id, id_rc))
			rc = 1;
		shown = true;
	} else if (ring == -ENOKEY && id_rc) {
		if (shown) {
			printf("\n");
			keyring_absent(label, ring, &id, id_rc);
		}
	} else {
		if (shown)
			printf("\n");
		keyring_absent(label, ring, &id, id_rc);
		shown = true;
		rc = 1;
	}

	if (!shown) {
		pr_err("no shirudo key material on this host: no %s and no "
		       "\"%s\" kernel keyring -- run `shirudo genkey` "
		       "(operator) or `shirudo init` (target)",
		       cert_path, SHIRUDO_KEYRING_NAME);
		rc = 1;
	}
	return rc;
}
