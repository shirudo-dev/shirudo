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
#include "util/format.h"
#include "util/help.h"
#include "util/hex.h"
#include "util/identity.h"
#include "util/io.h"
#include "util/image_keys.h"
#include "util/json.h"
#include "util/keyring.h"
#include "util/keys.h"
#include "util/log.h"
#include "util/options.h"
#include "util/malloc.h"
#include "util/paths.h"
#include "util/seal.h"
#include "util/upatch.h"

static X509 *read_cert_der(const char *path)
{
	int fd = open_trusted(path, O_RDONLY);
	BIO *bio;
	X509 *c;

	if (fd < 0) {
		pr_err("open %s: %s", path, strerror(-fd));
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
	BIO *b;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		pr_err("open %s: %s", path, strerror(errno));
		return NULL;
	}
	/* Unbuffered, where a FILE would keep the key in memory freed unscrubbed. */
	b = BIO_new_fd(fd, BIO_CLOSE);
	if (!b) {
		close(fd);
		openssl_complain("BIO_new_fd");
		return NULL;
	}
	k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
	BIO_free(b);
	if (!k)
		openssl_complain("PEM_read_bio_PrivateKey");
	return k;
}

static void name_to_str(const X509_NAME *name, char *out, size_t out_sz)
{
	if (!X509_NAME_oneline(name, out, (int)out_sz) &&
	    strscpy(out, "(parse error)", out_sz) < 0)
		out[0] = '\0';
}

static void asn1_time_to_iso(const ASN1_TIME *t, char *out, size_t out_sz)
{
	struct tm tm;

	if (!ASN1_TIME_to_tm(t, &tm)) {
		if (strscpy(out, "(unparseable)", out_sz) < 0)
			out[0] = '\0';
		return;
	}
	if (!strftime(out, out_sz, "%Y-%m-%dT%H:%M:%SZ", &tm) &&
	    strscpy(out, "(format error)", out_sz) < 0)
		out[0] = '\0';
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
	int ret = -1;

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
	ret = 0;
out:
	OPENSSL_free(der);
	return ret;
}

/* Set while keys prints JSON: every printer below emits into it instead. */
static struct json_emit *keys_json;

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
static __must_check int format_pkey_algorithm(EVP_PKEY *pkey, char *out,
					      size_t out_sz)
{
	const char *name = EVP_PKEY_get0_type_name(pkey);
	int id = EVP_PKEY_get_base_id(pkey);

	if (!name)
		name = "unknown";
	if (id == EVP_PKEY_RSA || id == EVP_PKEY_EC)
		return strsprintf(out, out_sz, "%s-%d", name,
				  EVP_PKEY_get_bits(pkey)) < 0 ? -E2BIG : 0;
	return strscpy(out, name, out_sz) < 0 ? -E2BIG : 0;
}

static int dump_operator_cert(X509 *cert, const char *cert_path,
			      const __u8 cert_spki_fpr[SHA256_DIGEST_LENGTH])
{
	const X509_NAME *subj = X509_get_subject_name(cert);
	const X509_NAME *iss  = X509_get_issuer_name(cert);
	const ASN1_TIME *nb = X509_get0_notBefore(cert);
	char subj_s[256], iss_s[256], nb_s[32];
	EVP_PKEY *pub = X509_get0_pubkey(cert);
	__u8 fpr[SHA256_DIGEST_LENGTH];
	char alg_s[64] = "";
	int self_signed;

	name_to_str(subj, subj_s, sizeof(subj_s));
	name_to_str(iss, iss_s, sizeof(iss_s));
	asn1_time_to_iso(nb, nb_s, sizeof(nb_s));
	if (pub && format_pkey_algorithm(pub, alg_s, sizeof(alg_s)))
		strscpy_literal(alg_s, "?");
	self_signed = (X509_NAME_cmp(subj, iss) == 0);

	if (keys_json) {
		char hex[65];

		json_obj_open_key(keys_json, "cert");
		json_kv_string(keys_json, "path", cert_path);
		json_kv_string(keys_json, "subject", subj_s);
		json_kv_string(keys_json, "issuer", iss_s);
		json_kv_bool(keys_json, "self_signed", self_signed);
		if (pub)
			json_kv_string(keys_json, "algorithm", alg_s);
		else
			json_kv_null(keys_json, "algorithm");
		if (compute_cert_fpr(cert, fpr) == 0) {
			hex_encode(fpr, SHA256_DIGEST_LENGTH, hex);
			json_kv_string(keys_json, "fingerprint", hex);
		} else {
			json_kv_null(keys_json, "fingerprint");
		}
		hex_encode(cert_spki_fpr, SHA256_DIGEST_LENGTH, hex);
		json_kv_string(keys_json, "spki_fingerprint", hex);
		json_kv_string(keys_json, "not_before", nb_s);
		json_obj_close(keys_json);
		return 0;
	}
	printf("Certificate (%s):\n", cert_path);
	printf("  %-22s %s\n", "Subject:", subj_s);
	printf("  %-22s %s%s\n", "Issuer:", iss_s,
	       self_signed ? "  (self-signed)" : "");
	if (pub)
		printf("  %-22s %s\n", "Public key:", alg_s);
	if (compute_cert_fpr(cert, fpr) == 0)
		print_fpr("Fingerprint:", fpr);
	print_fpr("SPKI fingerprint:", cert_spki_fpr);
	printf("  %-22s %s\n", "Issued:", nb_s);
	return 0;
}

static int dump_signing_key(const char *pkey_path,
			    const __u8 cert_spki_fpr[SHA256_DIGEST_LENGTH])
{
	__u8 fpr_priv[SHA256_DIGEST_LENGTH];
	char alg_s[64], hex[65];
	EVP_PKEY *priv;
	bool matches;
	int ret = 0;

	if (!path_exists(pkey_path)) {
		if (keys_json) {
			json_obj_open_key(keys_json, "signing_key");
			json_kv_string(keys_json, "path", pkey_path);
			json_kv_bool(keys_json, "present", false);
			json_obj_close(keys_json);
			return 0;
		}
		printf("Signing key (%s):\n", pkey_path);
		printf("  %-22s %s\n", "Present:",
		       "no, a target holds no private key");
		return 0;
	}

	priv = read_priv_pem(pkey_path);
	if (!priv)
		return -1;
	if (format_pkey_algorithm(priv, alg_s, sizeof(alg_s)))
		strscpy_literal(alg_s, "?");
	if (keys_json) {
		json_obj_open_key(keys_json, "signing_key");
		json_kv_string(keys_json, "path", pkey_path);
		json_kv_bool(keys_json, "present", true);
		json_kv_string(keys_json, "algorithm", alg_s);
	} else {
		printf("Signing key (%s):\n", pkey_path);
		printf("  %-22s %s\n", "Present:", "yes");
		printf("  %-22s %s\n", "Algorithm:", alg_s);
	}
	if (compute_spki_fpr(priv, fpr_priv) != 0) {
		ret = -1;
		goto out;
	}
	matches = memcmp(fpr_priv, cert_spki_fpr, SHA256_DIGEST_LENGTH) == 0;
	if (keys_json) {
		hex_encode(fpr_priv, SHA256_DIGEST_LENGTH, hex);
		json_kv_string(keys_json, "spki_fingerprint", hex);
		json_kv_bool(keys_json, "matches_cert", matches);
	} else {
		print_fpr("SPKI fingerprint:", fpr_priv);
		printf("  %-22s %s\n", "Matches cert:", matches ? "yes" :
		       "no, the private key is not the certificate's");
	}
	if (!matches) {
		pr_warn("keys: private key and cert have different public keys");
		ret = -1;
	}
out:
	if (keys_json)
		json_obj_close(keys_json);
	EVP_PKEY_free(priv);
	return ret;
}

static int keys_dump_disk_material(const char *cert_path,
				   const char *pkey_path)
{
	X509 *cert;
	EVP_PKEY *pub;
	__u8 cert_spki_fpr[SHA256_DIGEST_LENGTH];
	int ret;

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

	ret = dump_operator_cert(cert, cert_path, cert_spki_fpr);
	if (ret == 0) {
		if (!keys_json)
			printf("\n");
		ret = dump_signing_key(pkey_path, cert_spki_fpr);
	}
	X509_free(cert);
	return ret ? 1 : 0;
}

/* A keyring init froze: its serial and the keys it recorded in it. */
struct keys_anchor {
	const char	*label;
	key_serial_t	(*serial)(void);
	key_serial_t	frozen;		/* 0 when none was recorded */
	const __s32	*keys;
	size_t		n_keys;
};

static bool keys_anchor_holds(const struct keys_anchor *a, key_serial_t key)
{
	size_t i;

	for (i = 0; i < a->n_keys; i++)
		if (a->keys[i] == key)
			return true;
	return false;
}

static int keys_list_keyring(key_serial_t ring, const struct keys_anchor *a,
			     int id_rc)
{
	bool frozen = !id_rc && a->frozen > 0;
	struct keyring_link *links = NULL;
	size_t n = 0, i;
	int ret;

	if (keys_json) {
		json_obj_open(keys_json);
		json_kv_string(keys_json, "name", a->label);
		json_kv_bool(keys_json, "present", true);
		json_kv_int(keys_json, "serial", ring);
		if (frozen)
			json_kv_int(keys_json, "frozen_serial", a->frozen);
		else
			json_kv_null(keys_json, "frozen_serial");
		ret = keyring_links(ring, &links, &n);
		json_arr_open(keys_json, "members");
		for (i = 0; !ret && i < n; i++) {
			const struct keyring_link *l = &links[i];

			json_obj_open(keys_json);
			json_kv_int(keys_json, "serial", l->serial);
			if (l->err) {
				json_kv_null(keys_json, "type");
				json_kv_null(keys_json, "description");
			} else {
				json_kv_string(keys_json, "type", l->type);
				json_kv_string(keys_json, "description",
					       l->description);
			}
			if (frozen)
				json_kv_bool(keys_json, "frozen",
					     keys_anchor_holds(a, l->serial));
			else
				json_kv_null(keys_json, "frozen");
			json_obj_close(keys_json);
		}
		json_arr_close(keys_json);
		json_obj_close(keys_json);
		if (ret) {
			pr_err("keyring list: %s", strerror(-ret));
			return 1;
		}
		xfree(links, n * sizeof(*links));
		return 0;
	}
	printf("Keyring (%s):\n", a->label);
	printf("  %-22s %d\n", "Serial:", (int)ring);
	if (frozen) {
		printf("  %-22s %d  (%s)\n", "Frozen serial:", (int)a->frozen,
		       a->frozen == ring ? "matches" : "swapped");
		if (a->frozen != ring)
			pr_warn("%s keyring serial %d is not the frozen %d: swapped",
				a->label, (int)ring, (int)a->frozen);
	} else if (!id_rc || id_rc == -ENOENT) {
		printf("  %-22s %s\n", "Frozen serial:", "(none this boot)");
	} else {
		printf("  %-22s unreadable: %s\n", "Frozen serial:",
		       strerror(-id_rc));
	}

	ret = keyring_links(ring, &links, &n);
	if (ret) {
		pr_err("keyring list: %s", strerror(-ret));
		return 1;
	}
	printf("  Members (%zu):\n", n);
	if (!n)
		printf("    (empty)\n");
	for (i = 0; i < n; i++) {
		const struct keyring_link *l = &links[i];

		printf("    serial=%-10d  type=%-10s  ", (int)l->serial,
		       l->err ? "?" : l->type);
		if (l->err)
			printf("(cannot describe: %s)", strerror(-l->err));
		else
			fputs_sanitized(l->description, stdout);
		if (frozen)
			printf("  (%s)", keys_anchor_holds(a, l->serial) ?
			       "frozen" : "not frozen");
		printf("\n");
	}
	xfree(links, n * sizeof(*links));
	return 0;
}

static void keyring_absent(const struct keys_anchor *a, key_serial_t ret,
			   int id_rc)
{
	char reason[128];
	int n = 0;

	if (ret != (key_serial_t)-ENOKEY)
		n = strsprintf(reason, sizeof(reason), "lookup error: %s",
			       strerror(-ret));
	else if (!id_rc && a->frozen > 0)
		n = strsprintf(reason, sizeof(reason),
			       "gone, init froze serial %d this boot",
			       (int)a->frozen);
	else if (!id_rc || id_rc == -ENOENT)
		strscpy_literal(reason, "absent before init");
	else
		n = strsprintf(reason, sizeof(reason),
			       "frozen identity unreadable: %s",
			       strerror(-id_rc));
	if (n < 0)
		strscpy_literal(reason, "?");
	if (keys_json) {
		json_obj_open(keys_json);
		json_kv_string(keys_json, "name", a->label);
		json_kv_bool(keys_json, "present", false);
		json_kv_null(keys_json, "serial");
		if (!id_rc && a->frozen > 0)
			json_kv_int(keys_json, "frozen_serial", a->frozen);
		else
			json_kv_null(keys_json, "frozen_serial");
		json_kv_string(keys_json, "reason", reason);
		json_obj_close(keys_json);
		return;
	}
	printf("Keyring (%s):\n", a->label);
	printf("  %-22s no, %s\n", "Present:", reason);
}

static const struct help_item keys_subcmds[] = {
	{ "add", "trust a certificate an enrolled key vouched for (target)" },
	{ "revoke", "stop trusting a certificate now and for good (target)" },
	{ "vouch", "sign a vouch for a certificate (operator)" },
};

enum keys_opt {
	KEYS_KEYS_DIR,
	KEYS_JSON,
};

static const struct opt_spec keys_opts[] = {
	[KEYS_KEYS_DIR] = { "--keys-dir", 0, 0, "<dir>",
		"read signing_key.pem and cert.der from <dir>" },
	[KEYS_JSON] = { "--json", 0, 0, NULL,
		"print the key material as JSON" },
};

static const struct help_section keys_help_sections[] = {
	HELP_ITEMS("subcommands:", keys_subcmds),
	HELP_OPTIONS("options:", keys_opts),
};

static const struct help keys_help = {
	.usage   = "shirudo keys [--keys-dir <dir>] [--json]\n"
		   "       shirudo keys add <cert.der> --vouch <file>\n"
		   "       shirudo keys revoke\n"
		   "       shirudo keys vouch <cert.der> [-o <file>]",
	.summary = "Inspect the shirudo key material this host holds: the "
		   "on-disk cert and\nsigning key (if present), the trusted "
		   "set a target enrols, and the kernel\nkeyring holding it "
		   "(if init'd). Local-only on either side.",
	.sections   = keys_help_sections,
	.n_sections = ARRAY_SIZE(keys_help_sections),
	.footer  = "Default paths:\n"
		   "  " CERT_PATH "\n"
		   "  " SIGNING_KEY_PATH "\n\n"
		   "Or set the " KEYS_DIR_ENV
		   " environment variable.",
};

enum keys_add_opt {
	KEYS_ADD_VOUCH,
	KEYS_ADD_KEYS_DIR,
};

static const struct opt_spec keys_add_opts[] = {
	[KEYS_ADD_VOUCH] = { "--vouch", 0, 0, "<file>",
		"the vouch an enrolled key signed for the certificate" },
	[KEYS_ADD_KEYS_DIR] = { "--keys-dir", 0, 0, "<dir>",
		"the keys directory (default " KEYS_DIR ")" },
};

static const struct help_section keys_add_sections[] = {
	HELP_OPTIONS("options:", keys_add_opts),
};

static const struct help keys_add_help = {
	.usage   = "shirudo keys add <cert.der> --vouch <file> [--keys-dir <dir>]",
	.summary = "Add a certificate to the trusted set this target enrols at "
		   "its next boot.\nThe vouch must verify under a certificate "
		   "already in the set; regenerate\nthe initrd afterwards "
		   "(shirudo-gen-initrd). Prints the fingerprint.",
	.sections   = keys_add_sections,
	.n_sections = ARRAY_SIZE(keys_add_sections),
};

/* The public key must be one the kernel verifies loaders with. */
static int check_cert_algorithm(const __u8 *der, size_t der_sz,
				const char *what)
{
	char alg[32] = {};
	int ret;

	ret = cert_der_require_mldsa87(der, der_sz, alg, sizeof(alg));
	if (ret == -EKEYREJECTED)
		pr_err("keys add: %s is %s; shirudo accepts only ML-DSA-87",
		       what, alg);
	else if (ret)
		pr_err("keys add: %s is not a certificate", what);
	return ret;
}

/*
 * The vouching certificate must be one the kernel verifies against
 * right now, not only one on disk, when the live target's set is the
 * one being extended.
 */
static int check_voucher_live(const struct trusted_set *set,
			      const __u8 voucher[32])
{
	const struct trusted_cert *member;
	struct identity id;
	const __u8 *der = NULL;
	key_serial_t ring;
	size_t der_sz = 0;
	int ret = 0;

	if (identity_read(&id) ||
	    id.keyring_type != SIG_KEYRING_BPF)
		return 0;
	ring = keyring_bpf_serial();
	if (ring <= 0)
		return 0;
	member = keys_member(set, voucher);
	if (!member)
		return -ENOKEY;
	ret = keys_cert_der(member, &der, &der_sz);
	if (ret)
		return ret;
	ret = keyring_holds_cert(ring, der, der_sz);
	if (ret < 0)
		return ret;
	return ret ? 0 : -ENOKEY;
}

static int keys_add(int argc, const char **argv)
{
	const char *keys_dir_arg = NULL, *vouch_path = NULL, *cert = NULL;
	__u8 *der = NULL, *sig = NULL;
	__u8 sha256[32], fp[32], by[32];
	struct trusted_set set;
	char fp_hex[65], by_hex[65];
	size_t der_sz = 0, sig_sz = 0;
	char revoked[PATH_MAX];
	struct opt_parser p;
	const char *keys_dir;
	char out[PATH_MAX];
	int ret = 1, opt;
	size_t i;

	OPT_INIT(&p, "keys add", keys_add_opts, &keys_add_help, argc, argv, 1);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case KEYS_ADD_VOUCH:
			vouch_path = p.value;
			break;
		case KEYS_ADD_KEYS_DIR:
			keys_dir_arg = p.value;
			break;
		case OPT_ARG:
			if (cert) {
				opt_usage(&p, "unexpected argument '%s'",
					  p.value);
				return EXIT_USAGE;
			}
			cert = p.value;
			break;
		case OPT_DONE:
			return 0;
		default:
			return EXIT_USAGE;
		}
	}
	if (!cert || !vouch_path) {
		opt_usage(&p, "takes <cert.der> and --vouch <file>");
		return EXIT_USAGE;
	}
	if (image_config_active()) {
		pr_err("target: add vouched BPF signers to the signed "
		       "config selected for boot and reboot to enroll them");
		return 1;
	}
	keys_dir = keys_dir_resolve(keys_dir_arg);
	if (strsprintf(revoked, sizeof(revoked), "%s/revoked", keys_dir) < 0) {
		pr_err("keys add: keys directory path too long");
		return 2;
	}

	ret = keys_read_der(cert, &der, &der_sz);
	if (ret) {
		pr_err("keys add: read %s: %s", cert, strerror(-ret));
		return 1;
	}
	ret = keys_digest_der(der, der_sz, sha256, fp);
	if (ret) {
		pr_err("keys add: %s is not a certificate", cert);
		goto out;
	}
	ret = check_cert_algorithm(der, der_sz, cert);
	if (ret)
		goto out;
	hex_encode(fp, 32, fp_hex);

	ret = keys_load(keys_dir, NULL, true, &set);
	if (ret) {
		pr_err("keys add: no trusted set under %s: %s (install the "
		       "primary certificate first)", keys_dir, strerror(-ret));
		goto out;
	}
	if (keys_is_revoked(revoked, fp)) {
		pr_err("keys add: %s was revoked on this target", fp_hex);
		ret = -EKEYREVOKED;
		goto out;
	}
	ret = keys_read_der(vouch_path, &sig, &sig_sz);
	if (ret) {
		pr_err("keys add: read %s: %s", vouch_path, strerror(-ret));
		goto out;
	}
	ret = keys_verify_vouch(&set, der, der_sz, sig, sig_sz, by);
	if (ret) {
		pr_err("keys add: %s does not vouch for %s under any of the "
		       "%zu trusted certificate%s", vouch_path, fp_hex, set.n,
		       set.n == 1 ? "" : "s");
		goto out;
	}
	hex_encode(by, 32, by_hex);
	if (!strcmp(keys_dir, KEYS_DIR)) {
		ret = check_voucher_live(&set, by);
		if (ret) {
			pr_err("keys add: the vouching certificate %s is not "
			       "in the bpf keyring this boot%s%s", by_hex,
			       ret == -ENOKEY ? "" : ": ",
			       ret == -ENOKEY ? "" : strerror(-ret));
			goto out;
		}
	}
	for (i = 0; i < set.n; i++) {
		if (memcmp(set.certs[i].fingerprint, fp, 32))
			continue;
		pr_info("keys add: %s is already trusted", fp_hex);
		printf("%s\n", fp_hex);
		ret = 0;
		goto out;
	}
	/* A set past the limit would fail to load at all, init included. */
	if (set.n >= KEYS_MAX) {
		pr_err("keys add: the trusted set holds %d certificates, the "
		       "most a target enrols", KEYS_MAX);
		ret = -E2BIG;
		goto out;
	}
	ret = keys_install(keys_dir, der, der_sz, sig, sig_sz, out,
			   sizeof(out));
	if (ret) {
		pr_err("keys add: install under %s/trusted: %s", keys_dir,
		       strerror(-ret));
		goto out;
	}
	pr_audit("keys add: fingerprint=%s vouched_by=%s path=%s", fp_hex,
		 by_hex, out);
	pr_info("keys add: %s joins the set at the next boot; regenerate "
		"the initrd (shirudo-gen-initrd)", fp_hex);
	printf("%s\n", fp_hex);
out:
	xfree(sig, sig_sz);
	xfree(der, der_sz);
	return ret ? 1 : 0;
}

static const struct help keys_revoke_help = {
	.usage = "shirudo keys revoke",
	.summary = "Local revocation is disabled. Publish revocation records "
		   "in a signed config image and activate it with image update.",
};

static int format_key_event(const char *type, const char *fp_hex,
			    const __u8 cert_sha[32], const __u8 event[32],
			    char *buf, size_t size)
{
	struct json_emit e = { .buf = buf, .cap = size };
	char sha_hex[65];

	hex_encode(cert_sha, 32, sha_hex);
	eventlog_record_open(&e, type, event);
	json_obj_open_key(&e, "key");
	json_kv_string(&e, "fingerprint", fp_hex);
	json_kv_string(&e, "cert_sha256", sha_hex);
	json_obj_close(&e);
	json_obj_close(&e);
	if (e.err)
		pr_err("eventlog: %s entry encode failed: %s", type,
		       strerror(-e.err));
	return e.err;
}

/*
 * The register learns of the revocation before anything else changes
 * in the archive, so evidence taken at any point names it. The same
 * fail-closed treatment as a upatch event: no TPM is an error, not an
 * unmeasured success.
 */
static int measure_revoke_locked(const struct trusted_cert *c,
				 const char *fp_hex)
{
	char record[1024], chain_hex[65];
	__u8 event[32], chain[32];
	int ret;

	ret = chain_key_event("shirudo-key-revoke", c->sha256, event);
	if (ret) {
		pr_err("keys revoke: cannot hash the revocation event: %s; the key is revoked but the revocation is NOT measured; operator must reconcile",
		       strerror(-ret));
		return ret;
	}
	/*
	 * The record is written out before the extend, which nothing takes
	 * back: one that cannot be encoded after it would leave the register
	 * ahead of the log.
	 */
	ret = format_key_event("key_revoke", fp_hex, c->sha256, event, record,
			       sizeof(record));
	if (ret) {
		pr_err("keys revoke: cannot write the record of the revocation; the key is revoked but the revocation is NOT measured; operator must reconcile");
		return ret;
	}
	ret = chain_extend(event, chain);
	if (ret) {
		pr_err("keys revoke: register %s (category: %s); the key is "
		       "revoked but the revocation is NOT measured; operator "
		       "must reconcile",
		       ret == -ENODEV ? "unavailable" :
		       ret == -EACCES ? "is not the one init bound" :
		       "extend failed",
		       ret == -EACCES ? "tampered" : "tpm_error");
		return ret;
	}
	ret = eventlog_append(record);
	if (ret) {
		pr_err("keys revoke: eventlog append failed after the extend: "
		       "register and log disagree; the operator must reconcile");
		return ret;
	}
	hex_encode(chain, 32, chain_hex);
	pr_audit("key revoke measured: fingerprint=%s chain=%s", fp_hex,
		 chain_hex);
	return 0;
}

static int measure_revoke(const struct trusted_cert *c,
			  const char *fp_hex)
{
	int lock, ret;

	lock = eventlog_lock();
	if (lock < 0) {
		pr_err("keys revoke: cannot take the register lock: %s; the "
		       "revocation is NOT measured", strerror(-lock));
		return lock;
	}
	ret = measure_revoke_locked(c, fp_hex);
	eventlog_unlock(lock);
	return ret;
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
	struct cert cert = {};
	struct dirent **names = NULL;
	int n, i, ret = 0, purged = 0;

	*unloaded = 0;
	if (cert_read_der(der, der_sz, &cert))
		return -EINVAL;
	n = scandir(UPATCHES_DIR, &names, upatch_select,
		    alphasort);
	if (n < 0) {
		cert_free(&cert);
		return errno == ENOENT ? 0 : -errno;
	}
	for (i = 0; i < n; i++) {
		char name[UPATCH_NAME_MAX + 1];
		struct upatch u;
		char path[PATH_MAX];
		int signed_by, prc;

		if (strsprintf(path, sizeof(path), "%s/%s", UPATCHES_DIR,
			       names[i]->d_name) < 0)
			continue;
		if (upatch_open(path, &u))
			continue;
		signed_by = cms_signed_by(upatch_signature(&u),
					  u.hdr.signature_len, &cert);
		upatch_header_name(&u, name);
		upatch_close(&u);
		if (signed_by != 1)
			continue;
		prc = upatch_purge(name, &cert, "key_revoke");
		if (prc == -ESTALE) {
			pr_info("keys revoke: %s was replaced by an upatch the key did not sign; left alone",
				name);
			continue;
		}
		if (prc < 0) {
			pr_err("keys revoke: purge %s: %s", name,
			       strerror(-prc));
			ret = prc;
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
	return ret ? ret : purged;
}

int keys_revoke_image(const __u8 *der, size_t size, bool boot)
{
	struct trusted_cert cert = {};
	key_serial_t ring, key;
	char fingerprint[65];
	size_t unloaded;
	int ret;

	ring = keyring_bpf_serial();
	if (ring < 0)
		return ring;
	key = keyring_find_cert(ring, der, size);
	if (key != -ENOKEY && key < 0)
		return key;
	if (key >= 0) {
		ret = keyring_unlink_key(ring, key);
		if (ret)
			return ret;
		if (!boot) {
			ret = keys_digest_der(der, size, cert.sha256,
					      cert.fingerprint);
			if (ret)
				return ret;
			hex_encode(cert.fingerprint, 32, fingerprint);
			ret = measure_revoke(&cert, fingerprint);
			if (ret)
				return ret;
		}
	}
	ret = purge_signed_by(der, size, &unloaded);
	return min(ret, 0);
}

static int keys_revoke(int argc, const char **argv)
{
	if (argc == 2 && is_help(argv[1])) {
		print_help(&keys_revoke_help);
		return 0;
	}
	pr_err("keys revoke: put revocation records in a signed config image, "
	       "then run `shirudo image update`");
	return 1;
}

static int keys_vouch(int argc, const char **argv)
{
	return build_forward("keys vouch",
			     (const char *const[]){ "keys", "vouch", NULL },
			     argc - 1, argv + 1);
}

static int keys_show(int argc, const char **argv);

int cmd_keys(int argc, const char **argv)
{
	const char *sub;

	if (argc >= 2 && is_help(argv[1])) {
		print_help(&keys_help);
		return 0;
	}
	if (argc >= 2 && is_list_cmds(argv[1])) {
		print_subcmd_list(keys_subcmds, ARRAY_SIZE(keys_subcmds));
		return 0;
	}
	if (argc < 2 || argv[1][0] == '-')
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
	struct json_emit je = { .cap = 65536 };
	struct identity id = {};
	struct trusted_set set;
	const char *keys_dir;
	char pkey_path[PATH_MAX];
	char cert_path[PATH_MAX];
	bool shown = false, json = false, have_set = false;
	int ret = 0, id_rc, opt;
	struct opt_parser p;

	OPT_INIT(&p, "keys", keys_opts, &keys_help, argc, argv, 1);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case KEYS_KEYS_DIR:
			keys_dir_arg = p.value;
			break;
		case KEYS_JSON:
			json = true;
			break;
		case OPT_ARG:
			opt_usage(&p, "unexpected argument '%s'", p.value);
			return EXIT_USAGE;
		case OPT_DONE:
			return 0;
		default:
			return EXIT_USAGE;
		}
	}

	keys_dir = image_config_active() ? RUNTIME_DIR "/keys" :
		keys_dir_resolve(keys_dir_arg);

	ret = key_paths(keys_dir, pkey_path, sizeof(pkey_path),
			cert_path, sizeof(cert_path));
	if (ret) {
		pr_err("keys: invalid keys dir %s: %s",
		       keys_dir, strerror(-ret));
		return 2;
	}

	/*
	 * Both roles can coexist on one host (cert.der is held by the
	 * target as well as the operator), so report whatever is present
	 * rather than picking one mode: the on-disk cert + signing key,
	 * then the kernel keyring once `shirudo init` has populated one.
	 */
	if (json) {
		je.buf = xmalloc(je.cap);
		if (!je.buf)
			return 1;
		keys_json = &je;
		json_obj_open(&je);
		json_kv_int(&je, "schema", 1);
	}
	if (path_exists(cert_path)) {
		if (keys_dump_disk_material(cert_path, pkey_path))
			ret = 1;
		shown = true;
	} else if (json) {
		json_kv_null(&je, "cert");
		json_kv_null(&je, "signing_key");
	}

	have_set = keys_load(keys_dir, NULL, true, &set) == 0;
	if (json)
		json_arr_open(&je, "trusted_set");
	if (have_set && (json || set.n > 1 || set.n_revoked ||
			 set.n_unvouched)) {
		size_t i;

		if (!json)
			printf("%sTrusted set (%zu member%s, %zu revoked, "
			       "%zu unvouched):\n", shown ? "\n" : "", set.n,
			       set.n == 1 ? "" : "s", set.n_revoked,
			       set.n_unvouched);
		for (i = 0; i < set.n; i++) {
			char fp[65], sha[65], voucher[65];

			hex_encode(set.certs[i].fingerprint, 32, fp);
			hex_encode(set.certs[i].sha256, 32, sha);
			hex_encode(set.certs[i].voucher, 32, voucher);
			if (json) {
				json_obj_open(&je);
				json_kv_string(&je, "fingerprint", fp);
				json_kv_string(&je, "sha256", sha);
				json_kv_bool(&je, "primary",
					     set.certs[i].primary);
				if (set.certs[i].primary)
					json_kv_null(&je, "voucher");
				else
					json_kv_string(&je, "voucher", voucher);
				json_obj_close(&je);
				continue;
			}
			printf("  %s%s\n    sha256 %s\n", fp,
			       set.certs[i].primary ? "  (primary)" : "", sha);
			if (!set.certs[i].primary)
				printf("    vouched by %s\n", voucher);
		}
		if (!json)
			shown = true;
	}
	if (json)
		json_arr_close(&je);

	id_rc = identity_read(&id);
	{
		const struct keys_anchor anchors[] = {
			{ ".bpf", keyring_bpf_serial, id.keyring_serial,
			  id.key_serials,
			  min(id.n_keys, IDENTITY_KEYS_MAX) },
			{ ".dm-verity", keyring_dm_verity_serial,
			  id.dm_verity_ring, id.dm_verity_keys,
			  min(id.n_dm_verity_keys, IDENTITY_KEYS_MAX) },
		};
		size_t i;

		if (json)
			json_arr_open(&je, "keyrings");
		for (i = 0; i < ARRAY_SIZE(anchors); i++) {
			const struct keys_anchor *a = &anchors[i];
			key_serial_t ring = id_rc ? -ENOKEY : a->serial();

			if (ring >= 0) {
				if (shown && !json)
					printf("\n");
				if (keys_list_keyring(ring, a, id_rc))
					ret = 1;
				shown = true;
			} else if (ring == -ENOKEY && id_rc) {
				if (shown || json) {
					if (!json)
						printf("\n");
					keyring_absent(a, ring, id_rc);
				}
			} else {
				if (shown && !json)
					printf("\n");
				keyring_absent(a, ring, id_rc);
				shown = true;
				ret = 1;
			}
		}
		if (json)
			json_arr_close(&je);
	}
	if (json) {
		json_obj_close(&je);
		keys_json = NULL;
		if (je.err) {
			pr_err("keys: json encode failed");
			ret = 1;
		} else {
			puts(je.buf);
		}
		xfree(je.buf, je.cap);
	}
	if (!shown) {
		pr_err("no shirudo key material on this host: no %s and no "
		       "%s kernel keyring; run shirudo genkey on an operator "
		       "or shirudo init on a target",
		       cert_path, ".bpf");
		ret = 1;
	}
	return ret;
}
