// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * `shirudo-build keys vouch`: sign a vouch for another certificate.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "bpm.h"
#include "util/crypto.h"
#include "util/hex.h"
#include "util/io.h"
#include "util/keys.h"
#include "util/log.h"
#include "util/help.h"
#include "util/malloc.h"
#include "util/options.h"
#include "util/paths.h"
#include "util/sign.h"

#define VOUCH_SIG_MAX	(64u * 1024u)

enum vouch_opt {
	VOUCH_OUTPUT,
	VOUCH_KEYS_DIR,
	VOUCH_KEY,
	VOUCH_CERT,
};

static const struct opt_spec vouch_opts[] = {
	[VOUCH_OUTPUT] = { "--output", 'o', 0, "<file>",
		"where to write the vouch (default <cert.der>.vouch)" },
	[VOUCH_KEYS_DIR] = { "--keys-dir", 0, 0, "<dir>",
		"read signing_key.pem and cert.der from <dir>" },
	[VOUCH_KEY] = { "--key", 0, 0, "<signing_key.pem>",
		"the signing key (overrides --keys-dir)" },
	[VOUCH_CERT] = { "--cert", 0, 0, "<cert.der>",
		"the signing certificate (overrides --keys-dir)" },
};

static const struct help_section vouch_sections[] = {
	HELP_OPTIONS("options:", vouch_opts),
};

static const struct help vouch_help = {
	.usage	    = "shirudo keys vouch <cert.der> [-o <file>] "
		      "[--keys-dir <dir>]\n"
		      "                          [--key <signing_key.pem>] "
		      "[--cert <cert.der>]",
	.summary    = "Sign a vouch for another operator's certificate with "
		      "this operator's key,\nfor `shirudo keys add --vouch` on "
		      "the targets that enrol this key.\nPrints the vouched "
		      "certificate's fingerprint.",
	.sections   = vouch_sections,
	.n_sections = ARRAY_SIZE(vouch_sections),
};

static int cert_algorithm_ok(const __u8 *der, size_t der_sz,
			     const char *what)
{
	char alg[32] = {};
	int ret;

	ret = cert_der_require_mldsa87(der, der_sz, alg, sizeof(alg));
	if (ret == -EKEYREJECTED)
		pr_err("%s is %s; shirudo accepts only ML-DSA-87", what, alg);
	else if (ret)
		pr_err("%s is not a certificate", what);
	return ret;
}

static int write_file(const char *path, const void *data, size_t len)
{
	int fd, ret;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0)
		return -errno;
	ret = write_complete(fd, data, len);
	if (close(fd) && !ret)
		ret = -errno;
	if (ret)
		unlink(path);
	return ret;
}

int build_keys_vouch(int argc, const char **argv)
{
	const char *pkey = SIGNING_KEY_PATH, *cert = CERT_PATH;
	const char *keys_dir_arg = NULL, *input = NULL, *output = NULL;
	__u8 *der = NULL, *own = NULL, *payload = NULL;
	size_t der_sz = 0, own_sz = 0, payload_sz = 0;
	struct sign_io io = {};
	__u8 sha[32], fp[32], own_fp[32];
	int pkey_explicit = 0, cert_explicit = 0;
	char fp_hex[65], own_hex[65];
	char pkey_path[PATH_MAX];
	char cert_path[PATH_MAX];
	char out_path[PATH_MAX];
	struct opt_parser p;
	const char *keys_dir;
	int ret = 1, opt;

	OPT_INIT(&p, "keys vouch", vouch_opts, &vouch_help, argc, argv, 1);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case VOUCH_OUTPUT:
			output = p.value;
			break;
		case VOUCH_KEYS_DIR:
			keys_dir_arg = p.value;
			break;
		case VOUCH_KEY:
			pkey = p.value;
			pkey_explicit = 1;
			break;
		case VOUCH_CERT:
			cert = p.value;
			cert_explicit = 1;
			break;
		case OPT_ARG:
			if (input) {
				opt_usage(&p, "unexpected argument '%s'",
					  p.value);
				return EXIT_USAGE;
			}
			input = p.value;
			break;
		case OPT_DONE:
			return 0;
		default:
			return EXIT_USAGE;
		}
	}
	if (!input) {
		opt_usage(&p, "takes <cert.der>");
		return EXIT_USAGE;
	}
	keys_dir = keys_dir_resolve(keys_dir_arg);
	if (keys_dir) {
		if (!pkey_explicit) {
			if (format_key_path(pkey_path, sizeof(pkey_path),
					    keys_dir,
					    SIGNING_KEY_FILE)) {
				pr_err("invalid keys dir %s", keys_dir);
				return 2;
			}
			pkey = pkey_path;
		}
		if (!cert_explicit) {
			if (format_key_path(cert_path, sizeof(cert_path),
					    keys_dir, CERT_FILE)) {
				pr_err("invalid keys dir %s", keys_dir);
				return 2;
			}
			cert = cert_path;
		}
	}
	if (build_check_keys(pkey, cert))
		return 1;
	if (!output) {
		if (strsprintf(out_path, sizeof(out_path), "%s.vouch", input) < 0) {
			pr_err("keys vouch: output path too long");
			return 2;
		}
		output = out_path;
	}

	ret = keys_read_der(input, &der, &der_sz);
	if (ret) {
		pr_err("keys vouch: read %s: %s", input, strerror(-ret));
		return 1;
	}
	ret = keys_digest_der(der, der_sz, sha, fp);
	if (ret) {
		pr_err("keys vouch: %s is not a certificate", input);
		goto out;
	}
	ret = cert_algorithm_ok(der, der_sz, input);
	if (ret)
		goto out;
	ret = keys_read_der(cert, &own, &own_sz);
	if (ret) {
		pr_err("keys vouch: read %s: %s", cert, strerror(-ret));
		goto out;
	}
	ret = keys_digest_der(own, own_sz, sha, own_fp);
	if (ret) {
		pr_err("keys vouch: %s is not a certificate", cert);
		goto out;
	}
	hex_encode(fp, 32, fp_hex);
	hex_encode(own_fp, 32, own_hex);
	if (!memcmp(fp, own_fp, 32)) {
		pr_err("keys vouch: %s holds the signing key itself; a key "
		       "cannot vouch for its own certificate", input);
		ret = -EINVAL;
		goto out;
	}
	ret = keys_vouch_payload(der, der_sz, &payload, &payload_sz);
	if (ret)
		goto out;
	io.insns = payload;
	io.insns_sz = payload_sz;
	io.signature_sz = VOUCH_SIG_MAX;
	io.signature = xmalloc(VOUCH_SIG_MAX);
	if (!io.signature) {
		ret = -ENOMEM;
		goto out;
	}
	ret = cms_sign(&io, pkey, cert);
	if (ret) {
		pr_err("keys vouch: sign: %s", strerror(-ret));
		goto out;
	}
	ret = write_file(output, io.signature, io.signature_sz);
	if (ret) {
		pr_err("keys vouch: write %s: %s", output, strerror(-ret));
		goto out;
	}
	pr_info("keys vouch: %s vouched for by %s, written to %s", fp_hex,
		own_hex, output);
	printf("%s\n", fp_hex);
out:
	xfree(io.signature, VOUCH_SIG_MAX);
	xfree(payload, payload_sz);
	xfree(own, own_sz);
	xfree(der, der_sz);
	return ret ? 1 : 0;
}
