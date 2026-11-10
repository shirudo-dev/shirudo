// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * shirudo attest: TPM-signed evidence on a target; verify and predict
 * on the operator.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "builtin.h"
#include "util/attest.h"
#include "util/chain.h"
#include "util/crypto.h"
#include "util/config_measure.h"
#include "util/image_runtime.h"
#include "util/help.h"
#include "util/hex.h"
#include "util/io.h"
#include "util/json.h"
#include "util/keys.h"
#include "util/log.h"
#include "util/malloc.h"
#include "util/measured.h"
#include "util/paths.h"
#include "util/seal.h"
#include "util/upatch.h"

#define EVIDENCE_MAX		JSON_MAX_BYTES
#define EVENTS_MAX		256

static const struct help_item attest_subcmds[] = {
	{ "verify",    "check an evidence document against the expected state" },
	{ "predict",   "compute the register value a set of upatches yields" },
	{ "challenge", "make a credential challenge for a target's attestation key" },
};

static const struct help_item attest_options[] = {
	{ "--nonce=<hex>",      "freshness value from the verifier (up to 64 bytes)" },
	{ "--pcrs=<list>",      "PCRs to quote, comma separated (default 0-7,9,11-15)" },
	{ "--challenge=<path>", "a challenge from the verifier to activate while attesting" },
	{ "-o, --output <path>", "write the evidence there (0600) instead of stdout" },
};

static const struct help_item verify_options[] = {
	{ "--evidence=<path>",     "the document a target produced" },
	{ "--nonce=<hex>",         "the nonce that document was requested with" },
	{ "--ak-name=<hex>",       "the attestation key name pinned at enrollment" },
	{ "--cert=<cert.der>",     "a certificate the target enrols (repeatable)" },
	{ "--upatch=<file>",       "an installed artifact (repeatable)" },
	{ "--expect=<name>=<hex>", "an installed upatch by name and payload digest" },
	{ "--tree-root=<hex>",     "the upatch tree projection root at boot" },
	{ "--expect-chain=<hex>",  "the register value after the expected events" },
	{ "--expect-config-root=<hex>", "approved config image hash" },
	{ "--expect-config-pcr=<n>", "reserved config PCR number" },
	{ "--expect-pcr=<n>=<hex>", "a PCR value the quote must carry (repeatable)" },
	{ "--allow-runtime-events", "accept loads, unloads and revocations after boot" },
	{ "--json",             "print the checks and the verdict as JSON" },
	{ "--strict-anchor",       "require the anchoring PCR to hold only the anchor" },
	{ "--expect-credential=<hex>", "the credential the challenge given to the target carried" },
	{ "--ek-name=<hex>",       "the endorsement key name pinned at enrollment" },
	{ "--expect-bind-pcr=<n>=<hex>", "a PCR value the register was bound under (repeatable)" },
	{ "--require-initrd",      "fail unless init bound the register from the initrd" },
};

static const struct help_item challenge_options[] = {
	{ "--evidence=<path>",  "a document the target produced, carrying its keys" },
	{ "--ak-name=<hex>",    "the attestation key name the challenge is for" },
	{ "--ek-ca=<bundle>",   "PEM issuers the endorsement certificate must chain to" },
	{ "--ek-name=<hex>",    "an endorsement key name known out of band" },
	{ "--trust-presented-ek", "accept an endorsement key nothing vouches for" },
	{ "-o, --output <path>", "write the challenge there (0600)" },
};

static const struct help_item predict_options[] = {
	{ "--cert=<cert.der>",     "a certificate the target enrols (repeatable)" },
	{ "--upatch=<file>",       "an installed artifact (repeatable)" },
	{ "--expect=<name>=<hex>", "an installed upatch by name and payload digest" },
	{ "--tree-root=<hex>",     "the upatch tree projection root at boot" },
	{ "--event=<kind>:<name>=<hex>",
	  "a load, unload, tree:<seq> or revoke:<fingerprint> event after boot" },
	{ "--bind-pcr=<n>=<hex>",  "PCR 9 and 11 values at binding, for the register name" },
	{ "--json",             "print the values as JSON" },
	{ "--writer-public=<hex>", "init record's 384-byte RSA modulus (with --bind-pcr)" },
};

static const struct help_section attest_help_sections[] = {
	{ "subcommands:", attest_subcmds, ARRAY_SIZE(attest_subcmds) },
	{ "evidence options (target):", attest_options,
	  ARRAY_SIZE(attest_options) },
	{ "verify options (operator):", verify_options,
	  ARRAY_SIZE(verify_options) },
	{ "predict options (operator):", predict_options,
	  ARRAY_SIZE(predict_options) },
	{ "challenge options (operator):", challenge_options,
	  ARRAY_SIZE(challenge_options) },
};

static const struct help attest_help = {
	.usage      = "shirudo attest [--nonce=<hex>] [--pcrs=<list>] "
		      "[--challenge=<path>] [--output=<path>]\n"
		      "       shirudo attest verify --evidence=<path> --nonce=<hex> "
		      "--ak-name=<hex> [options]\n"
		      "       shirudo attest predict --cert=<cert.der> [options]\n"
		      "       shirudo attest challenge --evidence=<path> "
		      "--output=<path> --ek-ca=<bundle>|--ek-name=<hex>|"
		      "--trust-presented-ek [options]",
	.summary    = "Without a subcommand: emit a TPM-signed evidence document "
		      "for this\ntarget (quote over the PCRs, certification of "
		      "the measurement register,\nthis boot's eventlog, the "
		      "firmware and systemd measurement logs), activating\n"
		      "the verifier's challenge when given one.\n"
		      "verify, predict and challenge run on the operator and "
		      "touch no TPM.",
	.sections   = attest_help_sections,
	.n_sections = ARRAY_SIZE(attest_help_sections),
};

static int parse_hex32(const char *what, const char *hex, __u8 out[32])
{
	if (hex_decode(hex, out, 32)) {
		pr_err("attest: %s must be 64 hex characters", what);
		return -EINVAL;
	}
	return 0;
}

struct members {
	struct measured_upatch	*set;
	size_t				n;
};

static int member_add_file(struct members *m, const char *path)
{
	struct measured_upatch e;
	struct upatch u;
	int ret;

	ret = upatch_open(path, &u);
	if (ret) {
		pr_err("attest: open %s: %s", path, strerror(-ret));
		return ret;
	}
	measured_upatch_of(&e, &u);
	upatch_close(&u);
	ret = measured_set_add(m->set, &m->n, ATTEST_MEMBERS_MAX, e.name,
			       e.payload_hex);
	if (ret)
		pr_err("attest: --upatch %s: %s", path,
		       ret == -EEXIST ? "a second upatch of that name" :
		       strerror(-ret));
	return ret;
}

static int member_add_spec(struct members *m, const char *spec)
{
	char name[UPATCH_NAME_MAX + 1];
	char hex[2 * UPATCH_PAYLOAD_HASH_LEN + 1];
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN];
	int ret;

	ret = attest_parse_name_digest(spec, name, payload);
	if (!ret) {
		hex_encode(payload, sizeof(payload), hex);
		ret = measured_set_add(m->set, &m->n, ATTEST_MEMBERS_MAX, name,
				       hex);
	}
	if (ret)
		pr_err("attest: --expect '%s': %s", spec,
		       ret == -EEXIST ? "a second upatch of that name" :
		       ret == -EINVAL ? "not an upatch name and a digest" :
		       strerror(-ret));
	return ret;
}

/* What the init event counts of a certificate: the SHA-256 of its DER. */
static int cert_digest(const char *path, __u8 out[32])
{
	size_t len = 0;
	__u8 *der;
	int ret;

	ret = read_file(path, KEYS_DER_MAX, &der, &len);
	if (!ret) {
		ret = len ? sha256_calc(der, len, out) : -ENODATA;
		xfree(der, len + 1);
	}
	if (ret)
		pr_err("attest: --cert %s: %s", path, strerror(-ret));
	return ret;
}

static int apply_event(const char *spec, __u8 chain[32])
{
	const char *colon = strchr(spec, ':');
	char name[UPATCH_NAME_MAX + 1];
	__u8 digest[32], event[32];
	size_t kind_len;

	if (!colon || attest_parse_name_digest(colon + 1, name, digest))
		return -EINVAL;
	kind_len = (size_t)(colon - spec);
	if (kind_len == 4 && !strncmp(spec, "load", 4)) {
		if (chain_upatch_event("shirudo-upatch", name, digest, event))
			return -EIO;
	} else if (kind_len == 6 && !strncmp(spec, "unload", 6)) {
		if (chain_upatch_event("shirudo-unload", name, digest, event))
			return -EIO;
	} else if (kind_len == 4 && !strncmp(spec, "tree", 4)) {
		__s64 seq;

		if (parse_s64(name, strlen(name), 1, INT64_MAX, &seq))
			return -EINVAL;
		if (chain_tree_event(seq, digest, event))
			return -EIO;
	} else if (kind_len == 6 && !strncmp(spec, "revoke", 6)) {
		if (chain_key_event("shirudo-key-revoke", digest, event))
			return -EIO;
	} else {
		return -EINVAL;
	}
	return chain_fold(chain, event) ? -EIO : 0;
}

struct predict_out {
	bool		json;
	struct json_emit e;
};

static void predict_kv(struct predict_out *po, const char *key,
		       const char *value)
{
	if (po->json)
		json_kv_string(&po->e, key, value);
	else
		printf("%s: %s\n", key, value);
}

static int cmd_attest_predict(int argc, const char **argv)
{
	struct predict_out po = { .e = { .cap = 4096 } };
	char pcr_key[32];
	__u8 writer_public[TPM_NV_RSA_BYTES];
	__u8 cert_sha[32], tree_root[32] = {}, set_digest[32], init[32];
	__u8 cert_shas[KEYS_MAX][32];
	size_t n_certs = 0;
	__u8 bind[2][32], chain[32] = {};
	const char *events[EVENTS_MAX];
	struct members m = {};
	char hex[2 * TPM_NAME_LEN + 1];
	bool have_cert = false, have_writer = false, have_bind[2] = {};
	size_t n_events = 0, i;
	int ret = 2;

	m.set = xcalloc(ATTEST_MEMBERS_MAX, sizeof(*m.set));
	if (!m.set)
		return 1;
	for (i = 2; i < (size_t)argc; i++) {
		const char *a = argv[i];
		const char *v = NULL;
		enum opt_status r;

		if (opt_arg("--cert", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest predict: %s takes a value", a);
				goto out;
			}
			if (n_certs >= KEYS_MAX) {
				pr_err("attest predict: at most %d --cert",
				       KEYS_MAX);
				goto out;
			}
			if (cert_digest(v, cert_shas[n_certs]))
				goto out;
			n_certs++;
			have_cert = true;
		} else if (opt_arg("--upatch", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest predict: %s takes a value", a);
				goto out;
			}
			if (member_add_file(&m, v))
				goto out;
		} else if (opt_arg("--expect", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest predict: %s takes a value", a);
				goto out;
			}
			if (member_add_spec(&m, v))
				goto out;
		} else if (opt_arg("--tree-root", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest predict: %s takes a value", a);
				goto out;
			}
			if (parse_hex32("--tree-root", v, tree_root))
				goto out;
		} else if (opt_arg("--event", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest predict: %s takes a value", a);
				goto out;
			}
			if (n_events >= EVENTS_MAX)
				goto out;
			events[n_events++] = v;
		} else if (opt_arg("--writer-public", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest predict: %s takes a value", a);
				goto out;
			}
			if (hex_decode(v, writer_public, sizeof(writer_public))) {
				pr_err("attest predict: invalid RSA-3072 --writer-public");
				goto out;
			}
			have_writer = true;
		} else if (!strcmp(a, "--json")) {
			po.json = true;
		} else if (opt_arg("--bind-pcr", a, argc, argv, &i, &v, &r)) {
			const char *value = NULL;
			int slot = -1;
			__u64 n;

			if (r == OPT_MISSING) {
				pr_err("attest predict: %s takes a value", a);
				goto out;
			}
			if (!attest_parse_pcr_value(v, &n, &value))
				slot = n == CHAIN_PCR ? 0 :
				       n == CHAIN_PHASE_PCR ? 1 : -1;
			if (slot < 0 ||
			    parse_hex32("--bind-pcr value", value, bind[slot])) {
				pr_err("attest predict: --bind-pcr takes "
				       "%u=<hex> or %u=<hex>", CHAIN_PCR,
				       CHAIN_PHASE_PCR);
				goto out;
			}
			have_bind[slot] = true;
		} else if (is_help(a)) {
			print_help(&attest_help);
			ret = 0;
			goto out;
		} else {
			pr_err("attest predict: unknown option '%s'", a);
			goto out;
		}
	}
	if (!have_cert) {
		pr_err("attest predict: --cert is required");
		goto out;
	}
	if (po.json) {
		po.e.buf = xmalloc(po.e.cap);
		if (!po.e.buf) {
			ret = 1;
			goto out;
		}
		json_obj_open(&po.e);
		json_kv_int(&po.e, "schema", 1);
	}
	if (keys_anchor_digest(cert_shas, n_certs, cert_sha) ||
	    chain_init_event(cert_sha, m.set, m.n, tree_root, set_digest,
			     init)) {
		pr_err("attest predict: cannot hash the init event");
		goto out;
	}
	hex_encode(set_digest, 32, hex);
	predict_kv(&po, "set_digest", hex);
	hex_encode(init, 32, hex);
	predict_kv(&po, "init_event", hex);
	if (chain_fold(chain, init)) {
		pr_err("attest predict: cannot hash the register at boot");
		goto out;
	}
	hex_encode(chain, 32, hex);
	predict_kv(&po, "register_at_boot", hex);
	for (i = 0; i < n_events; i++) {
		if (apply_event(events[i], chain)) {
			pr_err("attest predict: bad --event '%s'", events[i]);
			goto out;
		}
	}
	if (n_events) {
		hex_encode(chain, 32, hex);
		predict_kv(&po, "register_after_events", hex);
	}
	if (have_bind[0] && have_bind[1]) {
		__u8 branch_written[32], branch_init[32], policy[32];
		__u8 name[TPM_NAME_LEN], anchor_digest[32];
		char anchor[CHAIN_ANCHOR_MAX];

		if (!have_writer) {
			pr_err("attest predict: --bind-pcr requires --writer-public");
			goto out;
		}
		if (tpm_register_policy(CHAIN_PCR_MASK, bind[0], 2,
					writer_public, branch_written, branch_init, policy)) {
			pr_err("attest predict: cannot compute the signed write policy");
			ret = 1;
			goto out;
		}
		if (tpm_nv_name(NV_INDEX, TPM_REGISTER_ATTRS | TPM_NV_WRITTEN,
				policy, 32, name)) {
			pr_err("attest predict: cannot compute the register name");
			ret = 1;
			goto out;
		}
		hex_encode(name, sizeof(name), hex);
		predict_kv(&po, "register_name", hex);
		if (chain_anchor(name, anchor, sizeof(anchor))) {
			pr_err("attest predict: the anchor does not fit");
			goto out;
		}
		predict_kv(&po, "anchor", anchor);
		if (sha256_calc(anchor, strlen(anchor), anchor_digest)) {
			pr_err("attest predict: cannot hash the anchor");
			goto out;
		}
		if (chain_fold(bind[0], anchor_digest)) {
			pr_err("attest predict: cannot hash PCR %u after the anchor",
			       CHAIN_PCR);
			goto out;
		}
		hex_encode(bind[0], 32, hex);
		if (strsprintf(pcr_key, sizeof(pcr_key), "pcr%u_after_anchor",
			       CHAIN_PCR) >= 0)
			predict_kv(&po, pcr_key, hex);
	} else if (have_bind[0] || have_bind[1] || have_writer) {
		pr_err("attest predict: --bind-pcr needs both %u and %u",
		       CHAIN_PCR, CHAIN_PHASE_PCR);
		goto out;
	}
	ret = 0;
	if (po.json) {
		json_obj_close(&po.e);
		if (po.e.err) {
			pr_err("attest predict: json encode failed");
			ret = 1;
		} else {
			puts(po.e.buf);
		}
	}
out:
	xfree(po.e.buf, po.e.cap);
	xfree(m.set, ATTEST_MEMBERS_MAX * sizeof(*m.set));
	return ret;
}

/*
 * The report is one check or note per line, OK, FAIL or NOTE then the
 * text, which the JSON form carries as an array of objects.
 */
static int report_emit_json(const char *report, const char *verdict)
{
	char *buf = xmalloc(ATTEST_REPORT_MAX * 2);
	struct json_emit e = { .buf = buf, .cap = ATTEST_REPORT_MAX * 2 };
	const char *line = report;
	int ret = 0;

	if (!buf)
		return 1;
	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_kv_string(&e, "verdict", verdict);
	json_arr_open(&e, "checks");
	while (*line) {
		const char *nl = strchr(line, '\n');
		size_t len = nl ? (size_t)(nl - line) : strlen(line);
		char text[ATTEST_REPORT_MAX];
		const char *kind = NULL;

		if (len > 8 && !strncmp(line, "  OK    ", 8))
			kind = "ok";
		else if (len > 8 && !strncmp(line, "  FAIL  ", 8))
			kind = "fail";
		else if (len > 8 && !strncmp(line, "  NOTE  ", 8))
			kind = "note";
		if (kind) {
			size_t n = min(len - 8, sizeof(text) - 1);

			memcpy(text, line + 8, n);
			text[n] = '\0';
			json_obj_open(&e);
			json_kv_string(&e, "result", kind);
			json_kv_string(&e, "text", text);
			json_obj_close(&e);
		}
		if (!nl)
			break;
		line = nl + 1;
	}
	json_arr_close(&e);
	json_obj_close(&e);
	if (e.err) {
		pr_err("attest: json encode failed");
		ret = 1;
	} else {
		puts(buf);
	}
	xfree(buf, ATTEST_REPORT_MAX * 2);
	return ret;
}

static int read_evidence(const char *path, char **out, size_t *len)
{
	int ret;

	ret = read_file(path, EVIDENCE_MAX, out, len);
	if (!ret && !*len) {
		xfree(*out, 1);
		*out = NULL;
		ret = -ENODATA;
	}
	if (ret)
		pr_err("attest: evidence %s: %s", path, strerror(-ret));
	return ret;
}

static int cmd_attest_verify(int argc, const char **argv)
{
	bool json = false;
	struct attest_expect x = {};
	__u8 nonce[ATTEST_NONCE_MAX], cert_sha[32], set_digest[32];
	__u8 cert_shas[KEYS_MAX][32];
	size_t n_certs = 0;
	__u8 tree_root[32] = {};
	const char *evidence_path = NULL;
	struct members m = {};
	char *evidence = NULL, *report;
	size_t evidence_len = 0, nonce_len = 0, i;
	bool have_cert = false, have_nonce = false, have_tree_root = false;
	int err, ret = 2;

	m.set = xcalloc(ATTEST_MEMBERS_MAX, sizeof(*m.set));
	report = xmalloc(ATTEST_REPORT_MAX);
	if (!m.set || !report)
		goto out;
	for (i = 2; i < (size_t)argc; i++) {
		const char *a = argv[i];
		const char *v = NULL;
		enum opt_status r;

		if (opt_arg("--evidence", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest verify: %s takes a value", a);
				ret = 2;
				goto out;
			}
			evidence_path = v;
		} else if (opt_arg("--nonce", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest verify: %s takes a value", a);
				ret = 2;
				goto out;
			}
			if (hex_decode_max(v, nonce, sizeof(nonce),
					   &nonce_len) || !nonce_len) {
				pr_err("attest verify: --nonce must be hex of "
				       "up to %d bytes",
				       ATTEST_NONCE_MAX);
				goto out;
			}
			have_nonce = true;
		} else if (opt_arg("--ak-name", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest verify: %s takes a value", a);
				ret = 2;
				goto out;
			}
			if (hex_decode(v, x.ak_name, TPM_NAME_LEN)) {
				pr_err("attest verify: --ak-name must be %d "
				       "hex characters",
				       2 * TPM_NAME_LEN);
				goto out;
			}
			x.have_ak_name = true;
		} else if (opt_arg("--cert", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest verify: %s takes a value", a);
				ret = 2;
				goto out;
			}
			if (n_certs >= KEYS_MAX) {
				pr_err("attest verify: at most %d --cert",
				       KEYS_MAX);
				goto out;
			}
			if (cert_digest(v, cert_shas[n_certs]))
				goto out;
			n_certs++;
			have_cert = true;
		} else if (opt_arg("--upatch", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest verify: %s takes a value", a);
				ret = 2;
				goto out;
			}
			if (member_add_file(&m, v))
				goto out;
		} else if (opt_arg("--expect", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest verify: %s takes a value", a);
				ret = 2;
				goto out;
			}
			if (member_add_spec(&m, v))
				goto out;
		} else if (opt_arg("--tree-root", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest verify: %s takes a value", a);
				ret = 2;
				goto out;
			}
			if (parse_hex32("--tree-root", v, tree_root))
				goto out;
			have_tree_root = true;
		} else if (opt_arg("--expect-config-root", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest verify: %s takes a value", a);
				ret = 2;
				goto out;
			}
			if (x.have_config_root ||
			    parse_hex32("--expect-config-root", v,
					x.config_root))
				goto out;
			x.have_config_root = true;
		} else if (opt_arg("--expect-config-pcr", a, argc, argv, &i, &v, &r)) {
			__u64 pcr;

			if (r == OPT_MISSING) {
				pr_err("attest verify: %s takes a value", a);
				ret = 2;
				goto out;
			}
			if (parse_u64(v, strlen(v), 15, &pcr) ||
			    x.have_config_pcr ||
			    config_measure_pcr_valid(pcr))
				goto out;
			x.config_pcr = pcr;
			x.have_config_pcr = true;
		} else if (opt_arg("--expect-chain", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest verify: %s takes a value", a);
				ret = 2;
				goto out;
			}
			if (parse_hex32("--expect-chain", v, x.chain))
				goto out;
			x.have_chain = true;
		} else if (opt_arg("--expect-pcr", a, argc, argv, &i, &v, &r)) {
			const char *value;
			__u64 n;

			if (r == OPT_MISSING) {
				pr_err("attest verify: %s takes a value", a);
				ret = 2;
				goto out;
			}
			if (attest_parse_pcr_value(v, &n, &value) ||
			    parse_hex32("--expect-pcr value", value, x.pcrs[n]))
				goto out;
			x.pcr_expect_mask |= 1u << n;
		} else if (!strcmp(a, "--json")) {
			json = true;
		} else if (!strcmp(a, "--allow-runtime-events")) {
			x.allow_runtime_events = true;
		} else if (!strcmp(a, "--strict-anchor")) {
			x.strict_anchor = true;
		} else if (opt_arg("--expect-credential", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest verify: %s takes a value", a);
				ret = 2;
				goto out;
			}
			if (parse_hex32("--expect-credential", v,
					x.credential))
				goto out;
			x.have_credential = true;
		} else if (opt_arg("--ek-name", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest verify: %s takes a value", a);
				ret = 2;
				goto out;
			}
			if (hex_decode(v, x.ek_name, TPM_NAME_LEN)) {
				pr_err("attest verify: --ek-name must be %d "
				       "hex characters",
				       2 * TPM_NAME_LEN);
				goto out;
			}
			x.have_ek_name = true;
		} else if (opt_arg("--expect-bind-pcr", a, argc, argv, &i, &v, &r)) {
			const char *value;
			__u64 n;

			if (r == OPT_MISSING) {
				pr_err("attest verify: %s takes a value", a);
				ret = 2;
				goto out;
			}
			if (attest_parse_pcr_value(v, &n, &value) ||
			    parse_hex32("--expect-bind-pcr value", value,
					x.bind_values[n]))
				goto out;
			x.bind_expect_mask |= 1u << n;
		} else if (!strcmp(a, "--require-initrd")) {
			x.require_initrd = true;
		} else if (is_help(a)) {
			print_help(&attest_help);
			ret = 0;
			goto out;
		} else {
			pr_err("attest verify: unknown option '%s'", a);
			goto out;
		}
	}
	if (x.have_config_root && !x.have_config_pcr) {
		pr_err("attest verify: --expect-config-root requires "
		       "--expect-config-pcr");
		goto out;
	}
	if (!evidence_path || !have_nonce) {
		pr_err("attest verify: --evidence and --nonce are required");
		goto out;
	}
	if (!have_cert && (m.n || have_tree_root)) {
		pr_err("attest verify: --upatch, --expect and --tree-root "
		       "describe the init event and need --cert");
		goto out;
	}
	/*
	 * The credential proves that the pinned attestation key sits beside
	 * the endorsement key; recovered on the target, its value says
	 * nothing about which key signed the evidence.
	 */
	if (x.have_credential && !x.have_ak_name) {
		pr_err("attest verify: --expect-credential needs the key the "
		       "challenge was made for; give --ak-name");
		goto out;
	}
	if (!x.have_ak_name)
		pr_warn("attest verify: no --ak-name; the signer is not "
			"pinned");
	x.nonce = nonce;
	x.nonce_len = nonce_len;
	if (have_cert) {
		if (keys_anchor_digest(cert_shas, n_certs, cert_sha) ||
		    chain_init_event(cert_sha, m.set, m.n, tree_root,
				     set_digest, x.init_event)) {
			pr_err("attest verify: cannot hash the init event");
			goto out;
		}
		x.have_init = true;
	}
	if (read_evidence(evidence_path, &evidence, &evidence_len))
		goto out;
	err = attest_verify(evidence, evidence_len, &x, report,
			    ATTEST_REPORT_MAX);
	if (err == -EINVAL) {
		if (!json)
			fputs(report, stdout);
		pr_err("attest verify: %s is not a shirudo evidence document",
		       evidence_path);
		ret = 2;
	} else if (json) {
		ret = report_emit_json(report, err ? "fail" : "ok");
		if (!ret && err)
			ret = 1;
	} else {
		fputs(report, stdout);
		printf("verdict: %s\n", err ? "fail" : "ok");
		ret = err ? 1 : 0;
	}
out:
	xfree(evidence, evidence ? evidence_len + 1 : 0);
	xfree(report, report ? ATTEST_REPORT_MAX : 0);
	xfree(m.set, m.set ? ATTEST_MEMBERS_MAX * sizeof(*m.set) : 0);
	memzero_explicit(&x, sizeof(x));
	return ret;
}

static int cmd_attest_challenge(int argc, const char **argv)
{
	struct attest_challenge_policy pol = {};
	__u8 credential[TPM_CREDENTIAL_LEN];
	__u8 ak_name[TPM_NAME_LEN], ek_name[TPM_NAME_LEN];
	const char *evidence_path = NULL, *out_path = NULL;
	char *evidence = NULL, *doc = NULL, *report;
	char hex[2 * TPM_CREDENTIAL_LEN + 1];
	size_t evidence_len = 0, len = 0, cap = 0, i;
	int err, ret = 2;

	report = xmalloc(ATTEST_REPORT_MAX);
	if (!report)
		return 1;
	for (i = 2; i < (size_t)argc; i++) {
		const char *a = argv[i];
		const char *v = NULL;
		enum opt_status r;

		if (!strcmp(a, "-o"))
			a = "--output";

		if (opt_arg("--evidence", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest challenge: %s takes a value", a);
				ret = 2;
				goto out;
			}
			evidence_path = v;
		} else if (opt_arg("--ek-ca", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest challenge: %s takes a value", a);
				ret = 2;
				goto out;
			}
			pol.ek_ca = v;
		} else if (opt_arg("--ak-name", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest challenge: %s takes a value", a);
				ret = 2;
				goto out;
			}
			if (hex_decode(v, ak_name, TPM_NAME_LEN)) {
				pr_err("attest challenge: --ak-name must be %d "
				       "hex characters", 2 * TPM_NAME_LEN);
				goto out;
			}
			pol.ak_name = ak_name;
		} else if (opt_arg("--ek-name", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest challenge: %s takes a value", a);
				ret = 2;
				goto out;
			}
			if (hex_decode(v, ek_name, TPM_NAME_LEN)) {
				pr_err("attest challenge: --ek-name must be %d "
				       "hex characters", 2 * TPM_NAME_LEN);
				goto out;
			}
			pol.ek_name = ek_name;
		} else if (!strcmp(a, "--trust-presented-ek")) {
			pol.trust_presented = true;
		} else if (opt_arg("--output", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest challenge: %s takes a value", a);
				ret = 2;
				goto out;
			}
			out_path = v;
		} else if (is_help(a)) {
			print_help(&attest_help);
			ret = 0;
			goto out;
		} else {
			pr_err("attest challenge: unknown option '%s'", a);
			goto out;
		}
	}
	if (!evidence_path || !out_path) {
		pr_err("attest challenge: --evidence and --output are required");
		goto out;
	}
	if (read_evidence(evidence_path, &evidence, &evidence_len))
		goto out;
	err = attest_challenge_make(evidence, evidence_len, &pol,
				    credential, &doc, &len, &cap, report,
				    ATTEST_REPORT_MAX);
	fputs(report, stdout);
	if (err == -EINVAL) {
		pr_err("attest challenge: %s carries no endorsement key",
		       evidence_path);
		goto out;
	}
	if (err) {
		printf("verdict: fail\n");
		ret = 1;
		goto out;
	}
	{
		struct seal_output out;

		err = seal_output_create(&out, out_path, 0600);
		if (err) {
			pr_err("attest challenge: open %s: %s", out_path,
			       strerror(-err));
			ret = 1;
			goto out;
		}
		err = seal_output_commit(&out, doc, len);
		if (err) {
			pr_err("attest challenge: write %s: %s", out_path,
			       strerror(-err));
			ret = 1;
			goto out;
		}
	}
	hex_encode(credential, sizeof(credential), hex);
	printf("challenge: %s\ncredential: %s\n", out_path, hex);
	ret = 0;
out:
	memzero_explicit(credential, sizeof(credential));
	xfree(doc, cap);
	xfree(evidence, evidence ? evidence_len + 1 : 0);
	xfree(report, ATTEST_REPORT_MAX);
	return ret;
}

static int cmd_attest_evidence(int argc, const char **argv)
{
	const struct attest_challenge *request;
	struct attest_challenge challenge = {};
	__u8 nonce[ATTEST_NONCE_MAX];
	__u32 mask = ATTEST_PCR_DEFAULT;
	const char *out_path = NULL, *challenge_path = NULL;
	char *doc = NULL;
	size_t nonce_len = 0, len = 0, cap = 0, i;
	int ret;

	for (i = 1; i < (size_t)argc; i++) {
		const char *a = argv[i];
		const char *v = NULL;
		enum opt_status r;

		if (!strcmp(a, "-o"))
			a = "--output";

		if (opt_arg("--challenge", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest: %s takes a value", a);
				return 2;
			}
			challenge_path = v;
		} else if (opt_arg("--nonce", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest: %s takes a value", a);
				return 2;
			}
			if (hex_decode_max(v, nonce, sizeof(nonce),
					   &nonce_len) || !nonce_len) {
				pr_err("attest: --nonce must be hex of up to "
				       "%d bytes", ATTEST_NONCE_MAX);
				return 2;
			}
		} else if (opt_arg("--pcrs", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest: %s takes a value", a);
				return 2;
			}
			if (attest_parse_pcrs(v, &mask)) {
				pr_err("attest: --pcrs takes a comma separated "
				       "list of 0..23");
				return 2;
			}
		} else if (opt_arg("--output", a, argc, argv, &i, &v, &r)) {
			if (r == OPT_MISSING) {
				pr_err("attest: %s takes a value", a);
				return 2;
			}
			out_path = v;
		} else if (is_help(a)) {
			print_help(&attest_help);
			return 0;
		} else {
			pr_err("attest: unknown option '%s'", a);
			return 2;
		}
	}
	if (!nonce_len)
		pr_warn("attest: no --nonce; the evidence proves no freshness");
	if (challenge_path &&
	    attest_challenge_read(challenge_path, &challenge)) {
		pr_err("attest: %s is not a shirudo credential challenge",
		       challenge_path);
		return 2;
	}

	request = challenge_path ? &challenge : NULL;
	ret = attest_evidence_config(nonce, nonce_len, mask, request,
				     image_update_context(),
				     &doc, &len, &cap);
	if (ret == -ENXIO) {
		pr_err("attest: no TPM answered (tpm_error)");
		return 1;
	}
	if (ret == -ENODEV) {
		pr_err("attest: register 0x%08X is not bound this boot "
		       "(tpm_error); run shirudo init first",
		       NV_INDEX);
		return 1;
	}
	if (ret == -EKEYREJECTED) {
		pr_err("attest: the TPM refused the challenge; the attestation key or the endorsement key is not this TPM's");
		return 1;
	}
	if (ret) {
		pr_err("attest: evidence failed: %s", strerror(-ret));
		return 1;
	}
	if (out_path) {
		struct seal_output out;

		ret = seal_output_create(&out, out_path, 0600);
		if (ret) {
			pr_err("attest: open %s: %s", out_path, strerror(-ret));
		} else {
			ret = seal_output_commit(&out, doc, len);
			if (ret)
				pr_err("attest: write %s: %s", out_path,
				       strerror(-ret));
		}
	} else if (fwrite(doc, 1, len, stdout) != len ||
		   fputc('\n', stdout) == EOF) {
		ret = -EIO;
	}
	xfree(doc, cap);
	return ret ? 1 : 0;
}

int cmd_attest(int argc, const char **argv)
{
	if (argc >= 2 && is_help(argv[1])) {
		print_help(&attest_help);
		return 0;
	}
	if (argc >= 2 && is_list_cmds(argv[1])) {
		print_subcmd_list(attest_subcmds,
				  ARRAY_SIZE(attest_subcmds));
		return 0;
	}
	if (argc >= 2 && argv[1][0] != '-') {
		const char *sub;

		sub = resolve_subcommand("attest", argv[1],
					 attest_subcmds,
					 ARRAY_SIZE(attest_subcmds));

		if (!sub)
			return 2;
		if (!strcmp(sub, "verify"))
			return cmd_attest_verify(argc, argv);
		if (!strcmp(sub, "challenge"))
			return cmd_attest_challenge(argc, argv);
		return cmd_attest_predict(argc, argv);
	}
	return cmd_attest_evidence(argc, argv);
}
