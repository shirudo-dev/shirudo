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
#include <shirudo/tpm.h>
#include <shirudo/string.h>

#include "builtin.h"
#include "util/attest.h"
#include "util/chain.h"
#include "util/crypto.h"
#include "util/config_measure.h"
#include "util/eventlog.h"
#include "util/image_runtime.h"
#include "util/help.h"
#include "util/hex.h"
#include "util/io.h"
#include "util/json.h"
#include "util/keys.h"
#include "util/log.h"
#include "util/malloc.h"
#include "util/measured.h"
#include "util/options.h"
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

enum evidence_opt {
	EVIDENCE_NONCE,
	EVIDENCE_PCRS,
	EVIDENCE_CHALLENGE,
	EVIDENCE_OUTPUT,
};

static const struct opt_spec evidence_opts[] = {
	[EVIDENCE_NONCE] = { "--nonce", 0, 0, "<hex>",
		"freshness value from the verifier (up to 64 bytes)" },
	[EVIDENCE_PCRS] = { "--pcrs", 0, 0, "<list>",
		"PCRs to quote, comma separated (default 0-7,9,11-15)" },
	[EVIDENCE_CHALLENGE] = { "--challenge", 0, 0, "<path>",
		"a challenge from the verifier to activate while attesting" },
	[EVIDENCE_OUTPUT] = { "--output", 'o', 0, "<path>",
		"write the evidence there (0600) instead of stdout" },
};

enum verify_opt {
	VERIFY_EVIDENCE,
	VERIFY_NONCE,
	VERIFY_AK_NAME,
	VERIFY_CERT,
	VERIFY_UPATCH,
	VERIFY_EXPECT,
	VERIFY_TREE_ROOT,
	VERIFY_EXPECT_CHAIN,
	VERIFY_EXPECT_CONFIG_ROOT,
	VERIFY_EXPECT_CONFIG_PCR,
	VERIFY_EXPECT_CONFIG_NVPCR,
	VERIFY_EXPECT_PCR,
	VERIFY_ALLOW_RUNTIME_EVENTS,
	VERIFY_JSON,
	VERIFY_STRICT_ANCHOR,
	VERIFY_EXPECT_CREDENTIAL,
	VERIFY_EK_NAME,
	VERIFY_EXPECT_BIND_PCR,
	VERIFY_REQUIRE_INITRD,
};

static const struct opt_spec verify_opts[] = {
	[VERIFY_EVIDENCE] = { "--evidence", 0, 0, "<path>",
		"the document a target produced" },
	[VERIFY_NONCE] = { "--nonce", 0, 0, "<hex>",
		"the nonce that document was requested with" },
	[VERIFY_AK_NAME] = { "--ak-name", 0, 0, "<hex>",
		"the attestation key name pinned at enrollment" },
	[VERIFY_CERT] = { "--cert", 0, OPT_REPEAT, "<cert.der>",
		"a certificate the target enrols (repeatable)" },
	[VERIFY_UPATCH] = { "--upatch", 0, OPT_REPEAT, "<file>",
		"an installed artifact (repeatable)" },
	[VERIFY_EXPECT] = { "--expect", 0, OPT_REPEAT, "[java:]<name>=<hex>",
		"an installed upatch by name and payload digest" },
	[VERIFY_TREE_ROOT] = { "--tree-root", 0, 0, "<hex>",
		"the upatch tree projection root at boot" },
	[VERIFY_EXPECT_CHAIN] = { "--expect-chain", 0, 0, "<hex>",
		"the register value after the expected events" },
	[VERIFY_EXPECT_CONFIG_ROOT] = { "--expect-config-root", 0, 0, "<hex>",
		"approved config image hash" },
	[VERIFY_EXPECT_CONFIG_PCR] = { "--expect-config-pcr", 0, 0, "<n>",
		"reserved config PCR number" },
	[VERIFY_EXPECT_CONFIG_NVPCR] = { "--expect-config-nvpcr", 0, 0, "<name>",
		"the config NvPCR's TPM name" },
	[VERIFY_EXPECT_PCR] = { "--expect-pcr", 0, OPT_REPEAT, "<n>=<hex>",
		"a PCR value the quote must carry (repeatable)" },
	[VERIFY_ALLOW_RUNTIME_EVENTS] = { "--allow-runtime-events", 0, 0, NULL,
		"accept loads, unloads and revocations after boot" },
	[VERIFY_JSON] = { "--json", 0, 0, NULL,
		"print the checks and the verdict as JSON" },
	[VERIFY_STRICT_ANCHOR] = { "--strict-anchor", 0, 0, NULL,
		"require the anchoring PCR to hold only the anchor" },
	[VERIFY_EXPECT_CREDENTIAL] = { "--expect-credential", 0, 0, "<hex>",
		"the credential the challenge given to the target carried" },
	[VERIFY_EK_NAME] = { "--ek-name", 0, 0, "<hex>",
		"the endorsement key name pinned at enrollment" },
	[VERIFY_EXPECT_BIND_PCR] = { "--expect-bind-pcr", 0, OPT_REPEAT, "<n>=<hex>",
		"a PCR value the register was bound under (repeatable)" },
	[VERIFY_REQUIRE_INITRD] = { "--require-initrd", 0, 0, NULL,
		"fail unless init bound the register from the initrd" },
};

enum challenge_opt {
	CHALLENGE_EVIDENCE,
	CHALLENGE_AK_NAME,
	CHALLENGE_EK_CA,
	CHALLENGE_EK_NAME,
	CHALLENGE_TRUST_PRESENTED_EK,
	CHALLENGE_OUTPUT,
};

static const struct opt_spec challenge_opts[] = {
	[CHALLENGE_EVIDENCE] = { "--evidence", 0, 0, "<path>",
		"a document the target produced, carrying its keys" },
	[CHALLENGE_AK_NAME] = { "--ak-name", 0, 0, "<hex>",
		"the attestation key name the challenge is for" },
	[CHALLENGE_EK_CA] = { "--ek-ca", 0, 0, "<bundle>",
		"PEM issuers the endorsement certificate must chain to" },
	[CHALLENGE_EK_NAME] = { "--ek-name", 0, 0, "<hex>",
		"an endorsement key name known out of band" },
	[CHALLENGE_TRUST_PRESENTED_EK] = { "--trust-presented-ek", 0, 0, NULL,
		"accept an endorsement key nothing vouches for" },
	[CHALLENGE_OUTPUT] = { "--output", 'o', 0, "<path>",
		"write the challenge there (0600)" },
};

enum predict_opt {
	PREDICT_CERT,
	PREDICT_UPATCH,
	PREDICT_EXPECT,
	PREDICT_TREE_ROOT,
	PREDICT_EVENT,
	PREDICT_BIND_PCR,
	PREDICT_JSON,
	PREDICT_WRITER_PUBLIC,
};

static const struct opt_spec predict_opts[] = {
	[PREDICT_CERT] = { "--cert", 0, OPT_REPEAT, "<cert.der>",
		"a certificate the target enrols (repeatable)" },
	[PREDICT_UPATCH] = { "--upatch", 0, OPT_REPEAT, "<file>",
		"an installed artifact (repeatable)" },
	[PREDICT_EXPECT] = { "--expect", 0, OPT_REPEAT, "[java:]<name>=<hex>",
		"an installed upatch by name and payload digest" },
	[PREDICT_TREE_ROOT] = { "--tree-root", 0, 0, "<hex>",
		"the upatch tree projection root at boot" },
	[PREDICT_EVENT] = { "--event", 0, OPT_REPEAT, "<kind>:<name>=<hex>",
		"a load, unload, java-load, java-unload, tree:<seq> or "
		"revoke:<fingerprint> event after boot" },
	[PREDICT_BIND_PCR] = { "--bind-pcr", 0, OPT_REPEAT, "<n>=<hex>",
		"PCR 9 and 11 values at binding, for the register name" },
	[PREDICT_JSON] = { "--json", 0, 0, NULL,
		"print the values as JSON" },
	[PREDICT_WRITER_PUBLIC] = { "--writer-public", 0, 0, "<hex>",
		"init record's 384-byte RSA modulus (with --bind-pcr)" },
};

static const struct help_section attest_help_sections[] = {
	HELP_ITEMS("subcommands:", attest_subcmds),
	HELP_OPTIONS("evidence options (target):", evidence_opts),
	HELP_OPTIONS("verify options (operator):", verify_opts),
	HELP_OPTIONS("predict options (operator):", predict_opts),
	HELP_OPTIONS("challenge options (operator):", challenge_opts),
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
			       e.payload_hex, e.type);
	if (ret)
		pr_err("attest: --upatch %s: %s", path,
		       ret == -EEXIST ? "a second upatch of that name" :
		       strerror(-ret));
	return ret;
}

/* name=<hex> for a BPF upatch, java:name=<hex> for a Java one. */
static int member_add_spec(struct members *m, const char *spec)
{
	char hex[2 * UPATCH_PAYLOAD_HASH_LEN + 1];
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN];
	char name[UPATCH_NAME_MAX + 1];
	const char *rest = spec;
	bool java;
	int ret;

	java = str_skip_prefix(&rest, "java:");
	ret = attest_parse_name_digest(rest, name, payload);
	if (!ret) {
		hex_encode(payload, sizeof(payload), hex);
		ret = measured_set_add(m->set, &m->n, ATTEST_MEMBERS_MAX, name,
				       hex, java ? UPATCH_TYPE_JAVA :
				       UPATCH_TYPE_BPF);
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
		ret = len ? sha256_buffer(der, len, out) : -ENODATA;
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
	__u32 type;
	bool load;

	if (!colon || attest_parse_name_digest(colon + 1, name, digest))
		return -EINVAL;
	kind_len = (size_t)(colon - spec);
	if (eventlog_upatch_kind_parse(spec, kind_len, &type, &load)) {
		if (chain_upatch_event(chain_upatch_tag(type, load), name,
				       digest, event))
			return -EIO;
	} else if (span_equals(spec, kind_len, "tree")) {
		__s64 seq;

		if (parse_s64(name, strlen(name), 1, INT64_MAX, &seq))
			return -EINVAL;
		if (chain_tree_event(seq, digest, event))
			return -EIO;
	} else if (span_equals(spec, kind_len, "revoke")) {
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
	int ret = EXIT_USAGE, opt;
	struct opt_parser p;

	m.set = xcalloc(ATTEST_MEMBERS_MAX, sizeof(*m.set));
	if (!m.set)
		return 1;
	OPT_INIT(&p, "attest predict", predict_opts, &attest_help, argc, argv, 2);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case PREDICT_CERT:
			if (n_certs >= KEYS_MAX) {
				opt_usage(&p, "at most %d --cert", KEYS_MAX);
				goto out;
			}
			if (cert_digest(p.value, cert_shas[n_certs]))
				goto out;
			n_certs++;
			have_cert = true;
			break;
		case PREDICT_UPATCH:
			if (member_add_file(&m, p.value))
				goto out;
			break;
		case PREDICT_EXPECT:
			if (member_add_spec(&m, p.value))
				goto out;
			break;
		case PREDICT_TREE_ROOT:
			if (parse_hex32("--tree-root", p.value, tree_root))
				goto out;
			break;
		case PREDICT_EVENT:
			if (n_events >= EVENTS_MAX) {
				opt_usage(&p, "at most %d --event", EVENTS_MAX);
				goto out;
			}
			events[n_events++] = p.value;
			break;
		case PREDICT_WRITER_PUBLIC:
			if (hex_decode(p.value, writer_public,
				       sizeof(writer_public))) {
				opt_usage(&p, "invalid RSA-3072 --writer-public");
				goto out;
			}
			have_writer = true;
			break;
		case PREDICT_JSON:
			po.json = true;
			break;
		case PREDICT_BIND_PCR: {
			const char *value = NULL;
			int slot = -1;
			__u64 n;

			if (!attest_parse_pcr_value(p.value, &n, &value))
				slot = n == CHAIN_PCR ? 0 :
				       n == CHAIN_PHASE_PCR ? 1 : -1;
			if (slot < 0 ||
			    parse_hex32("--bind-pcr value", value, bind[slot])) {
				opt_usage(&p, "--bind-pcr takes %u=<hex> or %u=<hex>",
					  CHAIN_PCR, CHAIN_PHASE_PCR);
				goto out;
			}
			if (have_bind[slot]) {
				opt_usage(&p, "--bind-pcr %llu given twice", n);
				goto out;
			}
			have_bind[slot] = true;
			break;
		}
		case OPT_ARG:
			opt_usage(&p, "unexpected argument '%s'", p.value);
			goto out;
		case OPT_DONE:
			ret = 0;
			goto out;
		default:
			goto out;
		}
	}
	if (!have_cert) {
		opt_usage(&p, "--cert is required");
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
		if (sha256_buffer(anchor, strlen(anchor), anchor_digest)) {
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
		const char *kind = NULL, *rest = line;
		size_t mark;

		if (str_skip_prefix(&rest, "  OK    "))
			kind = "ok";
		else if (str_skip_prefix(&rest, "  FAIL  "))
			kind = "fail";
		else if (str_skip_prefix(&rest, "  NOTE  "))
			kind = "note";
		mark = (size_t)(rest - line);
		if (kind && len > mark) {
			size_t n = min(len - mark, sizeof(text) - 1);

			memcpy(text, rest, n);
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
	size_t evidence_len = 0, nonce_len = 0;
	struct opt_parser p;
	bool have_cert = false, have_nonce = false, have_tree_root = false;
	int err, ret = EXIT_USAGE, opt;

	m.set = xcalloc(ATTEST_MEMBERS_MAX, sizeof(*m.set));
	report = xmalloc(ATTEST_REPORT_MAX);
	if (!m.set || !report)
		goto out;
	OPT_INIT(&p, "attest verify", verify_opts, &attest_help, argc, argv, 2);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case VERIFY_EVIDENCE:
			evidence_path = p.value;
			break;
		case VERIFY_NONCE:
			if (hex_decode_max(p.value, nonce, sizeof(nonce),
					   &nonce_len) || !nonce_len) {
				opt_usage(&p, "--nonce must be hex of up to %d bytes",
					  ATTEST_NONCE_MAX);
				goto out;
			}
			have_nonce = true;
			break;
		case VERIFY_AK_NAME:
			if (hex_decode(p.value, x.ak_name, TPM_NAME_LEN)) {
				opt_usage(&p, "--ak-name must be %d hex characters",
					  2 * TPM_NAME_LEN);
				goto out;
			}
			x.have_ak_name = true;
			break;
		case VERIFY_CERT:
			if (n_certs >= KEYS_MAX) {
				opt_usage(&p, "at most %d --cert", KEYS_MAX);
				goto out;
			}
			if (cert_digest(p.value, cert_shas[n_certs]))
				goto out;
			n_certs++;
			have_cert = true;
			break;
		case VERIFY_UPATCH:
			if (member_add_file(&m, p.value))
				goto out;
			break;
		case VERIFY_EXPECT:
			if (member_add_spec(&m, p.value))
				goto out;
			break;
		case VERIFY_TREE_ROOT:
			if (parse_hex32("--tree-root", p.value, tree_root))
				goto out;
			have_tree_root = true;
			break;
		case VERIFY_EXPECT_CONFIG_ROOT:
			if (parse_hex32("--expect-config-root", p.value,
					x.config_root))
				goto out;
			x.have_config_root = true;
			break;
		case VERIFY_EXPECT_CONFIG_PCR: {
			__u64 pcr;

			if (opt_u64(&p, 0, 15, &pcr))
				goto out;
			if (config_measure_pcr_valid(pcr)) {
				opt_usage(&p, "--expect-config-pcr cannot be 9 or 11");
				goto out;
			}
			x.config_pcr = pcr;
			x.have_config_pcr = true;
			break;
		}
		case VERIFY_EXPECT_CONFIG_NVPCR:
			if (hex_decode(p.value, x.config_nvpcr_name, 34)) {
				opt_usage(&p, "--expect-config-nvpcr must be 68 hex characters");
				goto out;
			}
			x.config_pcr = TPM_CONFIG_NVPCR_INDEX;
			x.have_config_pcr = true;
			x.have_config_nvpcr_name = true;
			break;
		case VERIFY_EXPECT_CHAIN:
			if (parse_hex32("--expect-chain", p.value, x.chain))
				goto out;
			x.have_chain = true;
			break;
		case VERIFY_EXPECT_PCR: {
			const char *value;
			__u64 n;

			if (attest_parse_pcr_value(p.value, &n, &value) ||
			    parse_hex32("--expect-pcr value", value, x.pcrs[n]))
				goto out;
			if (x.pcr_expect_mask & (1u << n)) {
				opt_usage(&p, "--expect-pcr %llu given twice", n);
				goto out;
			}
			x.pcr_expect_mask |= 1u << n;
			break;
		}
		case VERIFY_JSON:
			json = true;
			break;
		case VERIFY_ALLOW_RUNTIME_EVENTS:
			x.allow_runtime_events = true;
			break;
		case VERIFY_STRICT_ANCHOR:
			x.strict_anchor = true;
			break;
		case VERIFY_EXPECT_CREDENTIAL:
			if (parse_hex32("--expect-credential", p.value,
					x.credential))
				goto out;
			x.have_credential = true;
			break;
		case VERIFY_EK_NAME:
			if (hex_decode(p.value, x.ek_name, TPM_NAME_LEN)) {
				opt_usage(&p, "--ek-name must be %d hex characters",
					  2 * TPM_NAME_LEN);
				goto out;
			}
			x.have_ek_name = true;
			break;
		case VERIFY_EXPECT_BIND_PCR: {
			const char *value;
			__u64 n;

			if (attest_parse_pcr_value(p.value, &n, &value) ||
			    parse_hex32("--expect-bind-pcr value", value,
					x.bind_values[n]))
				goto out;
			if (x.bind_expect_mask & (1u << n)) {
				opt_usage(&p, "--expect-bind-pcr %llu given twice", n);
				goto out;
			}
			x.bind_expect_mask |= 1u << n;
			break;
		}
		case VERIFY_REQUIRE_INITRD:
			x.require_initrd = true;
			break;
		case OPT_ARG:
			opt_usage(&p, "unexpected argument '%s'", p.value);
			goto out;
		case OPT_DONE:
			ret = 0;
			goto out;
		default:
			goto out;
		}
	}
	if (opt_given(&p, VERIFY_EXPECT_CONFIG_PCR) &&
	    opt_given(&p, VERIFY_EXPECT_CONFIG_NVPCR)) {
		opt_usage(&p, "--expect-config-pcr and --expect-config-nvpcr "
			  "exclude each other");
		goto out;
	}
	if (x.have_config_root && !x.have_config_pcr) {
		opt_usage(&p, "--expect-config-root requires --expect-config-pcr "
			  "or --expect-config-nvpcr");
		goto out;
	}
	if (!evidence_path || !have_nonce) {
		opt_usage(&p, "--evidence and --nonce are required");
		goto out;
	}
	if (!have_cert && (m.n || have_tree_root)) {
		opt_usage(&p, "--upatch, --expect and --tree-root describe the init event and need --cert");
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
	size_t evidence_len = 0, len = 0, cap = 0;
	int err, ret = EXIT_USAGE, opt;
	struct opt_parser p;

	report = xmalloc(ATTEST_REPORT_MAX);
	if (!report)
		return 1;
	OPT_INIT(&p, "attest challenge", challenge_opts, &attest_help, argc, argv, 2);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case CHALLENGE_EVIDENCE:
			evidence_path = p.value;
			break;
		case CHALLENGE_EK_CA:
			pol.ek_ca = p.value;
			break;
		case CHALLENGE_AK_NAME:
			if (hex_decode(p.value, ak_name, TPM_NAME_LEN)) {
				opt_usage(&p, "--ak-name must be %d hex characters",
					  2 * TPM_NAME_LEN);
				goto out;
			}
			pol.ak_name = ak_name;
			break;
		case CHALLENGE_EK_NAME:
			if (hex_decode(p.value, ek_name, TPM_NAME_LEN)) {
				opt_usage(&p, "--ek-name must be %d hex characters",
					  2 * TPM_NAME_LEN);
				goto out;
			}
			pol.ek_name = ek_name;
			break;
		case CHALLENGE_TRUST_PRESENTED_EK:
			pol.trust_presented = true;
			break;
		case CHALLENGE_OUTPUT:
			out_path = p.value;
			break;
		case OPT_ARG:
			opt_usage(&p, "unexpected argument '%s'", p.value);
			goto out;
		case OPT_DONE:
			ret = 0;
			goto out;
		default:
			goto out;
		}
	}
	if (!evidence_path || !out_path) {
		opt_usage(&p, "--evidence and --output are required");
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
	size_t nonce_len = 0, len = 0, cap = 0;
	struct opt_parser p;
	int ret, opt;

	OPT_INIT(&p, "attest", evidence_opts, &attest_help, argc, argv, 1);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case EVIDENCE_CHALLENGE:
			challenge_path = p.value;
			break;
		case EVIDENCE_NONCE:
			if (hex_decode_max(p.value, nonce, sizeof(nonce),
					   &nonce_len) || !nonce_len) {
				opt_usage(&p, "--nonce must be hex of up to %d bytes",
					  ATTEST_NONCE_MAX);
				return EXIT_USAGE;
			}
			break;
		case EVIDENCE_PCRS:
			if (attest_parse_pcrs(p.value, &mask)) {
				opt_usage(&p, "--pcrs takes a comma separated list of 0..23");
				return EXIT_USAGE;
			}
			break;
		case EVIDENCE_OUTPUT:
			out_path = p.value;
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
