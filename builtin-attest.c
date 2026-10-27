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
#include "util/macros.h"
#include "util/malloc.h"
#include "util/paths.h"
#include "util/upatch.h"

#define EVIDENCE_MAX		SHIRUDO_JSON_MAX_BYTES
#define EVENTS_MAX		256

static const struct shirudo_help_item attest_subcmds[] = {
	{ "verify",    "check an evidence document against the expected state" },
	{ "predict",   "compute the register value a set of upatches yields" },
	{ "challenge", "make a credential challenge for a target's attestation key" },
};

static const struct shirudo_help_item attest_options[] = {
	{ "--nonce=<hex>",      "freshness value from the verifier (up to 64 bytes)" },
	{ "--pcrs=<list>",      "PCRs to quote, comma separated (default 0-7,9,11-15)" },
	{ "--challenge=<path>", "a challenge from the verifier to activate while attesting" },
	{ "--out=<path>",       "write the evidence there (0600) instead of stdout" },
};

static const struct shirudo_help_item verify_options[] = {
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
	{ "--strict-anchor",       "require the anchoring PCR to hold only the anchor" },
	{ "--expect-credential=<hex>", "the credential the challenge given to the target carried" },
	{ "--ek-name=<hex>",       "the endorsement key name pinned at enrollment" },
	{ "--expect-bind-pcr=<n>=<hex>", "a PCR value the register was bound under (repeatable)" },
	{ "--require-initrd",      "fail unless init bound the register from the initrd" },
};

static const struct shirudo_help_item challenge_options[] = {
	{ "--evidence=<path>",  "a document the target produced, carrying its keys" },
	{ "--ak-name=<hex>",    "the attestation key name the challenge is for" },
	{ "--ek-ca=<bundle>",   "PEM issuers the endorsement certificate must chain to" },
	{ "--ek-name=<hex>",    "an endorsement key name known out of band" },
	{ "--trust-presented-ek", "accept an endorsement key nothing vouches for" },
	{ "--out=<path>",       "write the challenge there (0600)" },
};

static const struct shirudo_help_item predict_options[] = {
	{ "--cert=<cert.der>",     "a certificate the target enrols (repeatable)" },
	{ "--upatch=<file>",       "an installed artifact (repeatable)" },
	{ "--expect=<name>=<hex>", "an installed upatch by name and payload digest" },
	{ "--tree-root=<hex>",     "the upatch tree projection root at boot" },
	{ "--event=<kind>:<name>=<hex>",
	  "a load, unload, tree:<seq> or revoke:<fingerprint> event after boot" },
	{ "--bind-pcr=<n>=<hex>",  "PCR 9 and 11 values at binding, for the register name" },
};

static const struct shirudo_help_section attest_help_sections[] = {
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

static const struct shirudo_help attest_help = {
	.usage      = "shirudo attest [--nonce=<hex>] [--pcrs=<list>] "
		      "[--challenge=<path>] [--out=<path>]\n"
		      "       shirudo attest verify --evidence=<path> --nonce=<hex> "
		      "--ak-name=<hex> [options]\n"
		      "       shirudo attest predict --cert=<cert.der> [options]\n"
		      "       shirudo attest challenge --evidence=<path> "
		      "--out=<path> --ek-ca=<bundle>|--ek-name=<hex>|"
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

static int parse_hex(const char *hex, __u8 *out, size_t cap, size_t *len)
{
	size_t n = strlen(hex);

	if (n == 0 || (n & 1) || n / 2 > cap)
		return -EINVAL;
	*len = n / 2;
	return hex_decode(hex, out, n / 2);
}

static int parse_hex32(const char *what, const char *hex, __u8 out[32])
{
	if (strlen(hex) != 64 || hex_decode(hex, out, 32)) {
		pr_err("attest: %s must be 64 hex characters", what);
		return -EINVAL;
	}
	return 0;
}

static int parse_pcrs(const char *list, __u32 *mask)
{
	const char *p = list;

	*mask = 0;
	while (*p) {
		size_t len = digits(p, strlen(p));
		__u64 n;

		if (parse_u64(p, len, 23, &n))
			return -EINVAL;
		*mask |= 1u << n;
		p += len;
		if (*p == ',')
			p++;
		else if (*p)
			return -EINVAL;
	}
	return *mask ? 0 : -EINVAL;
}

/* "<pcr>=<value>": the PCR, below 24, and where its value starts. */
static int parse_pcr_value(const char *arg, __u64 *pcr, const char **value)
{
	size_t len = digits(arg, strlen(arg));

	if (arg[len] != '=' || parse_u64(arg, len, 23, pcr))
		return -EINVAL;
	*value = arg + len + 1;
	return 0;
}

struct members {
	struct shirudo_measured_upatch	*set;
	size_t				n;
};

static int member_add_file(struct members *m, const char *path)
{
	struct shirudo_measured_upatch *e;
	struct shirudo_upatch u;
	int rc;

	if (m->n >= SHIRUDO_ATTEST_MEMBERS_MAX)
		return -E2BIG;
	rc = upatch_open(path, &u);
	if (rc) {
		pr_err("attest: open %s: %s", path, strerror(-rc));
		return rc;
	}
	e = &m->set[m->n++];
	memcpy(e->name, u.hdr.name, SHIRUDO_UPATCH_NAME_MAX);
	e->name[SHIRUDO_UPATCH_NAME_MAX] = '\0';
	hex_encode(u.hdr.payload_sha256,
		   SHIRUDO_UPATCH_PAYLOAD_HASH_LEN, e->payload_hex);
	upatch_close(&u);
	return 0;
}

static int member_add_spec(struct members *m, const char *spec)
{
	struct shirudo_measured_upatch *e;
	const char *eq = strchr(spec, '=');
	__u8 payload[32];

	if (!eq || eq == spec ||
	    (size_t)(eq - spec) > SHIRUDO_UPATCH_NAME_MAX ||
	    parse_hex32("--expect payload digest", eq + 1, payload))
		return -EINVAL;
	if (m->n >= SHIRUDO_ATTEST_MEMBERS_MAX)
		return -E2BIG;
	e = &m->set[m->n++];
	memcpy(e->name, spec, (size_t)(eq - spec));
	e->name[eq - spec] = '\0';
	hex_encode(payload, 32, e->payload_hex);
	return 0;
}

static int cert_digest(const char *path, __u8 out[32])
{
	struct stat st;
	ssize_t got;
	__u8 *buf;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		pr_err("attest: open %s: %s", path, strerror(errno));
		return -errno;
	}
	if (fstat(fd, &st) != 0 || st.st_size <= 0 ||
	    st.st_size > 1024 * 1024) {
		close(fd);
		return -EINVAL;
	}
	buf = xmalloc((size_t)st.st_size);
	if (!buf) {
		close(fd);
		return -ENOMEM;
	}
	got = read(fd, buf, (size_t)st.st_size);
	close(fd);
	if (got == st.st_size)
		shirudo_sha256(buf, (size_t)got, out);
	xfree(buf, (size_t)st.st_size);
	return got == st.st_size ? 0 : -EIO;
}

static int apply_event(const char *spec, __u8 chain[32])
{
	char name[SHIRUDO_UPATCH_NAME_MAX + 1];
	const char *colon = strchr(spec, ':'), *eq;
	__u8 digest[32], event[32];
	size_t kind_len, name_len;

	eq = colon ? strchr(colon, '=') : NULL;
	if (!colon || !eq || eq <= colon + 1 ||
	    parse_hex32("--event digest", eq + 1, digest))
		return -EINVAL;
	kind_len = (size_t)(colon - spec);
	name_len = (size_t)(eq - colon - 1);
	if (name_len > SHIRUDO_UPATCH_NAME_MAX)
		return -EINVAL;
	memcpy(name, colon + 1, name_len);
	name[name_len] = '\0';
	if (kind_len == 4 && !strncmp(spec, "load", 4)) {
		chain_upatch_event("shirudo-upatch", name, digest,
				   event);
	} else if (kind_len == 6 && !strncmp(spec, "unload", 6)) {
		chain_upatch_event("shirudo-unload", name, digest,
				   event);
	} else if (kind_len == 4 && !strncmp(spec, "tree", 4)) {
		__s64 seq;

		if (parse_s64(name, strlen(name), 1, INT64_MAX, &seq))
			return -EINVAL;
		chain_tree_event(seq, digest, event);
	} else if (kind_len == 6 && !strncmp(spec, "revoke", 6)) {
		chain_key_event("shirudo-key-revoke", digest, event);
	} else {
		return -EINVAL;
	}
	chain_fold(chain, event);
	return 0;
}

static int cmd_attest_predict(int argc, const char **argv)
{
	__u8 cert_sha[32], tree_root[32] = {}, set_digest[32], init[32];
	__u8 cert_shas[SHIRUDO_KEYS_MAX][32];
	size_t n_certs = 0;
	__u8 bind[2][32], chain[32] = {};
	const char *events[EVENTS_MAX];
	struct members m = {};
	char hex[2 * SHIRUDO_TPM_NAME_LEN + 1];
	bool have_cert = false, have_bind[2] = {};
	size_t n_events = 0, i;
	int ret = 2;

	m.set = xcalloc(SHIRUDO_ATTEST_MEMBERS_MAX, sizeof(*m.set));
	if (!m.set)
		return 1;
	for (i = 2; i < (size_t)argc; i++) {
		const char *a = argv[i];

		if (!strncmp(a, "--cert=", 7)) {
			if (n_certs >= SHIRUDO_KEYS_MAX) {
				pr_err("attest predict: at most %d --cert",
				       SHIRUDO_KEYS_MAX);
				goto out;
			}
			if (cert_digest(a + 7, cert_shas[n_certs]))
				goto out;
			n_certs++;
			have_cert = true;
		} else if (!strncmp(a, "--upatch=", 9)) {
			if (member_add_file(&m, a + 9))
				goto out;
		} else if (!strncmp(a, "--expect=", 9)) {
			if (member_add_spec(&m, a + 9)) {
				pr_err("attest: bad --expect '%s'", a + 9);
				goto out;
			}
		} else if (!strncmp(a, "--tree-root=", 12)) {
			if (parse_hex32("--tree-root", a + 12, tree_root))
				goto out;
		} else if (!strncmp(a, "--event=", 8)) {
			if (n_events >= EVENTS_MAX)
				goto out;
			events[n_events++] = a + 8;
		} else if (!strncmp(a, "--bind-pcr=", 11)) {
			const char *value = NULL;
			int slot = -1;
			__u64 n;

			if (!parse_pcr_value(a + 11, &n, &value))
				slot = n == SHIRUDO_CHAIN_PCR ? 0 :
				       n == SHIRUDO_CHAIN_PHASE_PCR ? 1 : -1;
			if (slot < 0 ||
			    parse_hex32("--bind-pcr value", value, bind[slot])) {
				pr_err("attest predict: --bind-pcr takes "
				       "%u=<hex> or %u=<hex>", SHIRUDO_CHAIN_PCR,
				       SHIRUDO_CHAIN_PHASE_PCR);
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
	keys_anchor_digest(cert_shas, n_certs, cert_sha);
	chain_init_event(cert_sha, m.set, m.n, tree_root, set_digest,
			 init);
	hex_encode(set_digest, 32, hex);
	printf("set_digest: %s\n", hex);
	hex_encode(init, 32, hex);
	printf("init_event: %s\n", hex);
	chain_fold(chain, init);
	hex_encode(chain, 32, hex);
	printf("register_at_boot: %s\n", hex);
	for (i = 0; i < n_events; i++) {
		if (apply_event(events[i], chain)) {
			pr_err("attest predict: bad --event '%s'", events[i]);
			goto out;
		}
	}
	if (n_events) {
		hex_encode(chain, 32, hex);
		printf("register_after_events: %s\n", hex);
	}
	if (have_bind[0] && have_bind[1]) {
		__u8 branch_written[32], branch_init[32], policy[32];
		__u8 name[SHIRUDO_TPM_NAME_LEN], anchor_digest[32];
		char anchor[SHIRUDO_CHAIN_ANCHOR_MAX];

		tpm_register_policy(SHIRUDO_CHAIN_PCR_MASK, bind[0], 2,
				    branch_written, branch_init,
				    policy);
		tpm_nv_name(SHIRUDO_NV_INDEX,
			    SHIRUDO_TPM_REGISTER_ATTRS |
			    SHIRUDO_TPM_NV_WRITTEN, policy, 32, name);
		hex_encode(name, sizeof(name), hex);
		printf("register_name: %s\n", hex);
		if (chain_anchor(name, anchor, sizeof(anchor))) {
			pr_err("attest predict: the anchor does not fit");
			goto out;
		}
		printf("anchor: %s\n", anchor);
		shirudo_sha256(anchor, strlen(anchor), anchor_digest);
		chain_fold(bind[0], anchor_digest);
		hex_encode(bind[0], 32, hex);
		printf("pcr%u_after_anchor: %s\n", SHIRUDO_CHAIN_PCR, hex);
	} else if (have_bind[0] || have_bind[1]) {
		pr_err("attest predict: --bind-pcr needs both %u and %u",
		       SHIRUDO_CHAIN_PCR, SHIRUDO_CHAIN_PHASE_PCR);
		goto out;
	}
	ret = 0;
out:
	xfree(m.set, SHIRUDO_ATTEST_MEMBERS_MAX * sizeof(*m.set));
	return ret;
}

static int read_evidence(const char *path, char **out, size_t *len)
{
	struct stat st;
	ssize_t got;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		pr_err("attest verify: open %s: %s", path, strerror(errno));
		return -errno;
	}
	if (fstat(fd, &st) != 0 || st.st_size <= 0 ||
	    st.st_size > (off_t)EVIDENCE_MAX) {
		close(fd);
		pr_err("attest verify: %s: empty or larger than %u bytes",
		       path, EVIDENCE_MAX);
		return -EFBIG;
	}
	*out = xmalloc((size_t)st.st_size + 1);
	if (!*out) {
		close(fd);
		return -ENOMEM;
	}
	got = read(fd, *out, (size_t)st.st_size);
	close(fd);
	if (got != st.st_size) {
		xfree(*out, (size_t)st.st_size + 1);
		*out = NULL;
		return -EIO;
	}
	(*out)[got] = '\0';
	*len = (size_t)got;
	return 0;
}

static int cmd_attest_verify(int argc, const char **argv)
{
	struct shirudo_attest_expect x = {};
	__u8 nonce[SHIRUDO_ATTEST_NONCE_MAX], cert_sha[32], set_digest[32];
	__u8 cert_shas[SHIRUDO_KEYS_MAX][32];
	size_t n_certs = 0;
	__u8 tree_root[32] = {};
	const char *evidence_path = NULL;
	struct members m = {};
	char *evidence = NULL, *report;
	size_t evidence_len = 0, nonce_len = 0, i;
	bool have_cert = false, have_nonce = false, have_tree_root = false;
	int rc, ret = 2;

	m.set = xcalloc(SHIRUDO_ATTEST_MEMBERS_MAX, sizeof(*m.set));
	report = xmalloc(SHIRUDO_ATTEST_REPORT_MAX);
	if (!m.set || !report)
		goto out;
	for (i = 2; i < (size_t)argc; i++) {
		const char *a = argv[i];

		if (!strncmp(a, "--evidence=", 11)) {
			evidence_path = a + 11;
		} else if (!strncmp(a, "--nonce=", 8)) {
			if (parse_hex(a + 8, nonce, sizeof(nonce),
				      &nonce_len)) {
				pr_err("attest verify: --nonce must be hex of "
				       "up to %d bytes",
				       SHIRUDO_ATTEST_NONCE_MAX);
				goto out;
			}
			have_nonce = true;
		} else if (!strncmp(a, "--ak-name=", 10)) {
			size_t n;

			if (parse_hex(a + 10, x.ak_name, sizeof(x.ak_name),
				      &n) || n != SHIRUDO_TPM_NAME_LEN) {
				pr_err("attest verify: --ak-name must be %d "
				       "hex characters",
				       2 * SHIRUDO_TPM_NAME_LEN);
				goto out;
			}
			x.have_ak_name = true;
		} else if (!strncmp(a, "--cert=", 7)) {
			if (n_certs >= SHIRUDO_KEYS_MAX) {
				pr_err("attest verify: at most %d --cert",
				       SHIRUDO_KEYS_MAX);
				goto out;
			}
			if (cert_digest(a + 7, cert_shas[n_certs]))
				goto out;
			n_certs++;
			have_cert = true;
		} else if (!strncmp(a, "--upatch=", 9)) {
			if (member_add_file(&m, a + 9))
				goto out;
		} else if (!strncmp(a, "--expect=", 9)) {
			if (member_add_spec(&m, a + 9)) {
				pr_err("attest verify: bad --expect '%s'",
				       a + 9);
				goto out;
			}
		} else if (!strncmp(a, "--tree-root=", 12)) {
			if (parse_hex32("--tree-root", a + 12, tree_root))
				goto out;
			have_tree_root = true;
		} else if (!strncmp(a, "--expect-config-root=", 21)) {
			if (x.have_config_root ||
			    parse_hex32("--expect-config-root", a + 21,
					x.config_root))
				goto out;
			x.have_config_root = true;
		} else if (!strncmp(a, "--expect-config-pcr=", 20)) {
			__u64 pcr;

			if (parse_u64(a + 20, strlen(a + 20), 15, &pcr) ||
			    x.have_config_pcr ||
			    shirudo_config_measure_pcr_valid(pcr))
				goto out;
			x.config_pcr = pcr;
			x.have_config_pcr = true;
		} else if (!strncmp(a, "--expect-chain=", 15)) {
			if (parse_hex32("--expect-chain", a + 15, x.chain))
				goto out;
			x.have_chain = true;
		} else if (!strncmp(a, "--expect-pcr=", 13)) {
			const char *value;
			__u64 n;

			if (parse_pcr_value(a + 13, &n, &value) ||
			    parse_hex32("--expect-pcr value", value, x.pcrs[n]))
				goto out;
			x.pcr_expect_mask |= 1u << n;
		} else if (!strcmp(a, "--allow-runtime-events")) {
			x.allow_runtime_events = true;
		} else if (!strcmp(a, "--strict-anchor")) {
			x.strict_anchor = true;
		} else if (!strncmp(a, "--expect-credential=", 20)) {
			if (parse_hex32("--expect-credential", a + 20,
					x.credential))
				goto out;
			x.have_credential = true;
		} else if (!strncmp(a, "--ek-name=", 10)) {
			size_t n;

			if (parse_hex(a + 10, x.ek_name, sizeof(x.ek_name),
				      &n) || n != SHIRUDO_TPM_NAME_LEN) {
				pr_err("attest verify: --ek-name must be %d "
				       "hex characters",
				       2 * SHIRUDO_TPM_NAME_LEN);
				goto out;
			}
			x.have_ek_name = true;
		} else if (!strncmp(a, "--expect-bind-pcr=", 18)) {
			const char *value;
			__u64 n;

			if (parse_pcr_value(a + 18, &n, &value) ||
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
		keys_anchor_digest(cert_shas, n_certs, cert_sha);
		chain_init_event(cert_sha, m.set, m.n, tree_root,
				 set_digest, x.init_event);
		x.have_init = true;
	}
	if (read_evidence(evidence_path, &evidence, &evidence_len))
		goto out;
	rc = attest_verify(evidence, evidence_len, &x, report,
			   SHIRUDO_ATTEST_REPORT_MAX);
	fputs(report, stdout);
	if (rc == -EINVAL) {
		pr_err("attest verify: %s is not a shirudo evidence document",
		       evidence_path);
		ret = 2;
	} else if (rc) {
		printf("verdict: FAIL\n");
		ret = 1;
	} else {
		printf("verdict: ok\n");
		ret = 0;
	}
out:
	xfree(evidence, evidence ? evidence_len + 1 : 0);
	xfree(report, report ? SHIRUDO_ATTEST_REPORT_MAX : 0);
	xfree(m.set, m.set ? SHIRUDO_ATTEST_MEMBERS_MAX * sizeof(*m.set) : 0);
	return ret;
}

static int cmd_attest_challenge(int argc, const char **argv)
{
	struct shirudo_attest_challenge_policy pol = {};
	__u8 credential[SHIRUDO_TPM_CREDENTIAL_LEN];
	__u8 ak_name[SHIRUDO_TPM_NAME_LEN], ek_name[SHIRUDO_TPM_NAME_LEN];
	const char *evidence_path = NULL, *out_path = NULL;
	char *evidence = NULL, *doc = NULL, *report;
	char hex[2 * SHIRUDO_TPM_CREDENTIAL_LEN + 1];
	size_t evidence_len = 0, len = 0, cap = 0, i, n;
	int rc, ret = 2;

	report = xmalloc(SHIRUDO_ATTEST_REPORT_MAX);
	if (!report)
		return 1;
	for (i = 2; i < (size_t)argc; i++) {
		const char *a = argv[i];

		if (!strncmp(a, "--evidence=", 11)) {
			evidence_path = a + 11;
		} else if (!strncmp(a, "--ek-ca=", 8)) {
			pol.ek_ca = a + 8;
		} else if (!strncmp(a, "--ak-name=", 10)) {
			if (parse_hex(a + 10, ak_name, sizeof(ak_name), &n) ||
			    n != SHIRUDO_TPM_NAME_LEN) {
				pr_err("attest challenge: --ak-name must be %d "
				       "hex characters", 2 * SHIRUDO_TPM_NAME_LEN);
				goto out;
			}
			pol.ak_name = ak_name;
		} else if (!strncmp(a, "--ek-name=", 10)) {
			if (parse_hex(a + 10, ek_name, sizeof(ek_name), &n) ||
			    n != SHIRUDO_TPM_NAME_LEN) {
				pr_err("attest challenge: --ek-name must be %d "
				       "hex characters", 2 * SHIRUDO_TPM_NAME_LEN);
				goto out;
			}
			pol.ek_name = ek_name;
		} else if (!strcmp(a, "--trust-presented-ek")) {
			pol.trust_presented = true;
		} else if (!strncmp(a, "--out=", 6)) {
			out_path = a + 6;
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
		pr_err("attest challenge: --evidence and --out are required");
		goto out;
	}
	if (read_evidence(evidence_path, &evidence, &evidence_len))
		goto out;
	rc = attest_challenge_make(evidence, evidence_len, &pol,
				   credential, &doc, &len, &cap, report,
				   SHIRUDO_ATTEST_REPORT_MAX);
	fputs(report, stdout);
	if (rc == -EINVAL) {
		pr_err("attest challenge: %s carries no endorsement key",
		       evidence_path);
		goto out;
	}
	if (rc) {
		printf("verdict: FAIL\n");
		ret = 1;
		goto out;
	}
	{
		int fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
			      0600);

		if (fd < 0 || write_complete(fd, doc, len) ||
		    write_complete(fd, "\n", 1) || close(fd)) {
			pr_err("attest challenge: write %s: %s", out_path,
			       strerror(errno));
			if (fd >= 0)
				close(fd);
			ret = 1;
			goto out;
		}
	}
	hex_encode(credential, sizeof(credential), hex);
	printf("challenge: %s\ncredential: %s\n", out_path, hex);
	ret = 0;
out:
	explicit_bzero(credential, sizeof(credential));
	xfree(doc, cap);
	xfree(evidence, evidence ? evidence_len + 1 : 0);
	xfree(report, SHIRUDO_ATTEST_REPORT_MAX);
	return ret;
}

static int cmd_attest_evidence(int argc, const char **argv)
{
	const struct shirudo_attest_challenge *request;
	struct shirudo_attest_challenge challenge = {};
	__u8 nonce[SHIRUDO_ATTEST_NONCE_MAX];
	__u32 mask = SHIRUDO_ATTEST_PCR_DEFAULT;
	const char *out_path = NULL, *challenge_path = NULL;
	char *doc = NULL;
	size_t nonce_len = 0, len = 0, cap = 0, i;
	int rc;

	for (i = 1; i < (size_t)argc; i++) {
		const char *a = argv[i];

		if (!strncmp(a, "--challenge=", 12)) {
			challenge_path = a + 12;
		} else if (!strncmp(a, "--nonce=", 8)) {
			if (parse_hex(a + 8, nonce, sizeof(nonce),
				      &nonce_len)) {
				pr_err("attest: --nonce must be hex of up to "
				       "%d bytes", SHIRUDO_ATTEST_NONCE_MAX);
				return 2;
			}
		} else if (!strncmp(a, "--pcrs=", 7)) {
			if (parse_pcrs(a + 7, &mask)) {
				pr_err("attest: --pcrs takes a comma separated "
				       "list of 0..23");
				return 2;
			}
		} else if (!strncmp(a, "--out=", 6)) {
			out_path = a + 6;
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
	rc = shirudo_attest_evidence_config(nonce, nonce_len, mask, request,
					    shirudo_image_update_context(),
					    &doc, &len, &cap);
	if (rc == -ENXIO) {
		pr_err("attest: no TPM answered (tpm_error)");
		return 1;
	}
	if (rc == -ENODEV) {
		pr_err("attest: register 0x%08X is not bound this boot "
		       "(tpm_error); run shirudo init first",
		       SHIRUDO_NV_INDEX);
		return 1;
	}
	if (rc == -EKEYREJECTED) {
		pr_err("attest: the challenge was refused (tampered?)");
		return 1;
	}
	if (rc) {
		pr_err("attest: evidence failed: %s", strerror(-rc));
		return 1;
	}
	if (out_path) {
		int fd = open(out_path,
			      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

		if (fd < 0 || write_complete(fd, doc, len) ||
		    write_complete(fd, "\n", 1) || close(fd)) {
			pr_err("attest: write %s: %s", out_path,
			       strerror(errno));
			if (fd >= 0)
				close(fd);
			rc = -EIO;
		}
	} else if (fwrite(doc, 1, len, stdout) != len ||
		   fputc('\n', stdout) == EOF) {
		rc = -EIO;
	}
	xfree(doc, cap);
	return rc ? 1 : 0;
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
