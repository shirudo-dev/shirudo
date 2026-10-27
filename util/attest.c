// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Attestation: evidence on the target, prediction and verification on
 * the operator.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "attest.h"
#include "chain.h"
#include "crypto.h"
#include "config_attest.h"
#include "eventlog.h"
#include "hex.h"
#include "io.h"
#include "json.h"
#include "log.h"
#include "macros.h"
#include "malloc.h"
#include "paths.h"
#include "tpm.h"
#include "version.h"

#define FIRMWARE_LOG_PATH \
	"/sys/kernel/security/tpm0/binary_bios_measurements"
#define SYSTEMD_LOG_PATH	"/run/log/systemd/tpm2-measure.log"
#define LOG_MAX_BYTES		(2u * 1024u * 1024u)
#define EK_CERT_MAX		4096
#define QUOTE_ATTEMPTS		3
#define RECORDS_MAX		4096
#define EK_CERT_B64_MAX		(4 * ((EK_CERT_MAX + 2) / 3) + 1)
/* restricted | sign | fixedTPM | fixedParent | sensitiveDataOrigin */
#define AK_ATTRS_REQUIRED	0x00050032u

/*
 * securityfs reports a size of 0 for the firmware event log, so the log
 * is read to its end rather than for the size fstat() gives.
 */
static int read_file_base64(const char *path, char **out, size_t *out_cap)
{
	__u8 *raw;
	size_t len = 0, cap;
	ssize_t got;
	int fd, rc = 0;

	*out = NULL;
	*out_cap = 0;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	raw = xmalloc(LOG_MAX_BYTES + 1);
	if (!raw) {
		close(fd);
		return -ENOMEM;
	}
	while (len <= LOG_MAX_BYTES) {
		got = read(fd, raw + len, LOG_MAX_BYTES + 1 - len);
		if (got < 0 && errno == EINTR)
			continue;
		if (got < 0)
			rc = -errno;
		if (got <= 0)
			break;
		len += (size_t)got;
	}
	close(fd);
	if (!rc && (len == 0 || len > LOG_MAX_BYTES))
		rc = -EFBIG;
	if (rc) {
		xfree(raw, LOG_MAX_BYTES + 1);
		return rc;
	}
	cap = 4 * ((len + 2) / 3) + 1;
	*out = xmalloc(cap);
	rc = *out ? base64_encode(raw, len, *out, cap) : -ENOMEM;
	xfree(raw, LOG_MAX_BYTES + 1);
	if (rc) {
		xfree(*out, cap);
		*out = NULL;
		return rc;
	}
	*out_cap = cap;
	return 0;
}

static int emit_line(const char *line, size_t len, void *ctx)
{
	json_raw(ctx, line, len);
	return 0;
}

static void emit_hex(struct shirudo_json_emit *e, const char *key,
		     const __u8 *data, size_t len)
{
	char hex[2 * SHIRUDO_TPM_ATTEST_MAX + 1];

	if (len > SHIRUDO_TPM_ATTEST_MAX) {
		e->err = -E2BIG;
		return;
	}
	hex_encode(data, len, hex);
	json_kv_string(e, key, hex);
}

/* A quote is accepted only when it covers the PCR values read beside it. */
static bool quote_covers(const struct shirudo_tpm_attestation *quote,
			 __u32 mask, __u8 values[24][32])
{
	struct shirudo_tpm_attest a;
	struct shirudo_sha256_ctx ctx;
	__u8 digest[32];
	__u32 i;

	if (tpm_attest_parse(quote->attest, quote->attest_len, &a) ||
	    a.type != SHIRUDO_TPM_ST_ATTEST_QUOTE || a.pcr_mask != mask)
		return false;
	if (sha256_init(&ctx) != 0)
		return false;
	for (i = 0; i < 24; i++) {
		if ((mask & (1u << i)) &&
		    sha256_update(&ctx, values[i], 32) != 0) {
			sha256_free(&ctx);
			return false;
		}
	}
	if (sha256_final(&ctx, digest) != 0)
		return false;
	return ct_eq(digest, a.pcr_digest, 32);
}

int shirudo_attest_evidence_config(const __u8 *nonce, size_t nonce_len,
				   __u32 pcr_mask,
				   const struct shirudo_attest_challenge *c,
				   struct shirudo_config_update *update,
				   char **out, size_t *len, size_t *cap)
{
	const struct shirudo_attest_challenge *challenge = c;
	struct shirudo_tpm_key ak = { .handle = 0 }, ek = { .handle = 0 };
	struct shirudo_tpm_key ak_copy = {}, ek_copy = {};
	struct shirudo_tpm_attestation quote = {}, certify = {};
	struct shirudo_config_evidence config = {};
	struct shirudo_tpm_attest quoted;
	struct tpm_nv_info nv;
	struct shirudo_tpm *tpm = NULL;
	struct shirudo_json_emit e;
	__u8 values[24][32] = {};
	__u8 reg[32], cred[SHIRUDO_TPM_CREDENTIAL_LEN], *ek_cert = NULL;
	size_t ek_cert_len = 0, ek_b64_cap = 0, fw_cap = 0, sd_cap = 0, need;
	size_t cred_len = 0;
	char *ek_b64 = NULL, *fw = NULL, *sd = NULL;
	char ts[32], boot_id[64], nv_index[16], nonce_hex[2 * 64 + 1];
	struct stat st;
	__u32 i, attempt;
	bool ek_cert_rsa = false, ek_rsa;
	int rc;

	*out = NULL;
	*len = 0;
	*cap = 0;
	if (nonce_len > SHIRUDO_ATTEST_NONCE_MAX || !pcr_mask ||
	    (pcr_mask & ~0x00FFFFFFu))
		return -EINVAL;

	rc = shirudo_config_evidence_collect(update, &config);
	if (rc)
		return rc;
	if (config.present)
		pcr_mask |= 1u << config.pcr;
	rc = tpm_open(&tpm);
	if (rc) {
		rc = -ENXIO;
		goto out;
	}
	rc = tpm_nv_info(tpm, SHIRUDO_NV_INDEX, &nv);
	if (rc)
		goto out;
	if (!nv.defined || !nv.written) {
		rc = -ENODEV;
		goto out;
	}
	rc = tpm_nv_read(tpm, SHIRUDO_NV_INDEX, reg);
	if (rc)
		goto out;
	rc = tpm_ak_create(tpm, &ak);
	if (rc)
		goto out;
	for (attempt = 0; attempt < QUOTE_ATTEMPTS; attempt++) {
		for (i = 0; i < 24; i++) {
			if (!(pcr_mask & (1u << i)))
				continue;
			rc = tpm_pcr_read(tpm, i, values[i]);
			if (rc)
				goto out;
		}
		rc = tpm_quote(tpm, &ak, nonce, nonce_len, pcr_mask,
			       &quote);
		if (rc)
			goto out;
		if (quote_covers(&quote, pcr_mask, values))
			break;
	}
	if (attempt == QUOTE_ATTEMPTS) {
		pr_err("attest: PCRs kept changing while quoting");
		rc = -EAGAIN;
		goto out;
	}
	if (config.present &&
	    (tpm_attest_parse(quote.attest, quote.attest_len,
				      &quoted) ||
	     quoted.reset_count != config.reset_count ||
	     quoted.restart_count != config.restart_count ||
	     memcmp(values[config.pcr],
		    config.value, 32))) {
		rc = -EUCLEAN;
		goto out;
	}
	rc = tpm_nv_certify(tpm, &ak, SHIRUDO_NV_INDEX, nonce,
			    nonce_len, &certify);
	if (rc)
		goto out;
	ek_cert = xmalloc(EK_CERT_MAX);
	if (!ek_cert) {
		rc = -ENOMEM;
		goto out;
	}
	if (tpm_ek_certificate(tpm, ek_cert, EK_CERT_MAX, &ek_cert_len,
			       &ek_cert_rsa) == 0) {
		ek_b64_cap = 4 * ((ek_cert_len + 2) / 3) + 1;
		ek_b64 = xmalloc(ek_b64_cap);
		if (!ek_b64 || base64_encode(ek_cert, ek_cert_len, ek_b64,
					     ek_b64_cap)) {
			xfree(ek_b64, ek_b64_cap);
			ek_b64 = NULL;
			ek_b64_cap = 0;
		}
	}
	/*
	 * The endorsement key the certificate describes, or the one the
	 * challenge was made for; a TPM without a certificate yields its
	 * ECC key, which the operator pins by name.
	 */
	ek_rsa = challenge ? challenge->ek_rsa : ek_cert_rsa;
	rc = tpm_ek_create(tpm, ek_rsa, &ek);
	if (rc)
		goto out;
	if (challenge) {
		if (ak.name_len != SHIRUDO_TPM_NAME_LEN ||
		    memcmp(challenge->ak_name, ak.name, SHIRUDO_TPM_NAME_LEN)) {
			pr_err("attest: the challenge was made for another "
			       "attestation key");
			rc = -EKEYREJECTED;
			goto out;
		}
		rc = tpm_activate_credential(tpm, &ak, &ek,
					     challenge->blob,
					     challenge->blob_len,
					     challenge->secret,
					     challenge->secret_len,
					     cred, sizeof(cred),
					     &cred_len);
		if (rc) {
			pr_err("attest: the TPM refused the challenge: not "
			       "made for this attestation key under this "
			       "endorsement key");
			goto out;
		}
	}
	/* The keys are flushed before the file work; keep their public parts. */
	memcpy(&ak_copy, &ak, sizeof(ak_copy));
	memcpy(&ek_copy, &ek, sizeof(ek_copy));
	tpm_key_flush(tpm, &ek);
	tpm_key_flush(tpm, &ak);
	tpm_close(tpm);
	tpm = NULL;

	read_file_base64(FIRMWARE_LOG_PATH, &fw, &fw_cap);
	read_file_base64(SYSTEMD_LOG_PATH, &sd, &sd_cap);
	need = 64 * 1024 + fw_cap + sd_cap + ek_b64_cap +
	       config.n_events * 160;
	if (stat(eventlog_path(), &st) == 0 && st.st_size > 0)
		need += 2 * (size_t)st.st_size;
	if (need > SHIRUDO_JSON_MAX_BYTES)
		need = SHIRUDO_JSON_MAX_BYTES;
	*out = xmalloc(need);
	if (!*out) {
		rc = -ENOMEM;
		goto out;
	}
	*cap = need;

	eventlog_timestamp(ts, sizeof(ts));
	eventlog_boot_id(boot_id, sizeof(boot_id));
	if (strsprintf(nv_index, sizeof(nv_index), "0x%08X",
		       SHIRUDO_NV_INDEX) < 0) {
		rc = -E2BIG;
		goto out;
	}
	hex_encode(nonce, nonce_len, nonce_hex);

	e = (struct shirudo_json_emit){ .buf = *out, .cap = need };
	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_kv_string(&e, "kind", "shirudo-attestation");
	json_kv_string(&e, "version_id", shirudo_version_id);
	json_kv_string(&e, "ts", ts);
	json_kv_string(&e, "boot_id", boot_id);
	json_kv_string(&e, "nonce", nonce_hex);
	json_kv_string(&e, "pcr_bank", "sha256");
	json_kv_int(&e, "pcr_mask", pcr_mask);
	json_arr_open(&e, "pcrs");
	for (i = 0; i < 24; i++) {
		if (!(pcr_mask & (1u << i)))
			continue;
		json_obj_open(&e);
		json_kv_int(&e, "index", i);
		emit_hex(&e, "value", values[i], 32);
		json_obj_close(&e);
	}
	json_arr_close(&e);
	json_obj_open_key(&e, "ak");
	emit_hex(&e, "public", ak_copy.public, ak_copy.public_len);
	emit_hex(&e, "name", ak_copy.name, ak_copy.name_len);
	json_obj_close(&e);
	json_obj_open_key(&e, "ek");
	json_kv_string(&e, "type", ek_rsa ? "rsa" : "ecc");
	emit_hex(&e, "public", ek_copy.public, ek_copy.public_len);
	emit_hex(&e, "name", ek_copy.name, ek_copy.name_len);
	json_obj_close(&e);
	json_obj_open_key(&e, "quote");
	emit_hex(&e, "attest", quote.attest, quote.attest_len);
	emit_hex(&e, "signature", quote.signature, quote.signature_len);
	json_obj_close(&e);
	json_obj_open_key(&e, "register");
	json_kv_string(&e, "nv_index", nv_index);
	json_kv_int(&e, "pcr", SHIRUDO_CHAIN_PCR);
	emit_hex(&e, "name", nv.name, nv.name_len);
	emit_hex(&e, "value", reg, sizeof(reg));
	emit_hex(&e, "attest", certify.attest, certify.attest_len);
	emit_hex(&e, "signature", certify.signature, certify.signature_len);
	json_obj_close(&e);
	json_arr_open(&e, "eventlog");
	eventlog_boot_lines(emit_line, &e);
	json_arr_close(&e);
	rc = shirudo_config_evidence_emit(&e, &config);
	if (rc)
		goto out;
	if (cred_len) {
		json_obj_open_key(&e, "credential");
		emit_hex(&e, "value", cred, cred_len);
		json_obj_close(&e);
	} else {
		json_kv_null(&e, "credential");
	}
	if (ek_b64)
		json_kv_string(&e, "ek_certificate", ek_b64);
	else
		json_kv_null(&e, "ek_certificate");
	json_obj_open_key(&e, "logs");
	if (fw)
		json_kv_string(&e, "firmware", fw);
	else
		json_kv_null(&e, "firmware");
	if (sd)
		json_kv_string(&e, "systemd", sd);
	else
		json_kv_null(&e, "systemd");
	json_obj_close(&e);
	json_obj_close(&e);
	if (e.err) {
		rc = e.err;
		goto out;
	}
	(*out)[e.len] = '\0';
	*len = e.len;
	rc = 0;
out:
	if (tpm) {
		tpm_key_flush(tpm, &ek);
		tpm_key_flush(tpm, &ak);
		tpm_close(tpm);
	}
	shirudo_config_evidence_clear(&config);
	xfree(ek_cert, ek_cert ? EK_CERT_MAX : 0);
	xfree(ek_b64, ek_b64_cap);
	xfree(fw, fw_cap);
	xfree(sd, sd_cap);
	explicit_bzero(cred, sizeof(cred));
	explicit_bzero(&ak, sizeof(ak));
	explicit_bzero(&ek, sizeof(ek));
	explicit_bzero(&ak_copy, sizeof(ak_copy));
	explicit_bzero(&ek_copy, sizeof(ek_copy));
	if (rc && *out) {
		xfree(*out, *cap);
		*out = NULL;
		*cap = 0;
	}
	return rc;
}

int attest_evidence(const __u8 *nonce, size_t nonce_len,
		    __u32 pcr_mask,
			    const struct shirudo_attest_challenge *challenge,
			    char **out, size_t *len, size_t *cap)
{
	return shirudo_attest_evidence_config(nonce, nonce_len, pcr_mask,
					      challenge, NULL, out, len, cap);
}

/* ---- verification ---------------------------------------------------- */

struct record {
	char	type[16];
	char	label[SHIRUDO_UPATCH_NAME_MAX + 64];
	__u8	digest[32];
	bool	derived;	/* digest follows from the record's fields */
};

struct init_record {
	bool		present;
	bool		have_reset_count;
	bool		initrd;
	__u32		reset_count;
	__u32		pcr;
	__u32		phase_pcr;
	__u8		digest[32];
	__u8		pcr_before[32];
	__u8		phase_before[32];
	__u8		name[SHIRUDO_TPM_NAME_LEN];
	__u8		anchor_digest[32];
	__u8		chain[32];
	char		anchor[SHIRUDO_CHAIN_ANCHOR_MAX];
};

struct parse {
	char		nonce_hex[2 * SHIRUDO_ATTEST_NONCE_MAX + 1];
	__s64		pcr_mask;
	char		ak_public_hex[2 * SHIRUDO_TPM_PUBLIC_MAX + 1];
	char		ak_name_hex[2 * SHIRUDO_TPM_NAME_LEN + 1];
	char		quote_attest_hex[2 * SHIRUDO_TPM_ATTEST_MAX + 1];
	char		quote_sig_hex[2 * SHIRUDO_TPM_SIGNATURE_MAX + 1];
	char		ek_type[8];
	char		ek_public_hex[2 * SHIRUDO_TPM_PUBLIC_MAX + 1];
	char		ek_name_hex[2 * SHIRUDO_TPM_NAME_LEN + 1];
	char		cred_hex[2 * SHIRUDO_TPM_CREDENTIAL_LEN + 1];
	char		reg_index[16];
	__s64		reg_pcr;
	char		reg_name_hex[2 * SHIRUDO_TPM_NAME_LEN + 1];
	char		reg_value_hex[65];
	char		reg_attest_hex[2 * SHIRUDO_TPM_ATTEST_MAX + 1];
	char		reg_sig_hex[2 * SHIRUDO_TPM_SIGNATURE_MAX + 1];
	__s64		pcr_index;
	char		pcr_value_hex[65];
	__u32		pcr_have;
	__u8		pcrs[24][32];
	char		type[16];
	char		digest_hex[65];
	char		pcr_before_hex[65];
	char		phase_before_hex[65];
	char		bound_in[8];
	char		nv_name_hex[2 * SHIRUDO_TPM_NAME_LEN + 1];
	char		anchor[SHIRUDO_CHAIN_ANCHOR_MAX];
	char		anchor_digest_hex[65];
	char		chain_hex[65];
	__s64		rec_pcr;
	__s64		rec_phase_pcr;
	__s64		rec_reset;
	char		upatch_name[SHIRUDO_UPATCH_NAME_MAX + 1];
	char		upatch_payload_hex[65];
	char		tree_id[SHIRUDO_UPATCH_NAME_MAX + 1];
	char		tree_op[16];
	char		tree_digest_hex[sizeof("sha256:") + 64];
	__s64		tree_seq;
	char		key_fingerprint[65];
	char		key_sha_hex[65];
	struct record	*recs;
	size_t		n_recs;
	__u32		inits;		/* init records this boot */
	__u32		inits_epoch;	/* for the last reset count */
	struct init_record init;
	int		err;
};

static int on_pcr(void *ctx)
{
	struct parse *p = ctx;

	if (p->pcr_index < 0 || p->pcr_index >= 24 ||
	    hex_decode(p->pcr_value_hex, p->pcrs[p->pcr_index], 32))
		return -EINVAL;
	p->pcr_have |= 1u << p->pcr_index;
	return 0;
}

static int on_record(void *ctx)
{
	struct parse *p = ctx;
	struct record *r;

	if (p->n_recs >= RECORDS_MAX)
		return -E2BIG;
	r = &p->recs[p->n_recs];
	memset(r, 0, sizeof(*r));
	strscpy(r->type, p->type, sizeof(r->type));
	if (hex_decode(p->digest_hex, r->digest, 32))
		return -EINVAL;
	if (!strcmp(p->type, "init")) {
		struct init_record *in = &p->init;
		__u32 prev_reset = in->reset_count;
		bool prev_have = in->have_reset_count;

		memset(in, 0, sizeof(*in));
		if (p->rec_pcr < 0 || p->rec_pcr >= 24 ||
		    p->rec_phase_pcr <= p->rec_pcr || p->rec_phase_pcr >= 24 ||
		    p->rec_reset > UINT32_MAX ||
		    strlen(p->nv_name_hex) != 2 * SHIRUDO_TPM_NAME_LEN ||
		    hex_decode(p->pcr_before_hex, in->pcr_before, 32) ||
		    hex_decode(p->phase_before_hex, in->phase_before,
			       32) ||
		    hex_decode(p->nv_name_hex, in->name,
			       SHIRUDO_TPM_NAME_LEN) ||
		    hex_decode(p->anchor_digest_hex, in->anchor_digest,
			       32) ||
		    hex_decode(p->chain_hex, in->chain, 32))
			return -EINVAL;
		memcpy(in->digest, r->digest, 32);
		in->pcr = (__u32)p->rec_pcr;
		in->phase_pcr = (__u32)p->rec_phase_pcr;
		in->initrd = !strcmp(p->bound_in, "initrd");
		in->have_reset_count = p->rec_reset >= 0;
		in->reset_count = (__u32)p->rec_reset;
		strscpy(in->anchor, p->anchor, sizeof(in->anchor));
		in->present = true;
		/*
		 * Records are of one TPM reset unless both carry a count
		 * and the counts differ; a second record for one reset is
		 * a register bound again after boot.
		 */
		p->inits++;
		if (p->inits == 1 || (in->have_reset_count && prev_have &&
				      in->reset_count != prev_reset))
			p->inits_epoch = 1;
		else
			p->inits_epoch++;
		p->n_recs = 0;	/* this boot's register starts here */
		r = &p->recs[0];
		memset(r, 0, sizeof(*r));
		strscpy(r->type, "init", sizeof(r->type));
		memcpy(r->digest, in->digest, 32);
	} else if (!strcmp(p->type, "upatch_load") ||
		   !strcmp(p->type, "upatch_unload")) {
		bool load = p->type[7] == 'l';
		__u8 payload[32], event[32];

		strscpy(r->label, p->upatch_name, sizeof(r->label));
		if (!hex_decode(p->upatch_payload_hex, payload, 32)) {
			chain_upatch_event(load ? "shirudo-upatch" :
					   "shirudo-unload", p->upatch_name,
					   payload, event);
			r->derived = ct_eq(event, r->digest, 32);
		}
	} else if (!strcmp(p->type, "tree_op")) {
		__u8 operation[32], event[32];

		if (strsprintf(r->label, sizeof(r->label), "%s %s seq %lld",
			       p->tree_op, p->tree_id, (__s64)p->tree_seq) < 0)
			return -E2BIG;
		if (p->tree_seq > 0 &&
		    !strncmp(p->tree_digest_hex, "sha256:", 7) &&
		    !hex_decode(p->tree_digest_hex + 7, operation, 32)) {
			chain_tree_event(p->tree_seq, operation, event);
			r->derived = ct_eq(event, r->digest, 32);
		}
	} else if (!strcmp(p->type, "key_revoke")) {
		__u8 sha[32], event[32];

		strscpy(r->label, p->key_fingerprint, sizeof(r->label));
		if (!hex_decode(p->key_sha_hex, sha, 32)) {
			chain_key_event("shirudo-key-revoke", sha, event);
			r->derived = ct_eq(event, r->digest, 32);
		}
	}
	p->n_recs++;
	/* Reset the per-element scratch the next element may not set. */
	p->type[0] = '\0';
	p->upatch_name[0] = '\0';
	p->upatch_payload_hex[0] = '\0';
	p->tree_id[0] = '\0';
	p->tree_op[0] = '\0';
	p->tree_digest_hex[0] = '\0';
	p->key_fingerprint[0] = '\0';
	p->key_sha_hex[0] = '\0';
	p->anchor[0] = '\0';
	p->bound_in[0] = '\0';
	p->tree_seq = 0;
	p->rec_pcr = -1;
	p->rec_phase_pcr = -1;
	p->rec_reset = -1;
	return 0;
}

struct reporter {
	char	*buf;
	size_t	cap;
	size_t	len;
	int	failed;
};

static void say(struct reporter *r, bool ok, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

static void say(struct reporter *r, bool ok, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (!ok)
		r->failed++;
	if (r->len + 8 >= r->cap)
		return;
	n = strscpy(r->buf + r->len, ok ? "ok:   " : "FAIL: ", r->cap - r->len);
	if (n > 0)
		r->len += (size_t)n;
	va_start(ap, fmt);
	n = vstrsprintf(r->buf + r->len, r->cap - r->len, fmt, ap);
	va_end(ap);
	if (n > 0)
		r->len += (size_t)n;
	if (r->len + 1 < r->cap) {
		r->buf[r->len++] = '\n';
		r->buf[r->len] = '\0';
	}
}

static void note(struct reporter *r, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static void note(struct reporter *r, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (r->len + 8 >= r->cap)
		return;
	n = strscpy(r->buf + r->len, "note: ", r->cap - r->len);
	if (n > 0)
		r->len += (size_t)n;
	va_start(ap, fmt);
	n = vstrsprintf(r->buf + r->len, r->cap - r->len, fmt, ap);
	va_end(ap);
	if (n > 0)
		r->len += (size_t)n;
	if (r->len + 1 < r->cap) {
		r->buf[r->len++] = '\n';
		r->buf[r->len] = '\0';
	}
}

static int hex_bytes(const char *hex, __u8 *out, size_t cap, size_t *len)
{
	size_t n = strlen(hex);

	if (n & 1 || n / 2 > cap)
		return -EINVAL;
	*len = n / 2;
	return hex_decode(hex, out, n / 2);
}

static int check_signed(struct reporter *rep, const char *what,
			const char *attest_hex, const char *sig_hex,
			const struct shirudo_tpm_ecc_public *ak,
			const __u8 ak_name[SHIRUDO_TPM_NAME_LEN],
			const __u8 *nonce, size_t nonce_len,
			__u8 *attest, size_t attest_cap, size_t *attest_len,
			struct shirudo_tpm_attest *parsed)
{
	__u8 sig[SHIRUDO_TPM_SIGNATURE_MAX], r[32], s[32], digest[32];
	__u8 qn[SHIRUDO_TPM_NAME_LEN];
	size_t sig_len;
	int rc;

	if (hex_bytes(attest_hex, attest, attest_cap, attest_len) ||
	    hex_bytes(sig_hex, sig, sizeof(sig), &sig_len))
		return -EINVAL;
	if (tpm_attest_parse(attest, *attest_len, parsed)) {
		say(rep, false, "%s: attestation structure unparseable", what);
		return -EKEYREJECTED;
	}
	if (tpm_ecdsa_signature_parse(sig, sig_len, r, s)) {
		say(rep, false, "%s: signature structure unparseable", what);
		return -EKEYREJECTED;
	}
	shirudo_sha256(attest, *attest_len, digest);
	rc = ecdsa_p256_verify(ak->x, ak->y, digest, r, s);
	say(rep, rc == 0, "%s: ECDSA signature by the attestation key", what);
	tpm_qualified_name(SHIRUDO_TPM_RH_ENDORSEMENT, ak_name, qn);
	say(rep, parsed->signer_len == SHIRUDO_TPM_NAME_LEN &&
	    ct_eq(parsed->signer, qn, SHIRUDO_TPM_NAME_LEN),
	    "%s: signed by the key as an endorsement primary", what);
	say(rep, parsed->extra_len == nonce_len &&
	    (nonce_len == 0 || ct_eq(parsed->extra, nonce, nonce_len)),
	    "%s: carries the nonce", what);
	return 0;
}

int attest_verify(const char *evidence, size_t len,
		  const struct shirudo_attest_expect *expect,
		  char *report, size_t report_cap)
{
	struct reporter rep = { .buf = report, .cap = report_cap };
	struct shirudo_config_evidence config = {};
	struct shirudo_tpm_attest quote = {}, certify = {};
	struct shirudo_tpm_ecc_public ak_pub;
	__u8 ak_public[SHIRUDO_TPM_PUBLIC_MAX];
	__u8 ak_name[SHIRUDO_TPM_NAME_LEN];
	__u8 reg_name[SHIRUDO_TPM_NAME_LEN], reg_value[32];
	__u8 attest[SHIRUDO_TPM_ATTEST_MAX];
	__u8 nonce[SHIRUDO_ATTEST_NONCE_MAX], chain[32] = {};
	__u8 branch_written[32], branch_init[32], policy[32], bind[64];
	__u8 expected_name[SHIRUDO_TPM_NAME_LEN], pcr_expected[32];
	__u8 anchor_digest[32], cred[SHIRUDO_TPM_CREDENTIAL_LEN];
	struct parse *p;
	size_t ak_public_len, ak_name_len, nonce_len, attest_len;
	size_t reg_name_len, reg_value_len, cred_len = 0, i, runtime = 0;
	__u32 reg_index;
	__u32 bit;
	bool have_ek = false, have_cred = false;
	int rc = 0, qrc = -1, crc = -1;

	if (report_cap)
		report[0] = '\0';
	p = xcalloc(1, sizeof(*p));
	if (!p)
		return -ENOMEM;
	p->recs = xcalloc(RECORDS_MAX, sizeof(*p->recs));
	if (!p->recs) {
		xfree(p, sizeof(*p));
		return -ENOMEM;
	}
	p->rec_pcr = -1;
	p->rec_phase_pcr = -1;
	p->rec_reset = -1;

	{
		struct shirudo_json_array pcr_sink = { on_pcr, p };
		struct shirudo_json_array rec_sink = { on_record, p };
		struct shirudo_json_field pcr_sub[] = {
			{ "index", SHIRUDO_JSON_T_INT, &p->pcr_index, 0, 0,
			  NULL, 0 },
			{ "value", SHIRUDO_JSON_T_STRING, p->pcr_value_hex,
			  sizeof(p->pcr_value_hex), 0, NULL, 0 },
		};
		struct shirudo_json_field ak_sub[] = {
			{ "public", SHIRUDO_JSON_T_STRING, p->ak_public_hex,
			  sizeof(p->ak_public_hex), 0, NULL, 0 },
			{ "name", SHIRUDO_JSON_T_STRING, p->ak_name_hex,
			  sizeof(p->ak_name_hex), 0, NULL, 0 },
		};
		struct shirudo_json_field quote_sub[] = {
			{ "attest", SHIRUDO_JSON_T_STRING, p->quote_attest_hex,
			  sizeof(p->quote_attest_hex), 0, NULL, 0 },
			{ "signature", SHIRUDO_JSON_T_STRING, p->quote_sig_hex,
			  sizeof(p->quote_sig_hex), 0, NULL, 0 },
		};
		struct shirudo_json_field ek_sub[] = {
			{ "type", SHIRUDO_JSON_T_STRING, p->ek_type,
			  sizeof(p->ek_type), 0, NULL, 0 },
			{ "public", SHIRUDO_JSON_T_STRING, p->ek_public_hex,
			  sizeof(p->ek_public_hex), 0, NULL, 0 },
			{ "name", SHIRUDO_JSON_T_STRING, p->ek_name_hex,
			  sizeof(p->ek_name_hex), 0, NULL, 0 },
		};
		struct shirudo_json_field cred_sub[] = {
			{ "value", SHIRUDO_JSON_T_STRING, p->cred_hex,
			  sizeof(p->cred_hex), 0, NULL, 0 },
		};
		struct shirudo_json_field reg_sub[] = {
			{ "nv_index", SHIRUDO_JSON_T_STRING, p->reg_index,
			  sizeof(p->reg_index), 0, NULL, 0 },
			{ "pcr", SHIRUDO_JSON_T_INT, &p->reg_pcr, 0, 0, NULL,
			  0 },
			{ "name", SHIRUDO_JSON_T_STRING, p->reg_name_hex,
			  sizeof(p->reg_name_hex), 0, NULL, 0 },
			{ "value", SHIRUDO_JSON_T_STRING, p->reg_value_hex,
			  sizeof(p->reg_value_hex), 0, NULL, 0 },
			{ "attest", SHIRUDO_JSON_T_STRING, p->reg_attest_hex,
			  sizeof(p->reg_attest_hex), 0, NULL, 0 },
			{ "signature", SHIRUDO_JSON_T_STRING, p->reg_sig_hex,
			  sizeof(p->reg_sig_hex), 0, NULL, 0 },
		};
		struct shirudo_json_field upatch_sub[] = {
			{ "name", SHIRUDO_JSON_T_STRING, p->upatch_name,
			  sizeof(p->upatch_name), 0, NULL, 0 },
			{ "payload_sha256", SHIRUDO_JSON_T_STRING,
			  p->upatch_payload_hex, sizeof(p->upatch_payload_hex),
			  0, NULL, 0 },
		};
		struct shirudo_json_field key_sub[] = {
			{ "fingerprint", SHIRUDO_JSON_T_STRING,
			  p->key_fingerprint, sizeof(p->key_fingerprint), 0,
			  NULL, 0 },
			{ "cert_sha256", SHIRUDO_JSON_T_STRING, p->key_sha_hex,
			  sizeof(p->key_sha_hex), 0, NULL, 0 },
		};
		struct shirudo_json_field tree_sub[] = {
			{ "seq", SHIRUDO_JSON_T_INT, &p->tree_seq, 0, 0, NULL,
			  0 },
			{ "op", SHIRUDO_JSON_T_STRING, p->tree_op,
			  sizeof(p->tree_op), 0, NULL, 0 },
			{ "id", SHIRUDO_JSON_T_STRING, p->tree_id,
			  sizeof(p->tree_id), 0, NULL, 0 },
			{ "operation_digest", SHIRUDO_JSON_T_STRING,
			  p->tree_digest_hex, sizeof(p->tree_digest_hex), 0,
			  NULL, 0 },
		};
		struct shirudo_json_field rec_sub[] = {
			{ "type", SHIRUDO_JSON_T_STRING, p->type,
			  sizeof(p->type), 0, NULL, 0 },
			{ "digest", SHIRUDO_JSON_T_STRING, p->digest_hex,
			  sizeof(p->digest_hex), 0, NULL, 0 },
			{ "pcr", SHIRUDO_JSON_T_INT, &p->rec_pcr, 0, 0, NULL,
			  0 },
			{ "tpm_reset_count", SHIRUDO_JSON_T_INT, &p->rec_reset,
			  0, 0, NULL, 0 },
			{ "pcr_before", SHIRUDO_JSON_T_STRING,
			  p->pcr_before_hex, sizeof(p->pcr_before_hex), 0,
			  NULL, 0 },
			{ "phase_pcr", SHIRUDO_JSON_T_INT, &p->rec_phase_pcr, 0,
			  0, NULL, 0 },
			{ "phase_before", SHIRUDO_JSON_T_STRING,
			  p->phase_before_hex, sizeof(p->phase_before_hex), 0,
			  NULL, 0 },
			{ "bound_in", SHIRUDO_JSON_T_STRING, p->bound_in,
			  sizeof(p->bound_in), 0, NULL, 0 },
			{ "nv_name", SHIRUDO_JSON_T_STRING, p->nv_name_hex,
			  sizeof(p->nv_name_hex), 0, NULL, 0 },
			{ "anchor", SHIRUDO_JSON_T_STRING, p->anchor,
			  sizeof(p->anchor), 0, NULL, 0 },
			{ "anchor_digest", SHIRUDO_JSON_T_STRING,
			  p->anchor_digest_hex, sizeof(p->anchor_digest_hex), 0,
			  NULL, 0 },
			{ "chain", SHIRUDO_JSON_T_STRING, p->chain_hex,
			  sizeof(p->chain_hex), 0, NULL, 0 },
			{ "upatch", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0,
			  upatch_sub, ARRAY_SIZE(upatch_sub) },
			{ "tree", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, tree_sub,
			  ARRAY_SIZE(tree_sub) },
			{ "key", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, key_sub,
			  ARRAY_SIZE(key_sub) },
		};
		struct shirudo_json_field top[] = {
			{ "nonce", SHIRUDO_JSON_T_STRING, p->nonce_hex,
			  sizeof(p->nonce_hex), 0, NULL, 0 },
			{ "pcr_mask", SHIRUDO_JSON_T_INT, &p->pcr_mask, 0, 0,
			  NULL, 0 },
			{ "pcrs", SHIRUDO_JSON_T_ARRAY, &pcr_sink, 0, 0,
			  pcr_sub, ARRAY_SIZE(pcr_sub) },
			{ "ak", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, ak_sub,
			  ARRAY_SIZE(ak_sub) },
			{ "quote", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, quote_sub,
			  ARRAY_SIZE(quote_sub) },
			{ "register", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0,
			  reg_sub, ARRAY_SIZE(reg_sub) },
			{ "eventlog", SHIRUDO_JSON_T_ARRAY, &rec_sink, 0, 0,
			  rec_sub, ARRAY_SIZE(rec_sub) },
			{ "ek", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, ek_sub,
			  ARRAY_SIZE(ek_sub) },
			{ "credential", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0,
			  cred_sub, ARRAY_SIZE(cred_sub) },
		};

		rc = json_parse(evidence, len, top, ARRAY_SIZE(top));
		if (rc || !top[0].seen || !top[1].seen || !top[2].seen ||
		    !top[3].seen || !top[4].seen || !top[5].seen ||
		    !top[6].seen) {
			rc = -EINVAL;
			goto out;
		}
		have_ek = ek_sub[0].seen && ek_sub[1].seen && ek_sub[2].seen;
		have_cred = cred_sub[0].seen;
	}

	rc = shirudo_config_evidence_parse(evidence, len, &config);
	if (rc)
		goto out;

	/* Freshness: the document must answer this request. */
	if (hex_bytes(p->nonce_hex, nonce, sizeof(nonce), &nonce_len)) {
		rc = -EINVAL;
		goto out;
	}
	say(&rep, expect->nonce_len == nonce_len &&
	    (nonce_len == 0 ||
	     ct_eq(nonce, expect->nonce, nonce_len)),
	    "nonce matches the request");

	if (hex_bytes(p->ak_public_hex, ak_public, sizeof(ak_public),
		      &ak_public_len) ||
	    hex_bytes(p->ak_name_hex, ak_name, sizeof(ak_name), &ak_name_len) ||
	    ak_name_len != SHIRUDO_TPM_NAME_LEN) {
		rc = -EINVAL;
		goto out;
	}
	if (tpm_ecc_public_parse(ak_public, ak_public_len, &ak_pub)) {
		say(&rep, false, "attestation key: public area is not a "
		    "P-256 ECDSA key");
		rc = -EKEYREJECTED;
		goto out;
	}
	say(&rep, (ak_pub.attrs & AK_ATTRS_REQUIRED) == AK_ATTRS_REQUIRED,
	    "attestation key: restricted, fixed to this TPM");
	{
		__u8 computed[SHIRUDO_TPM_NAME_LEN];

		tpm_object_name(ak_public, ak_public_len, computed);
		say(&rep, ct_eq(computed, ak_name, sizeof(computed)),
		    "attestation key: name matches its public area");
	}
	if (expect->have_ak_name)
		say(&rep, ct_eq(ak_name, expect->ak_name,
				SHIRUDO_TPM_NAME_LEN),
		    "attestation key: the pinned key");
	else
		note(&rep, "attestation key not pinned: name %s",
		     p->ak_name_hex);

	if (have_ek) {
		__u8 ek_public[SHIRUDO_TPM_PUBLIC_MAX];
		__u8 ek_name[SHIRUDO_TPM_NAME_LEN], computed[SHIRUDO_TPM_NAME_LEN];
		struct shirudo_tpm_public ek_pub;
		size_t ek_public_len, ek_name_len;
		bool parsed;

		if (hex_bytes(p->ek_public_hex, ek_public, sizeof(ek_public),
			      &ek_public_len) ||
		    hex_bytes(p->ek_name_hex, ek_name, sizeof(ek_name),
			      &ek_name_len) || ek_name_len != SHIRUDO_TPM_NAME_LEN) {
			rc = -EINVAL;
			goto out;
		}
		parsed = tpm_public_parse(ek_public, ek_public_len,
					  &ek_pub) == 0;
		tpm_object_name(ek_public, ek_public_len, computed);
		say(&rep, parsed && ct_eq(computed, ek_name,
					  SHIRUDO_TPM_NAME_LEN),
		    "endorsement key: name matches its public area");
		say(&rep, parsed && ek_pub.attrs == SHIRUDO_TPM_EK_ATTRS &&
		    ek_pub.policy_len == 32 &&
		    ct_eq(ek_pub.policy, shirudo_tpm_ek_policy, 32),
		    "endorsement key: TCG default template under the "
		    "endorsement policy");
	} else {
		note(&rep, "no endorsement key in the evidence");
	}
	if (expect->have_ek_name) {
		__u8 ek_name[SHIRUDO_TPM_NAME_LEN];
		size_t n;

		say(&rep, have_ek &&
		    !hex_bytes(p->ek_name_hex, ek_name, sizeof(ek_name), &n) &&
		    n == SHIRUDO_TPM_NAME_LEN &&
		    ct_eq(ek_name, expect->ek_name, SHIRUDO_TPM_NAME_LEN),
		    "endorsement key: the pinned key");
	}
	if (have_cred && hex_bytes(p->cred_hex, cred, sizeof(cred), &cred_len)) {
		rc = -EINVAL;
		goto out;
	}
	if (expect->have_credential)
		say(&rep, have_cred && cred_len == SHIRUDO_TPM_CREDENTIAL_LEN &&
		    ct_eq(cred, expect->credential,
			  SHIRUDO_TPM_CREDENTIAL_LEN),
		    "attestation key: activated the credential made for it "
		    "under the endorsement key");
	else if (have_cred)
		note(&rep, "a credential was activated but none is expected "
		     "(--expect-credential)");

	rc = check_signed(&rep, "quote", p->quote_attest_hex, p->quote_sig_hex,
			  &ak_pub, ak_name, nonce, nonce_len, attest,
			  sizeof(attest), &attest_len, &quote);
	if (rc == -EINVAL)
		goto out;
	qrc = rc;
	if (rc == 0) {
		struct shirudo_sha256_ctx ctx;
		__u8 digest[32] = {};
		bool complete =
			quote.type == SHIRUDO_TPM_ST_ATTEST_QUOTE &&
			quote.pcr_mask == (__u32)p->pcr_mask &&
			p->pcr_have == quote.pcr_mask;
		bool vouched;

		say(&rep, complete,
		    "quote: covers the PCRs the document lists");
		if (complete && sha256_init(&ctx) == 0) {
			for (bit = 0; bit < 24; bit++) {
				if (quote.pcr_mask & (1u << bit))
					sha256_update(&ctx,
						      p->pcrs[bit], 32);
			}
			sha256_final(&ctx, digest);
		}
		vouched = complete &&
			  ct_eq(digest, quote.pcr_digest, 32);
		say(&rep, vouched,
		    "quote: PCR digest matches the listed values");
		if (!vouched)
			p->pcr_have = 0;
	} else {
		p->pcr_have = 0;
	}

	rc = check_signed(&rep, "register", p->reg_attest_hex, p->reg_sig_hex,
			  &ak_pub, ak_name, nonce, nonce_len, attest,
			  sizeof(attest), &attest_len, &certify);
	if (rc == -EINVAL)
		goto out;
	crc = rc;
	if (hex_bytes(p->reg_name_hex, reg_name, sizeof(reg_name),
		      &reg_name_len) ||
	    reg_name_len != SHIRUDO_TPM_NAME_LEN ||
	    hex_bytes(p->reg_value_hex, reg_value, sizeof(reg_value),
		      &reg_value_len) || reg_value_len != 32 ||
	    sscanf(p->reg_index, "0x%x", &reg_index) != 1 ||
	    p->reg_pcr < 0 || p->reg_pcr >= 24) {
		rc = -EINVAL;
		goto out;
	}
	if (rc == 0) {
		say(&rep, certify.type == SHIRUDO_TPM_ST_ATTEST_NV &&
		    certify.index_name_len == SHIRUDO_TPM_NAME_LEN &&
		    ct_eq(certify.index_name, reg_name,
			  SHIRUDO_TPM_NAME_LEN),
		    "register: certification names the listed index");
		say(&rep, certify.type == SHIRUDO_TPM_ST_ATTEST_NV &&
		    certify.offset == 0 && certify.nv_len == 32 &&
		    ct_eq(certify.nv_data, reg_value, 32),
		    "register: certified contents match the listed value");
	}
	if (qrc == 0 && crc == 0)
		say(&rep, quote.reset_count == certify.reset_count &&
		    quote.firmware_version == certify.firmware_version,
		    "quote and certification are of one TPM reset");

	if (config.present || expect->have_config_root ||
	    expect->have_config_pcr) {
		const __u8 *root = expect->have_config_root ?
				      expect->config_root : NULL;
		const char *reason;
		int pcr;

		pcr = expect->have_config_pcr ? (int)expect->config_pcr : -1;
		rc = shirudo_config_evidence_verify(&config, quote.pcr_mask,
						    quote.reset_count,
						    quote.restart_count,
						    p->pcrs, root, pcr,
						    &reason);
		say(&rep, !rc, "config: %s", reason);
		if (config.present && !expect->have_config_root)
			note(&rep, "config root has no operator approval; use "
			     "--expect-config-root with --expect-config-pcr");
		if (config.present)
			note(&rep, "config records a selection; "
			     "direct TPM writer protection is deferred");
	}

	/*
	 * The binding: the certified index must have the public area a
	 * register bound to the recorded PCR values has, which is what
	 * makes a recreation impossible to pass off, and those values are
	 * what the operator pins to tell an initrd binding from a later one.
	 * The handle and the PCRs are the register's, never the document's:
	 * taken from the record, a target could certify an index of its own
	 * under a policy over PCRs it can extend and reset at will.
	 */
	say(&rep, p->init.present, "eventlog: this boot has an init record");
	if (!p->init.present) {
		rc = -EKEYREJECTED;
		goto out;
	}
	say(&rep, reg_index == SHIRUDO_NV_INDEX &&
	    (__u32)p->reg_pcr == SHIRUDO_CHAIN_PCR &&
	    p->init.pcr == SHIRUDO_CHAIN_PCR &&
	    p->init.phase_pcr == SHIRUDO_CHAIN_PHASE_PCR,
	    "register: the document names index 0x%08X and PCRs %u and %u",
	    SHIRUDO_NV_INDEX, SHIRUDO_CHAIN_PCR, SHIRUDO_CHAIN_PHASE_PCR);
	memcpy(bind, p->init.pcr_before, 32);
	memcpy(bind + 32, p->init.phase_before, 32);
	tpm_register_policy(SHIRUDO_CHAIN_PCR_MASK, bind, 2,
			    branch_written, branch_init, policy);
	tpm_nv_name(SHIRUDO_NV_INDEX,
		    SHIRUDO_TPM_REGISTER_ATTRS | SHIRUDO_TPM_NV_WRITTEN,
		    policy, 32, expected_name);
	say(&rep, ct_eq(expected_name, reg_name, SHIRUDO_TPM_NAME_LEN) &&
	    ct_eq(expected_name, p->init.name, SHIRUDO_TPM_NAME_LEN),
	    "register: public area is bound to PCRs %u and %u as recorded",
	    SHIRUDO_CHAIN_PCR, SHIRUDO_CHAIN_PHASE_PCR);
	for (bit = 0; bit < 24; bit++) {
		const __u8 *held;

		if (!(expect->bind_expect_mask & (1u << bit)))
			continue;
		held = bit == SHIRUDO_CHAIN_PCR ? p->init.pcr_before :
		       bit == SHIRUDO_CHAIN_PHASE_PCR ? p->init.phase_before :
		       NULL;
		say(&rep, held && ct_eq(held, expect->bind_values[bit],
					32),
		    "binding: PCR %u held the expected value", bit);
	}
	if (expect->require_initrd)
		say(&rep, p->init.initrd, "binding: made while the initrd ran");
	else
		note(&rep, "binding: made in the %s",
		     p->init.initrd ? "initrd" : "root file system");

	/*
	 * The epoch: one binding per TPM reset, and the one on record is
	 * of the reset the TPM certifies in, so no register bound again
	 * after boot can pass as the boot's.
	 */
	say(&rep, p->inits_epoch == 1,
	    "eventlog: one init record for this TPM reset (%u this boot)",
	    p->inits);
	if (crc == 0)
		say(&rep, p->init.have_reset_count &&
		    p->init.reset_count == certify.reset_count,
		    "register: init record is of the TPM's current reset "
		    "count");

	for (i = 0; i < p->n_recs; i++) {
		chain_fold(chain, p->recs[i].digest);
		if (i)
			runtime++;
	}
	say(&rep, ct_eq(chain, reg_value, 32),
	    "eventlog: %zu record%s replay to the certified value", p->n_recs,
	    p->n_recs == 1 ? "" : "s");
	/*
	 * A digest the record's own fields do not produce is a record
	 * relabelled after the fact: the replay still closes, but what the
	 * events say happened is not what was measured.
	 */
	for (i = 1; i < p->n_recs; i++) {
		if (!p->recs[i].derived)
			say(&rep, false, "eventlog: event %zu (%s %s) digest "
			    "does not derive from its fields", i,
			    p->recs[i].type, p->recs[i].label);
	}

	{
		char anchor[SHIRUDO_CHAIN_ANCHOR_MAX];
		bool named = !chain_anchor(p->init.name, anchor,
					   sizeof(anchor));

		shirudo_sha256(anchor, strlen(anchor), anchor_digest);
		say(&rep, named && ct_eq(anchor_digest, p->init.anchor_digest,
					 32),
		    "anchor: record digest matches the index name");
		memcpy(pcr_expected, p->init.pcr_before, 32);
		chain_fold(pcr_expected, anchor_digest);
		if (p->pcr_have & (1u << SHIRUDO_CHAIN_PCR)) {
			bool exact = ct_eq(pcr_expected,
					   p->pcrs[SHIRUDO_CHAIN_PCR], 32);

			if (exact || expect->strict_anchor)
				say(&rep, exact, "anchor: PCR %u equals the "
				    "recorded value extended by the anchor",
				    SHIRUDO_CHAIN_PCR);
			else
				note(&rep, "anchor: PCR %u carries further "
				     "measurements after the anchor; replay "
				     "the logs to confirm it",
				     SHIRUDO_CHAIN_PCR);
		} else {
			say(&rep, false, "anchor: PCR %u is not in the quote",
			    SHIRUDO_CHAIN_PCR);
		}
	}

	if (expect->have_init)
		say(&rep, ct_eq(p->init.digest, expect->init_event, 32),
		    "state: init event covers the expected certificate, set "
		    "and tree root");
	if (expect->have_chain) {
		say(&rep, ct_eq(reg_value, expect->chain, 32),
		    "state: register equals the expected value");
	} else if (expect->have_init) {
		__u8 predicted[32] = {};

		chain_fold(predicted, expect->init_event);
		if (runtime == 0)
			say(&rep, ct_eq(reg_value, predicted, 32),
			    "state: register equals the value predicted for "
			    "the set at boot");
		else
			say(&rep, expect->allow_runtime_events,
			    "state: %zu event%s after boot change the register",
			    runtime, runtime == 1 ? "" : "s");
	} else {
		note(&rep, "no expected state given; the register value is "
		     "%s", p->reg_value_hex);
	}
	for (i = 1; i < p->n_recs; i++)
		note(&rep, "event after boot: %s %s", p->recs[i].type,
		     p->recs[i].label);
	for (bit = 0; bit < 24; bit++) {
		if (!(expect->pcr_expect_mask & (1u << bit)))
			continue;
		say(&rep, (p->pcr_have & (1u << bit)) &&
		    ct_eq(p->pcrs[bit], expect->pcrs[bit], 32),
		    "PCR %u matches the expected value", bit);
	}
	rc = rep.failed ? -EKEYREJECTED : 0;
out:
	shirudo_config_evidence_clear(&config);
	xfree(p->recs, RECORDS_MAX * sizeof(*p->recs));
	xfree(p, sizeof(*p));
	return rc;
}

int attest_challenge_read(const char *path,
			  struct shirudo_attest_challenge *out)
{
	char blob_hex[2 * SHIRUDO_TPM_ID_OBJECT_LEN + 1], secret_hex[2 * 256 + 1];
	char ak_hex[2 * SHIRUDO_TPM_NAME_LEN + 1], kind[32], type[8];
	struct shirudo_json_field ek_sub[] = {
		{ "type", SHIRUDO_JSON_T_STRING, type, sizeof(type), 0, NULL,
		  0 },
	};
	struct shirudo_json_field top[] = {
		{ "kind", SHIRUDO_JSON_T_STRING, kind, sizeof(kind), 0, NULL,
		  0 },
		{ "ek", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, ek_sub,
		  ARRAY_SIZE(ek_sub) },
		{ "ak_name", SHIRUDO_JSON_T_STRING, ak_hex, sizeof(ak_hex), 0,
		  NULL, 0 },
		{ "credential_blob", SHIRUDO_JSON_T_STRING, blob_hex,
		  sizeof(blob_hex), 0, NULL, 0 },
		{ "secret", SHIRUDO_JSON_T_STRING, secret_hex,
		  sizeof(secret_hex), 0, NULL, 0 },
	};
	size_t len, ak_len;
	char *doc;
	int rc;

	memset(out, 0, sizeof(*out));
	kind[0] = '\0';
	type[0] = '\0';
	ak_hex[0] = '\0';
	blob_hex[0] = '\0';
	secret_hex[0] = '\0';
	rc = read_file(path, SHIRUDO_ATTEST_CHALLENGE_MAX, &doc, &len);
	if (rc)
		return rc;
	rc = json_parse(doc, len, top, ARRAY_SIZE(top));
	xfree(doc, len + 1);
	if (rc || !top[0].seen || strcmp(kind, "shirudo-credential") ||
	    !ek_sub[0].seen || !top[2].seen || !top[3].seen || !top[4].seen)
		return -EINVAL;
	if (!strcmp(type, "rsa"))
		out->ek_rsa = true;
	else if (strcmp(type, "ecc"))
		return -EINVAL;
	if (hex_bytes(ak_hex, out->ak_name, sizeof(out->ak_name), &ak_len) ||
	    ak_len != SHIRUDO_TPM_NAME_LEN ||
	    hex_bytes(blob_hex, out->blob, sizeof(out->blob), &out->blob_len) ||
	    out->blob_len != SHIRUDO_TPM_ID_OBJECT_LEN ||
	    hex_bytes(secret_hex, out->secret, sizeof(out->secret),
		      &out->secret_len) || !out->secret_len)
		return -EINVAL;
	return 0;
}

/* The certificate's key must be the endorsement key of the evidence. */
static bool cert_describes(const struct cert_pubkey *key,
			   const struct shirudo_tpm_public *pub)
{
	if (key->rsa != (pub->type == SHIRUDO_TPM_ALG_RSA))
		return false;
	if (key->rsa)
		return key->n_len == pub->n_len &&
		       ct_eq(key->n, pub->n, pub->n_len) &&
		       key->e == (pub->rsa_exponent ? pub->rsa_exponent : 65537);
	return ct_eq(key->x, pub->x, 32) &&
	       ct_eq(key->y, pub->y, 32);
}

int attest_challenge_make(const char *evidence, size_t len,
			  const struct shirudo_attest_challenge_policy *pol,
			  __u8 credential[SHIRUDO_TPM_CREDENTIAL_LEN],
			  char **out, size_t *out_len, size_t *cap,
			  char *report, size_t report_cap)
{
	const char *ek_ca = pol->ek_ca;
	bool vouched = pol->ek_name || pol->trust_presented;
	struct reporter rep = { .buf = report, .cap = report_cap };
	char ek_public_hex[2 * SHIRUDO_TPM_PUBLIC_MAX + 1], hex[2 * 256 + 1];
	char ak_hex[2 * SHIRUDO_TPM_NAME_LEN + 1], ek_type[8];
	char ek_name_hex[2 * SHIRUDO_TPM_NAME_LEN + 1];
	__u8 ak_name[SHIRUDO_TPM_NAME_LEN], ek_name[SHIRUDO_TPM_NAME_LEN];
	__u8 ek_public[SHIRUDO_TPM_PUBLIC_MAX], computed[SHIRUDO_TPM_NAME_LEN];
	__u8 seed[32], z[32], eph_x[32], eph_y[32], secret[256];
	__u8 blob[SHIRUDO_TPM_ID_OBJECT_LEN], *der = NULL;
	struct cert_pubkey cert_key;
	struct shirudo_tpm_public pub;
	struct shirudo_cert cert = {};
	struct shirudo_json_emit e;
	struct shirudo_json_field ak_sub[] = {
		{ "name", SHIRUDO_JSON_T_STRING, ak_hex, sizeof(ak_hex), 0,
		  NULL, 0 },
	};
	struct shirudo_json_field ek_sub[] = {
		{ "type", SHIRUDO_JSON_T_STRING, ek_type, sizeof(ek_type), 0,
		  NULL, 0 },
		{ "public", SHIRUDO_JSON_T_STRING, ek_public_hex,
		  sizeof(ek_public_hex), 0, NULL, 0 },
		{ "name", SHIRUDO_JSON_T_STRING, ek_name_hex,
		  sizeof(ek_name_hex), 0, NULL, 0 },
	};
	char *cert_b64 = xmalloc(EK_CERT_B64_MAX);
	struct shirudo_json_field top[] = {
		{ "ak", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, ak_sub,
		  ARRAY_SIZE(ak_sub) },
		{ "ek", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, ek_sub,
		  ARRAY_SIZE(ek_sub) },
		{ "ek_certificate", SHIRUDO_JSON_T_STRING, cert_b64,
		  EK_CERT_B64_MAX, 0, NULL, 0 },
	};
	size_t ak_len, ek_public_len, ek_name_len, secret_len = 0, der_len = 0;
	const char *reason = "";
	int rc = -EINVAL;
	bool rsa;

	*out = NULL;
	*out_len = 0;
	*cap = 0;
	if (report_cap)
		report[0] = '\0';
	if (!cert_b64)
		return -ENOMEM;
	cert_b64[0] = '\0';
	ak_hex[0] = '\0';
	ek_type[0] = '\0';
	ek_public_hex[0] = '\0';
	ek_name_hex[0] = '\0';
	if (json_parse(evidence, len, top, ARRAY_SIZE(top)) ||
	    !ak_sub[0].seen || !ek_sub[0].seen || !ek_sub[1].seen ||
	    !ek_sub[2].seen ||
	    hex_bytes(ak_hex, ak_name, sizeof(ak_name), &ak_len) ||
	    ak_len != SHIRUDO_TPM_NAME_LEN ||
	    hex_bytes(ek_public_hex, ek_public, sizeof(ek_public),
		      &ek_public_len) ||
	    hex_bytes(ek_name_hex, ek_name, sizeof(ek_name), &ek_name_len) ||
	    ek_name_len != SHIRUDO_TPM_NAME_LEN)
		goto out;
	if (!strcmp(ek_type, "rsa"))
		rsa = true;
	else if (!strcmp(ek_type, "ecc"))
		rsa = false;
	else
		goto out;
	if (tpm_public_parse(ek_public, ek_public_len, &pub) ||
	    pub.type != (rsa ? SHIRUDO_TPM_ALG_RSA : SHIRUDO_TPM_ALG_ECC))
		goto out;

	/*
	 * The operator's pins come first: the challenge is for the key the
	 * operator enrolled, not for whatever the document names.
	 */
	if (pol->ak_name)
		say(&rep, ct_eq(ak_name, pol->ak_name,
				SHIRUDO_TPM_NAME_LEN),
		    "attestation key: the pinned key");
	if (pol->ek_name)
		say(&rep, ct_eq(ek_name, pol->ek_name,
				SHIRUDO_TPM_NAME_LEN),
		    "endorsement key: the pinned key");

	/* The key must be an endorsement key, not any decryption key. */
	tpm_object_name(ek_public, ek_public_len, computed);
	say(&rep, ct_eq(computed, ek_name, SHIRUDO_TPM_NAME_LEN),
	    "endorsement key: name matches its public area");
	say(&rep, pub.attrs == SHIRUDO_TPM_EK_ATTRS && pub.policy_len == 32 &&
	    ct_eq(pub.policy, shirudo_tpm_ek_policy, 32),
	    "endorsement key: TCG default template under the endorsement "
	    "policy");
	if (top[2].seen) {
		der = xmalloc(EK_CERT_MAX);
		if (!der) {
			rc = -ENOMEM;
			goto out;
		}
		if (base64_decode(cert_b64, strlen(cert_b64), der,
				  EK_CERT_MAX, &der_len) ||
		    cert_read_der(der, der_len, &cert) ||
		    cert_pubkey(&cert, &cert_key)) {
			say(&rep, false, "endorsement certificate: parseable "
			    "with a P-256 or RSA-2048 key");
		} else {
			say(&rep, cert_describes(&cert_key, &pub),
			    "endorsement certificate: describes the "
			    "endorsement key");
			if (ek_ca) {
				int vrc = cert_verify_chain(&cert, ek_ca,
							    &reason);

				if (vrc == -EINVAL)
					say(&rep, false, "endorsement "
					    "certificate: issuer bundle %s "
					    "unreadable", ek_ca);
				else
					say(&rep, vrc == 0, "endorsement "
					    "certificate: chains to %s%s%s",
					    ek_ca, vrc ? ": " : "",
					    vrc ? reason : "");
			} else if (vouched) {
				note(&rep, "endorsement certificate: not "
				     "checked against an issuer bundle "
				     "(--ek-ca)");
			} else {
				say(&rep, false, "endorsement certificate: "
				    "not checked against an issuer bundle; "
				    "pass --ek-ca, pin the key with "
				    "--ek-name or waive with "
				    "--trust-presented-ek");
			}
		}
	} else if (vouched) {
		note(&rep, "no endorsement certificate: the endorsement key "
		     "is trusted as presented");
	} else {
		say(&rep, false, "no endorsement certificate: pin the key "
		    "with --ek-name or waive with --trust-presented-ek");
	}
	if (rep.failed) {
		rc = -EKEYREJECTED;
		goto out;
	}

	rc = -EIO;
	if (getrandom(credential, SHIRUDO_TPM_CREDENTIAL_LEN, 0) !=
	    SHIRUDO_TPM_CREDENTIAL_LEN)
		goto out;
	if (rsa) {
		if (getrandom(seed, sizeof(seed), 0) != (ssize_t)sizeof(seed) ||
		    rsa_oaep_encrypt(pub.n, pub.n_len, pub.rsa_exponent,
				     "IDENTITY", sizeof("IDENTITY"),
				     seed, sizeof(seed), secret,
				     sizeof(secret), &secret_len))
			goto out;
	} else {
		if (ecdh_p256_ephemeral(pub.x, pub.y, eph_x, eph_y, z))
			goto out;
		tpm_kdfe(z, "IDENTITY", eph_x, 32, pub.x, 32, seed);
		secret[0] = 0;
		secret[1] = 32;
		memcpy(secret + 2, eph_x, 32);
		secret[34] = 0;
		secret[35] = 32;
		memcpy(secret + 36, eph_y, 32);
		secret_len = 68;
	}
	if (tpm_credential_protect(seed, ak_name, credential, blob))
		goto out;

	*cap = 4096;
	*out = xmalloc(*cap);
	if (!*out) {
		rc = -ENOMEM;
		goto out;
	}
	e = (struct shirudo_json_emit){ .buf = *out, .cap = *cap };
	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_kv_string(&e, "kind", "shirudo-credential");
	json_obj_open_key(&e, "ek");
	json_kv_string(&e, "type", rsa ? "rsa" : "ecc");
	json_kv_string(&e, "name", ek_name_hex);
	json_obj_close(&e);
	json_kv_string(&e, "ak_name", ak_hex);
	hex_encode(blob, sizeof(blob), hex);
	json_kv_string(&e, "credential_blob", hex);
	hex_encode(secret, secret_len, hex);
	json_kv_string(&e, "secret", hex);
	json_obj_close(&e);
	if (e.err) {
		rc = e.err;
		goto out;
	}
	(*out)[e.len] = '\0';
	*out_len = e.len;
	rc = 0;
out:
	explicit_bzero(seed, sizeof(seed));
	explicit_bzero(z, sizeof(z));
	cert_free(&cert);
	xfree(der, der ? EK_CERT_MAX : 0);
	xfree(cert_b64, EK_CERT_B64_MAX);
	if (rc) {
		explicit_bzero(credential, SHIRUDO_TPM_CREDENTIAL_LEN);
		if (*out) {
			xfree(*out, *cap);
			*out = NULL;
			*cap = 0;
		}
	}
	return rc;
}
