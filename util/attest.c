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
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include "attest.h"
#include "chain.h"
#include "crypto.h"
#include "config_attest.h"
#include "config_measure.h"
#include "eventlog.h"
#include "hex.h"
#include "io.h"
#include "json.h"
#include "log.h"
#include "malloc.h"
#include "paths.h"
#include "tpm.h"
#include "upatch.h"
#include "version.h"

#define FIRMWARE_LOG_PATH \
	"/sys/kernel/security/tpm0/binary_bios_measurements"
#define SYSTEMD_LOG_PATH	"/run/log/systemd/tpm2-measure.log"
#define LOG_MAX_BYTES		(2u * 1024u * 1024u)
#define EK_CERT_MAX		4096
#define QUOTE_ATTEMPTS		3
#define RECORDS_MAX		4096
#define EK_CERT_B64_MAX		BASE64_SIZE(EK_CERT_MAX)
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
	int fd, ret = 0;

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
			ret = -errno;
		if (got <= 0)
			break;
		len += (size_t)got;
	}
	close(fd);
	if (!ret && (len == 0 || len > LOG_MAX_BYTES))
		ret = -EFBIG;
	if (ret) {
		xfree(raw, LOG_MAX_BYTES + 1);
		return ret;
	}
	cap = BASE64_SIZE(len);
	*out = xmalloc(cap);
	ret = *out ? base64_encode(raw, len, *out, cap) : -ENOMEM;
	xfree(raw, LOG_MAX_BYTES + 1);
	if (ret) {
		xfree(*out, cap);
		*out = NULL;
		return ret;
	}
	*out_cap = cap;
	return 0;
}

static int emit_line(const char *line, size_t len, void *ctx)
{
	json_raw(ctx, line, len);
	return 0;
}

static void emit_hex(struct json_emit *e, const char *key,
		     const __u8 *data, size_t len)
{
	char hex[2 * TPM_ATTEST_MAX + 1];

	if (len > TPM_ATTEST_MAX) {
		e->err = -E2BIG;
		return;
	}
	hex_encode(data, len, hex);
	json_kv_string(e, key, hex);
}

/* The PCR digest a quote of the PCRs in mask carries for these values. */
static int pcr_values_digest(__u32 mask, const __u8 values[24][32],
			     __u8 digest[32])
{
	struct sha256_ctx ctx;
	__u32 i;
	int ret;

	ret = sha256_init(&ctx);
	if (ret)
		return ret;
	for (i = 0; i < 24; i++) {
		if (!(mask & (1u << i)))
			continue;
		ret = sha256_update(&ctx, values[i], 32);
		if (ret) {
			sha256_free(&ctx);
			return ret;
		}
	}
	return sha256_final(&ctx, digest);
}

/* A quote is accepted only when it covers the PCR values read beside it. */
static bool quote_covers(const struct tpm_attestation *quote,
			 __u32 mask, __u8 values[24][32])
{
	struct tpm_attest a;
	__u8 digest[32];

	if (tpm_attest_parse(quote->attest, quote->attest_len, &a) ||
	    a.type != TPM_ST_ATTEST_QUOTE || a.pcr_mask != mask)
		return false;
	if (pcr_values_digest(mask, values, digest))
		return false;
	return !memneq_explicit(digest, a.pcr_digest, 32);
}

/*
 * Both NV indexes are extend-only within the boot. Certify each on both
 * sides of one PCR quote. The quote commits to the opening signatures,
 * and the closing certifications commit to the quote signature. Including
 * the TPM signatures establishes order even when TPM clock ticks coincide.
 */
static int snapshot_quote_nonce(const struct tpm_attestation *reg,
				const struct tpm_attestation *config,
				__u8 nonce[32])
{
	__u8 hashes[2][32] = {};
	int ret;

	ret = sha256_buffer(reg->signature, reg->signature_len, hashes[0]);
	if (!ret && config->signature_len)
		ret = sha256_buffer(config->signature, config->signature_len,
				    hashes[1]);
	return ret ? ret : sha256_buffer(hashes, sizeof(hashes), nonce);
}

static bool same_nv(const struct tpm_attest *a, const struct tpm_attest *b)
{
	return a->type == TPM_ST_ATTEST_NV && b->type == TPM_ST_ATTEST_NV &&
	       a->reset_count == b->reset_count &&
	       a->restart_count == b->restart_count &&
	       a->firmware_version == b->firmware_version &&
	       a->offset == 0 && b->offset == 0 &&
	       a->index_name_len == TPM_NAME_LEN && b->index_name_len == TPM_NAME_LEN &&
	       !memcmp(a->index_name, b->index_name, TPM_NAME_LEN) &&
	       a->nv_len == 32 && b->nv_len == 32 &&
	       !memcmp(a->nv_data, b->nv_data, 32);
}

static int certify_after_quote(struct tpm *tpm, struct tpm_key *ak, __u32 index,
			       const __u8 nonce[32],
			       const struct tpm_attestation *before,
			       struct tpm_attestation *after)
{
	struct tpm_attest a, b;
	int ret;

	ret = tpm_nv_certify(tpm, ak, index, nonce, 32, after);
	if (ret)
		return ret;
	if (tpm_attest_parse(before->attest, before->attest_len, &a) ||
	    tpm_attest_parse(after->attest, after->attest_len, &b))
		return -EBADMSG;
	return same_nv(&a, &b) ? 0 : -EAGAIN;
}

static void emit_certification(struct json_emit *e,
			       const struct tpm_attestation *before,
			       const struct tpm_attestation *after)
{
	emit_hex(e, "attest", before->attest, before->attest_len);
	emit_hex(e, "signature", before->signature, before->signature_len);
	emit_hex(e, "after_attest", after->attest, after->attest_len);
	emit_hex(e, "after_signature", after->signature, after->signature_len);
}

int attest_evidence_config(const __u8 *nonce, size_t nonce_len,
			   __u32 pcr_mask,
			   const struct attest_challenge *c,
			   struct config_update *update,
			   char **out, size_t *len, size_t *cap)
{
	const struct attest_challenge *challenge = c;
	struct tpm_key ak = { .handle = 0 }, ek = { .handle = 0 };
	struct tpm_key ak_copy = {}, ek_copy = {};
	struct tpm_attestation quote = {}, certify = {};
	struct tpm_attestation config_certify = {}, config_after = {};
	struct tpm_attestation reg_after = {};
	__u8 quote_nonce[32], after_nonce[32];
	struct config_evidence config = {};
	struct tpm_attest quoted, certified;
	struct tpm_nv_info nv, config_nv = {};
	struct tpm *tpm = NULL;
	struct json_emit e;
	__u8 values[24][32] = {};
	__u8 reg[32], cred[TPM_CREDENTIAL_LEN], *ek_cert = NULL;
	size_t ek_cert_len = 0, ek_b64_cap = 0, fw_cap = 0, sd_cap = 0, need;
	size_t cred_len = 0;
	char *ek_b64 = NULL, *fw = NULL, *sd = NULL;
	char ts[32], boot_id[64], nv_index[16], nonce_hex[2 * 64 + 1];
	struct stat st;
	__u32 i, attempt;
	bool ek_cert_rsa = false, ek_rsa, nvpcr;
	int ret;

	*out = NULL;
	*len = 0;
	*cap = 0;
	if (nonce_len > ATTEST_NONCE_MAX || !pcr_mask ||
	    (pcr_mask & ~0x00FFFFFFu))
		return -EINVAL;

	ret = config_evidence_collect(update, &config);
	if (ret)
		return ret;
	nvpcr = config.present && config_measure_nvpcr(config.pcr);
	if (config.present && !nvpcr)
		pcr_mask |= 1u << config.pcr;
	ret = tpm_open(&tpm);
	if (ret) {
		ret = -ENXIO;
		goto out;
	}
	ret = tpm_nv_info(tpm, NV_INDEX, &nv);
	if (ret)
		goto out;
	if (!nv.defined || !nv.written) {
		ret = -ENODEV;
		goto out;
	}
	ret = tpm_ak_create(tpm, &ak);
	if (ret)
		goto out;
	ret = tpm_nv_certify(tpm, &ak, NV_INDEX, nonce, nonce_len, &certify);
	if (ret)
		goto out;
	if (tpm_attest_parse(certify.attest, certify.attest_len, &certified) ||
	    certified.type != TPM_ST_ATTEST_NV || certified.nv_len != sizeof(reg)) {
		ret = -EBADMSG;
		goto out;
	}
	memcpy(reg, certified.nv_data, sizeof(reg));
	if (nvpcr) {
		ret = tpm_nv_info(tpm, config.pcr, &config_nv);
		if (!ret)
			ret = tpm_nv_certify(tpm, &ak, config.pcr, nonce,
					     nonce_len, &config_certify);
		if (ret)
			goto out;
		if (tpm_attest_parse(config_certify.attest,
				     config_certify.attest_len, &certified) ||
		    certified.reset_count != config.reset_count ||
		    certified.restart_count != config.restart_count ||
		    certified.offset != 0 || certified.nv_len != 32 ||
		    memcmp(certified.nv_data, config.value, 32)) {
			ret = -EUCLEAN;
			goto out;
		}
	}
	ret = snapshot_quote_nonce(&certify, &config_certify, quote_nonce);
	if (ret)
		goto out;
	for (attempt = 0; attempt < QUOTE_ATTEMPTS; attempt++) {
		for (i = 0; i < 24; i++) {
			if (!(pcr_mask & (1u << i)))
				continue;
			ret = tpm_pcr_read(tpm, i, values[i]);
			if (ret)
				goto out;
		}
		ret = tpm_quote(tpm, &ak, quote_nonce, sizeof(quote_nonce),
				pcr_mask, &quote);
		if (ret)
			goto out;
		if (quote_covers(&quote, pcr_mask, values))
			break;
	}
	if (attempt == QUOTE_ATTEMPTS) {
		pr_err("attest: PCRs kept changing while quoting");
		ret = -EAGAIN;
		goto out;
	}
	if (config.present &&
	    (tpm_attest_parse(quote.attest, quote.attest_len,
				      &quoted) ||
	     quoted.reset_count != config.reset_count ||
	     (!nvpcr && memcmp(values[config.pcr],
			       config.value, 32)))) {
		ret = -EUCLEAN;
		goto out;
	}
	ret = sha256_buffer(quote.signature, quote.signature_len, after_nonce);
	if (!ret && nvpcr)
		ret = certify_after_quote(tpm, &ak, config.pcr, after_nonce,
					  &config_certify, &config_after);
	if (!ret)
		ret = certify_after_quote(tpm, &ak, NV_INDEX, after_nonce,
					  &certify, &reg_after);
	if (ret)
		goto out;
	ek_cert = xmalloc(EK_CERT_MAX);
	if (!ek_cert) {
		ret = -ENOMEM;
		goto out;
	}
	if (tpm_ek_certificate(tpm, ek_cert, EK_CERT_MAX, &ek_cert_len,
			       &ek_cert_rsa) == 0) {
		ek_b64_cap = BASE64_SIZE(ek_cert_len);
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
	ret = tpm_ek_create(tpm, ek_rsa, &ek);
	if (ret)
		goto out;
	if (challenge) {
		if (ak.name_len != TPM_NAME_LEN ||
		    memcmp(challenge->ak_name, ak.name, TPM_NAME_LEN)) {
			pr_err("attest: the challenge was made for another "
			       "attestation key");
			ret = -EKEYREJECTED;
			goto out;
		}
		ret = tpm_activate_credential(tpm, &ak, &ek,
					      challenge->blob,
					      challenge->blob_len,
					      challenge->secret,
					      challenge->secret_len,
					      cred, sizeof(cred),
					      &cred_len);
		if (ret) {
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
		need = size_add(need, size_mul(2, st.st_size));
	if (need > JSON_MAX_BYTES)
		need = JSON_MAX_BYTES;
	*out = xmalloc(need);
	if (!*out) {
		ret = -ENOMEM;
		goto out;
	}
	*cap = need;

	eventlog_timestamp(ts, sizeof(ts));
	eventlog_boot_id(boot_id, sizeof(boot_id));
	if (strsprintf(nv_index, sizeof(nv_index), "0x%08X",
		       NV_INDEX) < 0) {
		ret = -E2BIG;
		goto out;
	}
	hex_encode(nonce, nonce_len, nonce_hex);

	e = (struct json_emit){ .buf = *out, .cap = need };
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
	json_kv_int(&e, "pcr", CHAIN_PCR);
	emit_hex(&e, "name", nv.name, nv.name_len);
	emit_hex(&e, "value", reg, sizeof(reg));
	emit_certification(&e, &certify, &reg_after);
	json_obj_close(&e);
	if (nvpcr) {
		json_obj_open_key(&e, "config_nvpcr");
		emit_hex(&e, "name", config_nv.name, config_nv.name_len);
		emit_certification(&e, &config_certify, &config_after);
		json_obj_close(&e);
	}
	json_arr_open(&e, "eventlog");
	/*
	 * A boot without an init record has no record to carry, which
	 * verify reports. A log read only part of the way would carry a
	 * history that stops short of what the register holds.
	 */
	ret = eventlog_boot_lines(emit_line, &e);
	if (ret && ret != -ENOENT) {
		pr_err("attest: eventlog %s unreadable: %s", eventlog_path(),
		       strerror(-ret));
		goto out;
	}
	json_arr_close(&e);
	ret = config_evidence_emit(&e, &config);
	if (ret)
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
		ret = e.err;
		goto out;
	}
	(*out)[e.len] = '\0';
	*len = e.len;
	ret = 0;
out:
	if (tpm) {
		tpm_key_flush(tpm, &ek);
		tpm_key_flush(tpm, &ak);
		tpm_close(tpm);
	}
	config_evidence_clear(&config);
	xfree(ek_cert, ek_cert ? EK_CERT_MAX : 0);
	xfree(ek_b64, ek_b64_cap);
	xfree(fw, fw_cap);
	xfree(sd, sd_cap);
	memzero_explicit(cred, sizeof(cred));
	memzero_explicit(&ak, sizeof(ak));
	memzero_explicit(&ek, sizeof(ek));
	memzero_explicit(&ak_copy, sizeof(ak_copy));
	memzero_explicit(&ek_copy, sizeof(ek_copy));
	if (ret && *out) {
		xfree(*out, *cap);
		*out = NULL;
		*cap = 0;
	}
	return ret;
}

/* ---- verification ---------------------------------------------------- */

struct record {
	char	type[16];
	char	label[UPATCH_NAME_MAX + 64];
	__u8	digest[32];
	bool	derived;	/* digest follows from the record's fields */
};

struct init_record {
	__u8		writer_public[TPM_NV_RSA_BYTES];
	bool		present;
	bool		have_reset_count;
	bool		initrd;
	__u32		reset_count;
	__u32		pcr;
	__u32		phase_pcr;
	__u8		digest[32];
	__u8		pcr_before[32];
	__u8		phase_before[32];
	__u8		name[TPM_NAME_LEN];
	__u8		anchor_digest[32];
	__u8		chain[32];
	char		anchor[CHAIN_ANCHOR_MAX];
};

struct signed_fields {
	char attest_hex[2 * TPM_ATTEST_MAX + 1];
	char sig_hex[2 * TPM_SIGNATURE_MAX + 1];
	struct tpm_attestation wire;
};

struct parse {
	struct signed_fields quote, reg, reg_after, nvpcr, nvpcr_after;
	char		writer_public_hex[2 * TPM_NV_RSA_BYTES + 1];
	char nvpcr_name_hex[69];
	char		nonce_hex[2 * ATTEST_NONCE_MAX + 1];
	__s64		pcr_mask;
	char		ak_public_hex[2 * TPM_PUBLIC_MAX + 1];
	char		ak_name_hex[2 * TPM_NAME_LEN + 1];
	char		ek_type[8];
	char		ek_public_hex[2 * TPM_PUBLIC_MAX + 1];
	char		ek_name_hex[2 * TPM_NAME_LEN + 1];
	char		cred_hex[2 * TPM_CREDENTIAL_LEN + 1];
	char		reg_index[16];
	__s64		reg_pcr;
	char		reg_name_hex[2 * TPM_NAME_LEN + 1];
	char		reg_value_hex[65];
	__s64		pcr_index;
	char		pcr_value_hex[65];
	__u32		pcr_have;
	__u8		pcrs[24][32];
	char		type[16];
	char		digest_hex[65];
	char		pcr_before_hex[65];
	char		phase_before_hex[65];
	char		bound_in[8];
	char		nv_name_hex[2 * TPM_NAME_LEN + 1];
	char		anchor[CHAIN_ANCHOR_MAX];
	char		anchor_digest_hex[65];
	char		chain_hex[65];
	__s64		rec_pcr;
	__s64		rec_phase_pcr;
	__s64		rec_reset;
	char		upatch_name[UPATCH_NAME_MAX + 1];
	char		upatch_payload_hex[65];
	char		tree_id[UPATCH_NAME_MAX + 1];
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

/*
 * The report prints a record's type and label as they stand, and the
 * target writes them: only the words its writers use may pass, or an
 * escape sequence would rewrite what the operator reads.
 */
static bool record_word(const char *s)
{
	for (; *s; s++)
		if ((*s < 'a' || *s > 'z') && *s != '_')
			return false;
	return true;
}

static int on_record(void *ctx)
{
	struct parse *p = ctx;
	__u32 payload_type;
	struct record *r;
	bool load;

	if (p->n_recs >= RECORDS_MAX)
		return -E2BIG;
	if (!record_word(p->type))
		return -EINVAL;
	r = &p->recs[p->n_recs];
	memset(r, 0, sizeof(*r));
	if (strscpy(r->type, p->type, sizeof(r->type)) < 0 ||
	    hex_decode(p->digest_hex, r->digest, 32))
		return -EINVAL;
	if (!strcmp(p->type, "init")) {
		struct init_record *in = &p->init;
		__u32 prev_reset = in->reset_count;
		bool prev_have = in->have_reset_count;

		memset(in, 0, sizeof(*in));
		if (p->rec_pcr < 0 || p->rec_pcr >= 24 ||
		    p->rec_phase_pcr <= p->rec_pcr || p->rec_phase_pcr >= 24 ||
		    p->rec_reset > UINT32_MAX ||
		    strlen(p->nv_name_hex) != 2 * TPM_NAME_LEN ||
		    hex_decode(p->pcr_before_hex, in->pcr_before, 32) ||
		    hex_decode(p->phase_before_hex, in->phase_before,
			       32) ||
		    hex_decode(p->nv_name_hex, in->name,
			       TPM_NAME_LEN) ||
		    hex_decode(p->anchor_digest_hex, in->anchor_digest,
			       32) ||
		    hex_decode(p->chain_hex, in->chain, 32) ||
		    hex_decode(p->writer_public_hex, in->writer_public,
			       sizeof(in->writer_public)))
			return -EINVAL;
		memcpy(in->digest, r->digest, 32);
		in->pcr = (__u32)p->rec_pcr;
		in->phase_pcr = (__u32)p->rec_phase_pcr;
		in->initrd = !strcmp(p->bound_in, "initrd");
		in->have_reset_count = p->rec_reset >= 0;
		in->reset_count = (__u32)p->rec_reset;
		if (strscpy(in->anchor, p->anchor, sizeof(in->anchor)) < 0)
			return -EINVAL;
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
		strscpy_literal(r->type, "init");
		memcpy(r->digest, in->digest, 32);
	} else if (eventlog_upatch_record_parse(p->type, &payload_type,
						&load)) {
		__u8 payload[32], event[32];

		if (!upatch_name_valid(p->upatch_name) ||
		    strscpy(r->label, p->upatch_name, sizeof(r->label)) < 0)
			return -EINVAL;
		if (!hex_decode(p->upatch_payload_hex, payload, 32) &&
		    !chain_upatch_event(chain_upatch_tag(payload_type, load),
					p->upatch_name, payload, event))
			r->derived = !memneq_explicit(event, r->digest, 32);
	} else if (!strcmp(p->type, "tree_op")) {
		__u8 operation[32], event[32];

		/* verify cannot tie op and id to the digest: leave them out. */
		if (strsprintf(r->label, sizeof(r->label), "seq %lld",
			       (__s64)p->tree_seq) < 0)
			return -E2BIG;
		if (p->tree_seq > 0 &&
		    !sha256_digest_decode(p->tree_digest_hex, operation) &&
		    !chain_tree_event(p->tree_seq, operation, event)) {
			r->derived = !memneq_explicit(event, r->digest, 32);
			if (strsprintf(r->label, sizeof(r->label),
				       "seq %lld operation %.12s",
				       (__s64)p->tree_seq,
				       p->tree_digest_hex + 7) < 0)
				return -E2BIG;
		}
	} else if (!strcmp(p->type, "key_revoke")) {
		__u8 sha[32], event[32];

		/* Nor the fingerprint: name the measured certificate. */
		if (!hex_decode(p->key_sha_hex, sha, 32) &&
		    !chain_key_event("shirudo-key-revoke", sha, event)) {
			r->derived = !memneq_explicit(event, r->digest, 32);
			if (strsprintf(r->label, sizeof(r->label),
				       "certificate %.12s", p->key_sha_hex) < 0)
				return -E2BIG;
		}
	}
	p->n_recs++;
	/* Reset the per-element scratch the next element may not set. */
	p->type[0] = '\0';
	p->digest_hex[0] = '\0';
	p->pcr_before_hex[0] = '\0';
	p->phase_before_hex[0] = '\0';
	p->nv_name_hex[0] = '\0';
	p->anchor_digest_hex[0] = '\0';
	p->chain_hex[0] = '\0';
	p->upatch_name[0] = '\0';
	p->upatch_payload_hex[0] = '\0';
	p->tree_id[0] = '\0';
	p->tree_op[0] = '\0';
	p->tree_digest_hex[0] = '\0';
	p->key_fingerprint[0] = '\0';
	p->key_sha_hex[0] = '\0';
	p->anchor[0] = '\0';
	p->writer_public_hex[0] = '\0';
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

/*
 * A line ends with its line feed in a full report too, so that what is
 * printed after the report, the verdict of attest verify, starts a line.
 */
static __printf(3, 0) void report_line(struct reporter *r, const char *mark,
				       const char *fmt, va_list ap)
{
	int n;

	/* The mark, a line feed and the NUL behind it. */
	if (r->len + strlen(mark) + 2 > r->cap)
		return;
	n = strscpy(r->buf + r->len, mark, r->cap - r->len);
	if (n > 0)
		r->len += (size_t)n;
	n = vstrsprintf(r->buf + r->len, r->cap - r->len - 1, fmt, ap);
	if (n > 0)
		r->len += (size_t)n;
	r->buf[r->len++] = '\n';
	r->buf[r->len] = '\0';
}

static void say(struct reporter *r, bool ok, const char *fmt, ...)
	__printf(3, 4);

static void say(struct reporter *r, bool ok, const char *fmt, ...)
{
	va_list ap;

	if (!ok)
		r->failed++;
	va_start(ap, fmt);
	report_line(r, ok ? "  OK    " : "  FAIL  ", fmt, ap);
	va_end(ap);
}

static void note(struct reporter *r, const char *fmt, ...)
	__printf(2, 3);

static void note(struct reporter *r, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	report_line(r, "  NOTE  ", fmt, ap);
	va_end(ap);
}

/* What the steps of attest_verify() share. */
struct verify {
	struct reporter			rep;
	const struct attest_expect	*expect;
	struct parse			*p;
	struct config_evidence		config;
	bool				have_ek;
	bool				have_cred;
	bool				have_nvpcr;
	bool				have_nvpcr_value;
	__u8				nvpcr_value[32];
	__u8				nonce[ATTEST_NONCE_MAX];
	size_t				nonce_len;
	struct tpm_ecc_public		ak_pub;
	__u8				ak_name[TPM_NAME_LEN];
	__u8				quote_nonce[32];
	__u8				after_nonce[32];
	struct tpm_attest		quote;
	struct tpm_attest		certify;
	int				qrc;	/* check_signed() of the quote */
	int				crc;	/* and of the register */
	__u8				reg_name[TPM_NAME_LEN];
	__u8				reg_value[32];
	__u64				reg_index;
	size_t				runtime;	/* records after init */
};

static int decode_signed(struct signed_fields *s)
{
	struct tpm_attestation *w = &s->wire;

	if (hex_decode_max(s->attest_hex, w->attest, sizeof(w->attest),
			   &w->attest_len) || !w->attest_len ||
	    hex_decode_max(s->sig_hex, w->signature, sizeof(w->signature),
			   &w->signature_len) || !w->signature_len)
		return -EINVAL;
	return 0;
}

/* A NULL qualifier selects the verifier's original challenge. */
static int check_signed(struct verify *v, const char *what,
			const struct signed_fields *s, const __u8 *qualifier,
			struct tpm_attest *parsed)
{
	const struct tpm_attestation *w = &s->wire;
	const __u8 *nonce = qualifier ? qualifier : v->nonce;
	size_t nonce_len = qualifier ? 32 : v->nonce_len;
	struct reporter *rep = &v->rep;
	bool signer = false;
	int ret;

	if (tpm_attest_parse(w->attest, w->attest_len, parsed)) {
		say(rep, false, "%s: attestation structure unparseable", what);
		return -EKEYREJECTED;
	}
	ret = tpm_attest_verify(w->attest, w->attest_len,
				w->signature, w->signature_len,
				v->ak_pub.x, v->ak_pub.y);
	if (ret == -EBADMSG) {
		say(rep, false, "%s: signature structure unparseable", what);
		return -EKEYREJECTED;
	}
	say(rep, ret == 0, "%s: ECDSA signature by the attestation key", what);
	say(rep, !tpm_attest_signer(parsed, v->ak_name, &signer) && signer,
	    "%s: signed by the key as an endorsement primary", what);
	say(rep, parsed->extra_len == nonce_len &&
	    (!nonce_len || !memneq_explicit(parsed->extra, nonce, nonce_len)),
	    "%s: carries the expected challenge", what);
	return 0;
}

static int evidence_parse(struct verify *v, const char *evidence, size_t len)
{
	struct parse *p = v->p;
	struct json_array pcr_sink = { on_pcr, p };
	struct json_array rec_sink = { on_record, p };
	struct json_field pcr_sub[] = {
		{ "index", JSON_T_INT, &p->pcr_index, 0, 0,
		  NULL, 0 },
		{ "value", JSON_T_STRING, p->pcr_value_hex,
		  sizeof(p->pcr_value_hex), 0, NULL, 0 },
	};
	struct json_field ak_sub[] = {
		{ "public", JSON_T_STRING, p->ak_public_hex,
		  sizeof(p->ak_public_hex), 0, NULL, 0 },
		{ "name", JSON_T_STRING, p->ak_name_hex,
		  sizeof(p->ak_name_hex), 0, NULL, 0 },
	};
	struct json_field quote_sub[] = {
		{ "attest", JSON_T_STRING, p->quote.attest_hex,
		  sizeof(p->quote.attest_hex), 0, NULL, 0 },
		{ "signature", JSON_T_STRING, p->quote.sig_hex,
		  sizeof(p->quote.sig_hex), 0, NULL, 0 },
	};
	struct json_field ek_sub[] = {
		{ "type", JSON_T_STRING, p->ek_type,
		  sizeof(p->ek_type), 0, NULL, 0 },
		{ "public", JSON_T_STRING, p->ek_public_hex,
		  sizeof(p->ek_public_hex), 0, NULL, 0 },
		{ "name", JSON_T_STRING, p->ek_name_hex,
		  sizeof(p->ek_name_hex), 0, NULL, 0 },
	};
	struct json_field cred_sub[] = {
		{ "value", JSON_T_STRING, p->cred_hex,
		  sizeof(p->cred_hex), 0, NULL, 0 },
	};
	struct json_field reg_sub[] = {
		{ "nv_index", JSON_T_STRING, p->reg_index,
		  sizeof(p->reg_index), 0, NULL, 0 },
		{ "pcr", JSON_T_INT, &p->reg_pcr, 0, 0, NULL,
		  0 },
		{ "name", JSON_T_STRING, p->reg_name_hex,
		  sizeof(p->reg_name_hex), 0, NULL, 0 },
		{ "value", JSON_T_STRING, p->reg_value_hex,
		  sizeof(p->reg_value_hex), 0, NULL, 0 },
		{ "attest", JSON_T_STRING, p->reg.attest_hex,
		  sizeof(p->reg.attest_hex), 0, NULL, 0 },
		{ "signature", JSON_T_STRING, p->reg.sig_hex,
		  sizeof(p->reg.sig_hex), 0, NULL, 0 },
		{ "after_attest", JSON_T_STRING, p->reg_after.attest_hex,
		  sizeof(p->reg_after.attest_hex), 0, NULL, 0 },
		{ "after_signature", JSON_T_STRING, p->reg_after.sig_hex,
		  sizeof(p->reg_after.sig_hex), 0, NULL, 0 },
	};
	struct json_field nvpcr_sub[] = {
		{ "name", JSON_T_STRING, p->nvpcr_name_hex,
		  sizeof(p->nvpcr_name_hex), 0, NULL, 0 },
		{ "attest", JSON_T_STRING, p->nvpcr.attest_hex,
		  sizeof(p->nvpcr.attest_hex), 0, NULL, 0 },
		{ "signature", JSON_T_STRING, p->nvpcr.sig_hex,
		  sizeof(p->nvpcr.sig_hex), 0, NULL, 0 },
		{ "after_attest", JSON_T_STRING, p->nvpcr_after.attest_hex,
		  sizeof(p->nvpcr_after.attest_hex), 0, NULL, 0 },
		{ "after_signature", JSON_T_STRING, p->nvpcr_after.sig_hex,
		  sizeof(p->nvpcr_after.sig_hex), 0, NULL, 0 },
	};
	struct json_field upatch_sub[] = {
		{ "name", JSON_T_STRING, p->upatch_name,
		  sizeof(p->upatch_name), 0, NULL, 0 },
		{ "payload_sha256", JSON_T_STRING,
		  p->upatch_payload_hex, sizeof(p->upatch_payload_hex),
		  0, NULL, 0 },
	};
	struct json_field key_sub[] = {
		{ "fingerprint", JSON_T_STRING,
		  p->key_fingerprint, sizeof(p->key_fingerprint), 0,
		  NULL, 0 },
		{ "cert_sha256", JSON_T_STRING, p->key_sha_hex,
		  sizeof(p->key_sha_hex), 0, NULL, 0 },
	};
	struct json_field tree_sub[] = {
		{ "seq", JSON_T_INT, &p->tree_seq, 0, 0, NULL,
		  0 },
		{ "op", JSON_T_STRING, p->tree_op,
		  sizeof(p->tree_op), 0, NULL, 0 },
		{ "id", JSON_T_STRING, p->tree_id,
		  sizeof(p->tree_id), 0, NULL, 0 },
		{ "operation_digest", JSON_T_STRING,
		  p->tree_digest_hex, sizeof(p->tree_digest_hex), 0,
		  NULL, 0 },
	};
	struct json_field rec_sub[] = {
		{ "type", JSON_T_STRING, p->type,
		  sizeof(p->type), 0, NULL, 0 },
		{ "digest", JSON_T_STRING, p->digest_hex,
		  sizeof(p->digest_hex), 0, NULL, 0 },
		{ "pcr", JSON_T_INT, &p->rec_pcr, 0, 0, NULL,
		  0 },
		{ "tpm_reset_count", JSON_T_INT, &p->rec_reset,
		  0, 0, NULL, 0 },
		{ "pcr_before", JSON_T_STRING,
		  p->pcr_before_hex, sizeof(p->pcr_before_hex), 0,
		  NULL, 0 },
		{ "phase_pcr", JSON_T_INT, &p->rec_phase_pcr, 0,
		  0, NULL, 0 },
		{ "phase_before", JSON_T_STRING,
		  p->phase_before_hex, sizeof(p->phase_before_hex), 0,
		  NULL, 0 },
		{ "bound_in", JSON_T_STRING, p->bound_in,
		  sizeof(p->bound_in), 0, NULL, 0 },
		{ "nv_name", JSON_T_STRING, p->nv_name_hex,
		  sizeof(p->nv_name_hex), 0, NULL, 0 },
		{ "nv_writer_public", JSON_T_STRING,
		  p->writer_public_hex, sizeof(p->writer_public_hex),
		  0, NULL, 0 },
		{ "anchor", JSON_T_STRING, p->anchor,
		  sizeof(p->anchor), 0, NULL, 0 },
		{ "anchor_digest", JSON_T_STRING,
		  p->anchor_digest_hex, sizeof(p->anchor_digest_hex), 0,
		  NULL, 0 },
		{ "chain", JSON_T_STRING, p->chain_hex,
		  sizeof(p->chain_hex), 0, NULL, 0 },
		{ "upatch", JSON_T_OBJECT, NULL, 0, 0,
		  upatch_sub, ARRAY_SIZE(upatch_sub) },
		{ "tree", JSON_T_OBJECT, NULL, 0, 0, tree_sub,
		  ARRAY_SIZE(tree_sub) },
		{ "key", JSON_T_OBJECT, NULL, 0, 0, key_sub,
		  ARRAY_SIZE(key_sub) },
	};
	struct json_field top[] = {
		{ "nonce", JSON_T_STRING, p->nonce_hex,
		  sizeof(p->nonce_hex), 0, NULL, 0 },
		{ "pcr_mask", JSON_T_INT, &p->pcr_mask, 0, 0,
		  NULL, 0 },
		{ "pcrs", JSON_T_ARRAY, &pcr_sink, 0, 0,
		  pcr_sub, ARRAY_SIZE(pcr_sub) },
		{ "ak", JSON_T_OBJECT, NULL, 0, 0, ak_sub,
		  ARRAY_SIZE(ak_sub) },
		{ "quote", JSON_T_OBJECT, NULL, 0, 0, quote_sub,
		  ARRAY_SIZE(quote_sub) },
		{ "register", JSON_T_OBJECT, NULL, 0, 0,
		  reg_sub, ARRAY_SIZE(reg_sub) },
		{ "eventlog", JSON_T_ARRAY, &rec_sink, 0, 0,
		  rec_sub, ARRAY_SIZE(rec_sub) },
		{ "ek", JSON_T_OBJECT, NULL, 0, 0, ek_sub,
		  ARRAY_SIZE(ek_sub) },
		{ "credential", JSON_T_OBJECT, NULL, 0, 0,
		  cred_sub, ARRAY_SIZE(cred_sub) },
		{ "config_nvpcr", JSON_T_OBJECT, NULL, 0, 0,
		  nvpcr_sub, ARRAY_SIZE(nvpcr_sub) },
	};
	int ret;

	p->rec_pcr = -1;
	p->rec_phase_pcr = -1;
	p->rec_reset = -1;
	ret = json_parse(evidence, len, top, ARRAY_SIZE(top));
	if (ret || !top[0].seen || !top[1].seen || !top[2].seen ||
	    !top[3].seen || !top[4].seen || !top[5].seen ||
	    !top[6].seen)
		return -EINVAL;
	v->have_ek = ek_sub[0].seen && ek_sub[1].seen && ek_sub[2].seen;
	v->have_cred = cred_sub[0].seen;
	v->have_nvpcr = top[ARRAY_SIZE(top) - 1].seen;
	if (decode_signed(&p->quote) || decode_signed(&p->reg) ||
	    decode_signed(&p->reg_after) ||
	    (v->have_nvpcr && (!nvpcr_sub[0].seen || decode_signed(&p->nvpcr) ||
			       decode_signed(&p->nvpcr_after))))
		return -EINVAL;
	ret = snapshot_quote_nonce(&p->reg.wire, &p->nvpcr.wire, v->quote_nonce);
	if (ret)
		return ret;
	return sha256_buffer(p->quote.wire.signature, p->quote.wire.signature_len,
			     v->after_nonce);
}

static int evidence_parse_config(struct verify *v, const char *evidence,
				 size_t len)
{
	int ret;

	ret = config_evidence_parse(evidence, len, &v->config);
	if (ret == -EKEYREJECTED)
		say(&v->rep, false, "config: the events are one boot event followed by updates in sequence");
	/* What json_parse() refuses past a bound is a malformed document. */
	if (ret == -E2BIG || ret == -ENOSPC)
		ret = -EINVAL;
	return ret;
}

/* Freshness: the document must answer this request. */
static int verify_nonce(struct verify *v)
{
	const struct attest_expect *expect = v->expect;

	if (hex_decode_max(v->p->nonce_hex, v->nonce, sizeof(v->nonce),
			   &v->nonce_len))
		return -EINVAL;
	say(&v->rep, expect->nonce_len == v->nonce_len &&
	    (v->nonce_len == 0 ||
	     !memneq_explicit(v->nonce, expect->nonce, v->nonce_len)),
	    "nonce matches the request");
	return 0;
}

static int verify_ak(struct verify *v)
{
	const struct attest_expect *expect = v->expect;
	struct reporter *rep = &v->rep;
	__u8 ak_public[TPM_PUBLIC_MAX];
	__u8 computed[TPM_NAME_LEN];
	struct parse *p = v->p;
	size_t ak_public_len;

	if (hex_decode_max(p->ak_public_hex, ak_public, sizeof(ak_public),
			   &ak_public_len) ||
	    hex_decode(p->ak_name_hex, v->ak_name, TPM_NAME_LEN))
		return -EINVAL;
	if (tpm_ecc_public_parse(ak_public, ak_public_len, &v->ak_pub)) {
		say(rep, false, "attestation key: public area is not a "
		    "P-256 ECDSA key");
		return -EKEYREJECTED;
	}
	say(rep, (v->ak_pub.attrs & AK_ATTRS_REQUIRED) == AK_ATTRS_REQUIRED,
	    "attestation key: restricted, fixed to this TPM");
	say(rep,
	    !tpm_object_name(ak_public, ak_public_len, computed) &&
	    !memneq_explicit(computed, v->ak_name, sizeof(computed)),
	    "attestation key: name matches its public area");
	if (expect->have_ak_name)
		say(rep,
		    !memneq_explicit(v->ak_name, expect->ak_name, TPM_NAME_LEN),
		    "attestation key: the pinned key");
	else
		note(rep, "attestation key not pinned: name %s",
		     p->ak_name_hex);
	return 0;
}

static int verify_ek(struct verify *v)
{
	const struct attest_expect *expect = v->expect;
	struct reporter *rep = &v->rep;
	struct parse *p = v->p;

	if (v->have_ek) {
		__u8 ek_public[TPM_PUBLIC_MAX];
		__u8 ek_name[TPM_NAME_LEN], computed[TPM_NAME_LEN];
		struct tpm_public ek_pub;
		size_t ek_public_len;
		bool parsed;

		if (hex_decode_max(p->ek_public_hex, ek_public,
				   sizeof(ek_public), &ek_public_len) ||
		    hex_decode(p->ek_name_hex, ek_name, TPM_NAME_LEN))
			return -EINVAL;
		parsed = tpm_public_parse(ek_public, ek_public_len,
					  &ek_pub) == 0;
		say(rep, parsed &&
		    !tpm_object_name(ek_public, ek_public_len, computed) &&
		    !memneq_explicit(computed, ek_name, TPM_NAME_LEN),
		    "endorsement key: name matches its public area");
		say(rep, parsed && ek_pub.attrs == TPM_EK_ATTRS &&
		    ek_pub.policy_len == 32 &&
		    !memneq_explicit(ek_pub.policy, shirudo_tpm_ek_policy, 32),
		    "endorsement key: TCG default template under the "
		    "endorsement policy");
	} else {
		note(rep, "no endorsement key in the evidence");
	}
	if (expect->have_ek_name) {
		__u8 ek_name[TPM_NAME_LEN];

		say(rep, v->have_ek &&
		    !hex_decode(p->ek_name_hex, ek_name, TPM_NAME_LEN) &&
		    !memneq_explicit(ek_name, expect->ek_name, TPM_NAME_LEN),
		    "endorsement key: the pinned key");
	}
	return 0;
}

static int verify_credential(struct verify *v)
{
	const struct attest_expect *expect = v->expect;
	struct reporter *rep = &v->rep;
	__u8 cred[TPM_CREDENTIAL_LEN];
	size_t cred_len = 0;
	int ret = 0;

	if (v->have_cred &&
	    hex_decode_max(v->p->cred_hex, cred, sizeof(cred), &cred_len))
		ret = -EINVAL;
	else if (expect->have_credential)
		say(rep, v->have_cred && cred_len == TPM_CREDENTIAL_LEN &&
		    !memneq_explicit(cred, expect->credential,
				     TPM_CREDENTIAL_LEN),
		    "attestation key: activated the credential made for it "
		    "under the endorsement key");
	else if (v->have_cred)
		note(rep, "a credential was activated but none is expected "
		     "(--expect-credential)");
	memzero_explicit(cred, sizeof(cred));
	return ret;
}

static int verify_quote(struct verify *v)
{
	struct tpm_attest *quote = &v->quote;
	struct reporter *rep = &v->rep;
	struct parse *p = v->p;
	int ret;

	ret = check_signed(v, "quote", &p->quote, v->quote_nonce, quote);
	if (ret == -EINVAL)
		return ret;
	v->qrc = ret;
	if (ret == 0) {
		__u8 digest[32] = {};
		bool complete =
			quote->type == TPM_ST_ATTEST_QUOTE &&
			p->pcr_mask == (__s64)quote->pcr_mask &&
			p->pcr_have == quote->pcr_mask;
		bool vouched;

		say(rep, complete,
		    "quote: covers the PCRs the document lists");
		vouched = complete &&
			  !pcr_values_digest(quote->pcr_mask, p->pcrs, digest) &&
			  !memneq_explicit(digest, quote->pcr_digest, 32);
		say(rep, vouched,
		    "quote: PCR digest matches the listed values");
		if (!vouched)
			p->pcr_have = 0;
	} else {
		p->pcr_have = 0;
	}
	return 0;
}

static int verify_after_quote(struct verify *v, const char *what,
			      const struct tpm_attest *before,
			      const struct signed_fields *after)
{
	struct tpm_attest last = {};
	int ret;

	ret = check_signed(v, what, after, v->after_nonce, &last);
	if (ret)
		return ret;
	say(&v->rep, same_nv(before, &last),
	    "%s: same index and value on both sides of the PCR quote", what);
	return 0;
}

static int verify_register(struct verify *v)
{
	const struct tpm_attest *quote = &v->quote;
	struct tpm_attest *certify = &v->certify;
	struct reporter *rep = &v->rep;
	const char *reg_index_hex;
	struct parse *p = v->p;
	int ret;

	ret = check_signed(v, "register", &p->reg, NULL, certify);
	if (ret == -EINVAL)
		return ret;
	v->crc = ret;
	reg_index_hex = p->reg_index;
	if (hex_decode(p->reg_name_hex, v->reg_name, TPM_NAME_LEN) ||
	    hex_decode(p->reg_value_hex, v->reg_value, 32) ||
	    !str_skip_prefix(&reg_index_hex, "0x") ||
	    parse_x64(reg_index_hex, strlen(reg_index_hex), 0xffffffffULL,
		      &v->reg_index) ||
	    p->reg_pcr < 0 || p->reg_pcr >= 24)
		return -EINVAL;
	if (ret == 0) {
		say(rep, certify->type == TPM_ST_ATTEST_NV &&
		    certify->index_name_len == TPM_NAME_LEN &&
		    !memneq_explicit(certify->index_name, v->reg_name,
				     TPM_NAME_LEN),
		    "register: certification names the listed index");
		say(rep, certify->type == TPM_ST_ATTEST_NV &&
		    certify->offset == 0 && certify->nv_len == 32 &&
		    !memneq_explicit(certify->nv_data, v->reg_value, 32),
		    "register: certified contents match the listed value");
	}
	/* A restart clears the register as a reset does. */
	if (v->qrc == 0 && v->crc == 0)
		say(rep, quote->reset_count == certify->reset_count &&
		    quote->restart_count == certify->restart_count &&
		    quote->firmware_version == certify->firmware_version,
		    "quote and certification are of one TPM boot");
	if (v->crc)
		return 0;
	return verify_after_quote(v, "register after quote", certify, &p->reg_after);
}

/* The quote does not cover an NV index: the config NvPCR is certified. */
static int verify_config_nvpcr(struct verify *v)
{
	const struct attest_expect *expect = v->expect;
	const struct tpm_attest *quote = &v->quote;
	struct reporter *rep = &v->rep;
	struct tpm_attest nvpcr = {};
	struct parse *p = v->p;
	__u8 name[34];
	bool contents;
	int ret;

	if (!v->have_nvpcr) {
		if (expect->have_config_nvpcr_name)
			say(rep, false, "config NvPCR: certification missing");
		return 0;
	}
	if (hex_decode(p->nvpcr_name_hex, name, sizeof(name)))
		return -EINVAL;
	ret = check_signed(v, "config NvPCR", &p->nvpcr, NULL, &nvpcr);
	if (ret == -EINVAL)
		return ret;
	contents = !ret && nvpcr.type == TPM_ST_ATTEST_NV &&
		   nvpcr.index_name_len == sizeof(name) &&
		   !memneq_explicit(nvpcr.index_name, name, sizeof(name)) &&
		   nvpcr.offset == 0 && nvpcr.nv_len == 32;
	say(rep, contents, "config NvPCR: certified name and contents");
	say(rep, !ret && !v->qrc &&
	    nvpcr.reset_count == quote->reset_count &&
	    nvpcr.restart_count == quote->restart_count &&
	    nvpcr.firmware_version == quote->firmware_version,
	    "config NvPCR: same TPM boot as quote");
	if (expect->have_config_nvpcr_name)
		say(rep, !memneq_explicit(name, expect->config_nvpcr_name,
					  sizeof(name)),
		    "config NvPCR: the operator-pinned index");
	else
		note(rep, "config NvPCR has no operator pin; use "
		     "--expect-config-nvpcr");
	if (contents) {
		memcpy(v->nvpcr_value, nvpcr.nv_data, 32);
		v->have_nvpcr_value = true;
	}
	if (ret)
		return 0;
	return verify_after_quote(v, "config NvPCR after quote", &nvpcr, &p->nvpcr_after);
}

static void verify_config(struct verify *v)
{
	const struct attest_expect *expect = v->expect;
	const struct tpm_attest *quote = &v->quote;
	const __u8 *root = expect->have_config_root ?
			   expect->config_root : NULL;
	struct reporter *rep = &v->rep;
	const char *reason;
	int pcr, ret;

	if (!v->config.present && !expect->have_config_root &&
	    !expect->have_config_pcr)
		return;
	pcr = expect->have_config_pcr ? (int)expect->config_pcr : -1;
	ret = config_evidence_verify(&v->config, quote->pcr_mask,
				     quote->reset_count,
				     v->p->pcrs,
				     v->have_nvpcr_value ? v->nvpcr_value : NULL,
				     root, pcr, &reason);
	say(rep, !ret, "config: %s", reason);
	if (v->config.present && !expect->have_config_root)
		note(rep, "config root has no operator approval; use "
		     "--expect-config-root with --expect-config-pcr");
	if (v->config.present)
		note(rep, "config records a selection; "
		     "operation completion depends on trusted runtime guards");
}

static int register_written_name(struct verify *v, __u8 name[TPM_NAME_LEN])
{
	__u8 branch_written[32], branch_init[32], policy[32], bind[64];
	struct reporter *rep = &v->rep;
	struct parse *p = v->p;
	int ret;

	memcpy(bind, p->init.pcr_before, 32);
	memcpy(bind + 32, p->init.phase_before, 32);
	ret = tpm_register_policy(CHAIN_PCR_MASK, bind, 2,
				  p->init.writer_public,
				  branch_written, branch_init, policy);
	if (ret) {
		say(rep, false, "register: cannot compute the signed write policy");
		/* Malformed recorded values are the document's failure, not a parse error. */
		if (ret == -EINVAL)
			ret = -EKEYREJECTED;
		return ret;
	}
	ret = tpm_nv_name(NV_INDEX, TPM_REGISTER_ATTRS | TPM_NV_WRITTEN,
			  policy, 32, name);
	if (ret) {
		say(rep, false, "register: cannot compute the index name");
		return ret;
	}
	return 0;
}

static void verify_bind_values(struct verify *v)
{
	const struct attest_expect *expect = v->expect;
	const struct parse *p = v->p;
	__u32 bit;

	for (bit = 0; bit < 24; bit++) {
		const __u8 *held;

		if (!(expect->bind_expect_mask & (1u << bit)))
			continue;
		held = bit == CHAIN_PCR ? p->init.pcr_before :
		       bit == CHAIN_PHASE_PCR ? p->init.phase_before :
		       NULL;
		say(&v->rep, held &&
		    !memneq_explicit(held, expect->bind_values[bit], 32),
		    "binding: PCR %u held the expected value", bit);
	}
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
static int verify_binding(struct verify *v)
{
	const struct attest_expect *expect = v->expect;
	__u8 expected_name[TPM_NAME_LEN];
	struct reporter *rep = &v->rep;
	struct parse *p = v->p;
	int ret;

	say(rep, p->init.present, "eventlog: this boot has an init record");
	if (!p->init.present)
		return -EKEYREJECTED;
	say(rep, v->reg_index == NV_INDEX &&
	    (__u32)p->reg_pcr == CHAIN_PCR &&
	    p->init.pcr == CHAIN_PCR &&
	    p->init.phase_pcr == CHAIN_PHASE_PCR,
	    "register: the document names index 0x%08X and PCRs %u and %u",
	    NV_INDEX, CHAIN_PCR, CHAIN_PHASE_PCR);
	ret = register_written_name(v, expected_name);
	if (ret)
		return ret;
	say(rep, !memneq_explicit(expected_name, v->reg_name, TPM_NAME_LEN) &&
	    !memneq_explicit(expected_name, p->init.name, TPM_NAME_LEN),
	    "register: public area is bound to PCRs %u and %u as recorded",
	    CHAIN_PCR, CHAIN_PHASE_PCR);
	verify_bind_values(v);
	if (expect->require_initrd)
		say(rep, p->init.initrd, "binding: made while the initrd ran");
	else
		note(rep, "binding: made in the %s",
		     p->init.initrd ? "initrd" : "root file system");
	return 0;
}

/*
 * The epoch: one binding per TPM reset, and the one on record is
 * of the reset the TPM certifies in, so no register bound again
 * after boot can pass as the boot's.
 */
static void verify_epoch(struct verify *v)
{
	struct reporter *rep = &v->rep;
	const struct parse *p = v->p;

	say(rep, p->inits_epoch == 1,
	    "eventlog: one init record for this TPM reset (%u this boot)",
	    p->inits);
	if (v->crc == 0)
		say(rep, p->init.have_reset_count &&
		    p->init.reset_count == v->certify.reset_count,
		    "register: init record is of the TPM's current reset "
		    "count");
}

static void verify_replay(struct verify *v)
{
	const struct parse *p = v->p;
	bool replayed = true;
	__u8 chain[32] = {};
	size_t i;

	for (i = 0; i < p->n_recs; i++) {
		if (chain_fold(chain, p->recs[i].digest))
			replayed = false;
		if (i)
			v->runtime++;
	}
	say(&v->rep, replayed && !memneq_explicit(chain, v->reg_value, 32),
	    "eventlog: %zu record%s replay to the certified value", p->n_recs,
	    p->n_recs == 1 ? "" : "s");
}

/*
 * A digest the record's own fields do not produce is a record
 * relabelled after the fact: the replay still closes, but what the
 * events say happened is not what was measured.
 */
static void verify_derived(struct verify *v)
{
	const struct parse *p = v->p;
	size_t i;

	for (i = 1; i < p->n_recs; i++) {
		if (!p->recs[i].derived)
			say(&v->rep, false, "eventlog: event %zu (%s %s) digest "
			    "does not derive from its fields", i,
			    p->recs[i].type, p->recs[i].label);
	}
}

static void verify_anchor(struct verify *v)
{
	const struct attest_expect *expect = v->expect;
	__u8 anchor_digest[32] = {}, pcr_expected[32];
	struct reporter *rep = &v->rep;
	char anchor[CHAIN_ANCHOR_MAX];
	const struct parse *p = v->p;
	bool named = !chain_anchor(p->init.name, anchor,
				   sizeof(anchor)) &&
		     !sha256_buffer(anchor, strlen(anchor),
				    anchor_digest);

	say(rep, named &&
	    !memneq_explicit(anchor_digest, p->init.anchor_digest, 32),
	    "anchor: record digest matches the index name");
	memcpy(pcr_expected, p->init.pcr_before, 32);
	named = !chain_fold(pcr_expected, anchor_digest) && named;
	if (p->pcr_have & (1u << CHAIN_PCR)) {
		bool exact = named &&
			     !memneq_explicit(pcr_expected,
					      p->pcrs[CHAIN_PCR], 32);

		if (exact || expect->strict_anchor)
			say(rep, exact, "anchor: PCR %u equals the "
			    "recorded value extended by the anchor",
			    CHAIN_PCR);
		else
			note(rep, "anchor: PCR %u carries further "
			     "measurements after the anchor; replay "
			     "the logs to confirm it",
			     CHAIN_PCR);
	} else {
		say(rep, false, "anchor: PCR %u is not in the quote",
		    CHAIN_PCR);
	}
}

static void verify_state(struct verify *v)
{
	const struct attest_expect *expect = v->expect;
	struct reporter *rep = &v->rep;
	const struct parse *p = v->p;
	size_t i;

	if (expect->have_init)
		say(rep,
		    !memneq_explicit(p->init.digest, expect->init_event, 32),
		    "state: init event covers the expected certificate, set "
		    "and tree root");
	if (expect->have_chain) {
		say(rep, !memneq_explicit(v->reg_value, expect->chain, 32),
		    "state: register equals the expected value");
	} else if (expect->have_init) {
		__u8 predicted[32] = {};
		bool folded = !chain_fold(predicted, expect->init_event);

		if (v->runtime == 0)
			say(rep, folded &&
			    !memneq_explicit(v->reg_value, predicted, 32),
			    "state: register equals the value predicted for "
			    "the set at boot");
		else
			say(rep, expect->allow_runtime_events,
			    "state: %zu event%s after boot change the register",
			    v->runtime, v->runtime == 1 ? "" : "s");
	} else {
		note(rep, "no expected state given; the register value is "
		     "%s", p->reg_value_hex);
	}
	for (i = 1; i < p->n_recs; i++)
		note(rep, "event after boot: %s %s", p->recs[i].type,
		     p->recs[i].label);
}

static void verify_expected_pcrs(struct verify *v)
{
	const struct attest_expect *expect = v->expect;
	const struct parse *p = v->p;
	__u32 bit;

	for (bit = 0; bit < 24; bit++) {
		if (!(expect->pcr_expect_mask & (1u << bit)))
			continue;
		say(&v->rep, (p->pcr_have & (1u << bit)) &&
		    !memneq_explicit(p->pcrs[bit], expect->pcrs[bit], 32),
		    "PCR %u matches the expected value", bit);
	}
}

static int verify_document(struct verify *v, const char *evidence,
			   size_t len)
{
	int ret;

	ret = evidence_parse(v, evidence, len);
	if (ret)
		return ret;
	ret = evidence_parse_config(v, evidence, len);
	if (ret)
		return ret;
	ret = verify_nonce(v);
	if (ret)
		return ret;
	ret = verify_ak(v);
	if (ret)
		return ret;
	ret = verify_ek(v);
	if (ret)
		return ret;
	ret = verify_credential(v);
	if (ret)
		return ret;
	ret = verify_quote(v);
	if (ret)
		return ret;
	ret = verify_register(v);
	if (ret)
		return ret;
	ret = verify_config_nvpcr(v);
	if (ret)
		return ret;
	verify_config(v);
	ret = verify_binding(v);
	if (ret)
		return ret;
	verify_epoch(v);
	verify_replay(v);
	verify_derived(v);
	verify_anchor(v);
	verify_state(v);
	verify_expected_pcrs(v);
	return v->rep.failed ? -EKEYREJECTED : 0;
}

int attest_verify(const char *evidence, size_t len,
		  const struct attest_expect *expect,
		  char *report, size_t report_cap)
{
	struct verify v = {
		.rep = { .buf = report, .cap = report_cap },
		.expect = expect,
		.qrc = -1,
		.crc = -1,
	};
	struct parse *p;
	int ret;

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
	v.p = p;
	ret = verify_document(&v, evidence, len);
	config_evidence_clear(&v.config);
	xfree(p->recs, RECORDS_MAX * sizeof(*p->recs));
	xfree(p, sizeof(*p));
	return ret;
}

int attest_challenge_read(const char *path,
			  struct attest_challenge *out)
{
	char blob_hex[2 * TPM_ID_OBJECT_LEN + 1], secret_hex[2 * 256 + 1];
	char ak_hex[2 * TPM_NAME_LEN + 1], kind[32], type[8];
	struct json_field ek_sub[] = {
		{ "type", JSON_T_STRING, type, sizeof(type), 0, NULL,
		  0 },
	};
	struct json_field top[] = {
		{ "kind", JSON_T_STRING, kind, sizeof(kind), 0, NULL,
		  0 },
		{ "ek", JSON_T_OBJECT, NULL, 0, 0, ek_sub,
		  ARRAY_SIZE(ek_sub) },
		{ "ak_name", JSON_T_STRING, ak_hex, sizeof(ak_hex), 0,
		  NULL, 0 },
		{ "credential_blob", JSON_T_STRING, blob_hex,
		  sizeof(blob_hex), 0, NULL, 0 },
		{ "secret", JSON_T_STRING, secret_hex,
		  sizeof(secret_hex), 0, NULL, 0 },
	};
	size_t len;
	char *doc;
	int ret;

	memset(out, 0, sizeof(*out));
	kind[0] = '\0';
	type[0] = '\0';
	ak_hex[0] = '\0';
	blob_hex[0] = '\0';
	secret_hex[0] = '\0';
	ret = read_file(path, ATTEST_CHALLENGE_MAX, &doc, &len);
	if (ret)
		return ret;
	ret = json_parse(doc, len, top, ARRAY_SIZE(top));
	xfree(doc, len + 1);
	if (ret || !top[0].seen || strcmp(kind, "shirudo-credential") ||
	    !ek_sub[0].seen || !top[2].seen || !top[3].seen || !top[4].seen)
		return -EINVAL;
	if (!strcmp(type, "rsa"))
		out->ek_rsa = true;
	else if (strcmp(type, "ecc"))
		return -EINVAL;
	if (hex_decode(ak_hex, out->ak_name, TPM_NAME_LEN) ||
	    hex_decode_max(blob_hex, out->blob, sizeof(out->blob),
			   &out->blob_len) ||
	    out->blob_len != TPM_ID_OBJECT_LEN ||
	    hex_decode_max(secret_hex, out->secret, sizeof(out->secret),
			   &out->secret_len) || !out->secret_len)
		return -EINVAL;
	return 0;
}

/* The certificate's key must be the endorsement key of the evidence. */
static bool cert_describes(const struct cert_pubkey *key,
			   const struct tpm_public *pub)
{
	bool rsa = pub->type == TPM_ALG_RSA;

	if (key->rsa != rsa)
		return false;
	if (key->rsa)
		return key->n_len == pub->n_len &&
		       !memneq_explicit(key->n, pub->n, pub->n_len) &&
		       key->e == (pub->rsa_exponent ? pub->rsa_exponent : 65537);
	return !memneq_explicit(key->x, pub->x, 32) &&
	       !memneq_explicit(key->y, pub->y, 32);
}

int attest_challenge_make(const char *evidence, size_t len,
			  const struct attest_challenge_policy *pol,
			  __u8 credential[TPM_CREDENTIAL_LEN],
			  char **out, size_t *out_len, size_t *cap,
			  char *report, size_t report_cap)
{
	const char *ek_ca = pol->ek_ca;
	bool vouched = pol->ek_name || pol->trust_presented;
	struct reporter rep = { .buf = report, .cap = report_cap };
	char ek_public_hex[2 * TPM_PUBLIC_MAX + 1], hex[2 * 256 + 1];
	char ak_hex[2 * TPM_NAME_LEN + 1], ek_type[8];
	char ek_name_hex[2 * TPM_NAME_LEN + 1];
	__u8 ak_name[TPM_NAME_LEN], ek_name[TPM_NAME_LEN];
	__u8 ek_public[TPM_PUBLIC_MAX], computed[TPM_NAME_LEN];
	__u8 seed[32], z[32], eph_x[32], eph_y[32], secret[256];
	__u8 blob[TPM_ID_OBJECT_LEN], *der = NULL;
	struct cert_pubkey cert_key;
	struct tpm_public pub;
	struct cert cert = {};
	struct json_emit e;
	struct json_field ak_sub[] = {
		{ "name", JSON_T_STRING, ak_hex, sizeof(ak_hex), 0,
		  NULL, 0 },
	};
	struct json_field ek_sub[] = {
		{ "type", JSON_T_STRING, ek_type, sizeof(ek_type), 0,
		  NULL, 0 },
		{ "public", JSON_T_STRING, ek_public_hex,
		  sizeof(ek_public_hex), 0, NULL, 0 },
		{ "name", JSON_T_STRING, ek_name_hex,
		  sizeof(ek_name_hex), 0, NULL, 0 },
	};
	char *cert_b64 = xmalloc(EK_CERT_B64_MAX);
	struct json_field top[] = {
		{ "ak", JSON_T_OBJECT, NULL, 0, 0, ak_sub,
		  ARRAY_SIZE(ak_sub) },
		{ "ek", JSON_T_OBJECT, NULL, 0, 0, ek_sub,
		  ARRAY_SIZE(ek_sub) },
		{ "ek_certificate", JSON_T_STRING, cert_b64,
		  EK_CERT_B64_MAX, 0, NULL, 0 },
	};
	size_t ek_public_len, secret_len = 0, der_len = 0;
	const char *reason = "";
	int ret = -EINVAL;
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
	    hex_decode(ak_hex, ak_name, TPM_NAME_LEN) ||
	    hex_decode_max(ek_public_hex, ek_public, sizeof(ek_public),
			   &ek_public_len) ||
	    hex_decode(ek_name_hex, ek_name, TPM_NAME_LEN))
		goto out;
	if (!strcmp(ek_type, "rsa"))
		rsa = true;
	else if (!strcmp(ek_type, "ecc"))
		rsa = false;
	else
		goto out;
	if (tpm_public_parse(ek_public, ek_public_len, &pub) ||
	    pub.type != (rsa ? TPM_ALG_RSA : TPM_ALG_ECC))
		goto out;

	/*
	 * The operator's pins come first: the challenge is for the key the
	 * operator enrolled, not for whatever the document names.
	 */
	if (pol->ak_name)
		say(&rep, !memneq_explicit(ak_name, pol->ak_name, TPM_NAME_LEN),
		    "attestation key: the pinned key");
	if (pol->ek_name)
		say(&rep, !memneq_explicit(ek_name, pol->ek_name, TPM_NAME_LEN),
		    "endorsement key: the pinned key");

	/* The key must be an endorsement key, not any decryption key. */
	say(&rep, !tpm_object_name(ek_public, ek_public_len, computed) &&
	    !memneq_explicit(computed, ek_name, TPM_NAME_LEN),
	    "endorsement key: name matches its public area");
	say(&rep, pub.attrs == TPM_EK_ATTRS && pub.policy_len == 32 &&
	    !memneq_explicit(pub.policy, shirudo_tpm_ek_policy, 32),
	    "endorsement key: TCG default template under the endorsement "
	    "policy");
	if (top[2].seen) {
		der = xmalloc(EK_CERT_MAX);
		if (!der) {
			ret = -ENOMEM;
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
		ret = -EKEYREJECTED;
		goto out;
	}

	ret = -EIO;
	if (getrandom(credential, TPM_CREDENTIAL_LEN, 0) !=
	    TPM_CREDENTIAL_LEN)
		goto out;
	if (rsa) {
		if (getrandom(seed, sizeof(seed), 0) != (ssize_t)sizeof(seed) ||
		    rsa_oaep_encrypt(pub.n, pub.n_len, pub.rsa_exponent,
				     "IDENTITY", sizeof("IDENTITY"),
				     seed, sizeof(seed), secret,
				     sizeof(secret), &secret_len))
			goto out;
	} else {
		if (ecdh_p256_ephemeral(pub.x, pub.y, eph_x, eph_y, z) ||
		    tpm_kdfe(z, "IDENTITY", eph_x, 32, pub.x, 32, seed))
			goto out;
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
		ret = -ENOMEM;
		goto out;
	}
	e = (struct json_emit){ .buf = *out, .cap = *cap };
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
		ret = e.err;
		goto out;
	}
	(*out)[e.len] = '\0';
	*out_len = e.len;
	ret = 0;
out:
	memzero_explicit(seed, sizeof(seed));
	memzero_explicit(z, sizeof(z));
	cert_free(&cert);
	xfree(der, der ? EK_CERT_MAX : 0);
	xfree(cert_b64, EK_CERT_B64_MAX);
	if (ret) {
		memzero_explicit(credential, TPM_CREDENTIAL_LEN);
		if (*out) {
			xfree(*out, *cap);
			*out = NULL;
			*cap = 0;
		}
	}
	return ret;
}

int attest_parse_pcrs(const char *list, __u32 *mask)
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
		if (*p == ',' && p[1])
			p++;
		else if (*p)
			return -EINVAL;
	}
	return *mask ? 0 : -EINVAL;
}

int attest_parse_pcr_value(const char *arg, __u64 *pcr, const char **value)
{
	size_t len = digits(arg, strlen(arg));

	if (arg[len] != '=' || parse_u64(arg, len, 23, pcr))
		return -EINVAL;
	*value = arg + len + 1;
	return 0;
}

int attest_parse_name_digest(const char *spec, char name[UPATCH_NAME_MAX + 1],
			     __u8 digest[32])
{
	const char *eq = strchr(spec, '=');
	size_t len;

	if (!eq)
		return -EINVAL;
	len = eq - spec;
	if (!len || len > UPATCH_NAME_MAX || hex_decode(eq + 1, digest, 32))
		return -EINVAL;
	memcpy(name, spec, len);
	name[len] = '\0';
	return 0;
}
