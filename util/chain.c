// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The measurement register and the digest helpers shared by every
 * measuring path.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <shirudo/misc.h>

#include "chain.h"
#include "config.h"
#include "crypto.h"
#include "initrd.h"
#include "log.h"
#include "malloc.h"
#include "paths.h"
#include "tpm.h"

void shirudo_sha256(const void *data, size_t len, __u8 out[32])
{
	if (sha256_buffer(data, len, out) != 0)
		memset(out, 0, 32);
}

void sha256_2(const void *a, size_t a_len,
	      const void *b, size_t b_len, __u8 out[32])
{
	struct shirudo_sha256_ctx ctx;

	if (sha256_init(&ctx) != 0) {
		memset(out, 0, 32);
		return;
	}
	if (sha256_update(&ctx, a, a_len) != 0 ||
	    (b_len && sha256_update(&ctx, b, b_len) != 0) ||
	    sha256_final(&ctx, out) != 0) {
		memset(out, 0, 32);
		sha256_free(&ctx);
	}
}

int ct_eq(const void *a, const void *b, size_t n)
{
	const __u8 *pa = a, *pb = b;
	__u8 diff = 0;
	size_t i;

	for (i = 0; i < n; i++)
		diff |= pa[i] ^ pb[i];
	return diff == 0;
}

static int member_cmp(const void *a, const void *b)
{
	return strcmp(((const struct shirudo_measured_upatch *)a)->name,
		      ((const struct shirudo_measured_upatch *)b)->name);
}

void chain_init_event(const __u8 cert_sha[32],
		      struct shirudo_measured_upatch *set, size_t n,
		      const __u8 tree_root[32],
		      __u8 set_digest[32], __u8 event[32])
{
	__u8 tag[sizeof("shirudo-init") + 96];
	size_t taglen = sizeof("shirudo-init"), listing_len = 0, off = 0, i;
	char *listing;

	/* set_digest = SHA256(sorted "<payload_hex> <name>\n" listing) */
	if (n > 1)
		qsort(set, n, sizeof(*set), member_cmp);
	for (i = 0; i < n; i++)
		listing_len += strlen(set[i].payload_hex) + 1 +
			       strlen(set[i].name) + 1;
	listing = xmalloc(listing_len + 1);
	if (!listing) {
		memset(set_digest, 0, 32);
		memset(event, 0, 32);
		return;
	}
	for (i = 0; i < n; i++)
		off += (size_t)snprintf(listing + off, listing_len + 1 - off,
					"%s %s\n", set[i].payload_hex,
					set[i].name);
	shirudo_sha256(listing, listing_len, set_digest);
	xfree(listing, listing_len + 1);

	memcpy(tag, "shirudo-init", taglen);
	memcpy(tag + taglen, cert_sha, 32);
	memcpy(tag + taglen + 32, set_digest, 32);
	memcpy(tag + taglen + 64, tree_root, 32);
	shirudo_sha256(tag, taglen + 96, event);
}

void chain_upatch_event(const char *tag, const char *name,
			const __u8 payload[32], __u8 event[32])
{
	__u8 buf[sizeof("shirudo-unload") + 32 + SHIRUDO_UPATCH_NAME_MAX];
	size_t taglen = strlen(tag) + 1, off = 0;
	size_t namelen = strnlen(name, SHIRUDO_UPATCH_NAME_MAX);

	memcpy(buf + off, tag, taglen);		/* tag + its NUL */
	off += taglen;
	memcpy(buf + off, payload, 32);
	off += 32;
	memcpy(buf + off, name, namelen);
	off += namelen;
	shirudo_sha256(buf, off, event);
}

void chain_key_event(const char *tag, const __u8 cert_sha[32],
		     __u8 event[32])
{
	sha256_2(tag, strlen(tag) + 1, cert_sha, 32, event);
}

void chain_tree_event(__s64 seq, const __u8 operation_digest[32],
		      __u8 event[32])
{
	__u8 buf[sizeof("shirudo-tree") + 8 + 32];
	size_t taglen = sizeof("shirudo-tree"), i;
	__u64 s = (__u64)seq;

	memcpy(buf, "shirudo-tree", taglen);
	for (i = 0; i < 8; i++)
		buf[taglen + i] = (__u8)(s >> (56 - 8 * i));
	memcpy(buf + taglen + 8, operation_digest, 32);
	shirudo_sha256(buf, taglen + 40, event);
}

int shirudo_chain_fold_checked(__u8 chain[32], const __u8 event[32])
{
	__u8 cat[64];

	memcpy(cat, chain, 32);
	memcpy(cat + 32, event, 32);
	return sha256_buffer(cat, sizeof(cat), chain);
}

void chain_fold(__u8 chain[32], const __u8 event[32])
{
	if (shirudo_chain_fold_checked(chain, event))
		memset(chain, 0, 32);
}

void chain_anchor(const __u8 name[SHIRUDO_TPM_NAME_LEN],
		  char *out, size_t cap)
{
	char hex[2 * SHIRUDO_TPM_NAME_LEN + 1];

	hex_encode(name, SHIRUDO_TPM_NAME_LEN, hex);
	snprintf(out, cap, "nvpcr-init:%s:0x%x:%s", SHIRUDO_CHAIN_NAME,
		 SHIRUDO_NV_INDEX, hex);
}

/* The binding PCR values in PCR order, as PolicyPCR hashes them. */
static void bind_values(const __u8 pcr_before[32],
			const __u8 phase_before[32], __u8 out[64])
{
	memcpy(out, pcr_before, 32);
	memcpy(out + 32, phase_before, 32);
}

/*
 * The write policy and the expected names for the PCR values the
 * register binds to. TPMA_NV_WRITTEN is part of the public area, so
 * the index is named differently before and after its first write;
 * the written name is the one the record, the anchor and every later
 * comparison use.
 */
static void register_expectation(const __u8 pcr_before[32],
				 const __u8 phase_before[32],
				 __u8 branch_written[32],
				 __u8 branch_init[32],
				 __u8 policy[32],
				 __u8 name_unwritten[SHIRUDO_TPM_NAME_LEN],
				 __u8 name_written[SHIRUDO_TPM_NAME_LEN])
{
	__u8 values[64];

	bind_values(pcr_before, phase_before, values);
	tpm_register_policy(SHIRUDO_CHAIN_PCR_MASK, values, 2,
			    branch_written, branch_init, policy);
	tpm_nv_name(SHIRUDO_NV_INDEX, SHIRUDO_TPM_REGISTER_ATTRS,
		    policy, SHIRUDO_TPM_NV_DIGEST_LEN, name_unwritten);
	tpm_nv_name(SHIRUDO_NV_INDEX,
		    SHIRUDO_TPM_REGISTER_ATTRS | SHIRUDO_TPM_NV_WRITTEN,
		    policy, SHIRUDO_TPM_NV_DIGEST_LEN, name_written);
}

static bool name_equals(const struct tpm_nv_info *info,
			const __u8 name[SHIRUDO_TPM_NAME_LEN])
{
	return info->name_len == SHIRUDO_TPM_NAME_LEN &&
	       ct_eq(info->name, name, SHIRUDO_TPM_NAME_LEN);
}

static int register_define(struct shirudo_tpm *tpm, bool defined,
			   const __u8 policy[32])
{
	struct shirudo_config cfg = {};
	int rc;

	config_load(&cfg);
	if (defined) {
		rc = tpm_nv_undefine(tpm, SHIRUDO_NV_INDEX,
				     cfg.tpm_owner_auth,
				     cfg.tpm_owner_auth_len);
		if (rc)
			goto out;
	}
	rc = tpm_nv_define(tpm, SHIRUDO_NV_INDEX, policy,
			   cfg.tpm_owner_auth, cfg.tpm_owner_auth_len);
out:
	explicit_bzero(&cfg, sizeof(cfg));
	return rc;
}

int chain_init(const __u8 event[32],
	       struct shirudo_chain_init_info *info)
{
	__u8 unwritten[SHIRUDO_TPM_NAME_LEN], written[SHIRUDO_TPM_NAME_LEN];
	__u8 branch_written[32], branch_init[32], policy[32];
	struct shirudo_eventlog_init rec;
	struct tpm_nv_info nv;
	struct shirudo_tpm *tpm = NULL;
	bool recorded;
	int rc;

	memset(info, 0, sizeof(*info));
	rc = tpm_open(&tpm);
	if (rc)
		return -ENODEV;
	rc = tpm_reset_count(tpm, &info->reset_count);
	if (rc)
		goto out;
	rc = tpm_nv_info(tpm, SHIRUDO_NV_INDEX, &nv);
	if (rc)
		goto out;

	/*
	 * A record of this boot for the TPM's current reset count means
	 * init already bound a register. Written and carrying the
	 * recorded name, it is a re-run and the register stays as it is.
	 * Anything else is refused: a second binding would restart the
	 * history the record vouches for, and only a TPM reset clears a
	 * register legitimately. Without such a record the index is
	 * bound, after a warning if someone wrote it before we ran; the
	 * PCR keeps the record of both bindings. A log that cannot be
	 * read may hold the record, so it is refused as well.
	 */
	rc = eventlog_boot_init(&rec);
	if (rc && rc != -ENOENT) {
		pr_err("tpm: eventlog %s unreadable: %s; not binding register "
		       "0x%08x", eventlog_path(), strerror(-rc),
		       SHIRUDO_NV_INDEX);
		goto out;
	}
	recorded = !rc && (!rec.have_reset_count ||
			   rec.reset_count == info->reset_count);
	if (recorded) {
		if (nv.defined && nv.written && name_equals(&nv, rec.name)) {
			rc = tpm_nv_read(tpm, SHIRUDO_NV_INDEX,
					 info->value);
			if (rc)
				goto out;
			memcpy(info->name, nv.name, nv.name_len);
			info->name_len = nv.name_len;
			memcpy(info->pcr_before, rec.pcr_before, 32);
			memcpy(info->phase_before, rec.phase_before, 32);
			memcpy(info->anchor_digest, rec.anchor_digest, 32);
			chain_anchor(info->name, info->anchor,
				     sizeof(info->anchor));
			info->initrd = rec.initrd;
			info->reused = true;
			goto out;
		}
		pr_err("tpm: register 0x%08x bound this boot is %s; not "
		       "binding another before the next TPM reset",
		       SHIRUDO_NV_INDEX, !nv.defined ? "gone" :
		       !nv.written ? "unwritten" : "not the recorded index");
		rc = -EEXIST;
		goto out;
	}
	if (nv.defined && nv.written)
		pr_warn("tpm: register 0x%08x written this boot without a "
			"record; rebinding it", SHIRUDO_NV_INDEX);

	rc = tpm_pcr_read(tpm, SHIRUDO_CHAIN_PCR, info->pcr_before);
	if (!rc)
		rc = tpm_pcr_read(tpm, SHIRUDO_CHAIN_PHASE_PCR,
				  info->phase_before);
	if (rc)
		goto out;
	info->initrd = in_initrd();
	register_expectation(info->pcr_before, info->phase_before,
			     branch_written, branch_init, policy, unwritten,
			     written);

	if (!nv.defined || nv.written || !name_equals(&nv, unwritten)) {
		rc = register_define(tpm, nv.defined, policy);
		if (rc)
			goto out;
		rc = tpm_nv_info(tpm, SHIRUDO_NV_INDEX, &nv);
		if (rc)
			goto out;
		if (!nv.defined || !name_equals(&nv, unwritten)) {
			pr_err("tpm: register 0x%08x name does not match the "
			       "computed public area", SHIRUDO_NV_INDEX);
			rc = -EPROTO;
			goto out;
		}
	}

	rc = tpm_nv_extend_first(tpm, SHIRUDO_NV_INDEX,
				 SHIRUDO_CHAIN_PCR_MASK, branch_written,
				 branch_init, event);
	if (rc)
		goto out;
	memcpy(info->name, written, sizeof(written));
	info->name_len = sizeof(written);
	chain_anchor(info->name, info->anchor, sizeof(info->anchor));
	shirudo_sha256(info->anchor, strlen(info->anchor), info->anchor_digest);
	rc = tpm_pcr_extend(tpm, SHIRUDO_CHAIN_PCR,
			    info->anchor_digest);
	if (rc) {
		pr_err("tpm: register written but PCR %u not anchored; "
		       "the init branch stays open until reboot",
		       SHIRUDO_CHAIN_PCR);
		goto out;
	}
	rc = tpm_nv_read(tpm, SHIRUDO_NV_INDEX, info->value);
out:
	tpm_close(tpm);
	return rc;
}

int chain_extend(const __u8 event[32], __u8 out_chain[32])
{
	__u8 branch_written[32], branch_init[32], policy[32], values[64];
	struct shirudo_eventlog_init rec;
	struct tpm_nv_info nv;
	struct shirudo_tpm *tpm = NULL;
	int rc;

	rc = eventlog_boot_init(&rec);
	if (rc)
		return -ENODEV;		/* no register this boot */
	bind_values(rec.pcr_before, rec.phase_before, values);
	tpm_register_policy(SHIRUDO_CHAIN_PCR_MASK, values, 2,
			    branch_written, branch_init, policy);

	rc = tpm_open(&tpm);
	if (rc)
		return -ENODEV;
	rc = tpm_nv_info(tpm, SHIRUDO_NV_INDEX, &nv);
	if (rc)
		goto out;
	if (!nv.defined || !nv.written) {
		rc = -ENODEV;
		goto out;
	}
	if (!name_equals(&nv, rec.name)) {
		pr_err("tpm: register 0x%08x is not the index init recorded "
		       "(recreated?)", SHIRUDO_NV_INDEX);
		rc = -EACCES;
		goto out;
	}
	rc = tpm_nv_extend(tpm, SHIRUDO_NV_INDEX, branch_written,
			   branch_init, event);
	if (rc) {
		rc = -EIO;
		goto out;
	}
	if (out_chain)
		rc = tpm_nv_read(tpm, SHIRUDO_NV_INDEX, out_chain) ?
		     -EIO : 0;
out:
	tpm_close(tpm);
	return rc;
}

int chain_read(__u8 out[32])
{
	struct shirudo_tpm *tpm = NULL;
	int rc;

	rc = tpm_open(&tpm);
	if (rc)
		return -ENODEV;
	rc = tpm_nv_read(tpm, SHIRUDO_NV_INDEX, out);
	tpm_close(tpm);
	return rc ? -ENODEV : 0;
}

bool chain_bound(void)
{
	struct shirudo_tpm *tpm = NULL;
	struct tpm_nv_info nv;
	bool bound;

	if (tpm_open_quiet(&tpm))
		return false;
	bound = tpm_nv_info(tpm, SHIRUDO_NV_INDEX, &nv) == 0 &&
		nv.defined && nv.written;
	tpm_close(tpm);
	return bound;
}

int chain_status(struct chain_status *st)
{
	struct tpm_nv_info nv;
	struct shirudo_tpm *tpm = NULL;
	__u32 reset_count = 0;
	int rc;

	memset(st, 0, sizeof(*st));
	st->logged = eventlog_boot_init(&st->init) == 0;
	st->rebound = st->logged && st->init.records_epoch > 1;
	rc = tpm_open_quiet(&tpm);
	if (rc)
		return -ENODEV;
	st->tpm = true;
	rc = tpm_reset_count(tpm, &reset_count);
	if (rc)
		goto out;
	rc = tpm_nv_info(tpm, SHIRUDO_NV_INDEX, &nv);
	if (rc)
		goto out;
	st->defined = nv.defined;
	st->written = nv.written;
	memcpy(st->name, nv.name, nv.name_len);
	st->name_len = nv.name_len;
	if (nv.defined && nv.written)
		rc = tpm_nv_read(tpm, SHIRUDO_NV_INDEX, st->value);
	st->anchored = nv.defined && nv.written && st->logged &&
		       name_equals(&nv, st->init.name) &&
		       (!st->init.have_reset_count ||
			st->init.reset_count == reset_count);
out:
	tpm_close(tpm);
	return rc;
}
