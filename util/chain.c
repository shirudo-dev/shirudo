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
#include <shirudo/string.h>

#include "chain.h"
#include "config.h"
#include "crypto.h"
#include "initrd.h"
#include "log.h"
#include "malloc.h"
#include "nv_writer.h"
#include "paths.h"
#include "tpm.h"

int sha256_calc(const void *data, size_t len, __u8 out[32])
{
	int ret = sha256_buffer(data, len, out);

	if (ret)
		memset(out, 0, 32);
	return ret;
}

int sha256_2(const void *a, size_t a_len,
	     const void *b, size_t b_len, __u8 out[32])
{
	struct sha256_ctx ctx;
	int ret;

	ret = sha256_init(&ctx);
	if (ret)
		goto out;
	ret = sha256_update(&ctx, a, a_len);
	if (!ret && b_len)
		ret = sha256_update(&ctx, b, b_len);
	if (!ret)
		ret = sha256_final(&ctx, out);
	sha256_free(&ctx);
out:
	if (ret)
		memset(out, 0, 32);
	return ret;
}

static int member_cmp(const void *a, const void *b)
{
	return strcmp(((const struct measured_upatch *)a)->name,
		      ((const struct measured_upatch *)b)->name);
}

int chain_init_event(const __u8 cert_sha[32],
		     struct measured_upatch *set, size_t n,
		     const __u8 tree_root[32],
		     __u8 set_digest[32], __u8 event[32])
{
	__u8 tag[sizeof("shirudo-init") + 96];
	size_t taglen = sizeof("shirudo-init"), listing_len = 0, off = 0, i;
	char *listing;
	int ret;

	/* set_digest = SHA256(sorted "<payload_hex> <name>\n" listing) */
	if (n > 1)
		qsort(set, n, sizeof(*set), member_cmp);
	for (i = 0; i < n; i++)
		listing_len += strlen(set[i].payload_hex) + 1 +
			       strlen(set[i].name) + 1;
	memset(set_digest, 0, 32);
	memset(event, 0, 32);
	listing = xmalloc(listing_len + 1);
	if (!listing)
		return -ENOMEM;
	for (i = 0; i < n; i++) {
		int w = strsprintf(listing + off, listing_len + 1 - off,
				   "%s %s\n", set[i].payload_hex, set[i].name);

		if (w < 0) {
			xfree(listing, listing_len + 1);
			return w;
		}
		off += (size_t)w;
	}
	ret = sha256_calc(listing, listing_len, set_digest);
	xfree(listing, listing_len + 1);
	if (ret)
		return ret;

	memcpy(tag, "shirudo-init", taglen);
	memcpy(tag + taglen, cert_sha, 32);
	memcpy(tag + taglen + 32, set_digest, 32);
	memcpy(tag + taglen + 64, tree_root, 32);
	return sha256_calc(tag, taglen + 96, event);
}

int chain_upatch_event(const char *tag, const char *name,
		       const __u8 payload[32], __u8 event[32])
{
	__u8 buf[sizeof("shirudo-unload") + 32 + UPATCH_NAME_MAX];
	size_t taglen = strlen(tag) + 1, off = 0;
	size_t namelen = strnlen(name, UPATCH_NAME_MAX);

	memcpy(buf + off, tag, taglen);		/* tag + its NUL */
	off += taglen;
	memcpy(buf + off, payload, 32);
	off += 32;
	memcpy(buf + off, name, namelen);
	off += namelen;
	return sha256_calc(buf, off, event);
}

int chain_key_event(const char *tag, const __u8 cert_sha[32],
		    __u8 event[32])
{
	return sha256_2(tag, strlen(tag) + 1, cert_sha, 32, event);
}

int chain_tree_event(__s64 seq, const __u8 operation_digest[32],
		     __u8 event[32])
{
	__u8 buf[sizeof("shirudo-tree") + 8 + 32];
	size_t taglen = sizeof("shirudo-tree"), i;
	__u64 s = (__u64)seq;

	memcpy(buf, "shirudo-tree", taglen);
	for (i = 0; i < 8; i++)
		buf[taglen + i] = (__u8)(s >> (56 - 8 * i));
	memcpy(buf + taglen + 8, operation_digest, 32);
	return sha256_calc(buf, taglen + 40, event);
}

int chain_fold(__u8 chain[32], const __u8 event[32])
{
	__u8 cat[64];

	memcpy(cat, chain, 32);
	memcpy(cat + 32, event, 32);
	return sha256_calc(cat, sizeof(cat), chain);
}

int chain_anchor(const __u8 name[TPM_NAME_LEN],
		 char *out, size_t cap)
{
	char hex[2 * TPM_NAME_LEN + 1];

	hex_encode(name, TPM_NAME_LEN, hex);
	return strsprintf(out, cap, "nvpcr-init:%s:0x%x:%s",
			  CHAIN_NAME, NV_INDEX, hex) < 0 ?
	       -E2BIG : 0;
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
static int register_expectation(const __u8 pcr_before[32],
				const __u8 phase_before[32],
				const __u8 writer_public[TPM_NV_RSA_BYTES],
				__u8 branch_written[32],
				__u8 branch_init[32],
				__u8 policy[32],
				__u8 name_unwritten[TPM_NAME_LEN],
				__u8 name_written[TPM_NAME_LEN])
{
	__u8 values[64];
	int ret;

	bind_values(pcr_before, phase_before, values);
	ret = tpm_register_policy(CHAIN_PCR_MASK, values, 2, writer_public,
				  branch_written, branch_init, policy);
	if (ret) {
		pr_err("tpm: compute signed register policy: %s", strerror(-ret));
		return ret;
	}
	ret = tpm_nv_name(NV_INDEX, TPM_REGISTER_ATTRS,
			  policy, TPM_NV_DIGEST_LEN, name_unwritten);
	if (!ret)
		ret = tpm_nv_name(NV_INDEX,
				  TPM_REGISTER_ATTRS | TPM_NV_WRITTEN,
				  policy, TPM_NV_DIGEST_LEN, name_written);
	return ret;
}

static bool name_equals(const struct tpm_nv_info *info,
			const __u8 name[TPM_NAME_LEN])
{
	return info->name_len == TPM_NAME_LEN &&
	       !memneq_explicit(info->name, name, TPM_NAME_LEN);
}

static int register_define(struct tpm *tpm, bool defined,
			   const __u8 policy[32])
{
	struct config cfg __cleanup(config_clear) = {};
	int ret;

	config_load(&cfg);
	if (defined) {
		ret = tpm_nv_undefine(tpm, NV_INDEX,
				      cfg.tpm_owner_auth,
				      cfg.tpm_owner_auth_len);
		if (ret)
			goto out;
	}
	ret = tpm_nv_define(tpm, NV_INDEX, policy,
			    cfg.tpm_owner_auth, cfg.tpm_owner_auth_len);
out:
	return ret;
}

static int register_writer(struct tpm *tpm,
			   __u8 public[TPM_NV_RSA_BYTES])
{
	__u8 seed[32];
	int ret;

	ret = nv_writer_read(seed, public);
	return ret ? ret : tpm_nv_set_writer(tpm, seed, public);
}

int chain_init(const __u8 event[32],
	       struct chain_init_info *info)
{
	__u8 unwritten[TPM_NAME_LEN], written[TPM_NAME_LEN];
	__u8 branch_written[32], branch_init[32], policy[32];
	struct eventlog_init rec;
	struct tpm_nv_info nv;
	struct tpm *tpm = NULL;
	bool recorded;
	int ret;

	memset(info, 0, sizeof(*info));
	ret = tpm_open(&tpm);
	if (ret)
		return -ENODEV;
	ret = tpm_reset_count(tpm, &info->reset_count);
	if (ret)
		goto out;
	ret = tpm_nv_info(tpm, NV_INDEX, &nv);
	if (ret)
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
	ret = eventlog_boot_init(&rec);
	if (ret && ret != -ENOENT) {
		pr_err("tpm: eventlog %s unreadable: %s; not binding register "
		       "0x%08x", eventlog_path(), strerror(-ret),
		       NV_INDEX);
		goto out;
	}
	recorded = !ret && (!rec.have_reset_count ||
			    rec.reset_count == info->reset_count);
	if (recorded) {
		ret = register_writer(tpm, info->writer_public);
		if (ret)
			goto out;
		ret = register_expectation(rec.pcr_before, rec.phase_before,
					   info->writer_public, branch_written,
					   branch_init, policy, unwritten, written);
		if (ret)
			goto out;
		if (!name_equals(&nv, written)) {
			pr_err("tpm: recorded register has an obsolete policy; "
			       "trusted reboot required");
			ret = -EEXIST;
			goto out;
		}
		if (memneq_explicit(info->writer_public, rec.writer_public,
				    sizeof(info->writer_public))) {
			pr_err("tpm: recorded NV writer differs from the guarded key");
			ret = -EKEYREJECTED;
			goto out;
		}
		if (nv.defined && nv.written && name_equals(&nv, rec.name)) {
			ret = tpm_nv_read(tpm, NV_INDEX,
					  info->value);
			if (ret)
				goto out;
			memcpy(info->name, nv.name, nv.name_len);
			info->name_len = nv.name_len;
			memcpy(info->pcr_before, rec.pcr_before, 32);
			memcpy(info->phase_before, rec.phase_before, 32);
			memcpy(info->anchor_digest, rec.anchor_digest, 32);
			ret = chain_anchor(info->name, info->anchor,
					   sizeof(info->anchor));
			if (ret)
				goto out;
			info->initrd = rec.initrd;
			info->reused = true;
			goto out;
		}
		pr_err("tpm: register 0x%08x bound this boot is %s; not "
		       "binding another before the next TPM reset",
		       NV_INDEX, !nv.defined ? "gone" :
		       !nv.written ? "unwritten" : "not the recorded index");
		ret = -EEXIST;
		goto out;
	}
	if (nv.defined && nv.written)
		pr_warn("tpm: register 0x%08x written this boot without a "
			"record; rebinding it", NV_INDEX);

	ret = tpm_pcr_read(tpm, CHAIN_PCR, info->pcr_before);
	if (!ret)
		ret = tpm_pcr_read(tpm, CHAIN_PHASE_PCR,
				   info->phase_before);
	if (ret)
		goto out;
	info->initrd = in_initrd();
	ret = register_writer(tpm, info->writer_public);
	if (ret)
		goto out;
	ret = register_expectation(info->pcr_before, info->phase_before,
				   info->writer_public, branch_written,
				   branch_init, policy, unwritten, written);
	if (!ret)
		ret = chain_anchor(written, info->anchor, sizeof(info->anchor));
	if (ret)
		goto out;

	if (!nv.defined || nv.written || !name_equals(&nv, unwritten)) {
		ret = register_define(tpm, nv.defined, policy);
		if (ret)
			goto out;
		ret = tpm_nv_info(tpm, NV_INDEX, &nv);
		if (ret)
			goto out;
		if (!nv.defined || !name_equals(&nv, unwritten)) {
			pr_err("tpm: register 0x%08x name does not match the "
			       "computed public area", NV_INDEX);
			ret = -EPROTO;
			goto out;
		}
	}

	ret = tpm_nv_extend_first(tpm, NV_INDEX,
				  CHAIN_PCR_MASK, branch_written,
				  branch_init, event);
	if (ret)
		goto out;
	memcpy(info->name, written, sizeof(written));
	info->name_len = sizeof(written);
	ret = sha256_calc(info->anchor, strlen(info->anchor),
			  info->anchor_digest);
	if (ret)
		goto out;
	ret = tpm_pcr_extend(tpm, CHAIN_PCR,
			     info->anchor_digest);
	if (ret) {
		pr_err("tpm: register written but PCR %u not anchored; "
		       "the init branch stays open until reboot",
		       CHAIN_PCR);
		goto out;
	}
	ret = tpm_nv_read(tpm, NV_INDEX, info->value);
out:
	tpm_close(tpm);
	return ret;
}

int chain_extend(const __u8 event[32], __u8 out_chain[32])
{
	__u8 writer_public[TPM_NV_RSA_BYTES];
	__u8 branch_written[32], branch_init[32], policy[32], values[64];
	struct eventlog_init rec;
	struct tpm_nv_info nv;
	struct tpm *tpm = NULL;
	__u32 reset;
	int ret;

	ret = eventlog_boot_init(&rec);
	if (ret)
		return -ENODEV;		/* no register this boot */
	bind_values(rec.pcr_before, rec.phase_before, values);
	ret = tpm_register_policy(CHAIN_PCR_MASK, values, 2, rec.writer_public,
				  branch_written, branch_init, policy);
	if (ret) {
		pr_err("tpm: compute signed register policy: %s", strerror(-ret));
		return ret;
	}

	ret = tpm_open(&tpm);
	if (ret)
		return -ENODEV;
	ret = tpm_nv_info(tpm, NV_INDEX, &nv);
	if (ret)
		goto out;
	if (!nv.defined || !nv.written) {
		ret = -ENODEV;
		goto out;
	}
	if (!name_equals(&nv, rec.name)) {
		pr_err("tpm: register 0x%08x is not the index init recorded "
		       "(recreated?)", NV_INDEX);
		ret = -EACCES;
		goto out;
	}
	if (memneq_explicit(nv.policy, policy, sizeof(policy))) {
		pr_err("tpm: register write policy is obsolete or substituted");
		ret = -EACCES;
		goto out;
	}
	ret = tpm_reset_count(tpm, &reset);
	if (ret)
		goto out;
	if (!rec.have_reset_count || reset != rec.reset_count) {
		pr_err("tpm: register reset differs from the init record");
		ret = -EACCES;
		goto out;
	}
	ret = register_writer(tpm, writer_public);
	if (ret)
		goto out;
	if (memneq_explicit(writer_public, rec.writer_public,
			    sizeof(writer_public))) {
		pr_err("tpm: recorded NV writer differs from the guarded key");
		ret = -EKEYREJECTED;
		goto out;
	}
	ret = tpm_nv_extend(tpm, NV_INDEX, branch_written,
			    branch_init, event);
	if (ret) {
		ret = -EIO;
		goto out;
	}
	if (out_chain)
		ret = tpm_nv_read(tpm, NV_INDEX, out_chain) ?
		     -EIO : 0;
out:
	tpm_close(tpm);
	return ret;
}

int chain_read(__u8 out[32])
{
	struct tpm *tpm = NULL;
	int ret;

	ret = tpm_open(&tpm);
	if (ret)
		return -ENODEV;
	ret = tpm_nv_read(tpm, NV_INDEX, out);
	tpm_close(tpm);
	return ret ? -ENODEV : 0;
}

bool chain_bound(void)
{
	struct tpm *tpm = NULL;
	struct tpm_nv_info nv;
	bool bound;

	if (tpm_open_quiet(&tpm))
		return false;
	bound = tpm_nv_info(tpm, NV_INDEX, &nv) == 0 &&
		nv.defined && nv.written;
	tpm_close(tpm);
	return bound;
}

int chain_status(struct chain_status *st)
{
	__u8 branch_written[32], branch_init[32], policy[32], values[64];
	__u8 expected[TPM_NAME_LEN];
	struct tpm *tpm = NULL;
	struct tpm_nv_info nv;
	__u32 reset_count = 0;
	int ret;

	memset(st, 0, sizeof(*st));
	st->logged = eventlog_boot_init(&st->init) == 0;
	st->rebound = st->logged && st->init.records_epoch > 1;
	ret = tpm_open_quiet(&tpm);
	if (ret)
		return -ENODEV;
	st->tpm = true;
	ret = tpm_reset_count(tpm, &reset_count);
	if (ret)
		goto out;
	ret = tpm_nv_info(tpm, NV_INDEX, &nv);
	if (ret)
		goto out;
	st->defined = nv.defined;
	st->written = nv.written;
	memcpy(st->name, nv.name, nv.name_len);
	st->name_len = nv.name_len;
	if (nv.defined && nv.written)
		ret = tpm_nv_read(tpm, NV_INDEX, st->value);
	st->anchored = nv.defined && nv.written && st->logged &&
		       name_equals(&nv, st->init.name) &&
		       (!st->init.have_reset_count ||
			st->init.reset_count == reset_count);
	if (st->anchored) {
		bind_values(st->init.pcr_before, st->init.phase_before, values);
		ret = tpm_register_policy(CHAIN_PCR_MASK, values, 2,
					  st->init.writer_public, branch_written,
					  branch_init, policy);
		if (ret) {
			pr_err("tpm: compute signed register policy: %s", strerror(-ret));
			st->anchored = false;
			goto out;
		}
		st->anchored = !tpm_nv_name(NV_INDEX,
					    TPM_REGISTER_ATTRS | TPM_NV_WRITTEN,
					    policy, 32, expected) &&
			       name_equals(&nv, expected);
	}
out:
	tpm_close(tpm);
	return ret;
}
