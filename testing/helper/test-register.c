// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Drives the measurement register against a TPM (SHIRUDO_TPM_TCTI) with
 * the eventlog and certificate redirected by environment. Subcommand on
 * argv[1]; prints what a shell test asserts on.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include <shirudo/misc.h>

#include "attest.h"
#include "chain.h"
#include "config.h"
#include "crypto.h"
#include "eventlog.h"
#include "hex.h"
#include "identity.h"
#include "json.h"
#include "malloc.h"
#include "nv_writer.h"
#include "paths.h"
#include "tpm.h"
#include "version.h"

/* Record the TPM writer's public identity before the VM attaches its LSM. */
static int writer_create(void)
{
	const struct guard_map *map = &shirudo_guard_maps[GUARD_IDENTITY];
	struct bpf_map_create_opts opts = {
		.sz = sizeof(opts),
		.map_flags = map->flags,
	};
	struct identity id = {};
	int fd, ret;
	__u32 zero = 0;

	ret = nv_writer_create(id.nv_writer_seed, id.nv_writer_public);
	if (ret)
		goto out;
	fd = bpf_map_create(map->type, map->name, map->key_size,
			    map->value_size, map->max_entries, &opts);
	if (fd < 0) {
		ret = -errno;
		goto out;
	}
	if (bpf_map_update_elem(fd, &zero, &id, BPF_ANY) ||
	    bpf_map_freeze(fd) || bpf_obj_pin(fd, IDENTITY_PIN))
		ret = -errno;
	close(fd);
	if (!ret)
		return 0;
out:
	fprintf(stderr, "TPM writer setup: %s\n", strerror(-ret));
	return 1;
}

static int writer_remove(void)
{
	if (unlink(IDENTITY_PIN)) {
		perror("unlink protocol-test identity");
		return 1;
	}
	return 0;
}

static void puthex(const __u8 *b, size_t n)
{
	char h[2 * 1024 + 1];

	if (n > 1024)
		return;
	hex_encode(b, n, h);
	printf("%s\n", h);
}

/* Record an init the way shirudo init does, minus the set details. */
static int append_init(const __u8 event[32],
		       const struct chain_init_info *info)
{
	char buf[4096], ts[32], boot_id[64], nv_index[16];
	char hex[2 * TPM_NV_RSA_BYTES + 1];
	struct json_emit e = { .buf = buf, .cap = sizeof(buf) };

	eventlog_timestamp(ts, sizeof(ts));
	eventlog_boot_id(boot_id, sizeof(boot_id));
	snprintf(nv_index, sizeof(nv_index), "0x%08X", NV_INDEX);
	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_kv_string(&e, "ts", ts);
	json_kv_string(&e, "nv_index", nv_index);
	json_kv_string(&e, "alg", "sha256");
	hex_encode(event, 32, hex);
	json_kv_string(&e, "digest", hex);
	json_kv_string(&e, "type", "init");
	json_kv_string(&e, "boot_id", boot_id);
	json_kv_int(&e, "tpm_reset_count", info->reset_count);
	json_kv_int(&e, "pcr", CHAIN_PCR);
	hex_encode(info->pcr_before, 32, hex);
	json_kv_string(&e, "pcr_before", hex);
	json_kv_int(&e, "phase_pcr", CHAIN_PHASE_PCR);
	hex_encode(info->phase_before, 32, hex);
	json_kv_string(&e, "phase_before", hex);
	json_kv_string(&e, "bound_in", info->initrd ? "initrd" : "root");
	hex_encode(info->name, info->name_len, hex);
	json_kv_string(&e, "nv_name", hex);
	hex_encode(info->writer_public, sizeof(info->writer_public), hex);
	json_kv_string(&e, "nv_writer_public", hex);
	json_kv_string(&e, "anchor", info->anchor);
	hex_encode(info->anchor_digest, 32, hex);
	json_kv_string(&e, "anchor_digest", hex);
	hex_encode(info->value, 32, hex);
	json_kv_string(&e, "chain", hex);
	json_obj_close(&e);
	if (e.err)
		return e.err;
	return eventlog_append(buf);
}

static int append_event(const char *type, const char *name,
			const __u8 payload[32], const __u8 event[32],
			const __u8 chain[32])
{
	char buf[4096], ts[32], boot_id[64], nv_index[16], hex[65];
	struct json_emit e = { .buf = buf, .cap = sizeof(buf) };

	eventlog_timestamp(ts, sizeof(ts));
	eventlog_boot_id(boot_id, sizeof(boot_id));
	snprintf(nv_index, sizeof(nv_index), "0x%08X", NV_INDEX);
	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_kv_string(&e, "ts", ts);
	json_kv_string(&e, "nv_index", nv_index);
	json_kv_string(&e, "alg", "sha256");
	hex_encode(event, 32, hex);
	json_kv_string(&e, "digest", hex);
	json_kv_string(&e, "type", type);
	json_kv_string(&e, "boot_id", boot_id);
	json_obj_open_key(&e, "upatch");
	json_kv_string(&e, "name", name);
	hex_encode(payload, 32, hex);
	json_kv_string(&e, "payload_sha256", hex);
	json_obj_close(&e);
	hex_encode(chain, 32, hex);
	json_kv_string(&e, "chain", hex);
	json_obj_close(&e);
	if (e.err)
		return e.err;
	return eventlog_append(buf);
}

static int append_tree(__s64 seq, const char *op, const char *id,
		       const char *operation_digest, const __u8 event[32],
		       const __u8 chain[32])
{
	char buf[4096], ts[32], boot_id[64], nv_index[16], hex[65];
	struct json_emit e = { .buf = buf, .cap = sizeof(buf) };

	eventlog_timestamp(ts, sizeof(ts));
	eventlog_boot_id(boot_id, sizeof(boot_id));
	snprintf(nv_index, sizeof(nv_index), "0x%08X", NV_INDEX);
	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_kv_string(&e, "ts", ts);
	json_kv_string(&e, "nv_index", nv_index);
	json_kv_string(&e, "alg", "sha256");
	hex_encode(event, 32, hex);
	json_kv_string(&e, "digest", hex);
	json_kv_string(&e, "type", "tree_op");
	json_kv_string(&e, "boot_id", boot_id);
	json_obj_open_key(&e, "tree");
	json_kv_int(&e, "seq", seq);
	json_kv_string(&e, "op", op);
	json_kv_string(&e, "id", id);
	json_kv_string(&e, "operation_digest", operation_digest);
	json_obj_close(&e);
	hex_encode(chain, 32, hex);
	json_kv_string(&e, "chain", hex);
	json_obj_close(&e);
	if (e.err)
		return e.err;
	return eventlog_append(buf);
}

int main(int argc, char **argv)
{
	__u8 event[32], chain[32];
	int ret;

	if (argc < 2)
		return 2;

	if (!strcmp(argv[1], "writer-create") && argc == 2)
		return writer_create();
	if (!strcmp(argv[1], "writer-remove") && argc == 2)
		return writer_remove();
	if (!strcmp(argv[1], "writer-public") && argc == 2) {
		__u8 public[TPM_NV_RSA_BYTES];
		__u8 seed[32];

		if (nv_writer_read(seed, public))
			return 1;
		puthex(public, sizeof(public));
		return 0;
	}

	if (strcmp(argv[1], "init") == 0 && argc == 3) {
		struct chain_init_info info;

		if (hex_decode(argv[2], event, 32))
			return 2;
		ret = chain_init(event, &info);
		printf("rc=%d\n", ret);
		if (ret)
			return 1;
		printf("reused=%d\n", info.reused);
		printf("reset_count=%u\n", info.reset_count);
		printf("value=");
		puthex(info.value, 32);
		printf("name=");
		puthex(info.name, info.name_len);
		printf("pcr_before=");
		puthex(info.pcr_before, 32);
		printf("phase_before=");
		puthex(info.phase_before, 32);
		printf("bound_in=%s\n", info.initrd ? "initrd" : "root");
		printf("anchor=%s\n", info.anchor);
		if (!info.reused && append_init(event, &info))
			return 1;
		return 0;
	}
	if ((strcmp(argv[1], "load") == 0 ||
	     strcmp(argv[1], "java-load") == 0) && argc == 4) {
		__u32 type = argv[1][0] == 'j' ? UPATCH_TYPE_JAVA :
						 UPATCH_TYPE_BPF;
		__u8 payload[32];

		if (hex_decode(argv[3], payload, 32))
			return 2;
		if (chain_upatch_event(chain_upatch_tag(type, true), argv[2],
				       payload, event))
			return 1;
		ret = chain_extend(event, chain);
		printf("rc=%d\n", ret);
		if (ret)
			return 1;
		printf("value=");
		puthex(chain, 32);
		return append_event(eventlog_upatch_record(type, true), argv[2],
				    payload, event, chain) ? 1 : 0;
	}
	/* A tree operation, with the digest in the form the target records. */
	if (strcmp(argv[1], "tree") == 0 && argc == 6) {
		__u8 operation[32];
		__s64 seq = atoi(argv[2]);

		if (sha256_digest_decode(argv[5], operation))
			return 2;
		if (chain_tree_event(seq, operation, event))
			return 2;
		ret = chain_extend(event, chain);
		printf("rc=%d\n", ret);
		if (ret)
			return 1;
		printf("value=");
		puthex(chain, 32);
		return append_tree(seq, argv[3], argv[4], argv[5], event,
				   chain) ? 1 : 0;
	}
	if (strcmp(argv[1], "extend-raw") == 0 && argc == 3) {
		if (hex_decode(argv[2], event, 32))
			return 2;
		ret = chain_extend(event, chain);
		printf("rc=%d\n", ret);
		if (ret)
			return 1;
		printf("value=");
		puthex(chain, 32);
		return 0;
	}
	if (strcmp(argv[1], "read") == 0) {
		ret = chain_read(chain);
		printf("rc=%d\n", ret);
		if (ret)
			return 1;
		printf("value=");
		puthex(chain, 32);
		return 0;
	}
	if (strcmp(argv[1], "status") == 0) {
		struct chain_status st;

		ret = chain_status(&st);
		printf("rc=%d\n", ret);
		printf("tpm=%d defined=%d written=%d logged=%d anchored=%d\n",
		       st.tpm, st.defined, st.written, st.logged, st.anchored);
		printf("rebound=%d\n", st.rebound);
		if (st.defined && st.written) {
			printf("value=");
			puthex(st.value, 32);
		}
		return ret ? 1 : 0;
	}
	/* A measurement into a PCR, as systemd's boot phases make them. */
	if (strcmp(argv[1], "pcr-extend") == 0 && argc == 4) {
		struct tpm *tpm = NULL;
		__u8 d[32];

		if (hex_decode(argv[3], d, 32) || tpm_open(&tpm))
			return 2;
		ret = tpm_pcr_extend(tpm, (__u32)atoi(argv[2]), d);
		tpm_close(tpm);
		printf("rc=%d\n", ret);
		return ret ? 1 : 0;
	}
	if (strcmp(argv[1], "pcr") == 0 && argc == 3) {
		struct tpm *tpm = NULL;
		__u8 v[32];

		if (tpm_open(&tpm))
			return 1;
		ret = tpm_pcr_read(tpm, (__u32)atoi(argv[2]), v);
		tpm_close(tpm);
		if (ret)
			return 1;
		puthex(v, 32);
		return 0;
	}
	/*
	 * The endorsement key of a type, as a target without a certificate
	 * presents it.
	 */
	if (strcmp(argv[1], "ek-public") == 0 && argc == 3) {
		struct tpm_key ek = { .handle = 0 };
		struct tpm *tpm = NULL;

		if (tpm_open(&tpm))
			return 1;
		ret = tpm_ek_create(tpm, strcmp(argv[2], "rsa") == 0,
				    &ek);
		if (!ret) {
			printf("public=");
			puthex(ek.public, ek.public_len);
			printf("name=");
			puthex(ek.name, ek.name_len);
			tpm_key_flush(tpm, &ek);
		}
		tpm_close(tpm);
		printf("rc=%d\n", ret);
		return ret ? 1 : 0;
	}
	/* The attack: recreate the index with the same public area. */
	if (strcmp(argv[1], "recreate") == 0) {
		struct tpm_nv_info nv;
		struct tpm *tpm = NULL;

		if (tpm_open(&tpm))
			return 1;
		ret = tpm_nv_info(tpm, NV_INDEX, &nv);
		if (!ret && nv.defined)
			ret = tpm_nv_undefine(tpm, NV_INDEX,
					      NULL, 0);
		if (!ret)
			ret = tpm_nv_define(tpm, NV_INDEX,
					    nv.policy, NULL, 0);
		if (!ret)
			ret = tpm_nv_info(tpm, NV_INDEX, &nv);
		tpm_close(tpm);
		printf("rc=%d\n", ret);
		if (ret)
			return 1;
		printf("written=%d\nname=", nv.written);
		puthex(nv.name, nv.name_len);
		return 0;
	}
	/* The attack: try the init branch again after the anchor. */
	if (strcmp(argv[1], "first-write") == 0 && argc == 3) {
		__u8 branch_written[32], branch_init[32], policy[32];
		struct eventlog_init rec;
		struct tpm *tpm = NULL;
		__u8 writer_public[TPM_NV_RSA_BYTES];
		__u8 writer_seed[32], values[64];

		if (hex_decode(argv[2], event, 32) ||
		    eventlog_boot_init(&rec) ||
		    nv_writer_read(writer_seed, writer_public) ||
		    memcmp(writer_public, rec.writer_public, sizeof(writer_public)))
			return 2;
		memcpy(values, rec.pcr_before, 32);
		memcpy(values + 32, rec.phase_before, 32);
		ret = tpm_register_policy(CHAIN_PCR_MASK, values, 2,
					  rec.writer_public, branch_written, branch_init, policy);
		if (ret) {
			fprintf(stderr, "register policy: %s\n", strerror(-ret));
			return 1;
		}
		if (tpm_open(&tpm))
			return 1;
		ret = tpm_nv_set_writer(tpm, writer_seed, writer_public);
		if (!ret)
			ret = tpm_nv_extend_first(tpm, NV_INDEX,
						  CHAIN_PCR_MASK,
						  branch_written, branch_init,
						  event);
		tpm_close(tpm);
		printf("rc=%d\n", ret);
		return ret ? 1 : 0;
	}
	/*
	 * The attack: a register of the target's own at another handle,
	 * bound to PCRs the target can extend and reset at will, written
	 * with the init event the operator expects, anchored into one of
	 * those PCRs and certified by the genuine attestation key in the
	 * real register's place.
	 */
	if (strcmp(argv[1], "forge") == 0 && argc == 7) {
		struct tpm_key ak = { .handle = 0 }, ek = { .handle = 0 };
		char hex[2 * TPM_ATTEST_MAX + 1], buf[32 * 1024];
		struct json_emit e = { .buf = buf, .cap = sizeof(buf) };
		struct tpm_attestation quote = {}, certify = {}, after = {};
		__u8 hashes[2][32] = {}, quote_nonce[32], after_nonce[32];
		__u8 values[24][32] = {}, before[64], anchor_digest[32];
		__u8 branch_written[32], branch_init[32], policy[32];
		__u32 index, pcr, phase, mask, quoted, reset = 0, i;
		struct tpm_key ak_copy = {}, ek_copy = {};
		__u8 writer_public[TPM_NV_RSA_BYTES];
		char ts[32], boot_id[64], nv_index[16];
		__u8 writer_seed[TPM_DIGEST_LEN];
		size_t nonce_len = strlen(argv[6]) / 2;
		char anchor[CHAIN_ANCHOR_MAX];
		struct tpm *tpm = NULL;
		__u8 value[32], nonce[64];
		struct tpm_nv_info nv;

		index = (__u32)strtoul(argv[2], NULL, 16);
		pcr = (__u32)atoi(argv[3]);
		phase = (__u32)atoi(argv[4]);
		mask = (1u << pcr) | (1u << phase);
		quoted = ATTEST_PCR_DEFAULT | mask;
		if (pcr > 23 || phase > 23 || pcr == phase ||
		    hex_decode(argv[5], event, 32) ||
		    nonce_len == 0 || nonce_len > sizeof(nonce) ||
		    hex_decode(argv[6], nonce, nonce_len))
			return 2;
		if (nv_writer_read(writer_seed, writer_public))
			return 1;
		if (tpm_open(&tpm))
			return 1;
		ret = tpm_nv_set_writer(tpm, writer_seed, writer_public);
		if (!ret)
			ret = tpm_reset_count(tpm, &reset);
		if (!ret)
			ret = tpm_pcr_read(tpm, pcr, before);
		if (!ret)
			ret = tpm_pcr_read(tpm, phase, before + 32);
		if (!ret)
			ret = tpm_register_policy(mask, before, 2, writer_public,
						  branch_written, branch_init, policy);
		if (!ret)
			ret = tpm_nv_define(tpm, index, policy, NULL, 0);
		if (!ret)
			ret = tpm_nv_extend_first(tpm, index, mask,
						  branch_written, branch_init,
						  event);
		if (!ret)
			ret = tpm_nv_info(tpm, index, &nv);
		if (!ret)
			ret = chain_anchor(nv.name, anchor, sizeof(anchor));
		if (!ret)
			ret = sha256_buffer(anchor, strlen(anchor),
					    anchor_digest);
		if (!ret)
			ret = tpm_pcr_extend(tpm, pcr, anchor_digest);
		if (!ret)
			ret = tpm_nv_read(tpm, index, value);
		if (!ret)
			ret = tpm_ak_create(tpm, &ak);
		if (!ret)
			ret = tpm_ek_create(tpm, false, &ek);
		for (i = 0; !ret && i < 24; i++) {
			if (quoted & (1u << i))
				ret = tpm_pcr_read(tpm, i, values[i]);
		}
		/*
		 * As attest collects: the certification answers the nonce,
		 * the quote commits to its signature and the closing
		 * certification to the quote's. No config register here.
		 */
		if (!ret)
			ret = tpm_nv_certify(tpm, &ak, index, nonce, nonce_len,
					     &certify);
		if (!ret)
			ret = sha256_buffer(certify.signature,
					    certify.signature_len, hashes[0]);
		if (!ret)
			ret = sha256_buffer(hashes, sizeof(hashes), quote_nonce);
		if (!ret)
			ret = tpm_quote(tpm, &ak, quote_nonce,
					sizeof(quote_nonce), quoted, &quote);
		if (!ret)
			ret = sha256_buffer(quote.signature, quote.signature_len,
					    after_nonce);
		if (!ret)
			ret = tpm_nv_certify(tpm, &ak, index, after_nonce,
					     sizeof(after_nonce), &after);
		/* Flushing scrubs the key; keep the public parts. */
		memcpy(&ak_copy, &ak, sizeof(ak_copy));
		memcpy(&ek_copy, &ek, sizeof(ek_copy));
		tpm_key_flush(tpm, &ek);
		tpm_key_flush(tpm, &ak);
		tpm_close(tpm);
		if (ret) {
			printf("rc=%d\n", ret);
			return 1;
		}

		eventlog_timestamp(ts, sizeof(ts));
		eventlog_boot_id(boot_id, sizeof(boot_id));
		snprintf(nv_index, sizeof(nv_index), "0x%08X", index);
		json_obj_open(&e);
		json_kv_int(&e, "schema", 1);
		json_kv_string(&e, "kind", "shirudo-attestation");
		json_kv_string(&e, "version_id", shirudo_version_id);
		json_kv_string(&e, "ts", ts);
		json_kv_string(&e, "boot_id", boot_id);
		hex_encode(nonce, nonce_len, hex);
		json_kv_string(&e, "nonce", hex);
		json_kv_string(&e, "pcr_bank", "sha256");
		json_kv_int(&e, "pcr_mask", quoted);
		json_arr_open(&e, "pcrs");
		for (i = 0; i < 24; i++) {
			if (!(quoted & (1u << i)))
				continue;
			json_obj_open(&e);
			json_kv_int(&e, "index", i);
			hex_encode(values[i], 32, hex);
			json_kv_string(&e, "value", hex);
			json_obj_close(&e);
		}
		json_arr_close(&e);
		json_obj_open_key(&e, "ak");
		hex_encode(ak_copy.public, ak_copy.public_len, hex);
		json_kv_string(&e, "public", hex);
		hex_encode(ak_copy.name, ak_copy.name_len, hex);
		json_kv_string(&e, "name", hex);
		json_obj_close(&e);
		json_obj_open_key(&e, "ek");
		json_kv_string(&e, "type", "ecc");
		hex_encode(ek_copy.public, ek_copy.public_len, hex);
		json_kv_string(&e, "public", hex);
		hex_encode(ek_copy.name, ek_copy.name_len, hex);
		json_kv_string(&e, "name", hex);
		json_obj_close(&e);
		json_obj_open_key(&e, "quote");
		hex_encode(quote.attest, quote.attest_len, hex);
		json_kv_string(&e, "attest", hex);
		hex_encode(quote.signature, quote.signature_len, hex);
		json_kv_string(&e, "signature", hex);
		json_obj_close(&e);
		json_obj_open_key(&e, "register");
		json_kv_string(&e, "nv_index", nv_index);
		json_kv_int(&e, "pcr", pcr);
		hex_encode(nv.name, nv.name_len, hex);
		json_kv_string(&e, "name", hex);
		hex_encode(value, 32, hex);
		json_kv_string(&e, "value", hex);
		hex_encode(certify.attest, certify.attest_len, hex);
		json_kv_string(&e, "attest", hex);
		hex_encode(certify.signature, certify.signature_len, hex);
		json_kv_string(&e, "signature", hex);
		hex_encode(after.attest, after.attest_len, hex);
		json_kv_string(&e, "after_attest", hex);
		hex_encode(after.signature, after.signature_len, hex);
		json_kv_string(&e, "after_signature", hex);
		json_obj_close(&e);
		json_arr_open(&e, "eventlog");
		json_obj_open(&e);
		json_kv_int(&e, "schema", 1);
		json_kv_string(&e, "ts", ts);
		json_kv_string(&e, "nv_index", nv_index);
		json_kv_string(&e, "alg", "sha256");
		hex_encode(event, 32, hex);
		json_kv_string(&e, "digest", hex);
		json_kv_string(&e, "type", "init");
		json_kv_string(&e, "boot_id", boot_id);
		json_kv_int(&e, "tpm_reset_count", reset);
		json_kv_int(&e, "pcr", pcr);
		hex_encode(before, 32, hex);
		json_kv_string(&e, "pcr_before", hex);
		json_kv_int(&e, "phase_pcr", phase);
		hex_encode(before + 32, 32, hex);
		json_kv_string(&e, "phase_before", hex);
		json_kv_string(&e, "bound_in", "initrd");
		hex_encode(nv.name, nv.name_len, hex);
		json_kv_string(&e, "nv_name", hex);
		hex_encode(writer_public, sizeof(writer_public), hex);
		json_kv_string(&e, "nv_writer_public", hex);
		json_kv_string(&e, "anchor", anchor);
		hex_encode(anchor_digest, 32, hex);
		json_kv_string(&e, "anchor_digest", hex);
		hex_encode(value, 32, hex);
		json_kv_string(&e, "chain", hex);
		json_obj_close(&e);
		json_arr_close(&e);
		json_kv_null(&e, "credential");
		json_kv_null(&e, "ek_certificate");
		json_obj_open_key(&e, "logs");
		json_kv_null(&e, "firmware");
		json_kv_null(&e, "systemd");
		json_obj_close(&e);
		json_obj_close(&e);
		if (e.err)
			return 1;
		fwrite(buf, 1, e.len, stdout);
		fputc('\n', stdout);
		return 0;
	}
	if (strcmp(argv[1], "evidence") == 0 && (argc == 3 || argc == 4)) {
		struct attest_challenge challenge = {};
		__u8 nonce[64];
		size_t nonce_len = strlen(argv[2]) / 2, len, cap;
		char *doc;

		if (nonce_len > sizeof(nonce) ||
		    hex_decode(argv[2], nonce, nonce_len))
			return 2;
		if (argc == 4 &&
		    attest_challenge_read(argv[3], &challenge)) {
			fprintf(stderr, "evidence: bad challenge\n");
			return 2;
		}
		ret = attest_evidence_config(nonce, nonce_len,
					     ATTEST_PCR_DEFAULT,
					     argc == 4 ? &challenge : NULL,
					     NULL, &doc, &len, &cap);
		if (ret) {
			fprintf(stderr, "evidence: %s\n", strerror(-ret));
			return 1;
		}
		fwrite(doc, 1, len, stdout);
		fputc('\n', stdout);
		xfree(doc, cap);
		return 0;
	}
	return 2;
}
