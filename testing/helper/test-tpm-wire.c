// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Harness for util/tpm_wire: policy digests, names and attestation
 * structure parsing. Subcommand on argv[1]; hex inputs as argv.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shirudo/misc.h>

#include "hex.h"
#include "tpm_wire.h"

static void puthex(const __u8 *b, size_t n)
{
	char h[2 * 2048 + 1];

	if (n > 2048)
		return;
	hex_encode(b, n, h);
	printf("%s\n", h);
}

static int gethex(const char *hex, __u8 *out, size_t cap, size_t *len)
{
	size_t n = strlen(hex);

	if (n & 1 || n / 2 > cap)
		return -1;
	*len = n / 2;
	return hex_decode(hex, out, n / 2);
}

int main(int argc, char **argv)
{
	__u8 public[SHIRUDO_TPM_NV_RSA_BYTES];
	__u8 a[32], b[32], out[32], buf[2048];
	size_t len;

	if (argc < 2)
		return 2;
	if (strcmp(argv[1], "writer-public") == 0 && argc == 3) {
		__u8 area[SHIRUDO_TPM_NV_RSA_PUBLIC_AREA_LEN];

		if (hex_decode(argv[2], buf, SHIRUDO_TPM_NV_RSA_BYTES))
			return 2;
		tpm_writer_public(buf, area);
		puthex(area, sizeof(area));
		return 0;
	}
	if (strcmp(argv[1], "policy-signed") == 0 && argc == 4) {
		if (hex_decode(argv[2], a, 32) ||
		    hex_decode(argv[3], public, sizeof(public)))
			return 2;
		if (tpm_policy_signed(a, public, out))
			return 1;
		puthex(out, 32);
		return 0;
	}
	if (strcmp(argv[1], "extend-cphash") == 0 && argc == 4) {
		if (hex_decode(argv[2], buf, SHIRUDO_TPM_NAME_LEN) ||
		    hex_decode(argv[3], a, 32))
			return 2;
		if (tpm_nv_extend_cphash(buf, a, out))
			return 1;
		puthex(out, 32);
		return 0;
	}
	if (strcmp(argv[1], "writer-auth") == 0 && argc == 4) {
		if (gethex(argv[2], buf, 64, &len) ||
		    hex_decode(argv[3], a, 32) ||
		    tpm_writer_auth_hash(buf, len, a, out))
			return 2;
		puthex(out, 32);
		return 0;
	}
	if (strcmp(argv[1], "command-code") == 0 && argc == 4) {
		__u32 command_code = (__u32)strtoul(argv[3], NULL, 0);

		if (hex_decode(argv[2], a, 32))
			return 2;
		tpm_policy_command_code(a, command_code, out);
		puthex(out, 32);
		return 0;
	}
	if (strcmp(argv[1], "register-final") == 0 && argc == 5) {
		if (hex_decode(argv[2], a, 32) ||
		    hex_decode(argv[3], b, 32) ||
		    hex_decode(argv[4], public, sizeof(public)))
			return 2;
		if (tpm_register_policy_final(a, b, public, out))
			return 1;
		puthex(out, 32);
		return 0;
	}
	if (strcmp(argv[1], "nv-written") == 0 && argc == 4) {
		if (hex_decode(argv[2], a, 32))
			return 2;
		tpm_policy_nv_written(a, atoi(argv[3]) != 0, out);
		puthex(out, 32);
		return 0;
	}
	if (strcmp(argv[1], "pcr") == 0 && argc == 5) {
		if (hex_decode(argv[2], a, 32) ||
		    hex_decode(argv[4], b, 32))
			return 2;
		tpm_policy_pcr(a, (__u32)strtoul(argv[3], NULL, 0),
			       b, out);
		puthex(out, 32);
		return 0;
	}
	if (strcmp(argv[1], "or") == 0 && argc == 4) {
		if (hex_decode(argv[2], a, 32) ||
		    hex_decode(argv[3], b, 32))
			return 2;
		tpm_policy_or(a, b, out);
		puthex(out, 32);
		return 0;
	}
	if (strcmp(argv[1], "register-policy") == 0 && argc == 6) {
		__u8 w[32], i[32], p[32], values[64];

		if (hex_decode(argv[3], values, 32) ||
		    hex_decode(argv[4], values + 32, 32) ||
		    hex_decode(argv[5], public, sizeof(public)))
			return 2;
		if (tpm_register_policy((__u32)strtoul(argv[2], NULL, 0),
					values, 2, public, w, i, p))
			return 1;
		puthex(w, 32);
		puthex(i, 32);
		puthex(p, 32);
		return 0;
	}
	if (strcmp(argv[1], "nv-name") == 0 && argc == 5) {
		__u8 name[SHIRUDO_TPM_NAME_LEN];

		if (hex_decode(argv[4], a, 32))
			return 2;
		tpm_nv_name((__u32)strtoul(argv[2], NULL, 0),
			    (__u32)strtoul(argv[3], NULL, 0), a, 32,
			    name);
		puthex(name, sizeof(name));
		return 0;
	}
	if (strcmp(argv[1], "object-name") == 0 && argc == 3) {
		__u8 name[SHIRUDO_TPM_NAME_LEN];

		if (gethex(argv[2], buf, sizeof(buf), &len) ||
		    tpm_object_name(buf, len, name))
			return 1;
		puthex(name, sizeof(name));
		return 0;
	}
	if (strcmp(argv[1], "ecc-public") == 0 && argc == 3) {
		struct shirudo_tpm_ecc_public pub;
		int rc;

		if (gethex(argv[2], buf, sizeof(buf), &len))
			return 2;
		rc = tpm_ecc_public_parse(buf, len, &pub);
		printf("rc=%d\n", rc);
		if (rc)
			return 0;
		printf("attrs=0x%08x scheme=0x%04x hash=0x%04x curve=0x%04x\n",
		       pub.attrs, pub.scheme, pub.hash, pub.curve);
		puthex(pub.x, 32);
		puthex(pub.y, 32);
		return 0;
	}
	if (strcmp(argv[1], "public") == 0 && argc == 3) {
		struct shirudo_tpm_public pub;
		__u8 again[512];
		size_t again_len = 0;
		int rc;

		if (gethex(argv[2], buf, sizeof(buf), &len))
			return 2;
		rc = tpm_public_parse(buf, len, &pub);
		printf("rc=%d\n", rc);
		if (rc)
			return 0;
		printf("type=0x%04x attrs=0x%08x policy_len=%zu sym=0x%04x/%u/0x%04x "
		       "scheme=0x%04x/0x%04x curve=0x%04x rsa_bits=%u exponent=%u "
		       "n_len=%zu\n", pub.type, pub.attrs, pub.policy_len,
		       pub.sym_alg, pub.sym_bits, pub.sym_mode, pub.scheme,
		       pub.scheme_hash, pub.curve, pub.rsa_bits,
		       pub.rsa_exponent, pub.n_len);
		rc = tpm_public_marshal(&pub, again, sizeof(again),
					&again_len);
		printf("marshal_rc=%d same=%d\n", rc,
		       rc == 0 && again_len == len && !memcmp(again, buf, len));
		return 0;
	}
	if (strcmp(argv[1], "kdfa") == 0 && argc == 6) {
		__u8 key[64], ctx[64], res[64];
		size_t key_len, ctx_len, res_len = (size_t)atoi(argv[5]);

		if (gethex(argv[2], key, sizeof(key), &key_len) ||
		    gethex(strcmp(argv[4], "-") ? argv[4] : "", ctx, sizeof(ctx),
			   &ctx_len) || res_len > sizeof(res))
			return 2;
		if (tpm_kdfa(key, key_len, argv[3], ctx, ctx_len, NULL, 0,
			     res, res_len))
			return 1;
		puthex(res, res_len);
		return 0;
	}
	if (strcmp(argv[1], "kdfe") == 0 && argc == 6) {
		__u8 z[32], u[64], v[64], res[32];
		size_t z_len, u_len, v_len;

		if (gethex(argv[2], z, sizeof(z), &z_len) || z_len != 32 ||
		    gethex(argv[4], u, sizeof(u), &u_len) ||
		    gethex(argv[5], v, sizeof(v), &v_len))
			return 2;
		tpm_kdfe(z, argv[3], u, u_len, v, v_len, res);
		puthex(res, 32);
		return 0;
	}
	if (strcmp(argv[1], "ek-policy") == 0) {
		puthex(shirudo_tpm_ek_policy, 32);
		return 0;
	}
	if (strcmp(argv[1], "credential") == 0 && argc == 5) {
		__u8 seed[32], name[SHIRUDO_TPM_NAME_LEN], cred[32];
		__u8 blob[SHIRUDO_TPM_ID_OBJECT_LEN];
		size_t n;

		if (gethex(argv[2], seed, sizeof(seed), &n) || n != 32 ||
		    gethex(argv[3], name, sizeof(name), &n) ||
		    n != SHIRUDO_TPM_NAME_LEN ||
		    gethex(argv[4], cred, sizeof(cred), &n) || n != 32)
			return 2;
		if (tpm_credential_protect(seed, name, cred, blob))
			return 1;
		puthex(blob, sizeof(blob));
		return 0;
	}
	if (strcmp(argv[1], "signature") == 0 && argc == 3) {
		__u8 r[32], s[32];
		int rc;

		if (gethex(argv[2], buf, sizeof(buf), &len))
			return 2;
		rc = tpm_ecdsa_signature_parse(buf, len, r, s);
		printf("rc=%d\n", rc);
		if (rc)
			return 0;
		puthex(r, 32);
		puthex(s, 32);
		return 0;
	}
	if (strcmp(argv[1], "attest") == 0 && argc == 3) {
		struct shirudo_tpm_attest at;
		int rc;

		if (gethex(argv[2], buf, sizeof(buf), &len))
			return 2;
		rc = tpm_attest_parse(buf, len, &at);
		printf("rc=%d\n", rc);
		if (rc)
			return 0;
		printf("type=0x%04x reset=%u restart=%u safe=%d\n", at.type,
		       at.reset_count, at.restart_count, at.safe);
		printf("signer=");
		puthex(at.signer, at.signer_len);
		printf("extra=");
		puthex(at.extra, at.extra_len);
		if (at.type == SHIRUDO_TPM_ST_ATTEST_QUOTE) {
			printf("mask=0x%06x\n", at.pcr_mask);
			printf("pcr_digest=");
			puthex(at.pcr_digest, 32);
		} else {
			printf("index_name=");
			puthex(at.index_name, at.index_name_len);
			printf("offset=%u\nnv=", at.offset);
			puthex(at.nv_data, at.nv_len);
		}
		return 0;
	}
	return 2;
}
