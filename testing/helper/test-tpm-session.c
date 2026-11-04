// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tpm_internal.h"

#include <shirudo/byteorder.h>
#include <shirudo/string.h>

#include "chain.h"
#include "crypto.h"
#include "tpm-session.h"

#define TEST_INDEX 0x01818E02u
#define CHECK(expr) do { \
	if (!(expr)) { \
		fprintf(stderr, "line %d: %s\n", __LINE__, #expr); \
		goto out; \
	} \
} while (0)

static struct identity identity;
static int identity_error;

int __wrap_identity_read(struct identity *out)
{
	*out = identity;
	return identity_error;
}

enum fault_mode {
	CAPTURE,
	REPLAY,
	FORGE,
	CORRUPT,
	CORRUPT_HMAC,
};

static struct {
	TSS2_TCTI_TRANSMIT_FCN transmit;
	TSS2_TCTI_RECEIVE_FCN receive;
	TSS2_TCTI_CONTEXT *context;
	__u8 response[4096];
	size_t response_len;
	enum fault_mode mode;
	__u32 command;
	bool selected;
	bool hit;
} proxy;

/*
 * NV_Extend replies have no parameters. Unsalted policy sessions may
 * omit the response HMAC; older libtpms versions still emit one.
 */
static TSS2_RC forge_success(const __u8 *command, size_t size)
{
	__u8 input[97], header[8], empty = 0;
	__u16 hmac_len;

	if (size < 62 || get_be16(command + 26) != TPM_DIGEST_LEN ||
	    proxy.response_len < 51 ||
	    get_be16(proxy.response + 14) != TPM_DIGEST_LEN)
		return TSS2_TCTI_RC_BAD_VALUE;
	hmac_len = get_be16(proxy.response + 49);
	if ((hmac_len && hmac_len != TPM_DIGEST_LEN) ||
	    proxy.response_len != 51u + hmac_len)
		return TSS2_TCTI_RC_BAD_VALUE;
	if (!hmac_len)
		return TSS2_RC_SUCCESS;
	memcpy(header, proxy.response + 6, 4);
	memcpy(header + 4, command + 6, 4);
	if (sha256_buffer(header, sizeof(header), input))
		return TSS2_TCTI_RC_GENERAL_FAILURE;
	memcpy(input + 32, proxy.response + 16, 32);
	memcpy(input + 64, command + 28, 32);
	input[96] = proxy.response[48];
	if (hmac_sha256(&empty, 0, input, sizeof(input), proxy.response + 51))
		return TSS2_TCTI_RC_GENERAL_FAILURE;
	return TSS2_RC_SUCCESS;
}

static int forge_reply_cases(void)
{
	__u8 command[97] = {};
	int ret = 1;

	put_be16(command + 26, TPM_DIGEST_LEN);
	put_be16(proxy.response + 14, TPM_DIGEST_LEN);
	proxy.response_len = 51;
	CHECK(forge_success(command, sizeof(command)) == TSS2_RC_SUCCESS);
	proxy.response_len = 83;
	CHECK(forge_success(command, sizeof(command)) == TSS2_TCTI_RC_BAD_VALUE);
	put_be16(proxy.response + 49, TPM_DIGEST_LEN);
	CHECK(forge_success(command, sizeof(command)) == TSS2_RC_SUCCESS);
	proxy.response_len--;
	CHECK(forge_success(command, sizeof(command)) == TSS2_TCTI_RC_BAD_VALUE);
	put_be16(proxy.response + 49, TPM_DIGEST_LEN - 1);
	CHECK(forge_success(command, sizeof(command)) == TSS2_TCTI_RC_BAD_VALUE);
	ret = 0;
out:
	memzero_explicit(&proxy, sizeof(proxy));
	return ret;
}

static TSS2_RC transmit(TSS2_TCTI_CONTEXT *context, size_t size,
			const __u8 *command)
{
	__u32 code;

	if (size < 10)
		return TSS2_TCTI_RC_BAD_VALUE;
	code = ((__u32)command[6] << 24) | ((__u32)command[7] << 16) |
	       ((__u32)command[8] << 8) | command[9];
	proxy.selected = code == proxy.command;
	if (proxy.selected && proxy.mode == FORGE)
		return forge_success(command, size);
	if (proxy.selected && proxy.mode == REPLAY)
		return TSS2_RC_SUCCESS;
	return proxy.transmit(context, size, command);
}

static TSS2_RC receive(TSS2_TCTI_CONTEXT *context, size_t *size,
		       __u8 *response, __s32 timeout)
{
	TSS2_RC ret;

	if (proxy.selected && (proxy.mode == REPLAY || proxy.mode == FORGE)) {
		if (!proxy.response_len)
			return TSS2_TCTI_RC_BAD_VALUE;
		if (response) {
			if (*size < proxy.response_len)
				return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
			memcpy(response, proxy.response, proxy.response_len);
			proxy.hit = true;
		}
		*size = proxy.response_len;
		return TSS2_RC_SUCCESS;
	}
	ret = proxy.receive(context, size, response, timeout);
	if (ret || !response || !proxy.selected)
		return ret;
	if (*size < 17 || *size > sizeof(proxy.response))
		return TSS2_TCTI_RC_BAD_VALUE;
	proxy.hit = true;
	if (proxy.mode == CAPTURE) {
		memcpy(proxy.response, response, *size);
		proxy.response_len = *size;
	} else if (proxy.mode == CORRUPT_HMAC) {
		if (get_be16(response) == TPM2_ST_SESSIONS)
			response[*size - 1] ^= 1;
	} else {
		response[16] ^= 1;
	}
	return TSS2_RC_SUCCESS;
}

static void intercept(struct tpm *t, __u32 command, enum fault_mode mode)
{
	proxy.context = t->tcti;
	proxy.transmit = TSS2_TCTI_TRANSMIT(t->tcti);
	proxy.receive = TSS2_TCTI_RECEIVE(t->tcti);
	proxy.command = command;
	proxy.mode = mode;
	proxy.selected = false;
	proxy.hit = false;
	TSS2_TCTI_TRANSMIT(t->tcti) = transmit;
	TSS2_TCTI_RECEIVE(t->tcti) = receive;
}

static void restore(void)
{
	if (!proxy.context)
		return;
	TSS2_TCTI_TRANSMIT(proxy.context) = proxy.transmit;
	TSS2_TCTI_RECEIVE(proxy.context) = proxy.receive;
	proxy.context = NULL;
}

static int activate(struct tpm *t, const struct tpm_key *ak,
		    bool rsa)
{
	TPM2B_DIGEST credential = { .size = 32, .buffer = { 7 } };
	TPM2B_ENCRYPTED_SECRET *secret = NULL;
	TPM2B_ID_OBJECT *blob = NULL;
	struct tpm_key ek = {};
	TPM2B_NAME name = {};
	__u8 recovered[32];
	size_t length = 0;
	int ret = 1;

	CHECK(!tpm_ek_create(t, rsa, &ek));
	name.size = ak->name_len;
	memcpy(name.name, ak->name, name.size);
	CHECK(Esys_MakeCredential(t->esys, ek.handle, t->session, ESYS_TR_NONE,
				  ESYS_TR_NONE, &credential, &name, &blob,
				  &secret) == TSS2_RC_SUCCESS);
	CHECK(!tpm_activate_credential(t, ak, &ek, blob->credential, blob->size,
				       secret->secret, secret->size, recovered,
				       sizeof(recovered), &length));
	CHECK(length == credential.size &&
	      !memneq_explicit(recovered, credential.buffer, length));
	blob->credential[blob->size - 1] ^= 1;
	CHECK(tpm_activate_credential(t, ak, &ek, blob->credential, blob->size,
				      secret->secret, secret->size, recovered,
				      sizeof(recovered), &length) == -EKEYREJECTED);
	ret = 0;
out:
	memzero_explicit(recovered, sizeof(recovered));
	memzero_explicit(&credential, sizeof(credential));
	if (secret)
		memzero_explicit(secret, sizeof(*secret));
	Esys_Free(secret);
	Esys_Free(blob);
	tpm_key_flush(t, &ek);
	return ret;
}

int main(int argc, char **argv)
{
	__u8 branch_written[32], branch_init[32], policy[32], values[64];
	__u8 public[TPM_NV_RSA_BYTES], seed[32] = { 1 };
	__u8 before[32], after[32], event[32] = { 2 };
	struct tpm *t = NULL, *other = NULL;
	struct tpm_attestation attestation;
	struct tpm_nv_info info;
	const char *log_setting;
	struct tpm_key ak = {};
	__u32 reset, restart;
	bool defined = false;
	int ret = 1;

	CHECK(argc == 2);
	CHECK(!forge_reply_cases());
	CHECK(!setenv("TSS2_LOG", "all+TRACE", 1));
	CHECK(!setenv("TSS2_LOGFILE", "stdout", 1));
	CHECK(!tpm_open(&t));
	log_setting = getenv("TSS2_LOG");
	CHECK(log_setting && !strcmp(log_setting, "all+none"));
	CHECK(!getenv("TSS2_LOGFILE"));
	tpm_ek_name(t, identity.ek_name);
	CHECK(identity.ek_name[1] == TPM2_ALG_SHA256);
	tpm_close(t);
	t = NULL;
	enforcing = 1;
	CHECK(!setenv("TSS2_LOG", "all+TRACE", 1));
	CHECK(!setenv("TSS2_LOGFILE", "stdout", 1));
	CHECK(!tpm_open(&t));
	log_setting = getenv("TSS2_LOG");
	CHECK(log_setting && !strcmp(log_setting, "all+none"));
	CHECK(!getenv("TSS2_LOGFILE"));
	CHECK(!tpm_boot_identity(t, &reset, &restart));
	CHECK(!tpm_pcr_read(t, 9, values));
	CHECK(!tpm_pcr_read(t, 11, values + 32));
	CHECK(!tpm_ak_create(t, &ak));
	CHECK(!tpm_quote(t, &ak, event, sizeof(event), 1u << 9, &attestation));
	CHECK(!activate(t, &ak, false));
	CHECK(!activate(t, &ak, true));
	tpm_key_flush(t, &ak);
	CHECK(!tpm_writer_create(t, seed, public));
	CHECK(!tpm_nv_set_writer(t, seed, public));
	CHECK(!tpm_register_policy(CHAIN_PCR_MASK, values, 2, public,
				   branch_written, branch_init, policy));
	CHECK(!tpm_nv_info(t, TEST_INDEX, &info) && !info.defined);
	CHECK(!tpm_nv_define(t, TEST_INDEX, policy, NULL, 0));
	defined = true;
	CHECK(!tpm_nv_extend_first(t, TEST_INDEX, CHAIN_PCR_MASK,
				   branch_written, branch_init, event));
	CHECK(!tpm_nv_read(t, TEST_INDEX, before));
	CHECK(!tpm_ak_create(t, &ak));
	CHECK(!tpm_nv_certify(t, &ak, TEST_INDEX, event, sizeof(event), &attestation));
	tpm_key_flush(t, &ak);
	puts("authenticated TPM reads, writes, quote and certification succeeded");

	if (!strcmp(argv[1], "nv-extend") || !strcmp(argv[1], "nv-replay") ||
	    !strcmp(argv[1], "unsalted-control")) {
		bool unsalted = !strcmp(argv[1], "unsalted-control");
		bool replay = !strcmp(argv[1], "nv-replay");
		ESYS_TR salting_key = t->session_key.handle;

		if (unsalted)
			t->session_key.handle = ESYS_TR_NONE;
		intercept(t, TPM2_CC_NV_Extend, CAPTURE);
		CHECK(!tpm_nv_extend(t, TEST_INDEX, branch_written, branch_init, event));
		CHECK(proxy.hit);
		restore();
		CHECK(!tpm_nv_read(t, TEST_INDEX, before));
		intercept(t, TPM2_CC_NV_Extend, replay ? REPLAY : FORGE);
		if (unsalted)
			CHECK(!tpm_nv_extend(t, TEST_INDEX, branch_written, branch_init, event));
		else
			CHECK(tpm_nv_extend(t, TEST_INDEX, branch_written, branch_init, event) < 0);
		CHECK(proxy.hit);
		restore();
		t->session_key.handle = salting_key;
		tpm_close(t);
		t = NULL;
		CHECK(!tpm_open(&t));
		CHECK(!tpm_nv_read(t, TEST_INDEX, after) && !memcmp(before, after, 32));
		puts(unsalted ? "negative control: unsalted session accepted suppressed NV_Extend" :
		     "suppressed NV_Extend with forged or replayed success rejected; register unchanged");
	} else if (!strcmp(argv[1], "pcr-extend")) {
		intercept(t, TPM2_CC_PCR_Extend, CAPTURE);
		CHECK(!tpm_pcr_extend(t, 23, event) && proxy.hit);
		restore();
		CHECK(!tpm_pcr_read(t, 23, before));
		intercept(t, TPM2_CC_PCR_Extend, REPLAY);
		CHECK(tpm_pcr_extend(t, 23, event) < 0 && proxy.hit);
		restore();
		tpm_close(t);
		t = NULL;
		CHECK(!tpm_open(&t));
		CHECK(!tpm_pcr_read(t, 23, after) && !memcmp(before, after, 32));
		puts("suppressed PCR_Extend with replayed success rejected; PCR unchanged");
	} else if (!strcmp(argv[1], "nv-read") || !strcmp(argv[1], "pcr-read") ||
		   !strcmp(argv[1], "clock") || !strcmp(argv[1], "policy-digest")) {
		if (!strcmp(argv[1], "policy-digest")) {
			intercept(t, TPM2_CC_PolicyGetDigest, CORRUPT_HMAC);
			CHECK(tpm_nv_extend(t, TEST_INDEX, branch_written,
					    branch_init, event) < 0 && proxy.hit);
		} else if (!strcmp(argv[1], "nv-read")) {
			intercept(t, TPM2_CC_NV_Read, CORRUPT);
			CHECK(tpm_nv_read(t, TEST_INDEX, after) < 0 && proxy.hit);
		} else if (!strcmp(argv[1], "pcr-read")) {
			intercept(t, TPM2_CC_PCR_Read, CORRUPT);
			CHECK(tpm_pcr_read(t, 9, after) < 0 && proxy.hit);
		} else {
			intercept(t, TPM2_CC_ReadClock, CORRUPT);
			CHECK(tpm_boot_identity(t, &reset, &restart) < 0 && proxy.hit);
		}
		restore();
		tpm_close(t);
		t = NULL;
		CHECK(!tpm_open(&t));
		CHECK(!tpm_nv_read(t, TEST_INDEX, after) && !memcmp(before, after, 32));
		puts("forged readback rejected; live register unchanged");
	} else {
		CHECK(!strcmp(argv[1], "identity"));
		tpm_close(t);
		t = NULL;
		identity.ek_name[2] ^= 1;
		CHECK(tpm_open(&other) == -EACCES && !other);
		identity.ek_name[2] ^= 1;
		identity.ek_name[1] = 0;
		CHECK(tpm_open(&other) == -EACCES && !other);
		identity.ek_name[1] = TPM2_ALG_SHA256;
		identity_error = -ENOENT;
		CHECK(tpm_open(&other) == -ENOENT && !other);
		identity_error = 0;
		enforcing = -EIO;
		CHECK(tpm_open(&other) == -EIO && !other);
		enforcing = 1;
		puts("wrong, missing and unreadable session-key pins refused without fallback");
	}
	ret = 0;
out:
	restore();
	tpm_key_flush(t, &ak);
	tpm_close(t);
	tpm_close(other);
	enforcing = 1;
	identity_error = 0;
	identity.ek_name[1] = TPM2_ALG_SHA256;
	if (defined) {
		t = NULL;
		if (tpm_open(&t) || tpm_nv_undefine(t, TEST_INDEX, NULL, 0))
			ret = 1;
		tpm_close(t);
	}
	return ret;
}
