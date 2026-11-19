// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The event encoders of util/chain.c and util/chain_history.c against
 * testing/proofs/lean4/Shirudo/Events.lean, with SHA-256 modelled as
 * recording what it is given: for every name of LEN bytes, payload,
 * digest, sequence number and register, chain_upatch_event(),
 * chain_key_event(), chain_tree_event(), chain_fold(),
 * chain_history_step() and chain_init_event() of an empty set hand SHA-256
 * exactly the bytes of the model, and give its digest, or zeros and its
 * error.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
/* The C converts a __s64 and cuts a __u64 to bytes on purpose. */
#pragma CPROVER check push
#pragma CPROVER check disable "conversion"
#include "../../../util/chain.c"
#include "../../../util/chain_history.c"
#pragma CPROVER check pop

/* The longest string an event hashes: a upatch of a 256-byte name. */
#define HASHED_MAX	(sizeof("shirudo-java-unload") + 32 + UPATCH_NAME_MAX)

/* What the last hash was given and gave, and the one before it. */
static __u8 hashed[HASHED_MAX];
static size_t hashed_len, prev_len, calls;
static __u8 digest[32], prev_digest[32];

static int any_result(void)
{
	int ret;

	return ret;
}

static void begin(void)
{
	__CPROVER_assert(calls < 2, "no more than the hashes of an event");
	prev_len = hashed_len;
	memcpy(prev_digest, digest, 32);
	hashed_len = 0;
}

static void record(const void *data, size_t len)
{
	__CPROVER_assert(__CPROVER_r_ok(data, len), "hashes only its input");
	__CPROVER_assert(hashed_len + len <= HASHED_MAX,
			 "no more than the longest event");
	memcpy(hashed + hashed_len, data, len);
	hashed_len += len;
}

/* A fresh digest each call, or a failure that leaves anything. */
static int give_digest(__u8 out[32])
{
	int ret = any_result();

	__CPROVER_assert(__CPROVER_w_ok(out, 32), "a digest's room");
	__CPROVER_havoc_slice(digest, 32);
	if (ret)
		__CPROVER_havoc_slice(out, 32);
	else
		memcpy(out, digest, 32);
	calls++;
	return ret;
}

int sha256_init(struct sha256_ctx *ctx)
{
	begin();
	return any_result();
}

int sha256_update(struct sha256_ctx *ctx, const void *data, size_t len)
{
	record(data, len);
	return any_result();
}

int sha256_final(struct sha256_ctx *ctx, __u8 out[32])
{
	return give_digest(out);
}

void sha256_free(struct sha256_ctx *ctx)
{
}

/* As util/crypto.h promises: where it fails, out is all zeros. */
int sha256_buffer(const void *data, size_t len, __u8 out[32])
{
	int ret;

	begin();
	record(data, len);
	ret = give_digest(out);
	if (ret)
		memset(out, 0, 32);
	return ret;
}

static void start(void)
{
	calls = 0;
	hashed_len = 0;
}

/* The last digest on success, zeros on failure. */
static void check_result(int ret, size_t n_calls, const __u8 event[32])
{
	size_t i;

	__CPROVER_assert(ret || calls == n_calls, "the last hash is the event");
	for (i = 0; i < 32; i++)
		__CPROVER_assert(event[i] == (ret ? 0 : digest[i]),
				 "the digest, or zeros on failure");
}

/* hashed[*at..] holds the tag's bytes and its NUL. */
static void check_tag(const char *tag, size_t *at)
{
	size_t i;

	for (i = 0; tag[i]; i++)
		__CPROVER_assert(hashed[*at + i] == (__u8)tag[i], "the tag");
	__CPROVER_assert(hashed[*at + i] == 0, "the tag's NUL");
	*at += i + 1;
}

static void check_bytes(const void *want, size_t len, size_t *at)
{
	const __u8 *w = want;
	size_t i;

	for (i = 0; i < len; i++)
		__CPROVER_assert(hashed[*at + i] == w[i], "the field's bytes");
	*at += len;
}

static void check_end(size_t at)
{
	__CPROVER_assert(hashed_len == at, "nothing more");
}

static char *any_name(void)
{
	char *name = any_bytes(LEN + 1);

	__CPROVER_assume(!name[LEN] && strnlen(name, LEN) == LEN);
	return name;
}

/*
 * upatchBytes: the tag and its NUL, the payload, and the name up to
 * strnlen(name, UPATCH_NAME_MAX).
 */
static void upatch_event(const char *tag)
{
	size_t cut = min_t(size_t, LEN, UPATCH_NAME_MAX), at = 0;
	__u8 *payload = any_bytes(32), event[32];
	char *name = any_name();
	int ret;

	start();
	ret = chain_upatch_event(tag, name, payload, event);
	if (!ret) {
		check_tag(tag, &at);
		check_bytes(payload, 32, &at);
		check_bytes(name, cut, &at);
		check_end(at);
	}
	check_result(ret, 1, event);
}

/* The tag each payload type and direction takes, as the model names it. */
static void upatch_tags(void)
{
	__CPROVER_assert(!strcmp(chain_upatch_tag(UPATCH_TYPE_BPF, true),
				 "shirudo-upatch") &&
			 !strcmp(chain_upatch_tag(UPATCH_TYPE_BPF, false),
				 "shirudo-unload") &&
			 !strcmp(chain_upatch_tag(UPATCH_TYPE_JAVA, true),
				 "shirudo-java") &&
			 !strcmp(chain_upatch_tag(UPATCH_TYPE_JAVA, false),
				 "shirudo-java-unload"),
			 "tagUpatch, tagUnload, tagJava and tagJavaUnload");
}

/* keyBytes: the tag and its NUL, then the certificate's digest. */
static void key_event(void)
{
	static const char tag[] = "shirudo-key-revoke";
	__u8 *cert = any_bytes(32), event[32];
	size_t at = 0;
	int ret;

	start();
	ret = chain_key_event(tag, cert, event);
	if (!ret) {
		check_tag(tag, &at);
		check_bytes(cert, 32, &at);
		check_end(at);
	}
	check_result(ret, 1, event);
}

/*
 * treeBytes: the tag and its NUL, be64 (u64OfS64 seq), which read back
 * most significant byte first is seq modulo 2^64, and the digest.
 */
static void tree_event(void)
{
	__u8 *operation = any_bytes(32), event[32];
	size_t at = 0, i;
	__u64 u, v = 0;
	__s64 seq;
	int ret;

	u = seq >= 0 ? (__u64)seq :
	    (__u64)(seq + INT64_MAX + 1) + ((__u64)INT64_MAX + 1);
	start();
	ret = chain_tree_event(seq, operation, event);
	if (!ret) {
		check_tag("shirudo-tree", &at);
		for (i = 0; i < 8; i++)
			v = v * 256 + hashed[at + i];
		__CPROVER_assert(v == u,
				 "seq modulo 2^64, most significant first");
		at += 8;
		check_bytes(operation, 32, &at);
		check_end(at);
	}
	check_result(ret, 1, event);
}

/* fold: the register and the event. */
static void fold(void)
{
	__u8 *chain = any_bytes(32), *event = any_bytes(32), was[32];
	size_t at = 0;
	int ret;

	memcpy(was, chain, 32);
	start();
	ret = chain_fold(chain, event);
	if (!ret) {
		check_bytes(was, 32, &at);
		check_bytes(event, 32, &at);
		check_end(at);
	}
	check_result(ret, 1, chain);
}

/* historyBytes: the tag and its NUL, the root before and the digest. */
static void history_step(void)
{
	__u8 *prev = any_bytes(32), *operation = any_bytes(32), root[32];
	size_t at = 0;
	int ret;

	start();
	ret = chain_history_step(prev, operation, root);
	if (!ret) {
		check_tag("shirudo-tree-history", &at);
		check_bytes(prev, 32, &at);
		check_bytes(operation, 32, &at);
		check_end(at);
	}
	check_result(ret, 1, root);
}

/*
 * chain_init_event() of an empty set: initBytes, the tag and its NUL, the
 * certificate digest, the digest of the empty listing and the tree root.
 */
static void init_event(void)
{
	__u8 *cert = any_bytes(32), *root = any_bytes(32);
	__u8 set_digest[32], event[32];
	struct measured_upatch set[1];
	size_t at = 0, i;
	int ret;

	start();
	ret = chain_init_event(cert, set, 0, root, set_digest, event);
	if (ret) {
		check_result(ret, 2, event);
		return;
	}
	__CPROVER_assert(prev_len == 0, "an empty listing");
	for (i = 0; i < 32; i++)
		__CPROVER_assert(set_digest[i] == prev_digest[i],
				 "the listing's digest");
	check_tag("shirudo-init", &at);
	check_bytes(cert, 32, &at);
	check_bytes(prev_digest, 32, &at);
	check_bytes(root, 32, &at);
	check_end(at);
	check_result(ret, 2, event);
}

void harness(void)
{
	upatch_tags();
	upatch_event("shirudo-upatch");
	upatch_event("shirudo-unload");
	upatch_event("shirudo-java");
	upatch_event("shirudo-java-unload");
	key_event();
	tree_event();
	fold();
	history_step();
	init_event();
}
