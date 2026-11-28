// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Raw add_key(2)/keyctl(2) wrappers; no libkeyutils dependency.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/keyctl.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "keyring.h"
#include "io.h"
#include "malloc.h"
#include "paths.h"

#ifndef KEYCTL_RESTRICT_KEYRING
#define KEYCTL_RESTRICT_KEYRING	29
#endif

/* How often read_links() grows its buffer before it refuses the keyring. */
#define READ_LINKS_TRIES	4

static long sys_add_key(const char *type, const char *desc,
			const void *payload, size_t plen, key_serial_t ring)
{
	return syscall(__NR_add_key, type, desc, payload, plen, ring);
}

static long sys_keyctl(int cmd, long a, long b, long c, long d)
{
	return syscall(__NR_keyctl, cmd, a, b, c, d);
}

static int describe_key(key_serial_t serial,
			char *out, size_t out_sz)
{
	long ret = sys_keyctl(KEYCTL_DESCRIBE, serial, (long)out,
			      (long)out_sz, 0);
	if (ret < 0)
		return -errno;
	if ((size_t)ret > out_sz)
		return -ERANGE;
	return 0;
}

static void split_describe(char *desc, const char **type,
			   const char **description)
{
	char *p = desc;
	int i;

	*type = desc;
	for (i = 0; i < 4; i++) {
		p = strchr(p, ';');
		if (!p) {
			*description = "";
			return;
		}
		if (i == 0)
			*p = '\0';
		p++;
	}
	*description = p;
}

/* Every link of <keyring>, whatever its type; freed with xfree(, *size). */
static int read_links(key_serial_t keyring, key_serial_t **out, size_t *n,
		      size_t *size)
{
	key_serial_t *serials = NULL;
	size_t cap = 64 * sizeof(*serials);
	long ret;
	void *bigger;
	int tries;

	serials = xmalloc(cap);
	if (!serials)
		return -ENOMEM;

	/*
	 * KEYCTL_READ copies nothing and returns the size it needs when the
	 * buffer is too small. The keyring can gain a link between two reads,
	 * so a read that did not fit is read again into a buffer of that
	 * size; one that keeps gaining links past the retries is refused
	 * rather than reported short.
	 */
	for (tries = 0; tries < READ_LINKS_TRIES; tries++) {
		ret = sys_keyctl(KEYCTL_READ, keyring, (long)serials, (long)cap, 0);
		if (ret < 0) {
			xfree(serials, cap);
			return -errno;
		}
		if ((size_t)ret <= cap) {
			*out = serials;
			*n = (size_t)ret / sizeof(*serials);
			*size = cap;
			return 0;
		}
		bigger = xreallocarray(serials, cap, (size_t)ret, 1);
		if (!bigger) {
			xfree(serials, cap);
			return -ENOMEM;
		}
		serials = bigger;
		cap = (size_t)ret;
	}
	xfree(serials, cap);
	return -EAGAIN;
}

int keyring_list(key_serial_t keyring,
		 shirudo_keyring_cb cb, void *ud)
{
	key_serial_t *serials = NULL;
	size_t n = 0, cap = 0, i;
	int ret;

	ret = read_links(keyring, &serials, &n, &cap);
	if (ret)
		return ret;
	for (i = 0; i < n; i++) {
		const char *type, *description;
		char desc[KEYRING_DESC_MAX];

		if (describe_key(serials[i], desc, sizeof(desc)) != 0)
			continue;
		split_describe(desc, &type, &description);
		cb(serials[i], type, description, ud);
	}
	xfree(serials, cap);
	return 0;
}

int keyring_links(key_serial_t keyring, struct keyring_link **links,
		  size_t *n)
{
	struct keyring_link *out = NULL;
	key_serial_t *serials = NULL;
	size_t count = 0, cap = 0, i;
	int ret;

	ret = read_links(keyring, &serials, &count, &cap);
	if (ret)
		return ret;
	if (count) {
		out = xcalloc(count, sizeof(*out));
		if (!out) {
			xfree(serials, cap);
			return -ENOMEM;
		}
	}
	for (i = 0; i < count; i++) {
		const char *type, *description;
		char desc[KEYRING_DESC_MAX];

		out[i].serial = serials[i];
		out[i].err = describe_key(serials[i], desc, sizeof(desc));
		if (out[i].err)
			continue;
		split_describe(desc, &type, &description);
		if (strscpy(out[i].type, type, sizeof(out[i].type)) < 0 ||
		    strscpy(out[i].description, description,
			    sizeof(out[i].description)) < 0)
			out[i].err = -ERANGE;
	}
	xfree(serials, cap);
	*links = out;
	*n = count;
	return 0;
}

int keyring_cert_description(const __u8 *der, size_t der_len,
			     char out[KEYRING_DESC_MAX])
{
	const char *type, *description;
	char desc[KEYRING_DESC_MAX];
	long probe;
	int ret;

	probe = sys_add_key("asymmetric", NULL, der, der_len,
			    KEY_SPEC_THREAD_KEYRING);
	if (probe < 0)
		return -errno;
	ret = describe_key((key_serial_t)probe, desc, sizeof(desc));
	sys_keyctl(KEYCTL_UNLINK, probe, KEY_SPEC_THREAD_KEYRING, 0, 0);
	if (ret)
		return ret;
	split_describe(desc, &type, &description);
	return strscpy(out, description, KEYRING_DESC_MAX) < 0 ? -ERANGE : 0;
}

struct holds_cert_ctx {
	char		want[KEYRING_DESC_MAX];
	key_serial_t	serial;
	bool		found;
};

static void holds_cert_cb(key_serial_t serial, const char *type,
			  const char *description, void *ud)
{
	struct holds_cert_ctx *ctx = ud;

	if (strcmp(type, "asymmetric") == 0 &&
	    strcmp(description, ctx->want) == 0) {
		ctx->serial = serial;
		ctx->found = true;
	}
}

int keyring_holds_cert(key_serial_t keyring,
		       const __u8 *der, size_t der_len)
{
	struct holds_cert_ctx ctx = {};
	int ret;

	ret = keyring_cert_description(der, der_len, ctx.want);
	if (!ret)
		ret = keyring_list(keyring, holds_cert_cb, &ctx);
	if (ret)
		return ret;
	return ctx.found ? 1 : 0;
}

key_serial_t keyring_find_cert(key_serial_t keyring,
			       const __u8 *der,
			       size_t der_len)
{
	struct holds_cert_ctx ctx = {};
	int ret;

	ret = keyring_cert_description(der, der_len, ctx.want);
	if (!ret)
		ret = keyring_list(keyring, holds_cert_cb, &ctx);
	if (ret)
		return ret;
	return ctx.found ? ctx.serial : -ENOKEY;
}

/*
 * Every link counts, whatever its type and whether it can be described:
 * the kernel's signature check searches a nested keyring, which the
 * seal does not cover, and a key hidden from view still verifies.
 */
int keyring_holds_exactly(key_serial_t keyring,
			  const struct keyring_cert *certs, size_t n)
{
	char (*want)[KEYRING_DESC_MAX] = NULL;
	size_t links = 0, cap = 0, i, j;
	key_serial_t *serials = NULL;
	bool *matched = NULL;
	int ret = -ENOMEM;

	if (n) {
		want = xcalloc(n, sizeof(*want));
		matched = xcalloc(n, sizeof(*matched));
		if (!want || !matched)
			goto out;
	}
	for (i = 0; i < n; i++) {
		ret = keyring_cert_description(certs[i].der, certs[i].len,
					       want[i]);
		if (ret)
			goto out;
	}
	ret = read_links(keyring, &serials, &links, &cap);
	if (ret)
		goto out;
	if (links != n)
		goto out;
	for (i = 0; i < links; i++) {
		const char *type, *description;
		char desc[KEYRING_DESC_MAX];

		if (describe_key(serials[i], desc, sizeof(desc)))
			goto out;
		split_describe(desc, &type, &description);
		if (strcmp(type, "asymmetric"))
			goto out;
		for (j = 0; j < n; j++)
			if (!matched[j] && !strcmp(description, want[j]))
				break;
		if (j == n)
			goto out;
		matched[j] = true;
	}
	ret = 1;
out:
	xfree(serials, cap);
	xfree(want, n * sizeof(*want));
	xfree(matched, n * sizeof(*matched));
	return ret;
}

int keyring_unlink_key(key_serial_t keyring, key_serial_t key)
{
	if (sys_keyctl(KEYCTL_UNLINK, key, keyring, 0, 0) < 0)
		return -errno;
	return 0;
}

key_serial_t keyring_bpf_serial(void)
{
	long ret = sys_keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_BPF_KEYRING, 0, 0,
			      0);

	return ret < 0 ? -errno : (key_serial_t)ret;
}

key_serial_t keyring_bpf_add_cert(const __u8 *cert,
				  size_t cert_len)
{
	long ret = sys_add_key("asymmetric", NULL, cert, cert_len,
			       KEY_SPEC_BPF_KEYRING);

	return ret < 0 ? -errno : (key_serial_t)ret;
}

int keyring_bpf_seal(void)
{
	/* No restriction type: the keyring rejects every further link. */
	if (sys_keyctl(KEYCTL_RESTRICT_KEYRING, KEY_SPEC_BPF_KEYRING,
		       0, 0, 0) < 0)
		return -errno;
	return 0;
}

/* Resolve the kernel-owned ring directly, without a name-based search. */
key_serial_t keyring_dm_verity_serial(void)
{
	long ret = sys_keyctl(KEYCTL_GET_KEYRING_ID,
			      KEY_SPEC_DM_VERITY_KEYRING, 0, 0, 0);

	return ret < 0 ? -errno : (key_serial_t)ret;
}

key_serial_t keyring_dm_verity_add_cert(const __u8 *cert,
					size_t cert_len)
{
	long ret = sys_add_key("asymmetric", NULL, cert, cert_len,
			       KEY_SPEC_DM_VERITY_KEYRING);

	return ret < 0 ? -errno : (key_serial_t)ret;
}

int keyring_dm_verity_seal(void)
{
	/* No restriction type: reject every subsequent addition. */
	if (sys_keyctl(KEYCTL_RESTRICT_KEYRING, KEY_SPEC_DM_VERITY_KEYRING,
		       0, 0, 0) < 0)
		return -errno;
	return 0;
}
