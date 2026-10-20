// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Raw add_key(2)/keyctl(2) wrappers; no libkeyutils dependency.
 */

#include <errno.h>
#include <limits.h>
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

#include "keyring.h"
#include "io.h"
#include "malloc.h"
#include "paths.h"

#ifndef KEY_SPEC_USER_KEYRING
#define KEY_SPEC_USER_KEYRING	(-4)
#endif

#define KEY_POS_VIEW	0x01000000
#define KEY_POS_READ	0x02000000
#define KEY_POS_WRITE	0x04000000
#define KEY_POS_SEARCH	0x08000000
#define KEY_POS_LINK	0x10000000
#define KEY_POS_SETATTR	0x20000000
#define KEY_USR_VIEW	0x00010000
#define KEY_USR_READ	0x00020000
#define KEY_USR_WRITE	0x00040000
#define KEY_USR_SEARCH	0x00080000
#define KEY_USR_SETATTR	0x00200000

#ifndef KEY_SPEC_SESSION_KEYRING
#define KEY_SPEC_SESSION_KEYRING (-3)
#endif
#ifndef KEYCTL_RESTRICT_KEYRING
#define KEYCTL_RESTRICT_KEYRING	29
#endif

static long sys_add_key(const char *type, const char *desc,
			const void *payload, size_t plen, key_serial_t ring)
{
	return syscall(__NR_add_key, type, desc, payload, plen, ring);
}

static long sys_keyctl(int cmd, long a, long b, long c, long d)
{
	return syscall(__NR_keyctl, cmd, a, b, c, d);
}

key_serial_t keyring_find(const char *name)
{
	long ret = sys_keyctl(KEYCTL_SEARCH, KEY_SPEC_USER_KEYRING,
			      (long)"keyring", (long)name, 0);
	if (ret < 0)
		return (key_serial_t)-errno;
	return (key_serial_t)ret;
}

static int keyring_make_mutable(key_serial_t keyring)
{
	/*
	 * A named keyring linked only from @u is not necessarily possessed by
	 * a systemd service process. Give root enough owner permission to
	 * populate it; init drops write/setattr again when sealing succeeds.
	 */
	long perm = KEY_POS_VIEW | KEY_POS_READ | KEY_POS_WRITE |
		    KEY_POS_SEARCH | KEY_POS_LINK | KEY_POS_SETATTR |
		    KEY_USR_VIEW | KEY_USR_READ | KEY_USR_WRITE |
		    KEY_USR_SEARCH | KEY_USR_SETATTR;

	if (sys_keyctl(KEYCTL_SETPERM, keyring, perm, 0, 0) < 0)
		return -errno;
	return 0;
}

key_serial_t keyring_open_or_create(const char *name)
{
	key_serial_t s = keyring_find(name);
	long ret;
	int rc;

	if (s != -ENOKEY)
		return s;	/* success, or some other error */

	ret = sys_add_key("keyring", name, NULL, 0,
			  KEY_SPEC_SESSION_KEYRING);
	if (ret < 0)
		return (key_serial_t)-errno;

	rc = keyring_make_mutable((key_serial_t)ret);
	if (rc)
		return (key_serial_t)rc;

	if (sys_keyctl(KEYCTL_LINK, ret, KEY_SPEC_USER_KEYRING, 0, 0) < 0)
		return (key_serial_t)-errno;

	return (key_serial_t)ret;
}

int keyring_unlink_from_user(key_serial_t keyring)
{
	if (sys_keyctl(KEYCTL_UNLINK, keyring, KEY_SPEC_USER_KEYRING, 0, 0) < 0)
		return -errno;
	return 0;
}

key_serial_t keyring_add_cert(key_serial_t keyring,
			      const void *cert, size_t cert_len)
{
	long ret = sys_add_key("asymmetric", NULL, cert, cert_len, keyring);

	if (ret < 0)
		return (key_serial_t)-errno;
	return (key_serial_t)ret;
}

int keyring_seal(key_serial_t keyring)
{
	/*
	 * Possessor + user keep view/read/search (so any root process can
	 * still search the cert at load); nobody keeps write/link/setattr.
	 * Once SETATTR is gone the perms are locked for the boot.
	 */
	long perm = KEY_POS_VIEW | KEY_POS_READ | KEY_POS_SEARCH |
		    KEY_USR_VIEW | KEY_USR_READ | KEY_USR_SEARCH;

	if (sys_keyctl(KEYCTL_SETPERM, keyring, perm, 0, 0) < 0)
		return -errno;
	return 0;
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

int keyring_list(key_serial_t keyring,
		 shirudo_keyring_cb cb, void *ud)
{
	key_serial_t *serials = NULL;
	size_t cap = 64 * sizeof(*serials);
	long ret;
	size_t n, i;

	serials = xmalloc(cap);
	if (!serials)
		return -ENOMEM;

	ret = sys_keyctl(KEYCTL_READ, keyring, (long)serials, (long)cap, 0);
	if (ret < 0) {
		xfree(serials, cap);
		return -errno;
	}
	if ((size_t)ret > cap) {
		void *bigger = xreallocarray(serials, cap, (size_t)ret, 1);

		if (!bigger) {
			xfree(serials, cap);
			return -ENOMEM;
		}
		serials = bigger;
		cap = (size_t)ret;
		ret = sys_keyctl(KEYCTL_READ, keyring, (long)serials,
				 (long)cap, 0);
		if (ret < 0) {
			xfree(serials, cap);
			return -errno;
		}
		/*
		 * The keyring can grow again between the two reads;
		 * KEYCTL_READ then returns the full size while filling only
		 * cap bytes. Clamp to what the buffer actually holds so the
		 * loop below never reads past the allocation.
		 */
		if ((size_t)ret > cap)
			ret = (long)cap;
	}

	n = (size_t)ret / sizeof(*serials);
	for (i = 0; i < n; i++) {
		char desc[512];
		const char *type, *description;

		if (describe_key(serials[i], desc, sizeof(desc)) != 0)
			continue;
		split_describe(desc, &type, &description);
		cb(serials[i], type, description, ud);
	}
	xfree(serials, cap);
	return 0;
}

struct holds_cert_ctx {
	char		want[512];
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
	const char *type, *description;
	char desc[512];
	long probe;
	int rc;

	probe = sys_add_key("asymmetric", NULL, der, der_len,
			    KEY_SPEC_THREAD_KEYRING);
	if (probe < 0)
		return -errno;
	rc = describe_key((key_serial_t)probe, desc, sizeof(desc));
	sys_keyctl(KEYCTL_UNLINK, probe, KEY_SPEC_THREAD_KEYRING, 0, 0);
	if (rc)
		return rc;
	split_describe(desc, &type, &description);
	if (strlen(description) >= sizeof(ctx.want))
		return -ERANGE;
	memcpy(ctx.want, description, strlen(description) + 1);

	rc = keyring_list(keyring, holds_cert_cb, &ctx);
	if (rc)
		return rc;
	return ctx.found ? 1 : 0;
}

key_serial_t keyring_find_cert(key_serial_t keyring,
			       const __u8 *der,
			       size_t der_len)
{
	struct holds_cert_ctx ctx = {};
	const char *type, *description;
	char desc[512];
	long probe;
	int rc;

	probe = sys_add_key("asymmetric", NULL, der, der_len,
			    KEY_SPEC_THREAD_KEYRING);
	if (probe < 0)
		return -errno;
	rc = describe_key((key_serial_t)probe, desc, sizeof(desc));
	sys_keyctl(KEYCTL_UNLINK, probe, KEY_SPEC_THREAD_KEYRING, 0, 0);
	if (rc)
		return rc;
	split_describe(desc, &type, &description);
	if (strlen(description) >= sizeof(ctx.want))
		return -ERANGE;
	memcpy(ctx.want, description, strlen(description) + 1);
	rc = keyring_list(keyring, holds_cert_cb, &ctx);
	if (rc)
		return rc;
	return ctx.found ? ctx.serial : -ENOKEY;
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

/* The kernel ring is unpossessed; discover it only during trusted boot. */
key_serial_t shirudo_keyring_dm_verity_serial(void)
{
	static const char expected[] = "keyring;0;0;082f0000;.dm-verity";
	char line[1024], flags[8], expiry[32], type[32], name[64];
	__u32 serial, usage, permissions, uid, gid;
	key_serial_t found = -ENOKEY;
	char description[128];
	FILE *file;
	int rc;

	file = fopen("/proc/keys", "re");
	if (!file)
		return -errno;
	while (fgets(line, sizeof(line), file)) {
		if (sscanf(line, "%x %7s %u %31s %x %u %u %31s %63s",
			   &serial, flags, &usage, expiry, &permissions,
			   &uid, &gid, type, name) != 9)
			continue;
		if (!serial || serial > INT_MAX || uid || gid ||
		    permissions != 0x082f0000 || strchr(flags, 'Q') ||
		    strcmp(type, "keyring") || strcmp(name, ".dm-verity:"))
			continue;
		rc = describe_key(serial, description, sizeof(description));
		if (rc || strcmp(description, expected))
			continue;
		if (found >= 0) {
			found = -EEXIST;
			break;
		}
		found = serial;
	}
	if (ferror(file))
		found = -EIO;
	fclose(file);
	return found;
}

key_serial_t shirudo_keyring_dm_verity_add_cert(const __u8 *cert,
						size_t cert_len)
{
	key_serial_t ring = shirudo_keyring_dm_verity_serial();

	return ring < 0 ? ring : keyring_add_cert(ring, cert, cert_len);
}

int shirudo_keyring_dm_verity_seal(void)
{
	key_serial_t ring = shirudo_keyring_dm_verity_serial();

	if (ring < 0)
		return ring;
	/* No restriction type: reject every subsequent addition. */
	if (sys_keyctl(KEYCTL_RESTRICT_KEYRING, ring, 0, 0, 0) < 0)
		return -errno;
	return 0;
}
