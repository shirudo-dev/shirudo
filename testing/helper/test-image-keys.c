// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "image_keys.h"
#include "chain.h"
#include "config_update.h"
#include "malloc.h"
#include "keyring.h"
#include "keys.h"

static __u32 mutations;
static char **held;
static int held_count;

struct test_context {
	struct shirudo_trusted_set *set;
	__u8 pcr[32];
	__u32 extends;
	__u32 activations;
	bool live;
	bool interrupt;
};

key_serial_t keyring_bpf_serial(void)
{
	return 42;
}

int keyring_holds_cert(key_serial_t ring, const __u8 *der,
		       size_t size)
{
	int i;

	(void)ring;
	for (i = 0; i < held_count; i++) {
		__u8 *candidate = NULL;
		size_t length = 0;
		int rc;

		rc = keys_read_der(held[i], &candidate, &length);
		if (rc)
			return rc;
		rc = size == length && !memcmp(der, candidate, size);
		xfree(candidate, length);
		if (rc)
			return 1;
	}
	return 0;
}

int shirudo_keys_revoke_image(const __u8 *der, size_t size, bool boot)
{
	(void)der;
	(void)size;
	(void)boot;
	mutations++;
	return -EPERM;
}

static int boot_count(void *opaque, __u32 *reset, __u32 *restart)
{
	(void)opaque;
	*reset = 1;
	*restart = 1;
	return 0;
}

static int pcr_read(void *opaque, __u32 pcr, __u8 out[32])
{
	struct test_context *ctx = opaque;

	(void)pcr;
	memcpy(out, ctx->pcr, 32);
	return 0;
}

static int pcr_extend(void *opaque, __u32 pcr, const __u8 event[32])
{
	struct test_context *ctx = opaque;

	(void)pcr;
	ctx->extends++;
	return shirudo_chain_fold_checked(ctx->pcr, event);
}

static int prepare(void *opaque,
		   const struct shirudo_config_update_target *target)
{
	struct test_context *ctx = opaque;

	(void)target;
	return ctx->live ? shirudo_keys_check_image_set(ctx->set) : 0;
}

static int activate(void *opaque,
		    const struct shirudo_config_update_target *target)
{
	struct test_context *ctx = opaque;

	(void)target;
	ctx->activations++;
	if (ctx->live && ctx->interrupt) {
		ctx->interrupt = false;
		return -EIO;
	}
	return 0;
}

static int seal(void *opaque, int fd)
{
	(void)opaque;
	(void)fd;
	return 0;
}

static const struct shirudo_config_update_ops ops = {
	.boot_identity = boot_count,
	.pcr_read = pcr_read,
	.pcr_extend = pcr_extend,
	.prepare = prepare,
	.activate = activate,
	.seal = seal,
};

static int live_update(const char *directory, struct shirudo_trusted_set *set)
{
	struct shirudo_config_update_target target = {};
	struct shirudo_config_update update;
	struct test_context ctx = { .set = set };
	int rc;

	rc = shirudo_config_update_open(directory, &ops, &ctx, &update);
	if (rc)
		return rc;
	strcpy(target.prefix, "/verified/boot");
	memset(target.root_hash, 1, 32);
	rc = shirudo_config_update_boot(&update, &target, 15);
	if (!rc)
		rc = shirudo_config_update_complete_boot(&update);
	ctx.live = true;
	ctx.interrupt = !!getenv("SHIRUDO_TEST_IMAGE_INTERRUPT");
	ctx.extends = 0;
	ctx.activations = 0;
	strcpy(target.prefix, "/verified/live");
	memset(target.root_hash, 2, 32);
	if (!rc)
		rc = shirudo_config_update_begin(&update, &target, 15);

	printf("extends=%u activations=%u\n", ctx.extends, ctx.activations);
	shirudo_config_update_close(&update);
	return rc;
}

int main(int argc, char **argv)
{
	struct shirudo_trusted_set set = {};
	int fd, rc;

	if (argc != 3 && argc < 5)
		return 2;
	fd = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return 2;
	rc = shirudo_keys_validate_image_set(argv[1], fd, &set);
	if (!rc && argc >= 5) {
		held = argv + 4;
		held_count = argc - 4;
		rc = live_update(argv[3], &set);
	}
	close(fd);
	printf("rc=%d mutations=%u signers=%zu\n", rc, mutations, set.n);
	return rc || mutations ? 1 : 0;
}
