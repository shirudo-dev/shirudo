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
	struct trusted_set *set;
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

	for (i = 0; i < held_count; i++) {
		__u8 *candidate = NULL;
		size_t length = 0;
		int ret;

		ret = keys_read_der(held[i], &candidate, &length);
		if (ret)
			return ret;
		ret = size == length && !memcmp(der, candidate, size);
		xfree(candidate, length);
		if (ret)
			return 1;
	}
	return 0;
}

int keys_revoke_image(const __u8 *der, size_t size, bool boot)
{
	mutations++;
	return -EPERM;
}

int keys_revoke_check(void)
{
	return 0;
}

static int boot_count(void *opaque, __u32 *reset, __u32 *restart)
{
	*reset = 1;
	*restart = 1;
	return 0;
}

static int pcr_read(void *opaque, __u32 pcr, __u8 out[32])
{
	struct test_context *ctx = opaque;

	memcpy(out, ctx->pcr, 32);
	return 0;
}

static int pcr_extend(void *opaque, __u32 pcr, const __u8 event[32])
{
	struct test_context *ctx = opaque;

	ctx->extends++;
	return chain_fold(ctx->pcr, event);
}

static int prepare(void *opaque,
		   const struct config_update_target *target)
{
	struct test_context *ctx = opaque;

	return ctx->live ? keys_check_image_set(ctx->set) : 0;
}

static int activate(void *opaque,
		    const struct config_update_target *target)
{
	struct test_context *ctx = opaque;

	ctx->activations++;
	if (ctx->live && ctx->interrupt) {
		ctx->interrupt = false;
		return -EIO;
	}
	return 0;
}

static int seal(void *opaque, int fd)
{
	return 0;
}

static const struct config_update_ops ops = {
	.boot_identity = boot_count,
	.pcr_read = pcr_read,
	.pcr_extend = pcr_extend,
	.prepare = prepare,
	.activate = activate,
	.seal = seal,
};

static int live_update(const char *directory, struct trusted_set *set)
{
	struct config_update_target target = {};
	struct config_update update;
	struct test_context ctx = { .set = set };
	int ret;

	ret = config_update_open(directory, &ops, &ctx, &update);
	if (ret)
		return ret;
	strcpy(target.prefix, "/verified/boot");
	memset(target.root_hash, 1, 32);
	ret = config_update_boot(&update, &target, 15);
	if (!ret)
		ret = config_update_complete_boot(&update);
	ctx.live = true;
	ctx.interrupt = !!getenv("SHIRUDO_TEST_IMAGE_INTERRUPT");
	ctx.extends = 0;
	ctx.activations = 0;
	strcpy(target.prefix, "/verified/live");
	memset(target.root_hash, 2, 32);
	if (!ret)
		ret = config_update_begin(&update, &target, 15);

	printf("extends=%u activations=%u\n", ctx.extends, ctx.activations);
	config_update_close(&update);
	return ret;
}

int main(int argc, char **argv)
{
	struct trusted_set set = {};
	int fd, ret;

	if (argc != 3 && argc < 5)
		return 2;
	fd = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return 2;
	ret = keys_validate_image_set(argv[1], fd, &set);
	if (!ret && argc >= 5) {
		held = argv + 4;
		held_count = argc - 4;
		ret = live_update(argv[3], &set);
	}
	close(fd);
	printf("rc=%d mutations=%u signers=%zu\n", ret, mutations, set.n);
	return ret || mutations ? 1 : 0;
}
