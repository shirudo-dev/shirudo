// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util/chain.h"
#include "util/config_measure.h"
#include "util/config_update.h"
#include "util/hex.h"
#include "util/io.h"
#include "util/tpm.h"

struct simulated_tpm {
	__u8 value[32];
	__u8 active[32];
	__u32 reset_count;
	__u32 restart_count;
	__u32 extends;
	__u32 prepares;
	__u32 activations;
	__u32 partial;
};

struct test_context {
	struct shirudo_config_update *update;
	struct simulated_tpm sim;
	struct shirudo_tpm *tpm;
	const char *directory;
};

static int simulator_save(struct test_context *ctx)
{
	char path[PATH_MAX], temporary[PATH_MAX];
	int fd, dir, rc;

	if (snprintf(path, sizeof(path), "%s/simulator", ctx->directory) >=
		    (int)sizeof(path) ||
	    snprintf(temporary, sizeof(temporary), "%s/simulator.tmp",
		     ctx->directory) >= (int)sizeof(temporary))
		return -ENAMETOOLONG;
	fd = open(temporary,
		  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0)
		return -errno;
	rc = write_complete(fd, &ctx->sim, sizeof(ctx->sim));
	if (!rc && fsync(fd))
		rc = -errno;
	if (close(fd) && !rc)
		rc = -errno;
	if (!rc && rename(temporary, path))
		rc = -errno;
	if (rc)
		return rc;
	dir = open(ctx->directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dir < 0)
		return -errno;
	rc = fsync(dir) ? -errno : 0;
	close(dir);
	return rc;
}

static int simulator_load(struct test_context *ctx)
{
	char path[PATH_MAX];
	ssize_t got;
	int fd;

	if (snprintf(path, sizeof(path), "%s/simulator", ctx->directory) >=
	    (int)sizeof(path))
		return -ENAMETOOLONG;
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0) {
		if (errno != ENOENT)
			return -errno;
		ctx->sim.reset_count = 1;
		return 0;
	}
	got = read(fd, &ctx->sim, sizeof(ctx->sim));
	close(fd);
	return got == sizeof(ctx->sim) ? 0 : -EIO;
}

static int test_boot_identity(void *opaque, __u32 *reset, __u32 *restart)
{
	struct test_context *ctx = opaque;

	if (ctx->tpm)
		return shirudo_tpm_boot_identity(ctx->tpm, reset, restart);
	*reset = ctx->sim.reset_count;
	*restart = ctx->sim.restart_count;
	return 0;
}

static int test_pcr_read(void *opaque, __u32 pcr, __u8 out[32])
{
	struct test_context *ctx = opaque;

	if (getenv("SHIRUDO_TEST_CONFIG_READ_FAIL"))
		return -EIO;
	if (ctx->tpm)
		return tpm_pcr_read(ctx->tpm, pcr, out);
	memcpy(out, ctx->sim.value, 32);
	return 0;
}

static int test_pcr_extend(void *opaque, __u32 pcr,
			   const __u8 event[32])
{
	const char *mode = getenv("SHIRUDO_TEST_CONFIG_EXTEND");
	struct test_context *ctx = opaque;
	__u8 wrong[32] = { 1 };
	int rc;

	ctx->sim.extends++;
	rc = simulator_save(ctx);
	if (rc)
		return rc;
	if (mode && !strcmp(mode, "before"))
		return -EIO;
	if (mode && !strcmp(mode, "drift"))
		event = wrong;
	if (ctx->tpm)
		rc = tpm_pcr_extend(ctx->tpm, pcr, event);
	else
		rc = shirudo_chain_fold_checked(ctx->sim.value, event);
	if (!rc)
		rc = simulator_save(ctx);
	if (!rc && mode && !strcmp(mode, "ambiguous"))
		return -ETIMEDOUT;
	return rc;
}

static int test_prepare(void *opaque,
			const struct shirudo_config_update_target *target)
{
	struct test_context *ctx = opaque;
	size_t i;
	int rc;

	ctx->sim.prepares++;
	rc = simulator_save(ctx);
	if (rc)
		return rc;
	if (getenv("SHIRUDO_TEST_CONFIG_PREPARE_FAIL"))
		return -EKEYREJECTED;
	if (strlen(target->prefix) != sizeof("/verified/config-A") - 1 ||
	    strncmp(target->prefix, "/verified/config-",
		    sizeof("/verified/config-") - 1))
		return -EKEYREJECTED;
	for (i = 0; i < sizeof(target->root_hash); i++)
		if (target->root_hash[i] !=
		    (__u8)target->prefix[strlen(target->prefix) - 1])
			return -EKEYREJECTED;
	return 0;
}

static int test_activate(void *opaque,
			 const struct shirudo_config_update_target *target)
{
	struct shirudo_config_update_record record;
	struct test_context *ctx = opaque;
	__u8 live[32];
	int rc;

	rc = shirudo_config_update_read(ctx->update, &record);
	if (!rc)
		rc = test_pcr_read(ctx, record.pcr, live);
	if (rc)
		return rc;
	if (!record.pending ||
	    memcmp(target->root_hash, record.target.root_hash, 32))
		return -EUCLEAN;
	ctx->sim.activations++;
	ctx->sim.partial = target->prefix[strlen(target->prefix) - 1];
	rc = simulator_save(ctx);
	if (rc)
		return rc;
	if (getenv("SHIRUDO_TEST_CONFIG_ACTIVATE_FAIL"))
		return -EIO;
	memcpy(ctx->sim.active, target->root_hash, sizeof(ctx->sim.active));
	ctx->sim.partial = 0;
	return simulator_save(ctx);
}

static int test_seal(void *opaque, int fd)
{
	(void)opaque;
	(void)fd;
	return getenv("SHIRUDO_TEST_CONFIG_SEAL_FAIL") ? -EPERM : 0;
}

static int test_checkpoint(void *opaque,
			   enum shirudo_config_update_checkpoint checkpoint)
{
	const char *crash = getenv("SHIRUDO_TEST_CONFIG_CRASH");
	const char *fail = getenv("SHIRUDO_TEST_CONFIG_FAIL");

	(void)opaque;
	if (crash && strtoul(crash, NULL, 10) == checkpoint)
		_exit(99);
	if (fail && strtoul(fail, NULL, 10) == checkpoint)
		return -ECANCELED;
	return 0;
}

static const struct shirudo_config_update_ops test_ops = {
	.boot_identity = test_boot_identity,
	.pcr_read = test_pcr_read,
	.pcr_extend = test_pcr_extend,
	.prepare = test_prepare,
	.activate = test_activate,
	.seal = test_seal,
	.checkpoint = test_checkpoint,
};

static int make_target(char id, struct shirudo_config_update_target *target)
{
	memset(target, 0, sizeof(*target));
	snprintf(target->prefix, sizeof(target->prefix), "/verified/config-%c",
		 id);
	memset(target->root_hash, id, sizeof(target->root_hash));
	return 0;
}

static int show_event(const struct shirudo_config_update_record *record,
		      void *opaque)
{
	__u32 *count = opaque;
	char hex[65];

	hex_encode(record->target.root_hash, 32, hex);
	printf("event=%llu:%u:%u:%u:%s\n", (__u64)record->sequence,
	       record->reset_count, record->pcr, record->kind, hex);
	(*count)++;
	return 0;
}

static void inspect(struct test_context *ctx)
{
	struct shirudo_config_update_record record;
	__u8 value[32];
	__u32 count = 0;
	char hex[65];
	int rc;

	printf("extends=%u\nprepares=%u\nactivations=%u\npartial=%u\n",
	       ctx->sim.extends, ctx->sim.prepares, ctx->sim.activations,
	       ctx->sim.partial);
	if (!test_pcr_read(ctx, 15, value)) {
		hex_encode(value, 32, hex);
		printf("pcr_value=%s\n", hex);
	}
	rc = shirudo_config_update_read(ctx->update, &record);
	printf("state_rc=%d\n", rc);
	if (!rc) {
		printf("sequence=%llu\npending=%u\nkind=%u\npcr=%u\nreset=%u\n",
		       (__u64)record.sequence, record.pending,
		       record.kind, record.pcr, record.reset_count);
		printf("prefix=%s\nrestart=%u\n", record.target.prefix,
		       record.restart_count);
		hex_encode(record.initial_pcr, 32, hex);
		printf("initial_pcr=%s\n", hex);
		hex_encode(record.target.root_hash, 32, hex);
		printf("root_hash=%s\n", hex);
	}
	rc = shirudo_config_update_events(ctx->update, show_event, &count);
	printf("events_rc=%d\nevents=%u\n", rc, count);
}

int main(int argc, char **argv)
{
	struct shirudo_config_update second = { .dir_fd = -1, .lock_fd = -1 };
	struct shirudo_config_update update = { .dir_fd = -1, .lock_fd = -1 };
	struct test_context ctx = { .update = &update };
	struct shirudo_config_update_target target;
	char hex[65];
	__u32 pcr = 15;
	__u8 event[32];
	int rc;

	if (argc < 3 || argc > 5)
		return 2;
	ctx.directory = argv[1];
	if (argc > 3 &&
	    (strlen(argv[3]) != 1 || argv[3][0] < 'A' || argv[3][0] > 'Z'))
		return 2;
	if (argc == 5)
		pcr = strtoul(argv[4], NULL, 10);
	rc = make_target(argc > 3 ? argv[3][0] : 'A', &target);
	if (rc)
		return 1;
	if (!strcmp(argv[2], "describe")) {
		hex_encode(target.root_hash, sizeof(target.root_hash),
			   hex);
		printf("root_hash=%s\n", hex);
		rc = shirudo_config_measure_event(SHIRUDO_CONFIG_EVENT_BOOT,
						  target.root_hash, event);
		if (!rc) {
			hex_encode(event, sizeof(event), hex);
			printf("boot_event=%s\n", hex);
		}
		return rc ? 1 : 0;
	}
	rc = simulator_load(&ctx);
	if (rc)
		goto out;
	if (getenv("SHIRUDO_TEST_CONFIG_TPM")) {
		rc = tpm_open(&ctx.tpm);
		if (rc)
			goto out;
	}
	rc = shirudo_config_update_open(argv[1], &test_ops, &ctx, &update);
	if (rc)
		goto out;
	if (!strcmp(argv[2], "boot")) {
		rc = shirudo_config_update_boot(&update, &target, pcr);
		if (!rc && !getenv("SHIRUDO_TEST_CONFIG_BOOT_PENDING"))
			rc = shirudo_config_update_complete_boot(&update);
	} else if (!strcmp(argv[2], "update")) {
		rc = shirudo_config_update_begin(&update, &target, pcr);
	} else if (!strcmp(argv[2], "complete")) {
		rc = shirudo_config_update_complete_boot(&update);
	} else if (!strcmp(argv[2], "check")) {
		rc = shirudo_config_update_check(&update, NULL);
	} else if (!strcmp(argv[2], "inspect")) {
		rc = 0;
	} else if (!strcmp(argv[2], "reset")) {
		ctx.sim.reset_count++;
		memset(ctx.sim.value, 0, sizeof(ctx.sim.value));
		rc = simulator_save(&ctx);
	} else if (!strcmp(argv[2], "restart")) {
		ctx.sim.restart_count++;
		memset(ctx.sim.value, 0, sizeof(ctx.sim.value));
		rc = simulator_save(&ctx);
	} else if (!strcmp(argv[2], "drift")) {
		memset(ctx.sim.value, 0x55, sizeof(ctx.sim.value));
		rc = simulator_save(&ctx);
	} else if (!strcmp(argv[2], "lock")) {
		rc = shirudo_config_update_open(argv[1], &test_ops, &ctx,
						&second);
		shirudo_config_update_close(&second);
	} else {
		rc = -EINVAL;
	}
	inspect(&ctx);
	shirudo_config_update_close(&update);
out:
	if (ctx.tpm)
		tpm_close(ctx.tpm);
	printf("rc=%d\n", rc);
	return rc ? 1 : 0;
}
