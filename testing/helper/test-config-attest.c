// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util/attest.h"
#include "util/config_attest.h"
#include "util/config_measure.h"
#include "util/hex.h"
#include "util/io.h"
#include "util/json.h"
#include "util/malloc.h"
#include "util/tpm.h"

static int boot_identity(void *ctx, __u32 *reset, __u32 *restart)
{
	struct shirudo_tpm *tpm = NULL;
	int rc;

	(void)ctx;
	rc = tpm_open(&tpm);
	if (!rc)
		rc = shirudo_tpm_boot_identity(tpm, reset, restart);
	tpm_close(tpm);
	return rc;
}

static int pcr_read(void *ctx, __u32 pcr, __u8 out[32])
{
	struct shirudo_tpm *tpm = NULL;
	int rc;

	(void)ctx;
	rc = tpm_open(&tpm);
	if (!rc)
		rc = tpm_pcr_read(tpm, pcr, out);
	tpm_close(tpm);
	return rc;
}

static int no_extend(void *ctx, __u32 pcr, const __u8 event[32])
{
	(void)ctx;
	(void)pcr;
	(void)event;
	return -EPERM;
}

static int no_activate(void *ctx,
		       const struct shirudo_config_update_target *target)
{
	(void)ctx;
	(void)target;
	return -EPERM;
}

static int no_seal(void *ctx, int fd)
{
	(void)ctx;
	(void)fd;
	return 0;
}

static const struct shirudo_config_update_ops ops = {
	.boot_identity = boot_identity,
	.pcr_read = pcr_read,
	.pcr_extend = no_extend,
	.prepare = no_activate,
	.activate = no_activate,
	.seal = no_seal,
};

static int render(const char *directory, const char *nonce)
{
	struct shirudo_config_update update = { .dir_fd = -1, .lock_fd = -1 };
	__u8 bytes[SHIRUDO_ATTEST_NONCE_MAX];
	char *document = NULL;
	size_t length = 0, capacity = 0, nonce_length;
	int rc;

	nonce_length = strlen(nonce) / 2;
	if (strlen(nonce) % 2 || nonce_length > sizeof(bytes) ||
	    hex_decode(nonce, bytes, nonce_length))
		return -EINVAL;
	rc = shirudo_config_update_open(directory, &ops, NULL, &update);
	if (!rc)
		rc = shirudo_attest_evidence_config(bytes, nonce_length,
						    SHIRUDO_CHAIN_PCR_MASK,
						    NULL, &update, &document,
						    &length, &capacity);
	if (!rc)
		rc = write_complete(STDOUT_FILENO, document, length);
	xfree(document, capacity);
	shirudo_config_update_close(&update);
	return rc;
}

static int read_document(const char *path, char **out, size_t *length)
{
	struct stat st;
	ssize_t got;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) || st.st_size <= 0 ||
	    st.st_size > SHIRUDO_JSON_MAX_BYTES) {
		close(fd);
		return -EINVAL;
	}
	*out = xmalloc(st.st_size + 1);
	if (!*out) {
		close(fd);
		return -ENOMEM;
	}
	got = read(fd, *out, st.st_size);
	close(fd);
	if (got != st.st_size) {
		xfree(*out, st.st_size + 1);
		*out = NULL;
		return -EIO;
	}
	(*out)[got] = 0;
	*length = got;
	return 0;
}

int main(int argc, char **argv)
{
	struct shirudo_config_evidence config = {};
	__u8 pcrs[24][32] = {}, root[32];
	const char *reason = NULL;
	const __u8 *expected;
	__u32 mask, reset, restart;
	char *document = NULL;
	size_t length = 0;
	int pcr, rc;

	if (argc == 4 && !strcmp(argv[1], "render")) {
		rc = render(argv[2], argv[3]);
		if (rc)
			fprintf(stderr, "render failed: %d\n", rc);
		return rc ? 1 : 0;
	}
	if (argc != 3 && argc != 8)
		return 2;
	rc = read_document(argv[2], &document, &length);
	if (!rc)
		rc = shirudo_config_evidence_parse(document, length, &config);
	if (rc)
		goto out;
	if (argc == 8 && !strcmp(argv[1], "replay")) {
		pcr = !strcmp(argv[4], "-") ? -1 : atoi(argv[4]);
		if (config.pcr >= 24 ||
		    (!strcmp(argv[3], "-") ?
			     0 :
			     hex_decode(argv[3], root, 32)) ||
		    hex_decode(argv[7], pcrs[config.pcr], 32)) {
			rc = -EINVAL;
			goto out;
		}
		mask = 1u << (pcr < 0 ? config.pcr : (__u32)pcr);
		reset = strtoul(argv[5], NULL, 10);
		restart = strtoul(argv[6], NULL, 10);
		expected = !strcmp(argv[3], "-") ? NULL : root;
		rc = shirudo_config_evidence_verify(&config, mask, reset,
						    restart, pcrs, expected,
						    pcr, &reason);
	} else if (strcmp(argv[1], "parse")) {
		rc = -EINVAL;
	}
out:
	if (reason)
		printf("reason=%s\n", reason);
	printf("rc=%d\n", rc);
	shirudo_config_evidence_clear(&config);
	xfree(document, document ? length + 1 : 0);
	return rc ? 1 : 0;
}
