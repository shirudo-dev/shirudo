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

static int boot_identity(void *ctx __attribute__((__unused__)),
			 __u32 *reset, __u32 *restart)
{
	struct tpm *tpm = NULL;
	int ret;

	ret = tpm_open(&tpm);
	if (!ret)
		ret = tpm_boot_identity(tpm, reset, restart);
	tpm_close(tpm);
	return ret;
}

static int pcr_read(void *ctx __attribute__((__unused__)),
		    __u32 pcr, __u8 out[32])
{
	struct tpm *tpm = NULL;
	int ret;

	ret = tpm_open(&tpm);
	if (!ret)
		ret = tpm_pcr_read(tpm, pcr, out);
	tpm_close(tpm);
	return ret;
}

static int no_extend(void *ctx __attribute__((__unused__)),
		     __u32 pcr __attribute__((__unused__)),
		     const __u8 event[32] __attribute__((__unused__)))
{
	return -EPERM;
}

static int no_activate(void *ctx __attribute__((__unused__)),
		       const struct config_update_target *target
		       __attribute__((__unused__)))
{
	return -EPERM;
}

static int no_seal(void *ctx __attribute__((__unused__)),
		   int fd __attribute__((__unused__)))
{
	return 0;
}

static const struct config_update_ops ops = {
	.boot_identity = boot_identity,
	.pcr_read = pcr_read,
	.pcr_extend = no_extend,
	.prepare = no_activate,
	.activate = no_activate,
	.seal = no_seal,
};

static int render(const char *directory, const char *nonce)
{
	struct config_update update = { .dir_fd = -1, .lock_fd = -1 };
	__u8 bytes[ATTEST_NONCE_MAX];
	char *document = NULL;
	size_t length = 0, capacity = 0, nonce_length;
	int ret;

	nonce_length = strlen(nonce) / 2;
	if (strlen(nonce) % 2 || nonce_length > sizeof(bytes) ||
	    hex_decode(nonce, bytes, nonce_length))
		return -EINVAL;
	ret = config_update_open(directory, &ops, NULL, &update);
	if (!ret)
		ret = attest_evidence_config(bytes, nonce_length,
					     CHAIN_PCR_MASK,
					     NULL, &update, &document,
					     &length, &capacity);
	if (!ret)
		ret = write_complete(STDOUT_FILENO, document, length);
	xfree(document, capacity);
	config_update_close(&update);
	return ret;
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
	    st.st_size > JSON_MAX_BYTES) {
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
	struct config_evidence config = {};
	__u8 pcrs[24][32] = {}, root[32];
	const char *reason = NULL;
	const __u8 *expected;
	__u32 mask, reset, restart;
	char *document = NULL;
	size_t length = 0;
	int pcr, ret;

	if (argc == 4 && !strcmp(argv[1], "render")) {
		ret = render(argv[2], argv[3]);
		if (ret)
			fprintf(stderr, "render failed: %d\n", ret);
		return ret ? 1 : 0;
	}
	if (argc != 3 && argc != 8)
		return 2;
	ret = read_document(argv[2], &document, &length);
	if (!ret)
		ret = config_evidence_parse(document, length, &config);
	if (ret)
		goto out;
	if (argc == 8 && !strcmp(argv[1], "replay")) {
		pcr = !strcmp(argv[4], "-") ? -1 : atoi(argv[4]);
		if (config.pcr >= 24 ||
		    (!strcmp(argv[3], "-") ?
			     0 :
			     hex_decode(argv[3], root, 32)) ||
		    hex_decode(argv[7], pcrs[config.pcr], 32)) {
			ret = -EINVAL;
			goto out;
		}
		mask = 1u << (pcr < 0 ? config.pcr : (__u32)pcr);
		reset = strtoul(argv[5], NULL, 10);
		restart = strtoul(argv[6], NULL, 10);
		expected = !strcmp(argv[3], "-") ? NULL : root;
		ret = config_evidence_verify(&config, mask, reset,
					     restart, pcrs, expected,
					     pcr, &reason);
	} else if (strcmp(argv[1], "parse")) {
		ret = -EINVAL;
	}
out:
	if (reason)
		printf("reason=%s\n", reason);
	printf("rc=%d\n", ret);
	config_evidence_clear(&config);
	xfree(document, document ? length + 1 : 0);
	return ret ? 1 : 0;
}
