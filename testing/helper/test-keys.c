// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Drives the trusted certificate set: load a keys directory, print its
 * members and the digest the init event covers, or name a upatch's
 * signer. Subcommand on argv[1]; prints what a shell test asserts on.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <shirudo/misc.h>

#include "crypto.h"
#include "hex.h"
#include "keys.h"
#include "io.h"
#include "malloc.h"
#include "upatch.h"

static void puthex(const __u8 *b, size_t n)
{
	char h[65];

	hex_encode(b, n, h);
	puts(h);
}

static noinline_for_stack int verify_signature(const char *directory,
					       const char *payload_path,
					       const char *signature_path)
{
	struct trusted_set set;
	__u8 *payload = NULL, *signature = NULL;
	size_t payload_sz = 0, signature_sz = 0;
	__u8 signer[32];
	char primary[PATH_MAX];
	int root, ret;

	snprintf(primary, sizeof(primary), "%s/cert.der", directory);
	root = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (root < 0)
		return 1;
	ret = keys_load_image_at(primary, root, true, &set);
	close(root);
	if (!ret)
		ret = read_file(payload_path, 1024 * 1024, &payload, &payload_sz);
	if (!ret)
		ret = read_file(signature_path, 65536, &signature, &signature_sz);
	if (!ret)
		ret = keys_verify_signature(&set, payload, payload_sz, signature,
					    signature_sz, signer);
	if (!ret)
		puthex(signer, sizeof(signer));
	xfree(payload, payload_sz + 1);
	xfree(signature, signature_sz + 1);
	printf("rc=%d\n", ret);
	return ret ? 1 : 0;
}

int main(int argc, char **argv)
{
	struct trusted_set set;
	__u8 digest[32];
	size_t i;
	int ret;

	if (argc < 3) {
		fprintf(stderr, "usage: %s load|digest|reject <keys-dir>"
			" [primary]"
			" | signer <upatch> <cert.der>\n", argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "verify-signature"))
		return argc == 5 ? verify_signature(argv[2], argv[3], argv[4]) : 2;
	if (strcmp(argv[1], "signer") == 0) {
		struct cert cert = {};
		struct upatch u;

		if (argc < 4 || upatch_open(argv[2], &u)) {
			fprintf(stderr, "usage: signer <upatch> <cert.der>\n");
			return 2;
		}
		if (cert_read_file(argv[3], &cert)) {
			upatch_close(&u);
			return 2;
		}
		ret = cms_signed_by(upatch_signature(&u),
				    u.hdr.signature_len, &cert);
		cert_free(&cert);
		upatch_close(&u);
		printf("%s\n", ret == 1 ? "yes" : ret == 0 ? "no" : "error");
		return ret < 0 ? 1 : 0;
	}
	if (!strcmp(argv[1], "image")) {
		char primary[PATH_MAX];
		int root;

		snprintf(primary, sizeof(primary), "%s/cert.der", argv[2]);
		root = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (root < 0)
			return 1;
		ret = keys_load_image_at(primary, root, true, &set);
		close(root);
	} else {
		ret = keys_load(argv[2], NULL,
				argc < 4 || strcmp(argv[3], "primary"),
				       &set);
	}
	if (!strcmp(argv[1], "reject"))
		return ret == -EINVAL ? 0 : 1;
	if (ret) {
		printf("rc=%d\n", ret);
		return 1;
	}
	if (!strcmp(argv[1], "load") || !strcmp(argv[1], "image")) {
		printf("n=%zu revoked=%zu unvouched=%zu\n", set.n,
		       set.n_revoked, set.n_unvouched);
		for (i = 0; i < set.n; i++) {
			char sha[65], fp[65];

			hex_encode(set.certs[i].sha256, 32, sha);
			hex_encode(set.certs[i].fingerprint, 32, fp);
			printf("%s %s %s %s\n", sha, fp,
			       set.certs[i].primary ? "primary" : "trusted",
			       set.certs[i].path);
		}
		return 0;
	}
	if (strcmp(argv[1], "digest") == 0) {
		keys_set_digest(&set, digest);
		puthex(digest, 32);
		return 0;
	}
	fprintf(stderr, "unknown subcommand\n");
	return 2;
}
