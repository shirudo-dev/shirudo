// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Drives the trusted certificate set: load a keys directory, print its
 * members and the digest the init event covers, or name a upatch's
 * signer. Subcommand on argv[1]; prints what a shell test asserts on.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "hex.h"
#include "keys.h"
#include "upatch.h"

static void puthex(const uint8_t *b, size_t n)
{
	char h[65];

	shirudo_hex_encode(b, n, h);
	puts(h);
}

int main(int argc, char **argv)
{
	struct shirudo_trusted_set set;
	uint8_t digest[32];
	size_t i;
	int rc;

	if (argc < 3) {
		fprintf(stderr, "usage: %s load|digest|reject <keys-dir>"
			" [primary]"
			" | signer <upatch> <cert.der>\n", argv[0]);
		return 2;
	}
	if (strcmp(argv[1], "signer") == 0) {
		struct shirudo_cert cert = {};
		struct shirudo_upatch u;

		if (argc < 4 || shirudo_upatch_open(argv[2], &u)) {
			fprintf(stderr, "usage: signer <upatch> <cert.der>\n");
			return 2;
		}
		if (shirudo_cert_read_file(argv[3], &cert)) {
			shirudo_upatch_close(&u);
			return 2;
		}
		rc = shirudo_cms_signed_by(shirudo_upatch_signature(&u),
					   u.hdr.signature_len, &cert);
		shirudo_cert_free(&cert);
		shirudo_upatch_close(&u);
		printf("%s\n", rc == 1 ? "yes" : rc == 0 ? "no" : "error");
		return rc < 0 ? 1 : 0;
	}
	rc = shirudo_keys_load(argv[2], NULL,
			       argc < 4 || strcmp(argv[3], "primary"), &set);
	if (!strcmp(argv[1], "reject"))
		return rc == -EINVAL ? 0 : 1;
	if (rc) {
		printf("rc=%d\n", rc);
		return 1;
	}
	if (strcmp(argv[1], "load") == 0) {
		printf("n=%zu revoked=%zu unvouched=%zu\n", set.n,
		       set.n_revoked, set.n_unvouched);
		for (i = 0; i < set.n; i++) {
			char sha[65], fp[65];

			shirudo_hex_encode(set.certs[i].sha256, 32, sha);
			shirudo_hex_encode(set.certs[i].fingerprint, 32, fp);
			printf("%s %s %s %s\n", sha, fp,
			       set.certs[i].primary ? "primary" : "trusted",
			       set.certs[i].path);
		}
		return 0;
	}
	if (strcmp(argv[1], "digest") == 0) {
		shirudo_keys_set_digest(&set, digest);
		puthex(digest, 32);
		return 0;
	}
	fprintf(stderr, "unknown subcommand\n");
	return 2;
}
