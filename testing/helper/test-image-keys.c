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
#include "malloc.h"
#include "keyring.h"
#include "keys.h"

static __u32 mutations;
static char **held;
static int held_count;

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

int main(int argc, char **argv)
{
	struct shirudo_trusted_set set = {};
	int fd, rc;

	if (argc != 3)
		return 2;
	fd = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return 2;
	rc = shirudo_keys_validate_image_set(argv[1], fd, &set);
	close(fd);
	printf("rc=%d mutations=%u signers=%zu\n", rc, mutations, set.n);
	return rc || mutations ? 1 : 0;
}
