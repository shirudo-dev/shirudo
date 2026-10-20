// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "config_image.h"
#include "hex.h"

static int header_read(const char *path, struct shirudo_config_image *image)
{
	int fd, rc;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	rc = shirudo_config_image_read_header(fd, image);
	close(fd);
	return rc;
}

int main(int argc, char **argv)
{
	struct shirudo_config_image_open op = {
		.data_fd = -1,
		.hash_fd = -1,
		.signature_fd = -1,
	};
	struct shirudo_config_image image;
	__u8 root[32];
	int rc = -EINVAL;

	if (argc == 4 && !strcmp(argv[1], "root")) {
		rc = hex_decode(argv[3], root, sizeof(root));
		if (!rc)
			rc = shirudo_config_image_open_root(argv[2], root,
							    &op);
		shirudo_config_image_close(&op);
	} else if (argc == 3 && !strcmp(argv[1], "decode")) {
		rc = header_read(argv[2], &image);
		if (!rc) {
			printf("%llu %llu\n",
			       (__u64)image.data_blocks,
			       (__u64)image.hash_blocks);
		}
	}
	if (rc)
		fprintf(stderr, "config image: %s (%d)\n", strerror(-rc), rc);
	return rc ? 1 : 0;
}
