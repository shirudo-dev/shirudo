// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The bootstrap settings of a runtime image, as the initial image and as
 * a later one carries them, and the verity superblock of a config image.
 */

#include "fuzz.h"
#include "config_image.h"
#include "image_bootstrap.h"

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct image_bootstrap boot = {};
	struct config_image image;
	char path[64];
	int fd;

	fd = fuzz_file(data, size, path, sizeof(path));
	if (fd < 0)
		return 0;
	image_bootstrap_read_fd(fd, &boot, true);
	image_bootstrap_read_fd(fd, &boot, false);
	config_image_read_header(fd, &image);
	close(fd);
	return 0;
}
