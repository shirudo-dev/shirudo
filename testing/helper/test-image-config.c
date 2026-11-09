// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "util/config.h"
#include "util/image_config.h"
#include "util/image_bootstrap.h"
#include "util/hex.h"

static int read_bootstrap(int argc, char **argv)
{
	struct image_bootstrap boot = {};
	char root[65];
	size_t i;
	int ret;

	ret = image_bootstrap_read(argv[2], &boot, true);
	if (!ret && argc == 4)
		ret = image_bootstrap_read(argv[3], &boot, false);
	if (!ret) {
		hex_encode(boot.runtime_root, 32, root);
		printf("runtime=%s\nroot=%s\nconfig=%s\npcr=%u\n",
		       boot.runtime, root, boot.config, boot.pcr);
		printf("certificates=%zu\n", boot.n_certificates);
		for (i = 0; i < boot.n_certificates; i++)
			printf("certificate=%s\n", boot.certificates[i]);
	}
	printf("rc=%d\n", ret);
	return ret ? 1 : 0;
}

int main(int argc, char **argv)
{
	struct config bootstrap, effective;
	int fd, ret;

	if (argc < 3 || argc > 4)
		return 2;
	if (!strcmp(argv[1], "bootstrap"))
		return read_bootstrap(argc, argv);
	fd = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return 1;
	ret = config_load_path(&bootstrap, "/dev/null");
	if (ret)
		goto out;
	memcpy(bootstrap.tpm_owner_auth, "bootstrap-owner", 15);
	bootstrap.tpm_owner_auth_len = 15;
	snprintf(bootstrap.tpm_tcti, sizeof(bootstrap.tpm_tcti),
		 "bootstrap-tcti");
	if (!strcmp(argv[1], "validate")) {
		ret = image_config_validate(fd);
	} else if (!strcmp(argv[1], "effective")) {
		ret = image_config_set(&bootstrap, fd);
		if (!ret && !image_config_get(&effective))
			ret = -EIO;
		if (!ret) {
			printf("owner=%.*s\ntcti=%s\nlimit=%llu\n",
			       (int)effective.tpm_owner_auth_len,
			       effective.tpm_owner_auth, effective.tpm_tcti,
			       effective.eventlog_max_bytes);
			ret = image_open(IMAGE_REGISTRIES,
					 O_RDONLY | O_DIRECTORY);
			printf("registries=%s\n", ret >= 0 ? "open" : "missing");
			if (ret >= 0)
				close(ret);
			ret = 0;
		}
	} else if (!strcmp(argv[1], "relative") && argc == 4) {
		ret = image_config_set(&bootstrap, fd);
		if (!ret)
			ret = image_open_relative(argv[3], O_RDONLY);
		if (ret >= 0) {
			printf("resolved=open\n");
			close(ret);
			ret = 0;
		}
	} else {
		ret = -EINVAL;
	}
out:
	image_config_clear();
	close(fd);
	printf("rc=%d\n", ret);
	return ret ? 1 : 0;
}
