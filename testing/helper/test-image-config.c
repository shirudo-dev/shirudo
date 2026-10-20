// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "util/config.h"
#include "util/image_config.h"

int main(int argc, char **argv)
{
	struct shirudo_config bootstrap, effective;
	char resolved[4096];
	int fd, rc;

	if (argc < 3 || argc > 4)
		return 2;
	fd = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return 1;
	rc = config_load_path(&bootstrap, "/dev/null");
	if (rc)
		goto out;
	memcpy(bootstrap.tpm_owner_auth, "bootstrap-owner", 15);
	bootstrap.tpm_owner_auth_len = 15;
	snprintf(bootstrap.tpm_tcti, sizeof(bootstrap.tpm_tcti),
		 "bootstrap-tcti");
	if (!strcmp(argv[1], "validate")) {
		rc = shirudo_image_config_validate(fd);
	} else if (!strcmp(argv[1], "effective")) {
		rc = shirudo_image_config_set(&bootstrap, fd);
		if (!rc && !shirudo_image_config_get(&effective))
			rc = -EIO;
		if (!rc) {
			printf("owner=%.*s\ntcti=%s\nlimit=%llu\n",
			       (int)effective.tpm_owner_auth_len,
			       effective.tpm_owner_auth, effective.tpm_tcti,
			       effective.eventlog_max_bytes);
			printf("registries=%s\n",
			       shirudo_image_path(SHIRUDO_IMAGE_REGISTRIES));
		}
	} else if (!strcmp(argv[1], "relative") && argc == 4) {
		rc = shirudo_image_config_set(&bootstrap, fd);
		if (!rc)
			rc = shirudo_image_path_relative(resolved,
							 sizeof(resolved),
							 argv[3]);
		if (!rc)
			printf("resolved=%s\n", resolved);
	} else {
		rc = -EINVAL;
	}
out:
	shirudo_image_config_clear();
	close(fd);
	printf("rc=%d\n", rc);
	return rc ? 1 : 0;
}
