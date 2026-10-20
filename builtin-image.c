// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "builtin.h"
#include "util/image_config.h"
#include "util/image_runtime.h"
#include "util/log.h"
#include "util/malloc.h"

static void image_help(void)
{
	fprintf(stderr,
		"usage: shirudo image build [image builder options]\n"
		"       shirudo image verify <prefix> --cert <certificate>\n"
		"       shirudo image update <prefix-or-https-prefix>\n"
		"       shirudo image status\n");
}

int cmd_image(int argc, const char **argv)
{
	int rc;

	if (argc == 2 && !strcmp(argv[1], "--list-cmds")) {
		puts("build verify update status");
		return 0;
	}
	if (argc < 2 || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
		image_help();
		return argc < 2 ? 2 : 0;
	}
	if (!strcmp(argv[1], "build") || !strcmp(argv[1], "verify")) {
		char **helper;
		size_t bytes;
		int i;

		bytes = ((size_t)argc + 2) * sizeof(*helper);
		helper = xcalloc((size_t)argc + 2, sizeof(*helper));
		if (!helper)
			return 1;
		helper[1] = "image";
		for (i = 1; i < argc; i++)
			helper[i + 1] = (char *)argv[i];
		rc = shirudo_build_exec(!strcmp(argv[1], "build") ?
					"image build" : "image verify", helper);
		xfree(helper, bytes);
		return rc;
	}
	if (!strcmp(argv[1], "update") && argc == 3) {
		rc = shirudo_image_update(argv[2]);
	} else if (!strcmp(argv[1], "status") && argc == 2) {
		rc = shirudo_image_status();
	} else {
		image_help();
		return 2;
	}
	if (rc == -EINPROGRESS)
		pr_err("image: activation is pending; further changes are blocked");
	else if (rc)
		pr_err("image %s: %s", argv[1], strerror(-rc));
	return rc ? 1 : 0;
}
