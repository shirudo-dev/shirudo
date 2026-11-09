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
		"       shirudo image stage <prefix-or-https-prefix>\n"
		"       shirudo image stage --cancel\n"
		"       shirudo image status [--json]\n");
}

int cmd_image(int argc, const char **argv)
{
	int ret;

	if (argc == 2 && !strcmp(argv[1], "--list-cmds")) {
		puts("build verify update stage status");
		return 0;
	}
	if (argc < 2 || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
		image_help();
		return argc < 2 ? 2 : 0;
	}
	if (!strcmp(argv[1], "build") || !strcmp(argv[1], "verify"))
		return build_forward(!strcmp(argv[1], "build") ?
				     "image build" : "image verify",
				     (const char *const[]){ "image", NULL },
				     argc - 1, argv + 1);
	if (!strcmp(argv[1], "update") && argc == 3) {
		ret = image_update(argv[2]);
	} else if (!strcmp(argv[1], "stage") && argc == 3) {
		ret = !strcmp(argv[2], "--cancel") ? image_stage_cancel() :
						    image_stage(argv[2]);
	} else if (!strcmp(argv[1], "status") &&
		   (argc == 2 || (argc == 3 && !strcmp(argv[2], "--json")))) {
		ret = image_status(argc == 3);
		if (ret == -ENODEV) {
			pr_err("image status: no config activation state on this host");
			return 1;
		}
	} else {
		image_help();
		return 2;
	}
	if (ret == -EINPROGRESS)
		pr_err("image: activation is pending; further changes are blocked");
	else if (ret)
		pr_err("image %s: %s", argv[1], strerror(-ret));
	return ret ? 1 : 0;
}
