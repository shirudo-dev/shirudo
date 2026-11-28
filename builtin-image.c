// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "builtin.h"
#include "util/help.h"
#include "util/image_config.h"
#include "util/image_runtime.h"
#include "util/log.h"
#include "util/malloc.h"
#include "util/options.h"

static const struct help_item image_subcmds[] = {
	{ "build", "build a signed image from a file system image (operator)" },
	{ "verify", "check an image's signature and hash tree (operator)" },
	{ "update", "activate a config image now (target)" },
	{ "stage", "select a config image for the next boot (target)" },
	{ "status", "print the state of config activation (target)" },
};

enum image_stage_opt {
	IMAGE_STAGE_CANCEL,
};

static const struct opt_spec image_stage_opts[] = {
	[IMAGE_STAGE_CANCEL] = { "--cancel", 0, 0, NULL,
		"drop the selection for the next boot" },
};

enum image_status_opt {
	IMAGE_STATUS_JSON,
};

static const struct opt_spec image_status_opts[] = {
	[IMAGE_STATUS_JSON] = { "--json", 0, 0, NULL,
		"print the state as JSON" },
};

static const struct help_section image_help_sections[] = {
	HELP_ITEMS("subcommands:", image_subcmds),
	HELP_OPTIONS("stage options:", image_stage_opts),
	HELP_OPTIONS("status options:", image_status_opts),
};

static const struct help image_help = {
	.usage	    = "shirudo image build [image builder options]\n"
		      "       shirudo image verify <prefix> --cert <certificate>\n"
		      "       shirudo image update <prefix-or-https-prefix>\n"
		      "       shirudo image stage <prefix-or-https-prefix>\n"
		      "       shirudo image stage --cancel\n"
		      "       shirudo image status [--json]",
	.sections   = image_help_sections,
	.n_sections = ARRAY_SIZE(image_help_sections),
};

static int image_done(const char *sub, int ret)
{
	if (ret == -EINTR)
		return EXIT_INTERRUPTED;
	if (ret == -EINPROGRESS)
		pr_err("image: activation is pending; further changes are blocked");
	else if (ret)
		pr_err("image %s: %s", sub, strerror(-ret));
	return ret ? 1 : 0;
}

/*
 * The arguments of an update or a stage: OPT_END with either *prefix or
 * *cancel set, or OPT_DONE or OPT_USAGE to stop at. want names what the
 * command takes.
 */
static int image_target(struct opt_parser *p, bool *cancel,
			const char **prefix, const char *want)
{
	int opt;

	*cancel = false;
	*prefix = NULL;
	for (opt = opt_next(p); opt != OPT_END; opt = opt_next(p)) {
		switch (opt) {
		case IMAGE_STAGE_CANCEL:
			*cancel = true;
			break;
		case OPT_ARG:
			if (*prefix) {
				opt_usage(p, "unexpected argument '%s'",
					  p->value);
				return OPT_USAGE;
			}
			*prefix = p->value;
			break;
		default:
			return opt;
		}
	}
	if (*cancel == !!*prefix) {
		opt_usage(p, "takes %s", want);
		return OPT_USAGE;
	}
	return OPT_END;
}

static int image_update_cmd(int argc, const char **argv)
{
	const char *prefix;
	struct opt_parser p;
	bool cancel;
	int ret;

	opt_init(&p, "image update", NULL, 0, &image_help, argc, argv, 1);
	ret = image_target(&p, &cancel, &prefix, "<prefix>");
	if (ret != OPT_END)
		return ret == OPT_DONE ? 0 : EXIT_USAGE;
	return image_done("update", image_update(prefix));
}

static int image_stage_cmd(int argc, const char **argv)
{
	const char *prefix;
	struct opt_parser p;
	bool cancel;
	int ret;

	OPT_INIT(&p, "image stage", image_stage_opts, &image_help, argc, argv,
		 1);
	ret = image_target(&p, &cancel, &prefix, "<prefix> or --cancel");
	if (ret != OPT_END)
		return ret == OPT_DONE ? 0 : EXIT_USAGE;
	return image_done("stage", cancel ? image_stage_cancel() :
					    image_stage(prefix));
}

static int image_status_cmd(int argc, const char **argv)
{
	struct opt_parser p;
	bool json = false;
	int opt, ret;

	OPT_INIT(&p, "image status", image_status_opts, &image_help, argc,
		 argv, 1);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case IMAGE_STATUS_JSON:
			json = true;
			break;
		case OPT_ARG:
			opt_usage(&p, "unexpected argument '%s'", p.value);
			return EXIT_USAGE;
		case OPT_DONE:
			return 0;
		default:
			return EXIT_USAGE;
		}
	}
	ret = image_status(json);
	if (ret == -ENODEV) {
		pr_err("image status: no config activation state on this host");
		return 1;
	}
	return image_done("status", ret);
}

int cmd_image(int argc, const char **argv)
{
	const char *names[ARRAY_SIZE(image_subcmds)];
	size_t i;

	if (argc >= 2 && is_list_cmds(argv[1])) {
		print_subcmd_list(image_subcmds, ARRAY_SIZE(image_subcmds));
		return 0;
	}
	if (argc < 2 || is_help(argv[1])) {
		print_help(&image_help);
		return argc < 2 ? EXIT_USAGE : 0;
	}
	if (!strcmp(argv[1], "build") || !strcmp(argv[1], "verify"))
		return build_forward(!strcmp(argv[1], "build") ?
				     "image build" : "image verify",
				     (const char *const[]){ "image", NULL },
				     argc - 1, argv + 1);
	if (!strcmp(argv[1], "update"))
		return image_update_cmd(argc - 1, argv + 1);
	if (!strcmp(argv[1], "stage"))
		return image_stage_cmd(argc - 1, argv + 1);
	if (!strcmp(argv[1], "status"))
		return image_status_cmd(argc - 1, argv + 1);
	pr_err("image: '%s' is not a subcommand", argv[1]);
	for (i = 0; i < ARRAY_SIZE(image_subcmds); i++)
		names[i] = image_subcmds[i].name;
	help_suggest(argv[1], names, ARRAY_SIZE(names));
	return EXIT_USAGE;
}
