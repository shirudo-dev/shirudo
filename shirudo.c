// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * main() and the subcommand dispatch table.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "builtin.h"
#include "util/harden.h"
#include "util/image_runtime.h"
#include "util/help.h"
#include "util/log.h"
#include "util/macros.h"
#include "util/similar.h"

enum cmd_group {
	GROUP_OPERATOR,
	GROUP_TARGET,
	GROUP_LOCAL,
	GROUP_GENERAL,
};

struct cmd {
	const char	*name;
	int		(*fn)(int argc, const char **argv);
	enum cmd_group	group;
	const char	*summary;
};

static int cmd_help(int argc, const char **argv);

/*
 * Adding an entry updates the dispatch, `shirudo help` and bash
 * completion, which pulls the list live through --list-cmds.
 */
static const struct cmd commands[] = {
	{ "genkey",	cmd_genkey,	GROUP_OPERATOR,	"generate the signing key + cert" },
	{ "build",	cmd_build,	GROUP_OPERATOR,	"compile + sign a .upatch" },

	{ "image", cmd_image, GROUP_LOCAL,
	  "build, verify and activate dm-verity config images" },
	{ "init",	cmd_init,	GROUP_TARGET,
	  "bootstrap shirudo enforcement on this target" },
	{ "upatch",	cmd_upatch,	GROUP_TARGET,
	  "load / unload (target); list / info (read-only, anywhere)" },
	{ "bpm",	cmd_bpm,	GROUP_TARGET,
	  "manage signed OCI packages on this target" },

	{ "status",	cmd_status,	GROUP_LOCAL,	"local readiness + state report" },
	{ "attest",	cmd_attest,	GROUP_LOCAL,
	  "TPM-signed evidence (target); verify / predict (operator)" },
	{ "keys",	cmd_keys,	GROUP_LOCAL,	"inspect cert / keyring contents" },
	{ "version",	cmd_version,	GROUP_LOCAL,	"print version and SHIRUDO_VERSION_ID" },

	{ "config",	cmd_config,	GROUP_GENERAL,
	  "print the effective shirudo.conf (defaults if absent)" },
	{ "help",	cmd_help,	GROUP_GENERAL,	"show this list" },
};

static const size_t commands_n = ARRAY_SIZE(commands);

static void print_group(enum cmd_group g, const char *header)
{
	int first = 1;

	for (size_t i = 0; i < commands_n; i++) {
		if (commands[i].group != g)
			continue;
		if (first) {
			fprintf(stderr, "%s\n", header);
			first = 0;
		}
		fprintf(stderr, "  %-9s %s\n",
			commands[i].name, commands[i].summary);
	}
	if (!first)
		fprintf(stderr, "\n");
}

static int cmd_help(int argc, const char **argv)
{
	if (argc > 1 && strcmp(argv[1], "--list-cmds") == 0) {
		for (size_t i = 0; i < commands_n; i++)
			printf("%s\n", commands[i].name);
		return 0;
	}

	fprintf(stderr, "usage: shirudo <command> [<args>]\n\n");
	print_group(GROUP_OPERATOR,
		    "operator commands (hold the signing key; drive targets):");
	print_group(GROUP_TARGET,
		    "target commands (run locally on the target):");
	print_group(GROUP_LOCAL, "local commands (operator or target):");
	print_group(GROUP_GENERAL, "other:");
	fprintf(stderr, "See Documentation/ for the design.\n");
	return 0;
}

int main(int argc, const char **argv)
{
	const struct cmd *c = NULL;
	const char *names[ARRAY_SIZE(commands)];
	size_t matches[ARRAY_SIZE(commands)];
	size_t i, n_match;
	int rc;

	harden_stdio();
	log_init();
	harden_self();

	if (argc < 2) {
		cmd_help(0, NULL);
		return 1;
	}
	if (is_list_cmds(argv[1])) {
		for (i = 0; i < commands_n; i++)
			printf("%s\n", commands[i].name);
		return 0;
	}
	/* With the rest of argv, so `--help --list-cmds` still lists. */
	if (is_help(argv[1]))
		return cmd_help(argc - 1, argv + 1);

	for (i = 0; i < commands_n; i++)
		names[i] = commands[i].name;

	/* Tolerant matching is the Levenshtein pass below. */
	n_match = resolve(argv[1], names, commands_n,
			  matches, ARRAY_SIZE(matches));
	if (n_match == 1) {
		c = &commands[matches[0]];
	} else if (n_match > 1) {
		fprintf(stderr, "shirudo: '%s' is ambiguous; matches:\n",
			argv[1]);
		for (i = 0; i < n_match; i++)
			fprintf(stderr, "\t%s\n", commands[matches[i]].name);
		return 1;
	}
	if (!c) {
		struct shirudo_suggestion sugg[4];
		size_t n;
		int max_dist, len;

		fprintf(stderr,
			"'%s' is not a shirudo command.\n"
			"See 'shirudo help'.\n", argv[1]);

		/*
		 * Edit-distance threshold: a quarter is too tight for short
		 * inputs and "anything goes" for long ones, so cap at 3.
		 */
		len = (int)strlen(argv[1]);
		max_dist = len / 2 + 1;
		if (max_dist > 3)
			max_dist = 3;

		n = suggest(argv[1], names, commands_n, max_dist,
			    sugg, ARRAY_SIZE(sugg));
		if (n) {
			fprintf(stderr, "\nDid you mean one of:\n");
			for (i = 0; i < n; i++)
				fprintf(stderr, "\t%s\n", sugg[i].name);
		}
		return 1;
	}

	rc = shirudo_image_enter(c->name, argc - 1, argv + 1);

	if (rc) {
		fprintf(stderr, "shirudo: image state: %s\n", strerror(-rc));
		shirudo_image_leave();
		return 1;
	}
	rc = c->fn(argc - 1, argv + 1);
	shirudo_image_leave();
	return rc;
}
