// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <stdio.h>
#include <string.h>

#include "builtin.h"
#include "harden.h"
#include "identity.h"
#include "log.h"

/* Protocol setup and offline prediction do not enter the runtime. */
int main(int argc, const char **argv)
{
	harden_stdio();
	log_init();
	if (harden_self())
		return 1;
	if (argc > 2 && !strcmp(argv[1], "attest") && !strcmp(argv[2], "predict"))
		return cmd_attest(argc - 1, argv + 1);
	if (shirudo_enforcement_active() != 0) {
		fputs("register CLI fixture requires an uninitialized target\n", stderr);
		return 1;
	}
	if (argc > 1 && !strcmp(argv[1], "attest"))
		return cmd_attest(argc - 1, argv + 1);
	if (argc > 1 && !strcmp(argv[1], "status"))
		return cmd_status(argc - 1, argv + 1);
	fputs("usage: test-register-cli attest|status [options]\n", stderr);
	return 2;
}
