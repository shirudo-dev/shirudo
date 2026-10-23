// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>

#include "harden.h"

static int lock_error;
static int lock_flags;

/* Supply deterministic outcomes without locking the test process. */
int mlockall(int flags)
{
	lock_flags = flags;
	if (lock_error) {
		errno = lock_error;
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct rlimit core = {};
	int rc;

	if (argc != 2)
		goto usage;
	if (!strcmp(argv[1], "success"))
		lock_error = 0;
	else if (!strcmp(argv[1], "denied"))
		lock_error = EPERM;
	else if (!strcmp(argv[1], "limit"))
		lock_error = ENOMEM;
	else
		goto usage;

	rc = harden_self();
	if (lock_flags != (MCL_CURRENT | MCL_FUTURE) || rc != -lock_error) {
		fprintf(stderr, "unexpected lock flags or result\n");
		return 2;
	}
	if (prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0 ||
	    prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
	    getrlimit(RLIMIT_CORE, &core) || core.rlim_cur || core.rlim_max) {
		fprintf(stderr, "existing startup hardening changed\n");
		return 2;
	}
	printf("rc=%d\n", rc);
	return rc ? 1 : 0;
usage:
	fprintf(stderr, "usage: %s success|denied|limit\n", argv[0]);
	return 2;
}
