// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Operator-side execv of clang -target bpf for .bpf.c -> .bpf.o.
 * The clang path is hardcoded at build time; PATH is never consulted.
 */

#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <shirudo/string.h>

#include "compile.h"
#include "log.h"
#include "malloc.h"

#ifndef SHIRUDO_CLANG_PATH
#define SHIRUDO_CLANG_PATH	"/usr/bin/clang"
#endif

#ifndef SHIRUDO_BPF_INCDIR
#define SHIRUDO_BPF_INCDIR	"/usr/share/shirudo/bpf/include"
#endif

#define SHIRUDO_BUILD_MAX_ARGS	64

static int push(const char **argv, int *n, const char *arg)
{
	if (*n >= SHIRUDO_BUILD_MAX_ARGS - 1)
		return -E2BIG;
	argv[(*n)++] = arg;
	return 0;
}

static const char *locate_bpf_headers(void)
{
	static const char installed[] = "-I" SHIRUDO_BPF_INCDIR;
	static const char in_tree[] = "-I./vendor/libbpf";
	struct stat st;

	if (stat("./vendor/libbpf/bpf/bpf_helpers.h", &st) == 0)
		return in_tree;
	if (stat(SHIRUDO_BPF_INCDIR "/bpf/bpf_helpers.h", &st) == 0)
		return installed;
	return NULL;
}

static const char *locate_shirudo_bpf_headers(void)
{
	static const char in_tree[] = "-I./bpf/lib";
	struct stat st;

	if (stat("./bpf/lib/shirudo_serializer.h", &st) == 0)
		return in_tree;
	return NULL;
}

int shirudo_build_compile(const char *source, const char *output,
			  const char *vmlinux_h, const char *extra_cflags)
{
	const char *argv[SHIRUDO_BUILD_MAX_ARGS] = {};
	char inc_vmlinux[1024 + 8];
	char vmlinux_dir[1024];
	char *cf_copy = NULL;
	int rc = 0;
	int status;
	int n = 0;
	pid_t pid;

	if (access(SHIRUDO_CLANG_PATH, X_OK) != 0) {
		pr_err("clang not at hardcoded path %s: %s",
		       SHIRUDO_CLANG_PATH, strerror(errno));
		return -ENOENT;
	}

	if (strscpy(vmlinux_dir, vmlinux_h, sizeof(vmlinux_dir)) < 0) {
		pr_err("vmlinux.h path too long: %s", vmlinux_h);
		return -ENAMETOOLONG;
	}
	{
		char *slash = strrchr(vmlinux_dir, '/');

		if (slash)
			*slash = '\0';
		else
			snprintf(vmlinux_dir, sizeof(vmlinux_dir), ".");
	}
	snprintf(inc_vmlinux, sizeof(inc_vmlinux), "-I%s", vmlinux_dir);

	push(argv, &n, SHIRUDO_CLANG_PATH);
	push(argv, &n, "-target");
	push(argv, &n, "bpf");
	push(argv, &n, "-O2");
	push(argv, &n, "-g");
	push(argv, &n, "-Wall");
	push(argv, &n, "-Wextra");
	/*
	 * vmlinux.h dumps anonymous struct forward declarations that
	 * trip -Wmissing-declarations -- unfixable upstream of us;
	 * BPF_PROG() macro expansion produces named-but-unused params
	 * that trip -Wunused-parameter. Both are pure noise; operators
	 * can re-enable via --extra-cflags if they want.
	 */
	push(argv, &n, "-Wno-missing-declarations");
	push(argv, &n, "-Wno-unused-parameter");
	push(argv, &n, inc_vmlinux);
	{
		const char *inc_bpf = locate_bpf_headers();

		if (inc_bpf)
			push(argv, &n, inc_bpf);
	}
	{
		const char *inc_shirudo_bpf = locate_shirudo_bpf_headers();

		if (inc_shirudo_bpf)
			push(argv, &n, inc_shirudo_bpf);
	}
	push(argv, &n, "-c");
	push(argv, &n, source);
	push(argv, &n, "-o");
	push(argv, &n, output);

	if (extra_cflags && extra_cflags[0]) {
		char *tok;

		cf_copy = xstrdup(extra_cflags);
		if (!cf_copy)
			return -ENOMEM;
		for (tok = strtok(cf_copy, " \t\n"); tok;
		     tok = strtok(NULL, " \t\n")) {
			rc = push(argv, &n, tok);
			if (rc) {
				xstrfree(cf_copy);
				return rc;
			}
		}
	}
	argv[n] = NULL;

	pid = fork();
	if (pid < 0) {
		rc = -errno;
		pr_err("fork: %s", strerror(errno));
		goto out;
	}
	if (pid == 0) {
		execv(SHIRUDO_CLANG_PATH, (char *const *)argv);
		fprintf(stderr, "exec %s: %s\n",
			SHIRUDO_CLANG_PATH, strerror(errno));
		_exit(127);
	}
	if (waitpid(pid, &status, 0) < 0) {
		rc = -errno;
		goto out;
	}
	if (WIFEXITED(status)) {
		int es = WEXITSTATUS(status);

		if (es == 0) {
			rc = 0;
		} else {
			pr_err("clang exited with status %d", es);
			rc = -EIO;
		}
	} else if (WIFSIGNALED(status)) {
		pr_err("clang killed by signal %d", WTERMSIG(status));
		rc = -EINTR;
	} else {
		rc = -EIO;
	}
out:
	xstrfree(cf_copy);
	return rc;
}
