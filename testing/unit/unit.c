// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Runs a unit suite in TAP, each case in a child so one crash fails it alone.
 */

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

#ifdef UNIT_GCOV
#include <gcov.h>
#endif

#include <shirudo/string.h>

#include "unit.h"

#define UNIT_TIMEOUT	60
#define UNIT_SKIPPED	77
#define UNIT_REASON_MAX	256

static int unit_failed;
static char *unit_reason;

void unit_fail(const char *file, int line, const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s:%d: ", file, line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	unit_failed = 1;
}

void unit_fail_mem(const char *file, int line, const char *what,
		   const void *a, const void *b, size_t len)
{
	const __u8 *x = a, *y = b;
	size_t i = 0;

	while (i < len && x[i] == y[i])
		i++;
	unit_fail(file, line, "%s: differ at byte %zu of %zu: %02x vs %02x",
		  what, i, len, x[i], y[i]);
}

static __noreturn void unit_exit(int status)
{
	fflush(stdout);
	fflush(stderr);
#ifdef UNIT_GCOV
	__gcov_dump();
#endif
	_exit(status);
}

void unit_abort(void)
{
	unit_exit(1);
}

void unit_skip(const char *reason)
{
	size_t n = strlen(reason);

	if (n >= UNIT_REASON_MAX)
		n = UNIT_REASON_MAX - 1;
	memcpy(unit_reason, reason, n);
	unit_reason[n] = '\0';
	unit_exit(UNIT_SKIPPED);
}

/* A failing case's stderr comes back as TAP diagnostics. */
static void replay(int fd)
{
	char buf[4096];
	int bol = 1;
	ssize_t n;

	if (lseek(fd, 0, SEEK_SET) < 0)
		return;
	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		for (ssize_t i = 0; i < n; i++) {
			if (bol)
				fputs("# ", stdout);
			fputc(buf[i], stdout);
			bol = buf[i] == '\n';
		}
	}
	if (!bol)
		fputc('\n', stdout);
}

static int run_case(const struct unit_case *c, size_t nr)
{
	int fd, status;
	pid_t pid;

	fd = memfd_create("unit-stderr", MFD_CLOEXEC);
	if (fd < 0) {
		printf("not ok %zu - %s # memfd: %s\n", nr, c->name,
		       strerror(errno));
		return 1;
	}
	unit_reason[0] = '\0';
	fflush(stdout);
	fflush(stderr);
	pid = fork();
	if (pid < 0) {
		printf("not ok %zu - %s # fork: %s\n", nr, c->name,
		       strerror(errno));
		close(fd);
		return 1;
	}
	if (pid == 0) {
		dup2(fd, STDERR_FILENO);
		alarm(UNIT_TIMEOUT);
		c->run();
		unit_exit(unit_failed ? 1 : 0);
	}
	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR) {
			status = -1;
			break;
		}
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		printf("ok %zu - %s\n", nr, c->name);
		close(fd);
		return 0;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == UNIT_SKIPPED) {
		printf("ok %zu - %s # SKIP %s\n", nr, c->name, unit_reason);
		close(fd);
		return 0;
	}
	printf("not ok %zu - %s\n", nr, c->name);
	if (WIFSIGNALED(status))
		printf("# %s\n", WTERMSIG(status) == SIGALRM ?
		       "timed out" : strsignal(WTERMSIG(status)));
	replay(fd);
	close(fd);
	return 1;
}

int main(int argc, char **argv)
{
	const char *only = argc > 1 ? argv[1] : NULL;
	size_t nr = 0, failed = 0;

	unit_reason = mmap(NULL, UNIT_REASON_MAX, PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (unit_reason == MAP_FAILED) {
		printf("Bail out! mmap: %s\n", strerror(errno));
		return 1;
	}
	printf("# %s\n", unit_suite.name);
	for (const struct unit_case *c = unit_suite.cases; c->name; c++) {
		if (only && !str_contains(c->name, only))
			continue;
		failed += run_case(c, ++nr);
	}
	printf("1..%zu\n", nr);
	return failed ? 1 : 0;
}
