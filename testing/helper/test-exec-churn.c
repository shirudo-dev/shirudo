// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <shirudo/misc.h>

#include "io.h"

extern char **environ;

static __u64 monotonic_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (__u64)ts.tv_sec * 1000000000ULL +
		(__u64)ts.tv_nsec;
}

static int parse_positive(const char *text, __u64 *value)
{
	char *end;
	__u64 parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || end == text || *end != '\0' || parsed == 0)
		return -1;
	*value = parsed;
	return 0;
}

static int worker(__u64 deadline, int fd)
{
	char *const argv[] = { (char *)"/bin/true", NULL };
	__u64 completed = 0;

	for (;;) {
		pid_t child;
		int status;

		if (monotonic_ns() >= deadline)
			break;
		child = fork();
		if (child == 0) {
			execve(argv[0], argv, environ);
			_exit(127);
		}
		if (child < 0) {
			if (errno == EINTR)
				continue;
			return 1;
		}
		while (waitpid(child, &status, 0) < 0) {
			if (errno != EINTR)
				return 1;
		}
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
			completed++;
	}

	if (write_complete(fd, &completed, sizeof(completed)))
		return 1;
	return 0;
}

int main(int argc, char **argv)
{
	__u64 start, deadline, elapsed, completed = 0;
	__u64 duration_sec = 0, workers = 0;
	int exit_status = 0;
	int result_fd[2];
	pid_t *children;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--duration") && i + 1 < argc) {
			if (parse_positive(argv[++i], &duration_sec))
				return 2;
		} else if (!strcmp(argv[i], "--workers") && i + 1 < argc) {
			if (parse_positive(argv[++i], &workers))
				return 2;
		} else {
			fprintf(stderr, "usage: %s --duration SEC --workers COUNT\n",
				argv[0]);
			return 2;
		}
	}
	if (!duration_sec || !workers || workers > 1024)
		return 2;
	start = monotonic_ns();
	if (!start || duration_sec > UINT64_MAX / 1000000000ULL ||
	    start > UINT64_MAX - duration_sec * 1000000000ULL)
		return 1;
	deadline = start + duration_sec * 1000000000ULL;
	if (pipe(result_fd) != 0)
		return 1;
	children = calloc(workers, sizeof(*children));
	if (!children)
		return 1;

	for (__u64 i = 0; i < workers; i++) {
		children[i] = fork();
		if (children[i] == 0) {
			close(result_fd[0]);
			_exit(worker(deadline, result_fd[1]) ? 1 : 0);
		}
		if (children[i] < 0) {
			exit_status = 1;
			break;
		}
	}
	close(result_fd[1]);
	for (__u64 i = 0; i < workers; i++) {
		__u64 count;

		if (!children[i])
			continue;
		if (waitpid(children[i], NULL, 0) < 0)
			exit_status = 1;
		if (read(result_fd[0], &count, sizeof(count)) == sizeof(count))
			completed += count;
		else
			exit_status = 1;
	}
	close(result_fd[0]);
	free(children);
	if (exit_status)
		return 1;
	elapsed = monotonic_ns() - start;
	printf("execs=%llu elapsed_ns=%llu"
	       " execs_per_sec=%.3f workers=%llu\n", completed, elapsed,
	       elapsed ? (double)completed * 1e9 / (double)elapsed : 0.0,
	       workers);
	return 0;
}
