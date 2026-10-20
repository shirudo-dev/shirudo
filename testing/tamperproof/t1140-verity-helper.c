// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include "../../include/shirudo/misc.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../util/identity.h"

static __u64 probe_word = 0x5348495255444fUL;

static int check_mark(const char *pin, int expected)
{
	struct shirudo_task_authority authority = {};
	union bpf_attr attr = {};
	int fd, pidfd, rc;

	pidfd = syscall(SYS_pidfd_open, getpid(), 0);
	if (pidfd < 0)
		return 1;
	attr.pathname = (uintptr_t)pin;
	attr.file_flags = BPF_F_RDONLY;
	fd = syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
	if (fd < 0) {
		close(pidfd);
		return 1;
	}
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = (uintptr_t)&pidfd;
	attr.value = (uintptr_t)&authority;
	rc = syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
	if (rc && errno != ENOENT)
		rc = 1;
	else
		rc = !!authority.trusted != expected;
	close(pidfd);
	close(fd);
	return rc;
}

static int check_mappings(const char *trusted, const char *outside)
{
	long length = sysconf(_SC_PAGESIZE);
	void *mapping;
	int fd;

	errno = 0;
	mapping = mmap(NULL, length, PROT_READ | PROT_EXEC,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mapping != MAP_FAILED || errno != EACCES)
		return 1;
	mapping = mmap(NULL, length, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mapping == MAP_FAILED)
		return 1;
	errno = 0;
	if (!mprotect(mapping, length, PROT_READ | PROT_EXEC) ||
	    errno != EACCES)
		return 1;
	munmap(mapping, length);
	fd = open(outside, O_RDONLY);
	if (fd < 0)
		return 1;
	errno = 0;
	mapping = mmap(NULL, length, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
	close(fd);
	if (mapping != MAP_FAILED || errno != EACCES)
		return 1;
	fd = open(trusted, O_RDONLY);
	if (fd < 0)
		return 1;
	mapping = mmap(NULL, length, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
	if (mapping == MAP_FAILED) {
		close(fd);
		return 1;
	}
	errno = 0;
	if (!mprotect(mapping, length, PROT_READ | PROT_WRITE) ||
	    errno != EACCES)
		return 1;
	munmap(mapping, length);
	mapping = mmap(NULL, length, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE, fd, 0);
	close(fd);
	if (mapping == MAP_FAILED)
		return 1;
	if (mprotect(mapping, length, PROT_READ))
		return 1;
	errno = 0;
	if (!mprotect(mapping, length, PROT_READ | PROT_EXEC) ||
	    errno != EACCES)
		return 1;
	munmap(mapping, length);
	return 0;
}

int main(int argc, char **argv)
{
	char *failed[2] = {};
	pid_t child;
	int status;

	if (argc < 3)
		return 2;
	if (!strcmp(argv[1], "unlink"))
		return unlink(argv[2]) ? 1 : 0;
	if (!strcmp(argv[1], "mkdir"))
		return mkdir(argv[2], 0700) ? 1 : 0;
	if (!strcmp(argv[1], "rmdir"))
		return rmdir(argv[2]) ? 1 : 0;
	if (!strcmp(argv[1], "create")) {
		int fd = open(argv[2], O_WRONLY | O_CREAT | O_EXCL, 0600);

		return fd < 0 ? 1 : !!close(fd);
	}
	if (!strcmp(argv[1], "wait")) {
		FILE *ready = fopen(argv[2], "w");

		if (!ready)
			return 1;
		if (fprintf(ready, "%ld %llx\n", (long)getpid(),
			    (__u64)(uintptr_t)&probe_word) < 0 ||
		    fclose(ready))
			return 1;
		for (;;)
			pause();
	}
	if (!strcmp(argv[1], "mark") && argc == 4)
		return check_mark(argv[2], atoi(argv[3]));
	if (!strcmp(argv[1], "failed-exec")) {
		failed[0] = (char *)"missing";
		execv(argc == 4 ? argv[3] :
		      "/no-such-shirudo-test-executable", failed);
		if (errno != (argc == 4 ? ENOEXEC : ENOENT))
			return 1;
		return check_mark(argv[2], 1);
	}
	if (!strcmp(argv[1], "fork")) {
		child = fork();
		if (child < 0)
			return 1;
		if (!child)
			_exit(check_mark(argv[2], 1));
		if (waitpid(child, &status, 0) != child)
			return 1;
		return !WIFEXITED(status) || WEXITSTATUS(status);
	}
	if (!strcmp(argv[1], "exec") && argc == 5) {
		char *next[5] = {};

		next[0] = argv[3];
		next[1] = (char *)"mark";
		next[2] = argv[2];
		next[3] = argv[4];
		execv(argv[3], next);
		return 1;
	}
	if (!strcmp(argv[1], "mappings") && argc == 4)
		return check_mappings(argv[2], argv[3]);
	return 2;
}
