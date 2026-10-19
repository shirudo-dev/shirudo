// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#ifndef SYS_clone3
#define SYS_clone3 435
#endif

#define CLONE_STACK_SIZE (1024 * 1024)

struct clone_context {
	const char *path;
};

static void exec_payload(const char *path)
{
	char *const argv[] = { (char *)path, (char *)"--payload", NULL };

	execve(path, argv, environ);
	_exit(127);
}

static int wait_child(pid_t pid)
{
	int status;

	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR)
			return -1;
	}
	return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int fork_exec(const char *path)
{
	pid_t pid = fork();

	if (pid == 0)
		exec_payload(path);
	if (pid < 0)
		return -1;
	return wait_child(pid);
}

static int vfork_exec(const char *path)
{
	pid_t pid = vfork();

	if (pid == 0)
		exec_payload(path);
	if (pid < 0)
		return -1;
	return wait_child(pid);
}

static int clone_child(void *data)
{
	struct clone_context *context = data;

	exec_payload(context->path);
	return 127;
}

static int clone_exec(const char *path)
{
	struct clone_context context = { .path = path };
	void *stack = mmap(NULL, CLONE_STACK_SIZE, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	pid_t pid;
	int result;

	if (stack == MAP_FAILED)
		return -1;
	pid = clone(clone_child, (char *)stack + CLONE_STACK_SIZE, SIGCHLD,
		    &context);
	if (pid < 0) {
		munmap(stack, CLONE_STACK_SIZE);
		return -1;
	}
	result = wait_child(pid);
	munmap(stack, CLONE_STACK_SIZE);
	return result;
}

static int clone3_exec(const char *path)
{
	struct clone_args args = {};
	pid_t pid;

	args.exit_signal = SIGCHLD;
	pid = syscall(SYS_clone3, &args, sizeof(args));
	if (pid == 0)
		exec_payload(path);
	if (pid < 0)
		return -1;
	return wait_child(pid);
}

static void exec_fd(const char *path, int use_fexecve)
{
	char *const args[] = { (char *)path, NULL };
	int fd = open(path, O_RDONLY);

	if (fd < 0)
		_exit(126);
	if (use_fexecve)
		fexecve(fd, args, environ);
	else
		syscall(SYS_execveat, fd, "", args, environ, AT_EMPTY_PATH);
	_exit(127);
}

static int fd_exec_path(const char *path, int use_fexecve)
{
	pid_t pid = fork();

	if (pid == 0)
		exec_fd(path, use_fexecve);
	if (pid < 0)
		return -1;
	return wait_child(pid);
}

static void exec_dirfd(const char *directory, const char *path)
{
	char *const args[] = { (char *)path, NULL };
	int dirfd = open(directory, O_RDONLY | O_DIRECTORY);

	if (dirfd < 0)
		_exit(126);
	syscall(SYS_execveat, dirfd, path, args, environ, 0);
	_exit(127);
}

static int dirfd_exec_path(const char *directory, const char *path)
{
	pid_t pid = fork();

	if (pid == 0)
		exec_dirfd(directory, path);
	if (pid < 0)
		return -1;
	return wait_child(pid);
}

static void exec_drop_euid(const char *path)
{
	if (setresuid(65534, 0, 65534))
		_exit(125);
	exec_payload(path);
}

static int drop_euid_exec_path(const char *path)
{
	pid_t pid = fork();

	if (pid == 0)
		exec_drop_euid(path);
	if (pid < 0)
		return -1;
	return wait_child(pid);
}

static int make_script(const char *directory, const char *name, char *path,
		       size_t path_size)
{
	static const char script[] = "#!/bin/sh\nexit 0\n";
	ssize_t written;
	int length;
	int fd;

	length = snprintf(path, path_size, "%s/%s", directory, name);
	if (length < 0 || (size_t)length >= path_size)
		return -1;
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
	if (fd < 0)
		return -1;
	written = write(fd, script, sizeof(script) - 1);
	if (close(fd) < 0 || written != sizeof(script) - 1)
		return -1;
	return 0;
}

static void *thread_exec(void *data)
{
	exec_payload(data);
	return NULL;
}

static int thread_exec_path(const char *path)
{
	pthread_t thread;
	int result;

	result = pthread_create(&thread, NULL, thread_exec, (void *)path);
	if (result)
		return -1;
	result = pthread_join(thread, NULL);
	return result ? -1 : 0;
}

int main(int argc, char **argv)
{
	char script_fd[4096];
	char script[4096];
	const char *self = argv[0];

	if (argc == 2 && !strcmp(argv[1], "--payload"))
		return 0;
	if (argc == 3 && !strcmp(argv[1], "--replace"))
		exec_payload(argv[2]);
	if (argc == 3 && !strcmp(argv[1], "--execveat-empty"))
		return fd_exec_path(argv[2], 0) ? 1 : 0;
	if (argc == 3 && !strcmp(argv[1], "--fexecve"))
		return fd_exec_path(argv[2], 1) ? 1 : 0;
	if (argc == 4 && !strcmp(argv[1], "--execveat-dirfd"))
		return dirfd_exec_path(argv[2], argv[3]) ? 1 : 0;
	if (argc == 3 && !strcmp(argv[1], "--drop-euid"))
		return drop_euid_exec_path(argv[2]) ? 1 : 0;
	if (argc != 2 || make_script(argv[1], "exec-script", script,
				     sizeof(script)) ||
	    make_script(argv[1], "exec-script-fd", script_fd,
			sizeof(script_fd))) {
		fprintf(stderr, "could not create shebang test executable\n");
		return 1;
	}
	if (fork_exec(self)) {
		fprintf(stderr, "fork() -> execve() case failed\n");
		return 1;
	}
	if (vfork_exec(self)) {
		fprintf(stderr, "vfork() -> execve() case failed\n");
		return 1;
	}
	if (clone_exec(self)) {
		fprintf(stderr, "clone() -> execve() case failed\n");
		return 1;
	}
	if (clone3_exec(self)) {
		fprintf(stderr, "clone3() -> execve() case failed\n");
		return 1;
	}
	if (fork_exec(script)) {
		fprintf(stderr, "fork() -> shebang execve() case failed\n");
		return 1;
	}
	if (fd_exec_path(script_fd, 1)) {
		fprintf(stderr, "fexecve() -> shebang case failed\n");
		return 1;
	}
	if (thread_exec_path(self)) {
		fprintf(stderr, "non-leader thread execve() case failed\n");
		return 1;
	}
	return 0;
}
