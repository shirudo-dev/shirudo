// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <sys/auxv.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "../../include/shirudo/misc.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../util/identity.h"

static __u64 probe_word = 0x5348495255444fUL;

static int check_mark(const char *pin, int expected)
{
	struct task_authority authority = {};
	union bpf_attr attr = {};
	int fd, pidfd, ret;

	pidfd = syscall(SYS_pidfd_open, getpid(), 0);
	if (pidfd < 0)
		return 1;
	attr.pathname = (uintptr_t)pin;
	attr.file_flags = BPF_F_RDONLY;
	fd = syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
	if (fd < 0) {
		/* Only a task with authority may open the pin at all. */
		ret = errno == EACCES && !expected ? 0 : 1;
		close(pidfd);
		return ret;
	}
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = (uintptr_t)&pidfd;
	attr.value = (uintptr_t)&authority;
	ret = syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
	if (ret && errno != ENOENT)
		ret = 1;
	else
		ret = !!authority.trusted != expected;
	close(pidfd);
	close(fd);
	return ret;
}

static int read_policy(const char *pin, __u64 *active)
{
	struct shirudo_task_policy policy = {};
	union bpf_attr attr = {};
	int fd, pidfd, rc;

	pidfd = syscall(SYS_pidfd_open, getpid(), 0);
	if (pidfd < 0)
		return -errno;
	attr.pathname = (uintptr_t)pin;
	attr.file_flags = BPF_F_RDONLY;
	fd = syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
	if (fd < 0) {
		rc = -errno;
		close(pidfd);
		return rc;
	}
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = (uintptr_t)&pidfd;
	attr.value = (uintptr_t)&policy;
	rc = syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) ?
		-errno : 0;
	close(fd);
	close(pidfd);
	if (!rc)
		*active = policy.active;
	return rc;
}

static int read_socket_policy(int socket_fd, __u64 *active)
{
	union bpf_attr attr = {};
	__u64 value = 0;
	int fd, rc;

	attr.pathname = (uintptr_t)"/run/shirudo/bpffs/socket_policy_map";
	attr.file_flags = BPF_F_RDONLY;
	fd = syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
	if (fd < 0)
		return -errno;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = (uintptr_t)&socket_fd;
	attr.value = (uintptr_t)&value;
	rc = syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
	if (rc && errno != ENOENT)
		rc = -errno;
	else
		rc = 0;
	close(fd);
	if (!rc)
		*active = value;
	return rc;
}

static int check_socket_policy(int socket_fd, __u64 expected)
{
	__u64 actual = 0;

	return read_socket_policy(socket_fd, &actual) || actual != expected;
}

static int parse_policy(const char *text, __u64 *value);

static int accept_child(void)
{
	__u64 active = 0;
	__u64 task_bits, socket_bits;
	const char *listener_text = getenv("SHIRUDO_TEST_LISTENER");
	const char *task_text = getenv("SHIRUDO_TEST_TASK_BITS");
	const char *socket_text = getenv("SHIRUDO_TEST_SOCKET_BITS");
	char *end;
	long listener;
	int accepted;

	if (!listener_text || !task_text || !socket_text ||
	    parse_policy(task_text, &task_bits) ||
	    parse_policy(socket_text, &socket_bits))
		return 1;
	listener = strtol(listener_text, &end, 10);
	if (*end || listener < 0 ||
	    read_policy("/run/shirudo/bpffs/policy_map", &active) ||
	    active != task_bits)
		return 1;
	accepted = accept((int)listener, NULL, NULL);
	if (accepted < 0)
		return 1;
	return check_socket_policy(accepted, socket_bits);
}

static int socket_inheritance(const char *script, __u64 extra)
{
	struct sockaddr_in addr = {};
	static const char contents[] =
		"#!/run/shirudo/runtime/usr/bin/shirudo-policy-probe accept-child\n";
	char acceptor[PATH_MAX], number[32];
	__u64 active = 0;
	int listener, client, status, rc, length;
	pid_t child;

	if (read_policy("/run/shirudo/bpffs/policy_map", &active) || !active)
		return 1;
	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0 || check_socket_policy(listener, active))
		return 1;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) ||
	    listen(listener, 1))
		return 1;
	rc = getsockname(listener, (struct sockaddr *)&addr,
			 (socklen_t[]){ sizeof(addr) });
	if (rc)
		return 1;
	length = snprintf(acceptor, sizeof(acceptor), "%s.acceptor", script);
	if (length < 0 || (size_t)length >= sizeof(acceptor))
		return 1;
	{
		int fd = open(acceptor, O_WRONLY | O_CREAT | O_TRUNC, 0700);

		if (fd < 0)
			return 1;
		if (write(fd, contents, sizeof(contents) - 1) !=
		    (ssize_t)(sizeof(contents) - 1)) {
			close(fd);
			return 1;
		}
		close(fd);
	}
	{
		__u64 value = extra;

		if (setxattr(acceptor, "security.bpf.shirudo.policy", &value,
			     sizeof(value), 0))
			return 1;
	}
	length = snprintf(number, sizeof(number), "%d", listener);
	if (length < 0 || (size_t)length >= sizeof(number) ||
	    setenv("SHIRUDO_TEST_LISTENER", number, 1))
		return 1;
	length = snprintf(number, sizeof(number), "0x%llx", active | extra);
	if (length < 0 || (size_t)length >= sizeof(number) ||
	    setenv("SHIRUDO_TEST_TASK_BITS", number, 1))
		return 1;
	length = snprintf(number, sizeof(number), "0x%llx", active);
	if (length < 0 || (size_t)length >= sizeof(number) ||
	    setenv("SHIRUDO_TEST_SOCKET_BITS", number, 1))
		return 1;
	child = fork();
	if (child < 0)
		return 1;
	if (!child) {
		char *const args[] = { acceptor, NULL };

		execv(acceptor, args);
		_exit(127);
	}
	client = socket(AF_INET, SOCK_STREAM, 0);
	if (client < 0 || connect(client, (struct sockaddr *)&addr, sizeof(addr)))
		return 1;
	close(client);
	if (waitpid(child, &status, 0) != child)
		return 1;
	close(listener);
	unlink(acceptor);
	return !WIFEXITED(status) || WEXITSTATUS(status);
}

static int parse_policy(const char *text, __u64 *value)
{
	char *end;
	__u64 parsed;

	errno = 0;
	parsed = strtoull(text, &end, 0);
	if (errno || end == text || *end)
		return -EINVAL;
	*value = (__u64)parsed;
	return 0;
}

static int set_policy(const char *path, const char *text)
{
	__u64 value;

	if (parse_policy(text, &value))
		return 2;
	return setxattr(path, "security.bpf.shirudo.policy", &value,
			sizeof(value), 0) ? 1 : 0;
}

static int remove_policy(const char *path)
{
	__u64 value;
	ssize_t n;

	if (removexattr(path, "security.bpf.shirudo.policy"))
		return 1;
	n = getxattr(path, "security.bpf.shirudo.policy", &value,
		     sizeof(value));
	return n < 0 && errno == ENODATA ? 0 : 1;
}

static int check_policy(const char *text)
{
	__u64 expected, active = 0;

	if (parse_policy(text, &expected) ||
	    read_policy("/run/shirudo/bpffs/policy_map", &active))
		return 1;
	return active != expected;
}

static int check_policy_env(void)
{
	const char *expected = getenv("SHIRUDO_EXPECTED_POLICY");

	return !expected || check_policy(expected);
}

static int fork_exec_policy_env(void)
{
	const char *path = getenv("SHIRUDO_POLICY_CHILD");
	const char *parent = getenv("SHIRUDO_POLICY_PARENT");
	const char *expected = getenv("SHIRUDO_POLICY_CHILD_EXPECTED");
	char *const child_argv[] = { (char *)path, NULL };
	pid_t child;
	int status;

	if (!path || !parent || !expected || check_policy(parent))
		return 1;
	child = fork();
	if (child < 0)
		return 1;
	if (!child) {
		if (setenv("SHIRUDO_EXPECTED_POLICY", expected, 1))
			_exit(127);
		execv(path, child_argv);
		_exit(127);
	}
	if (waitpid(child, &status, 0) != child)
		return 1;
	return !WIFEXITED(status) || WEXITSTATUS(status);
}

static void print_hex(const __u8 *bytes, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		printf("%02x", bytes[i]);
	printf("\n");
}

static int print_identity(const char *pin, const char *field)
{
	struct identity id = {};
	union bpf_attr attr = {};
	__u32 zero = 0;
	int fd, ret;

	attr.pathname = (uintptr_t)pin;
	attr.file_flags = BPF_F_RDONLY;
	fd = syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
	if (fd < 0)
		return 1;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = (uintptr_t)&zero;
	attr.value = (uintptr_t)&id;
	ret = syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
	close(fd);
	if (ret)
		return 1;
	if (!strcmp(field, "runtime_root"))
		print_hex(id.runtime_root, sizeof(id.runtime_root));
	else if (!strcmp(field, "nv_writer_public"))
		print_hex(id.nv_writer_public, sizeof(id.nv_writer_public));
	else if (!strcmp(field, "nv_index"))
		printf("%u\n", id.nv_index);
	else
		return 2;
	return 0;
}

static int check_mappings(const char *trusted, const char *outside)
{
	long length = sysconf(_SC_PAGESIZE);
	void *mapping;
	int fd, err;

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
	err = errno;
	close(fd);
	if (mapping != MAP_FAILED || err != EACCES)
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
	    errno != EACCES) {
		close(fd);
		return 1;
	}
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

	/* As a script's interpreter the script's path follows the mode. */
	if (argc >= 2 && !strcmp(argv[1], "secure")) {
		printf("%lu\n", getauxval(AT_SECURE));
		return 0;
	}
	if (argc == 4 && !strcmp(argv[1], "set-policy"))
		return set_policy(argv[2], argv[3]);
	if (argc == 3 && !strcmp(argv[1], "remove-policy"))
		return remove_policy(argv[2]);
	if (argc >= 2 && !strcmp(argv[1], "check-policy"))
		return check_policy_env();
	if (argc >= 2 && !strcmp(argv[1], "fork-exec-policy"))
		return fork_exec_policy_env();
	if (argc >= 3 && !strcmp(argv[1], "socket-inherit")) {
		__u64 extra;

		extra = 2;
		return socket_inheritance(argv[2], extra);
	}
	if (argc >= 2 && !strcmp(argv[1], "accept-child"))
		return accept_child();
	if (argc < 3)
		return 2;
	if (!strcmp(argv[1], "unlink"))
		return unlink(argv[2]) ? 1 : 0;
	if (!strcmp(argv[1], "mkdir"))
		return mkdir(argv[2], 0700) ? 1 : 0;
	if (!strcmp(argv[1], "rmdir"))
		return rmdir(argv[2]) ? 1 : 0;
	if (!strcmp(argv[1], "symlink") && argc == 4)
		return symlink(argv[2], argv[3]) ? 1 : 0;
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
	if (!strcmp(argv[1], "identity") && argc == 4)
		return print_identity(argv[2], argv[3]);
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
