// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <libgen.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define EXEC_2 "/tmp/shirudo-policy-exec-graph/exec-2"
#define EXEC_4 "/tmp/shirudo-policy-exec-graph/exec-4"
#define EXEC_1 "/tmp/shirudo-policy-exec-graph/exec-1"
#define EXEC_UNLABELED "/tmp/shirudo-policy-exec-graph/unlabeled"
#define SOCKET_A "/tmp/shirudo-policy-exec-graph/socket-a"
#define SOCKET_B "/tmp/shirudo-policy-exec-graph/socket-b"

static int exec_child(const char *path, const char *name,
		      const char *mode, const char *arg)
{
	char *const argv[] = {(char *)name, (char *)mode, (char *)arg, NULL};
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return -1;
	if (!pid) {
		execve(path, argv, environ);
		_exit(errno == EACCES ? 100 : 101);
	}
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return -1;
	return WEXITSTATUS(status);
}

static int listen_loopback(int *port)
{
	struct sockaddr_in address = {};
	socklen_t address_len = sizeof(address);
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) ||
	    listen(fd, 1) ||
	    getsockname(fd, (struct sockaddr *)&address, &address_len)) {
		close(fd);
		return -1;
	}
	*port = ntohs(address.sin_port);
	return fd;
}

static int socket_connect(const char *name, const char *port_string)
{
	struct sockaddr_in address = {};
	int fd, port, rc;

	port = atoi(port_string);
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return 101;
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = htons(port);
	rc = connect(fd, (struct sockaddr *)&address, sizeof(address));
	if (!rc) {
		close(fd);
		return !strcmp(name, "socket-a") ? 28 : 29;
	}
	rc = errno;
	close(fd);
	return !strcmp(name, "socket-b") && rc == EACCES ? 100 : 101;
}

static void report(int *failed, int number, int passed, const char *title)
{
	if (passed) {
		printf("ok %d - %s\n", number, title);
	} else {
		printf("not ok %d - %s\n", number, title);
		*failed = 1;
	}
}

int main(int argc, char **argv)
{
	const char *name = basename(argv[0]);
	char port_string[8];
	struct sockaddr_in peer = {};
	socklen_t peer_len = sizeof(peer);
	int listener, accepted, port, port_len, socket_a, socket_b;
	int socket_b_probe;
	int failed = 0;

	if (argc > 1 && !strcmp(argv[1], "target")) {
		if (!strcmp(name, "exec-1"))
			return 11;
		if (!strcmp(name, "exec-2"))
			return 22;
		if (!strcmp(name, "exec-4"))
			return 44;
		if (!strcmp(name, "unlabeled"))
			return 45;
		return 46;
	}
	if (argc > 2 && !strcmp(argv[1], "connect"))
		return socket_connect(name, argv[2]);
	if (!strcmp(name, "unlabeled") && argc > 1 &&
	    !strcmp(argv[1], "verify")) {
		if (exec_child(EXEC_UNLABELED, "unlabeled", "target", NULL) != 45 ||
		    exec_child(EXEC_1, "exec-1", "target", NULL) != 11)
			return 1;
		return 0;
	}
	if (!strcmp(name, "socket-b") && argc > 1 &&
	    !strcmp(argv[1], "probe"))
		return exec_child(EXEC_UNLABELED, "unlabeled", "target", NULL) == 100 ?
			0 : 1;
	if (strcmp(name, "exec-1") || argc < 2 || strcmp(argv[1], "run"))
		return 47;
	report(&failed, 1, argc > 2 && !strcmp(argv[2], "ok"),
	       "unlabeled execs to unlabeled and policy 0x1 are allowed");
	report(&failed, 2,
	       exec_child(EXEC_2, "exec-2", "target", NULL) == 22,
	       "policy 0x1 allows exec to policy 0x2");
	report(&failed, 3,
	       exec_child(EXEC_4, "exec-4", "target", NULL) == 100,
	       "policy 0x1 denies exec to policy 0x4");
	report(&failed, 4,
	       exec_child(EXEC_UNLABELED, "unlabeled", "target", NULL) == 100,
	       "policy 0x1 denies unlabeled exec");
	listener = listen_loopback(&port);
	port_len = listener < 0 ? -1 :
		snprintf(port_string, sizeof(port_string), "%d", port);
	if (listener < 0 || port_len < 0 ||
	    (size_t)port_len >= sizeof(port_string)) {
		report(&failed, 5, 0,
		       "policy A connects to 127.0.0.1 using socket policy bits");
		report(&failed, 6, 0,
		       "policy B denies exec to an unlabeled file");
		report(&failed, 7, 0,
		       "policy B is denied 127.0.0.1 by socket policy bits");
	} else {
		socket_a = exec_child(SOCKET_A, "socket-a", "connect",
				      port_string);
		accepted = socket_a == 28 ?
			accept(listener, (struct sockaddr *)&peer, &peer_len) : -1;
		if (accepted >= 0)
			close(accepted);
		report(&failed, 5, socket_a == 28 && accepted >= 0,
		       "policy A connects to 127.0.0.1 using socket policy bits");
		socket_b_probe = exec_child(SOCKET_B, "socket-b", "probe", NULL);
		report(&failed, 6, socket_b_probe == 0,
		       "policy B denies exec to an unlabeled file");
		socket_b = exec_child(SOCKET_B, "socket-b", "connect",
				      port_string);
		report(&failed, 7, socket_b == 100,
		       "policy B is denied 127.0.0.1 by socket policy bits");
	}
	if (listener >= 0)
		close(listener);
	puts("1..7");
	return failed;
}
