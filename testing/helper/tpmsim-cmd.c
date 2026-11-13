// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * libtpms-backed TPM 2.0 for the tss2 "cmd" TCTI: commands on stdin,
 * responses on stdout, state kept under the directory in argv[1].
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_library.h>

#include <shirudo/misc.h>

#define SIM_CMD_MAX	(64u * 1024u)

/*
 * tss2's "cmd" TCTI reaps this process with SIGTERM before it closes
 * stdin, so a plain blocking read() never sees the EOF that would
 * otherwise drive save_state() below. Route the signal through a
 * self-pipe and treat it exactly like EOF instead of dying with
 * whatever TPM state is still unsaved.
 */
static int shutdown_pipe[2] = { -1, -1 };

static void request_shutdown(int sig)
{
	char byte = 0;

	if (write(shutdown_pipe[1], &byte, 1) < 0)
		return;
}

static int install_shutdown_handler(void)
{
	struct sigaction sa = { .sa_handler = request_shutdown };

	if (pipe(shutdown_pipe) != 0)
		return -1;
	if (fcntl(shutdown_pipe[1], F_SETFL, O_NONBLOCK) != 0)
		return -1;
	return sigaction(SIGTERM, &sa, NULL);
}

/* 1: a command is ready on stdin, 0: shutdown requested, -1: error. */
static int wait_for_command(void)
{
	struct pollfd pfd[2] = {
		{ .fd = STDIN_FILENO, .events = POLLIN },
		{ .fd = shutdown_pipe[0], .events = POLLIN },
	};
	int ret;

	do {
		ret = poll(pfd, ARRAY_SIZE(pfd), -1);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0)
		return -1;
	return (pfd[1].revents & POLLIN) ? 0 : 1;
}

/* TPM2_Startup(TPM_SU_CLEAR): sent when no volatile state was restored. */
static const __u8 startup_clear[] = {
	0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
};

static int read_full(int fd, void *buf, size_t n)
{
	size_t off = 0;
	__u8 *p = buf;

	while (off < n) {
		ssize_t got = read(fd, p + off, n - off);

		if (got < 0 && errno == EINTR)
			continue;
		if (got <= 0)
			return -1;
		off += (size_t)got;
	}
	return 0;
}

static int write_full(int fd, const void *buf, size_t n)
{
	const __u8 *p = buf;
	size_t off = 0;

	while (off < n) {
		ssize_t put = write(fd, p + off, n - off);

		if (put < 0 && errno == EINTR)
			continue;
		if (put <= 0)
			return -1;
		off += (size_t)put;
	}
	return 0;
}

static int load_blob(const char *path, __u8 **out, __u32 *len)
{
	struct stat st;
	__u8 *buf;
	int fd;

	*out = NULL;
	*len = 0;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (fstat(fd, &st) != 0 || st.st_size <= 0 ||
	    st.st_size > 16 * 1024 * 1024) {
		close(fd);
		return -1;
	}
	buf = malloc((size_t)st.st_size);
	if (!buf || read_full(fd, buf, (size_t)st.st_size) != 0) {
		free(buf);
		close(fd);
		return -1;
	}
	close(fd);
	*out = buf;
	*len = (__u32)st.st_size;
	return 0;
}

static int store_blob(const char *path, const __u8 *buf,
		      __u32 len)
{
	char tmp[4096 + 8];
	int fd, ret;

	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;
	ret = write_full(fd, buf, len);
	if (close(fd) != 0)
		ret = -1;
	if (ret == 0)
		ret = rename(tmp, path);
	return ret;
}

static int process(__u8 **resp, __u32 *resp_size,
		   __u32 *resp_cap, const __u8 *cmd, __u32 len)
{
	TPM_RESULT r = TPMLIB_Process(resp, resp_size, resp_cap,
				      (__u8 *)cmd, len);

	return r == TPM_SUCCESS ? 0 : -1;
}

static int save_state(const char *dir)
{
	static const struct {
		enum TPMLIB_StateType	type;
		const char		*name;
	} blobs[] = {
		{ TPMLIB_STATE_PERMANENT, "permanent" },
		{ TPMLIB_STATE_VOLATILE,  "volatile" },
	};
	char path[4096];
	size_t i;
	int ret = 0;

	for (i = 0; i < ARRAY_SIZE(blobs); i++) {
		__u32 blob_len = 0;
		__u8 *blob = NULL;

		if (TPMLIB_GetState(blobs[i].type, &blob, &blob_len) !=
		    TPM_SUCCESS || !blob) {
			ret = -1;
			continue;
		}
		snprintf(path, sizeof(path), "%s/%s", dir, blobs[i].name);
		if (store_blob(path, blob, blob_len) != 0)
			ret = -1;
		free(blob);
	}
	return ret;
}

int main(int argc, char **argv)
{
	__u8 *resp = NULL, *permanent = NULL, *vol = NULL;
	__u32 resp_size = 0, resp_cap = 0, permanent_len, vol_len;
	char path[4096];
	int ret = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: tpmsim-cmd <state-dir>\n");
		return 2;
	}
	if ((mkdir(argv[1], 0700) != 0 && errno != EEXIST) ||
	    chdir(argv[1]) != 0) {
		perror("tpmsim-cmd: state directory");
		return 1;
	}
	if (install_shutdown_handler() != 0) {
		perror("tpmsim-cmd: shutdown handler");
		return 1;
	}
	setenv("TPM_PATH", ".", 1);
	if (TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2) != TPM_SUCCESS) {
		fprintf(stderr, "tpmsim-cmd: TPM 2.0 unsupported by libtpms\n");
		return 1;
	}
	snprintf(path, sizeof(path), "permanent");
	if (load_blob(path, &permanent, &permanent_len) == 0 &&
	    TPMLIB_SetState(TPMLIB_STATE_PERMANENT, permanent,
			    permanent_len) != TPM_SUCCESS) {
		fprintf(stderr, "tpmsim-cmd: permanent state rejected\n");
		return 1;
	}
	snprintf(path, sizeof(path), "volatile");
	if (permanent && load_blob(path, &vol, &vol_len) == 0 &&
	    TPMLIB_SetState(TPMLIB_STATE_VOLATILE, vol, vol_len) !=
	    TPM_SUCCESS) {
		fprintf(stderr, "tpmsim-cmd: volatile state rejected\n");
		return 1;
	}
	if (TPMLIB_MainInit() != TPM_SUCCESS) {
		fprintf(stderr, "tpmsim-cmd: TPMLIB_MainInit failed\n");
		return 1;
	}
	/* No volatile state means a power cycle: PCRs and STCLEAR reset. */
	if (!vol && process(&resp, &resp_size, &resp_cap, startup_clear,
			    sizeof(startup_clear)) != 0) {
		fprintf(stderr, "tpmsim-cmd: TPM2_Startup failed\n");
		return 1;
	}

	for (;;) {
		__u8 cmd[SIM_CMD_MAX];
		__u32 len;
		int avail;

		avail = wait_for_command();
		if (avail <= 0) {
			ret = avail < 0;
			break;
		}
		if (read_full(STDIN_FILENO, cmd, 10) != 0)
			break;
		len = ((__u32)cmd[2] << 24) | ((__u32)cmd[3] << 16) |
		      ((__u32)cmd[4] << 8) | cmd[5];
		if (len < 10 || len > sizeof(cmd) ||
		    (len > 10 && read_full(STDIN_FILENO, cmd + 10,
					   len - 10) != 0)) {
			ret = 1;
			break;
		}
		if (process(&resp, &resp_size, &resp_cap, cmd, len) != 0 ||
		    write_full(STDOUT_FILENO, resp, resp_size) != 0) {
			ret = 1;
			break;
		}
	}
	if (save_state(".") != 0) {
		fprintf(stderr, "tpmsim-cmd: saving TPM state failed\n");
		ret = 1;
	}
	TPMLIB_Terminate();
	free(resp);
	free(permanent);
	free(vol);
	return ret;
}
