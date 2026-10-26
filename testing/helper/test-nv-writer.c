// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <linux/keyctl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include "identity.h"
#include "eventlog.h"
#include "nv_writer.h"
#include "paths.h"

int main(int argc, char **argv)
{
	__u8 data[SHIRUDO_TPM_NV_RSA_BYTES] = {};
	__u8 signature[SHIRUDO_TPM_NV_RSA_BYTES];
	struct keyctl_pkey_params params = {};
	struct bpf_obj_get_opts opts = {
		.sz = sizeof(opts),
		.file_flags = BPF_F_RDONLY,
	};
	struct shirudo_identity id = {};
	const char *operation;
	key_serial_t target;
	__u32 zero = 0;
	int fd, cmd;
	long ret;

	if (argc != 2)
		return 2;
	fd = bpf_obj_get_opts(SHIRUDO_IDENTITY_PIN, &opts);
	if (fd < 0) {
		perror("open read-only identity");
		return 2;
	}
	ret = bpf_map_lookup_elem(fd, &zero, &id);
	close(fd);
	if (ret || id.nv_writer_ring <= 0 ||
	    id.nv_writer_key <= 0) {
		fprintf(stderr, "cannot read NV writer identity\n");
		return 2;
	}
	if (!strcmp(argv[1], "public")) {
		struct shirudo_eventlog_init rec;

		if (eventlog_boot_init(&rec) ||
		    memcmp(id.nv_writer_public, rec.writer_public, sizeof(data))) {
			fprintf(stderr, "writer modulus differs between identity and init record\n");
			return 1;
		}
		return 0;
	}
	if (!strcmp(argv[1], "sign")) {
		params.key_id = id.nv_writer_key;
		params.in_len = 32;
		params.out_len = sizeof(signature);
		ret = syscall(__NR_keyctl, KEYCTL_PKEY_SIGN, &params,
			      "enc=pkcs1 hash=sha256", data, signature);
		if (ret == -1 && (errno == EACCES || errno == ENOKEY))
			return 0;
		fprintf(stderr, "writer signing was not denied: %ld/%d\n", ret, errno);
		return 1;
	}
	if (!strcmp(argv[1], "sign-shared")) {
		int rc;

		rc = nv_writer_sign_key(id.nv_writer_key, data, signature);
		if (rc == -EACCES || rc == -ENOKEY)
			return 0;
		fprintf(stderr, "shared writer signing was not denied: %d\n", rc);
		return 1;
	}
	operation = argv[1];
	target = id.nv_writer_key;
	if (!strncmp(operation, "ring-", 5)) {
		target = id.nv_writer_ring;
		operation += 5;
	}
	if (!strcmp(operation, "private-read"))
		cmd = KEYCTL_READ;
	else if (!strcmp(operation, "update"))
		cmd = KEYCTL_UPDATE;
	else if (!strcmp(operation, "clear"))
		cmd = KEYCTL_CLEAR;
	else if (!strcmp(operation, "revoke"))
		cmd = KEYCTL_REVOKE;
	else if (!strcmp(operation, "invalidate"))
		cmd = KEYCTL_INVALIDATE;
	else if (!strcmp(operation, "setperm"))
		cmd = KEYCTL_SETPERM;
	else
		return 2;
	errno = 0;
	ret = syscall(__NR_keyctl, cmd, target,
		      cmd == KEYCTL_SETPERM ? 0x00030000L : (long)data,
		      sizeof(data), 0);
	explicit_bzero(data, sizeof(data));
	if (ret == -1 && (errno == EACCES || errno == ENOKEY))
		return 0;
	fprintf(stderr, "writer operation %s was not refused: %ld/%d\n",
		argv[1], ret, errno);
	return 1;
}
