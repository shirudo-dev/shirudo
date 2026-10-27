// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include "tpm_internal.h"
#include "eventlog.h"
#include "identity.h"
#include "paths.h"

static int public_matches_init(void)
{
	struct bpf_obj_get_opts opts = {
		.sz = sizeof(opts),
		.file_flags = BPF_F_RDONLY,
	};
	struct shirudo_eventlog_init rec;
	struct shirudo_identity id = {};
	__u32 zero = 0;
	int fd, rc;

	fd = bpf_obj_get_opts(SHIRUDO_IDENTITY_PIN, &opts);
	if (fd < 0) {
		perror("open read-only identity");
		return 1;
	}
	rc = bpf_map_lookup_elem(fd, &zero, &id);
	close(fd);
	if (rc || eventlog_boot_init(&rec) ||
	    memcmp(id.nv_writer_public, rec.writer_public,
		   sizeof(id.nv_writer_public))) {
		fprintf(stderr, "writer modulus differs between identity and init record\n");
		return 1;
	}
	return 0;
}

static int sign_once(ESYS_CONTEXT *esys, ESYS_TR key)
{
	TPMT_TK_HASHCHECK validation = {
		.tag = TPM2_ST_HASHCHECK,
		.hierarchy = TPM2_RH_NULL,
	};
	TPMT_SIG_SCHEME scheme = { .scheme = TPM2_ALG_ECDSA };
	TPMT_SIGNATURE *signature = NULL;
	TPM2B_DIGEST digest = { .size = 32 };
	TSS2_RC rc;

	scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
	memset(digest.buffer, 0x5a, digest.size);
	rc = Esys_Sign(esys, key, ESYS_TR_PASSWORD, ESYS_TR_NONE,
		       ESYS_TR_NONE, &digest, &scheme, &validation, &signature);
	if (rc == TSS2_RC_SUCCESS && signature) {
		Esys_Free(signature);
		return 0;
	}
	Esys_Free(signature);
	fprintf(stderr, "unrelated TPM2_Sign failed: rc=0x%08x\n", (__u32)rc);
	return 1;
}

static int sign_check(const char *device, bool inherited)
{
	TPM2B_SENSITIVE_CREATE sensitive = {};
	TPML_PCR_SELECTION creation_pcr = {};
	TPM2B_PUBLIC in_public = {};
	TPM2B_PUBLIC *out_public = NULL;
	TSS2_TCTI_CONTEXT *tcti = NULL;
	TPM2B_DATA outside = {};
	ESYS_CONTEXT *esys = NULL;
	ESYS_TR key = ESYS_TR_NONE;
	TSS2_RC trc;
	int status, rc = 1;
	pid_t pid;

	trc = Tss2_TctiLdr_Initialize(device, &tcti);
	if (trc)
		goto tpm_error;
	trc = Esys_Initialize(&esys, tcti, NULL);
	if (trc)
		goto tpm_error;
	in_public.publicArea.type = TPM2_ALG_ECC;
	in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
	in_public.publicArea.objectAttributes =
		TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
		TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
		TPMA_OBJECT_SIGN_ENCRYPT;
	in_public.publicArea.parameters.eccDetail.symmetric.algorithm =
		TPM2_ALG_NULL;
	in_public.publicArea.parameters.eccDetail.scheme.scheme =
		TPM2_ALG_ECDSA;
	in_public.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg =
		TPM2_ALG_SHA256;
	in_public.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
	in_public.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
	trc = Esys_CreatePrimary(esys, ESYS_TR_RH_NULL, ESYS_TR_PASSWORD,
				 ESYS_TR_NONE, ESYS_TR_NONE, &sensitive,
				 &in_public, &outside, &creation_pcr, &key,
				 &out_public, NULL, NULL, NULL);
	if (trc)
		goto tpm_error;
	if (!inherited) {
		rc = sign_once(esys, key);
		goto out;
	}
	pid = fork();
	if (pid < 0) {
		perror("fork");
		goto out;
	}
	if (!pid) {
		rc = sign_once(esys, key);
		fflush(stderr);
		_exit(rc);
	}
	if (waitpid(pid, &status, 0) != pid) {
		perror("waitpid");
		goto out;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		goto out;
	rc = 0;
	goto out;
tpm_error:
	fprintf(stderr, "prepare TPM signing request on %s: rc=0x%08x\n",
		device, (__u32)trc);
out:
	Esys_Free(out_public);
	if (key != ESYS_TR_NONE)
		Esys_FlushContext(esys, key);
	Esys_Finalize(&esys);
	Tss2_TctiLdr_Finalize(&tcti);
	return rc;
}

enum extend_probe {
	EXTEND_TARGET,
	EXTEND_OTHER,
	EXTEND_SHORT,
};

static int write_extend(int fd, const char *device, enum extend_probe probe)
{
	__u8 command[18] = { 0x80, 0x01 };
	__u32 index = SHIRUDO_NV_INDEX;
	size_t size = sizeof(command);
	ssize_t written;
	int saved_errno;

	if (probe == EXTEND_OTHER)
		index++;
	if (probe == EXTEND_SHORT)
		size = 10;
	tpm_put32(command + 2, (__u32)size);
	tpm_put32(command + 6, SHIRUDO_TPM_CC_NV_EXTEND);
	tpm_put32(command + 10, index);
	tpm_put32(command + 14, index);
	errno = 0;
	written = write(fd, command, size);
	saved_errno = errno;
	if (probe == EXTEND_OTHER && written == (ssize_t)size)
		return 0;
	if (probe != EXTEND_OTHER && written == -1 &&
	    saved_errno == EACCES)
		return 0;
	fprintf(stderr, "%s NV_Extend 0x%08x: wrote %zd/%zu, errno=%d\n",
		device, index, written, size, saved_errno);
	return 1;
}

static int raw_extend_check(const char *device, enum extend_probe probe,
			    bool nonblock, bool inherited)
{
	int flags = O_RDWR | O_CLOEXEC;
	int status, rc;
	pid_t pid;
	int fd;

	if (strcmp(device, "/dev/tpmrm0") && strcmp(device, "/dev/tpm0"))
		return 2;
	if (nonblock)
		flags |= O_NONBLOCK;
	fd = open(device, flags);
	if (fd < 0) {
		perror(device);
		return 1;
	}
	if (!inherited) {
		rc = write_extend(fd, device, probe);
		close(fd);
		return rc;
	}
	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(fd);
		return 1;
	}
	if (!pid) {
		rc = write_extend(fd, device, probe);
		_exit(rc);
	}
	rc = waitpid(pid, &status, 0) == pid &&
	     WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
	close(fd);
	return rc;
}

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "public"))
		return public_matches_init();
	if (argc != 3)
		return 2;
	if (!strcmp(argv[1], "sign-allowed"))
		return sign_check(argv[2], false);
	if (!strcmp(argv[1], "sign-allowed-inherited"))
		return sign_check(argv[2], true);
	if (!strcmp(argv[1], "raw-extend"))
		return raw_extend_check(argv[2], EXTEND_TARGET, false, false);
	if (!strcmp(argv[1], "raw-extend-nonblock"))
		return raw_extend_check(argv[2], EXTEND_TARGET, true, false);
	if (!strcmp(argv[1], "raw-extend-inherited"))
		return raw_extend_check(argv[2], EXTEND_TARGET, false, true);
	if (!strcmp(argv[1], "raw-extend-other"))
		return raw_extend_check(argv[2], EXTEND_OTHER, true, false);
	if (!strcmp(argv[1], "raw-extend-short"))
		return raw_extend_check(argv[2], EXTEND_SHORT, false, false);
	return 2;
}
