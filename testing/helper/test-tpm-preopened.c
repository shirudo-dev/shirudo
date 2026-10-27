// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "tpm_internal.h"
#include "chain.h"
#include "eventlog.h"
#include "paths.h"

static int tpm_failed(TSS2_RC rc, const char *operation)
{
	if (rc == TSS2_RC_SUCCESS)
		return 0;
	fprintf(stderr, "%s: rc=0x%08x\n", operation, (__u32)rc);
	return 1;
}

static int unauthorized_extend(struct shirudo_tpm *tpm)
{
	__u8 branch_written[32], branch_init[32], policy[32], values[64];
	TPM2B_MAX_NV_BUFFER event = { .size = 32 };
	TPML_DIGEST branches = { .count = 2 };
	struct shirudo_eventlog_init rec;
	ESYS_TR session = ESYS_TR_NONE;
	__u8 before[32], after[32];
	ESYS_TR nv = ESYS_TR_NONE;
	TSS2_RC trc;
	int saved_errno;
	int rc = 1;

	if (eventlog_boot_init(&rec)) {
		fputs("cannot read the boot binding\n", stderr);
		return 1;
	}
	memcpy(values, rec.pcr_before, 32);
	memcpy(values + 32, rec.phase_before, 32);
	if (tpm_register_policy(SHIRUDO_CHAIN_PCR_MASK, values, 2, rec.writer_public,
				branch_written, branch_init, policy)) {
		fputs("cannot reconstruct the policy branches\n", stderr);
		return 1;
	}
	chain_upatch_event("shirudo-upatch", "not-installed",
			   (__u8[32]) {}, event.buffer);
	if (tpm_nv_read(tpm, SHIRUDO_NV_INDEX, before) ||
	    tpm_failed(Esys_TR_FromTPMPublic(tpm->esys, SHIRUDO_NV_INDEX, ESYS_TR_NONE,
					     ESYS_TR_NONE, ESYS_TR_NONE, &nv),
		       "TR_FromTPMPublic") ||
	    tpm_policy_session_start(tpm, &session) ||
	    tpm_failed(Esys_PolicyNvWritten(tpm->esys, session, ESYS_TR_NONE,
					    ESYS_TR_NONE, ESYS_TR_NONE, TPM2_YES),
		       "PolicyNvWritten"))
		goto out;
	branches.digests[0].size = 32;
	memcpy(branches.digests[0].buffer, branch_written, 32);
	branches.digests[1].size = 32;
	memcpy(branches.digests[1].buffer, branch_init, 32);
	if (tpm_failed(Esys_PolicyOR(tpm->esys, session, ESYS_TR_NONE, ESYS_TR_NONE,
				     ESYS_TR_NONE, &branches), "PolicyOR"))
		goto out;
	errno = 0;
	trc = Esys_NV_Extend(tpm->esys, nv, nv, session, ESYS_TR_NONE,
			     ESYS_TR_NONE, &event);
	saved_errno = errno;
	if (trc != TSS2_TCTI_RC_IO_ERROR || saved_errno != EACCES) {
		fprintf(stderr, "unsigned NV_Extend: expected LSM denial, got 0x%08x/%d\n",
			(__u32)trc, saved_errno);
		goto out;
	}
	if (tpm_nv_read(tpm, SHIRUDO_NV_INDEX, after))
		goto out;
	if (memcmp(before, after, 32)) {
		fputs("unsigned NV_Extend changed the production register\n", stderr);
		goto out;
	}
	rc = 0;
out:
	if (session != ESYS_TR_NONE &&
	    tpm_failed(Esys_FlushContext(tpm->esys, session), "FlushContext"))
		rc = 1;
	if (nv != ESYS_TR_NONE && tpm_failed(Esys_TR_Close(tpm->esys, &nv), "TR_Close"))
		rc = 1;
	if (!rc)
		puts("inherited-TPM: unsigned NV_Extend rejected by LSM; value unchanged");
	return rc;
}

int main(void)
{
	struct shirudo_tpm *tpm = NULL;
	int status, rc = 1;
	pid_t pid;

	if (tpm_open(&tpm))
		return 2;
	pid = fork();
	if (pid < 0) {
		perror("fork");
		goto out;
	}
	if (!pid) {
		rc = unauthorized_extend(tpm);
		fflush(stdout);
		tpm_close(tpm);
		_exit(rc);
	}
	if (waitpid(pid, &status, 0) != pid)
		perror("waitpid");
	else if (WIFEXITED(status))
		rc = WEXITSTATUS(status);
	else
		fputs("unsigned NV writer terminated abnormally\n", stderr);
out:
	tpm_close(tpm);
	return rc;
}
