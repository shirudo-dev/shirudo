// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Shared local security conditions block + status verdict.
 */

#include <stdio.h>
#include <string.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "conditions.h"

size_t conditions(const struct shirudo_conditions_input *in,
		  struct shirudo_condition *c, size_t cap)
{
	size_t n = 0;

	if (n < cap) {
		c[n].type = "LsmAttached";
		c[n].status = in->lsm_attached ? "OK" : "ALERT";
		strscpy(c[n].detail, in->lsm_attached ?
			"lsm/bpf link present and pinned" :
			"lsm/bpf absent -- enforcement OFF",
			sizeof(c[n].detail));
		n++;
	}
	if (n < cap) {
		c[n].type = "KeyringSealed";
		if (!in->keyring_present && in->ksp_seen) {
			c[n].status = "ALERT";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "pin serial=%lld, the BPF keyring is gone "
				 "(removed?)",
				 (__s64)in->keyring_serial_pinned);
		} else if (!in->keyring_present) {
			c[n].status = "WARN";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "shirudo keyring absent (not init'd?)");
		} else if (in->ksm_seen && !in->keyring_serial_matches) {
			c[n].status = "ALERT";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "pin serial=%lld != live serial=%lld (swapped?)",
				 (__s64)in->keyring_serial_pinned,
				 (__s64)in->keyring_serial);
		} else {
			c[n].status = "OK";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "serial=%lld in the BPF keyring, %s",
				 (__s64)in->keyring_serial,
				 in->ksp_seen ? "pin matches"
					      : "no pin recorded");
		}
		n++;
	}
	if (n < cap) {
		c[n].type = "ChainIntact";
		if (!in->chain_seen) {
			c[n].status = "WARN";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 in->tpm_reachable ?
				 "no register bound this boot (init incomplete)" :
				 "no TPM answered, no register to replay");
		} else if (in->cm_seen && in->chain_matches) {
			c[n].status = "OK";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "live register == eventlog replay");
		} else if (in->cm_seen) {
			c[n].status = "ALERT";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "live register != eventlog replay (tamper?)");
		} else {
			c[n].status = "WARN";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "chain present, replay not evaluated");
		}
		n++;
	}
	if (n < cap) {
		c[n].type = "TpmMeasured";
		c[n].status = in->chain_seen ? "OK" : "WARN";
		if (in->chain_seen)
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "NV index %s readable",
				 in->nv_index ? in->nv_index : "?");
		else if (in->tpm_reachable)
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "NV index %s not bound this boot",
				 in->nv_index ? in->nv_index : "?");
		else
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "no TPM answered");
		n++;
	}
	return n;
}

void conditions_print(const struct shirudo_condition *c, size_t n)
{
	size_t i;

	printf("Conditions:\n");
	printf("  %-16s %-7s %s\n", "TYPE", "STATUS", "DETAIL");
	for (i = 0; i < n; i++)
		printf("  %-16s %-7s %s\n", c[i].type, c[i].status,
		       c[i].detail);
}

const char *status_verdict(const struct shirudo_conditions_input *in)
{
	if (!in->reachable)
		return "unreachable";
	if (!in->parsed)
		return "unparseable";
	if ((in->cm_seen && !in->chain_matches) ||
	    (in->ksm_seen && !in->keyring_serial_matches) ||
	    (in->ksp_seen && !in->keyring_present))
		return "tampered";
	if (!in->lsm_attached)
		return "lsm-off";
	if (!in->keyring_present)
		return "init-pending";
	if (!in->chain_seen)
		return "degraded";
	return "ok";
}

void status_reason(const struct shirudo_conditions_input *in,
		   char *buf, size_t cap)
{
	const char *v = status_verdict(in);

	buf[0] = '\0';
	if (strcmp(v, "unreachable") == 0) {
		if (in->unreach)
			strscpy(buf, in->unreach, cap);
	} else if (strcmp(v, "unparseable") == 0) {
		snprintf(buf, cap, "status JSON unparseable");
	} else if (strcmp(v, "tampered") == 0) {
		if (in->cm_seen && !in->chain_matches)
			snprintf(buf, cap, "live register != eventlog replay");
		else if (!in->keyring_present)
			snprintf(buf, cap, "the keyring init froze is gone");
		else
			snprintf(buf, cap, "keyring serial swap detected");
	} else if (strcmp(v, "lsm-off") == 0) {
		snprintf(buf, cap, "LSM not attached -- enforcement OFF");
	} else if (strcmp(v, "init-pending") == 0) {
		snprintf(buf, cap, "target hasn't been `shirudo init`'d");
	} else if (strcmp(v, "degraded") == 0) {
		snprintf(buf, cap, in->tpm_reachable ?
			 "no register bound this boot" : "no TPM answered");
	}
}
