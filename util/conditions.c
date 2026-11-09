// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Shared local security conditions block + status verdict.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "conditions.h"

static bool config_untrusted(const struct conditions_input *in)
{
	return in->config_seen && in->config_state &&
	       in->config_state != -EINPROGRESS;
}

static const char *config_untrusted_detail(int state)
{
	if (state == -ESTALE)
		return "the config activation record does not belong to this TPM boot";
	if (state == -EKEYREJECTED)
		return "the mounted config does not match the selected root";
	return "the config PCR, activation records and mounted config disagree";
}

static bool keyring_tampered(const struct conditions_input *in)
{
	return (in->ksp_seen && !in->keyring_present) ||
	       (in->ksm_seen && !in->keyring_serial_matches) ||
	       (in->dmvp_seen && !in->dmv_present) ||
	       (in->dmvm_seen && !in->dmv_serial_matches) ||
	       in->bpf_unfrozen || in->dmv_unfrozen || in->dmv_key_missing;
}

static void __printf(3, 4)
set_detail(struct condition *c, const char *status,
	   const char *fmt, ...)
{
	va_list ap;

	c->status = status;
	va_start(ap, fmt);
	if (vstrsprintf(c->detail, sizeof(c->detail), fmt, ap) < 0)
		strscpy(c->detail, "?", sizeof(c->detail));
	va_end(ap);
}

static void keyring_condition(const struct conditions_input *in,
			      struct condition *c)
{
	c->type = "KeyringSealed";
	if (!in->keyring_present && in->ksp_seen)
		set_detail(c, "ALERT",
			   "pinned serial %lld, the .bpf keyring is gone",
			   (__s64)in->keyring_serial_pinned);
	else if (!in->keyring_present)
		set_detail(c, "WARN", ".bpf keyring absent before init");
	else if (in->ksm_seen && !in->keyring_serial_matches)
		set_detail(c, "ALERT",
			   "pinned serial %lld, live serial %lld: swapped",
			   (__s64)in->keyring_serial_pinned,
			   (__s64)in->keyring_serial);
	else if (in->bpf_unfrozen)
		set_detail(c, "ALERT",
			   "the BPF keyring holds %d link%s init did not freeze",
			   in->bpf_unfrozen, in->bpf_unfrozen == 1 ? "" : "s");
	else if (in->dmvp_seen && !in->dmv_present)
		set_detail(c, "ALERT",
			   "dm-verity pinned serial %lld, the dm-verity keyring is gone",
			   (__s64)in->dmv_serial_pinned);
	else if (in->dmvm_seen && !in->dmv_serial_matches)
		set_detail(c, "ALERT",
			   "dm-verity pinned serial %lld, live serial %lld: swapped",
			   (__s64)in->dmv_serial_pinned,
			   (__s64)in->dmv_serial);
	else if (in->dmv_unfrozen)
		set_detail(c, "ALERT",
			   "the dm-verity keyring holds %d link%s init did not freeze",
			   in->dmv_unfrozen, in->dmv_unfrozen == 1 ? "" : "s");
	else if (in->dmv_key_missing)
		set_detail(c, "ALERT",
			   "a config key init froze is gone from the dm-verity keyring");
	else if (in->ksp_seen && in->dmvp_seen)
		set_detail(c, "OK",
			   "bpf serial %lld, dm-verity serial %lld, pins match",
			   (__s64)in->keyring_serial, (__s64)in->dmv_serial);
	else
		set_detail(c, "OK", "bpf serial %lld, %s",
			   (__s64)in->keyring_serial,
			   in->ksp_seen ? "pin matches" : "no pin recorded");
}

size_t conditions(const struct conditions_input *in,
		  struct condition *c, size_t cap)
{
	size_t n = 0;

	if (n < cap) {
		c[n].type = "LsmAttached";
		c[n].status = in->lsm_attached ? "OK" : "ALERT";
		strscpy(c[n].detail, in->lsm_attached ?
			"lsm/bpf link present and pinned" :
			"lsm/bpf link absent, enforcement off",
			sizeof(c[n].detail));
		n++;
	}
	if (n < cap)
		keyring_condition(in, &c[n++]);
	if (n < cap) {
		c[n].type = "ChainIntact";
		if (!in->chain_seen) {
			c[n].status = "WARN";
			strscpy(c[n].detail, in->tpm_reachable ?
				"no register bound this boot (init incomplete)" :
				"no TPM answered, no register to replay",
				sizeof(c[n].detail));
		} else if (in->cm_seen && in->chain_matches) {
			c[n].status = "OK";
			strscpy(c[n].detail, "live register equals the eventlog replay",
				sizeof(c[n].detail));
		} else if (in->cm_seen) {
			c[n].status = "ALERT";
			strscpy(c[n].detail,
				"live register differs from the eventlog replay",
				sizeof(c[n].detail));
		} else {
			c[n].status = "WARN";
			strscpy(c[n].detail,
				"chain present, replay not evaluated",
				sizeof(c[n].detail));
		}
		n++;
	}
	if (n < cap) {
		c[n].type = "UpatchesMeasured";
		if (in->pins_rc == -ENOENT)
			set_detail(&c[n], "WARN",
				   "no record of this boot to check the pins against");
		else if (in->pins_rc)
			set_detail(&c[n], "WARN",
				   "pins not checked against the records: %s",
				   strerror(-in->pins_rc));
		else if (in->pins_unmeasured)
			set_detail(&c[n], "ALERT",
				   "%d pinned or archived without a record of this boot: %s",
				   in->pins_unmeasured,
				   in->pins_detail ? in->pins_detail : "?");
		else
			set_detail(&c[n], "OK",
				   "every pinned or archived upatch is in this boot's records");
		n++;
	}
	if (n < cap) {
		c[n].type = "TpmMeasured";
		c[n].status = in->chain_seen ? "OK" : "WARN";
		if (in->chain_seen) {
			if (strsprintf(c[n].detail, sizeof(c[n].detail),
				       "NV index %s readable",
				       in->nv_index ? in->nv_index : "?") < 0)
				strscpy(c[n].detail, "?", sizeof(c[n].detail));
		} else if (in->tpm_reachable) {
			if (strsprintf(c[n].detail, sizeof(c[n].detail),
				       "NV index %s not bound this boot",
				       in->nv_index ? in->nv_index : "?") < 0)
				strscpy(c[n].detail, "?", sizeof(c[n].detail));
		} else {
			strscpy(c[n].detail, "no TPM answered",
				sizeof(c[n].detail));
		}
		n++;
	}
	if (n < cap) {
		const char *root = in->config_root ? in->config_root : "?";

		c[n].type = "ConfigActive";
		c[n].status = "OK";
		if (!in->config_seen) {
			c[n].status = "WARN";
			strscpy(c[n].detail, "no config activation state before init",
				sizeof(c[n].detail));
		} else if (in->config_state == -EINPROGRESS) {
			c[n].status = "WARN";
			if (strsprintf(c[n].detail, sizeof(c[n].detail),
				       "the activation of config %.12s.. is pending until the next reboot",
				       root) < 0)
				strscpy(c[n].detail, "?", sizeof(c[n].detail));
		} else if (config_untrusted(in)) {
			c[n].status = "ALERT";
			strscpy(c[n].detail, config_untrusted_detail(in->config_state),
				sizeof(c[n].detail));
		} else if (strsprintf(c[n].detail, sizeof(c[n].detail),
				      "config %.12s.. is active", root) < 0) {
			strscpy(c[n].detail, "?", sizeof(c[n].detail));
		}
		n++;
	}
	return n;
}

void conditions_print(const struct condition *c, size_t n)
{
	size_t i;

	printf("Conditions:\n");
	printf("  %-18s %-7s %s\n", "TYPE", "STATUS", "DETAIL");
	for (i = 0; i < n; i++)
		printf("  %-18s %-7s %s\n", c[i].type, c[i].status,
		       c[i].detail);
}

const char *status_verdict(const struct conditions_input *in)
{
	if (!in->reachable)
		return "unreachable";
	if (!in->parsed)
		return "unparseable";
	if ((in->cm_seen && !in->chain_matches) || in->pins_unmeasured ||
	    keyring_tampered(in) || config_untrusted(in))
		return "tampered";
	if (!in->lsm_attached)
		return "lsm-off";
	if (!in->keyring_present)
		return "init-pending";
	if (in->config_seen && in->config_state == -EINPROGRESS)
		return "reboot-pending";
	if (!in->chain_seen)
		return "degraded";
	return "ok";
}

void status_reason(const struct conditions_input *in,
		   char *buf, size_t cap)
{
	const char *v = status_verdict(in);

	buf[0] = '\0';
	if (strcmp(v, "unreachable") == 0) {
		if (in->unreach)
			strscpy(buf, in->unreach, cap);
	} else if (strcmp(v, "unparseable") == 0) {
		strscpy(buf, "status JSON unparseable", cap);
	} else if (strcmp(v, "tampered") == 0) {
		if (in->cm_seen && !in->chain_matches)
			strscpy(buf, "live register differs from the eventlog replay", cap);
		else if (in->pins_unmeasured)
			strscpy(buf, "a upatch is pinned or archived without a record of this boot",
				cap);
		else if (config_untrusted(in))
			strscpy(buf, "the selected config cannot be verified against its records",
				cap);
		else if (in->ksp_seen && !in->keyring_present)
			strscpy(buf, "the keyring init froze is gone", cap);
		else if (in->ksm_seen && !in->keyring_serial_matches)
			strscpy(buf, "keyring serial swap detected", cap);
		else if (in->dmvp_seen && !in->dmv_present)
			strscpy(buf, "the dm-verity keyring init froze is gone",
				cap);
		else if (in->dmvm_seen && !in->dmv_serial_matches)
			strscpy(buf, "dm-verity keyring serial swap detected",
				cap);
		else if (in->bpf_unfrozen || in->dmv_unfrozen)
			strscpy(buf, "a keyring holds a link init did not freeze",
				cap);
		else
			strscpy(buf, "the config key init froze is gone", cap);
	} else if (strcmp(v, "lsm-off") == 0) {
		strscpy(buf, "LSM not attached, enforcement off", cap);
	} else if (strcmp(v, "init-pending") == 0) {
		strscpy(buf, ".bpf keyring absent before init", cap);
	} else if (strcmp(v, "reboot-pending") == 0) {
		strscpy(buf, "a config activation is pending until the next reboot",
			cap);
	} else if (strcmp(v, "degraded") == 0) {
		strscpy(buf, in->tpm_reachable ?
			"no register bound this boot" : "no TPM answered", cap);
	}
}
