/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_CONFIG_ATTEST_H
#define SHIRUDO_CONFIG_ATTEST_H

#include <shirudo/misc.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config_update.h"

#define CONFIG_EVIDENCE_EVENTS_MAX 4096u

struct json_emit;

struct config_evidence_event {
	__u8 root_hash[32];
	__u64 sequence;
	enum config_event_kind kind;
};

struct config_evidence {
	struct config_evidence_event *events;
	__u8 initial_pcr[32];
	__u8 value[32];
	size_t n_events;
	size_t capacity;
	__u32 reset_count;
	__u32 restart_count;
	__u32 pcr;
	bool present;
};

int config_evidence_collect(struct config_update *update,
			    struct config_evidence *out);
void config_evidence_clear(struct config_evidence *view);
int config_evidence_emit(struct json_emit *emit,
			 const struct config_evidence *view);
int config_evidence_parse(const char *evidence, size_t length,
			  struct config_evidence *out);
int config_evidence_verify(const struct config_evidence *view,
			   __u32 quote_mask, __u32 reset,
			   const __u8 pcrs[24][32],
			   const __u8 *nvpcr_value,
			   const __u8 *expected_root,
			   int expected_pcr, const char **reason);

#endif /* SHIRUDO_CONFIG_ATTEST_H */
