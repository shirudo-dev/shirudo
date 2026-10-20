/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_CONFIG_ATTEST_H
#define SHIRUDO_CONFIG_ATTEST_H

#include <shirudo/misc.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config_update.h"

#define SHIRUDO_CONFIG_EVIDENCE_EVENTS_MAX 4096u

struct shirudo_json_emit;

struct shirudo_config_evidence_event {
	__u8 root_hash[32];
	__u64 sequence;
	enum shirudo_config_event_kind kind;
};

struct shirudo_config_evidence {
	struct shirudo_config_evidence_event *events;
	__u8 initial_pcr[32];
	__u8 value[32];
	size_t n_events;
	size_t capacity;
	__u32 reset_count;
	__u32 restart_count;
	__u32 pcr;
	bool present;
};

int shirudo_config_evidence_collect(struct shirudo_config_update *update,
				    struct shirudo_config_evidence *out);
void shirudo_config_evidence_clear(struct shirudo_config_evidence *view);
int shirudo_config_evidence_emit(struct shirudo_json_emit *emit,
				 const struct shirudo_config_evidence *view);
int shirudo_config_evidence_parse(const char *evidence, size_t length,
				  struct shirudo_config_evidence *out);
int shirudo_config_evidence_verify(const struct shirudo_config_evidence *view,
				   __u32 quote_mask, __u32 reset,
				   __u32 restart, const __u8 pcrs[24][32],
				   const __u8 *expected_root,
				   int expected_pcr, const char **reason);

#endif /* SHIRUDO_CONFIG_ATTEST_H */
