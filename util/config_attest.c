// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "chain.h"
#include "config_attest.h"
#include "config_measure.h"
#include "hex.h"
#include "json.h"
#include "macros.h"
#include "malloc.h"

static int append_event(struct shirudo_config_evidence *view,
			const struct shirudo_config_evidence_event *event)
{
	struct shirudo_config_evidence_event *events;
	size_t capacity;

	if (view->n_events >= SHIRUDO_CONFIG_EVIDENCE_EVENTS_MAX)
		return -E2BIG;
	if (view->n_events == view->capacity) {
		capacity = view->capacity ? view->capacity * 2 : 16;
		events = xreallocarray(view->events, view->capacity, capacity,
				       sizeof(*events));
		if (!events)
			return -ENOMEM;
		view->events = events;
		view->capacity = capacity;
	}
	view->events[view->n_events++] = *event;
	return 0;
}

static int replay(const struct shirudo_config_evidence *view, __u8 out[32])
{
	__u8 digest[32];
	__u64 sequence = 0;
	size_t i;
	int rc;

	if (!view->events || !view->n_events ||
	    view->n_events > SHIRUDO_CONFIG_EVIDENCE_EVENTS_MAX)
		return -EINVAL;
	memcpy(out, view->initial_pcr, 32);
	for (i = 0; i < view->n_events; i++) {
		const struct shirudo_config_evidence_event *event =
			&view->events[i];

		if (!event->sequence || event->sequence > INT64_MAX ||
		    (i && event->sequence != sequence + 1) ||
		    event->kind != (i ? SHIRUDO_CONFIG_EVENT_UPDATE :
					SHIRUDO_CONFIG_EVENT_BOOT))
			return -EKEYREJECTED;
		rc = shirudo_config_measure_event(event->kind, event->root_hash,
						  digest);
		if (!rc)
			rc = shirudo_chain_fold_checked(out, digest);
		if (rc)
			return rc;
		sequence = event->sequence;
	}
	return 0;
}

static int collect_event(const struct shirudo_config_update_record *record,
			 void *opaque)
{
	struct shirudo_config_evidence_event event = {};
	struct shirudo_config_evidence *view = opaque;

	if (record->reset_count != view->reset_count ||
	    record->restart_count != view->restart_count)
		return 0;
	if (record->pcr != view->pcr || record->sequence > INT64_MAX ||
	    memcmp(record->initial_pcr, view->initial_pcr, 32))
		return -EUCLEAN;
	memcpy(event.root_hash, record->target.root_hash, 32);
	event.sequence = record->sequence;
	event.kind = record->kind;
	return append_event(view, &event);
}

int shirudo_config_evidence_collect(struct shirudo_config_update *update,
				    struct shirudo_config_evidence *out)
{
	struct shirudo_config_update_record active;
	const struct shirudo_config_evidence_event *last;
	int rc;

	memset(out, 0, sizeof(*out));
	if (!update)
		return 0;
	rc = shirudo_config_update_check(update, &active);
	if (rc)
		return rc;
	out->pcr = active.pcr;
	out->reset_count = active.reset_count;
	out->restart_count = active.restart_count;
	memcpy(out->initial_pcr, active.initial_pcr, 32);
	rc = shirudo_config_update_events(update, collect_event, out);
	if (!rc)
		rc = replay(out, out->value);
	if (!rc) {
		last = &out->events[out->n_events - 1];
		if (last->sequence != active.sequence ||
		    memcmp(last->root_hash, active.target.root_hash, 32))
			rc = -EUCLEAN;
	}
	if (rc) {
		shirudo_config_evidence_clear(out);
		return rc;
	}
	out->present = true;
	return 0;
}

void shirudo_config_evidence_clear(struct shirudo_config_evidence *view)
{
	if (!view)
		return;
	xfree(view->events, view->capacity * sizeof(*view->events));
	memset(view, 0, sizeof(*view));
}

static void emit_hash(struct shirudo_json_emit *emit, const char *key,
		      const __u8 bytes[32])
{
	char hex[65];

	hex_encode(bytes, 32, hex);
	json_kv_string(emit, key, hex);
}

int shirudo_config_evidence_emit(struct shirudo_json_emit *emit,
				 const struct shirudo_config_evidence *view)
{
	size_t i;

	if (!view->present)
		return 0;
	json_obj_open_key(emit, "config");
	json_kv_int(emit, "schema", 1);
	json_kv_int(emit, "pcr", view->pcr);
	json_kv_int(emit, "reset_count", view->reset_count);
	json_kv_int(emit, "restart_count", view->restart_count);
	emit_hash(emit, "initial_pcr", view->initial_pcr);
	json_arr_open(emit, "events");
	for (i = 0; i < view->n_events; i++) {
		const struct shirudo_config_evidence_event *event =
			&view->events[i];

		if (event->sequence > INT64_MAX)
			return -EOVERFLOW;
		json_obj_open(emit);
		json_kv_int(emit, "sequence", event->sequence);
		json_kv_int(emit, "kind", event->kind);
		emit_hash(emit, "root_hash", event->root_hash);
		json_obj_close(emit);
	}
	json_arr_close(emit);
	json_obj_close(emit);
	return emit->err;
}

struct config_parser {
	struct shirudo_config_evidence *view;
	struct shirudo_json_field *event_fields;
	size_t n_fields;
	__s64 sequence, kind;
	char root_hash[65];
};

static int on_event(void *opaque)
{
	struct shirudo_config_evidence_event event = {};
	struct config_parser *parser = opaque;
	size_t i;

	for (i = 0; i < parser->n_fields; i++)
		if (!parser->event_fields[i].seen)
			return -EINVAL;
	if (parser->sequence <= 0 ||
	    (parser->kind != SHIRUDO_CONFIG_EVENT_BOOT &&
	     parser->kind != SHIRUDO_CONFIG_EVENT_UPDATE) ||
	    strlen(parser->root_hash) != 64 ||
	    hex_decode(parser->root_hash, event.root_hash, 32))
		return -EINVAL;
	event.sequence = parser->sequence;
	event.kind = parser->kind;
	return append_event(parser->view, &event);
}

int shirudo_config_evidence_parse(const char *evidence, size_t length,
				  struct shirudo_config_evidence *out)
{
	struct config_parser parser = { .view = out };
	struct shirudo_json_array sink = { on_event, &parser };
	__s64 schema = 0, reset = 0, restart = 0, pcr = 0;
	char initial[65] = {};
	size_t i;
	int rc;
	struct shirudo_json_field event_fields[] = {
		{ "sequence", SHIRUDO_JSON_T_INT, &parser.sequence, 0, 0, NULL,
		  0 },
		{ "kind", SHIRUDO_JSON_T_INT, &parser.kind, 0, 0, NULL, 0 },
		{ "root_hash", SHIRUDO_JSON_T_STRING, parser.root_hash,
		  sizeof(parser.root_hash), 0, NULL, 0 },
	};
	struct shirudo_json_field config_fields[] = {
		{ "schema", SHIRUDO_JSON_T_INT, &schema, 0, 0, NULL, 0 },
		{ "pcr", SHIRUDO_JSON_T_INT, &pcr, 0, 0, NULL, 0 },
		{ "reset_count", SHIRUDO_JSON_T_INT, &reset, 0, 0, NULL, 0 },
		{ "restart_count", SHIRUDO_JSON_T_INT, &restart, 0, 0, NULL,
		  0 },
		{ "initial_pcr", SHIRUDO_JSON_T_STRING, initial,
		  sizeof(initial), 0, NULL, 0 },
		{ "events", SHIRUDO_JSON_T_ARRAY, &sink, 0, 0, event_fields,
		  ARRAY_SIZE(event_fields) },
	};
	struct shirudo_json_field top[] = {
		{ "config", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, config_fields,
		  ARRAY_SIZE(config_fields) },
	};

	memset(out, 0, sizeof(*out));
	parser.event_fields = event_fields;
	parser.n_fields = ARRAY_SIZE(event_fields);
	rc = json_parse(evidence, length, top, ARRAY_SIZE(top));
	if (rc)
		goto fail;
	if (!top[0].seen)
		return 0;
	for (i = 0; i < ARRAY_SIZE(config_fields); i++)
		if (!config_fields[i].seen) {
			rc = -EINVAL;
			goto fail;
		}
	if (schema != 1 || reset < 0 || reset > UINT32_MAX || restart < 0 ||
	    restart > UINT32_MAX || pcr < 0 || pcr > 15 ||
	    shirudo_config_measure_pcr_valid(pcr) || strlen(initial) != 64 ||
	    hex_decode(initial, out->initial_pcr, 32)) {
		rc = -EINVAL;
		goto fail;
	}
	out->pcr = pcr;
	out->reset_count = reset;
	out->restart_count = restart;
	rc = replay(out, out->value);
	if (rc)
		goto fail;
	out->present = true;
	return 0;
fail:
	shirudo_config_evidence_clear(out);
	return rc;
}

int shirudo_config_evidence_verify(const struct shirudo_config_evidence *view,
				   __u32 quote_mask, __u32 reset,
				   __u32 restart, const __u8 pcrs[24][32],
				   const __u8 *expected_root,
				   int expected_pcr, const char **reason)
{
	__u8 value[32];
	int rc;

	*reason = "config root history matches the quoted PCR";
	if (!view->present) {
		*reason = "configuration evidence is missing";
		return expected_root || expected_pcr >= 0 ? -EKEYREJECTED : 0;
	}
	if (shirudo_config_measure_pcr_valid(view->pcr) ||
	    !(quote_mask & (1u << view->pcr)) ||
	    (expected_pcr >= 0 && view->pcr != (__u32)expected_pcr)) {
		*reason = "config PCR is unquoted or unexpected";
		return -EKEYREJECTED;
	}
	if (view->reset_count != reset || view->restart_count != restart) {
		*reason = "config history belongs to another TPM boot";
		return -EKEYREJECTED;
	}
	if (expected_root && expected_pcr < 0) {
		*reason = "expected config root needs an expected PCR";
		return -EKEYREJECTED;
	}
	rc = replay(view, value);
	if (rc || memcmp(value, pcrs[view->pcr], 32)) {
		*reason = "config history does not match the quoted PCR";
		return rc ? rc : -EKEYREJECTED;
	}
	if (expected_root && memcmp(view->events[view->n_events - 1].root_hash,
				    expected_root, 32)) {
		*reason = "config root was not approved by the operator";
		return -EKEYREJECTED;
	}
	return 0;
}
