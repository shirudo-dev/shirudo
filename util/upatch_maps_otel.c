// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * OTLP/HTTP JSON export of map snapshots: a signal chosen from the
 * map's BTF or named by the caller, or a snapshot in S3 behind a log
 * reference.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/btf.h>

#include <bpf/btf.h>
#include <curl/curl.h>
#include <zlib.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>
#include <shirudo/upatch.h>

#include "config.h"
#include "crypto.h"
#include "curl.h"
#include "hex.h"
#include "json.h"
#include "log.h"
#include "malloc.h"
#include "paths.h"
#include "tenant_id.h"
#include "upatch_decode.h"
#include "upatch_maps_otel.h"
#include "version.h"

#define OTEL_ENDPOINT_MAX	2048
#define OTEL_RESPONSE_MAX	(64U * 1024U)
#define OTEL_DEFAULT_TIMEOUT_MS	10000L
#define OTEL_MAX_TIMEOUT_MS	120000L
#define OTEL_MAX_HEADER_BYTES	16384U
#define OTEL_MAX_TYPE_UNWRAP	32

#define S3_BUCKET_MAX		63
#define S3_PREFIX_MAX		512
#define S3_REGION_MAX		64
#define S3_URL_MAX		4096
#define S3_KEY_MAX		1024
#define S3_DECODER_JSON_MAX_BYTES	(64U * 1024U * 1024U)
#define S3_JSON_BUFFER_SIZE	(64U * 1024U)
#define S3_GZIP_BUFFER_SIZE	(64U * 1024U)
#define S3_REFERENCE_MAX	(64U * 1024U)

struct otel_response {
	char		buf[OTEL_RESPONSE_MAX];
	size_t		len;
	__u64		retry_after;
	bool		retry_after_valid;
};

struct otel_state {
	enum otel_signal signal;
	struct otel_opts opts;
	const char *decoder_path;
	char endpoint[OTEL_ENDPOINT_MAX];
	char host[256];
	const char *ca_file;
	const char *client_cert;
	const char *client_key;
	long timeout_ms;
	bool gzip;
	bool insecure_tls;
	bool s3_reference;
	struct curl_slist *headers;
};

struct s3_snapshot {
	FILE		*file;
	__u64		json_bytes;
	__u64		object_bytes;
	__u8		sha256[32];
	char		sha256_hex[65];
	char		sha256_b64[45];
};

struct otel_s3_state {
	struct otel_state *otel;
	struct otel_opts opts;
	char	bucket[S3_BUCKET_MAX + 1];
	char	prefix[S3_PREFIX_MAX + 1];
	char	region[S3_REGION_MAX];
	char	endpoint[OTEL_ENDPOINT_MAX];
	char	host[256];
	char	*credentials;
	size_t	credentials_len;
	const char *session_token;
	const char *ca_file;
	bool	custom_endpoint;
	bool	insecure_tls;
};

struct metric_type {
	bool is_signed;
	__u32 width;
};

static const struct btf_type *unwrap_btf_type(const struct btf *btf,
					      __u32 id)
{
	const struct btf_type *t;
	int i;

	for (i = 0; i < OTEL_MAX_TYPE_UNWRAP; i++) {
		t = btf__type_by_id(btf, id);
		if (!t)
			return NULL;
		if (!btf_is_typedef(t) && !btf_is_mod(t))
			return t;
		id = t->type;
	}
	return NULL;
}

static int metric_type_from_view(const struct map_view *v,
				 struct metric_type *out)
{
	const struct btf_type *t;

	if (!v || !v->btf || !v->value_type_id)
		return -ENODATA;
	t = unwrap_btf_type(v->btf, v->value_type_id);
	if (!t || !btf_is_int(t) || t->size != v->value_size ||
	    btf_int_offset(t) != 0 || btf_int_bits(t) != t->size * 8 ||
	    (t->size != 1 && t->size != 2 && t->size != 4 && t->size != 8))
		return -EOPNOTSUPP;
	out->is_signed = (btf_int_encoding(t) & BTF_INT_SIGNED) != 0;
	out->width = t->size;
	return 0;
}

int upatch_maps_otel_classify(const struct map_view *v,
			      enum otel_signal *signal,
			      char *reason, size_t reason_sz)
{
	struct metric_type mt;
	int ret;

	if (!v || !signal)
		return -EINVAL;
	*signal = OTEL_LOG;
	if (v->serialized) {
		strscpy(reason, "map uses a serializer", reason_sz);
		return 0;
	}
	if (v->skipped) {
		strscpy(reason, "map type is not generically readable",
			reason_sz);
		return 0;
	}
	if (!upatch_map_is_percpu(v->type)) {
		strscpy(reason, "map is not per-CPU", reason_sz);
		return 0;
	}
	ret = metric_type_from_view(v, &mt);
	if (ret) {
		strscpy(reason, "value is not a BTF integer scalar", reason_sz);
		return 0;
	}
	if (mt.is_signed) {
		strscpy(reason, "value is signed", reason_sz);
		return 0;
	}
	*signal = OTEL_METRIC;
	if (strsprintf(reason, reason_sz, "unsigned per-CPU %u-bit scalar",
		       mt.width * 8) < 0)
		return -E2BIG;
	return 0;
}

static void otlp_kv_string(struct json_emit *e, const char *key,
			   const char *value)
{
	json_obj_open(e);
	json_kv_string(e, "key", key);
	json_obj_open_key(e, "value");
	json_kv_string(e, "stringValue", value ? value : "");
	json_obj_close(e);
	json_obj_close(e);
}

static void otlp_kv_int(struct json_emit *e, const char *key,
			__s64 value)
{
	char num[32];

	if (strsprintf(num, sizeof(num), "%lld", value) < 0) {
		e->err = -E2BIG;
		return;
	}
	json_obj_open(e);
	json_kv_string(e, "key", key);
	json_obj_open_key(e, "value");
	json_kv_string(e, "intValue", num);
	json_obj_close(e);
	json_obj_close(e);
}

static void otlp_kv_bool(struct json_emit *e, const char *key,
			 bool value)
{
	json_obj_open(e);
	json_kv_string(e, "key", key);
	json_obj_open_key(e, "value");
	json_kv_bool(e, "boolValue", value);
	json_obj_close(e);
	json_obj_close(e);
}

static void otlp_kvlist_begin(struct json_emit *e, const char *key)
{
	json_obj_open(e);
	json_kv_string(e, "key", key);
	json_obj_open_key(e, "value");
	json_obj_open_key(e, "kvlistValue");
	json_arr_open(e, "values");
}

static void otlp_kvlist_end(struct json_emit *e)
{
	json_arr_close(e);
	json_obj_close(e);
	json_obj_close(e);
	json_obj_close(e);
}

static void otlp_array_begin(struct json_emit *e, const char *key)
{
	json_obj_open(e);
	json_kv_string(e, "key", key);
	json_obj_open_key(e, "value");
	json_obj_open_key(e, "arrayValue");
	json_arr_open(e, "values");
}

static void otlp_array_end(struct json_emit *e)
{
	json_arr_close(e);
	json_obj_close(e);
	json_obj_close(e);
	json_obj_close(e);
}

static void otlp_array_string(struct json_emit *e, const char *value)
{
	json_obj_open(e);
	json_kv_string(e, "stringValue", value ? value : "");
	json_obj_close(e);
}

static void otlp_array_kvlist_begin(struct json_emit *e)
{
	json_obj_open(e);
	json_obj_open_key(e, "kvlistValue");
	json_arr_open(e, "values");
}

static void otlp_array_kvlist_end(struct json_emit *e)
{
	json_arr_close(e);
	json_obj_close(e);
	json_obj_close(e);
}

struct anyvalue_walk {
	struct json_emit	*e;
	__u32			depth;
	bool			wrap;
	/* Whether the container at each depth is an array. */
	bool			array[JSON_MAX_DEPTH + 1];
};

/*
 * A value in an array is an AnyValue object of its own; one in an object
 * goes into the {"key","value"} the key opened; one at the top is the
 * caller's AnyValue, or with wrap an object of its own.
 */
static void anyvalue_begin(struct anyvalue_walk *w)
{
	if (w->depth ? w->array[w->depth] : w->wrap)
		json_obj_open(w->e);
}

static void anyvalue_end(struct anyvalue_walk *w)
{
	if (!w->depth) {
		if (w->wrap)
			json_obj_close(w->e);
	} else if (w->array[w->depth]) {
		json_obj_close(w->e);
	} else {
		json_obj_close(w->e);
		json_obj_close(w->e);
	}
}

static int anyvalue_open(void *ctx, bool array)
{
	struct anyvalue_walk *w = ctx;

	if (!w->depth && !w->wrap && array)
		return -EINVAL;
	anyvalue_begin(w);
	json_obj_open_key(w->e, array ? "arrayValue" : "kvlistValue");
	json_arr_open(w->e, "values");
	w->array[++w->depth] = array;
	return w->e->err;
}

static int anyvalue_close(void *ctx, bool array)
{
	struct anyvalue_walk *w = ctx;

	json_arr_close(w->e);
	json_obj_close(w->e);
	w->depth--;
	anyvalue_end(w);
	return w->e->err;
}

static int anyvalue_key(void *ctx, const char *key)
{
	struct anyvalue_walk *w = ctx;

	json_obj_open(w->e);
	json_kv_string(w->e, "key", key);
	json_obj_open_key(w->e, "value");
	return w->e->err;
}

static int anyvalue_scalar(struct anyvalue_walk *w)
{
	return !w->depth && !w->wrap ? -EINVAL : 0;
}

static int anyvalue_string(void *ctx, const char *s)
{
	struct anyvalue_walk *w = ctx;
	int ret = anyvalue_scalar(w);

	if (ret)
		return ret;
	anyvalue_begin(w);
	json_kv_string(w->e, "stringValue", s);
	anyvalue_end(w);
	return w->e->err;
}

/*
 * An AnyValue's intValue is a 64-bit integer: a longer one, or one with a
 * fraction or an exponent, goes as a doubleValue as it is written.
 */
static int anyvalue_number(void *ctx, const char *text, size_t len,
			   bool integer)
{
	struct anyvalue_walk *w = ctx;
	int ret = anyvalue_scalar(w);
	__s64 value;

	if (ret)
		return ret;
	anyvalue_begin(w);
	if (integer && !parse_s64(text, len, INT64_MIN, INT64_MAX, &value)) {
		char num[24];

		if (strsprintf(num, sizeof(num), "%lld", value) < 0)
			return -E2BIG;
		json_kv_string(w->e, "intValue", num);
	} else {
		json_kv_raw(w->e, "doubleValue", text, len);
	}
	anyvalue_end(w);
	return w->e->err;
}

static int anyvalue_literal(void *ctx, int value)
{
	struct anyvalue_walk *w = ctx;
	int ret = anyvalue_scalar(w);

	if (ret)
		return ret;
	anyvalue_begin(w);
	/* An empty AnyValue is the OTLP JSON representation of null. */
	if (value >= 0)
		json_kv_bool(w->e, "boolValue", value);
	anyvalue_end(w);
	return w->e->err;
}

static const struct json_visitor anyvalue_visitor = {
	.open = anyvalue_open,
	.close = anyvalue_close,
	.key = anyvalue_key,
	.string = anyvalue_string,
	.number = anyvalue_number,
	.literal = anyvalue_literal,
};

/*
 * One ordinary JSON value as the OTLP JSON representation of an
 * AnyValue: with wrap any value as an AnyValue object of its own,
 * without it an object as the kvlistValue of the AnyValue the caller has
 * open. Status already has a stable JSON emitter, so that status and its
 * machine-readable output share one source of truth.
 */
static int json_anyvalue_from_document(struct json_emit *e,
				       const char *json, size_t len, bool wrap)
{
	struct anyvalue_walk w = { .e = e, .wrap = wrap };

	return json_walk(json, len, &anyvalue_visitor, &w);
}

static void emit_resource_attributes(struct json_emit *e)
{
	char hostname[256] = "unknown";

	if (gethostname(hostname, sizeof(hostname)) != 0)
		strscpy(hostname, "unknown", sizeof(hostname));
	hostname[sizeof(hostname) - 1] = '\0';
	json_arr_open(e, "attributes");
	otlp_kv_string(e, "service.name", "shirudo");
	otlp_kv_string(e, "service.version", shirudo_version);
	otlp_kv_string(e, "host.name", hostname);
	json_arr_close(e);
}

static __u64 realtime_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		return 0;
	return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static int u64_decimal(__u64 value, char out[32])
{
	return strsprintf(out, 32, "%llu", value);
}

/* An OTLP document down to its scope; otlp_close() ends it. */
static void otlp_open(struct json_emit *e, const char *resource_key,
		      const char *scope_key, const char *scope_name)
{
	json_obj_open(e);
	json_arr_open(e, resource_key);
	json_obj_open(e);
	json_obj_open_key(e, "resource");
	emit_resource_attributes(e);
	json_obj_close(e);
	json_arr_open(e, scope_key);
	json_obj_open(e);
	json_obj_open_key(e, "scope");
	json_kv_string(e, "name", scope_name);
	json_kv_string(e, "version", shirudo_version);
	json_obj_close(e);
}

static void otlp_close(struct json_emit *e)
{
	json_obj_close(e);
	json_arr_close(e);
	json_obj_close(e);
	json_arr_close(e);
	json_obj_close(e);
}

/* A logs document with its one record open; log_close() ends both. */
static void log_open(struct json_emit *e, const char *scope_name,
		     int severity_number, const char *severity_text,
		     const char *event_name)
{
	char now[32];

	u64_decimal(realtime_ns(), now);
	otlp_open(e, "resourceLogs", "scopeLogs", scope_name);
	json_arr_open(e, "logRecords");
	json_obj_open(e);
	json_kv_string(e, "timeUnixNano", now);
	json_kv_string(e, "observedTimeUnixNano", now);
	json_kv_int(e, "severityNumber", severity_number);
	json_kv_string(e, "severityText", severity_text);
	json_kv_string(e, "eventName", event_name);
}

static void log_close(struct json_emit *e)
{
	json_obj_close(e);
	json_arr_close(e);
	otlp_close(e);
}

static void emit_map_attributes(struct json_emit *e,
				const struct map_view *v)
{
	otlp_kv_string(e, "shirudo.upatch.name", v->upatch);
	otlp_kv_string(e, "shirudo.upatch.location", v->location);
	otlp_kv_string(e, "shirudo.map.name", v->name);
	otlp_kv_string(e, "shirudo.map.type", v->type_name);
	otlp_kv_int(e, "shirudo.map.max_entries", v->max_entries);
	otlp_kv_int(e, "shirudo.map.n_entries", v->n_entries);
	otlp_kv_int(e, "shirudo.map.n_cpus", v->n_cpus);
	otlp_kv_bool(e, "shirudo.map.serialized", v->serialized);
	otlp_kv_bool(e, "shirudo.map.truncated", v->truncated);
}

static void emit_log_map_data(struct json_emit *e,
			      const struct map_view *v)
{
	__u32 i, j;

	otlp_kv_string(e, "name", v->name);
	otlp_kv_string(e, "type", v->type_name);
	otlp_kv_int(e, "max_entries", v->max_entries);
	otlp_kv_int(e, "n_entries", v->n_entries);
	if (upatch_map_is_percpu(v->type))
		otlp_kv_int(e, "n_cpus", v->n_cpus);
	if (v->serialized) {
		__u32 p;

		otlp_kv_bool(e, "serialized", true);
		otlp_kv_int(e, "serialized_pages", v->n_serial_pages);
		otlp_kv_int(e, "serialized_bytes",
			    (__s64)v->serial_bytes_total);
		otlp_array_begin(e, "pages");
		for (p = 0; p < v->n_serial_pages; p++) {
			const struct serial_page *page = &v->serial_pages[p];
			char *hex = hex_alloc(page->data,
						      page->bytes);

			otlp_array_kvlist_begin(e);
			otlp_kv_int(e, "page_index", page->page_index);
			otlp_kv_int(e, "cursor", (__s64)page->cursor);
			otlp_kv_int(e, "next_cursor",
				    (__s64)page->next_cursor);
			otlp_kv_bool(e, "done", page->done);
			otlp_kv_int(e, "flags", page->flags);
			otlp_kv_int(e, "chunks", page->chunks);
			otlp_kv_int(e, "bytes", page->bytes);
			otlp_kv_string(e, "data_hex", hex ? hex : "");
			xfree(hex, size_add(size_mul(page->bytes, 2), 1));
			otlp_array_kvlist_end(e);
		}
		otlp_array_end(e);
		return;
	}
	otlp_kv_bool(e, "serialized", false);
	if (v->skipped) {
		otlp_kv_string(e, "skipped", v->skipped_reason ?: "");
		return;
	}
	otlp_kv_bool(e, "truncated", v->truncated);
	if (v->truncated)
		otlp_kv_int(e, "n_truncated_at", v->n_truncated_at);
	if (v->btf_key_type[0] || v->btf_value_type[0]) {
		otlp_kvlist_begin(e, "btf");
		otlp_kv_string(e, "key_type", v->btf_key_type);
		otlp_kv_string(e, "value_type", v->btf_value_type);
		if (v->key_type_def[0])
			otlp_kv_string(e, "key_type_def", v->key_type_def);
		if (v->value_type_def[0])
			otlp_kv_string(e, "value_type_def", v->value_type_def);
		otlp_kvlist_end(e);
	}
	otlp_array_begin(e, "entries");
	for (i = 0; i < v->n_entries; i++) {
		const struct map_entry *en = &v->entries[i];
		char *key;

		key = upatch_map_format_cell(v, v->key_type_id,
					     en->key, v->key_size,
					     v->btf_key_type);
		otlp_array_kvlist_begin(e);
		otlp_kv_string(e, "key", key ?: "");
		if (upatch_map_is_percpu(v->type)) {
			char *sum;

			sum = upatch_map_format_percpu_sum(v, en->value,
							   v->btf_value_type);
			otlp_array_begin(e, "values_per_cpu");
			for (j = 0; j < v->n_cpus; j++) {
				const char *p = (const char *)en->value +
						(size_t)j * upatch_map_value_stride(v);
				char *one;

				one = upatch_map_format_cell(v, v->value_type_id,
							     p, v->value_size,
							     v->btf_value_type);
				otlp_array_string(e, one ?: "");
				xstrfree(one);
			}
			otlp_array_end(e);
			otlp_kv_string(e, "sum", sum ?: "");
			xstrfree(sum);
		} else {
			char *value;

			value = upatch_map_format_cell(v, v->value_type_id,
						       en->value, v->value_size,
						       v->btf_value_type);
			otlp_kv_string(e, "value", value ?: "");
			xstrfree(value);
		}
		otlp_array_kvlist_end(e);
		xstrfree(key);
	}
	otlp_array_end(e);
}

/* record_max bounds the decoded body, 0 for none. */
static int build_log_payload(const char *path,
			     const struct map_view *v,
			     size_t record_max,
			     char **out, size_t *out_len)
{
	struct json_emit e = {};
	char *decoded = NULL;
	size_t decoded_len = 0;
	char *buf;
	int decode_rc;

	buf = xmalloc(JSON_MAX_BYTES);
	if (!buf)
		return -ENOMEM;
	e.buf = buf;
	e.cap = JSON_MAX_BYTES;

	log_open(&e, "shirudo.upatch.maps", 9, "INFO",
		 "shirudo.bpf.map.snapshot");
	decode_rc = path ? upatch_decode_map_file_otel(path, v,
							      &decoded, &decoded_len) :
			upatch_decode_map_otel(v, &decoded, &decoded_len);
	if (!decode_rc && record_max && decoded_len > record_max) {
		xfree(decoded, decoded_len + 1);
		decoded = NULL;
		decode_rc = -E2BIG;
	}
	if (decode_rc == 0) {
		json_kv_raw(&e, "body", decoded, decoded_len);
	} else if (decode_rc == -ENODATA) {
		json_obj_open_key(&e, "body");
		json_obj_open_key(&e, "kvlistValue");
		json_arr_open(&e, "values");
		emit_log_map_data(&e, v);
		json_arr_close(&e);
		json_obj_close(&e);
		json_obj_close(&e);
	} else {
		xfree(buf, JSON_MAX_BYTES);
		return decode_rc;
	}
	xfree(decoded, decoded_len + 1);
	json_arr_open(&e, "attributes");
	emit_map_attributes(&e, v);
	json_arr_close(&e);
	log_close(&e);

	if (e.err) {
		xfree(buf, JSON_MAX_BYTES);
		return e.err;
	}
	*out = buf;
	*out_len = e.len;
	return 0;
}

int upatch_maps_otel_build_log_file(const char *path,
				    const struct map_view *v,
				    char **out, size_t *out_len)
{
	if (!path)
		return -EINVAL;
	return build_log_payload(path, v, 0, out, out_len);
}

static int build_metric_decoded_payload(const char *path,
					const struct map_view *v,
					char **out, size_t *out_len)
{
	struct json_emit e = {};
	char *decoded = NULL, *decoded_buf, *buf;
	size_t decoded_len = 0, decoded_alloc_len;
	int ret;

	ret = path ? upatch_decode_map_file_json(path, v,
							&decoded, &decoded_len) :
		upatch_decode_map_json(v, &decoded, &decoded_len);
	if (ret)
		return ret;
	decoded_buf = decoded;
	decoded_alloc_len = decoded_len;
	while (decoded_len && isspace((__u8)decoded[0])) {
		decoded++;
		decoded_len--;
	}
	if (!decoded_len || decoded[0] != '[') {
		xfree(decoded_buf, decoded_alloc_len + 1);
		return -EINVAL;
	}
	buf = xmalloc(JSON_MAX_BYTES);
	if (!buf) {
		xfree(decoded_buf, decoded_alloc_len + 1);
		return -ENOMEM;
	}
	e.buf = buf;
	e.cap = JSON_MAX_BYTES;
	otlp_open(&e, "resourceMetrics", "scopeMetrics", "shirudo.upatch.maps");
	json_kv_raw(&e, "metrics", decoded, decoded_len);
	otlp_close(&e);
	if (e.err) {
		xfree(buf, JSON_MAX_BYTES);
		xfree(decoded_buf, decoded_alloc_len + 1);
		return e.err;
	}
	xfree(decoded_buf, decoded_alloc_len + 1);
	*out = buf;
	*out_len = e.len;
	return 0;
}

static const char *signal_name(enum otel_signal signal)
{
	return signal == OTEL_LOG ? "LOGS" : "METRICS";
}

static const char *signal_path(enum otel_signal signal)
{
	return signal == OTEL_LOG ? "v1/logs" : "v1/metrics";
}

static const char *otel_signal_env(enum otel_signal signal,
				   const char *suffix)
{
	char name[128];
	const char *value;

	if (strsprintf(name, sizeof(name), "OTEL_EXPORTER_OTLP_%s_%s",
		       signal_name(signal), suffix) < 0)
		return NULL;
	value = getenv(name);
	return value && value[0] ? value : NULL;
}

static const char *otel_env(enum otel_signal signal,
			    const char *suffix)
{
	const char *value = otel_signal_env(signal, suffix);
	char name[128];

	if (value)
		return value;
	if (strsprintf(name, sizeof(name), "OTEL_EXPORTER_OTLP_%s",
		       suffix) < 0)
		return NULL;
	value = getenv(name);
	return value && value[0] ? value : NULL;
}

static int append_signal_path(const char *base, enum otel_signal signal,
			      char *out, size_t out_sz)
{
	size_t prefix_len;
	const char *slash;
	const char *tail;

	if (!base || !base[0])
		return -EINVAL;
	tail = strpbrk(base, "?#");
	prefix_len = tail ? (size_t)(tail - base) : strlen(base);
	if (prefix_len == 0)
		return -EINVAL;
	slash = base[prefix_len - 1] == '/' ? "" : "/";
	return strsprintf(out, out_sz, "%.*s%s%s%s", (int)prefix_len, base,
			  slash, signal_path(signal), tail ? tail : "") < 0 ?
	       -ENAMETOOLONG : 0;
}

static int resolve_endpoint(struct otel_state *st, const char *spec,
			    bool spec_is_base)
{
	const char *signal_endpoint, *generic_endpoint;

	if (spec && spec[0]) {
		if (spec_is_base)
			return append_signal_path(spec, st->signal, st->endpoint,
						  sizeof(st->endpoint));
		if (strlen(spec) >= sizeof(st->endpoint))
			return -ENAMETOOLONG;
		if (strscpy(st->endpoint, spec, sizeof(st->endpoint)) < 0)
			return -ENAMETOOLONG;
		return 0;
	}
	signal_endpoint = otel_signal_env(st->signal, "ENDPOINT");
	if (signal_endpoint) {
		if (strlen(signal_endpoint) >= sizeof(st->endpoint))
			return -ENAMETOOLONG;
		if (strscpy(st->endpoint, signal_endpoint,
			    sizeof(st->endpoint)) < 0)
			return -ENAMETOOLONG;
		return 0;
	}
	generic_endpoint = getenv("OTEL_EXPORTER_OTLP_ENDPOINT");
	if (!generic_endpoint || !generic_endpoint[0])
		generic_endpoint = "http://localhost:4318";
	return append_signal_path(generic_endpoint, st->signal, st->endpoint,
				  sizeof(st->endpoint));
}

static bool loopback_host(const char *host)
{
	return strcasecmp(host, "localhost") == 0 ||
	       strcmp(host, "127.0.0.1") == 0 || strcmp(host, "[::1]") == 0;
}

static int validate_endpoint_security(struct otel_state *st)
{
	CURLU *url = curl_url();
	char *scheme = NULL, *host = NULL, *user = NULL, *password = NULL;
	CURLUcode uc;
	int ret = 0;

	if (!url)
		return -ENOMEM;
	uc = curl_url_set(url, CURLUPART_URL, st->endpoint, 0);
	if (uc)
		return curl_url_cleanup(url), -EINVAL;
	if (curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) ||
	    curl_url_get(url, CURLUPART_HOST, &host, 0)) {
		ret = -EINVAL;
		goto out;
	}
	curl_url_get(url, CURLUPART_USER, &user, 0);
	curl_url_get(url, CURLUPART_PASSWORD, &password, 0);
	if ((user && user[0]) || (password && password[0])) {
		ret = -EINVAL;
		goto out;
	}
	if (strscpy(st->host, host, sizeof(st->host)) < 0) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	if (strcmp(scheme, "http") == 0) {
		if (!loopback_host(host) && !st->opts.allow_insecure) {
			ret = -EPERM;
			goto out;
		}
		if (st->opts.allow_insecure)
			fprintf(stderr, "WARNING: --otel-insecure sends OTLP data to "
				"http://%s without encryption; data and credentials "
				"may be intercepted or modified\n", host);
	} else if (strcmp(scheme, "https") == 0) {
		st->insecure_tls = st->opts.allow_insecure;
		if (st->insecure_tls)
			fprintf(stderr, "WARNING: --otel-insecure disables TLS certificate "
				"and hostname verification for %s; the Collector's "
				"identity is not verified\n", host);
	} else {
		ret = -EPROTONOSUPPORT;
	}
out:
	curl_free(scheme);
	curl_free(host);
	curl_free(user);
	curl_free(password);
	curl_url_cleanup(url);
	return ret;
}

int upatch_maps_otel_build_metric_file(const char *path,
				       const struct map_view *v,
				       char **out, size_t *out_len)
{
	if (!path)
		return -EINVAL;
	return build_metric_decoded_payload(path, v, out, out_len);
}

static int parse_timeout(const char *value, long *out)
{
	__u64 n;

	if (!value) {
		*out = OTEL_DEFAULT_TIMEOUT_MS;
		return 0;
	}
	/* curl reads 0 as no limit at all, which would let a run hang. */
	if (parse_u64(value, strlen(value), OTEL_MAX_TIMEOUT_MS, &n) || !n)
		return -EINVAL;
	*out = (long)n;
	return 0;
}

static bool reserved_header(const char *name)
{
	return strcasecmp(name, "content-type") == 0 ||
	       strcasecmp(name, "content-encoding") == 0 ||
	       strcasecmp(name, "content-length") == 0 ||
	       strcasecmp(name, "host") == 0 ||
	       strcasecmp(name, "user-agent") == 0;
}

static int append_header(struct otel_state *st, const char *line)
{
	struct curl_slist *headers = curl_slist_append(st->headers, line);

	if (!headers)
		return -ENOMEM;
	st->headers = headers;
	return 0;
}

static int percent_decode(char *s)
{
	char *src = s, *dst = s;

	while (*src) {
		if (*src == '%') {
			int hi, lo;

			if (!src[1] || !src[2])
				return -EINVAL;
			hi = hex_nibble(src[1]);
			lo = hex_nibble(src[2]);
			/* A NUL would cut the value where the string ends. */
			if (hi < 0 || lo < 0 || !(hi | lo))
				return -EINVAL;
			*dst++ = (char)((hi << 4) | lo);
			src += 3;
		} else {
			*dst++ = *src++;
		}
	}
	*dst = '\0';
	return 0;
}

/* RFC 9110, 5.6.2: a field name is a token. */
static bool header_name_ok(const char *s)
{
	if (!*s)
		return false;
	for (; *s; s++)
		if (!isalnum((__u8)*s) && !strchr("!#$%&'*+-.^_`|~", *s))
			return false;
	return true;
}

/* RFC 9110, 5.5: a field value holds no control character but tab. */
static bool header_value_ok(const char *s)
{
	for (; *s; s++)
		if (((__u8)*s < 0x20 && *s != '\t') || *s == 0x7f)
			return false;
	return true;
}

static int add_configured_headers(struct otel_state *st, const char *input)
{
	char *copy, *save = NULL, *pair;
	size_t total = input ? strlen(input) : 0;
	bool tenant_seen = false;
	int ret = 0;

	if (!input)
		return 0;
	if (total > OTEL_MAX_HEADER_BYTES)
		return -E2BIG;
	copy = xstrdup(input);
	if (!copy)
		return -ENOMEM;
	for (pair = strtok_r(copy, ",", &save); pair;
	     pair = strtok_r(NULL, ",", &save)) {
		char *eq = strchr(pair, '=');
		char *name, *value, *line;
		const char *header;
		bool tenant;
		size_t n;

		if (!eq) {
			ret = -EINVAL;
			break;
		}
		*eq = '\0';
		name = pair;
		value = eq + 1;
		while (isspace((__u8)*name))
			name++;
		while (isspace((__u8)*value))
			value++;
		for (char *p = name + strlen(name);
		     p > name && isspace((__u8)p[-1]); p--)
			p[-1] = '\0';
		for (char *p = value + strlen(value);
		     p > value && isspace((__u8)p[-1]); p--)
			p[-1] = '\0';
		tenant = strcasecmp(name, "x-tenant-id") == 0;
		if (!header_name_ok(name) || reserved_header(name) ||
		    percent_decode(value) != 0 || !header_value_ok(value)) {
			ret = -EINVAL;
			break;
		}
		if (tenant) {
			if (st->opts.tenant_id)
				continue;
			if (tenant_seen || !tenant_id_valid(value)) {
				ret = -EINVAL;
				break;
			}
			tenant_seen = true;
		}
		header = tenant ? "X-Tenant-ID" : name;
		n = strlen(header) + strlen(value) + 3;
		line = xmalloc(n);
		if (!line) {
			ret = -ENOMEM;
			break;
		}
		ret = strsprintf(line, n, "%s: %s", header, value) < 0 ? -E2BIG :
		     append_header(st, line);
		memzero_explicit(line, n);
		xfree(line, n);
		if (ret)
			break;
	}
	memzero_explicit(copy, total);
	xfree(copy, total + 1);
	return ret;
}

static int configure_state(struct otel_state *st, const char *spec,
			   bool spec_is_base)
{
	const char *protocol = otel_env(st->signal, "PROTOCOL");
	const char *compression = otel_env(st->signal, "COMPRESSION");
	const char *headers = otel_env(st->signal, "HEADERS");
	int ret;

	if (protocol && strcmp(protocol, "http/json") != 0)
		return -EPROTONOSUPPORT;
	if (compression && strcmp(compression, "none") != 0 &&
	    strcmp(compression, "gzip") != 0)
		return -EINVAL;
	st->gzip = compression && strcmp(compression, "gzip") == 0;
	st->ca_file = otel_env(st->signal, "CERTIFICATE");
	st->client_cert = otel_env(st->signal, "CLIENT_CERTIFICATE");
	st->client_key = otel_env(st->signal, "CLIENT_KEY");
	if (!!st->client_cert != !!st->client_key)
		return -EINVAL;
	ret = parse_timeout(otel_env(st->signal, "TIMEOUT"), &st->timeout_ms);
	if (ret)
		return ret;
	ret = resolve_endpoint(st, spec, spec_is_base);
	if (ret)
		return ret;
	ret = validate_endpoint_security(st);
	if (ret)
		return ret;
	ret = append_header(st, "Content-Type: application/json");
	if (ret)
		return ret;
	if (st->gzip) {
		ret = append_header(st, "Content-Encoding: gzip");
		if (ret)
			return ret;
	}
	ret = add_configured_headers(st, headers);
	if (ret || !st->opts.tenant_id)
		return ret;
	if (!tenant_id_valid(st->opts.tenant_id))
		return -EINVAL;
	{
		char line[sizeof("X-Tenant-ID: ") + TENANT_ID_MAX];

		if (strsprintf(line, sizeof(line), "X-Tenant-ID: %s",
			       st->opts.tenant_id) < 0)
			return -E2BIG;
		return append_header(st, line);
	}
}

static size_t response_write(char *ptr, size_t size, size_t nmemb, void *ctx)
{
	struct otel_response *r = ctx;
	size_t n;

	if (check_mul_overflow(size, nmemb, &n) ||
	    n > sizeof(r->buf) - 1 - r->len)
		return 0;
	memcpy(r->buf + r->len, ptr, n);
	r->len += n;
	r->buf[r->len] = '\0';
	return n;
}

static size_t response_header(char *ptr, size_t size, size_t nmemb, void *ctx)
{
	static const char prefix[] = "Retry-After:";
	struct otel_response *r = ctx;
	size_t n;

	if (check_mul_overflow(size, nmemb, &n))
		return 0;
	if (n > sizeof(prefix) - 1 &&
	    strncasecmp(ptr, prefix, sizeof(prefix) - 1) == 0) {
		char value[128];
		char *p = ptr + sizeof(prefix) - 1;
		size_t len = n - (sizeof(prefix) - 1);
		__u64 seconds;

		while (len && isspace((__u8)*p)) {
			p++;
			len--;
		}
		while (len && isspace((__u8)p[len - 1]))
			len--;
		if (len < sizeof(value)) {
			memcpy(value, p, len);
			value[len] = '\0';
			if (!otel_retry_after(value, time(NULL), &seconds)) {
				r->retry_after = seconds;
				r->retry_after_valid = true;
			}
		}
	}
	return n;
}

static int gzip_data(const char *in, size_t in_len,
		     __u8 **out, size_t *out_len)
{
	z_stream z = {};
	__u8 *buf;
	size_t cap;
	int zr;

	/* zlib counts in uInt; a longer input would be cut short silently. */
	if (in_len > UINT_MAX)
		return -EFBIG;
	cap = size_add(compressBound(in_len), 32);
	if (cap > UINT_MAX)
		return -EFBIG;
	buf = xmalloc(cap);
	if (!buf)
		return -ENOMEM;
	zr = deflateInit2(&z, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8,
			  Z_DEFAULT_STRATEGY);
	if (zr != Z_OK) {
		xfree(buf, cap);
		return -EIO;
	}
	z.next_in = (__u8 *)in;
	z.avail_in = (uInt)in_len;
	z.next_out = buf;
	z.avail_out = (uInt)cap;
	zr = deflate(&z, Z_FINISH);
	if (zr != Z_STREAM_END) {
		deflateEnd(&z);
		xfree(buf, cap);
		return -EIO;
	}
	*out_len = z.total_out;
	*out = buf;
	deflateEnd(&z);
	return 0;
}

static bool retryable_curl(CURLcode code)
{
	switch (code) {
	case CURLE_COULDNT_RESOLVE_HOST:
	case CURLE_COULDNT_CONNECT:
	case CURLE_OPERATION_TIMEDOUT:
	case CURLE_SEND_ERROR:
	case CURLE_RECV_ERROR:
	case CURLE_GOT_NOTHING:
	case CURLE_PARTIAL_FILE:
	case CURLE_HTTP2:
	case CURLE_AGAIN:
		return true;
	default:
		return false;
	}
}

static bool retryable_http(long code)
{
	return code == 429 || code == 502 || code == 503 || code == 504;
}

int status_otel_severity(const char *status, const char **text)
{
	if (strcmp(status, "ok") == 0) {
		*text = "INFO";
		return 9;
	}
	if (strcmp(status, "degraded") == 0 ||
	    strcmp(status, "init-pending") == 0 ||
	    strcmp(status, "reboot-pending") == 0) {
		*text = "WARN";
		return 13;
	}
	*text = "ERROR";
	return 17;
}

int otel_retry_after(const char *value, time_t now, __u64 *seconds)
{
	struct tm date = {};
	time_t retry_time;
	__u64 delay = 0;
	const char *p;
	char *end;
	int parsed;

	if (!value || !seconds || !value[0])
		return -EINVAL;
	for (p = value; *p; p++) {
		if (*p < '0' || *p > '9')
			break;
		if (delay < 31)
			delay = delay * 10 + (__u64)(*p - '0');
	}
	if (!*p) {
		*seconds = min(delay, 30U);
		return 0;
	}
	parsed = 0;
	memset(&date, 0, sizeof(date));
	end = strptime(value, "%a, %d %b %Y %H:%M:%S GMT", &date);
	parsed = !!end;
	if (!parsed) {
		memset(&date, 0, sizeof(date));
		end = strptime(value, "%A, %d-%b-%y %H:%M:%S GMT", &date);
		parsed = !!end;
	}
	if (!parsed) {
		memset(&date, 0, sizeof(date));
		end = strptime(value, "%a %b %e %H:%M:%S %Y", &date);
		parsed = !!end;
	}
	if (!parsed)
		return -EINVAL;
	while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')
		end++;
	if (*end)
		return -EINVAL;
	retry_time = timegm(&date);
	if (retry_time <= now) {
		*seconds = 0;
		return 0;
	}
	delay = (__u64)(retry_time - now);
	*seconds = min(delay, 30U);
	return 0;
}

/*
 * The proto3 JSON mapping lets a receiver send the rejected count as a
 * string or a number, and the message is advisory: one that does not
 * fit is left out rather than failing an export the collector took.
 */
static int check_partial_success(enum otel_signal signal,
				 const char *body, size_t len)
{
	const char *count = signal == OTEL_LOG ?
			    "rejectedLogRecords" : "rejectedDataPoints";
	char rejected_text[32] = {};
	char error[256] = {};
	struct json_field partial[] = {
		{ count, JSON_T_STRING, rejected_text,
		  sizeof(rejected_text), 0, NULL, 0 },
	};
	struct json_field root[] = {
		{ "partialSuccess", JSON_T_OBJECT, NULL, 0, 0,
		  partial, ARRAY_SIZE(partial) },
	};
	__s64 rejected = 0;
	int ret;

	if (len == 0)
		return 0;
	ret = json_parse(body, len, root, ARRAY_SIZE(root));
	if (ret) {
		partial[0] = (struct json_field){
			count, JSON_T_INT, &rejected, 0, 0, NULL, 0 };
		if (json_parse(body, len, root, ARRAY_SIZE(root)))
			return -EBADMSG;
	} else if (partial[0].seen) {
		if (parse_s64(rejected_text, strlen(rejected_text), 0,
			      LLONG_MAX, &rejected))
			return -EBADMSG;
	}
	if (rejected < 0)
		return -EBADMSG;
	if (rejected > 0) {
		partial[0] = (struct json_field){
			"errorMessage", JSON_T_STRING, error,
			sizeof(error), 0, NULL, 0 };
		if (json_parse(body, len, root, ARRAY_SIZE(root)))
			error[0] = '\0';
		pr_err("otel: Collector partially rejected %lld %s%s%s",
		       rejected, signal == OTEL_LOG ? "log record(s)" :
		       "data point(s)", error[0] ? ": " : "", error);
		return -EREMOTEIO;
	}
	return 0;
}

static __u32 random_below(__u32 limit)
{
	__u32 value;

	if (limit == 0)
		return 0;
	if (getrandom(&value, sizeof(value), 0) != sizeof(value))
		value = (__u32)time(NULL) ^ (__u32)getpid();
	return value % limit;
}

static void retry_wait(__u32 retry, __u64 retry_after,
		       bool retry_after_valid)
{
	struct timespec ts;
	__u32 cap_ms = 250U << min(retry, 4U);
	__u32 delay_ms;

	if (cap_ms > 5000)
		cap_ms = 5000;
	delay_ms = retry_after_valid ? (__u32)retry_after * 1000U :
		 random_below(cap_ms + 1);
	ts.tv_sec = delay_ms / 1000;
	ts.tv_nsec = (long)(delay_ms % 1000) * 1000000L;
	while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
		;
}

static noinline_for_stack int otel_post(struct otel_state *st,
					const char *json, size_t json_len)
{
	__u8 *compressed = NULL;
	const void *body = json;
	size_t body_len = json_len, compressed_cap = 0;
	__u32 attempt, max_attempts;
	int ret = -EIO;

	if (check_add_overflow(st->opts.retries, 1, &max_attempts))
		return -EINVAL;
	if (!st->s3_reference && st->opts.otlp_max_bytes &&
	    json_len > st->opts.otlp_max_bytes)
		return -E2BIG;
	if (st->gzip) {
		ret = gzip_data(json, json_len, &compressed, &body_len);
		if (ret)
			return ret;
		body = compressed;
		compressed_cap = compressBound(json_len) + 32;
	}
	for (attempt = 0; attempt < max_attempts; attempt++) {
		struct otel_response response = {};
		CURL *curl = curl_easy_init();
		CURLcode cc;
		long status = 0;
		bool retry;

		if (!curl) {
			ret = -ENOMEM;
			break;
		}
		curl_easy_setopt(curl, CURLOPT_URL, st->endpoint);
		curl_easy_setopt(curl, CURLOPT_POST, 1L);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
				 (curl_off_t)body_len);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, st->headers);
		curl_easy_setopt(curl, CURLOPT_USERAGENT,
				 "shirudo OTel-OTLP-Exporter-C/1");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_write);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, response_header);
		curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response);
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, st->timeout_ms);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,
				 st->insecure_tls ? 0L : 1L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,
				 st->insecure_tls ? 0L : 2L);
		if (tls_curl_policy(curl, NULL)) {
			curl_easy_cleanup(curl);
			ret = -EINVAL;
			break;
		}
		if (st->ca_file)
			curl_easy_setopt(curl, CURLOPT_CAINFO, st->ca_file);
		if (st->client_cert)
			curl_easy_setopt(curl, CURLOPT_SSLCERT, st->client_cert);
		if (st->client_key)
			curl_easy_setopt(curl, CURLOPT_SSLKEY, st->client_key);
		cc = curl_easy_perform(curl);
		if (cc == CURLE_OK)
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
		if (cc == CURLE_OK && status == 200) {
			ret = check_partial_success(st->signal, response.buf,
						    response.len);
			curl_easy_cleanup(curl);
			break;
		}
		retry = cc != CURLE_OK ? retryable_curl(cc) :
			retryable_http(status);
		if (cc != CURLE_OK)
			fprintf(stderr, "otel: export attempt %u/%u failed: %s\n",
				attempt + 1, max_attempts, curl_easy_strerror(cc));
		else
			fprintf(stderr, "otel: export attempt %u/%u received HTTP %ld\n",
				attempt + 1, max_attempts, status);
		ret = cc == CURLE_OPERATION_TIMEDOUT ? -ETIMEDOUT :
		     cc != CURLE_OK ? -EHOSTUNREACH : -EREMOTEIO;
		curl_easy_cleanup(curl);
		if (!retry || attempt + 1 == max_attempts)
			break;
		retry_wait(attempt, response.retry_after,
			   response.retry_after_valid);
	}
	xfree(compressed, compressed_cap);
	return ret;
}

static int otel_open_transport(enum otel_signal signal,
			       const char *spec,
			       const struct otel_opts *opts,
			       const char *decoder_path, void **state)
{
	struct otel_state *st;
	int ret;

	if (!state)
		return -EINVAL;
	st = xcalloc(1, sizeof(*st));
	if (!st)
		return -ENOMEM;
	st->signal = signal;
	st->opts.retries = 3;
	if (opts)
		st->opts = *opts;
	/* Callers without the configuration leave the limits at 0. */
	if (!st->opts.otlp_max_bytes)
		st->opts.otlp_max_bytes = MAP_EXPORT_OTLP_MAX_DEFAULT;
	if (!st->opts.log_record_max_bytes)
		st->opts.log_record_max_bytes =
			MAP_EXPORT_LOG_RECORD_MAX_DEFAULT;
	st->decoder_path = decoder_path;
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
		ret = -EIO;
		goto err;
	}
	/* Explicit CLI/config endpoints are base URLs for the selected signal. */
	ret = configure_state(st, spec, true);
	if (ret)
		goto err_global;
	*state = st;
	return 0;

err_global:
	curl_global_cleanup();
err:
	curl_slist_free_sensitive(st->headers);
	xfree(st, sizeof(*st));
	return ret;
}

static int otel_open_common(const char *spec, const struct map_view *v,
			    const struct otel_opts *opts,
			    bool automatic, enum otel_signal forced,
			    const char *decoder_path, void **state)
{
	enum otel_signal signal;
	char reason[160];
	int ret;

	if (!v || !state)
		return -EINVAL;
	if (automatic) {
		ret = upatch_maps_otel_classify(v, &signal,
						reason, sizeof(reason));
		if (ret)
			return ret;
		fprintf(stderr, "otel: selected %s for %s map %s: %s\n",
			signal == OTEL_LOG ? "log" : "metric",
			v->type_name, v->name, reason);
	} else {
		signal = forced;
	}
	return otel_open_transport(signal, spec, opts, decoder_path, state);
}

static int otel_emit(void *state, const struct map_view *v)
{
	struct otel_state *st = state;
	char *payload = NULL;
	size_t len = 0;
	int ret;

	if (!st || !v)
		return -EINVAL;
	if (st->signal == OTEL_LOG)
		ret = build_log_payload(st->decoder_path, v,
					st->opts.log_record_max_bytes,
					&payload, &len);
	else
		ret = build_metric_decoded_payload(st->decoder_path, v,
						   &payload, &len);
	if (ret)
		return ret;
	ret = otel_post(st, payload, len);
	xfree(payload, JSON_MAX_BYTES);
	return ret;
}

static int otel_close(void *state)
{
	struct otel_state *st = state;

	if (!st)
		return 0;
	curl_slist_free_sensitive(st->headers);
	xfree(st, sizeof(*st));
	curl_global_cleanup();
	return 0;
}

static int build_generic_log_payload(const char *scope_name,
				     const char *event_name,
				     int severity_number,
				     const char *severity_text,
				     const char *status, const char *version_id,
				     __s64 tamper_attempts,
				     const char *body_json, size_t body_len,
				     char **out, size_t *out_len,
				     size_t *alloc_len)
{
	struct json_emit e = { .max = JSON_MAX_BYTES };
	int ret;

	if (!scope_name || !event_name || !severity_text || !body_json ||
	    !out || !out_len || !alloc_len)
		return -EINVAL;
	log_open(&e, scope_name, severity_number, severity_text, event_name);
	json_obj_open_key(&e, "body");
	ret = json_anyvalue_from_document(&e, body_json, body_len, false);
	json_obj_close(&e);
	if (ret) {
		xfree(e.buf, e.cap);
		return ret;
	}
	json_arr_open(&e, "attributes");
	if (status)
		otlp_kv_string(&e, "shirudo.status", status);
	if (version_id)
		otlp_kv_string(&e, "shirudo.version_id", version_id);
	if (tamper_attempts >= 0)
		otlp_kv_int(&e, "shirudo.tamper_attempts", tamper_attempts);
	json_arr_close(&e);
	log_close(&e);
	if (e.err) {
		xfree(e.buf, e.cap);
		return e.err;
	}
	*out = e.buf;
	*out_len = e.len;
	*alloc_len = e.cap;
	return 0;
}

int otel_send_log_json(const struct otel_opts *opts,
		       const char *scope_name,
		       const char *event_name,
		       int severity_number,
		       const char *severity_text,
		       const char *status,
		       const char *version_id,
		       __s64 tamper_attempts,
		       const char *body_json, size_t body_len)
{
	char *payload = NULL;
	void *state = NULL;
	size_t payload_len = 0, alloc_len = 0;
	int ret;

	ret = otel_open_transport(OTEL_LOG,
				  opts ? opts->endpoint : NULL, opts, NULL, &state);
	if (ret)
		return ret;
	ret = build_generic_log_payload(scope_name, event_name,
					severity_number, severity_text,
					status, version_id,
					tamper_attempts,
					body_json, body_len,
					&payload, &payload_len, &alloc_len);
	if (!ret)
		ret = otel_post(state, payload, payload_len);
	xfree(payload, alloc_len);
	otel_close(state);
	return ret;
}

struct snapshot_writer {
	FILE		*file;
	z_stream	z;
	gz_header	header;
	struct sha256_ctx md;
	__u64		json_bytes;
	__u64		object_bytes;
	bool		deflate_ready;
};

static int snapshot_temp_file(FILE **out)
{
	const char *tmpdir = getenv("TMPDIR");
	char path[PATH_MAX];
	FILE *file;
	int fd;

	if (!tmpdir || !tmpdir[0])
		tmpdir = "/tmp";
	if (strsprintf(path, sizeof(path), "%s/%s", tmpdir,
		       "shirudo-map-snapshot.XXXXXX") < 0)
		return -ENAMETOOLONG;
	fd = mkstemp(path);
	if (fd < 0)
		return -errno;
	if (fchmod(fd, 0600) != 0) {
		int ret = -errno;

		unlink(path);
		close(fd);
		return ret;
	}
	if (unlink(path) != 0) {
		int ret = -errno;

		close(fd);
		return ret;
	}
	file = fdopen(fd, "w+b");
	if (!file) {
		int ret = -errno;

		close(fd);
		return ret;
	}
	*out = file;
	return 0;
}

static int snapshot_write_compressed(struct snapshot_writer *w,
				     const __u8 *data, size_t len)
{
	__u64 total;

	if (check_add_overflow(w->object_bytes, len, &total))
		return -EOVERFLOW;
	if (len && fwrite(data, 1, len, w->file) != len)
		return -EIO;
	if (len && sha256_update(&w->md, data, len) != 0)
		return -EIO;
	w->object_bytes = total;
	return 0;
}

static int snapshot_writer_init(struct snapshot_writer *w, FILE *file)
{
	int zr;

	memset(w, 0, sizeof(*w));
	w->file = file;
	if (sha256_init(&w->md) != 0)
		return -EIO;
	zr = deflateInit2(&w->z, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16,
			  8, Z_DEFAULT_STRATEGY);
	if (zr != Z_OK)
		return -EIO;
	w->deflate_ready = true;
	/* A zero timestamp makes identical JSON produce identical gzip bytes. */
	w->header.time = 0;
	w->header.os = 255;
	if (deflateSetHeader(&w->z, &w->header) != Z_OK)
		return -EIO;
	return 0;
}

static void snapshot_writer_abort(struct snapshot_writer *w)
{
	if (w->deflate_ready)
		deflateEnd(&w->z);
	sha256_free(&w->md);
	w->deflate_ready = false;
}

static int snapshot_json_sink(void *ctx, const char *data, size_t len)
{
	struct snapshot_writer *w = ctx;
	__u8 out[S3_GZIP_BUFFER_SIZE];

	if (check_add_overflow(w->json_bytes, len, &w->json_bytes))
		return -EOVERFLOW;
	while (len) {
		uInt chunk = len > UINT_MAX ? UINT_MAX : (uInt)len;

		w->z.next_in = (__u8 *)data;
		w->z.avail_in = chunk;
		while (w->z.avail_in) {
			size_t produced;
			int ret, zr;

			w->z.next_out = out;
			w->z.avail_out = sizeof(out);
			zr = deflate(&w->z, Z_NO_FLUSH);
			if (zr != Z_OK)
				return -EIO;
			produced = sizeof(out) - w->z.avail_out;
			ret = snapshot_write_compressed(w, out, produced);
			if (ret)
				return ret;
		}
		data += chunk;
		len -= chunk;
	}
	return 0;
}

static int snapshot_writer_finish(struct snapshot_writer *w,
				  struct s3_snapshot *snapshot)
{
	__u8 out[S3_GZIP_BUFFER_SIZE];
	int zr, ret;

	do {
		size_t produced;

		w->z.next_out = out;
		w->z.avail_out = sizeof(out);
		zr = deflate(&w->z, Z_FINISH);
		if (zr != Z_OK && zr != Z_STREAM_END)
			return -EIO;
		produced = sizeof(out) - w->z.avail_out;
		ret = snapshot_write_compressed(w, out, produced);
		if (ret)
			return ret;
	} while (zr != Z_STREAM_END);
	if (deflateEnd(&w->z) != Z_OK)
		return -EIO;
	w->deflate_ready = false;
	if (sha256_final(&w->md, snapshot->sha256) != 0)
		return -EIO;
	if (fflush(w->file) != 0 || fseeko(w->file, 0, SEEK_SET) != 0)
		return -EIO;
	snapshot->json_bytes = w->json_bytes;
	snapshot->object_bytes = w->object_bytes;
	hex_encode(snapshot->sha256, sizeof(snapshot->sha256),
		   snapshot->sha256_hex);
	if (base64_encode(snapshot->sha256, sizeof(snapshot->sha256),
			  snapshot->sha256_b64,
			  sizeof(snapshot->sha256_b64)) != 0)
		return -EIO;
	snapshot->sha256_b64[44] = '\0';
	return 0;
}

static int build_s3_snapshot(const char *decoder_path,
			     const struct map_view *v,
			     struct s3_snapshot *snapshot)
{
	struct snapshot_writer writer;
	char *decoded = NULL;
	size_t decoded_len = 0;
	int ret;

	memset(snapshot, 0, sizeof(*snapshot));
	/* S3 stores exactly the canonical value returned by the signed decoder. */
	if (decoder_path)
		ret = upatch_decode_map_file_json_limit(decoder_path, v,
							S3_DECODER_JSON_MAX_BYTES,
							&decoded,
							&decoded_len);
	else
		ret = upatch_decode_map_json_limit(v,
						   S3_DECODER_JSON_MAX_BYTES,
						   &decoded,
						   &decoded_len);
	if (ret)
		return ret;
	ret = snapshot_temp_file(&snapshot->file);
	if (ret) {
		xfree(decoded, decoded_len + 1);
		return ret;
	}
	ret = snapshot_writer_init(&writer, snapshot->file);
	if (ret) {
		xfree(decoded, decoded_len + 1);
		goto err_writer;
	}
	ret = snapshot_json_sink(&writer, decoded, decoded_len);
	xfree(decoded, decoded_len + 1);
	if (ret)
		goto err_writer;
	ret = snapshot_writer_finish(&writer, snapshot);
	if (ret)
		goto err_writer;
	return 0;

err_writer:
	snapshot_writer_abort(&writer);
	fclose(snapshot->file);
	snapshot->file = NULL;
	return ret;
}

static bool valid_bucket(const char *bucket, size_t len)
{
	if (len < 3 || len > S3_BUCKET_MAX ||
	    !isalnum((__u8)bucket[0]) ||
	    !isalnum((__u8)bucket[len - 1]))
		return false;
	for (size_t i = 0; i < len; i++) {
		__u8 c = bucket[i];

		if (!(c >= 'a' && c <= 'z') && !isdigit(c) && c != '-' &&
		    c != '.')
			return false;
	}
	return true;
}

static bool valid_region(const char *region)
{
	if (!region || !region[0] || strlen(region) >= S3_REGION_MAX)
		return false;
	for (const __u8 *p = (const __u8 *)region; *p; p++) {
		if (!isalnum(*p) && *p != '-')
			return false;
	}
	return true;
}

static int parse_s3_spec(struct otel_s3_state *st, const char *spec)
{
	const char *bucket, *slash, *prefix, *region, *endpoint;
	const char *access, *secret;
	size_t bucket_len, prefix_len, credentials_len;

	if (!spec || strncmp(spec, "s3://", 5) != 0)
		return -EINVAL;
	bucket = spec + 5;
	slash = strchr(bucket, '/');
	bucket_len = slash ? (size_t)(slash - bucket) : strlen(bucket);
	if (!valid_bucket(bucket, bucket_len))
		return -EINVAL;
	memcpy(st->bucket, bucket, bucket_len);
	st->bucket[bucket_len] = '\0';
	prefix = slash ? slash + 1 : "";
	while (*prefix == '/')
		prefix++;
	prefix_len = strlen(prefix);
	while (prefix_len && prefix[prefix_len - 1] == '/')
		prefix_len--;
	if (prefix_len > S3_PREFIX_MAX)
		return -ENAMETOOLONG;
	for (size_t i = 0; i < prefix_len; i++) {
		if ((__u8)prefix[i] < 0x20 || prefix[i] == '?' ||
		    prefix[i] == '#')
			return -EINVAL;
		if ((prefix[i] == '.' && (i == 0 || prefix[i - 1] == '/') &&
		     (i + 1 == prefix_len || prefix[i + 1] == '/')) ||
		    (prefix[i] == '.' && i + 1 < prefix_len &&
		     prefix[i + 1] == '.' &&
		     (i == 0 || prefix[i - 1] == '/') &&
		     (i + 2 == prefix_len || prefix[i + 2] == '/')))
			return -EINVAL;
	}
	memcpy(st->prefix, prefix, prefix_len);
	st->prefix[prefix_len] = '\0';
	region = getenv("AWS_REGION");
	if (!region || !region[0])
		region = getenv("AWS_DEFAULT_REGION");
	if (!region || !region[0])
		region = "us-east-1";
	if (!valid_region(region))
		return -EINVAL;
	if (strscpy(st->region, region, sizeof(st->region)) < 0)
		return -ENAMETOOLONG;
	endpoint = getenv("AWS_ENDPOINT_URL_S3");
	if (endpoint && endpoint[0]) {
		size_t len = strlen(endpoint);

		if (len >= sizeof(st->endpoint))
			return -ENAMETOOLONG;
		while (len && endpoint[len - 1] == '/')
			len--;
		if (!len)
			return -EINVAL;
		memcpy(st->endpoint, endpoint, len);
		st->endpoint[len] = '\0';
		st->custom_endpoint = true;
	}
	access = getenv("AWS_ACCESS_KEY_ID");
	secret = getenv("AWS_SECRET_ACCESS_KEY");
	if (!access || !access[0] || !secret || !secret[0] ||
	    strpbrk(access, "\r\n:") || strpbrk(secret, "\r\n"))
		return -EACCES;
	if (check_add_overflow(strlen(access), strlen(secret),
			       &credentials_len) ||
	    check_add_overflow(credentials_len, 2, &credentials_len))
		return -EOVERFLOW;
	st->credentials = xmalloc(credentials_len);
	if (!st->credentials)
		return -ENOMEM;
	st->credentials_len = credentials_len;
	if (strsprintf(st->credentials, credentials_len, "%s:%s", access,
		       secret) < 0)
		return -E2BIG;
	st->session_token = getenv("AWS_SESSION_TOKEN");
	if (st->session_token &&
	    (!st->session_token[0] || strpbrk(st->session_token, "\r\n")))
		return -EINVAL;
	st->ca_file = getenv("AWS_CA_BUNDLE");
	if (st->ca_file && !st->ca_file[0])
		st->ca_file = NULL;
	return 0;
}

static int validate_s3_endpoint(struct otel_s3_state *st)
{
	CURLU *url;
	char *scheme = NULL, *host = NULL, *user = NULL, *password = NULL;
	int ret = 0;

	if (!st->custom_endpoint) {
		if (st->opts.allow_insecure) {
			st->insecure_tls = true;
			fprintf(stderr, "WARNING: --otel-insecure disables TLS certificate "
				"and hostname verification for Amazon S3\n");
		}
		return 0;
	}
	url = curl_url();
	if (!url)
		return -ENOMEM;
	if (curl_url_set(url, CURLUPART_URL, st->endpoint, 0) ||
	    curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) ||
	    curl_url_get(url, CURLUPART_HOST, &host, 0)) {
		ret = -EINVAL;
		goto out;
	}
	curl_url_get(url, CURLUPART_USER, &user, 0);
	curl_url_get(url, CURLUPART_PASSWORD, &password, 0);
	if ((user && user[0]) || (password && password[0]) ||
	    strchr(st->endpoint, '?') || strchr(st->endpoint, '#')) {
		ret = -EINVAL;
		goto out;
	}
	if (strlen(host) >= sizeof(st->host)) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	if (strscpy(st->host, host, sizeof(st->host)) < 0) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	if (strcmp(scheme, "http") == 0) {
		if (!loopback_host(host) && !st->opts.allow_insecure) {
			ret = -EPERM;
			goto out;
		}
		if (st->opts.allow_insecure)
			fprintf(stderr, "WARNING: --otel-insecure sends S3 snapshots and "
				"credentials to http://%s without encryption\n", host);
	} else if (strcmp(scheme, "https") == 0) {
		st->insecure_tls = st->opts.allow_insecure;
		if (st->insecure_tls)
			fprintf(stderr, "WARNING: --otel-insecure disables TLS certificate "
				"and hostname verification for S3 endpoint %s\n", host);
	} else {
		ret = -EPROTONOSUPPORT;
	}
out:
	curl_free(scheme);
	curl_free(host);
	curl_free(user);
	curl_free(password);
	curl_url_cleanup(url);
	return ret;
}

static void safe_key_segment(char *segment)
{
	for (__u8 *p = (__u8 *)segment; *p; p++) {
		if (!isalnum(*p) && *p != '-' && *p != '_' && *p != '.')
			*p = '_';
	}
}

static int escape_s3_path(const char *path, char *out, size_t out_sz)
{
	static const char hex[] = "0123456789ABCDEF";
	size_t n = 0;

	for (const __u8 *p = (const __u8 *)path; *p; p++) {
		bool plain = isalnum(*p) || *p == '-' || *p == '_' || *p == '.' ||
			     *p == '~' || *p == '/';

		if (plain) {
			if (n + 1 >= out_sz)
				return -ENAMETOOLONG;
			out[n++] = (char)*p;
		} else {
			if (n + 3 >= out_sz)
				return -ENAMETOOLONG;
			out[n++] = '%';
			out[n++] = hex[*p >> 4];
			out[n++] = hex[*p & 0xf];
		}
	}
	out[n] = '\0';
	return 0;
}

static int build_s3_urls(const struct otel_s3_state *st,
			 const struct map_view *v,
			 const struct s3_snapshot *snapshot,
			 char *url, size_t url_sz, char *uri, size_t uri_sz)
{
	char hostname[256] = "unknown";
	char key[S3_URL_MAX], escaped[S3_URL_MAX];
	int n, ret;

	if (gethostname(hostname, sizeof(hostname)) != 0)
		strscpy(hostname, "unknown", sizeof(hostname));
	hostname[sizeof(hostname) - 1] = '\0';
	safe_key_segment(hostname);
	n = strsprintf(key, sizeof(key), "%s%s%s/%s/%s/%s.json.gz",
		       st->prefix, st->prefix[0] ? "/" : "", hostname,
		       v->upatch, v->name, snapshot->sha256_hex);
	if (n < 0 || (size_t)n > S3_KEY_MAX)
		return -ENAMETOOLONG;
	ret = escape_s3_path(key, escaped, sizeof(escaped));
	if (ret)
		return ret;
	if (strsprintf(uri, uri_sz, "s3://%s/%s", st->bucket, escaped) < 0)
		return -ENAMETOOLONG;
	if (st->custom_endpoint)
		n = strsprintf(url, url_sz, "%s/%s/%s", st->endpoint,
			       st->bucket, escaped);
	else if (strchr(st->bucket, '.'))
		n = strsprintf(url, url_sz, "https://s3.%s.amazonaws.com/%s/%s",
			       st->region, st->bucket, escaped);
	else
		n = strsprintf(url, url_sz, "https://%s.s3.%s.amazonaws.com/%s",
			       st->bucket, st->region, escaped);
	return n < 0 ? -ENAMETOOLONG : 0;
}

static int s3_header(struct curl_slist **headers, const char *line)
{
	struct curl_slist *next = curl_slist_append(*headers, line);

	if (!next)
		return -ENOMEM;
	*headers = next;
	return 0;
}

static int s3_headers(const struct otel_s3_state *st,
		      const struct map_view *v,
		      const struct s3_snapshot *snapshot,
		      struct curl_slist **out)
{
	char sha256[512], checksum[512], upatch[512], map[512];
	const char *const lines[] = {
		"Content-Type: application/json",
		"Content-Encoding: gzip",
		"Cache-Control: immutable",
		"If-None-Match: *",
		"Expect:",
		sha256,
		checksum,
		"x-amz-meta-shirudo-schema: 1",
		upatch,
		map,
	};
	int ret;

	if (strsprintf(sha256, sizeof(sha256), "x-amz-content-sha256: %s",
		       snapshot->sha256_hex) < 0 ||
	    strsprintf(checksum, sizeof(checksum), "x-amz-checksum-sha256: %s",
		       snapshot->sha256_b64) < 0 ||
	    strsprintf(upatch, sizeof(upatch), "x-amz-meta-shirudo-upatch: %s",
		       v->upatch) < 0 ||
	    strsprintf(map, sizeof(map), "x-amz-meta-shirudo-map: %s",
		       v->name) < 0)
		return -E2BIG;
	for (size_t i = 0; i < ARRAY_SIZE(lines); i++) {
		ret = s3_header(out, lines[i]);
		if (ret)
			return ret;
	}
	/* STS session tokens run well past a kilobyte. */
	if (st->session_token) {
		size_t len = strlen("x-amz-security-token: ") +
			     strlen(st->session_token) + 1;
		char *token = xmalloc(len);

		if (!token)
			return -ENOMEM;
		ret = strsprintf(token, len, "x-amz-security-token: %s",
				 st->session_token) < 0 ? -E2BIG :
		     s3_header(out, token);
		xfree(token, len);
		if (ret)
			return ret;
	}
	return 0;
}

static bool retryable_s3_http(long status)
{
	return status == 408 || status == 409 || status == 500 ||
	       retryable_http(status);
}

static noinline_for_stack int s3_put(struct otel_s3_state *st,
				     const struct map_view *v,
				     struct s3_snapshot *snapshot,
				     const char *url, bool *already_present)
{
	struct curl_slist *headers = NULL;
	char sigv4[128];
	__u32 max_attempts;
	int ret;

	*already_present = false;
	if (check_add_overflow(st->opts.retries, 1, &max_attempts))
		return -EINVAL;
	ret = s3_headers(st, v, snapshot, &headers);
	if (ret) {
		curl_slist_free_sensitive(headers);
		return ret;
	}
	if (strsprintf(sigv4, sizeof(sigv4), "aws:amz:%s:s3", st->region) < 0) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	for (__u32 attempt = 0; attempt < max_attempts; attempt++) {
		struct otel_response response = {};
		CURL *curl = curl_easy_init();
		CURLcode cc;
		long status = 0;
		bool retry;

		if (!curl) {
			ret = -ENOMEM;
			break;
		}
		clearerr(snapshot->file);
		if (fseeko(snapshot->file, 0, SEEK_SET) != 0) {
			curl_easy_cleanup(curl);
			ret = -EIO;
			break;
		}
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
		curl_easy_setopt(curl, CURLOPT_READDATA, snapshot->file);
		curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
				 (curl_off_t)snapshot->object_bytes);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_AWS_SIGV4, sigv4);
		curl_easy_setopt(curl, CURLOPT_USERPWD, st->credentials);
		curl_easy_setopt(curl, CURLOPT_USERAGENT,
				 "shirudo-S3-Exporter-C/1");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_write);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, response_header);
		curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response);
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS,
				 OTEL_DEFAULT_TIMEOUT_MS);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,
				 st->insecure_tls ? 0L : 1L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,
				 st->insecure_tls ? 0L : 2L);
		if (tls_curl_policy(curl, NULL)) {
			curl_easy_cleanup(curl);
			ret = -EINVAL;
			break;
		}
		if (st->ca_file)
			curl_easy_setopt(curl, CURLOPT_CAINFO, st->ca_file);
		cc = curl_easy_perform(curl);
		if (cc == CURLE_OK)
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
		if (cc == CURLE_OK &&
		    (status == 200 || status == 201 || status == 204 ||
		     status == 412)) {
			*already_present = status == 412;
			ret = 0;
			curl_easy_cleanup(curl);
			break;
		}
		retry = cc != CURLE_OK ? retryable_curl(cc) :
			retryable_s3_http(status);
		if (cc != CURLE_OK)
			fprintf(stderr, "otel.s3: upload attempt %u/%u failed: %s\n",
				attempt + 1, max_attempts, curl_easy_strerror(cc));
		else
			fprintf(stderr, "otel.s3: upload attempt %u/%u received HTTP %ld\n",
				attempt + 1, max_attempts, status);
		ret = cc == CURLE_OPERATION_TIMEDOUT ? -ETIMEDOUT :
		     cc != CURLE_OK ? -EHOSTUNREACH : -EREMOTEIO;
		curl_easy_cleanup(curl);
		if (!retry || attempt + 1 == max_attempts)
			break;
		retry_wait(attempt, response.retry_after,
			   response.retry_after_valid);
	}
out:
	curl_slist_free_sensitive(headers);
	return ret;
}

static int build_s3_reference(const struct map_view *v,
			      const struct s3_snapshot *snapshot,
			      const char *uri, char **out, size_t *out_len)
{
	struct json_emit e = {};
	char description[S3_URL_MAX + 64];
	char *buf;

	if (strsprintf(description, sizeof(description),
		       "BPF map snapshot stored in S3: %s", uri) < 0)
		return -E2BIG;
	buf = xmalloc(S3_REFERENCE_MAX);
	if (!buf)
		return -ENOMEM;
	e.buf = buf;
	e.cap = S3_REFERENCE_MAX;
	log_open(&e, "shirudo.upatch.maps", 9, "INFO",
		 "shirudo.bpf.map.snapshot.reference");
	json_obj_open_key(&e, "body");
	json_kv_string(&e, "stringValue", description);
	json_obj_close(&e);
	json_arr_open(&e, "attributes");
	emit_map_attributes(&e, v);
	otlp_kv_string(&e, "shirudo.map.snapshot.uri", uri);
	otlp_kv_string(&e, "shirudo.map.snapshot.format",
		       "shirudo.map.v1+json");
	otlp_kv_string(&e, "shirudo.map.snapshot.content_type",
		       "application/json");
	otlp_kv_string(&e, "shirudo.map.snapshot.content_encoding", "gzip");
	otlp_kv_int(&e, "shirudo.map.snapshot.size_bytes",
		    (__s64)snapshot->object_bytes);
	otlp_kv_int(&e, "shirudo.map.snapshot.uncompressed_size_bytes",
		    (__s64)snapshot->json_bytes);
	otlp_kv_string(&e, "shirudo.map.snapshot.sha256",
		       snapshot->sha256_hex);
	json_arr_close(&e);
	log_close(&e);
	if (e.err || e.depth) {
		if (!e.err)
			e.err = -EBADMSG;
		xfree(buf, S3_REFERENCE_MAX);
		return e.err;
	}
	*out = buf;
	*out_len = e.len;
	return 0;
}

static void otel_s3_state_free(struct otel_s3_state *st)
{
	if (!st)
		return;
	if (st->otel)
		otel_close(st->otel);
	if (st->credentials) {
		memzero_explicit(st->credentials, st->credentials_len);
		xfree(st->credentials, st->credentials_len);
	}
	xfree(st, sizeof(*st));
}

static int otel_s3_open(const char *spec, const struct map_view *v,
			const struct otel_opts *opts,
			const char *decoder_path,
			void **state)
{
	struct otel_s3_state *st;
	void *otel = NULL;
	int ret;

	if (!v || !state || !spec || !spec[0])
		return -EINVAL;
	if (v->skipped)
		return -EOPNOTSUPP;
	if (v->truncated)
		return -E2BIG;
	st = xcalloc(1, sizeof(*st));
	if (!st)
		return -ENOMEM;
	st->opts.retries = 3;
	if (opts)
		st->opts = *opts;
	ret = parse_s3_spec(st, spec);
	if (ret)
		goto err;
	ret = validate_s3_endpoint(st);
	if (ret)
		goto err;
	ret = otel_open_common(st->opts.endpoint, v, &st->opts, false,
			       OTEL_LOG, decoder_path, &otel);
	if (ret)
		goto err;
	st->otel = otel;
	st->otel->s3_reference = true;
	*state = st;
	return 0;
err:
	otel_s3_state_free(st);
	return ret;
}

static int otel_s3_emit(void *state, const struct map_view *v)
{
	struct otel_s3_state *st = state;
	struct s3_snapshot snapshot = {};
	char url[S3_URL_MAX], uri[S3_URL_MAX];
	char *payload = NULL;
	size_t payload_len = 0;
	bool already_present;
	int ret;

	if (!st || !v)
		return -EINVAL;
	ret = build_s3_snapshot(st->otel ? st->otel->decoder_path : NULL,
				v, &snapshot);
	if (ret)
		return ret;
	ret = build_s3_urls(st, v, &snapshot, url, sizeof(url), uri,
			    sizeof(uri));
	if (ret)
		goto out;
	ret = s3_put(st, v, &snapshot, url, &already_present);
	if (ret)
		goto out;
	fprintf(stderr, "otel.s3: %s %s (%llu bytes)\n",
		already_present ? "found" : "uploaded", uri,
		snapshot.object_bytes);
	ret = build_s3_reference(v, &snapshot, uri, &payload, &payload_len);
	if (ret)
		goto out;
	ret = otel_post(st->otel, payload, payload_len);
out:
	xfree(payload, S3_REFERENCE_MAX);
	if (snapshot.file)
		fclose(snapshot.file);
	return ret;
}

static int otel_s3_close(void *state)
{
	otel_s3_state_free(state);
	return 0;
}

int upatch_maps_otel_send_file(const char *decoder_path,
			       const struct map_view *v,
			       enum otel_mode mode,
			       const struct otel_opts *opts)
{
	const char *endpoint = opts ? opts->endpoint : NULL;
	bool automatic = mode == OTEL_AUTO;
	enum otel_signal signal;
	void *state = NULL;
	int ret, close_rc;

	if (mode == OTEL_S3) {
		if (!opts || !opts->s3_uri)
			return -EINVAL;
		ret = otel_s3_open(opts->s3_uri, v, opts, decoder_path, &state);
		if (ret)
			return ret;
		ret = otel_s3_emit(state, v);
		close_rc = otel_s3_close(state);
		return ret ? ret : close_rc;
	}
	if (mode == OTEL_FORCE_LOG)
		signal = OTEL_LOG;
	else if (mode == OTEL_FORCE_METRIC)
		signal = OTEL_METRIC;
	else if (mode == OTEL_AUTO)
		signal = OTEL_LOG;
	else
		return -EINVAL;
	ret = otel_open_common(endpoint, v, opts, automatic, signal,
			       decoder_path, &state);
	if (ret)
		return ret;
	ret = otel_emit(state, v);
	close_rc = otel_close(state);
	return ret ? ret : close_rc;
}

int upatch_maps_otel_send(const struct map_view *v,
			  enum otel_mode mode,
			  const struct otel_opts *opts)
{
	return upatch_maps_otel_send_file(NULL, v, mode, opts);
}

int upatch_maps_otel_send_decoded(const struct map_view *v,
				  enum otel_signal signal,
				  const struct otel_opts *opts)
{
	int ret;

	if (signal == OTEL_LOG)
		ret = upatch_maps_otel_send(v, OTEL_FORCE_LOG,
					    opts);
	else if (signal == OTEL_METRIC)
		ret = upatch_maps_otel_send(v, OTEL_FORCE_METRIC,
					    opts);
	else
		return -EINVAL;
	if (ret == -E2BIG && opts && opts->s3_uri)
		return upatch_maps_otel_send(v, OTEL_S3, opts);
	return ret;
}
