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

#include <shirudo/misc.h>
#include <shirudo/string.h>
#include <shirudo/upatch.h>

#include <bpf/btf.h>
#include <curl/curl.h>
#include <zlib.h>

#include "crypto.h"
#include "hex.h"
#include "json.h"
#include "log.h"
#include "config.h"
#include "macros.h"
#include "malloc.h"
#include "paths.h"
#include "tenant_id.h"
#include "upatch_decode.h"
#include "upatch_maps_otel.h"
#include "version.h"

#define OTEL_ENDPOINT_MAX	2048
#define OTEL_RESPONSE_MAX	(64U * 1024U)
#define OTEL_DEFAULT_TIMEOUT_MS	10000L
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
	enum shirudo_otel_signal signal;
	struct shirudo_otel_opts opts;
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
	struct shirudo_otel_opts opts;
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

static int metric_type_from_view(const struct shirudo_map_view *v,
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

int shirudo_upatch_maps_otel_classify(const struct shirudo_map_view *v,
				      enum shirudo_otel_signal *signal,
				      char *reason, size_t reason_sz)
{
	struct metric_type mt;
	int rc;

	if (!v || !signal)
		return -EINVAL;
	*signal = SHIRUDO_OTEL_LOG;
	if (v->serialized) {
		snprintf(reason, reason_sz, "map uses a serializer");
		return 0;
	}
	if (v->skipped) {
		snprintf(reason, reason_sz, "map type is not generically readable");
		return 0;
	}
	if (!upatch_map_is_percpu(v->type)) {
		snprintf(reason, reason_sz, "map is not per-CPU");
		return 0;
	}
	rc = metric_type_from_view(v, &mt);
	if (rc) {
		snprintf(reason, reason_sz, "value is not a BTF integer scalar");
		return 0;
	}
	if (mt.is_signed) {
		snprintf(reason, reason_sz, "value is signed");
		return 0;
	}
	*signal = SHIRUDO_OTEL_METRIC;
	snprintf(reason, reason_sz, "unsigned per-CPU %u-bit scalar",
		 mt.width * 8);
	return 0;
}

static void otlp_kv_string(struct shirudo_json_emit *e, const char *key,
			   const char *value)
{
	json_obj_open(e);
	json_kv_string(e, "key", key);
	json_obj_open_key(e, "value");
	json_kv_string(e, "stringValue", value ? value : "");
	json_obj_close(e);
	json_obj_close(e);
}

static void otlp_kv_int(struct shirudo_json_emit *e, const char *key,
			__s64 value)
{
	char num[32];

	snprintf(num, sizeof(num), "%lld", value);
	json_obj_open(e);
	json_kv_string(e, "key", key);
	json_obj_open_key(e, "value");
	json_kv_string(e, "intValue", num);
	json_obj_close(e);
	json_obj_close(e);
}

static void otlp_kv_bool(struct shirudo_json_emit *e, const char *key,
			 bool value)
{
	json_obj_open(e);
	json_kv_string(e, "key", key);
	json_obj_open_key(e, "value");
	json_kv_bool(e, "boolValue", value);
	json_obj_close(e);
	json_obj_close(e);
}

static void otlp_kvlist_begin(struct shirudo_json_emit *e, const char *key)
{
	json_obj_open(e);
	json_kv_string(e, "key", key);
	json_obj_open_key(e, "value");
	json_obj_open_key(e, "kvlistValue");
	json_arr_open(e, "values");
}

static void otlp_kvlist_end(struct shirudo_json_emit *e)
{
	json_arr_close(e);
	json_obj_close(e);
	json_obj_close(e);
	json_obj_close(e);
}

static void otlp_array_begin(struct shirudo_json_emit *e, const char *key)
{
	json_obj_open(e);
	json_kv_string(e, "key", key);
	json_obj_open_key(e, "value");
	json_obj_open_key(e, "arrayValue");
	json_arr_open(e, "values");
}

static void otlp_array_end(struct shirudo_json_emit *e)
{
	json_arr_close(e);
	json_obj_close(e);
	json_obj_close(e);
	json_obj_close(e);
}

static void otlp_array_string(struct shirudo_json_emit *e, const char *value)
{
	json_obj_open(e);
	json_kv_string(e, "stringValue", value ? value : "");
	json_obj_close(e);
}

static void otlp_array_kvlist_begin(struct shirudo_json_emit *e)
{
	json_obj_open(e);
	json_obj_open_key(e, "kvlistValue");
	json_arr_open(e, "values");
}

static void otlp_array_kvlist_end(struct shirudo_json_emit *e)
{
	json_arr_close(e);
	json_obj_close(e);
	json_obj_close(e);
}

/*
 * Convert one ordinary JSON value into the OTLP JSON representation of an
 * AnyValue.  Status already has a stable JSON emitter, so keeping this
 * adapter here lets status and its machine-readable output share one source
 * of truth without duplicating every status field in an OTLP renderer.
 */
struct json_anyvalue_ctx {
	const char *p;
	const char *end;
	__u32 depth;
};

static void json_anyvalue_skip_ws(struct json_anyvalue_ctx *c)
{
	while (c->p < c->end && isspace((__u8)*c->p))
		c->p++;
}

static int json_anyvalue_string(struct json_anyvalue_ctx *c,
				const char **start, size_t *len)
{
	const char *p;

	if (c->p >= c->end || *c->p != '"')
		return -EINVAL;
	p = c->p++;
	while (c->p < c->end) {
		__u8 ch = (__u8)*c->p++;

		if (ch == '"') {
			*start = p;
			*len = (size_t)(c->p - p);
			return 0;
		}
		if (ch == '\\') {
			if (c->p >= c->end)
				return -EINVAL;
			ch = (__u8)*c->p++;
			if (ch == 'u') {
				int i;

				if ((size_t)(c->end - c->p) < 4)
					return -EINVAL;
				for (i = 0; i < 4; i++) {
					if (!isxdigit((__u8)c->p[i]))
						return -EINVAL;
				}
				c->p += 4;
			} else if (ch != '"' && ch != '\\' && ch != '/' &&
				   ch != 'b' && ch != 'f' && ch != 'n' &&
				   ch != 'r' && ch != 't') {
				return -EINVAL;
			}
		} else if (ch < 0x20) {
			return -EINVAL;
		}
	}
	return -EINVAL;
}

static int json_anyvalue_literal(struct json_anyvalue_ctx *c,
				 const char *literal)
{
	size_t len = strlen(literal);

	if ((size_t)(c->end - c->p) < len ||
	    memcmp(c->p, literal, len) != 0)
		return -EINVAL;
	c->p += len;
	return 0;
}

static int json_anyvalue_number(struct json_anyvalue_ctx *c,
				struct shirudo_json_emit *e)
{
	const char *start = c->p;
	bool fraction = false;
	size_t len;
	char number[128];

	if (c->p < c->end && *c->p == '-')
		c->p++;
	if (c->p >= c->end || !isdigit((__u8)*c->p))
		return -EINVAL;
	if (*c->p == '0') {
		c->p++;
	} else {
		while (c->p < c->end && isdigit((__u8)*c->p))
			c->p++;
	}
	if (c->p < c->end && *c->p == '.') {
		fraction = true;
		c->p++;
		if (c->p >= c->end || !isdigit((__u8)*c->p))
			return -EINVAL;
		while (c->p < c->end && isdigit((__u8)*c->p))
			c->p++;
	}
	if (c->p < c->end && (*c->p == 'e' || *c->p == 'E')) {
		fraction = true;
		c->p++;
		if (c->p < c->end && (*c->p == '+' || *c->p == '-'))
			c->p++;
		if (c->p >= c->end || !isdigit((__u8)*c->p))
			return -EINVAL;
		while (c->p < c->end && isdigit((__u8)*c->p))
			c->p++;
	}
	len = (size_t)(c->p - start);
	if (len == 0 || len >= sizeof(number))
		return -E2BIG;
	memcpy(number, start, len);
	number[len] = '\0';
	if (fraction)
		json_kv_string(e, "doubleValue", number);
	else
		json_kv_string(e, "intValue", number);
	return 0;
}

static int json_anyvalue_emit_contents(struct json_anyvalue_ctx *c,
				       struct shirudo_json_emit *e);

static int json_anyvalue_emit(struct json_anyvalue_ctx *c,
			      struct shirudo_json_emit *e);

static int json_anyvalue_object(struct json_anyvalue_ctx *c,
				struct shirudo_json_emit *e, bool wrap)
{
	int rc;

	if (c->depth++ >= SHIRUDO_JSON_MAX_DEPTH) {
		c->depth--;
		return -E2BIG;
	}
	c->p++;
	if (wrap)
		json_obj_open(e);
	json_obj_open_key(e, "kvlistValue");
	json_arr_open(e, "values");
	json_anyvalue_skip_ws(c);
	if (c->p < c->end && *c->p == '}') {
		c->p++;
		json_arr_close(e);
		json_obj_close(e);
		if (wrap)
			json_obj_close(e);
		c->depth--;
		return 0;
	}
	for (;;) {
		const char *key;
		size_t key_len;

		rc = json_anyvalue_string(c, &key, &key_len);
		if (rc)
			break;
		json_anyvalue_skip_ws(c);
		if (c->p >= c->end || *c->p++ != ':') {
			rc = -EINVAL;
			break;
		}
		json_anyvalue_skip_ws(c);
		json_obj_open(e);
		json_kv_raw(e, "key", key, key_len);
		json_obj_open_key(e, "value");
		rc = json_anyvalue_emit_contents(c, e);
		json_obj_close(e);
		json_obj_close(e);
		if (rc)
			break;
		json_anyvalue_skip_ws(c);
		if (c->p >= c->end) {
			rc = -EINVAL;
			break;
		}
		if (*c->p == '}') {
			c->p++;
			rc = 0;
			break;
		}
		if (*c->p++ != ',') {
			rc = -EINVAL;
			break;
		}
		json_anyvalue_skip_ws(c);
	}
	json_arr_close(e);
	json_obj_close(e);
	if (wrap)
		json_obj_close(e);
	c->depth--;
	return rc;
}

static int json_anyvalue_array(struct json_anyvalue_ctx *c,
			       struct shirudo_json_emit *e, bool wrap)
{
	int rc = 0;

	if (c->depth++ >= SHIRUDO_JSON_MAX_DEPTH) {
		c->depth--;
		return -E2BIG;
	}
	c->p++;
	if (wrap)
		json_obj_open(e);
	json_obj_open_key(e, "arrayValue");
	json_arr_open(e, "values");
	json_anyvalue_skip_ws(c);
	if (c->p < c->end && *c->p == ']') {
		c->p++;
	} else {
		for (;;) {
			json_anyvalue_skip_ws(c);
			rc = json_anyvalue_emit(c, e);
			if (rc)
				break;
			json_anyvalue_skip_ws(c);
			if (c->p >= c->end) {
				rc = -EINVAL;
				break;
			}
			if (*c->p == ']') {
				c->p++;
				break;
			}
			if (*c->p++ != ',') {
				rc = -EINVAL;
				break;
			}
		}
	}
	json_arr_close(e);
	json_obj_close(e);
	if (wrap)
		json_obj_close(e);
	c->depth--;
	return rc;
}

static int json_anyvalue_emit_contents(struct json_anyvalue_ctx *c,
				       struct shirudo_json_emit *e)
{
	const char *start;
	size_t len;
	int rc;

	json_anyvalue_skip_ws(c);
	if (c->p >= c->end)
		return -EINVAL;
	switch (*c->p) {
	case '{':
		return json_anyvalue_object(c, e, false);
	case '[':
		return json_anyvalue_array(c, e, false);
	case '"':
		rc = json_anyvalue_string(c, &start, &len);
		if (rc)
			return rc;
		json_kv_raw(e, "stringValue", start, len);
		return 0;
	case 't':
		rc = json_anyvalue_literal(c, "true");
		if (rc)
			return rc;
		json_kv_bool(e, "boolValue", true);
		return 0;
	case 'f':
		rc = json_anyvalue_literal(c, "false");
		if (rc)
			return rc;
		json_kv_bool(e, "boolValue", false);
		return 0;
	case 'n':
		rc = json_anyvalue_literal(c, "null");
		if (rc)
			return rc;
		/* An empty AnyValue is the OTLP JSON representation of null. */
		return 0;
	default:
		return json_anyvalue_number(c, e);
	}
}

static int json_anyvalue_emit(struct json_anyvalue_ctx *c,
			      struct shirudo_json_emit *e)
{
	int rc;

	json_obj_open(e);
	rc = json_anyvalue_emit_contents(c, e);
	json_obj_close(e);
	return rc;
}

static int json_anyvalue_from_document(struct shirudo_json_emit *e,
				       const char *json, size_t len, bool wrap)
{
	struct json_anyvalue_ctx c = {
		.p = json,
		.end = json + len,
	};
	int rc;

	if (!wrap && (c.p >= c.end || *c.p != '{'))
		return -EINVAL;
	rc = wrap ? json_anyvalue_emit(&c, e) :
		json_anyvalue_object(&c, e, false);
	if (rc)
		return rc;
	json_anyvalue_skip_ws(&c);
	return c.p == c.end ? 0 : -EINVAL;
}

static void emit_resource_attributes(struct shirudo_json_emit *e)
{
	char hostname[256] = "unknown";

	if (gethostname(hostname, sizeof(hostname)) != 0)
		snprintf(hostname, sizeof(hostname), "unknown");
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

static void u64_decimal(__u64 value, char out[32])
{
	snprintf(out, 32, "%llu", value);
}

static void emit_log_map_data(struct shirudo_json_emit *e,
			      const struct shirudo_map_view *v)
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
			const struct shirudo_serial_page *page = &v->serial_pages[p];
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
			xfree(hex, (size_t)page->bytes * 2 + 1);
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
		const struct shirudo_map_entry *en = &v->entries[i];
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
			     const struct shirudo_map_view *v,
			     size_t record_max,
			     char **out, size_t *out_len)
{
	struct shirudo_json_emit e = {};
	char *decoded = NULL;
	size_t decoded_len = 0;
	char now[32];
	char *buf;
	int decode_rc;

	buf = xmalloc(SHIRUDO_JSON_MAX_BYTES);
	if (!buf)
		return -ENOMEM;
	e.buf = buf;
	e.cap = SHIRUDO_JSON_MAX_BYTES;
	u64_decimal(realtime_ns(), now);

	json_obj_open(&e);
	json_arr_open(&e, "resourceLogs");
	json_obj_open(&e);
	json_obj_open_key(&e, "resource");
	emit_resource_attributes(&e);
	json_obj_close(&e);
	json_arr_open(&e, "scopeLogs");
	json_obj_open(&e);
	json_obj_open_key(&e, "scope");
	json_kv_string(&e, "name", "shirudo.upatch.maps");
	json_kv_string(&e, "version", shirudo_version);
	json_obj_close(&e);
	json_arr_open(&e, "logRecords");
	json_obj_open(&e);
	json_kv_string(&e, "timeUnixNano", now);
	json_kv_string(&e, "observedTimeUnixNano", now);
	json_kv_int(&e, "severityNumber", 9);
	json_kv_string(&e, "severityText", "INFO");
	json_kv_string(&e, "eventName", "shirudo.bpf.map.snapshot");
	decode_rc = path ? upatch_decode_map_file_otel(path, v,
							      &decoded, &decoded_len) :
			upatch_decode_map_otel(v, &decoded, &decoded_len);
	if (!decode_rc && record_max && decoded_len > record_max) {
		xfree(decoded, decoded_len + 1);
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
		xfree(buf, SHIRUDO_JSON_MAX_BYTES);
		return decode_rc;
	}
	xfree(decoded, decoded_len + 1);
	json_arr_open(&e, "attributes");
	otlp_kv_string(&e, "shirudo.upatch.name", v->upatch);
	otlp_kv_string(&e, "shirudo.upatch.location", v->location);
	otlp_kv_string(&e, "shirudo.map.name", v->name);
	otlp_kv_string(&e, "shirudo.map.type", v->type_name);
	otlp_kv_int(&e, "shirudo.map.max_entries", v->max_entries);
	otlp_kv_int(&e, "shirudo.map.n_entries", v->n_entries);
	otlp_kv_int(&e, "shirudo.map.n_cpus", v->n_cpus);
	otlp_kv_bool(&e, "shirudo.map.serialized", v->serialized);
	otlp_kv_bool(&e, "shirudo.map.truncated", v->truncated);
	json_arr_close(&e);
	json_obj_close(&e);
	json_arr_close(&e);
	json_obj_close(&e);
	json_arr_close(&e);
	json_obj_close(&e);
	json_arr_close(&e);
	json_obj_close(&e);

	if (e.err) {
		xfree(buf, SHIRUDO_JSON_MAX_BYTES);
		return e.err;
	}
	*out = buf;
	*out_len = e.len;
	return 0;
}

int shirudo_upatch_maps_otel_build_log_file(const char *path,
					    const struct shirudo_map_view *v,
					    char **out, size_t *out_len)
{
	if (!path)
		return -EINVAL;
	return build_log_payload(path, v, 0, out, out_len);
}

static int read_integer(const void *p, const struct metric_type *mt,
			__int128 *signed_out, unsigned __int128 *unsigned_out)
{
	__u64 u = 0;
	__s64 s = 0;

	memcpy(&u, p, mt->width);
	if (mt->is_signed) {
		switch (mt->width) {
		case 1:
			s = (__s8)u;
			break;
		case 2:
			s = (__s16)u;
			break;
		case 4:
			s = (__s32)u;
			break;
		case 8:
			memcpy(&s, p, 8);
			break;
		default:
			return -EOPNOTSUPP;
		}
		*signed_out = s;
	} else {
		*unsigned_out = u;
	}
	return 0;
}

static int entry_metric_value(const struct shirudo_map_view *v,
			      const struct shirudo_map_entry *en,
			      const struct metric_type *mt, __s64 *out)
{
	__u32 count = upatch_map_is_percpu(v->type) ?
		v->n_cpus : 1;
	__int128 signed_sum = 0;

	unsigned __int128 unsigned_sum = 0;
	__u32 stride = upatch_map_value_stride(v);
	__u32 i;

	for (i = 0; i < count; i++) {
		__int128 s = 0;

		unsigned __int128 u = 0;
		int rc = read_integer((const char *)en->value +
				      (size_t)i * stride, mt, &s, &u);

		if (rc)
			return rc;
		if (mt->is_signed)
			signed_sum += s;
		else
			unsigned_sum += u;
	}
	if (mt->is_signed) {
		if (signed_sum < INT64_MIN || signed_sum > INT64_MAX)
			return -ERANGE;
		*out = (__s64)signed_sum;
	} else {
		if (unsigned_sum > INT64_MAX)
			return -ERANGE;
		*out = (__s64)unsigned_sum;
	}
	return 0;
}

static bool valid_metric_name(const char *name)
{
	size_t i, n;

	if (!name || !isalpha((__u8)name[0]))
		return false;
	n = strlen(name);
	if (n == 0 || n > 255)
		return false;
	for (i = 1; i < n; i++) {
		__u8 c = (__u8)name[i];

		if (!isalnum(c) && c != '_' && c != '.' && c != '-' && c != '/')
			return false;
	}
	return true;
}

static int metric_name(const struct otel_state *st,
		       const struct shirudo_map_view *v, char out[256])
{
	size_t i;
	int n;

	if (st->opts.metric_name) {
		if (!valid_metric_name(st->opts.metric_name))
			return -EINVAL;
		if (strscpy(out, st->opts.metric_name, 256) < 0)
			return -ENAMETOOLONG;
		return 0;
	}
	n = snprintf(out, 256, "shirudo.%s.%s", v->upatch, v->name);
	if (n < 0 || n >= 256)
		return -ENAMETOOLONG;
	for (i = 0; out[i]; i++) {
		__u8 c = (__u8)out[i];

		if (!isalnum(c) && c != '_' && c != '.' && c != '-' && c != '/')
			out[i] = '_';
	}
	return 0;
}

static int map_start_ns(const struct shirudo_map_view *v, __u64 *out)
{
	char path[PATH_MAX];
	char bpffs_name[SHIRUDO_UPATCH_BPFFS_NAME_MAX + 1];
	struct stat st;

	if (v->lifetime_start_ns) {
		*out = v->lifetime_start_ns;
		return 0;
	}
	if (upatch_bpffs_name(bpffs_name, sizeof(bpffs_name), v->upatch))
		return -ENAMETOOLONG;
	if ((size_t)snprintf(path, sizeof(path), "%s/%s",
			     SHIRUDO_BPFFS_UPATCHES_DIR, bpffs_name) >=
	    sizeof(path))
		return -ENAMETOOLONG;
	if (stat(path, &st) != 0)
		return -errno;
	*out = (__u64)st.st_ctim.tv_sec * 1000000000ULL +
	       (__u64)st.st_ctim.tv_nsec;
	return 0;
}

static int validate_metric_view(const struct otel_state *st,
				const struct shirudo_map_view *v,
				struct metric_type *mt)
{
	int rc;

	if (v->serialized || v->skipped)
		return -EOPNOTSUPP;
	if (v->truncated)
		return -E2BIG;
	rc = metric_type_from_view(v, mt);
	if (rc)
		return rc;
	if (st->opts.metric_kind == SHIRUDO_OTEL_METRIC_COUNTER &&
	    mt->is_signed)
		return -EDOM;
	return 0;
}

static __attribute__((unused)) int build_metric_payload(const struct otel_state *st,
							const struct shirudo_map_view *v,
							char **out, size_t *out_len)
{
	struct shirudo_json_emit e = {};
	struct metric_type mt;
	char name[256], now[32], start[32];
	__u64 now_ns, start_ns = 0;
	char *buf;
	__u32 i;
	int rc;

	rc = validate_metric_view(st, v, &mt);
	if (rc)
		return rc;
	if (v->n_entries == 0) {
		*out = NULL;
		*out_len = 0;
		return 0;
	}
	rc = metric_name(st, v, name);
	if (rc)
		return rc;
	now_ns = realtime_ns();
	u64_decimal(now_ns, now);
	if (st->opts.metric_kind == SHIRUDO_OTEL_METRIC_COUNTER) {
		rc = map_start_ns(v, &start_ns);
		if (rc)
			return rc;
		u64_decimal(start_ns, start);
	}
	buf = xmalloc(SHIRUDO_JSON_MAX_BYTES);
	if (!buf)
		return -ENOMEM;
	e.buf = buf;
	e.cap = SHIRUDO_JSON_MAX_BYTES;

	json_obj_open(&e);
	json_arr_open(&e, "resourceMetrics");
	json_obj_open(&e);
	json_obj_open_key(&e, "resource");
	emit_resource_attributes(&e);
	json_obj_close(&e);
	json_arr_open(&e, "scopeMetrics");
	json_obj_open(&e);
	json_obj_open_key(&e, "scope");
	json_kv_string(&e, "name", "shirudo.upatch.maps");
	json_kv_string(&e, "version", shirudo_version);
	json_obj_close(&e);
	json_arr_open(&e, "metrics");
	json_obj_open(&e);
	json_kv_string(&e, "name", name);
	if (st->opts.metric_description && st->opts.metric_description[0])
		json_kv_string(&e, "description",
			       st->opts.metric_description);
	json_kv_string(&e, "unit",
		       st->opts.metric_unit ?: "1");
	json_obj_open_key(&e,
			  st->opts.metric_kind == SHIRUDO_OTEL_METRIC_COUNTER ?
				  "sum" : "gauge");
	if (st->opts.metric_kind == SHIRUDO_OTEL_METRIC_COUNTER) {
		json_kv_int(&e, "aggregationTemporality", 2);
		json_kv_bool(&e, "isMonotonic", true);
	}
	json_arr_open(&e, "dataPoints");
	for (i = 0; i < v->n_entries; i++) {
		const struct shirudo_map_entry *en = &v->entries[i];
		char value[32];
		char *key;
		__s64 point;

		rc = entry_metric_value(v, en, &mt, &point);
		if (rc) {
			xfree(buf, SHIRUDO_JSON_MAX_BYTES);
			return rc;
		}
		snprintf(value, sizeof(value), "%lld", point);
		key = upatch_map_format_cell(v, v->key_type_id,
					     en->key, v->key_size, v->btf_key_type);
		json_obj_open(&e);
		if (st->opts.metric_kind == SHIRUDO_OTEL_METRIC_COUNTER)
			json_kv_string(&e, "startTimeUnixNano", start);
		json_kv_string(&e, "timeUnixNano", now);
		json_kv_string(&e, "asInt", value);
		json_arr_open(&e, "attributes");
		otlp_kv_string(&e, "shirudo.map.key", key ?: "");
		otlp_kv_string(&e, "shirudo.upatch.name", v->upatch);
		otlp_kv_string(&e, "shirudo.upatch.location", v->location);
		otlp_kv_string(&e, "shirudo.map.name", v->name);
		otlp_kv_string(&e, "shirudo.map.type", v->type_name);
		json_arr_close(&e);
		json_obj_close(&e);
		xstrfree(key);
	}
	json_arr_close(&e);
	json_obj_close(&e);
	json_obj_close(&e);
	json_arr_close(&e);
	json_obj_close(&e);
	json_arr_close(&e);
	json_obj_close(&e);
	json_arr_close(&e);
	json_obj_close(&e);

	if (e.err) {
		xfree(buf, SHIRUDO_JSON_MAX_BYTES);
		return e.err;
	}
	*out = buf;
	*out_len = e.len;
	return 0;
}

static int build_metric_decoded_payload(const char *path,
					const struct shirudo_map_view *v,
					const struct shirudo_otel_opts *opts,
					char **out, size_t *out_len)
{
	struct shirudo_json_emit e = {};
	char *decoded = NULL, *decoded_buf, *buf;
	size_t decoded_len = 0, decoded_alloc_len;
	int rc;

	(void)opts;
	rc = path ? upatch_decode_map_file_json(path, v,
							&decoded, &decoded_len) :
		upatch_decode_map_json(v, &decoded, &decoded_len);
	if (rc)
		return rc;
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
	buf = xmalloc(SHIRUDO_JSON_MAX_BYTES);
	if (!buf) {
		xfree(decoded_buf, decoded_alloc_len + 1);
		return -ENOMEM;
	}
	e.buf = buf;
	e.cap = SHIRUDO_JSON_MAX_BYTES;
	json_obj_open(&e);
	json_arr_open(&e, "resourceMetrics");
	json_obj_open(&e);
	json_obj_open_key(&e, "resource");
	emit_resource_attributes(&e);
	json_obj_close(&e);
	json_arr_open(&e, "scopeMetrics");
	json_obj_open(&e);
	json_obj_open_key(&e, "scope");
	json_kv_string(&e, "name", "shirudo.upatch.maps");
	json_kv_string(&e, "version", shirudo_version);
	json_obj_close(&e);
	json_kv_raw(&e, "metrics", decoded, decoded_len);
	json_obj_close(&e);
	json_arr_close(&e);
	json_obj_close(&e);
	json_arr_close(&e);
	json_obj_close(&e);
	if (e.err) {
		xfree(buf, SHIRUDO_JSON_MAX_BYTES);
		xfree(decoded_buf, decoded_alloc_len + 1);
		return e.err;
	}
	xfree(decoded_buf, decoded_alloc_len + 1);
	*out = buf;
	*out_len = e.len;
	return 0;
}

static const char *signal_name(enum shirudo_otel_signal signal)
{
	return signal == SHIRUDO_OTEL_LOG ? "LOGS" : "METRICS";
}

static const char *signal_path(enum shirudo_otel_signal signal)
{
	return signal == SHIRUDO_OTEL_LOG ? "v1/logs" : "v1/metrics";
}

static const char *otel_env(enum shirudo_otel_signal signal,
			    const char *suffix)
{
	char name[128];
	const char *value;

	snprintf(name, sizeof(name), "OTEL_EXPORTER_OTLP_%s_%s",
		 signal_name(signal), suffix);
	value = getenv(name);
	if (value && value[0])
		return value;
	snprintf(name, sizeof(name), "OTEL_EXPORTER_OTLP_%s", suffix);
	value = getenv(name);
	return value && value[0] ? value : NULL;
}

static const char *otel_signal_env(enum shirudo_otel_signal signal,
				   const char *suffix)
{
	char name[128];
	const char *value;

	snprintf(name, sizeof(name), "OTEL_EXPORTER_OTLP_%s_%s",
		 signal_name(signal), suffix);
	value = getenv(name);
	return value && value[0] ? value : NULL;
}

static int append_signal_path(const char *base, enum shirudo_otel_signal signal,
			      char *out, size_t out_sz)
{
	const char *tail;
	size_t prefix_len;
	const char *slash;
	int n;

	if (!base || !base[0])
		return -EINVAL;
	tail = strpbrk(base, "?#");
	prefix_len = tail ? (size_t)(tail - base) : strlen(base);
	if (prefix_len == 0)
		return -EINVAL;
	slash = base[prefix_len - 1] == '/' ? "" : "/";
	n = snprintf(out, out_sz, "%.*s%s%s%s", (int)prefix_len, base,
		     slash, signal_path(signal), tail ? tail : "");

	return n < 0 || (size_t)n >= out_sz ? -ENAMETOOLONG : 0;
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
	int rc = 0;

	if (!url)
		return -ENOMEM;
	uc = curl_url_set(url, CURLUPART_URL, st->endpoint, 0);
	if (uc)
		return curl_url_cleanup(url), -EINVAL;
	if (curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) ||
	    curl_url_get(url, CURLUPART_HOST, &host, 0)) {
		rc = -EINVAL;
		goto out;
	}
	(void)curl_url_get(url, CURLUPART_USER, &user, 0);
	(void)curl_url_get(url, CURLUPART_PASSWORD, &password, 0);
	if ((user && user[0]) || (password && password[0])) {
		rc = -EINVAL;
		goto out;
	}
	if (strscpy(st->host, host, sizeof(st->host)) < 0) {
		rc = -ENAMETOOLONG;
		goto out;
	}
	if (strcmp(scheme, "http") == 0) {
		if (!loopback_host(host) && !st->opts.allow_insecure) {
			rc = -EPERM;
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
		rc = -EPROTONOSUPPORT;
	}
out:
	curl_free(scheme);
	curl_free(host);
	curl_free(user);
	curl_free(password);
	curl_url_cleanup(url);
	return rc;
}

static int
shirudo_upatch_maps_otel_build_metric(const struct shirudo_map_view *v,
				      const struct shirudo_otel_opts *opts,
				      char **out, size_t *out_len)
{
	return build_metric_decoded_payload(NULL, v, opts, out, out_len);
}

int shirudo_upatch_maps_otel_build_metric_file(const char *path,
					       const struct shirudo_map_view *v,
					       const struct shirudo_otel_opts *opts,
					       char **out, size_t *out_len)
{
	if (!path)
		return -EINVAL;
	return build_metric_decoded_payload(path, v, opts, out, out_len);
}

static int parse_timeout(const char *value, long *out)
{
	__u64 n;

	if (!value) {
		*out = OTEL_DEFAULT_TIMEOUT_MS;
		return 0;
	}
	if (parse_u64(value, strlen(value), LONG_MAX, &n))
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
			if (hi < 0 || lo < 0)
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

static int add_configured_headers(struct otel_state *st, const char *input)
{
	char *copy, *save = NULL, *pair;
	size_t total = input ? strlen(input) : 0;
	bool tenant_seen = false;
	int rc = 0;

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
		bool tenant;
		size_t n;

		if (!eq) {
			rc = -EINVAL;
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
		tenant = strcasecmp(name, "x-tenant-id") == 0;
		if (!name[0] || reserved_header(name) ||
		    percent_decode(value) != 0 || strpbrk(name, "\r\n:") ||
		    strpbrk(value, "\r\n")) {
			rc = -EINVAL;
			break;
		}
		if (tenant) {
			if (st->opts.tenant_id)
				continue;
			if (tenant_seen || !tenant_id_valid(value)) {
				rc = -EINVAL;
				break;
			}
			tenant_seen = true;
			name = "X-Tenant-ID";
		}
		n = strlen(name) + strlen(value) + 3;
		line = xmalloc(n);
		if (!line) {
			rc = -ENOMEM;
			break;
		}
		snprintf(line, n, "%s: %s", name, value);
		rc = append_header(st, line);
		explicit_bzero(line, n);
		xfree(line, n);
		if (rc)
			break;
	}
	explicit_bzero(copy, total);
	xfree(copy, total + 1);
	return rc;
}

static int configure_state(struct otel_state *st, const char *spec,
			   bool spec_is_base)
{
	const char *protocol = otel_env(st->signal, "PROTOCOL");
	const char *compression = otel_env(st->signal, "COMPRESSION");
	const char *headers = otel_env(st->signal, "HEADERS");
	int rc;

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
	rc = parse_timeout(otel_env(st->signal, "TIMEOUT"), &st->timeout_ms);
	if (rc)
		return rc;
	rc = resolve_endpoint(st, spec, spec_is_base);
	if (rc)
		return rc;
	rc = validate_endpoint_security(st);
	if (rc)
		return rc;
	rc = append_header(st, "Content-Type: application/json");
	if (rc)
		return rc;
	if (st->gzip) {
		rc = append_header(st, "Content-Encoding: gzip");
		if (rc)
			return rc;
	}
	rc = add_configured_headers(st, headers);
	if (rc || !st->opts.tenant_id)
		return rc;
	if (!tenant_id_valid(st->opts.tenant_id))
		return -EINVAL;
	{
		char line[sizeof("X-Tenant-ID: ") + SHIRUDO_TENANT_ID_MAX];

		snprintf(line, sizeof(line), "X-Tenant-ID: %s",
			 st->opts.tenant_id);
		return append_header(st, line);
	}
}

static size_t response_write(char *ptr, size_t size, size_t nmemb, void *ctx)
{
	struct otel_response *r = ctx;
	size_t n = size * nmemb;

	if (n > sizeof(r->buf) - 1 - r->len)
		return 0;
	memcpy(r->buf + r->len, ptr, n);
	r->len += n;
	r->buf[r->len] = '\0';
	return n;
}

static size_t response_header(char *ptr, size_t size, size_t nmemb, void *ctx)
{
	struct otel_response *r = ctx;
	size_t n = size * nmemb;
	static const char prefix[] = "Retry-After:";

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
			if (!shirudo_otel_retry_after(value, time(NULL), &seconds)) {
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
	size_t cap = compressBound(in_len) + 32;
	__u8 *buf;
	int zr;

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

int shirudo_status_otel_severity(const char *status, const char **text)
{
	if (strcmp(status, "ok") == 0) {
		*text = "INFO";
		return 9;
	}
	if (strcmp(status, "degraded") == 0 ||
	    strcmp(status, "init-pending") == 0) {
		*text = "WARN";
		return 13;
	}
	*text = "ERROR";
	return 17;
}

int shirudo_otel_retry_after(const char *value, time_t now, __u64 *seconds)
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
		*seconds = delay > 30 ? 30 : delay;
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
	*seconds = delay > 30 ? 30 : delay;
	return 0;
}

/*
 * The proto3 JSON mapping lets a receiver send the rejected count as a
 * string or a number, and the message is advisory: one that does not
 * fit is left out rather than failing an export the collector took.
 */
static int check_partial_success(enum shirudo_otel_signal signal,
				 const char *body, size_t len)
{
	const char *count = signal == SHIRUDO_OTEL_LOG ?
			    "rejectedLogRecords" : "rejectedDataPoints";
	char rejected_text[32] = {};
	char error[256] = {};
	struct shirudo_json_field partial[] = {
		{ count, SHIRUDO_JSON_T_STRING, rejected_text,
		  sizeof(rejected_text), 0, NULL, 0 },
	};
	struct shirudo_json_field root[] = {
		{ "partialSuccess", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0,
		  partial, ARRAY_SIZE(partial) },
	};
	__s64 rejected = 0;
	int rc;

	if (len == 0)
		return 0;
	rc = json_parse(body, len, root, ARRAY_SIZE(root));
	if (rc) {
		partial[0] = (struct shirudo_json_field){
			count, SHIRUDO_JSON_T_INT, &rejected, 0, 0, NULL, 0 };
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
		partial[0] = (struct shirudo_json_field){
			"errorMessage", SHIRUDO_JSON_T_STRING, error,
			sizeof(error), 0, NULL, 0 };
		if (json_parse(body, len, root, ARRAY_SIZE(root)))
			error[0] = '\0';
		pr_err("otel: Collector partially rejected %lld %s%s%s",
		       rejected, signal == SHIRUDO_OTEL_LOG ? "log record(s)" :
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
	__u32 cap_ms = 250U << (retry > 4 ? 4 : retry);
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

static int otel_post(struct otel_state *st, const char *json, size_t json_len)
{
	__u8 *compressed = NULL;
	const void *body = json;
	size_t body_len = json_len, compressed_cap = 0;
	__u32 attempt, max_attempts = st->opts.retries + 1;
	int rc = -EIO;

	if (!st->s3_reference && st->opts.otlp_max_bytes &&
	    json_len > st->opts.otlp_max_bytes)
		return -E2BIG;
	if (st->gzip) {
		rc = gzip_data(json, json_len, &compressed, &body_len);
		if (rc)
			return rc;
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
			rc = -ENOMEM;
			break;
		}
		curl_easy_setopt(curl, CURLOPT_URL, st->endpoint);
		curl_easy_setopt(curl, CURLOPT_POST, 1L);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
				 (curl_off_t)body_len);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, st->headers);
		curl_easy_setopt(curl, CURLOPT_USERAGENT,
				 "Shirudo OTel-OTLP-Exporter-C/1");
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
			rc = -EINVAL;
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
			rc = check_partial_success(st->signal, response.buf,
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
		rc = cc == CURLE_OPERATION_TIMEDOUT ? -ETIMEDOUT :
		     cc != CURLE_OK ? -EHOSTUNREACH : -EREMOTEIO;
		curl_easy_cleanup(curl);
		if (!retry || attempt + 1 == max_attempts)
			break;
		retry_wait(attempt, response.retry_after,
			   response.retry_after_valid);
	}
	if (compressed)
		xfree(compressed, compressed_cap);
	return rc;
}

static int otel_open_transport(enum shirudo_otel_signal signal,
			       const char *spec,
			       const struct shirudo_otel_opts *opts,
			       const char *decoder_path, void **state)
{
	struct otel_state *st;
	int rc;

	if (!state)
		return -EINVAL;
	st = xcalloc(1, sizeof(*st));
	if (!st)
		return -ENOMEM;
	st->signal = signal;
	st->opts.retries = 3;
	st->opts.metric_kind = SHIRUDO_OTEL_METRIC_COUNTER;
	if (opts)
		st->opts = *opts;
	/* Callers without the configuration leave the limits at 0. */
	if (!st->opts.otlp_max_bytes)
		st->opts.otlp_max_bytes = SHIRUDO_MAP_EXPORT_OTLP_MAX_DEFAULT;
	if (!st->opts.log_record_max_bytes)
		st->opts.log_record_max_bytes =
			SHIRUDO_MAP_EXPORT_LOG_RECORD_MAX_DEFAULT;
	st->decoder_path = decoder_path;
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
		rc = -EIO;
		goto err;
	}
	/* Explicit CLI/config endpoints are base URLs for the selected signal. */
	rc = configure_state(st, spec, true);
	if (rc)
		goto err_global;
	*state = st;
	return 0;

err_global:
	curl_global_cleanup();
err:
	curl_slist_free_all(st->headers);
	xfree(st, sizeof(*st));
	return rc;
}

static int otel_open_common(const char *spec, const struct shirudo_map_view *v,
			    const struct shirudo_otel_opts *opts,
			    bool automatic, enum shirudo_otel_signal forced,
			    const char *decoder_path, void **state)
{
	enum shirudo_otel_signal signal;
	char reason[160];
	int rc;

	if (!v || !state)
		return -EINVAL;
	if (automatic) {
		rc = shirudo_upatch_maps_otel_classify(v, &signal,
						       reason, sizeof(reason));
		if (rc)
			return rc;
		fprintf(stderr, "otel: selected %s for %s map %s: %s\n",
			signal == SHIRUDO_OTEL_LOG ? "log" : "metric",
			v->type_name, v->name, reason);
		if (signal == SHIRUDO_OTEL_LOG && opts &&
		    (opts->metric_kind_set || opts->metric_name ||
		     opts->metric_unit || opts->metric_description)) {
			return -EINVAL;
		}
	} else {
		signal = forced;
	}
	return otel_open_transport(signal, spec, opts, decoder_path, state);
}

static int otel_emit(void *state, const struct shirudo_map_view *v)
{
	struct otel_state *st = state;
	char *payload = NULL;
	size_t len = 0;
	int rc;

	if (!st || !v)
		return -EINVAL;
	if (st->signal == SHIRUDO_OTEL_LOG)
		rc = build_log_payload(st->decoder_path, v,
				       st->opts.log_record_max_bytes,
				       &payload, &len);
	else if (st->decoder_path)
		rc = shirudo_upatch_maps_otel_build_metric_file(st->decoder_path, v,
								&st->opts,
								&payload, &len);
	else
		rc = shirudo_upatch_maps_otel_build_metric(v, &st->opts,
							   &payload, &len);
	if (rc)
		return rc;
	if (!payload) {
		fprintf(stderr, "otel: metric map %s has no data points; "
			"nothing exported\n", v->name);
		return 0;
	}
	rc = otel_post(st, payload, len);
	xfree(payload, SHIRUDO_JSON_MAX_BYTES);
	return rc;
}

static int otel_close(void *state)
{
	struct otel_state *st = state;

	if (!st)
		return 0;
	curl_slist_free_all(st->headers);
	xfree(st, sizeof(*st));
	curl_global_cleanup();
	return 0;
}

static size_t generic_log_capacity(size_t body_len)
{
	if (body_len > (SIZE_MAX - 65536) / 4)
		return 0;
	return body_len * 4 + 65536;
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
	struct shirudo_json_emit e = {};
	char now[32];
	char *buf;
	int rc;
	size_t cap;

	if (!scope_name || !event_name || !severity_text || !body_json ||
	    !out || !out_len || !alloc_len)
		return -EINVAL;
	cap = generic_log_capacity(body_len);
	if (!cap)
		return -EOVERFLOW;
	buf = xmalloc(cap);
	if (!buf)
		return -ENOMEM;
	e.buf = buf;
	e.cap = cap;
	u64_decimal(realtime_ns(), now);

	json_obj_open(&e);
	json_arr_open(&e, "resourceLogs");
	json_obj_open(&e);
	json_obj_open_key(&e, "resource");
	emit_resource_attributes(&e);
	json_obj_close(&e);
	json_arr_open(&e, "scopeLogs");
	json_obj_open(&e);
	json_obj_open_key(&e, "scope");
	json_kv_string(&e, "name", scope_name);
	json_kv_string(&e, "version", shirudo_version);
	json_obj_close(&e);
	json_arr_open(&e, "logRecords");
	json_obj_open(&e);
	json_kv_string(&e, "timeUnixNano", now);
	json_kv_string(&e, "observedTimeUnixNano", now);
	json_kv_int(&e, "severityNumber", severity_number);
	json_kv_string(&e, "severityText", severity_text);
	json_kv_string(&e, "eventName", event_name);
	json_obj_open_key(&e, "body");
	rc = json_anyvalue_from_document(&e, body_json, body_len, false);
	json_obj_close(&e);
	if (rc) {
		xfree(buf, cap);
		return rc;
	}
	json_arr_open(&e, "attributes");
	if (status)
		otlp_kv_string(&e, "shirudo.status", status);
	if (version_id)
		otlp_kv_string(&e, "shirudo.version_id", version_id);
	if (tamper_attempts >= 0)
		otlp_kv_int(&e, "shirudo.tamper_attempts", tamper_attempts);
	json_arr_close(&e);
	json_obj_close(&e);
	json_arr_close(&e);
	json_obj_close(&e);
	json_arr_close(&e);
	json_obj_close(&e);
	json_arr_close(&e);
	json_obj_close(&e);
	if (e.err) {
		xfree(buf, cap);
		return e.err;
	}
	*out = buf;
	*out_len = e.len;
	*alloc_len = cap;
	return 0;
}

int shirudo_otel_send_log_json(const struct shirudo_otel_opts *opts,
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
	int rc;

	rc = otel_open_transport(SHIRUDO_OTEL_LOG,
				 opts ? opts->endpoint : NULL, opts, NULL, &state);
	if (rc)
		return rc;
	rc = build_generic_log_payload(scope_name, event_name,
				       severity_number, severity_text,
				       status, version_id,
				       tamper_attempts,
				       body_json, body_len,
				       &payload, &payload_len, &alloc_len);
	if (!rc)
		rc = otel_post(state, payload, payload_len);
	if (payload)
		xfree(payload, alloc_len);
	otel_close(state);
	return rc;
}

struct snapshot_writer {
	FILE		*file;
	z_stream	z;
	gz_header	header;
	struct shirudo_sha256_ctx md;
	__u64		json_bytes;
	__u64		object_bytes;
	bool		deflate_ready;
};

static int snapshot_temp_file(FILE **out)
{
	const char *tmpdir = getenv("TMPDIR");
	char path[PATH_MAX];
	FILE *file;
	int fd, n;

	if (!tmpdir || !tmpdir[0])
		tmpdir = "/tmp";
	n = snprintf(path, sizeof(path), "%s/%s", tmpdir,
		     "shirudo-map-snapshot.XXXXXX");
	if (n < 0 || (size_t)n >= sizeof(path))
		return -ENAMETOOLONG;
	fd = mkstemp(path);
	if (fd < 0)
		return -errno;
	if (fchmod(fd, 0600) != 0) {
		int rc = -errno;

		unlink(path);
		close(fd);
		return rc;
	}
	if (unlink(path) != 0) {
		int rc = -errno;

		close(fd);
		return rc;
	}
	file = fdopen(fd, "w+b");
	if (!file) {
		int rc = -errno;

		close(fd);
		return rc;
	}
	*out = file;
	return 0;
}

static int snapshot_write_compressed(struct snapshot_writer *w,
				     const __u8 *data, size_t len)
{
	if (UINT64_MAX - w->object_bytes < len)
		return -EOVERFLOW;
	if (len && fwrite(data, 1, len, w->file) != len)
		return -EIO;
	if (len && sha256_update(&w->md, data, len) != 0)
		return -EIO;
	w->object_bytes += len;
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

	if (UINT64_MAX - w->json_bytes < len)
		return -EOVERFLOW;
	w->json_bytes += len;
	while (len) {
		uInt chunk = len > UINT_MAX ? UINT_MAX : (uInt)len;

		w->z.next_in = (__u8 *)data;
		w->z.avail_in = chunk;
		while (w->z.avail_in) {
			size_t produced;
			int rc, zr;

			w->z.next_out = out;
			w->z.avail_out = sizeof(out);
			zr = deflate(&w->z, Z_NO_FLUSH);
			if (zr != Z_OK)
				return -EIO;
			produced = sizeof(out) - w->z.avail_out;
			rc = snapshot_write_compressed(w, out, produced);
			if (rc)
				return rc;
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
	int zr, rc;

	do {
		size_t produced;

		w->z.next_out = out;
		w->z.avail_out = sizeof(out);
		zr = deflate(&w->z, Z_FINISH);
		if (zr != Z_OK && zr != Z_STREAM_END)
			return -EIO;
		produced = sizeof(out) - w->z.avail_out;
		rc = snapshot_write_compressed(w, out, produced);
		if (rc)
			return rc;
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
	for (size_t i = 0; i < sizeof(snapshot->sha256); i++)
		snprintf(snapshot->sha256_hex + i * 2, 3, "%02x",
			 snapshot->sha256[i]);
	if (base64_encode(snapshot->sha256, sizeof(snapshot->sha256),
			  snapshot->sha256_b64,
			  sizeof(snapshot->sha256_b64)) != 0)
		return -EIO;
	snapshot->sha256_b64[44] = '\0';
	return 0;
}

static int build_s3_snapshot(const char *decoder_path,
			     const struct shirudo_map_view *v,
			     struct s3_snapshot *snapshot)
{
	struct snapshot_writer writer;
	char *decoded = NULL;
	size_t decoded_len = 0;
	int rc;

	memset(snapshot, 0, sizeof(*snapshot));
	/* S3 stores exactly the canonical value returned by the signed decoder. */
	if (decoder_path)
		rc = upatch_decode_map_file_json_limit(decoder_path, v,
						       S3_DECODER_JSON_MAX_BYTES,
						       &decoded,
						       &decoded_len);
	else
		rc = upatch_decode_map_json_limit(v,
						  S3_DECODER_JSON_MAX_BYTES,
						  &decoded,
						  &decoded_len);
	if (rc)
		return rc;
	rc = snapshot_temp_file(&snapshot->file);
	if (rc) {
		xfree(decoded, decoded_len + 1);
		return rc;
	}
	rc = snapshot_writer_init(&writer, snapshot->file);
	if (rc) {
		xfree(decoded, decoded_len + 1);
		goto err_writer;
	}
	rc = snapshot_json_sink(&writer, decoded, decoded_len);
	xfree(decoded, decoded_len + 1);
	if (rc)
		goto err_writer;
	rc = snapshot_writer_finish(&writer, snapshot);
	if (rc)
		goto err_writer;
	return 0;

err_writer:
	snapshot_writer_abort(&writer);
	fclose(snapshot->file);
	snapshot->file = NULL;
	return rc;
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
	if (strlen(access) > SIZE_MAX - strlen(secret) - 2)
		return -EOVERFLOW;
	credentials_len = strlen(access) + strlen(secret) + 2;
	st->credentials = xmalloc(credentials_len);
	if (!st->credentials)
		return -ENOMEM;
	st->credentials_len = credentials_len;
	snprintf(st->credentials, credentials_len, "%s:%s", access, secret);
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
	int rc = 0;

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
		rc = -EINVAL;
		goto out;
	}
	(void)curl_url_get(url, CURLUPART_USER, &user, 0);
	(void)curl_url_get(url, CURLUPART_PASSWORD, &password, 0);
	if ((user && user[0]) || (password && password[0]) ||
	    strchr(st->endpoint, '?') || strchr(st->endpoint, '#')) {
		rc = -EINVAL;
		goto out;
	}
	if (strlen(host) >= sizeof(st->host)) {
		rc = -ENAMETOOLONG;
		goto out;
	}
	if (strscpy(st->host, host, sizeof(st->host)) < 0) {
		rc = -ENAMETOOLONG;
		goto out;
	}
	if (strcmp(scheme, "http") == 0) {
		if (!loopback_host(host) && !st->opts.allow_insecure) {
			rc = -EPERM;
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
		rc = -EPROTONOSUPPORT;
	}
out:
	curl_free(scheme);
	curl_free(host);
	curl_free(user);
	curl_free(password);
	curl_url_cleanup(url);
	return rc;
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
			 const struct shirudo_map_view *v,
			 const struct s3_snapshot *snapshot,
			 char *url, size_t url_sz, char *uri, size_t uri_sz)
{
	char hostname[256] = "unknown";
	char key[S3_URL_MAX], escaped[S3_URL_MAX];
	int n, rc;

	if (gethostname(hostname, sizeof(hostname)) != 0)
		snprintf(hostname, sizeof(hostname), "unknown");
	hostname[sizeof(hostname) - 1] = '\0';
	safe_key_segment(hostname);
	n = snprintf(key, sizeof(key), "%s%s%s/%s/%s/%s.json.gz",
		     st->prefix, st->prefix[0] ? "/" : "", hostname,
		     v->upatch, v->name, snapshot->sha256_hex);
	if (n < 0 || (size_t)n >= sizeof(key))
		return -ENAMETOOLONG;
	if ((size_t)n > S3_KEY_MAX)
		return -ENAMETOOLONG;
	rc = escape_s3_path(key, escaped, sizeof(escaped));
	if (rc)
		return rc;
	n = snprintf(uri, uri_sz, "s3://%s/%s", st->bucket, escaped);
	if (n < 0 || (size_t)n >= uri_sz)
		return -ENAMETOOLONG;
	if (st->custom_endpoint)
		n = snprintf(url, url_sz, "%s/%s/%s", st->endpoint,
			     st->bucket, escaped);
	else if (strchr(st->bucket, '.'))
		n = snprintf(url, url_sz, "https://s3.%s.amazonaws.com/%s/%s",
			     st->region, st->bucket, escaped);
	else
		n = snprintf(url, url_sz, "https://%s.s3.%s.amazonaws.com/%s",
			     st->bucket, st->region, escaped);
	return n < 0 || (size_t)n >= url_sz ? -ENAMETOOLONG : 0;
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
		      const struct shirudo_map_view *v,
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
	int rc;

	snprintf(sha256, sizeof(sha256), "x-amz-content-sha256: %s",
		 snapshot->sha256_hex);
	snprintf(checksum, sizeof(checksum), "x-amz-checksum-sha256: %s",
		 snapshot->sha256_b64);
	snprintf(upatch, sizeof(upatch), "x-amz-meta-shirudo-upatch: %s",
		 v->upatch);
	snprintf(map, sizeof(map), "x-amz-meta-shirudo-map: %s", v->name);
	for (size_t i = 0; i < ARRAY_SIZE(lines); i++) {
		rc = s3_header(out, lines[i]);
		if (rc)
			return rc;
	}
	/* STS session tokens run well past a kilobyte. */
	if (st->session_token) {
		size_t len = strlen("x-amz-security-token: ") +
			     strlen(st->session_token) + 1;
		char *token = xmalloc(len);

		if (!token)
			return -ENOMEM;
		snprintf(token, len, "x-amz-security-token: %s",
			 st->session_token);
		rc = s3_header(out, token);
		xfree(token, len);
		if (rc)
			return rc;
	}
	return 0;
}

static bool retryable_s3_http(long status)
{
	return status == 408 || status == 409 || status == 500 ||
	       retryable_http(status);
}

static int s3_put(struct otel_s3_state *st,
		  const struct shirudo_map_view *v,
		  struct s3_snapshot *snapshot, const char *url,
		  bool *already_present)
{
	struct curl_slist *headers = NULL;
	char sigv4[128];
	__u32 max_attempts = st->opts.retries + 1;
	int rc;

	*already_present = false;
	rc = s3_headers(st, v, snapshot, &headers);
	if (rc) {
		curl_slist_free_all(headers);
		return rc;
	}
	if (snprintf(sigv4, sizeof(sigv4), "aws:amz:%s:s3", st->region) >=
	    (int)sizeof(sigv4)) {
		rc = -ENAMETOOLONG;
		goto out;
	}
	for (__u32 attempt = 0; attempt < max_attempts; attempt++) {
		struct otel_response response = {};
		CURL *curl = curl_easy_init();
		CURLcode cc;
		long status = 0;
		bool retry;

		if (!curl) {
			rc = -ENOMEM;
			break;
		}
		clearerr(snapshot->file);
		if (fseeko(snapshot->file, 0, SEEK_SET) != 0) {
			curl_easy_cleanup(curl);
			rc = -EIO;
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
				 "Shirudo-S3-Exporter-C/1");
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
			rc = -EINVAL;
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
			rc = 0;
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
		rc = cc == CURLE_OPERATION_TIMEDOUT ? -ETIMEDOUT :
		     cc != CURLE_OK ? -EHOSTUNREACH : -EREMOTEIO;
		curl_easy_cleanup(curl);
		if (!retry || attempt + 1 == max_attempts)
			break;
		retry_wait(attempt, response.retry_after,
			   response.retry_after_valid);
	}
out:
	curl_slist_free_all(headers);
	return rc;
}

static int build_s3_reference(const struct shirudo_map_view *v,
			      const struct s3_snapshot *snapshot,
			      const char *uri, char **out, size_t *out_len)
{
	struct shirudo_json_emit e = {};
	char now[32], description[S3_URL_MAX + 64];
	char *buf = xmalloc(S3_REFERENCE_MAX);

	if (!buf)
		return -ENOMEM;
	e.buf = buf;
	e.cap = S3_REFERENCE_MAX;
	u64_decimal(realtime_ns(), now);
	snprintf(description, sizeof(description),
		 "BPF map snapshot stored in S3: %s", uri);
	json_obj_open(&e);
	json_arr_open(&e, "resourceLogs");
	json_obj_open(&e);
	json_obj_open_key(&e, "resource");
	emit_resource_attributes(&e);
	json_obj_close(&e);
	json_arr_open(&e, "scopeLogs");
	json_obj_open(&e);
	json_obj_open_key(&e, "scope");
	json_kv_string(&e, "name", "shirudo.upatch.maps");
	json_kv_string(&e, "version", shirudo_version);
	json_obj_close(&e);
	json_arr_open(&e, "logRecords");
	json_obj_open(&e);
	json_kv_string(&e, "timeUnixNano", now);
	json_kv_string(&e, "observedTimeUnixNano", now);
	json_kv_int(&e, "severityNumber", 9);
	json_kv_string(&e, "severityText", "INFO");
	json_kv_string(&e, "eventName",
		       "shirudo.bpf.map.snapshot.reference");
	json_obj_open_key(&e, "body");
	json_kv_string(&e, "stringValue", description);
	json_obj_close(&e);
	json_arr_open(&e, "attributes");
	otlp_kv_string(&e, "shirudo.upatch.name", v->upatch);
	otlp_kv_string(&e, "shirudo.upatch.location", v->location);
	otlp_kv_string(&e, "shirudo.map.name", v->name);
	otlp_kv_string(&e, "shirudo.map.type", v->type_name);
	otlp_kv_int(&e, "shirudo.map.max_entries", v->max_entries);
	otlp_kv_int(&e, "shirudo.map.n_entries", v->n_entries);
	otlp_kv_int(&e, "shirudo.map.n_cpus", v->n_cpus);
	otlp_kv_bool(&e, "shirudo.map.serialized", v->serialized);
	otlp_kv_bool(&e, "shirudo.map.truncated", v->truncated);
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
	json_obj_close(&e);
	json_arr_close(&e);
	json_obj_close(&e);
	json_arr_close(&e);
	json_obj_close(&e);
	json_arr_close(&e);
	json_obj_close(&e);
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
		explicit_bzero(st->credentials, st->credentials_len);
		xfree(st->credentials, st->credentials_len);
	}
	xfree(st, sizeof(*st));
}

static int otel_s3_open(const char *spec, const struct shirudo_map_view *v,
			const struct shirudo_otel_opts *opts,
			const char *decoder_path,
			void **state)
{
	struct otel_s3_state *st;
	void *otel = NULL;
	int rc;

	if (!v || !state || !spec || !spec[0])
		return -EINVAL;
	if (v->skipped)
		return -EOPNOTSUPP;
	if (v->truncated)
		return -E2BIG;
	if (opts && (opts->metric_kind_set || opts->metric_name ||
		     opts->metric_unit || opts->metric_description))
		return -EINVAL;
	st = xcalloc(1, sizeof(*st));
	if (!st)
		return -ENOMEM;
	st->opts.retries = 3;
	st->opts.metric_kind = SHIRUDO_OTEL_METRIC_COUNTER;
	if (opts)
		st->opts = *opts;
	rc = parse_s3_spec(st, spec);
	if (rc)
		goto err;
	rc = validate_s3_endpoint(st);
	if (rc)
		goto err;
	rc = otel_open_common(st->opts.endpoint, v, &st->opts, false,
			      SHIRUDO_OTEL_LOG, decoder_path, &otel);
	if (rc)
		goto err;
	st->otel = otel;
	st->otel->s3_reference = true;
	*state = st;
	return 0;
err:
	otel_s3_state_free(st);
	return rc;
}

static int otel_s3_emit(void *state, const struct shirudo_map_view *v)
{
	struct otel_s3_state *st = state;
	struct s3_snapshot snapshot = {};
	char url[S3_URL_MAX], uri[S3_URL_MAX];
	char *payload = NULL;
	size_t payload_len = 0;
	bool already_present;
	int rc;

	if (!st || !v)
		return -EINVAL;
	rc = build_s3_snapshot(st->otel ? st->otel->decoder_path : NULL,
			       v, &snapshot);
	if (rc)
		return rc;
	rc = build_s3_urls(st, v, &snapshot, url, sizeof(url), uri,
			   sizeof(uri));
	if (rc)
		goto out;
	rc = s3_put(st, v, &snapshot, url, &already_present);
	if (rc)
		goto out;
	fprintf(stderr, "otel.s3: %s %s (%llu bytes)\n",
		already_present ? "found" : "uploaded", uri,
		snapshot.object_bytes);
	rc = build_s3_reference(v, &snapshot, uri, &payload, &payload_len);
	if (rc)
		goto out;
	rc = otel_post(st->otel, payload, payload_len);
out:
	if (payload)
		xfree(payload, S3_REFERENCE_MAX);
	if (snapshot.file)
		fclose(snapshot.file);
	return rc;
}

static int otel_s3_close(void *state)
{
	otel_s3_state_free(state);
	return 0;
}

int shirudo_upatch_maps_otel_send_file(const char *decoder_path,
				       const struct shirudo_map_view *v,
				       enum shirudo_otel_mode mode,
				       const struct shirudo_otel_opts *opts)
{
	const char *endpoint = opts ? opts->endpoint : NULL;
	bool automatic = mode == SHIRUDO_OTEL_AUTO;
	enum shirudo_otel_signal signal;
	void *state = NULL;
	int rc, close_rc;

	if (mode == SHIRUDO_OTEL_S3) {
		if (!opts || !opts->s3_uri)
			return -EINVAL;
		rc = otel_s3_open(opts->s3_uri, v, opts, decoder_path, &state);
		if (rc)
			return rc;
		rc = otel_s3_emit(state, v);
		close_rc = otel_s3_close(state);
		return rc ? rc : close_rc;
	}
	if (mode == SHIRUDO_OTEL_FORCE_LOG)
		signal = SHIRUDO_OTEL_LOG;
	else if (mode == SHIRUDO_OTEL_FORCE_METRIC)
		signal = SHIRUDO_OTEL_METRIC;
	else if (mode == SHIRUDO_OTEL_AUTO)
		signal = SHIRUDO_OTEL_LOG;
	else
		return -EINVAL;
	rc = otel_open_common(endpoint, v, opts, automatic, signal,
			      decoder_path, &state);
	if (rc)
		return rc;
	rc = otel_emit(state, v);
	close_rc = otel_close(state);
	return rc ? rc : close_rc;
}

int shirudo_upatch_maps_otel_send(const struct shirudo_map_view *v,
				  enum shirudo_otel_mode mode,
				  const struct shirudo_otel_opts *opts)
{
	return shirudo_upatch_maps_otel_send_file(NULL, v, mode, opts);
}

int shirudo_upatch_maps_otel_send_decoded(const struct shirudo_map_view *v,
					  enum shirudo_otel_signal signal,
					  const struct shirudo_otel_opts *opts)
{
	int rc;

	if (signal == SHIRUDO_OTEL_LOG)
		rc = shirudo_upatch_maps_otel_send(v, SHIRUDO_OTEL_FORCE_LOG,
						   opts);
	else if (signal == SHIRUDO_OTEL_METRIC)
		rc = shirudo_upatch_maps_otel_send(v, SHIRUDO_OTEL_FORCE_METRIC,
						   opts);
	else
		return -EINVAL;
	if (rc == -E2BIG && opts && opts->s3_uri)
		return shirudo_upatch_maps_otel_send(v, SHIRUDO_OTEL_S3, opts);
	return rc;
}
