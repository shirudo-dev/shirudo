// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What an OTLP collector answers, the response header lines and the
 * partial-success body, the decoded map JSON a log record carries, and
 * the configured OTEL_EXPORTER_OTLP_HEADERS.
 */

#include "fuzz.h"
#include "upatch_maps_otel.c"

/* The map decoding the exporter calls is fuzzed on its own. */
const struct btf_type *btf__type_by_id(const struct btf *btf, __u32 id)
{
	return NULL;
}

bool upatch_map_is_percpu(__u32 type)
{
	return false;
}

int upatch_decode_map_json(const struct map_view *v,
			   char **out, size_t *out_len)
{
	return -EOPNOTSUPP;
}

int upatch_decode_map_json_limit(const struct map_view *v,
				 size_t max_bytes,
				 char **out, size_t *out_len)
{
	return -EOPNOTSUPP;
}

int upatch_decode_map_otel(const struct map_view *v,
			   char **out, size_t *out_len)
{
	return -EOPNOTSUPP;
}

int upatch_decode_map_file_json(const char *path,
				const struct map_view *v,
				char **out, size_t *out_len)
{
	return -EOPNOTSUPP;
}

int upatch_decode_map_file_json_limit(const char *path,
				      const struct map_view *v,
				      size_t max_bytes, char **out,
				      size_t *out_len)
{
	return -EOPNOTSUPP;
}

int upatch_decode_map_file_otel(const char *path,
				const struct map_view *v,
				char **out, size_t *out_len)
{
	return -EOPNOTSUPP;
}

static const struct json_visitor any_value = {};

static size_t deepest_nesting(const char *s, size_t len)
{
	size_t depth = 0, deepest = 0, i;
	bool in_string = false;

	for (i = 0; i < len; i++) {
		if (in_string) {
			if (s[i] == '\\')
				i++;
			else if (s[i] == '"')
				in_string = false;
		} else if (s[i] == '"') {
			in_string = true;
		} else if (s[i] == '{' || s[i] == '[') {
			if (++depth > deepest)
				deepest = depth;
		} else if ((s[i] == '}' || s[i] == ']') && depth) {
			depth--;
		}
	}
	return deepest;
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct json_emit e = { .max = JSON_MAX_BYTES };
	struct otel_response r = {};
	struct otel_state st = {};
	size_t off, n;
	char *body, *line;
	int ret;

	/*
	 * curl hands the header callback one line at a time, end included
	 * and not NUL-terminated: each line in a buffer of its own size.
	 */
	for (off = 0; off < size; off += n) {
		const __u8 *nl = memchr(data + off, '\n', size - off);

		n = nl ? (size_t)(nl - data) - off + 1 : size - off;
		line = xmalloc(n);
		if (!line)
			return 0;
		memcpy(line, data + off, n);
		response_header(line, 1, n, &r);
		xfree(line, n);
	}

	body = xmalloc(size + 1);
	if (!body)
		return 0;
	memcpy(body, data, size);
	body[size] = '\0';
	check_partial_success(OTEL_LOG, body, size);
	check_partial_success(OTEL_METRIC, body, size);

	json_obj_open(&e);
	/*
	 * What the conversion writes reads back as JSON, in a buffer that
	 * grows for it. An input level takes up to four in the output,
	 * which can so nest deeper than the walk goes; such output must read
	 * back up to that depth.
	 */
	if (!json_anyvalue_from_document(&e, body, size, false)) {
		json_obj_close(&e);
		if (e.err == -ENOSPC)
			abort();
		if (!e.err) {
			ret = json_walk(e.buf, e.len, &any_value, NULL);
			if (deepest_nesting(e.buf, e.len) <= JSON_MAX_DEPTH ?
			    ret : ret != -E2BIG)
				abort();
		}
	}
	xfree(e.buf, e.cap);

	if (!memchr(data, '\0', size)) {
		if (!add_configured_headers(&st, body)) {
			for (struct curl_slist *h = st.headers; h; h = h->next) {
				char *colon = strchr(h->data, ':');
				bool ok;

				if (!colon)
					abort();
				*colon = '\0';
				ok = header_name_ok(h->data) &&
				     header_value_ok(colon + 1);
				*colon = ':';
				if (!ok)
					abort();
			}
		}
		curl_slist_free_sensitive(st.headers);
	}
	xfree(body, size + 1);
	return 0;
}
