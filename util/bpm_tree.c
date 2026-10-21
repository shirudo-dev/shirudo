// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <shirudo/misc.h>

#include "bpm_tree.h"
#include "crypto.h"
#include "hex.h"
#include "json.h"
#include "macros.h"
#include "malloc.h"

/*
 * The tree payload is deliberately parsed here instead of through the
 * schema parser: selectors contain maps whose keys are not known ahead of
 * time.  The parser is still bounded and ignores unknown fields.
 */
struct tree_parser {
	const char *p;
	const char *end;
	__u32 depth;
};

static void tp_ws(struct tree_parser *p)
{
	while (p->p < p->end && isspace((__u8)*p->p))
		p->p++;
}

static int tp_char(struct tree_parser *p, char c)
{
	tp_ws(p);
	if (p->p >= p->end || *p->p != c)
		return -EINVAL;
	p->p++;
	return 0;
}

static int tp_string(struct tree_parser *p, char *out, size_t cap)
{
	size_t n = 0;

	tp_ws(p);
	if (p->p >= p->end || *p->p++ != '"')
		return -EINVAL;
	while (p->p < p->end) {
		__u8 c = (__u8)*p->p++;

		if (c == '"') {
			if (cap)
				out[n < cap ? n : cap - 1] = '\0';
			return n < cap ? 0 : -ENOSPC;
		}
		if (c == '\\') {
			if (p->p >= p->end)
				return -EINVAL;
			c = (__u8)*p->p++;
			switch (c) {
			case '"':
			case '\\':
			case '/':
				break;
			case 'b':
				c = '\b';
				break;
			case 'f':
				c = '\f';
				break;
			case 'n':
				c = '\n';
				break;
			case 'r':
				c = '\r';
				break;
			case 't':
				c = '\t';
				break;
			default:
				return -EINVAL;
			}
		}
		if (c < 0x20)
			return -EINVAL;
		if (n + 1 < cap)
			out[n] = (char)c;
		n++;
	}
	return -EINVAL;
}

static int tp_skip(struct tree_parser *p)
{
	char scratch[SHIRUDO_TREE_STRING_MAX];

	tp_ws(p);
	if (p->p >= p->end)
		return -EINVAL;
	if (*p->p == '"')
		return tp_string(p, scratch, sizeof(scratch));
	if (*p->p == '{' || *p->p == '[') {
		char open = *p->p++, close = open == '{' ? '}' : ']';

		if (++p->depth > 32)
			return -E2BIG;
		for (;;) {
			tp_ws(p);
			if (p->p >= p->end)
				return -EINVAL;
			if (*p->p == close) {
				p->p++;
				p->depth--;
				return 0;
			}
			if (open == '{') {
				if (tp_string(p, scratch, sizeof(scratch)) ||
				    tp_char(p, ':'))
					return -EINVAL;
			}
			if (tp_skip(p))
				return -EINVAL;
			tp_ws(p);
			if (p->p < p->end && *p->p == ',') {
				p->p++;
				continue;
			}
			if (p->p < p->end && *p->p == close)
				continue;
			return -EINVAL;
		}
	}
	if (*p->p == '-' || isdigit((__u8)*p->p)) {
		if (*p->p == '-')
			p->p++;
		while (p->p < p->end && isdigit((__u8)*p->p))
			p->p++;
		if (p->p < p->end && *p->p == '.') {
			p->p++;
			while (p->p < p->end && isdigit((__u8)*p->p))
				p->p++;
		}
		return 0;
	}
	if ((size_t)(p->end - p->p) >= 4 && !strncmp(p->p, "true", 4)) {
		p->p += 4;
		return 0;
	}
	if ((size_t)(p->end - p->p) >= 5 && !strncmp(p->p, "false", 5)) {
		p->p += 5;
		return 0;
	}
	if ((size_t)(p->end - p->p) >= 4 && !strncmp(p->p, "null", 4)) {
		p->p += 4;
		return 0;
	}
	return -EINVAL;
}

static int tp_int(struct tree_parser *p, __s64 *out)
{
	const char *start, *scan;
	__u64 value = 0, limit;
	__u8 digit;
	bool negative = false;

	tp_ws(p);
	start = p->p;
	scan = start;
	if (scan < p->end && *scan == '-') {
		negative = true;
		scan++;
	}
	if (scan >= p->end || !isdigit((__u8)*scan))
		return -EINVAL;
	limit = negative ? (__u64)INT64_MAX + 1 : INT64_MAX;
	while (scan < p->end && isdigit((__u8)*scan)) {
		digit = (__u8)*scan - '0';
		if (value > (limit - digit) / 10)
			return -EINVAL;
		value = value * 10 + digit;
		scan++;
	}
	p->p = scan;
	if (negative && value == (__u64)INT64_MAX + 1)
		*out = INT64_MIN;
	else
		*out = negative ? -(__s64)value : (__s64)value;
	return 0;
}

static int tp_key(struct tree_parser *p, char *key, size_t cap, bool *first)
{
	tp_ws(p);
	if (!*first) {
		if (tp_char(p, ','))
			return -EINVAL;
	}
	*first = false;
	if (tp_string(p, key, cap) || tp_char(p, ':'))
		return -EINVAL;
	return 0;
}

static int tp_string_array(struct tree_parser *p,
			   char values[][SHIRUDO_TREE_STRING_MAX], int *n, int max)
{
	int count = 0;

	if (tp_char(p, '['))
		return -EINVAL;
	for (;;) {
		tp_ws(p);
		if (p->p < p->end && *p->p == ']') {
			p->p++;
			if (!count)
				return -EINVAL;
			*n = count;
			return 0;
		}
		if (count >= max || tp_string(p, values[count],
					      SHIRUDO_TREE_STRING_MAX))
			return count >= max ? -E2BIG : -EINVAL;
		count++;
		tp_ws(p);
		if (p->p >= p->end)
			return -EINVAL;
		if (*p->p == ',') {
			p->p++;
			continue;
		}
		if (*p->p != ']')
			return -EINVAL;
	}
}

static int tp_selector_string_map(struct tree_parser *p,
				  struct shirudo_tree_selector_kv *dst,
				  int *n, int max)
{
	char key[SHIRUDO_TREE_STRING_MAX];
	bool first = true;

	if (tp_char(p, '{'))
		return -EINVAL;
	for (;;) {
		int values = 0;

		tp_ws(p);
		if (p->p < p->end && *p->p == '}') {
			p->p++;
			return 0;
		}
		if (tp_key(p, key, sizeof(key), &first) || *n >= max ||
		    tp_string_array(p, dst[*n].values, &values,
				    SHIRUDO_TREE_MAX_SELECTOR_VALUES))
			return -EINVAL;
		strcpy(dst[*n].key, key);
		dst[*n].n_values = values;
		(*n)++;
	}
}

static int tp_selector(struct tree_parser *p, struct shirudo_tree_selector *s)
{
	char key[SHIRUDO_TREE_STRING_MAX];
	bool first = true;

	if (tp_char(p, '{'))
		return -EINVAL;
	for (;;) {
		tp_ws(p);
		if (p->p < p->end && *p->p == '}') {
			p->p++;
			return 0;
		}
		if (tp_key(p, key, sizeof(key), &first))
			return -EINVAL;
		if (!strcmp(key, "kernel_release_prefix")) {
			if (tp_string_array(p, s->kernel_release_prefix,
					    &s->n_kernel_release_prefix,
					    SHIRUDO_TREE_MAX_SELECTOR_VALUES))
				return -EINVAL;
		} else if (!strcmp(key, "kernel_build_id")) {
			if (tp_string_array(p, s->kernel_build_id,
					    &s->n_kernel_build_id,
					    SHIRUDO_TREE_MAX_SELECTOR_VALUES))
				return -EINVAL;
		} else if (!strcmp(key, "architecture")) {
			if (tp_string_array(p, s->architecture,
					    &s->n_architecture,
					    SHIRUDO_TREE_MAX_SELECTOR_VALUES))
				return -EINVAL;
		} else if (!strcmp(key, "kconfig") ||
			   !strcmp(key, "kernel_config")) {
			if (tp_selector_string_map(p, s->kconfig, &s->n_kconfig,
						   SHIRUDO_TREE_MAX_KCONFIG))
				return -EINVAL;
		} else if (!strcmp(key, "labels")) {
			if (tp_selector_string_map(p, s->labels, &s->n_labels,
						   SHIRUDO_TREE_MAX_LABELS))
				return -EINVAL;
		} else if (tp_skip(p)) {
			return -EINVAL;
		}
	}
}

static int tp_artifact(struct tree_parser *p, struct shirudo_tree_artifact *a)
{
	char key[SHIRUDO_TREE_STRING_MAX];
	bool first = true;

	if (tp_char(p, '{'))
		return -EINVAL;
	for (;;) {
		tp_ws(p);
		if (p->p < p->end && *p->p == '}') {
			p->p++;
			return 0;
		}
		if (tp_key(p, key, sizeof(key), &first))
			return -EINVAL;
		if (!strcmp(key, "repository")) {
			if (tp_string(p, a->repository, sizeof(a->repository)))
				return -EINVAL;
		} else if (!strcmp(key, "manifest_digest")) {
			if (tp_string(p, a->manifest_digest,
				      sizeof(a->manifest_digest)))
				return -EINVAL;
		} else if (!strcmp(key, "layer_digest")) {
			if (tp_string(p, a->layer_digest, sizeof(a->layer_digest)))
				return -EINVAL;
		} else if (!strcmp(key, "payload_sha256")) {
			if (tp_string(p, a->payload_sha256,
				      sizeof(a->payload_sha256)))
				return -EINVAL;
		} else if (tp_skip(p)) {
			return -EINVAL;
		}
	}
}

static int tp_operation(struct tree_parser *p, struct shirudo_tree_operation *o)
{
	char key[SHIRUDO_TREE_STRING_MAX];
	bool first = true;

	if (tp_char(p, '{'))
		return -EINVAL;
	for (;;) {
		tp_ws(p);
		if (p->p < p->end && *p->p == '}') {
			p->p++;
			if (!o->id[0] || !o->op[0] || o->seq <= 0 ||
			    !o->operation_digest[0] || !o->artifact.repository[0] ||
			    !o->artifact.manifest_digest[0] ||
			    !o->artifact.layer_digest[0] ||
			    !o->artifact.payload_sha256[0])
				return -EINVAL;
			return 0;
		}
		if (tp_key(p, key, sizeof(key), &first))
			return -EINVAL;
		if (!strcmp(key, "seq")) {
			if (tp_int(p, &o->seq))
				return -EINVAL;
		} else if (!strcmp(key, "op")) {
			if (tp_string(p, o->op, sizeof(o->op)))
				return -EINVAL;
		} else if (!strcmp(key, "id")) {
			if (tp_string(p, o->id, sizeof(o->id)))
				return -EINVAL;
		} else if (!strcmp(key, "selector")) {
			if (tp_selector(p, &o->selector))
				return -EINVAL;
		} else if (!strcmp(key, "artifact")) {
			if (tp_artifact(p, &o->artifact))
				return -EINVAL;
		} else if (!strcmp(key, "expected_payload_sha256")) {
			if (tp_string(p, o->expected_payload_sha256,
				      sizeof(o->expected_payload_sha256)))
				return -EINVAL;
		} else if (!strcmp(key, "operation_digest")) {
			if (tp_string(p, o->operation_digest,
				      sizeof(o->operation_digest)))
				return -EINVAL;
		} else if (tp_skip(p)) {
			return -EINVAL;
		}
	}
}

void shirudo_tree_publication_free(struct shirudo_tree_publication *pub)
{
	if (!pub)
		return;
	if (pub->operations)
		xfree(pub->operations,
		      (size_t)pub->operations_capacity * sizeof(*pub->operations));
	*pub = (struct shirudo_tree_publication){};
}

static int tree_operations_reserve(struct shirudo_tree_publication *pub)
{
	struct shirudo_tree_operation *operations;
	int old_capacity = pub->operations_capacity;
	int new_capacity = old_capacity ? old_capacity * 2 : 16;

	if (pub->n_operations >= SHIRUDO_TREE_MAX_OPS)
		return -E2BIG;
	if (pub->n_operations < old_capacity)
		return 0;
	if (new_capacity > SHIRUDO_TREE_MAX_OPS)
		new_capacity = SHIRUDO_TREE_MAX_OPS;
	operations = xreallocarray(pub->operations, (size_t)old_capacity,
				   (size_t)new_capacity, sizeof(*operations));
	if (!operations)
		return -ENOMEM;
	pub->operations = operations;
	pub->operations_capacity = new_capacity;
	return 0;
}

int shirudo_tree_publication_append(struct shirudo_tree_publication *pub,
				    const struct shirudo_tree_operation *op)
{
	int rc;

	if (!pub || !op)
		return -EINVAL;
	rc = tree_operations_reserve(pub);
	if (rc)
		return rc;
	pub->operations[pub->n_operations++] = *op;
	return 0;
}

/* The "base" and "head" objects: {"seq": <int>} plus fields to skip. */
static int tp_seq_object(struct tree_parser *p, char *key, size_t cap,
			 __s64 *seq, bool *seen_seq)
{
	bool first = true;

	if (tp_char(p, '{'))
		return -EINVAL;
	for (;;) {
		tp_ws(p);
		if (p->p < p->end && *p->p == '}') {
			p->p++;
			return 0;
		}
		if (tp_key(p, key, cap, &first))
			return -EINVAL;
		if (!strcmp(key, "seq")) {
			if (tp_int(p, seq))
				return -EINVAL;
			*seen_seq = true;
		} else if (tp_skip(p)) {
			return -EINVAL;
		}
	}
}

int shirudo_tree_parse(const char *body, size_t len,
		       struct shirudo_tree_publication *out)
{
	struct tree_parser p;
	char key[SHIRUDO_TREE_STRING_MAX];
	bool first = true;
	bool seen_schema = false, seen_generation = false;
	bool seen_base = false, seen_base_seq = false;
	bool seen_operations = false, seen_head = false, seen_head_seq = false;
	__s64 schema = 0;
	int rc;

	if (!body || !out || len > SHIRUDO_JSON_MAX_BYTES)
		return -EINVAL;
	p = (struct tree_parser){ .p = body, .end = body + len };
	*out = (struct shirudo_tree_publication){};
	if (tp_char(&p, '{')) {
		rc = -EINVAL;
		goto fail;
	}
	for (;;) {
		tp_ws(&p);
		if (p.p < p.end && *p.p == '}') {
			p.p++;
			break;
		}
		if (tp_key(&p, key, sizeof(key), &first)) {
			rc = -EINVAL;
			goto fail;
		}
		if (!strcmp(key, "schema")) {
			if (tp_int(&p, &schema)) {
				rc = -EINVAL;
				goto fail;
			}
			out->schema = (int)schema;
			seen_schema = true;
		} else if (!strcmp(key, "tree_id")) {
			if (tp_string(&p, out->tree_id, sizeof(out->tree_id))) {
				rc = -EINVAL;
				goto fail;
			}
		} else if (!strcmp(key, "generation")) {
			if (tp_int(&p, &out->generation)) {
				rc = -EINVAL;
				goto fail;
			}
			seen_generation = true;
		} else if (!strcmp(key, "parent_manifest_digest")) {
			if (tp_string(&p, out->parent_manifest_digest,
				      sizeof(out->parent_manifest_digest))) {
				rc = -EINVAL;
				goto fail;
			}
		} else if (!strcmp(key, "base")) {
			seen_base = true;
			if (tp_seq_object(&p, key, sizeof(key), &out->base_seq,
					  &seen_base_seq)) {
				rc = -EINVAL;
				goto fail;
			}
		} else if (!strcmp(key, "operations")) {
			seen_operations = true;
			if (tp_char(&p, '[')) {
				rc = -EINVAL;
				goto fail;
			}
			for (;;) {
				tp_ws(&p);
				if (p.p < p.end && *p.p == ']') {
					p.p++;
					break;
				}
				rc = tree_operations_reserve(out);
				if (rc)
					goto fail;
				if (tp_operation(&p, &out->operations[out->n_operations])) {
					rc = -EINVAL;
					goto fail;
				}
				out->n_operations++;
				tp_ws(&p);
				if (p.p < p.end && *p.p == ',') {
					p.p++;
					continue;
				}
				if (p.p < p.end && *p.p == ']') {
					p.p++;
					break;
				}
				rc = -EINVAL;
				goto fail;
			}
		} else if (!strcmp(key, "head")) {
			seen_head = true;
			if (tp_seq_object(&p, key, sizeof(key), &out->head_seq,
					  &seen_head_seq)) {
				rc = -EINVAL;
				goto fail;
			}
		} else if (tp_skip(&p)) {
			rc = -EINVAL;
			goto fail;
		}
		tp_ws(&p);
		if (p.p < p.end && *p.p == '}') {
			p.p++;
			break;
		}
		if (p.p >= p.end) {
			rc = -EINVAL;
			goto fail;
		}
	}
	tp_ws(&p);
	if (p.p != p.end || !seen_schema || !seen_generation || !seen_base ||
	    !seen_base_seq || !seen_operations || !seen_head || !seen_head_seq ||
	    schema != 2 || !out->tree_id[0] ||
	    out->generation < 0 || out->generation == INT64_MAX ||
	    out->base_seq < 0 || out->head_seq < out->base_seq ||
	    out->head_seq == INT64_MAX) {
		rc = -EINVAL;
		goto fail;
	}
	/* Every operation's seq is positive, so seq - 1 cannot overflow. */
	for (int i = 0; i < out->n_operations; i++) {
		if (i && out->operations[i].seq - 1 != out->operations[i - 1].seq) {
			rc = -EINVAL;
			goto fail;
		}
	}
	return 0;
fail:
	shirudo_tree_publication_free(out);
	return rc;
}

static int tree_selector_kv_compare(const void *left, const void *right)
{
	const struct shirudo_tree_selector_kv *a =
		*(const struct shirudo_tree_selector_kv * const *)left;
	const struct shirudo_tree_selector_kv *b =
		*(const struct shirudo_tree_selector_kv * const *)right;
	return strcmp(a->key, b->key);
}

/*
 * Canonical selector object: keys in lexicographic order, each list in
 * the publisher's order. Targets recompute operation digests from this
 * form, so publisher and consumer share one emitter.
 */
static int tree_emit_selector(struct shirudo_json_emit *e,
			      const struct shirudo_tree_selector *s)
{
	const struct shirudo_tree_selector_kv *kconfig[SHIRUDO_TREE_MAX_KCONFIG];
	const struct shirudo_tree_selector_kv *labels[SHIRUDO_TREE_MAX_LABELS];

	if (s->n_kconfig > (int)ARRAY_SIZE(kconfig) ||
	    s->n_labels > (int)ARRAY_SIZE(labels))
		return -E2BIG;
	for (int i = 0; i < s->n_kconfig; i++)
		kconfig[i] = &s->kconfig[i];
	for (int i = 0; i < s->n_labels; i++)
		labels[i] = &s->labels[i];
	qsort(kconfig, (size_t)s->n_kconfig, sizeof(kconfig[0]),
	      tree_selector_kv_compare);
	qsort(labels, (size_t)s->n_labels, sizeof(labels[0]),
	      tree_selector_kv_compare);

	shirudo_json_obj_open_key(e, "selector");
	if (s->n_architecture) {
		shirudo_json_arr_open(e, "architecture");
		for (int i = 0; i < s->n_architecture; i++)
			shirudo_json_str(e, s->architecture[i]);
		shirudo_json_arr_close(e);
	}
	if (s->n_kconfig) {
		shirudo_json_obj_open_key(e, "kconfig");
		for (int i = 0; i < s->n_kconfig; i++) {
			shirudo_json_arr_open(e, kconfig[i]->key);
			for (int j = 0; j < kconfig[i]->n_values; j++)
				shirudo_json_str(e, kconfig[i]->values[j]);
			shirudo_json_arr_close(e);
		}
		shirudo_json_obj_close(e);
	}
	if (s->n_kernel_build_id) {
		shirudo_json_arr_open(e, "kernel_build_id");
		for (int i = 0; i < s->n_kernel_build_id; i++)
			shirudo_json_str(e, s->kernel_build_id[i]);
		shirudo_json_arr_close(e);
	}
	if (s->n_kernel_release_prefix) {
		shirudo_json_arr_open(e, "kernel_release_prefix");
		for (int i = 0; i < s->n_kernel_release_prefix; i++)
			shirudo_json_str(e, s->kernel_release_prefix[i]);
		shirudo_json_arr_close(e);
	}
	if (s->n_labels) {
		shirudo_json_obj_open_key(e, "labels");
		for (int i = 0; i < s->n_labels; i++) {
			shirudo_json_arr_open(e, labels[i]->key);
			for (int j = 0; j < labels[i]->n_values; j++)
				shirudo_json_str(e, labels[i]->values[j]);
			shirudo_json_arr_close(e);
		}
		shirudo_json_obj_close(e);
	}
	shirudo_json_obj_close(e);
	return 0;
}

static void tree_emit_artifact(struct shirudo_json_emit *e,
			       const struct shirudo_tree_artifact *a)
{
	shirudo_json_obj_open_key(e, "artifact");
	shirudo_json_kv_string(e, "repository", a->repository);
	shirudo_json_kv_string(e, "manifest_digest", a->manifest_digest);
	shirudo_json_kv_string(e, "layer_digest", a->layer_digest);
	shirudo_json_kv_string(e, "payload_sha256", a->payload_sha256);
	shirudo_json_obj_close(e);
}

static int tree_emit_operation(struct shirudo_json_emit *e,
			       const struct shirudo_tree_operation *op,
			       bool with_digest)
{
	int rc;

	shirudo_json_obj_open(e);
	shirudo_json_kv_int(e, "seq", op->seq);
	shirudo_json_kv_string(e, "op", op->op);
	shirudo_json_kv_string(e, "id", op->id);
	rc = tree_emit_selector(e, &op->selector);
	if (rc)
		return rc;
	tree_emit_artifact(e, &op->artifact);
	if (with_digest)
		shirudo_json_kv_string(e, "operation_digest", op->operation_digest);
	shirudo_json_obj_close(e);
	return e->err;
}

/*
 * The operation digest covers the canonical operation without the digest
 * field itself: seq, op, id, selector and artifact.
 */
int shirudo_tree_operation_digest(const struct shirudo_tree_operation *op,
				  char out[72])
{
	size_t body_cap = 1024u * 1024u;
	struct shirudo_json_emit e;
	char *body, hex[65];
	__u8 digest[32];
	int rc;

	body = xmalloc(body_cap);
	if (!body)
		return -ENOMEM;
	e = (struct shirudo_json_emit){ .buf = body, .cap = body_cap };
	rc = tree_emit_operation(&e, op, false);
	if (!rc && shirudo_sha256_buffer(body, e.len, digest))
		rc = -EIO;
	if (!rc) {
		shirudo_hex_encode(digest, sizeof(digest), hex);
		memcpy(out, "sha256:", 7);
		memcpy(out + 7, hex, sizeof(hex));
	}
	xfree(body, body_cap);
	return rc;
}

static size_t tree_json_bound(const char *s)
{
	return 2 * strlen(s) + 4;
}

static size_t tree_selector_kv_bound(const struct shirudo_tree_selector_kv *kv)
{
	size_t n = 8 + tree_json_bound(kv->key);

	for (int i = 0; i < kv->n_values; i++)
		n += tree_json_bound(kv->values[i]);
	return n;
}

static size_t tree_operation_bound(const struct shirudo_tree_operation *op)
{
	const struct shirudo_tree_selector *s = &op->selector;
	size_t n = 512;

	n += tree_json_bound(op->op) + tree_json_bound(op->id) +
	     tree_json_bound(op->operation_digest) +
	     tree_json_bound(op->artifact.repository) +
	     tree_json_bound(op->artifact.manifest_digest) +
	     tree_json_bound(op->artifact.layer_digest) +
	     tree_json_bound(op->artifact.payload_sha256);
	for (int i = 0; i < s->n_kernel_release_prefix; i++)
		n += tree_json_bound(s->kernel_release_prefix[i]);
	for (int i = 0; i < s->n_kernel_build_id; i++)
		n += tree_json_bound(s->kernel_build_id[i]);
	for (int i = 0; i < s->n_architecture; i++)
		n += tree_json_bound(s->architecture[i]);
	for (int i = 0; i < s->n_kconfig; i++)
		n += tree_selector_kv_bound(&s->kconfig[i]);
	for (int i = 0; i < s->n_labels; i++)
		n += tree_selector_kv_bound(&s->labels[i]);
	return n;
}

/*
 * Serialise a publication in the field order every publisher has used:
 * schema, tree_id, generation, parent_manifest_digest (when any), base,
 * operations, head.
 */
int shirudo_tree_emit_publication(const struct shirudo_tree_publication *pub,
				  char **out, size_t *out_len)
{
	struct shirudo_json_emit e;
	size_t cap = 4096;
	char *body;
	int rc = 0;

	for (int i = 0; i < pub->n_operations; i++)
		cap += tree_operation_bound(&pub->operations[i]);
	body = xmalloc(cap);
	if (!body)
		return -ENOMEM;
	e = (struct shirudo_json_emit){ .buf = body, .cap = cap };
	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schema", pub->schema);
	shirudo_json_kv_string(&e, "tree_id", pub->tree_id);
	shirudo_json_kv_int(&e, "generation", pub->generation);
	if (pub->parent_manifest_digest[0])
		shirudo_json_kv_string(&e, "parent_manifest_digest",
				       pub->parent_manifest_digest);
	shirudo_json_obj_open_key(&e, "base");
	shirudo_json_kv_int(&e, "seq", pub->base_seq);
	shirudo_json_obj_close(&e);
	shirudo_json_arr_open(&e, "operations");
	for (int i = 0; !rc && i < pub->n_operations; i++)
		rc = tree_emit_operation(&e, &pub->operations[i], true);
	shirudo_json_arr_close(&e);
	shirudo_json_obj_open_key(&e, "head");
	shirudo_json_kv_int(&e, "seq", pub->head_seq);
	shirudo_json_obj_close(&e);
	shirudo_json_obj_close(&e);
	if (!rc)
		rc = e.err;
	if (rc) {
		xfree(body, cap);
		return rc;
	}
	*out = body;
	*out_len = e.len;
	return 0;
}
