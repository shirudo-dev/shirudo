// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/xattr.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>
#include <shirudo/upatch.h>

#include "chain.h"
#include "eventlog.h"
#include "hex.h"
#include "json.h"
#include "malloc.h"
#include "measured.h"
#include "paths.h"
#include "seal.h"
#include "upatch.h"

struct measured_entry {
	char	name[UPATCH_NAME_MAX + 1];
	char	payload_hex[2 * UPATCH_PAYLOAD_HASH_LEN + 1];
};

struct measured_set {
	struct measured_entry	*entries;
	size_t			n;
};

static int measured_event(enum eventlog_upatch_event event, const char *name,
			  const char *payload_hex, void *ctx)
{
	struct measured_set *s = ctx;
	size_t i;

	if (event == EVENTLOG_UPATCH_INIT) {
		s->n = 0;
		return 0;
	}
	for (i = 0; i < s->n; i++) {
		if (!strcmp(s->entries[i].name, name))
			break;
	}
	if (event == EVENTLOG_UPATCH_UNLOAD) {
		if (i < s->n)
			s->entries[i] = s->entries[--s->n];
		return 0;
	}
	if (i == s->n) {
		if (s->n == MEASURED_MAX)
			return -ENOSPC;
		s->n++;
	}
	if (strscpy(s->entries[i].name, name,
		    sizeof(s->entries[i].name)) < 0 ||
	    strscpy(s->entries[i].payload_hex, payload_hex,
		    sizeof(s->entries[i].payload_hex)) < 0)
		return -EINVAL;
	return 0;
}

/* Whether line is an init record of the register the TPM reports now. */
static bool init_of_live(const char *line, size_t len,
			 const struct chain_live *live)
{
	char type[8], name_hex[2 * TPM_NAME_LEN + 1];
	__u8 name[TPM_NAME_LEN];
	__s64 reset = -1;
	struct json_field f[] = {
		{ "type", JSON_T_STRING, type, sizeof(type), 0, NULL, 0 },
		{ "nv_name", JSON_T_STRING, name_hex, sizeof(name_hex), 0,
		  NULL, 0 },
		{ "tpm_reset_count", JSON_T_INT, &reset, 0, 0, NULL, 0 },
	};

	type[0] = '\0';
	if (json_parse(line, len, f, ARRAY_SIZE(f)) || strcmp(type, "init") ||
	    !f[1].seen || !f[2].seen || reset != live->reset_count ||
	    strlen(name_hex) != 2 * TPM_NAME_LEN ||
	    hex_decode(name_hex, name, sizeof(name)))
		return false;
	return !memcmp(name, live->name, sizeof(name));
}

struct record_fields {
	char			type[32];
	char			digest_hex[2 * 32 + 1];
	char			cert_hex[2 * 32 + 1];
	char			tree_root_hex[2 * 32 + 1];
	char			key_hex[2 * 32 + 1];
	char			operation[sizeof("sha256:") + 2 * 32];
	char			name[UPATCH_NAME_MAX + 1];
	char			payload_hex[2 * UPATCH_PAYLOAD_HASH_LEN + 1];
	char			member_type[8];
	__s64			seq;
	struct measured_upatch	*set;
	size_t			n;
	bool			init, upatch, key, tree;
};

static int record_set_entry(void *arg)
{
	struct record_fields *r = arg;
	__u32 type;
	int ret;

	ret = measured_member_type(r->member_type, &type);
	if (!ret)
		ret = measured_set_add(r->set, &r->n, MEASURED_MAX, r->name,
				       r->payload_hex, type);
	r->name[0] = '\0';
	r->payload_hex[0] = '\0';
	r->member_type[0] = '\0';
	return ret;
}

static int record_parse(const char *line, size_t len, struct record_fields *r)
{
	struct json_field entry[] = {
		{ "name", JSON_T_STRING, r->name, sizeof(r->name), 0, NULL, 0 },
		{ "payload_sha256", JSON_T_STRING, r->payload_hex,
		  sizeof(r->payload_hex), 0, NULL, 0 },
		{ "type", JSON_T_STRING, r->member_type,
		  sizeof(r->member_type), 0, NULL, 0 },
	};
	struct json_field upatch[] = {
		{ "name", JSON_T_STRING, r->name, sizeof(r->name), 0, NULL, 0 },
		{ "payload_sha256", JSON_T_STRING, r->payload_hex,
		  sizeof(r->payload_hex), 0, NULL, 0 },
	};
	struct json_field key[] = {
		{ "cert_sha256", JSON_T_STRING, r->key_hex, sizeof(r->key_hex),
		  0, NULL, 0 },
	};
	struct json_field tree[] = {
		{ "seq", JSON_T_INT, &r->seq, 0, 0, NULL, 0 },
		{ "operation_digest", JSON_T_STRING, r->operation,
		  sizeof(r->operation), 0, NULL, 0 },
	};
	struct json_array set = { record_set_entry, r };
	struct json_field f[] = {
		{ "type", JSON_T_STRING, r->type, sizeof(r->type), 0, NULL, 0 },
		{ "digest", JSON_T_STRING, r->digest_hex, sizeof(r->digest_hex),
		  0, NULL, 0 },
		{ "cert_sha256", JSON_T_STRING, r->cert_hex, sizeof(r->cert_hex),
		  0, NULL, 0 },
		{ "tree_root", JSON_T_STRING, r->tree_root_hex,
		  sizeof(r->tree_root_hex), 0, NULL, 0 },
		{ "set", JSON_T_ARRAY, &set, 0, 0, entry, ARRAY_SIZE(entry) },
		{ "upatch", JSON_T_OBJECT, NULL, 0, 0, upatch,
		  ARRAY_SIZE(upatch) },
		{ "key", JSON_T_OBJECT, NULL, 0, 0, key, ARRAY_SIZE(key) },
		{ "tree", JSON_T_OBJECT, NULL, 0, 0, tree, ARRAY_SIZE(tree) },
	};

	if (json_parse(line, len, f, ARRAY_SIZE(f)) || !f[0].seen ||
	    !f[1].seen)
		return -EINVAL;
	r->init = f[2].seen && f[3].seen && f[4].seen;
	r->upatch = f[5].seen;
	r->key = key[0].seen;
	r->tree = tree[0].seen && tree[1].seen && r->seq > 0;
	return 0;
}

static int init_event_of(struct record_fields *r, __u8 event[32])
{
	__u8 cert[32], tree_root[32], set_digest[32];

	if (!r->init || hex_decode(r->cert_hex, cert, sizeof(cert)) ||
	    hex_decode(r->tree_root_hex, tree_root, sizeof(tree_root)))
		return -EINVAL;
	return chain_init_event(cert, r->set, r->n, tree_root, set_digest,
				event);
}

static int upatch_event_of(struct record_fields *r, __u32 type, bool load,
			   __u8 event[32])
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN];

	if (!r->upatch || !upatch_member_valid(r->name, r->payload_hex) ||
	    hex_decode(r->payload_hex, payload, sizeof(payload)))
		return -EINVAL;
	return chain_upatch_event(chain_upatch_tag(type, load), r->name,
				  payload, event);
}

static int key_event_of(struct record_fields *r, __u8 event[32])
{
	__u8 cert[32];

	if (!r->key || hex_decode(r->key_hex, cert, sizeof(cert)))
		return -EINVAL;
	return chain_key_event("shirudo-key-revoke", cert, event);
}

static int tree_event_of(struct record_fields *r, __u8 event[32])
{
	__u8 operation[32];

	if (!r->tree || sha256_digest_decode(r->operation, operation))
		return -EINVAL;
	return chain_tree_event(r->seq, operation, event);
}

static int record_event_of(struct record_fields *r, __u8 event[32])
{
	__u32 type;
	bool load;

	if (!strcmp(r->type, "init"))
		return init_event_of(r, event);
	if (eventlog_upatch_record_parse(r->type, &type, &load))
		return upatch_event_of(r, type, load, event);
	if (!strcmp(r->type, "key_revoke"))
		return key_event_of(r, event);
	if (!strcmp(r->type, "tree_op"))
		return tree_event_of(r, event);
	return -EINVAL;
}

/*
 * The event the fields of a record give, as the extend that wrote it
 * made it, and the digest the record claims for it: a record counts for
 * what it says only where the two agree. A type no writer uses is
 * refused.
 */
static int record_event(const char *line, size_t len, __u8 event[32],
			__u8 digest[32])
{
	struct record_fields *r;
	int ret;

	r = xcalloc(1, sizeof(*r));
	if (!r)
		return -ENOMEM;
	r->set = xcalloc(MEASURED_MAX, sizeof(*r->set));
	if (!r->set) {
		xfree(r, sizeof(*r));
		return -ENOMEM;
	}
	ret = record_parse(line, len, r);
	if (!ret && hex_decode(r->digest_hex, digest, 32))
		ret = -EINVAL;
	if (!ret)
		ret = record_event_of(r, event);
	xfree(r->set, MEASURED_MAX * sizeof(*r->set));
	xfree(r, sizeof(*r));
	return ret;
}

/*
 * eventlog_boot_upatches() for the records the TPM vouches for: the boot
 * starts at the last init record that names the live index and the
 * TPM's reset count, every record's digest is derived from its fields,
 * and the records fold to the value the TPM reports. cb sees the events
 * as the walk goes; only a return of 0 makes them this boot's. -ENOENT
 * without such an init record, -EBADMSG when a record or the fold does
 * not match, -ENODEV without a register this reset.
 */
static int verified_upatches(int (*cb)(enum eventlog_upatch_event event,
				       const char *name,
				       const char *payload_hex, void *ctx),
			     void *ctx)
{
	__u8 chain[32] = {}, event[32], digest[32];
	const char *anchor = NULL, *line, *end;
	struct chain_live live;
	char *buf = NULL;
	size_t len = 0;
	int ret;

	ret = chain_live(&live);
	if (ret)
		return ret;
	ret = eventlog_read(&buf, &len);
	if (ret)
		return ret;
	for (line = buf; (end = strchr(line, '\n')); line = end + 1) {
		if (init_of_live(line, (size_t)(end - line), &live))
			anchor = line;
	}
	if (!anchor)
		ret = -ENOENT;
	for (line = anchor; !ret && (end = strchr(line, '\n'));
	     line = end + 1) {
		ret = record_event(line, (size_t)(end - line), event, digest);
		if (!ret && memneq_explicit(event, digest, sizeof(event)))
			ret = -EBADMSG;
		if (!ret)
			ret = chain_fold(chain, event);
		if (!ret)
			ret = eventlog_upatches_record(line,
						       (size_t)(end - line),
						       line == anchor, cb,
						       ctx);
	}
	if (!ret && memneq_explicit(chain, live.value, sizeof(chain)))
		ret = -EBADMSG;
	xfree(buf, len + 1);
	return ret;
}

static int measured_set_fold(struct measured_set **out, bool all)
{
	struct measured_set *s;
	int ret;

	*out = NULL;
	s = xmalloc(sizeof(*s));
	if (!s)
		return -ENOMEM;
	s->n = 0;
	s->entries = xcalloc(MEASURED_MAX, sizeof(*s->entries));
	if (!s->entries) {
		xfree(s, sizeof(*s));
		return -ENOMEM;
	}
	ret = all ? eventlog_upatches(measured_event, s) :
	      verified_upatches(measured_event, s);
	if (ret == -ENOENT && all)
		ret = 0;
	if (ret) {
		measured_set_free(s);
		return ret;
	}
	*out = s;
	return 0;
}

int measured_set_boot(struct measured_set **out)
{
	return measured_set_fold(out, false);
}

int measured_set_log(struct measured_set **out)
{
	return measured_set_fold(out, true);
}

void measured_upatch_of(struct measured_upatch *e, const struct upatch *u)
{
	upatch_header_name(u, e->name);
	hex_encode(u->hdr.payload_sha256, UPATCH_PAYLOAD_HASH_LEN,
		   e->payload_hex);
	e->type = u->hdr.type;
}

int measured_member_type(const char *text, __u32 *type)
{
	if (!text[0]) {
		*type = UPATCH_TYPE_BPF;
		return 0;
	}
	if (!strcmp(text, "java")) {
		*type = UPATCH_TYPE_JAVA;
		return 0;
	}
	return -EINVAL;
}

int measured_set_add(struct measured_upatch *set, size_t *n, size_t max,
		     const char *name, const char *payload_hex, __u32 type)
{
	struct measured_upatch *e;
	size_t i;

	if (!upatch_member_valid(name, payload_hex))
		return -EINVAL;
	for (i = 0; i < *n; i++) {
		if (!strcmp(set[i].name, name))
			return -EEXIST;
	}
	if (*n >= max)
		return -E2BIG;
	if (!chain_upatch_tag(type, true))
		return -EINVAL;
	e = &set[*n];
	if (strscpy(e->name, name, sizeof(e->name)) < 0 ||
	    strscpy(e->payload_hex, payload_hex, sizeof(e->payload_hex)) < 0)
		return -E2BIG;
	e->type = type;
	(*n)++;
	return 0;
}

bool measured_holds(const struct measured_set *s, const char *name,
		    const char *payload_hex)
{
	size_t i;

	for (i = 0; i < s->n; i++) {
		if (!strcmp(s->entries[i].name, name) &&
		    !strcmp(s->entries[i].payload_hex, payload_hex))
			return true;
	}
	return false;
}

void measured_set_free(struct measured_set *s)
{
	if (!s)
		return;
	xfree(s->entries, MEASURED_MAX * sizeof(*s->entries));
	xfree(s, sizeof(*s));
}

static void free_names(struct dirent **names, int n)
{
	int i;

	for (i = 0; i < n; i++)
		libc_free(names[i]);
	libc_free(names);
}

int measured_unmeasured_pins(const struct measured_set *s,
			     int (*cb)(const char *name, void *ctx),
			     void *ctx)
{
	struct dirent **pins = NULL;
	int n, i, ret = 0, unmeasured = 0;

	n = scandir(BPFFS_UPATCHES_DIR, &pins, NULL, alphasort);
	if (n < 0)
		return errno == ENOENT ? 0 : -errno;
	for (i = 0; i < n; i++) {
		char payload_hex[2 * UPATCH_PAYLOAD_HASH_LEN + 1] = "";
		__u8 payload[UPATCH_PAYLOAD_HASH_LEN];
		char name[UPATCH_NAME_MAX + 1];
		char dir[PATH_MAX];

		if (!strcmp(pins[i]->d_name, ".") ||
		    !strcmp(pins[i]->d_name, "..") ||
		    upatch_name_from_bpffs(name, sizeof(name),
					   pins[i]->d_name) ||
		    strsprintf(dir, sizeof(dir), "%s/%s", BPFFS_UPATCHES_DIR,
			       pins[i]->d_name) < 0)
			continue;
		if (getxattr(dir, XATTR_PAYLOAD, payload, sizeof(payload)) ==
		    (ssize_t)sizeof(payload))
			hex_encode(payload, sizeof(payload), payload_hex);
		if (measured_holds(s, name, payload_hex))
			continue;
		unmeasured++;
		if (cb) {
			ret = cb(name, ctx);
			if (ret)
				break;
		}
	}
	free_names(pins, n);
	return ret ? ret : unmeasured;
}

int measured_each(const struct measured_set *s,
		  int (*cb)(const char *name, const char *payload_hex,
			    void *ctx),
		  void *ctx)
{
	int ret = 0;
	size_t i;

	for (i = 0; i < s->n && !ret; i++)
		ret = cb(s->entries[i].name, s->entries[i].payload_hex, ctx);
	return ret;
}

int measured_unmeasured_archives(const struct measured_set *s,
				 int (*cb)(const char *name,
					   const char *path, void *ctx),
				 void *ctx)
{
	struct dirent **names = NULL;
	int n, i, ret = 0, unmeasured = 0;

	n = scandir(UPATCHES_DIR, &names, upatch_select, alphasort);
	if (n < 0)
		return errno == ENOENT ? 0 : -errno;
	for (i = 0; i < n; i++) {
		struct measured_upatch m;
		char path[PATH_MAX];
		struct upatch u;

		if (strsprintf(path, sizeof(path), "%s/%s", UPATCHES_DIR,
			       names[i]->d_name) < 0 ||
		    !seal_owns(path) || upatch_open(path, &u))
			continue;
		measured_upatch_of(&m, &u);
		upatch_close(&u);
		if (measured_holds(s, m.name, m.payload_hex))
			continue;
		unmeasured++;
		if (cb) {
			ret = cb(m.name, path, ctx);
			if (ret)
				break;
		}
	}
	free_names(names, n);
	return ret ? ret : unmeasured;
}
