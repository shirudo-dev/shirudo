// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Target-side upatch tree state: selector matching, persisted cursor,
 * event log and the dedicated TPM projection chain.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <zlib.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "bpm_tree.h"
#include "chain.h"
#include "io.h"
#include "json.h"
#include "kernel_build_id.h"
#include "kernel_release.h"
#include "log.h"
#include "macros.h"
#include "malloc.h"
#include "paths.h"
#include "seal.h"

static int kv_add(struct shirudo_tree_kv *dst, int *n, int max,
		  const char *key, const char *value)
{
	if (*n >= max)
		return -E2BIG;
	if (strscpy(dst[*n].key, key, sizeof(dst[0].key)) < 0 ||
	    strscpy(dst[*n].value, value, sizeof(dst[0].value)) < 0)
		return -ENOSPC;
	(*n)++;
	return 0;
}

static const char *kv_value(const struct shirudo_tree_kv *v, int n,
			    const char *key)
{
	for (int i = 0; i < n; i++) {
		if (!strcmp(v[i].key, key))
			return v[i].value;
	}
	return NULL;
}

static int selector_values_match(const struct shirudo_tree_selector_kv *v,
				 const char *want)
{
	if (!v || !want)
		return 0;
	for (int i = 0; i < v->n_values; i++) {
		if (!strcmp(v->values[i], want))
			return 1;
	}
	return 0;
}

static int read_config_file(const char *path, struct shirudo_tree_kv *out,
			    int *n, int max, bool gz)
{
	char line[512];
	int rc = 0;

	*n = 0;
	if (gz) {
		gzFile f = gzopen(path, "rb");

		if (!f)
			return -errno;
		while (gzgets(f, line, sizeof(line))) {
			char *eq, *key, *value;

			eq = strchr(line, '=');
			if (line[0] == '#' && !strncmp(line, "# CONFIG_", 9)) {
				key = line + 2;
				eq = strstr(key, " is not set");
				if (eq) {
					*eq = '\0';
					rc = kv_add(out, n, max, key, "n");
				}
			} else if (eq) {
				*eq++ = '\0';
				key = line;
				value = eq;
				value[strcspn(value, "\r\n")] = '\0';
				if (value[0] == '"') {
					size_t l = strlen(value);

					if (l > 1 && value[l - 1] == '"') {
						value[l - 1] = '\0';
						value++;
					}
				}
				rc = kv_add(out, n, max, key, value);
			}
			if (rc)
				break;
		}
		gzclose(f);
		return rc;
	}
	{
		FILE *f = fopen(path, "r");

		if (!f)
			return -errno;
		while (fgets(line, sizeof(line), f)) {
			char *start = line, *end, *eq;

			while (*start && isspace((__u8)*start))
				start++;
			if (*start == '#' || *start == '\0')
				continue;
			end = start + strlen(start);
			while (end > start && isspace((__u8)end[-1]))
				*--end = '\0';
			eq = strchr(start, '=');
			if (!eq)
				continue;
			*eq++ = '\0';
			end = eq + strlen(eq);
			while (end > eq && isspace((__u8)end[-1]))
				*--end = '\0';
			while (*eq && isspace((__u8)*eq))
				eq++;
			rc = kv_add(out, n, max, start, eq);
			if (rc)
				break;
		}
		fclose(f);
	}
	return rc;
}

/*
 * The kernel config can contain thousands of entries.  Index only the
 * selector keys, then scan the complete config once and retain matching
 * values.  This avoids both an arbitrary config-entry cap and an O(N*M)
 * lookup for N config entries and M selector keys.
 */
#define SHIRUDO_TREE_SELECTOR_HASH_SIZE 128

static __u32 selector_hash(const char *key)
{
	__u32 hash = 2166136261u;

	for (; *key; key++)
		hash = (hash ^ (__u8)*key) * 16777619u;
	return hash;
}

static void selector_hash_build(const struct shirudo_tree_selector *s,
				int slots[SHIRUDO_TREE_SELECTOR_HASH_SIZE])
{
	memset(slots, 0xff, sizeof(int) * SHIRUDO_TREE_SELECTOR_HASH_SIZE);
	for (int i = 0; i < s->n_kconfig; i++) {
		__u32 slot = selector_hash(s->kconfig[i].key) &
			(SHIRUDO_TREE_SELECTOR_HASH_SIZE - 1);

		while (slots[slot] >= 0 &&
		       strcmp(s->kconfig[slots[slot]].key, s->kconfig[i].key))
			slot = (slot + 1) & (SHIRUDO_TREE_SELECTOR_HASH_SIZE - 1);
		if (slots[slot] < 0)
			slots[slot] = i;
	}
}

static int selector_hash_find(const struct shirudo_tree_selector *s,
			      const int slots[SHIRUDO_TREE_SELECTOR_HASH_SIZE],
			      const char *key)
{
	__u32 slot = selector_hash(key) &
		(SHIRUDO_TREE_SELECTOR_HASH_SIZE - 1);

	for (int probes = 0; probes < SHIRUDO_TREE_SELECTOR_HASH_SIZE;
	     probes++, slot = (slot + 1) &
	     (SHIRUDO_TREE_SELECTOR_HASH_SIZE - 1)) {
		if (slots[slot] < 0)
			return -1;
		if (!strcmp(s->kconfig[slots[slot]].key, key))
			return slots[slot];
	}
	return -1;
}

static int selector_config_line(const char *line,
				const struct shirudo_tree_selector *s,
				const int slots[SHIRUDO_TREE_SELECTOR_HASH_SIZE],
				char values[][SHIRUDO_TREE_STRING_MAX],
				bool found[])
{
	char copy[1024], *start, *eq, *end, *value;
	int index;

	if (strscpy(copy, line, sizeof(copy)) < 0)
		return 0;
	start = copy;
	while (*start && isspace((__u8)*start))
		start++;
	if (!*start)
		return 0;

	if (!strncmp(start, "# CONFIG_", 9)) {
		start += 2;
		eq = strstr(start, " is not set");
		if (!eq)
			return 0;
		*eq = '\0';
		value = "n";
	} else {
		if (*start == '#')
			return 0;
		eq = strchr(start, '=');
		if (!eq)
			return 0;
		*eq++ = '\0';
		end = start + strlen(start);
		while (end > start && isspace((__u8)end[-1]))
			*--end = '\0';
		while (*eq && isspace((__u8)*eq))
			eq++;
		end = eq + strlen(eq);
		while (end > eq && isspace((__u8)end[-1]))
			*--end = '\0';
		value = eq;
		if (value[0] == '"') {
			size_t len = strlen(value);

			if (len > 1 && value[len - 1] == '"') {
				value[len - 1] = '\0';
				value++;
			}
		}
	}

	index = selector_hash_find(s, slots, start);
	if (index < 0)
		return 0;
	if (strscpy(values[index], value, SHIRUDO_TREE_STRING_MAX) < 0)
		return -ENOSPC;
	found[index] = true;
	return 0;
}

static int read_selector_config_file(const char *path,
				     const struct shirudo_tree_selector *s,
				     const int slots[SHIRUDO_TREE_SELECTOR_HASH_SIZE],
				     char values[][SHIRUDO_TREE_STRING_MAX],
				     bool found[], bool gz)
{
	char line[1024];
	int rc = 0;

	if (gz) {
		gzFile f = gzopen(path, "rb");

		if (!f)
			return -errno;
		while (gzgets(f, line, sizeof(line))) {
			rc = selector_config_line(line, s, slots, values, found);
			if (rc)
				break;
		}
		if (!rc && gzclose(f) != Z_OK)
			rc = -EIO;
		else if (rc)
			gzclose(f);
		return rc;
	}

	{
		FILE *f = fopen(path, "r");

		if (!f)
			return -errno;
		while (fgets(line, sizeof(line), f)) {
			rc = selector_config_line(line, s, slots, values, found);
			if (rc)
				break;
		}
		if (!rc && ferror(f))
			rc = errno ? -errno : -EIO;
		fclose(f);
	}
	return rc;
}

int tree_selector_matches(const struct shirudo_tree_selector *s)
{
	struct utsname u;
	struct shirudo_tree_kv labels[SHIRUDO_TREE_MAX_LABELS];
	char cfg_values[SHIRUDO_TREE_MAX_KCONFIG][SHIRUDO_TREE_STRING_MAX];
	int cfg_slots[SHIRUDO_TREE_SELECTOR_HASH_SIZE];
	bool cfg_found[SHIRUDO_TREE_MAX_KCONFIG] = {};
	int nl = 0, config_rc, rc;
	const char *v;
	char path[PATH_MAX];
	bool matched, config_any;

	/*
	 * An empty selector is the tree's explicit wildcard.  Evaluate this
	 * before consulting node metadata so an unconstrained operation is
	 * still applicable if uname(2) is unavailable.
	 */
	if (!s)
		return 0;
	if (!s->n_kernel_release_prefix && !s->n_kernel_build_id && !s->n_architecture &&
	    !s->n_kconfig && !s->n_labels)
		return 1;
	if (uname(&u) != 0)
		return 0;
	if (s->n_kernel_release_prefix) {
		matched = false;
		for (int i = 0; i < s->n_kernel_release_prefix; i++) {
			if (kernel_release_prefix_matches(u.release,
							  s->kernel_release_prefix[i])) {
				matched = true;
				break;
			}
		}
		if (!matched)
			return 0;
	}
	if (s->n_kernel_build_id) {
		char build_id[SHIRUDO_KERNEL_BUILD_ID_STRING_MAX];

		/*
		 * A selector carrying a build ID is deliberately fail-closed
		 * when the running kernel does not publish a GNU build ID.
		 */
		if (kernel_build_id_read(build_id))
			return 0;
		matched = false;
		for (int i = 0; i < s->n_kernel_build_id; i++) {
			if (!strcmp(build_id, s->kernel_build_id[i])) {
				matched = true;
				break;
			}
		}
		if (!matched)
			return 0;
	}
	if (s->n_architecture) {
		matched = false;
		for (int i = 0; i < s->n_architecture; i++) {
			if (!strcmp(u.machine, s->architecture[i])) {
				matched = true;
				break;
			}
		}
		if (!matched)
			return 0;
	}
	if (s->n_kconfig) {
		selector_hash_build(s, cfg_slots);
		config_rc = read_selector_config_file("/proc/config.gz", s,
						      cfg_slots, cfg_values, cfg_found,
						      true);
		config_any = false;
		for (int i = 0; i < s->n_kconfig; i++) {
			if (cfg_found[i])
				config_any = true;
		}
		if (config_rc || !config_any) {
			memset(cfg_found, 0, sizeof(cfg_found));
			snprintf(path, sizeof(path), "/boot/config-%s", u.release);
			if (read_selector_config_file(path, s, cfg_slots, cfg_values,
						      cfg_found, false))
				return 0;
		}
		for (int i = 0; i < s->n_kconfig; i++) {
			if (!cfg_found[i] ||
			    !selector_values_match(&s->kconfig[i], cfg_values[i]))
				return 0;
		}
	}
	if (s->n_labels) {
		rc = read_config_file("/etc/shirudo/node.labels", labels, &nl,
				      ARRAY_SIZE(labels), false);
		if (rc == -ENOENT)
			return 0;
		if (rc)
			return rc;
		for (int i = 0; i < s->n_labels; i++) {
			v = kv_value(labels, nl, s->labels[i].key);
			if (!v || !selector_values_match(&s->labels[i], v))
				return 0;
		}
	}
	return 1;
}

static int tree_read_file(const char *path, __u8 **body, size_t *len)
{
	struct stat st;
	__u8 *p;
	ssize_t got;
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) || st.st_size < 0 || st.st_size > SHIRUDO_JSON_MAX_BYTES) {
		close(fd);
		return -E2BIG;
	}
	p = xmalloc((size_t)st.st_size + 1);
	if (!p) {
		close(fd);
		return -ENOMEM;
	}
	got = read(fd, p, (size_t)st.st_size);
	close(fd);
	if (got != st.st_size) {
		xfree(p, (size_t)st.st_size + 1);
		return -EIO;
	}
	p[got] = '\0';
	*body = p;
	*len = (size_t)got;
	return 0;
}

/* hex is exactly 64 hex digits: a SHA-256 digest. */
static bool hex32_valid(const char *hex)
{
	__u8 raw[32];

	return !hex_decode(hex, raw, sizeof(raw));
}

int tree_state_read(struct shirudo_tree_state *out)
{
	__u8 *body;
	size_t len;
	__s64 schema = 0;
	struct shirudo_json_field f[] = {
		{ "schema", SHIRUDO_JSON_T_INT, &schema, 0, 0, NULL, 0 },
		{ "tree_id", SHIRUDO_JSON_T_STRING, out->tree_id,
		  sizeof(out->tree_id), 0, NULL, 0 },
		{ "generation", SHIRUDO_JSON_T_INT, &out->generation, 0, 0, NULL, 0 },
		{ "last_seq", SHIRUDO_JSON_T_INT, &out->last_seq, 0, 0, NULL, 0 },
		{ "projection_root", SHIRUDO_JSON_T_STRING, out->projection_root,
		  sizeof(out->projection_root), 0, NULL, 0 },
		{ "projection_root_tpm", SHIRUDO_JSON_T_STRING,
		  out->projection_root_tpm, sizeof(out->projection_root_tpm), 0, NULL, 0 },
		{ "manifest_digest", SHIRUDO_JSON_T_STRING, out->manifest_digest,
		  sizeof(out->manifest_digest), 0, NULL, 0 },
	};
	int rc;

	*out = (struct shirudo_tree_state){};
	rc = tree_read_file(SHIRUDO_BPM_TREE_STATE_PATH, &body, &len);
	if (rc)
		return rc;
	rc = json_parse((const char *)body, len, f, ARRAY_SIZE(f));
	if (!rc && (schema != 1 || !f[1].seen || !f[3].seen || !f[4].seen))
		rc = -EINVAL;
	if (!rc && !f[5].seen) {
		/* State written before the software projection field was added. */
		memcpy(out->projection_root_tpm, out->projection_root,
		       sizeof(out->projection_root_tpm));
	}
	if (!rc && (strlen(out->projection_root) != 64 ||
		    !hex32_valid(out->projection_root) ||
		    (out->projection_root_tpm[0] &&
		     (strlen(out->projection_root_tpm) != 64 ||
		      !hex32_valid(out->projection_root_tpm)))))
		rc = -EINVAL;
	if (!rc && out->manifest_digest[0] &&
	    (strlen(out->manifest_digest) != 71 ||
	     strncmp(out->manifest_digest, "sha256:", 7) ||
	     !hex32_valid(out->manifest_digest + 7)))
		rc = -EINVAL;
	out->schema = (int)schema;
	xfree(body, len + 1);
	return rc;
}

static int tree_atomic_write(const char *path, const void *data, size_t len)
{
	const char *slash = strrchr(path, '/');
	char dir[PATH_MAX];
	int rc;

	if (!slash || (size_t)(slash - path) >= sizeof(dir))
		return -EINVAL;
	memcpy(dir, path, slash - path);
	dir[slash - path] = '\0';
	rc = seal_mkdir_p(dir, 0700);
	if (rc) {
		pr_err("tree state mkdir %s: %s", dir, strerror(-rc));
		return rc;
	}
	return seal_write_file(path, data, len, 0600);
}

int tree_state_write(const struct shirudo_tree_state *s)
{
	char buf[4096];
	struct shirudo_json_emit e = { .buf = buf, .cap = sizeof(buf) };

	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_kv_string(&e, "tree_id", s->tree_id);
	json_kv_int(&e, "generation", s->generation);
	json_kv_int(&e, "last_seq", s->last_seq);
	json_kv_string(&e, "projection_root", s->projection_root);
	json_kv_string(&e, "projection_root_tpm", s->projection_root_tpm);
	json_kv_string(&e, "manifest_digest", s->manifest_digest);
	json_obj_close(&e);
	if (e.err)
		return e.err;
	return tree_atomic_write(SHIRUDO_BPM_TREE_STATE_PATH, buf, e.len);
}

/*
 * Each line goes in with one write, newline included, so a file that
 * does not end in one ends in an append a crash cut short. The chain
 * runs over every line and cannot pass over it: the torn tail goes,
 * and the operation it recorded is applied again.
 */
static int drop_torn_tail(int fd, off_t size, off_t *kept)
{
	char tail[4096];
	off_t from;
	ssize_t n;

	*kept = size;
	if (size == 0)
		return 0;
	from = size > (off_t)sizeof(tail) ? size - (off_t)sizeof(tail) : 0;
	n = pread(fd, tail, (size_t)(size - from), from);
	if (n != size - from)
		return n < 0 ? -errno : -EIO;
	if (tail[n - 1] == '\n')
		return 0;
	while (n > 0 && tail[n - 1] != '\n')
		n--;
	if (n == 0 && from > 0)
		return -EBADMSG;
	*kept = from + n;
	pr_warn("tree: dropping a torn record at the end of %s",
		SHIRUDO_BPM_TREE_EVENTLOG_PATH);
	return ftruncate(fd, *kept) != 0 ? -errno : 0;
}

int tree_event_append(__s64 seq, const char *operation_digest,
		      const __u8 projection_root[32])
{
	char buf[1024], root[65];
	struct shirudo_json_emit e = { .buf = buf, .cap = sizeof(buf) - 1 };
	struct stat st;
	off_t kept;
	int fd, rc;

	if (!operation_digest || strncmp(operation_digest, "sha256:", 7) ||
	    !hex32_valid(operation_digest + 7))
		return -EINVAL;
	hex_encode(projection_root, 32, root);
	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_kv_int(&e, "seq", seq);
	json_kv_string(&e, "digest", operation_digest);
	json_kv_string(&e, "projection_root", root);
	json_obj_close(&e);
	if (e.err)
		return e.err;
	rc = seal_mkdir_p(SHIRUDO_BPM_TREE_VAR_DIR, 0700);
	if (rc)
		return rc;
	fd = seal_open(SHIRUDO_BPM_TREE_EVENTLOG_PATH,
		       O_RDWR | O_CREAT | O_APPEND, 0600);
	if (fd < 0)
		return fd;
	/* A partial line would fail every later replay; roll it back. */
	while (flock(fd, LOCK_EX) != 0) {
		if (errno != EINTR) {
			rc = -errno;
			goto out;
		}
	}
	if (fstat(fd, &st) != 0) {
		rc = -errno;
		goto out;
	}
	rc = drop_torn_tail(fd, st.st_size, &kept);
	if (rc)
		goto out;
	buf[e.len] = '\n';
	rc = write_all(fd, buf, e.len + 1);
	if (!rc && fsync(fd))
		rc = -errno;
	if (rc && ftruncate(fd, kept))
		pr_warn("tree: could not roll back a partial append to %s: %s",
			SHIRUDO_BPM_TREE_EVENTLOG_PATH, strerror(errno));
out:
	if (close(fd) && !rc)
		rc = -errno;
	return rc;
}

int tree_event_replay(__u8 out[32])
{
	__u8 *body;
	size_t len;
	char *save, *line;
	__u8 chain[32] = {};
	__s64 previous_seq = 0;
	int rc = tree_read_file(SHIRUDO_BPM_TREE_EVENTLOG_PATH, &body, &len);

	if (rc)
		return rc;
	for (line = strtok_r((char *)body, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char digest[128] = {};
		char projection[65] = {};
		__s64 seq = 0;
		struct shirudo_json_field f[] = {
			{ "seq", SHIRUDO_JSON_T_INT, &seq, 0, 0, NULL, 0 },
			{ "digest", SHIRUDO_JSON_T_STRING, digest, sizeof(digest),
			  0, NULL, 0 },
			{ "projection_root", SHIRUDO_JSON_T_STRING, projection,
			  sizeof(projection), 0, NULL, 0 },
		};
		__u8 d[32], next[64], recorded[32];

		rc = json_parse(line, strlen(line), f, ARRAY_SIZE(f));
		if (rc || !f[0].seen || !f[1].seen || !f[2].seen ||
		    seq <= previous_seq || strlen(projection) != 64 ||
		    hex_decode(projection, recorded, 32)) {
			rc = -EINVAL;
			break;
		}
		previous_seq = seq;
		if (strncmp(digest, "sha256:", 7) ||
		    hex_decode(digest + 7, d, sizeof(d))) {
			rc = -EINVAL;
			break;
		}
		memcpy(next, chain, 32);
		memcpy(next + 32, d, 32);
		shirudo_sha256(next, sizeof(next), chain);
		if (!ct_eq(chain, recorded, 32)) {
			rc = -EINVAL;
			break;
		}
	}
	if (!rc)
		memcpy(out, chain, 32);
	xfree(body, len + 1);
	return rc;
}

void tree_emit_status(struct shirudo_json_emit *e)
{
	struct shirudo_tree_state s = {};
	__u8 live[32], replay[32];
	char hex[65];
	bool configured = access(SHIRUDO_BPM_TREE_ETC_PATH, R_OK) == 0;

	json_obj_open_key(e, "upatch_tree");
	json_kv_bool(e, "configured", configured);
	json_kv_bool(e, "pending", access(SHIRUDO_BPM_TREE_PENDING_PATH,
					  R_OK) == 0);
	if (tree_state_read(&s) == 0) {
		json_kv_string(e, "tree_id", s.tree_id);
		json_kv_int(e, "generation", s.generation);
		json_kv_int(e, "last_seq", s.last_seq);
		json_kv_string(e, "projection_root", s.projection_root);
		json_kv_string(e, "manifest_digest", s.manifest_digest);
	} else {
		json_kv_null(e, "state");
	}
	if (tree_event_replay(replay) == 0) {
		hex_encode(replay, 32, hex);
		json_kv_string(e, "eventlog_projection_root", hex);
		json_kv_bool(e, "eventlog_matches_state",
			     hex_decode(s.projection_root, live,
					32) == 0 &&
			     ct_eq(live, replay, 32));
	} else {
		json_kv_null(e, "eventlog_projection_root");
		json_kv_null(e, "eventlog_matches_state");
	}
	json_obj_close(e);
}
