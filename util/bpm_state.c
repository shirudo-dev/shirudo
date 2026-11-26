// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "bpm_state.h"
#include "io.h"
#include "identity.h"
#include "json.h"
#include "malloc.h"
#include "paths.h"
#include "seal.h"

#define STATE_FILE_MAX	(8u * 1024u * 1024u)
#define STATE_EMIT_MAX	(1024u * 1024u)

struct state_sink {
	struct bpm_state_entry *items;
	int n;
	struct bpm_state_entry scratch;
};

static int on_state_entry(void *ud)
{
	struct state_sink *s = ud;
	char expected[PATH_MAX];

	if (s->n >= BPM_MAX_STATE)
		return -E2BIG;
	if (!s->scratch.name[0] || !s->scratch.version[0] ||
	    !bpm_name_ok(s->scratch.name) ||
	    !bpm_version_ok(s->scratch.version) ||
	    !bpm_name_ok(s->scratch.source))
		return -EINVAL;
	if (strsprintf(expected, sizeof(expected), "%s/%s/%s",
		       BPM_PACKAGES_DIR, s->scratch.name,
		       s->scratch.version) < 0 ||
	    strcmp(expected, s->scratch.path))
		return -EINVAL;
	s->items[s->n++] = s->scratch;
	/* A field the next entry leaves out is not this entry's. */
	memset(&s->scratch, 0, sizeof(s->scratch));
	return 0;
}

int bpm_state_parse(const char *body, size_t len,
		    struct bpm_state_entry *st, int *n)
{
	struct state_sink sink = { .items = st };
	struct json_array arr = { on_state_entry, &sink };
	struct json_field sub[] = {
		{ "name", JSON_T_STRING, sink.scratch.name,
		  sizeof(sink.scratch.name), 0, NULL, 0 },
		{ "version", JSON_T_STRING, sink.scratch.version,
		  sizeof(sink.scratch.version), 0, NULL, 0 },
		{ "source", JSON_T_STRING, sink.scratch.source,
		  sizeof(sink.scratch.source), 0, NULL, 0 },
		{ "path", JSON_T_STRING, sink.scratch.path,
		  sizeof(sink.scratch.path), 0, NULL, 0 },
	};
	struct json_field root[] = {
		{ "packages", JSON_T_ARRAY, &arr, 0, 0, sub, ARRAY_SIZE(sub) },
	};
	int ret;

	ret = json_parse(body, len, root, ARRAY_SIZE(root));
	if (ret)
		return ret;
	if (!root[0].seen)
		return -EINVAL;
	*n = sink.n;
	return 0;
}

int bpm_state_emit(const struct bpm_state_entry *st, int n, char *buf,
		   size_t cap, size_t *len)
{
	struct json_emit e = { .buf = buf, .cap = cap };

	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_arr_open(&e, "packages");
	for (int i = 0; i < n; i++) {
		json_obj_open(&e);
		json_kv_string(&e, "name", st[i].name);
		json_kv_string(&e, "version", st[i].version);
		json_kv_string(&e, "source", st[i].source);
		json_kv_string(&e, "path", st[i].path);
		json_obj_close(&e);
	}
	json_arr_close(&e);
	json_obj_close(&e);
	if (e.err)
		return -E2BIG;
	*len = e.len;
	return 0;
}

static int read_state_file(char **body, size_t *len)
{
	int active, root, bpm, fd, ret;

	active = enforcement_active();
	if (active <= 0)
		return active ? active : read_file(BPM_STATE_PATH, STATE_FILE_MAX, body, len);
	root = state_root_open();
	if (root < 0)
		return root == -ENOENT ? -ENODEV : root;
	bpm = seal_open_child(root, "bpm", O_RDONLY | O_DIRECTORY);
	close(root);
	if (bpm < 0)
		return bpm;
	fd = seal_open_child(bpm, "state.json", O_RDONLY | O_NONBLOCK);
	close(bpm);
	if (fd < 0)
		return fd;
	ret = read_fd(fd, BPM_STATE_PATH, STATE_FILE_MAX, body, len);
	close(fd);
	return ret;
}

int bpm_state_read(struct bpm_state_entry *st, int *n)
{
	size_t len;
	char *body;
	int ret;

	ret = read_state_file(&body, &len);
	if (ret == -ENOENT) {
		*n = 0;
		return 0;
	}
	if (ret)
		return ret;
	ret = bpm_state_parse(body, len, st, n);
	xfree(body, len + 1);
	return ret;
}

static int write_state_file(const char *buf, size_t len)
{
	int active, root, bpm, ret;

	active = enforcement_active();
	if (active < 0)
		return active;
	if (!active) {
		ret = seal_mkdir_p(BPM_VAR_DIR, 0700);
		return ret ? ret : seal_write_file(BPM_STATE_PATH, buf, len, 0600);
	}
	root = state_root_open();
	if (root < 0)
		return root;
	if (mkdirat(root, "bpm", 0700) && errno != EEXIST) {
		ret = -errno;
		close(root);
		return ret;
	}
	bpm = seal_open_child(root, "bpm", O_RDONLY | O_DIRECTORY);
	close(root);
	if (bpm < 0)
		return bpm;
	ret = seal_replace_locked_at(bpm, "state.json", buf, len, 0600);
	close(bpm);
	return ret;
}

int bpm_state_write(const struct bpm_state_entry *st, int n)
{
	size_t len = 0;
	char *buf;
	int ret;

	buf = xmalloc(STATE_EMIT_MAX);
	if (!buf)
		return -ENOMEM;
	ret = bpm_state_emit(st, n, buf, STATE_EMIT_MAX, &len);
	if (!ret)
		ret = write_state_file(buf, len);
	xfree(buf, STATE_EMIT_MAX);
	return ret;
}
