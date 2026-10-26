// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The eventlog: one JSON line per register extension, appended only
 * after the extend succeeded so a replay reproduces the live value.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <shirudo/misc.h>

#include "chain.h"
#include "eventlog.h"
#include "timefmt.h"
#include "io.h"
#include "json.h"
#include "log.h"
#include "malloc.h"
#include "paths.h"
#include "seal.h"

const char *eventlog_path(void)
{
	const char *env = shirudo_image_config_active() ? NULL :
		getenv("SHIRUDO_EVENTLOG_PATH");

	return env && *env ? env : SHIRUDO_EVENTLOG_PATH;
}

const char *eventlog_pending_path(void)
{
	const char *env = shirudo_image_config_active() ? NULL :
		getenv("SHIRUDO_EVENTLOG_PENDING_PATH");

	return env && *env ? env : SHIRUDO_EVENTLOG_PENDING_PATH;
}

static int adopt_pending(void);

/*
 * The init record the initrd left pending opens this boot's part of the
 * log: a line appended ahead of it would drop out of every replay, so
 * the record is adopted first.
 */
int eventlog_append(const char *json_line)
{
	int rc;

	rc = adopt_pending();
	if (rc)
		return rc;
	return eventlog_append_to(eventlog_path(), json_line);
}

/*
 * A line cut short, by a full file system say, would leave every reader
 * of the log failing on it, so a failed append is rolled back under the
 * lock that keeps appenders from interleaving.
 */
int eventlog_append_to(const char *path, const char *json_line)
{
	size_t len = strlen(json_line);
	struct stat st;
	int fd, rc;

	fd = seal_open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
	if (fd < 0) {
		pr_err("eventlog: open %s: %s", path, strerror(-fd));
		return fd;
	}
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

	rc = write_complete(fd, json_line, len);
	if (!rc && (len == 0 || json_line[len - 1] != '\n'))
		rc = write_complete(fd, "\n", 1);
	if (!rc && fsync(fd) != 0)
		rc = -errno;
	if (rc && ftruncate(fd, st.st_size) != 0)
		pr_warn("eventlog: could not roll back a partial append to "
			"%s: %s", path, strerror(errno));
out:
	if (close(fd) != 0 && !rc)
		rc = -errno;
	if (rc) {
		pr_err("eventlog: append: %s", strerror(-rc));
		return rc;
	}
	return 0;
}

int eventlog_would_exceed(__u64 max_bytes)
{
	struct stat st;
	__u64 cur = 0;

	if (max_bytes == 0)
		return 0;	/* unlimited */
	if (stat(eventlog_path(), &st) == 0)
		cur = (__u64)st.st_size;
	return cur + SHIRUDO_EVENTLOG_LINE_MAX > max_bytes;
}

static int read_log(char **out, size_t *out_len)
{
	size_t base_len = 0, pending_len = 0, off;
	char *base = NULL, *pending = NULL, *buf;
	int rc, rc_pending;

	rc = read_file(eventlog_path(), SHIRUDO_JSON_MAX_BYTES,
		       &base, &base_len);
	if (rc && rc != -ENOENT)
		return rc;
	rc_pending = read_file(eventlog_pending_path(),
			       SHIRUDO_JSON_MAX_BYTES, &pending,
			       &pending_len);
	if (rc_pending && rc_pending != -ENOENT) {
		xfree(base, base_len + 1);
		return rc_pending;
	}
	if (rc && rc_pending)
		return -ENOENT;
	if (rc_pending) {
		*out = base;
		*out_len = base_len;
		return 0;
	}
	if (rc) {
		*out = pending;
		*out_len = pending_len;
		return 0;
	}
	if (base_len + pending_len > SHIRUDO_JSON_MAX_BYTES) {
		rc = -EFBIG;
		goto out;
	}
	buf = xmalloc(base_len + pending_len + 2);
	if (!buf) {
		rc = -ENOMEM;
		goto out;
	}
	memcpy(buf, base, base_len);
	off = base_len;
	if (off && buf[off - 1] != '\n')
		buf[off++] = '\n';
	memcpy(buf + off, pending, pending_len);
	off += pending_len;
	buf[off] = '\0';
	*out = buf;
	*out_len = off;
out:
	xfree(base, base_len + 1);
	xfree(pending, pending_len + 1);
	return rc;
}

/*
 * This boot's records from its last init line on; the callback learns
 * which line that is so a replay can start from zero.
 */
static int walk_lines(char *buf, int (*cb)(const char *line, size_t len,
					   bool is_init, void *ctx), void *ctx)
{
	char boot_id[64], line_boot[64], type[32];
	bool in_boot = false;
	char *line, *save;
	int rc = 0;

	eventlog_boot_id(boot_id, sizeof(boot_id));
	for (line = strtok_r(buf, "\n", &save); line && !rc;
	     line = strtok_r(NULL, "\n", &save)) {
		struct shirudo_json_field f[] = {
			{ "boot_id", SHIRUDO_JSON_T_STRING, line_boot,
			  sizeof(line_boot), 0, NULL, 0 },
			{ "type", SHIRUDO_JSON_T_STRING, type, sizeof(type),
			  0, NULL, 0 },
		};
		bool is_init;

		line_boot[0] = '\0';
		type[0] = '\0';
		if (json_parse(line, strlen(line), f, 2)) {
			rc = -EINVAL;
			break;
		}
		if (!f[0].seen || !boot_id[0] || strcmp(line_boot, boot_id))
			continue;
		is_init = f[1].seen && strcmp(type, "init") == 0;
		if (is_init)
			in_boot = true;
		if (!in_boot)
			continue;
		rc = cb(line, strlen(line), is_init, ctx);
	}
	if (!rc && !in_boot)
		return -ENOENT;
	return rc;
}

static int walk_boot(int (*cb)(const char *line, size_t len, bool is_init,
			       void *ctx), void *ctx)
{
	char *buf = NULL;
	size_t len = 0;
	int rc;

	rc = read_log(&buf, &len);
	if (rc)
		return rc;
	rc = walk_lines(buf, cb, ctx);
	xfree(buf, len + 1);
	return rc;
}

struct adopt_ctx {
	const char	*line;
	size_t		len;
	bool		found;
};

static int adopt_seen(const char *line, size_t len, bool is_init, void *ctx)
{
	struct adopt_ctx *a = ctx;

	(void)is_init;
	if (len == a->len && memcmp(line, a->line, len) == 0)
		a->found = true;
	return 0;
}

static int log_holds(const char *line, size_t len)
{
	struct adopt_ctx a = { .line = line, .len = len };
	char *buf = NULL;
	size_t blen = 0;
	int rc;

	rc = read_file(eventlog_path(), SHIRUDO_JSON_MAX_BYTES,
		       &buf, &blen);
	if (rc == -ENOENT)
		return 0;
	if (rc)
		return rc;
	rc = walk_lines(buf, adopt_seen, &a);
	xfree(buf, blen + 1);
	if (rc && rc != -ENOENT)
		return rc;
	return a.found ? 1 : 0;
}

static int adopt_pending(void)
{
	const char *pending = eventlog_pending_path();
	char *buf = NULL, *line, *save;
	size_t len = 0;
	int rc;

	rc = read_file(pending, SHIRUDO_JSON_MAX_BYTES, &buf, &len);
	if (rc == -ENOENT)
		return 0;
	if (rc)
		return rc;
	for (line = strtok_r(buf, "\n", &save); line && !rc;
	     line = strtok_r(NULL, "\n", &save)) {
		if (!*line)
			continue;
		rc = log_holds(line, strlen(line));
		if (rc > 0) {
			rc = 0;
			continue;
		}
		if (!rc)
			rc = eventlog_append_to(eventlog_path(),
						line);
	}
	xfree(buf, len + 1);
	if (rc)
		return rc;
	if (unlink(pending) != 0 && errno != ENOENT)
		return -errno;
	return 0;
}

int eventlog_adopt_pending(void)
{
	return adopt_pending();
}

static int replay_line(const char *line, size_t len, bool is_init, void *ctx)
{
	char digest_hex[2 * 32 + 1];
	struct shirudo_json_field f[] = {
		{ "digest", SHIRUDO_JSON_T_STRING, digest_hex,
		  sizeof(digest_hex), 0, NULL, 0 },
	};
	__u8 digest[32], cat[64];
	__u8 *chain = ctx;

	if (json_parse(line, len, f, 1) || !f[0].seen ||
	    hex_decode(digest_hex, digest, sizeof(digest)))
		return -EINVAL;
	if (is_init)
		memset(chain, 0, 32);
	memcpy(cat, chain, 32);
	memcpy(cat + 32, digest, 32);
	shirudo_sha256(cat, sizeof(cat), chain);
	return 0;
}

int eventlog_replay(__u8 out[32])
{
	__u8 chain[32] = {};
	int rc;

	rc = walk_boot(replay_line, chain);
	if (!rc)
		memcpy(out, chain, 32);
	return rc;
}

static int init_line(const char *line, size_t len, bool is_init, void *ctx)
{
	char writer_public[2 * SHIRUDO_TPM_NV_RSA_BYTES + 1];
	char pcr_before[2 * 32 + 1], name[2 * SHIRUDO_TPM_NAME_LEN + 1];
	char phase_before[2 * 32 + 1], anchor[2 * 32 + 1], bound_in[8];
	struct shirudo_eventlog_init *out = ctx;
	__s64 pcr = -1, reset_count = -1;
	struct shirudo_json_field f[] = {
		{ "pcr_before", SHIRUDO_JSON_T_STRING, pcr_before,
		  sizeof(pcr_before), 0, NULL, 0 },
		{ "nv_name", SHIRUDO_JSON_T_STRING, name, sizeof(name), 0,
		  NULL, 0 },
		{ "anchor_digest", SHIRUDO_JSON_T_STRING, anchor,
		  sizeof(anchor), 0, NULL, 0 },
		{ "pcr", SHIRUDO_JSON_T_INT, &pcr, 0, 0, NULL, 0 },
		{ "tpm_reset_count", SHIRUDO_JSON_T_INT, &reset_count, 0, 0,
		  NULL, 0 },
		{ "phase_before", SHIRUDO_JSON_T_STRING, phase_before,
		  sizeof(phase_before), 0, NULL, 0 },
		{ "bound_in", SHIRUDO_JSON_T_STRING, bound_in, sizeof(bound_in),
		  0, NULL, 0 },
		{ "nv_writer_public", SHIRUDO_JSON_T_STRING, writer_public,
		  sizeof(writer_public), 0, NULL, 0 },
	};
	bool have_reset_count;

	if (!is_init)
		return 0;
	bound_in[0] = '\0';
	if (json_parse(line, len, f, 8) || !f[0].seen || !f[1].seen ||
	    !f[2].seen || !f[3].seen || !f[5].seen || pcr < 0 || pcr >= 24 ||
	    (f[4].seen && (reset_count < 0 || reset_count > UINT32_MAX)) ||
	    strlen(name) != 2 * SHIRUDO_TPM_NAME_LEN ||
	    hex_decode(pcr_before, out->pcr_before, 32) ||
	    hex_decode(phase_before, out->phase_before, 32) ||
	    hex_decode(name, out->name, SHIRUDO_TPM_NAME_LEN) ||
	    hex_decode(anchor, out->anchor_digest, 32) || !f[7].seen ||
	    hex_decode(writer_public, out->writer_public,
		       sizeof(out->writer_public)))
		return -EINVAL;
	out->initrd = f[6].seen && !strcmp(bound_in, "initrd");
	/*
	 * Records are of one TPM reset unless both carry a count and
	 * the counts differ; a record without one cannot vouch for a
	 * reset in between.
	 */
	have_reset_count = f[4].seen;
	out->records++;
	if (out->records == 1 ||
	    (have_reset_count && out->have_reset_count &&
	     (__u32)reset_count != out->reset_count))
		out->records_epoch = 1;
	else
		out->records_epoch++;
	out->have_reset_count = have_reset_count;
	out->reset_count = (__u32)reset_count;
	out->name_len = SHIRUDO_TPM_NAME_LEN;
	out->pcr = (__u32)pcr;
	return 0;
}

int eventlog_boot_init(struct shirudo_eventlog_init *out)
{
	memset(out, 0, sizeof(*out));
	return walk_boot(init_line, out);
}

struct lines_ctx {
	int	(*cb)(const char *line, size_t len, void *ctx);
	void	*ctx;
};

static int lines_line(const char *line, size_t len, bool is_init, void *ctx)
{
	struct lines_ctx *l = ctx;

	return l->cb(line, len, l->ctx);
}

int eventlog_boot_lines(int (*cb)(const char *line, size_t len,
				  void *ctx), void *ctx)
{
	struct lines_ctx l = { cb, ctx };

	return walk_boot(lines_line, &l);
}

void eventlog_timestamp(char *out, size_t cap)
{
	iso8601(time(NULL), out, cap);
}

void eventlog_boot_id(char *out, size_t cap)
{
	ssize_t n;
	int fd;

	out[0] = '\0';
	fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	n = read(fd, out, cap - 1);
	close(fd);
	if (n <= 0) {
		out[0] = '\0';
		return;
	}
	out[n] = '\0';
	while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
		out[--n] = '\0';
}
