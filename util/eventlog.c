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
	const char *env = getenv("SHIRUDO_EVENTLOG_PATH");

	return env && *env ? env : SHIRUDO_EVENTLOG_PATH;
}

const char *eventlog_pending_path(void)
{
	const char *env = getenv("SHIRUDO_EVENTLOG_PENDING_PATH");

	return env && *env ? env : SHIRUDO_EVENTLOG_PENDING_PATH;
}

/*
 * The largest line shirudo writes, an init record; a longer one is not a
 * record and is passed over whole.
 */
#define EVENTLOG_LINE_CAP	(64 * 1024)

/*
 * Held across a register extend and the append that records it, so
 * that the order of the lines is the order of the extends, and shared
 * by readers, which would otherwise see half an append or a pending
 * record both adopted and still pending.
 */
static int lock_fd = -1, lock_depth;
static bool lock_excl;

int eventlog_lock(bool exclusive)
{
	int fd;

	if (lock_depth) {
		if (exclusive && !lock_excl)
			return -EDEADLK;
		lock_depth++;
		return 0;
	}
	if (exclusive) {
		fd = seal_open(eventlog_path(), O_RDWR | O_CREAT | O_APPEND,
			       0600);
	} else {
		fd = open(eventlog_path(), O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			fd = -errno;
	}
	if (fd == -ENOENT) {
		fd = -1;
	} else if (fd < 0) {
		pr_err("eventlog: open %s: %s", eventlog_path(),
		       strerror(-fd));
		return fd;
	}
	while (fd >= 0 && flock(fd, exclusive ? LOCK_EX : LOCK_SH) != 0) {
		if (errno != EINTR) {
			int rc = -errno;

			close(fd);
			return rc;
		}
	}
	lock_fd = fd;
	lock_depth = 1;
	lock_excl = exclusive;
	return 0;
}

void eventlog_unlock(void)
{
	if (!lock_depth || --lock_depth)
		return;
	if (lock_fd >= 0)
		close(lock_fd);
	lock_fd = -1;
	lock_excl = false;
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

	rc = eventlog_lock(true);
	if (rc)
		return rc;
	rc = adopt_pending();
	if (!rc)
		rc = eventlog_append_to(eventlog_path(), json_line);
	eventlog_unlock();
	return rc;
}

/*
 * One write per line, behind a newline when the file does not end in
 * one: a line cut short by a crash then stays a line of its own rather
 * than swallowing the next. A failed append is rolled back under the
 * lock that keeps appenders from interleaving.
 */
static int append_fd(int fd, const char *path, const char *json_line)
{
	size_t len = strlen(json_line), n = 0;
	struct stat st;
	char *buf, last;
	int rc;

	if (fstat(fd, &st) != 0)
		return -errno;
	buf = xmalloc(len + 2);
	if (!buf)
		return -ENOMEM;
	if (st.st_size > 0) {
		if (pread(fd, &last, 1, st.st_size - 1) != 1) {
			rc = -EIO;
			goto out;
		}
		if (last != '\n')
			buf[n++] = '\n';
	}
	memcpy(buf + n, json_line, len);
	n += len;
	if (!len || json_line[len - 1] != '\n')
		buf[n++] = '\n';

	rc = write_all(fd, buf, n);
	if (!rc && fsync(fd) != 0)
		rc = -errno;
	if (rc && ftruncate(fd, st.st_size) != 0)
		pr_warn("eventlog: could not roll back a partial append to "
			"%s: %s", path, strerror(errno));
out:
	xfree(buf, len + 2);
	return rc;
}

int eventlog_append_to(const char *path, const char *json_line)
{
	int fd, rc;

	if (lock_depth && lock_excl && lock_fd >= 0 &&
	    strcmp(path, eventlog_path()) == 0) {
		rc = append_fd(lock_fd, path, json_line);
		goto out;
	}
	fd = seal_open(path, O_RDWR | O_CREAT | O_APPEND, 0600);
	if (fd < 0) {
		pr_err("eventlog: open %s: %s", path, strerror(-fd));
		return fd;
	}
	while (flock(fd, LOCK_EX) != 0) {
		if (errno != EINTR) {
			rc = -errno;
			close(fd);
			goto out;
		}
	}
	rc = append_fd(fd, path, json_line);
	if (close(fd) != 0 && !rc)
		rc = -errno;
out:
	if (rc)
		pr_err("eventlog: append: %s", strerror(-rc));
	return rc;
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

struct walk {
	char	boot_id[64];
	bool	in_boot;
	int	(*cb)(const char *line, size_t len, bool is_init, void *ctx);
	void	*ctx;
};

/*
 * Only this boot's lines are parsed: a line of an earlier boot that a
 * power cut left half written says nothing about this one, while a
 * malformed line of this boot is a record the replay cannot do without.
 */
static int walk_line(struct walk *w, const char *line, size_t len)
{
	char line_boot[64], type[32];
	struct shirudo_json_field f[] = {
		{ "boot_id", SHIRUDO_JSON_T_STRING, line_boot,
		  sizeof(line_boot), 0, NULL, 0 },
		{ "type", SHIRUDO_JSON_T_STRING, type, sizeof(type),
		  0, NULL, 0 },
	};
	bool is_init;

	if (!w->boot_id[0] ||
	    !memmem(line, len, w->boot_id, strlen(w->boot_id)))
		return 0;
	line_boot[0] = '\0';
	type[0] = '\0';
	if (json_parse(line, len, f, 2))
		return -EINVAL;
	if (!f[0].seen || strcmp(line_boot, w->boot_id))
		return 0;
	is_init = f[1].seen && strcmp(type, "init") == 0;
	if (is_init)
		w->in_boot = true;
	if (!w->in_boot)
		return 0;
	return w->cb(line, len, is_init, w->ctx);
}

/*
 * Streamed, so the log may grow past what fits in memory. A NUL ends a
 * line as a newline does: a crash can leave a run of zeros where an
 * append was, and the records written after it must stay visible.
 */
static int walk_fd(int fd, struct walk *w)
{
	size_t cap = 2 * EVENTLOG_LINE_CAP, have = 0, start, i;
	bool skipping = false;
	off_t off = 0;
	ssize_t n;
	char *buf;
	int rc = 0;

	buf = xmalloc(cap + 1);
	if (!buf)
		return -ENOMEM;
	for (;;) {
		n = pread(fd, buf + have, cap - have, off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			rc = -errno;
			break;
		}
		off += n;
		have += (size_t)n;
		if (n == 0 && have)
			buf[have++] = '\0';
		start = 0;
		for (i = 0; i < have && !rc; i++) {
			if (buf[i] != '\n' && buf[i] != '\0')
				continue;
			buf[i] = '\0';
			if (!skipping && i > start)
				rc = walk_line(w, buf + start, i - start);
			skipping = false;
			start = i + 1;
		}
		if (rc || n == 0)
			break;
		have -= start;
		memmove(buf, buf + start, have);
		if (have == cap) {
			skipping = true;
			have = 0;
		}
	}
	xfree(buf, cap + 1);
	return rc;
}

static int walk_path(const char *path, struct walk *w)
{
	int fd, rc;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOENT ? 0 : -errno;
	rc = walk_fd(fd, w);
	close(fd);
	return rc;
}

/*
 * This boot's records from its last init line on, the log's and then
 * the pending file's; the callback learns which line that is so a
 * replay can start from zero.
 */
static int walk_boot(int (*cb)(const char *line, size_t len, bool is_init,
			       void *ctx), void *ctx)
{
	struct walk w = { .cb = cb, .ctx = ctx };
	int rc;

	rc = eventlog_lock(false);
	if (rc)
		return rc;
	eventlog_boot_id(w.boot_id, sizeof(w.boot_id));
	rc = lock_fd >= 0 ? walk_fd(lock_fd, &w) : 0;
	if (!rc)
		rc = walk_path(eventlog_pending_path(), &w);
	eventlog_unlock();
	if (!rc && !w.in_boot)
		return -ENOENT;
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

/* Under the exclusive lock, which holds the log open. */
static int log_holds(const char *line, size_t len)
{
	struct adopt_ctx a = { .line = line, .len = len };
	struct walk w = { .cb = adopt_seen, .ctx = &a };
	int rc;

	if (lock_fd < 0)
		return 0;
	eventlog_boot_id(w.boot_id, sizeof(w.boot_id));
	rc = walk_fd(lock_fd, &w);
	if (rc)
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
	int rc;

	rc = eventlog_lock(true);
	if (rc)
		return rc;
	rc = adopt_pending();
	eventlog_unlock();
	return rc;
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
	};
	bool have_reset_count;

	if (!is_init)
		return 0;
	bound_in[0] = '\0';
	if (json_parse(line, len, f, 7) || !f[0].seen || !f[1].seen ||
	    !f[2].seen || !f[3].seen || !f[5].seen || pcr < 0 || pcr >= 24 ||
	    (f[4].seen && (reset_count < 0 || reset_count > UINT32_MAX)) ||
	    strlen(name) != 2 * SHIRUDO_TPM_NAME_LEN ||
	    hex_decode(pcr_before, out->pcr_before, 32) ||
	    hex_decode(phase_before, out->phase_before, 32) ||
	    hex_decode(name, out->name, SHIRUDO_TPM_NAME_LEN) ||
	    hex_decode(anchor, out->anchor_digest, 32))
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
