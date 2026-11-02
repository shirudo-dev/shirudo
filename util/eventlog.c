// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The eventlog: one JSON line per register extension, appended only
 * after the extend succeeded so a replay reproduces the live value.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "chain.h"
#include "eventlog.h"
#include "hex.h"
#include "timefmt.h"
#include "io.h"
#include "json.h"
#include "log.h"
#include "malloc.h"
#include "paths.h"
#include "seal.h"

const char *eventlog_path(void)
{
	const char *env = image_config_active() ? NULL :
		getenv("SHIRUDO_EVENTLOG_PATH");

	return env && *env ? env : EVENTLOG_PATH;
}

const char *eventlog_pending_path(void)
{
	const char *env = image_config_active() ? NULL :
		getenv("SHIRUDO_EVENTLOG_PENDING_PATH");

	return env && *env ? env : EVENTLOG_PENDING_PATH;
}

static int adopt_pending(void);

/*
 * The init record the initrd left pending opens this boot's part of the
 * log: a line appended ahead of it would drop out of every replay, so
 * the record is adopted first.
 */
int eventlog_append(const char *json_line)
{
	int ret;

	ret = adopt_pending();
	if (ret)
		return ret;
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
	int fd, ret;

	fd = seal_open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
	if (fd < 0) {
		pr_err("eventlog: open %s: %s", path, strerror(-fd));
		return fd;
	}
	while (flock(fd, LOCK_EX) != 0) {
		if (errno != EINTR) {
			ret = -errno;
			goto out;
		}
	}
	if (fstat(fd, &st) != 0) {
		ret = -errno;
		goto out;
	}

	ret = write_complete(fd, json_line, len);
	if (!ret && (len == 0 || json_line[len - 1] != '\n'))
		ret = write_complete(fd, "\n", 1);
	if (!ret && fsync(fd) != 0)
		ret = -errno;
	if (ret && ftruncate(fd, st.st_size) != 0)
		pr_warn("eventlog: could not roll back a partial append to "
			"%s: %s", path, strerror(errno));
out:
	if (close(fd) != 0 && !ret)
		ret = -errno;
	if (ret) {
		pr_err("eventlog: append: %s", strerror(-ret));
		return ret;
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
	return cur + EVENTLOG_LINE_MAX > max_bytes;
}

static int read_log(char **out, size_t *out_len)
{
	size_t base_len = 0, pending_len = 0, off;
	char *base = NULL, *pending = NULL, *buf;
	int ret, rc_pending;

	ret = read_file(eventlog_path(), JSON_MAX_BYTES,
			&base, &base_len);
	if (ret && ret != -ENOENT)
		return ret;
	rc_pending = read_file(eventlog_pending_path(),
			       JSON_MAX_BYTES, &pending,
			       &pending_len);
	if (rc_pending && rc_pending != -ENOENT) {
		xfree(base, base_len + 1);
		return rc_pending;
	}
	if (ret && rc_pending)
		return -ENOENT;
	if (rc_pending) {
		*out = base;
		*out_len = base_len;
		return 0;
	}
	if (ret) {
		*out = pending;
		*out_len = pending_len;
		return 0;
	}
	if (base_len + pending_len > JSON_MAX_BYTES) {
		ret = -EFBIG;
		goto out;
	}
	buf = xmalloc(base_len + pending_len + 2);
	if (!buf) {
		ret = -ENOMEM;
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
	return ret;
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
	int ret = 0;

	eventlog_boot_id(boot_id, sizeof(boot_id));
	for (line = strtok_r(buf, "\n", &save); line && !ret;
	     line = strtok_r(NULL, "\n", &save)) {
		struct json_field f[] = {
			{ "boot_id", JSON_T_STRING, line_boot,
			  sizeof(line_boot), 0, NULL, 0 },
			{ "type", JSON_T_STRING, type, sizeof(type),
			  0, NULL, 0 },
		};
		bool is_init;

		line_boot[0] = '\0';
		type[0] = '\0';
		if (json_parse(line, strlen(line), f, 2)) {
			ret = -EINVAL;
			break;
		}
		if (!f[0].seen || !boot_id[0] || strcmp(line_boot, boot_id))
			continue;
		is_init = f[1].seen && strcmp(type, "init") == 0;
		if (is_init)
			in_boot = true;
		if (!in_boot)
			continue;
		ret = cb(line, strlen(line), is_init, ctx);
	}
	if (!ret && !in_boot)
		return -ENOENT;
	return ret;
}

static int walk_boot(int (*cb)(const char *line, size_t len, bool is_init,
			       void *ctx), void *ctx)
{
	char *buf = NULL;
	size_t len = 0;
	int ret;

	ret = read_log(&buf, &len);
	if (ret)
		return ret;
	ret = walk_lines(buf, cb, ctx);
	xfree(buf, len + 1);
	return ret;
}

struct adopt_ctx {
	const char	*line;
	size_t		len;
	bool		found;
};

static int adopt_seen(const char *line, size_t len,
		      bool is_init __attribute__((__unused__)), void *ctx)
{
	struct adopt_ctx *a = ctx;

	if (len == a->len && memcmp(line, a->line, len) == 0)
		a->found = true;
	return 0;
}

static int log_holds(const char *line, size_t len)
{
	struct adopt_ctx a = { .line = line, .len = len };
	char *buf = NULL;
	size_t blen = 0;
	int ret;

	ret = read_file(eventlog_path(), JSON_MAX_BYTES,
			&buf, &blen);
	if (ret == -ENOENT)
		return 0;
	if (ret)
		return ret;
	ret = walk_lines(buf, adopt_seen, &a);
	xfree(buf, blen + 1);
	if (ret && ret != -ENOENT)
		return ret;
	return a.found ? 1 : 0;
}

static int adopt_pending(void)
{
	const char *pending = eventlog_pending_path();
	char *buf = NULL, *line, *save;
	size_t len = 0;
	int ret;

	ret = read_file(pending, JSON_MAX_BYTES, &buf, &len);
	if (ret == -ENOENT)
		return 0;
	if (ret)
		return ret;
	for (line = strtok_r(buf, "\n", &save); line && !ret;
	     line = strtok_r(NULL, "\n", &save)) {
		if (!*line)
			continue;
		ret = log_holds(line, strlen(line));
		if (ret > 0) {
			ret = 0;
			continue;
		}
		if (!ret)
			ret = eventlog_append_to(eventlog_path(),
						 line);
	}
	xfree(buf, len + 1);
	if (ret)
		return ret;
	if (unlink(pending) != 0 && errno != ENOENT)
		return -errno;
	return 0;
}

/*
 * The register and the eventlog advance together only while one process
 * at a time extends and appends: two measuring commands under locks of
 * their own interleaved extend, extend, append, append and left a log
 * that replays the events in the other order. Every measuring path holds
 * this from its extend to its append; it lives beside the log it guards.
 */
int eventlog_lock(void)
{
	char path[PATH_MAX];
	int fd, ret;

	if (strsprintf(path, sizeof(path), "%s.lock", eventlog_path()) < 0)
		return -ENAMETOOLONG;
	fd = seal_open(path, O_RDWR | O_CREAT, 0600);
	if (fd < 0)
		return fd;
	while (flock(fd, LOCK_EX)) {
		if (errno != EINTR) {
			ret = -errno;
			close(fd);
			return ret;
		}
	}
	return fd;
}

void eventlog_unlock(int fd)
{
	if (fd >= 0)
		close(fd);
}

/*
 * init adopts the initrd's record while a command may append, and both
 * would find it missing and append it. Without a record there is
 * nothing to adopt, nor yet a state directory for the lock on a first
 * boot.
 */
int eventlog_adopt_pending(void)
{
	int lock, ret;

	if (access(eventlog_pending_path(), F_OK) && errno == ENOENT)
		return 0;
	lock = eventlog_lock();
	if (lock < 0)
		return lock;
	ret = adopt_pending();
	eventlog_unlock(lock);
	return ret;
}

static int replay_line(const char *line, size_t len, bool is_init, void *ctx)
{
	char digest_hex[2 * 32 + 1];
	struct json_field f[] = {
		{ "digest", JSON_T_STRING, digest_hex,
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
	return sha256_calc(cat, sizeof(cat), chain);
}

int eventlog_replay(__u8 out[32])
{
	__u8 chain[32] = {};
	int ret;

	ret = walk_boot(replay_line, chain);
	if (!ret)
		memcpy(out, chain, 32);
	return ret;
}

static int init_line(const char *line, size_t len, bool is_init, void *ctx)
{
	char writer_public[2 * TPM_NV_RSA_BYTES + 1];
	char pcr_before[2 * 32 + 1], name[2 * TPM_NAME_LEN + 1];
	char phase_before[2 * 32 + 1], anchor[2 * 32 + 1], bound_in[8];
	struct eventlog_init *out = ctx;
	__s64 pcr = -1, reset_count = -1;
	struct json_field f[] = {
		{ "pcr_before", JSON_T_STRING, pcr_before,
		  sizeof(pcr_before), 0, NULL, 0 },
		{ "nv_name", JSON_T_STRING, name, sizeof(name), 0,
		  NULL, 0 },
		{ "anchor_digest", JSON_T_STRING, anchor,
		  sizeof(anchor), 0, NULL, 0 },
		{ "pcr", JSON_T_INT, &pcr, 0, 0, NULL, 0 },
		{ "tpm_reset_count", JSON_T_INT, &reset_count, 0, 0,
		  NULL, 0 },
		{ "phase_before", JSON_T_STRING, phase_before,
		  sizeof(phase_before), 0, NULL, 0 },
		{ "bound_in", JSON_T_STRING, bound_in, sizeof(bound_in),
		  0, NULL, 0 },
		{ "nv_writer_public", JSON_T_STRING, writer_public,
		  sizeof(writer_public), 0, NULL, 0 },
	};
	bool have_reset_count;

	if (!is_init)
		return 0;
	bound_in[0] = '\0';
	if (json_parse(line, len, f, 8) || !f[0].seen || !f[1].seen ||
	    !f[2].seen || !f[3].seen || !f[5].seen || pcr < 0 || pcr >= 24 ||
	    (f[4].seen && (reset_count < 0 || reset_count > UINT32_MAX)) ||
	    strlen(name) != 2 * TPM_NAME_LEN ||
	    hex_decode(pcr_before, out->pcr_before, 32) ||
	    hex_decode(phase_before, out->phase_before, 32) ||
	    hex_decode(name, out->name, TPM_NAME_LEN) ||
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
	out->name_len = TPM_NAME_LEN;
	out->pcr = (__u32)pcr;
	return 0;
}

int eventlog_boot_init(struct eventlog_init *out)
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

void eventlog_record_open(struct json_emit *e, const char *type,
			  const __u8 digest[32])
{
	char ts[32], boot_id[64], nv_index[16], digest_hex[65];

	eventlog_timestamp(ts, sizeof(ts));
	eventlog_boot_id(boot_id, sizeof(boot_id));
	if (strsprintf(nv_index, sizeof(nv_index), "0x%08X",
		       NV_INDEX) < 0 && !e->err)
		e->err = -E2BIG;
	hex_encode(digest, 32, digest_hex);

	json_obj_open(e);
	json_kv_int(e, "schema", 1);
	json_kv_string(e, "ts", ts);
	json_kv_string(e, "nv_index", nv_index);
	json_kv_string(e, "alg", "sha256");
	json_kv_string(e, "digest", digest_hex);
	json_kv_string(e, "type", type);
	json_kv_string(e, "boot_id", boot_id);
}
