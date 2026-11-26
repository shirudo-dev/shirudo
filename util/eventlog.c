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
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>
#include <shirudo/upatch.h>

#include "chain.h"
#include "crypto.h"
#include "eventlog.h"
#include "hex.h"
#include "identity.h"
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
 * A line cut short, by a full file system or a kill between writes,
 * would join the next record on its line and leave every reader of the
 * log failing on it, so appenders take the lock that keeps them from
 * interleaving and append_line() drops what did not finish.
 */
static int append_record(const char *path, const char *line, size_t len)
{
	int ret;

	ret = seal_append_line(path, line, len);
	if (ret)
		pr_err("eventlog: append to %s: %s", path, strerror(-ret));
	return ret;
}

int eventlog_append_to(const char *path, const char *json_line)
{
	return append_record(path, json_line, strlen(json_line));
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

/*
 * The records of the len bytes read_file() left at buf: a NUL would end
 * every walk there and hide the records after it, and a last line
 * without its newline is no record yet.
 */
static int log_records(char *buf, size_t len)
{
	int ret = span_to_str(buf, len + 1, buf, len);

	if (!ret)
		buf[lines_len(buf, len)] = '\0';
	return ret;
}

/*
 * The record the initrd left in /run/shirudo, as sealed state where the
 * log is: a /run of root's making, in a mount namespace of its own,
 * would otherwise hand each reader records the register never saw, and
 * have the next append adopt them into the sealed log. A host without
 * the seal, as the register tests run on, labels neither.
 */
static int read_pending(char **out, size_t *len)
{
	const char *path = eventlog_pending_path();
	int fd, ret;

	if (strcmp(path, EVENTLOG_PENDING_PATH))
		return read_file(path, JSON_MAX_BYTES, out, len);
	fd = seal_parent_labeled(eventlog_path()) ? seal_open_sealed(path) :
	     seal_open_read(path);
	if (fd < 0)
		return fd;
	ret = read_fd(fd, path, JSON_MAX_BYTES, out, len);
	close(fd);
	return ret;
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
	rc_pending = read_pending(&pending, &pending_len);
	if (rc_pending && rc_pending != -ENOENT) {
		xfree(base, base_len + 1);
		return rc_pending;
	}
	if (ret && rc_pending)
		return -ENOENT;
	if ((!ret && log_records(base, base_len)) ||
	    (!rc_pending && log_records(pending, pending_len))) {
		ret = -EINVAL;
		goto out;
	}
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
	buf = xmalloc(base_len + pending_len + 1);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}
	off = strlen(base);
	memcpy(buf, base, off);
	memcpy(buf + off, pending, strlen(pending));
	off += strlen(pending);
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
static int walk_lines(const char *buf, bool all,
		      int (*cb)(const char *line, size_t len, bool is_init,
				void *ctx), void *ctx)
{
	char boot_id[64], line_boot[64], type[32];
	bool in_boot = false;
	const char *line;
	int ret = 0;
	size_t len;

	eventlog_boot_id(boot_id, sizeof(boot_id));
	for_each_token(line, len, buf, strlen(buf), "\n") {
		struct json_field f[] = {
			{ "boot_id", JSON_T_STRING, line_boot,
			  sizeof(line_boot), 0, NULL, 0 },
			{ "type", JSON_T_STRING, type, sizeof(type),
			  0, NULL, 0 },
		};
		bool is_init;

		line_boot[0] = '\0';
		type[0] = '\0';
		if (json_parse(line, len, f, 2)) {
			ret = -EINVAL;
			break;
		}
		if (!all &&
		    (!f[0].seen || !boot_id[0] || strcmp(line_boot, boot_id)))
			continue;
		is_init = f[1].seen && strcmp(type, "init") == 0;
		if (is_init)
			in_boot = true;
		if (!all && !in_boot)
			continue;
		ret = cb(line, len, is_init, ctx);
		if (ret)
			break;
	}
	if (!all && !ret && !in_boot)
		return -ENOENT;
	return ret;
}

static int walk_log(bool all, int (*cb)(const char *line, size_t len,
					bool is_init, void *ctx), void *ctx)
{
	char *buf = NULL;
	size_t len = 0;
	int ret;

	ret = read_log(&buf, &len);
	if (ret)
		return ret;
	ret = walk_lines(buf, all, cb, ctx);
	xfree(buf, len + 1);
	return ret;
}

static int walk_boot(int (*cb)(const char *line, size_t len, bool is_init,
			       void *ctx), void *ctx)
{
	return walk_log(false, cb, ctx);
}

struct adopt_ctx {
	const char	*line;
	size_t		len;
	bool		found;
};

static int adopt_seen(const char *line, size_t len, bool is_init, void *ctx)
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
	ret = log_records(buf, blen);
	if (!ret)
		ret = walk_lines(buf, false, adopt_seen, &a);
	xfree(buf, blen + 1);
	if (ret && ret != -ENOENT)
		return ret;
	return a.found ? 1 : 0;
}

/* Append each of the pending records the log does not hold yet. */
static int adopt_records(const char *records)
{
	const char *line;
	size_t len;
	int ret;

	for_each_token(line, len, records, strlen(records), "\n") {
		ret = log_holds(line, len);
		if (!ret)
			ret = append_record(eventlog_path(), line, len);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int adopt_pending(void)
{
	const char *pending = eventlog_pending_path();
	char *buf = NULL;
	size_t len = 0;
	int ret;

	ret = read_pending(&buf, &len);
	if (ret == -ENOENT)
		return 0;
	if (ret)
		return ret;
	ret = log_records(buf, len);
	if (!ret)
		ret = adopt_records(buf);
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
 * that replays the events in the other order. A load or an unload holds
 * this from before it touches the pins to its append, every other
 * measuring path from its extend to its append.
 *
 * The lock is the root of the private bpffs, one inode in every mount
 * namespace. A file beside the log is root's to cover with another
 * labeled inode in a namespace of its own, where a command would lock
 * that one and undo the pins of a load still in flight, which then
 * measures an upatch nothing runs. Only a log the environment names,
 * which image_enter() allows on a host without shirudo's config alone,
 * keeps its lock beside it.
 */
int eventlog_lock(void)
{
	const char *log = eventlog_path();
	char path[PATH_MAX];
	int fd, ret;

	if (strcmp(log, EVENTLOG_PATH)) {
		if (strsprintf(path, sizeof(path), "%s.lock", log) < 0)
			return -ENAMETOOLONG;
		return seal_lock(path);
	}
	fd = bpffs_root_open();
	if (fd < 0)
		return fd;
	ret = lock_exclusive(fd);
	if (ret) {
		close(fd);
		return ret;
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
	return sha256_buffer(cat, sizeof(cat), chain);
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

struct tree_op_ctx {
	const char	*operation_digest;
	__s64		seq;
	bool		found;
};

static int tree_op_line(const char *line, size_t len, bool is_init,
			void *ctx)
{
	struct tree_op_ctx *t = ctx;
	char type[32], digest[128];
	__s64 seq = 0;
	struct json_field tree[] = {
		{ "seq", JSON_T_INT, &seq, 0, 0, NULL, 0 },
		{ "operation_digest", JSON_T_STRING, digest, sizeof(digest),
		  0, NULL, 0 },
	};
	struct json_field f[] = {
		{ "type", JSON_T_STRING, type, sizeof(type), 0, NULL, 0 },
		{ "tree", JSON_T_OBJECT, NULL, 0, 0, tree, ARRAY_SIZE(tree) },
	};

	if (json_parse(line, len, f, ARRAY_SIZE(f)))
		return -EINVAL;
	if (f[0].seen && !strcmp(type, "tree_op") && tree[0].seen &&
	    tree[1].seen && seq == t->seq &&
	    !strcmp(digest, t->operation_digest))
		t->found = true;
	return 0;
}

int eventlog_tree_op_measured(__s64 seq, const char *operation_digest)
{
	struct tree_op_ctx t = {
		.operation_digest = operation_digest, .seq = seq,
	};
	int ret;

	ret = walk_boot(tree_op_line, &t);
	if (ret == -ENOENT)
		return 0;
	if (ret)
		return ret;
	return t.found;
}

static const struct {
	const char	*record;
	const char	*kind;
	__u32		type;
	bool		load;
} upatch_records[] = {
	{ "upatch_load",	"load",		UPATCH_TYPE_BPF,	true },
	{ "upatch_unload",	"unload",	UPATCH_TYPE_BPF,	false },
	{ "java_load",		"java-load",	UPATCH_TYPE_JAVA,	true },
	{ "java_unload",	"java-unload",	UPATCH_TYPE_JAVA,	false },
};

bool eventlog_upatch_kind_parse(const char *kind, size_t len, __u32 *type,
				bool *load)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(upatch_records); i++) {
		const char *k = upatch_records[i].kind;

		if (strlen(k) == len && !memcmp(kind, k, len)) {
			*type = upatch_records[i].type;
			*load = upatch_records[i].load;
			return true;
		}
	}
	return false;
}

const char *eventlog_upatch_record(__u32 type, bool load)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(upatch_records); i++) {
		if (upatch_records[i].type == type &&
		    upatch_records[i].load == load)
			return upatch_records[i].record;
	}
	return NULL;
}

bool eventlog_upatch_record_parse(const char *record, __u32 *type,
				  bool *load)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(upatch_records); i++) {
		if (!strcmp(upatch_records[i].record, record)) {
			*type = upatch_records[i].type;
			*load = upatch_records[i].load;
			return true;
		}
	}
	return false;
}

struct upatches_ctx {
	int	(*cb)(enum eventlog_upatch_event event, const char *name,
		      const char *payload_hex, void *ctx);
	void	*ctx;
	char	name[UPATCH_NAME_MAX + 1];
	char	payload_hex[2 * UPATCH_PAYLOAD_HASH_LEN + 1];
	int	ret;
};

/* The fields one line's set entries are parsed into, for that line only. */
struct upatches_set {
	struct upatches_ctx	*u;
	const struct json_field	*entry;
};

/* Pin and archive membership use the same bytes as measurement replay. */
static int upatches_member(struct upatches_ctx *u, enum eventlog_upatch_event event)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN];

	if (!upatch_name_valid(u->name) ||
	    hex_decode(u->payload_hex, payload, sizeof(payload)))
		return -EINVAL;
	hex_encode(payload, sizeof(payload), u->payload_hex);
	return u->cb(event, u->name, u->payload_hex, u->ctx);
}

/* The buffers are the upatch member's too: an entry names both itself. */
static int upatches_set_entry(void *arg)
{
	struct upatches_set *s = arg;
	struct upatches_ctx *u = s->u;

	if (!s->entry[0].seen || !s->entry[1].seen)
		return -EINVAL;
	u->ret = upatches_member(u, EVENTLOG_UPATCH_LOAD);
	u->name[0] = '\0';
	u->payload_hex[0] = '\0';
	return u->ret;
}

static int upatches_line(const char *line, size_t len, bool is_init,
			 void *ctx)
{
	struct upatches_ctx *u = ctx;
	struct json_field entry[] = {
		{ "name", JSON_T_STRING, u->name, sizeof(u->name), 0,
		  NULL, 0 },
		{ "payload_sha256", JSON_T_STRING, u->payload_hex,
		  sizeof(u->payload_hex), 0, NULL, 0 },
	};
	struct upatches_set entries = { u, entry };
	struct json_array set = { upatches_set_entry, &entries };
	__u32 payload_type;
	char type[32];
	bool load;
	/* Only an init record's set lists what boot restore loaded. */
	struct json_field f[] = {
		{ "type", JSON_T_STRING, type, sizeof(type), 0, NULL, 0 },
		{ is_init ? "set" : NULL, JSON_T_ARRAY, &set, 0, 0, entry,
		  ARRAY_SIZE(entry) },
		{ "upatch", JSON_T_OBJECT, NULL, 0, 0, entry,
		  ARRAY_SIZE(entry) },
	};
	int ret;

	u->name[0] = '\0';
	u->payload_hex[0] = '\0';
	type[0] = '\0';
	if (is_init) {
		ret = u->cb(EVENTLOG_UPATCH_INIT, NULL, NULL, u->ctx);
		if (ret)
			return ret;
	}
	if (json_parse(line, len, f, ARRAY_SIZE(f)))
		return u->ret ? u->ret : -EINVAL;
	if (is_init)
		return 0;
	if (!eventlog_upatch_record_parse(type, &payload_type, &load))
		return 0;
	if (!f[2].seen)
		return -EINVAL;
	return upatches_member(u, load ? EVENTLOG_UPATCH_LOAD : EVENTLOG_UPATCH_UNLOAD);
}

int eventlog_boot_upatches(int (*cb)(enum eventlog_upatch_event event,
				     const char *name,
				     const char *payload_hex, void *ctx),
			   void *ctx)
{
	struct upatches_ctx u = { .cb = cb, .ctx = ctx };

	return walk_boot(upatches_line, &u);
}

int eventlog_upatches(int (*cb)(enum eventlog_upatch_event event,
				const char *name, const char *payload_hex,
				void *ctx),
		      void *ctx)
{
	struct upatches_ctx u = { .cb = cb, .ctx = ctx };

	return walk_log(true, upatches_line, &u);
}

int eventlog_read(char **out, size_t *len)
{
	return read_log(out, len);
}

int eventlog_upatches_record(const char *line, size_t len, bool is_init,
			     int (*cb)(enum eventlog_upatch_event event,
				       const char *name,
				       const char *payload_hex, void *ctx),
			     void *ctx)
{
	struct upatches_ctx u = { .cb = cb, .ctx = ctx };

	return upatches_line(line, len, is_init, &u);
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
