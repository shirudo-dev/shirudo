// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "chain.h"
#include "config_measure.h"
#include "config_update.h"
#include "hex.h"
#include "io.h"
#include "json.h"
#include "log.h"

#define RECORD_MAX (2 * CONFIG_UPDATE_PREFIX_MAX + 1024)

static int target_valid(const struct config_update_target *target)
{
	size_t len, i;

	if (!target)
		return -EINVAL;
	len = strnlen(target->prefix, sizeof(target->prefix));
	if (!len || len == sizeof(target->prefix) || target->prefix[0] != '/')
		return -EINVAL;
	for (i = 0; i < len; i++)
		if ((__u8)target->prefix[i] < 0x20 ||
		    (__u8)target->prefix[i] == 0x7f)
			return -EINVAL;
	return 0;
}

static int record_encode(const struct config_update_record *record,
			 bool state, char *out, size_t cap, size_t *length)
{
	struct json_emit emit = { .buf = out, .cap = cap - 1 };
	char root[65], initial[65];

	hex_encode(record->target.root_hash, 32, root);
	hex_encode(record->initial_pcr, 32, initial);
	json_obj_open(&emit);
	json_kv_int(&emit, "schema", 1);
	json_kv_int(&emit, "sequence", record->sequence);
	json_kv_int(&emit, "reset_count", record->reset_count);
	json_kv_int(&emit, "restart_count", record->restart_count);
	json_kv_int(&emit, "pcr", record->pcr);
	json_kv_int(&emit, "kind", record->kind);
	json_kv_string(&emit, "root_hash", root);
	json_kv_string(&emit, "initial_pcr", initial);
	if (state) {
		json_kv_string(&emit, "prefix", record->target.prefix);
		json_kv_bool(&emit, "pending", record->pending);
	}
	json_obj_close(&emit);
	if (emit.err)
		return emit.err;
	out[emit.len++] = '\n';
	*length = emit.len;
	return 0;
}

static int record_decode(const char *data, size_t length, bool state,
			 struct config_update_record *record)
{
	__s64 schema = 0, sequence = 0, reset = 0, restart = 0;
	char root[65] = {}, initial[65] = {};
	__s64 pcr = 0, kind = 0;
	int pending = 0;
	size_t i;
	int ret;
	struct json_field fields[] = {
		{ "schema", JSON_T_INT, &schema, 0, 0, NULL, 0 },
		{ "sequence", JSON_T_INT, &sequence, 0, 0, NULL, 0 },
		{ "reset_count", JSON_T_INT, &reset, 0, 0, NULL, 0 },
		{ "restart_count", JSON_T_INT, &restart, 0, 0,
		  NULL, 0 },
		{ "pcr", JSON_T_INT, &pcr, 0, 0, NULL, 0 },
		{ "kind", JSON_T_INT, &kind, 0, 0, NULL, 0 },
		{ "root_hash", JSON_T_STRING, root, sizeof(root), 0,
		  NULL, 0 },
		{ "initial_pcr", JSON_T_STRING, initial,
		  sizeof(initial), 0, NULL, 0 },
		{ "prefix", JSON_T_STRING, record->target.prefix,
		  sizeof(record->target.prefix), 0, NULL, 0 },
		{ "pending", JSON_T_BOOL, &pending, 0, 0, NULL, 0 },
	};

	memset(record, 0, sizeof(*record));
	ret = json_parse(data, length, fields, ARRAY_SIZE(fields));
	if (ret)
		return ret;
	for (i = 0; i < ARRAY_SIZE(fields) - (state ? 0 : 2); i++)
		if (!fields[i].seen)
			return -EBADMSG;
	if (schema != 1 || sequence <= 0 || reset < 0 ||
	    reset > UINT32_MAX || restart < 0 || restart > UINT32_MAX ||
	    pcr < 0 || pcr > 15 || config_measure_pcr_valid(pcr) ||
	    (kind != CONFIG_EVENT_BOOT &&
	     kind != CONFIG_EVENT_UPDATE) ||
	    hex_decode(root, record->target.root_hash, 32) ||
	    hex_decode(initial, record->initial_pcr, 32) ||
	    (state && target_valid(&record->target)))
		return -EBADMSG;
	record->sequence = sequence;
	record->reset_count = reset;
	record->restart_count = restart;
	record->pcr = pcr;
	record->kind = kind;
	record->pending = pending;
	return 0;
}

static int regular_file(int fd)
{
	struct stat st;

	if (fstat(fd, &st))
		return -errno;
	if (!S_ISREG(st.st_mode) || st.st_nlink != 1 ||
	    st.st_uid != geteuid() || (st.st_mode & 077))
		return -EPERM;
	return 0;
}

static int checkpoint(struct config_update *update,
		      enum config_update_checkpoint point)
{
	return update->ops->checkpoint ?
		       update->ops->checkpoint(update->ctx, point) :
		       0;
}

/*
 * Every target command holds the lock for its whole run, and the keepalive
 * and map-export timers start one every few seconds, so a short wait lets
 * them take turns instead of failing each other.
 */
static int lock_wait(int fd, __u32 wait_ms)
{
	struct timespec pause = { .tv_nsec = 100 * 1000 * 1000 };
	bool told = false;
	__u32 waited = 0;
	int err;

	for (;;) {
		if (!flock(fd, LOCK_EX | LOCK_NB))
			return 0;
		err = errno;
		if (err != EWOULDBLOCK || waited >= wait_ms)
			return -err;
		if (!told && waited >= 1000) {
			pr_info("image: waiting for another shirudo command to release the config operation lock");
			told = true;
		}
		nanosleep(&pause, NULL);
		waited += 100;
	}
}

int config_update_open(const char *directory,
		       const struct config_update_ops *ops,
		       void *ctx, struct config_update *out)
{
	struct stat st;
	int ret;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	out->dir_fd = -1;
	out->lock_fd = -1;
	if (!directory || !ops || !ops->boot_identity ||
	    !ops->pcr_read || !ops->pcr_extend || !ops->prepare ||
	    !ops->activate || !ops->seal)
		return -EINVAL;
	out->ops = ops;
	out->ctx = ctx;
	out->dir_fd = open(directory,
			   O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (out->dir_fd < 0)
		return -errno;
	if (fstat(out->dir_fd, &st)) {
		ret = -errno;
		goto fail;
	}
	if (st.st_uid != geteuid() || (st.st_mode & 022)) {
		ret = -EPERM;
		goto fail;
	}
	ret = ops->seal(ctx, out->dir_fd);
	if (ret)
		goto fail;
	out->lock_fd = openat(out->dir_fd,
			      "lock",
			      O_RDWR | O_CREAT | O_CLOEXEC |
			      O_NOFOLLOW | O_NONBLOCK, 0600);
	if (out->lock_fd < 0) {
		ret = -errno;
		goto fail;
	}
	ret = regular_file(out->lock_fd);
	if (ret)
		goto fail;
	ret = lock_wait(out->lock_fd, ops->lock_wait_ms);
	if (ret) {
		if (ret == -EWOULDBLOCK)
			pr_err("image: another shirudo command still holds the config operation lock %s/lock after %u seconds",
			       directory, ops->lock_wait_ms / 1000);
		goto fail;
	}
	ret = ops->seal(ctx, out->lock_fd);
	if (ret)
		goto fail;
	if (fsync(out->lock_fd) || fsync(out->dir_fd)) {
		ret = -errno;
		goto fail;
	}
	return 0;
fail:
	config_update_close(out);
	return ret;
}

void config_update_close(struct config_update *update)
{
	if (!update)
		return;
	if (update->lock_fd >= 0)
		close(update->lock_fd);
	if (update->dir_fd >= 0)
		close(update->dir_fd);
	update->dir_fd = -1;
	update->lock_fd = -1;
}

static int selection_read(struct config_update *update, const char *name,
			  struct config_update_record *out)
{
	char wire[RECORD_MAX];
	struct stat st;
	size_t done = 0;
	ssize_t got;
	int fd, ret;

	if (!update || update->dir_fd < 0 || !out)
		return -EINVAL;
	fd = openat(update->dir_fd, name,
		    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (fd < 0)
		return -errno;
	ret = regular_file(fd);
	if (!ret && fstat(fd, &st))
		ret = -errno;
	if (!ret && (st.st_size <= 0 || (__u64)st.st_size >= sizeof(wire)))
		ret = -EBADMSG;
	while (!ret && done < (size_t)st.st_size) {
		got = read(fd, wire + done, st.st_size - done);
		if (got < 0) {
			if (errno == EINTR)
				continue;
			ret = -errno;
		} else if (!got) {
			ret = -EIO;
		} else {
			done += got;
		}
	}
	if (!ret)
		ret = record_decode(wire, done, true, out);
	close(fd);
	return ret;
}

int config_update_read(struct config_update *update,
		       struct config_update_record *out)
{
	return selection_read(update, "state", out);
}

static int selection_save(struct config_update *update,
			  const struct config_update_record *record,
			  const char *name, const char *temporary,
			  bool inject)
{
	char wire[RECORD_MAX];
	size_t length;
	int fd, ret;

	ret = record_encode(record, true, wire, sizeof(wire), &length);
	if (ret)
		return ret;
	if (unlinkat(update->dir_fd, temporary, 0) && errno != ENOENT)
		return -errno;
	fd = openat(update->dir_fd, temporary,
		    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0)
		return -errno;
	ret = update->ops->seal(update->ctx, fd);
	if (!ret)
		ret = write_complete(fd, wire, length);
	if (!ret && inject)
		ret = checkpoint(update, CONFIG_CHECK_STATE_WRITE);
	if (!ret && fsync(fd))
		ret = -errno;
	if (close(fd) && !ret)
		ret = -errno;
	if (!ret &&
	    renameat(update->dir_fd, temporary, update->dir_fd, name))
		ret = -errno;
	if (!ret && inject)
		ret = checkpoint(update, CONFIG_CHECK_STATE_RENAME);
	if (!ret && fsync(update->dir_fd))
		ret = -errno;
	if (ret)
		unlinkat(update->dir_fd, temporary, 0);
	return ret;
}

static int state_save(struct config_update *update,
		      const struct config_update_record *record,
		      bool inject)
{
	return selection_save(update, record, "state", ".state.tmp", inject);
}

static bool same_boot(const struct config_update_record *a,
		      const struct config_update_record *b)
{
	return a->reset_count == b->reset_count &&
	       a->restart_count == b->restart_count;
}

static bool same_target(const struct config_update_target *a,
			const struct config_update_target *b)
{
	return !strcmp(a->prefix, b->prefix) &&
	       !memcmp(a->root_hash, b->root_hash, 32);
}

static bool same_event(const struct config_update_record *a,
		       const struct config_update_record *b)
{
	return same_boot(a, b) && a->sequence == b->sequence &&
	       a->pcr == b->pcr && a->kind == b->kind &&
	       !memcmp(a->initial_pcr, b->initial_pcr, 32) &&
	       !memcmp(a->target.root_hash, b->target.root_hash, 32);
}

static int event_follows(const struct config_update_record *previous,
			 const struct config_update_record *record)
{
	if (record->sequence != previous->sequence + 1)
		return -EUCLEAN;
	if (!previous->sequence || !same_boot(previous, record))
		return record->kind == CONFIG_EVENT_BOOT ? 0 :
								 -EUCLEAN;
	if (record->kind != CONFIG_EVENT_UPDATE ||
	    previous->pcr != record->pcr ||
	    memcmp(previous->initial_pcr, record->initial_pcr, 32))
		return -EUCLEAN;
	return 0;
}

/* A trailing partial append can be discarded only on a later trusted boot. */
static int read_line(FILE *file, char *line, size_t cap, size_t *length)
{
	int c;

	*length = 0;
	while ((c = fgetc(file)) != EOF) {
		if (!c || *length == cap)
			return -EBADMSG;
		line[(*length)++] = c;
		if (c == '\n')
			return 1;
	}
	if (ferror(file))
		return -EIO;
	return *length ? -ENODATA : 0;
}

static int events_scan(struct config_update *update,
		       struct config_update_record *last,
		       __u8 value[32], off_t *end, bool partial,
		       shirudo_config_cb consume, void *ctx)
{
	struct config_update_record previous = {}, record;
	const __u8 *root = record.target.root_hash;
	__u8 running[32] = {}, digest[32];
	char wire[RECORD_MAX];
	size_t length;
	int fd, ret;
	FILE *file;

	memset(last, 0, sizeof(*last));
	if (end)
		*end = 0;
	fd = openat(update->dir_fd, "events",
		    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (fd < 0)
		return errno == ENOENT ? 0 : -errno;
	ret = regular_file(fd);
	if (ret) {
		close(fd);
		return ret;
	}
	file = fdopen(fd, "r");
	if (!file) {
		ret = -errno;
		close(fd);
		return ret;
	}
	while ((ret = read_line(file, wire, sizeof(wire), &length)) > 0) {
		ret = record_decode(wire, length, false, &record);
		if (!ret)
			ret = event_follows(&previous, &record);
		if (!ret && record.kind == CONFIG_EVENT_BOOT)
			memcpy(running, record.initial_pcr, 32);
		if (!ret)
			ret = config_measure_event(record.kind,
						   root, digest);
		if (!ret)
			ret = chain_fold(running, digest);
		if (!ret && consume)
			ret = consume(&record, ctx);
		if (ret)
			break;
		previous = record;
		if (end) {
			*end = ftello(file);
			if (*end < 0) {
				ret = -errno;
				break;
			}
		}
	}
	if (ret == -ENODATA && partial)
		ret = 0;
	if (!ret) {
		*last = previous;
		if (value)
			memcpy(value, running, 32);
	}
	fclose(file);
	return ret;
}

int config_update_events(struct config_update *update,
			 shirudo_config_cb consume, void *ctx)
{
	struct config_update_record last;

	if (!update || update->dir_fd < 0 || !consume)
		return -EINVAL;
	return events_scan(update, &last, NULL, NULL, false, consume, ctx);
}

static int event_append(struct config_update *update,
			const struct config_update_record *record)
{
	struct config_update_record last;
	char wire[RECORD_MAX];
	size_t length;
	int fd, ret;
	off_t end;

	ret = events_scan(update, &last, NULL, &end,
			  record->kind == CONFIG_EVENT_BOOT, NULL, NULL);
	if (!ret)
		ret = event_follows(&last, record);
	if (!ret)
		ret = record_encode(record, false, wire, sizeof(wire), &length);
	if (ret)
		return ret;
	fd = openat(update->dir_fd, "events",
		    O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW |
			    O_NONBLOCK, 0600);
	if (fd < 0)
		return -errno;
	ret = regular_file(fd);
	if (!ret)
		ret = update->ops->seal(update->ctx, fd);
	if (!ret && ftruncate(fd, end))
		ret = -errno;
	if (!ret)
		ret = write_complete(fd, wire, length);
	if (!ret)
		ret = checkpoint(update, CONFIG_CHECK_EVENT_WRITE);
	if (!ret && fsync(fd))
		ret = -errno;
	if (close(fd) && !ret)
		ret = -errno;
	if (!ret && fsync(update->dir_fd))
		ret = -errno;
	return ret;
}

static int live_read(struct config_update *update, __u32 pcr,
		     __u32 *reset, __u32 *restart, __u8 value[32])
{
	__u32 reset_after, restart_after;
	int ret;

	ret = update->ops->boot_identity(update->ctx, reset, restart);
	if (!ret)
		ret = update->ops->pcr_read(update->ctx, pcr, value);
	if (!ret)
		ret = update->ops->boot_identity(update->ctx, &reset_after,
						 &restart_after);
	if (!ret && (*reset != reset_after || *restart != restart_after))
		ret = -ESTALE;
	return ret;
}

static int check_record(struct config_update *update,
			const struct config_update_record *record)
{
	struct config_update_record last;
	__u8 expected[32], value[32];
	__u32 reset, restart;
	int ret;

	ret = events_scan(update, &last, expected, NULL, false, NULL, NULL);
	if (!ret && !same_event(record, &last))
		ret = -EUCLEAN;
	if (!ret)
		ret = live_read(update, record->pcr, &reset, &restart, value);
	if (!ret && (reset != record->reset_count ||
		     restart != record->restart_count))
		ret = -ESTALE;
	if (!ret && memcmp(value, expected, 32))
		ret = -EUCLEAN;
	return ret;
}

int config_update_check(struct config_update *update,
			struct config_update_record *out)
{
	struct config_update_record record;
	int ret;

	ret = config_update_read(update, &record);
	if (!ret && record.pending)
		ret = -EINPROGRESS;
	if (!ret)
		ret = check_record(update, &record);
	if (!ret && out)
		*out = record;
	return ret;
}

static int complete(struct config_update *update)
{
	struct config_update_record record;
	int ret, restore;

	ret = config_update_read(update, &record);
	if (!ret)
		ret = check_record(update, &record);
	if (ret)
		return ret;
	record.pending = false;
	ret = state_save(update, &record, true);
	if (!ret)
		ret = checkpoint(update, CONFIG_CHECK_COMPLETE_SYNC);
	if (ret) {
		record.pending = true;
		restore = state_save(update, &record, false);
		if (restore)
			pr_err("image: cannot restore pending selection: %s",
			       strerror(-restore));
	}
	return ret;
}

static int begin_event(struct config_update *update,
		       const struct config_update_target *target,
		       const struct config_update_record *previous,
		       __u32 pcr, enum config_event_kind kind)
{
	struct config_update_record record = {};
	__u8 before[32], expected[32], value[32], event[32];
	__u32 reset, restart;
	int ret;

	if (previous->sequence == INT64_MAX)
		return -EOVERFLOW;
	ret = update->ops->prepare(update->ctx, target);
	if (ret)
		return ret;
	record.target = *target;
	record.sequence = previous->sequence + 1;
	record.pcr = pcr;
	record.kind = kind;
	record.pending = true;
	ret = live_read(update, pcr, &record.reset_count, &record.restart_count,
			before);
	if (ret)
		return ret;
	memcpy(record.initial_pcr, kind == CONFIG_EVENT_BOOT ?
	       before : previous->initial_pcr, 32);
	ret = event_follows(previous, &record);
	if (!ret)
		ret = config_measure_event(kind, target->root_hash,
					   event);
	memcpy(expected, before, 32);
	if (!ret)
		ret = chain_fold(expected, event);
	if (!ret)
		ret = state_save(update, &record, true);
	if (!ret)
		ret = checkpoint(update, CONFIG_CHECK_PENDING_SYNC);
	if (!ret)
		ret = update->ops->pcr_extend(update->ctx, pcr, event);
	if (!ret)
		ret = checkpoint(update, CONFIG_CHECK_EXTEND);
	if (!ret)
		ret = live_read(update, pcr, &reset, &restart, value);
	if (!ret && (reset != record.reset_count ||
		     restart != record.restart_count ||
		     memcmp(value, expected, 32)))
		ret = -EUCLEAN;
	if (!ret)
		ret = event_append(update, &record);
	if (!ret)
		ret = checkpoint(update, CONFIG_CHECK_EVENT_SYNC);
	if (!ret)
		ret = update->ops->activate(update->ctx, target);
	if (!ret)
		ret = checkpoint(update, CONFIG_CHECK_ACTIVATE);
	if (ret)
		return ret;
	if (kind == CONFIG_EVENT_BOOT) {
		update->boot_pending = true;
		return 0;
	}
	return complete(update);
}

int config_update_stage_read(struct config_update *update,
			     struct config_update_record *out)
{
	return selection_read(update, "next-boot", out);
}

int config_update_clear_staged(struct config_update *update)
{
	if (!update || update->dir_fd < 0 || update->lock_fd < 0)
		return -EINVAL;
	if (unlinkat(update->dir_fd, "next-boot", 0))
		return errno == ENOENT ? 0 : -errno;
	return fsync(update->dir_fd) ? -errno : 0;
}

int config_update_stage(struct config_update *update,
			const struct config_update_target *target)
{
	struct config_update_record record;
	int ret;

	if (!update || update->lock_fd < 0 || target_valid(target))
		return -EINVAL;
	ret = config_update_check(update, &record);
	if (ret)
		return ret;
	record.target = *target;
	return selection_save(update, &record, "next-boot", ".next-boot.tmp",
			      false);
}

int config_update_staged(struct config_update *update,
			 const struct config_update_record *previous,
			 __u32 reset, __u32 restart,
			 struct config_update_target *target)
{
	struct config_update_record staged;
	int ret;

	if (!previous || !target)
		return -EINVAL;
	ret = config_update_stage_read(update, &staged);
	if (ret)
		return ret == -ENOENT ? 0 : ret;
	if (staged.pending)
		return -EBADMSG;
	if (staged.reset_count == reset && staged.restart_count == restart)
		return 0;
	if (same_target(&staged.target, &previous->target))
		return 0;
	if (staged.sequence != previous->sequence ||
	    !same_boot(&staged, previous)) {
		pr_warn("image: ignoring staged config because the active selection changed");
		return 0;
	}
	*target = staged.target;
	return 1;
}

static int complete_staged(struct config_update *update)
{
	struct config_update_record staged, current;
	int ret;

	ret = config_update_stage_read(update, &staged);
	if (ret)
		return ret == -ENOENT ? 0 : ret;
	ret = config_update_read(update, &current);
	if (ret || same_boot(&current, &staged))
		return ret;
	return config_update_clear_staged(update);
}

int config_update_begin(struct config_update *update,
			const struct config_update_target *t,
			__u32 pcr)
{
	struct config_update_record previous;
	int ret;

	if (!update || update->dir_fd < 0 || target_valid(t) ||
	    config_measure_pcr_valid(pcr))
		return -EINVAL;
	ret = config_update_check(update, &previous);
	if (ret)
		return ret;
	if (pcr != previous.pcr)
		return -EPERM;
	if (!memcmp(t->root_hash, previous.target.root_hash, 32))
		return 0;
	ret = begin_event(update, t, &previous, pcr, CONFIG_EVENT_UPDATE);
	if (!ret) {
		int err = config_update_clear_staged(update);

		if (err)
			pr_warn("image: cannot remove obsolete staged config: %s",
				strerror(-err));
	}
	return ret;
}

int config_update_boot(struct config_update *update,
		       const struct config_update_target *t,
		       __u32 pcr)
{
	struct config_update_record previous = {}, last;
	struct config_update_target staged;
	__u32 reset, restart;
	int ret;

	if (!update || update->dir_fd < 0 || target_valid(t) ||
	    config_measure_pcr_valid(pcr))
		return -EINVAL;
	update->boot_pending = false;
	ret = config_update_read(update, &previous);
	if (ret && ret != -ENOENT)
		return ret;
	ret = update->ops->boot_identity(update->ctx, &reset, &restart);
	if (ret)
		return ret;
	if (previous.sequence && previous.reset_count == reset &&
	    previous.restart_count == restart) {
		if (previous.pending)
			return -EINPROGRESS;
		if (previous.pcr != pcr ||
		    memcmp(t->root_hash, previous.target.root_hash, 32))
			return -EBUSY;
		return config_update_check(update, NULL);
	}
	if (previous.sequence && !same_target(t, &previous.target)) {
		ret = config_update_staged(update, &previous, reset, restart,
					   &staged);
		if (ret < 0)
			return ret;
		if (!ret || !same_target(t, &staged))
			return -EUCLEAN;
	}
	ret = events_scan(update, &last, NULL, NULL, previous.pending,
			  NULL, NULL);
	if (ret)
		return ret;
	if (!previous.sequence && last.sequence)
		return -EUCLEAN;
	if (previous.sequence &&
	    !(same_event(&previous, &last) ||
	      (previous.pending && !event_follows(&last, &previous))))
		return -EUCLEAN;
	return begin_event(update, t, &last, pcr,
			   CONFIG_EVENT_BOOT);
}

int config_update_complete_boot(struct config_update *update)
{
	int ret;

	if (!update || update->dir_fd < 0)
		return -EINVAL;
	if (!update->boot_pending) {
		ret = config_update_check(update, NULL);
	} else {
		update->boot_pending = false;
		ret = complete(update);
	}
	return ret ? ret : complete_staged(update);
}
