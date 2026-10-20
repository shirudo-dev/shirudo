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
#include <unistd.h>

#include "chain.h"
#include "config_measure.h"
#include "config_update.h"
#include "hex.h"
#include "io.h"
#include "json.h"
#include "log.h"
#include "macros.h"

#define RECORD_MAX (2 * SHIRUDO_CONFIG_UPDATE_PREFIX_MAX + 1024)

static int target_valid(const struct shirudo_config_update_target *target)
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

static int record_encode(const struct shirudo_config_update_record *record,
			 bool state, char *out, size_t cap, size_t *length)
{
	struct shirudo_json_emit emit = { .buf = out, .cap = cap - 1 };
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
			 struct shirudo_config_update_record *record)
{
	__s64 schema = 0, sequence = 0, reset = 0, restart = 0;
	char root[65] = {}, initial[65] = {};
	__s64 pcr = 0, kind = 0;
	int pending = 0;
	size_t i;
	int rc;
	struct shirudo_json_field fields[] = {
		{ "schema", SHIRUDO_JSON_T_INT, &schema, 0, 0, NULL, 0 },
		{ "sequence", SHIRUDO_JSON_T_INT, &sequence, 0, 0, NULL, 0 },
		{ "reset_count", SHIRUDO_JSON_T_INT, &reset, 0, 0, NULL, 0 },
		{ "restart_count", SHIRUDO_JSON_T_INT, &restart, 0, 0,
		  NULL, 0 },
		{ "pcr", SHIRUDO_JSON_T_INT, &pcr, 0, 0, NULL, 0 },
		{ "kind", SHIRUDO_JSON_T_INT, &kind, 0, 0, NULL, 0 },
		{ "root_hash", SHIRUDO_JSON_T_STRING, root, sizeof(root), 0,
		  NULL, 0 },
		{ "initial_pcr", SHIRUDO_JSON_T_STRING, initial,
		  sizeof(initial), 0, NULL, 0 },
		{ "prefix", SHIRUDO_JSON_T_STRING, record->target.prefix,
		  sizeof(record->target.prefix), 0, NULL, 0 },
		{ "pending", SHIRUDO_JSON_T_BOOL, &pending, 0, 0, NULL, 0 },
	};

	memset(record, 0, sizeof(*record));
	rc = json_parse(data, length, fields, ARRAY_SIZE(fields));
	if (rc)
		return rc;
	for (i = 0; i < ARRAY_SIZE(fields) - (state ? 0 : 2); i++)
		if (!fields[i].seen)
			return -EBADMSG;
	if (schema != 1 || sequence <= 0 || reset < 0 ||
	    reset > UINT32_MAX || restart < 0 || restart > UINT32_MAX ||
	    pcr < 0 || pcr > 15 || shirudo_config_measure_pcr_valid(pcr) ||
	    (kind != SHIRUDO_CONFIG_EVENT_BOOT &&
	     kind != SHIRUDO_CONFIG_EVENT_UPDATE) ||
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

static int checkpoint(struct shirudo_config_update *update,
		      enum shirudo_config_update_checkpoint point)
{
	return update->ops->checkpoint ?
		       update->ops->checkpoint(update->ctx, point) :
		       0;
}

int shirudo_config_update_open(const char *directory,
			       const struct shirudo_config_update_ops *ops,
			       void *ctx, struct shirudo_config_update *out)
{
	struct stat st;
	int rc;

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
		rc = -errno;
		goto fail;
	}
	if (st.st_uid != geteuid() || (st.st_mode & 022)) {
		rc = -EPERM;
		goto fail;
	}
	rc = ops->seal(ctx, out->dir_fd);
	if (rc)
		goto fail;
	out->lock_fd = openat(out->dir_fd,
			      "lock",
			      O_RDWR | O_CREAT | O_CLOEXEC |
			      O_NOFOLLOW | O_NONBLOCK, 0600);
	if (out->lock_fd < 0) {
		rc = -errno;
		goto fail;
	}
	rc = regular_file(out->lock_fd);
	if (rc)
		goto fail;
	if (flock(out->lock_fd, LOCK_EX | LOCK_NB)) {
		rc = -errno;
		goto fail;
	}
	rc = ops->seal(ctx, out->lock_fd);
	if (rc)
		goto fail;
	if (fsync(out->lock_fd) || fsync(out->dir_fd)) {
		rc = -errno;
		goto fail;
	}
	return 0;
fail:
	shirudo_config_update_close(out);
	return rc;
}

void shirudo_config_update_close(struct shirudo_config_update *update)
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

int shirudo_config_update_read(struct shirudo_config_update *update,
			       struct shirudo_config_update_record *out)
{
	char wire[RECORD_MAX];
	struct stat st;
	size_t done = 0;
	ssize_t got;
	int fd, rc;

	if (!update || update->dir_fd < 0 || !out)
		return -EINVAL;
	fd = openat(update->dir_fd, "state",
		    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (fd < 0)
		return -errno;
	rc = regular_file(fd);
	if (!rc && fstat(fd, &st))
		rc = -errno;
	if (!rc && (st.st_size <= 0 || (__u64)st.st_size >= sizeof(wire)))
		rc = -EBADMSG;
	while (!rc && done < (size_t)st.st_size) {
		got = read(fd, wire + done, st.st_size - done);
		if (got < 0) {
			if (errno == EINTR)
				continue;
			rc = -errno;
		} else if (!got) {
			rc = -EIO;
		} else {
			done += got;
		}
	}
	if (!rc)
		rc = record_decode(wire, done, true, out);
	close(fd);
	return rc;
}

static int state_save(struct shirudo_config_update *update,
		      const struct shirudo_config_update_record *record,
		      bool inject)
{
	char wire[RECORD_MAX];
	size_t length;
	int fd, rc;

	rc = record_encode(record, true, wire, sizeof(wire), &length);
	if (rc)
		return rc;
	if (unlinkat(update->dir_fd, ".state.tmp", 0) && errno != ENOENT)
		return -errno;
	fd = openat(update->dir_fd, ".state.tmp",
		    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0)
		return -errno;
	rc = update->ops->seal(update->ctx, fd);
	if (!rc)
		rc = write_complete(fd, wire, length);
	if (!rc && inject)
		rc = checkpoint(update, SHIRUDO_CONFIG_CHECK_STATE_WRITE);
	if (!rc && fsync(fd))
		rc = -errno;
	if (close(fd) && !rc)
		rc = -errno;
	if (!rc &&
	    renameat(update->dir_fd, ".state.tmp", update->dir_fd, "state"))
		rc = -errno;
	if (!rc && inject)
		rc = checkpoint(update, SHIRUDO_CONFIG_CHECK_STATE_RENAME);
	if (!rc && fsync(update->dir_fd))
		rc = -errno;
	if (rc)
		unlinkat(update->dir_fd, ".state.tmp", 0);
	return rc;
}

static bool same_boot(const struct shirudo_config_update_record *a,
		      const struct shirudo_config_update_record *b)
{
	return a->reset_count == b->reset_count &&
	       a->restart_count == b->restart_count;
}

static bool same_event(const struct shirudo_config_update_record *a,
		       const struct shirudo_config_update_record *b)
{
	return same_boot(a, b) && a->sequence == b->sequence &&
	       a->pcr == b->pcr && a->kind == b->kind &&
	       !memcmp(a->initial_pcr, b->initial_pcr, 32) &&
	       !memcmp(a->target.root_hash, b->target.root_hash, 32);
}

static int event_follows(const struct shirudo_config_update_record *previous,
			 const struct shirudo_config_update_record *record)
{
	if (record->sequence != previous->sequence + 1)
		return -EUCLEAN;
	if (!previous->sequence || !same_boot(previous, record))
		return record->kind == SHIRUDO_CONFIG_EVENT_BOOT ? 0 :
								 -EUCLEAN;
	if (record->kind != SHIRUDO_CONFIG_EVENT_UPDATE ||
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

static int events_scan(struct shirudo_config_update *update,
		       struct shirudo_config_update_record *last,
		       __u8 value[32], off_t *end, bool partial,
		       shirudo_config_cb consume, void *ctx)
{
	struct shirudo_config_update_record previous = {}, record;
	const __u8 *root = record.target.root_hash;
	__u8 running[32] = {}, digest[32];
	char wire[RECORD_MAX];
	size_t length;
	int fd, rc;
	FILE *file;

	memset(last, 0, sizeof(*last));
	if (end)
		*end = 0;
	fd = openat(update->dir_fd, "events",
		    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (fd < 0)
		return errno == ENOENT ? 0 : -errno;
	rc = regular_file(fd);
	if (rc) {
		close(fd);
		return rc;
	}
	file = fdopen(fd, "r");
	if (!file) {
		rc = -errno;
		close(fd);
		return rc;
	}
	while ((rc = read_line(file, wire, sizeof(wire), &length)) > 0) {
		rc = record_decode(wire, length, false, &record);
		if (!rc)
			rc = event_follows(&previous, &record);
		if (!rc && record.kind == SHIRUDO_CONFIG_EVENT_BOOT)
			memcpy(running, record.initial_pcr, 32);
		if (!rc)
			rc = shirudo_config_measure_event(record.kind,
							  root, digest);
		if (!rc)
			rc = shirudo_chain_fold_checked(running, digest);
		if (!rc && consume)
			rc = consume(&record, ctx);
		if (rc)
			break;
		previous = record;
		if (end) {
			*end = ftello(file);
			if (*end < 0) {
				rc = -errno;
				break;
			}
		}
	}
	if (rc == -ENODATA && partial)
		rc = 0;
	if (!rc) {
		*last = previous;
		if (value)
			memcpy(value, running, 32);
	}
	fclose(file);
	return rc;
}

int shirudo_config_update_events(struct shirudo_config_update *update,
				 shirudo_config_cb consume, void *ctx)
{
	struct shirudo_config_update_record last;

	if (!update || update->dir_fd < 0 || !consume)
		return -EINVAL;
	return events_scan(update, &last, NULL, NULL, false, consume, ctx);
}

static int event_append(struct shirudo_config_update *update,
			const struct shirudo_config_update_record *record)
{
	struct shirudo_config_update_record last;
	char wire[RECORD_MAX];
	size_t length;
	int fd, rc;
	off_t end;

	rc = events_scan(update, &last, NULL, &end,
			 record->kind == SHIRUDO_CONFIG_EVENT_BOOT, NULL, NULL);
	if (!rc)
		rc = event_follows(&last, record);
	if (!rc)
		rc = record_encode(record, false, wire, sizeof(wire), &length);
	if (rc)
		return rc;
	fd = openat(update->dir_fd, "events",
		    O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW |
			    O_NONBLOCK, 0600);
	if (fd < 0)
		return -errno;
	rc = regular_file(fd);
	if (!rc)
		rc = update->ops->seal(update->ctx, fd);
	if (!rc && ftruncate(fd, end))
		rc = -errno;
	if (!rc)
		rc = write_complete(fd, wire, length);
	if (!rc)
		rc = checkpoint(update, SHIRUDO_CONFIG_CHECK_EVENT_WRITE);
	if (!rc && fsync(fd))
		rc = -errno;
	if (close(fd) && !rc)
		rc = -errno;
	if (!rc && fsync(update->dir_fd))
		rc = -errno;
	return rc;
}

static int live_read(struct shirudo_config_update *update, __u32 pcr,
		     __u32 *reset, __u32 *restart, __u8 value[32])
{
	__u32 reset_after, restart_after;
	int rc;

	rc = update->ops->boot_identity(update->ctx, reset, restart);
	if (!rc)
		rc = update->ops->pcr_read(update->ctx, pcr, value);
	if (!rc)
		rc = update->ops->boot_identity(update->ctx, &reset_after,
						&restart_after);
	if (!rc && (*reset != reset_after || *restart != restart_after))
		rc = -ESTALE;
	return rc;
}

static int check_record(struct shirudo_config_update *update,
			const struct shirudo_config_update_record *record)
{
	struct shirudo_config_update_record last;
	__u8 expected[32], value[32];
	__u32 reset, restart;
	int rc;

	rc = events_scan(update, &last, expected, NULL, false, NULL, NULL);
	if (!rc && !same_event(record, &last))
		rc = -EUCLEAN;
	if (!rc)
		rc = live_read(update, record->pcr, &reset, &restart, value);
	if (!rc && (reset != record->reset_count ||
		    restart != record->restart_count))
		rc = -ESTALE;
	if (!rc && memcmp(value, expected, 32))
		rc = -EUCLEAN;
	return rc;
}

int shirudo_config_update_check(struct shirudo_config_update *update,
				struct shirudo_config_update_record *out)
{
	struct shirudo_config_update_record record;
	int rc;

	rc = shirudo_config_update_read(update, &record);
	if (!rc && record.pending)
		rc = -EINPROGRESS;
	if (!rc)
		rc = check_record(update, &record);
	if (!rc && out)
		*out = record;
	return rc;
}

static int complete(struct shirudo_config_update *update)
{
	struct shirudo_config_update_record record;
	int rc, restore;

	rc = shirudo_config_update_read(update, &record);
	if (!rc)
		rc = check_record(update, &record);
	if (rc)
		return rc;
	record.pending = false;
	rc = state_save(update, &record, true);
	if (!rc)
		rc = checkpoint(update, SHIRUDO_CONFIG_CHECK_COMPLETE_SYNC);
	if (rc) {
		record.pending = true;
		restore = state_save(update, &record, false);
		if (restore)
			pr_err("image: cannot restore pending selection: %s",
			       strerror(-restore));
	}
	return rc;
}

static int begin_event(struct shirudo_config_update *update,
		       const struct shirudo_config_update_target *target,
		       const struct shirudo_config_update_record *previous,
		       __u32 pcr, enum shirudo_config_event_kind kind)
{
	struct shirudo_config_update_record record = {};
	__u8 before[32], expected[32], value[32], event[32];
	__u32 reset, restart;
	int rc;

	if (previous->sequence == INT64_MAX)
		return -EOVERFLOW;
	rc = update->ops->prepare(update->ctx, target);
	if (rc)
		return rc;
	record.target = *target;
	record.sequence = previous->sequence + 1;
	record.pcr = pcr;
	record.kind = kind;
	record.pending = true;
	rc = live_read(update, pcr, &record.reset_count, &record.restart_count,
		       before);
	if (rc)
		return rc;
	memcpy(record.initial_pcr, kind == SHIRUDO_CONFIG_EVENT_BOOT ?
	       before : previous->initial_pcr, 32);
	if (!rc)
		rc = event_follows(previous, &record);
	if (!rc)
		rc = shirudo_config_measure_event(kind, target->root_hash,
						  event);
	memcpy(expected, before, 32);
	if (!rc)
		rc = shirudo_chain_fold_checked(expected, event);
	if (!rc)
		rc = state_save(update, &record, true);
	if (!rc)
		rc = checkpoint(update, SHIRUDO_CONFIG_CHECK_PENDING_SYNC);
	if (!rc)
		rc = update->ops->pcr_extend(update->ctx, pcr, event);
	if (!rc)
		rc = checkpoint(update, SHIRUDO_CONFIG_CHECK_EXTEND);
	if (!rc)
		rc = live_read(update, pcr, &reset, &restart, value);
	if (!rc && (reset != record.reset_count ||
		    restart != record.restart_count ||
		    memcmp(value, expected, 32)))
		rc = -EUCLEAN;
	if (!rc)
		rc = event_append(update, &record);
	if (!rc)
		rc = checkpoint(update, SHIRUDO_CONFIG_CHECK_EVENT_SYNC);
	if (!rc)
		rc = update->ops->activate(update->ctx, target);
	if (!rc)
		rc = checkpoint(update, SHIRUDO_CONFIG_CHECK_ACTIVATE);
	if (rc)
		return rc;
	if (kind == SHIRUDO_CONFIG_EVENT_BOOT) {
		update->boot_pending = true;
		return 0;
	}
	return complete(update);
}

int shirudo_config_update_begin(struct shirudo_config_update *update,
				const struct shirudo_config_update_target *t,
				__u32 pcr)
{
	struct shirudo_config_update_record previous;
	int rc;

	if (!update || update->dir_fd < 0 || target_valid(t) ||
	    shirudo_config_measure_pcr_valid(pcr))
		return -EINVAL;
	rc = shirudo_config_update_check(update, &previous);
	if (rc)
		return rc;
	if (pcr != previous.pcr)
		return -EPERM;
	if (!memcmp(t->root_hash, previous.target.root_hash, 32))
		return 0;
	return begin_event(update, t, &previous, pcr,
			   SHIRUDO_CONFIG_EVENT_UPDATE);
}

int shirudo_config_update_boot(struct shirudo_config_update *update,
			       const struct shirudo_config_update_target *t,
			       __u32 pcr)
{
	struct shirudo_config_update_record previous = {}, last;
	__u32 reset, restart;
	int rc;

	if (!update || update->dir_fd < 0 || target_valid(t) ||
	    shirudo_config_measure_pcr_valid(pcr))
		return -EINVAL;
	update->boot_pending = false;
	rc = shirudo_config_update_read(update, &previous);
	if (rc && rc != -ENOENT)
		return rc;
	rc = update->ops->boot_identity(update->ctx, &reset, &restart);
	if (rc)
		return rc;
	if (previous.sequence && previous.reset_count == reset &&
	    previous.restart_count == restart) {
		if (previous.pending)
			return -EINPROGRESS;
		if (previous.pcr != pcr ||
		    memcmp(t->root_hash, previous.target.root_hash, 32))
			return -EBUSY;
		return shirudo_config_update_check(update, NULL);
	}
	if (previous.sequence &&
	    (strcmp(t->prefix, previous.target.prefix) ||
	     memcmp(t->root_hash, previous.target.root_hash, 32)))
		return -EUCLEAN;
	rc = events_scan(update, &last, NULL, NULL, previous.pending,
			 NULL, NULL);
	if (rc)
		return rc;
	if (!previous.sequence && last.sequence)
		return -EUCLEAN;
	if (previous.sequence &&
	    !(same_event(&previous, &last) ||
	      (previous.pending && !event_follows(&last, &previous))))
		return -EUCLEAN;
	return begin_event(update, t, &last, pcr,
			   SHIRUDO_CONFIG_EVENT_BOOT);
}

int shirudo_config_update_complete_boot(struct shirudo_config_update *update)
{
	int rc;

	if (!update || update->dir_fd < 0)
		return -EINVAL;
	if (!update->boot_pending)
		return shirudo_config_update_check(update, NULL);
	update->boot_pending = false;
	rc = complete(update);
	return rc;
}
