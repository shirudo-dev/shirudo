// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The local readiness and state report, safe before `init`.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <limits.h>
#include <linux/bpf.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>
#include <shirudo/upatch.h>

#include <time.h>

#include "builtin.h"
#include "util/chain.h"
#include "util/bpm_tree.h"
#include "util/conditions.h"
#include "util/measured.h"
#include "util/config.h"
#include "util/crypto.h"
#include "util/eventlog.h"

#include "util/help.h"
#include "util/io.h"
#include "util/java_agent.h"
#include "util/json.h"
#include "util/identity.h"
#include "util/keepalive.h"
#include "util/keepalive_quote.h"
#include "util/image_bootstrap.h"
#include "util/image_runtime.h"
#include "util/keyring.h"
#include "util/keys.h"
#include "util/log.h"
#include "util/options.h"
#include "util/malloc.h"
#include "util/paths.h"
#include "util/initrd.h"
#include "util/integrity.h"
#include "util/format.h"
#include "util/sysinfo.h"
#include "util/timefmt.h"
#include "util/tpm.h"
#include "util/upatch.h"
#include "util/upatch_maps.h"
#include "util/upatch_maps_otel.h"
#include "util/tamper.h"
#include "util/upatch_resolve.h"
#include "util/upatch_table.h"
#include "util/upatch_verify.h"
#include "util/version.h"
#include "util/xdp.h"

#define UNMEASURED_NAMES	256

static int note_unmeasured(const char *name, void *ctx)
{
	char *names = ctx;
	size_t used = strlen(names);

	if (used >= 3 && !strcmp(names + used - 3, "..."))
		return 0;
	if (strsprintf(names + used, UNMEASURED_NAMES - used, "%s%s",
		       used ? ", " : "", name) < 0 && used)
		strscpy(names + used, ", ...", UNMEASURED_NAMES - used);
	return 0;
}

static int note_unmeasured_archive(const char *name, const char *path,
				   void *ctx)
{
	return note_unmeasured(name, ctx);
}

static int note_uncovered(const char *name, const char *dev, const char *why,
			  void *ctx)
{
	char entry[UPATCH_NAME_MAX + XDP_IFNAME_MAX + 64];

	if (strsprintf(entry, sizeof(entry), "%s on %s (%s)", name, dev,
		       why) < 0)
		return note_unmeasured(name, ctx);
	return note_unmeasured(entry, ctx);
}

static int notdot(const struct dirent *e)
{
	return strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0;
}

static noinline_for_stack int count_eventlog(long *entries, long *bytes)
{
	char buf[65536];
	struct stat st;
	long lines = 0;
	ssize_t n;
	int fd;

	if (stat(eventlog_path(), &st) != 0)
		return -errno;
	*bytes = (long)st.st_size;
	fd = open(eventlog_path(), O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		ssize_t i;

		for (i = 0; i < n; i++) {
			if (buf[i] == '\n')
				lines++;
		}
	}
	close(fd);
	*entries = lines;
	return 0;
}

struct asset_view {
	long eventlog_bytes;
	int n_upatches;
	bool cert;
	bool signing_key;
	bool eventlog;
	bool bpffs_mounted;
};

static int count_upatches(const char *dir)
{
	struct dirent **list = NULL;
	int n, i, count = 0;

	n = scandir(dir, &list, notdot, alphasort);
	if (n < 0)
		return -1;	/* directory absent */
	for (i = 0; i < n; i++) {
		if (upatch_select(list[i]))
			count++;
		libc_free(list[i]);
	}
	libc_free(list);
	return count;
}

static void gather_assets(struct asset_view *a)
{
	struct stat st;

	*a = (struct asset_view){};
	a->cert = access(get_cert_path(), F_OK) == 0;
	a->signing_key = access(SIGNING_KEY_PATH, F_OK) == 0;
	if (stat(eventlog_path(), &st) == 0) {
		a->eventlog = true;
		a->eventlog_bytes = (long)st.st_size;
	}
	a->n_upatches = count_upatches(UPATCHES_DIR);
	a->bpffs_mounted = bpffs_mounted_at(BPFFS_DIR) > 0;
}

/*
 * Enough of a record for the table and events[]; the log itself stays
 * the authoritative copy.
 */
struct ev_proj {
	char ts[40];
	char type[24];
	char digest[65];
	char set_digest[65];
	char up_name[UPATCH_NAME_MAX + 1];
	char up_payload[65];
};

static int parse_event_line(const char *line, size_t len, struct ev_proj *ev)
{
	struct json_field up[] = {
		{ "name", JSON_T_STRING, ev->up_name,
		  sizeof(ev->up_name), 0, NULL, 0 },
		{ "payload_sha256", JSON_T_STRING, ev->up_payload,
		  sizeof(ev->up_payload), 0, NULL, 0 },
	};
	struct json_field f[] = {
		{ "ts", JSON_T_STRING, ev->ts, sizeof(ev->ts),
		  0, NULL, 0 },
		{ "type", JSON_T_STRING, ev->type, sizeof(ev->type),
		  0, NULL, 0 },
		{ "digest", JSON_T_STRING, ev->digest,
		  sizeof(ev->digest), 0, NULL, 0 },
		{ "set_digest", JSON_T_STRING, ev->set_digest,
		  sizeof(ev->set_digest), 0, NULL, 0 },
		{ "upatch", JSON_T_OBJECT, NULL, 0, 0, up, 2 },
	};

	*ev = (struct ev_proj){};
	return json_parse(line, len, f, ARRAY_SIZE(f));
}

static void emit_eventlog_events(struct json_emit *e)
{
	char *save, *line, *buf;
	size_t len;

	json_arr_open(e, "events");
	if (read_file(eventlog_path(), JSON_MAX_BYTES,
		      &buf, &len) != 0) {
		json_arr_close(e);
		return;
	}
	for (line = strtok_r(buf, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		struct ev_proj ev;

		json_obj_open(e);
		if (parse_event_line(line, strlen(line), &ev) != 0) {
			json_kv_string(e, "type", "unparseable");
			json_obj_close(e);
			continue;
		}
		json_kv_string(e, "ts", ev.ts);
		json_kv_string(e, "type", ev.type);
		json_kv_string(e, "digest", ev.digest);
		if (ev.set_digest[0])
			json_kv_string(e, "set_digest", ev.set_digest);
		if (ev.up_name[0]) {
			json_obj_open_key(e, "upatch");
			json_kv_string(e, "name", ev.up_name);
			json_kv_string(e, "payload_sha256",
				       ev.up_payload);
			json_obj_close(e);
		}
		json_obj_close(e);
	}
	xfree(buf, len + 1);
	json_arr_close(e);
}

static int event_detail(const struct ev_proj *ev, char *out, size_t cap)
{
	if (ev->up_name[0])
		return strsprintf(out, cap, "%s payload=%.12s..", ev->up_name,
				  ev->up_payload);
	if (ev->set_digest[0])
		return strsprintf(out, cap, "set_digest=%.12s..",
				  ev->set_digest);
	out[0] = '\0';
	return 0;
}

static void print_eventlog_table(void)
{
	char *save, *line, *buf;
	size_t len;

	if (read_file(eventlog_path(), JSON_MAX_BYTES,
		      &buf, &len) != 0)
		return;
	printf("\nEventlog:\n");
	printf("  %-20s %-13s %-13s %s\n", "TIME", "TYPE", "DIGEST",
	       "DETAIL");
	for (line = strtok_r(buf, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char detail[256];
		struct ev_proj ev;

		if (parse_event_line(line, strlen(line), &ev) != 0) {
			printf("  %-20s %-13s %-13s\n", "?", "unparseable",
			       "");
			continue;
		}
		event_detail(&ev, detail, sizeof(detail));
		printf("  %-20s %-13s %-13.12s %s\n", ev.ts, ev.type,
		       ev.digest[0] ? ev.digest : "-", detail);
	}
	xfree(buf, len + 1);
}

static void print_counters(int rc, __u64 total, const __u64 *count,
			   __u32 n, const char *(*name)(__u32),
			   const char *(*meaning)(__u32))
{
	__u32 i;

	if (rc == -ENOENT)
		printf("  none recorded before init\n");
	else if (rc)
		printf("  unavailable: %s\n", strerror(-rc));
	else if (total == 0)
		printf("  none\n");
	for (i = 0; rc == 0 && i < n; i++) {
		if (count[i])
			printf("  %-20s %6llu  %s\n", name(i),
			       (__u64)count[i], meaning(i));
	}
}

static void print_system_human(const struct sysinfo *si)
{
	printf("\nSystem:\n");
	printf("  %-22s %s\n", "OS:", si->os_pretty);
	printf("  %-22s %s\n", "Kernel:", si->kernel_release);
	if (si->kernel_version[0])
		printf("  %-22s %s\n", "Kernel version:", si->kernel_version);
	if (si->kernel_build_id[0])
		printf("  %-22s %s\n", "Kernel build ID:",
		       si->kernel_build_id);
	printf("  %-22s %s\n", "Architecture:", si->machine);
	if (si->nproc > 0)
		printf("  %-22s %ld\n", "CPUs:", si->nproc);
	if (si->mem_total_kb > 0) {
		char tot[16], used[16];

		human_size((__u64)si->mem_total_kb * 1024,
			   tot, sizeof(tot));
		if (si->mem_avail_kb >= 0 &&
		    si->mem_avail_kb <= si->mem_total_kb) {
			human_size((__u64)(si->mem_total_kb -
					   si->mem_avail_kb) * 1024,
				   used, sizeof(used));
			printf("  %-22s %s/%s\n", "Memory:", used, tot);
		} else {
			printf("  %-22s %s\n", "Memory:", tot);
		}
	}
	if (si->disk_total_kb > 0) {
		char tot[16], used[16];

		human_size((__u64)si->disk_total_kb * 1024,
			   tot, sizeof(tot));
		human_size((__u64)si->disk_used_kb * 1024,
			   used, sizeof(used));
		printf("  %-22s %s/%s\n", "Disk:", used, tot);
	}
	if (si->uptime_sec >= 0)
		printf("  %-22s %ldd %ldh %ldm\n", "Uptime:",
		       si->uptime_sec / 86400,
		       (si->uptime_sec % 86400) / 3600,
		       (si->uptime_sec % 3600) / 60);
	if (si->machine_id[0])
		printf("  %-22s %s\n", "Machine ID:", si->machine_id);
	if (si->boot_id[0])
		printf("  %-22s %s\n", "Boot ID:", si->boot_id);
}

enum status_opt {
	STATUS_JSON,
	STATUS_OTEL,
	STATUS_KEEPALIVE,
	STATUS_CHECK,
	STATUS_SHOW_FULL,
	STATUS_INCLUDE_SYSTEM,
	STATUS_INCLUDE_EVENTLOG,
};

static const struct opt_spec status_opts[] = {
	[STATUS_JSON] = { "--json", 0, 0, NULL,
		"print the report as one JSON document" },
	[STATUS_OTEL] = { "--otel", 0, 0, NULL,
		"quote the keepalive body with the TPM and send it as an OTLP log" },
	[STATUS_KEEPALIVE] = { "--keepalive", 0, 0, NULL,
		"print the keepalive body, unquoted and unsent" },
	[STATUS_CHECK] = { "--check", 0, 0, NULL,
		"exit 1 when the verdict is tampered" },
	[STATUS_SHOW_FULL] = { "--show-full", 0, 0, NULL,
		"print every section, folded or not, and the system and eventlog sections" },
	[STATUS_INCLUDE_SYSTEM] = { "--include-system", 0, 0, NULL,
		"add the system section: OS, kernel, machine, memory, disk, uptime" },
	[STATUS_INCLUDE_EVENTLOG] = { "--include-eventlog", 0, 0, NULL,
		"add the eventlog records, all boots" },
};

static const struct help_section status_help_sections[] = {
	HELP_OPTIONS("options:", status_opts),
};

static const struct help status_help = {
	.usage      = "shirudo status [--json | --otel | --keepalive] "
		      "[--check]\n"
		      "                       [--show-full] [--include-system] "
		      "[--include-eventlog]",
	.summary    = "Report the state of this host: the verdict, the "
		      "conditions behind it, the\ntamper counters and the "
		      "loaded upatches. A section whose condition is not OK\n"
		      "unfolds below them. Safe to run before init, on a target "
		      "or an operator host.",
	.sections   = status_help_sections,
	.n_sections = ARRAY_SIZE(status_help_sections),
};

struct java_rows {
	struct upatch_table_row	*rows;
	size_t			n;
};

/* A Java agent has no pin: its jar's change time is when it was loaded. */
static int java_row(const char *name,
		    const __u8 payload[UPATCH_PAYLOAD_HASH_LEN], void *ctx)
{
	struct java_rows *j = ctx;
	struct upatch_table_row *r;
	char path[PATH_MAX];
	struct stat st;

	r = xreallocarray(j->rows, j->n, j->n + 1, sizeof(*r));
	if (!r)
		return -ENOMEM;
	j->rows = r;
	r = &j->rows[j->n++];
	memset(r, 0, sizeof(*r));
	strscpy(r->name, name, sizeof(r->name));
	strscpy(r->location, "java", sizeof(r->location));
	hex_encode(payload, UPATCH_PAYLOAD_HASH_LEN, r->payload_sha256);
	if (!java_agent_path(name, path, sizeof(path)) && !stat(path, &st))
		iso8601(st.st_ctim.tv_sec, r->loaded_at, sizeof(r->loaded_at));
	r->age_sec = upatch_age_sec(r->loaded_at);
	return 0;
}

static const char *roles_str(int is_target, int is_operator)
{
	if (is_target && is_operator)
		return "target, operator";
	if (is_operator)
		return "operator";
	if (is_target)
		return "target";
	return "none";
}

/*
 * Unlike the general OTLP exporter, the periodic status keepalive must not
 * silently turn an absent configuration into a request to localhost. Keep
 * the exporter fallback unchanged for map commands, but make status export
 * conditional on an explicitly configured endpoint.
 */
static bool status_otel_endpoint_configured(const struct config *cfg)
{
	const char *endpoint;

	if (cfg->map_export_otel_endpoint[0])
		return true;
	endpoint = getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT");
	if (endpoint && endpoint[0])
		return true;
	endpoint = getenv("OTEL_EXPORTER_OTLP_ENDPOINT");
	return endpoint && endpoint[0];
}

/* What a keepalive snapshot reads past the tree state, for one try. */
struct keepalive_view {
	__s64	base_seq;
	int	outcomes_rc;
	__u8	codes[KEEPALIVE_MASK_OPS];
	char	base_root[2 * CHAIN_DIGEST_LEN + 1];
	char	mask[KEEPALIVE_MASK_B64_MAX];
	bool	log_mismatch;
	char	set_sha256[2 * CHAIN_DIGEST_LEN + 1];
	__u64	count;
	__u64	not_ok;
};

static int keepalive_read_state(void *ctx, struct tree_state *state)
{
	return tree_state_read(state);
}

static bool keepalive_pending(void *ctx)
{
	return access(BPM_TREE_PENDING_PATH, F_OK) == 0;
}

/*
 * The window reaches past the recorded segment's base into the segments
 * before it, whose outcomes the record keeps from seq 1.
 */
static void keepalive_window(struct keepalive_view *v,
			     const struct tree_state *s)
{
	__u8 projection[CHAIN_DIGEST_LEN], history[CHAIN_DIGEST_LEN];

	memset(v->codes, 0, sizeof(v->codes));
	if (s->last_seq < 0 || s->last_seq > s->head_seq) {
		v->outcomes_rc = -EBADMSG;
		return;
	}
	v->base_seq = max_t(__s64, s->head_seq - KEEPALIVE_WINDOW_OPS, 0);
	if (s->last_seq < v->base_seq) {
		v->outcomes_rc = -EBADMSG;
		return;
	}
	v->outcomes_rc = tree_outcomes_read(v->base_seq, s->last_seq, v->codes,
					    projection, history);
	if (!v->outcomes_rc)
		v->outcomes_rc = keepalive_mask(v->codes,
						s->head_seq - v->base_seq,
						v->mask, sizeof(v->mask));
	if (!v->outcomes_rc)
		hex_encode(projection, sizeof(projection), v->base_root);
}

/* eventlog_matches_state of the status document, false only. */
static bool keepalive_log_mismatch(const struct tree_state *s, int state_rc)
{
	__u8 replay[CHAIN_DIGEST_LEN];
	bool matches;

	if (tree_eventlog_matches(s, state_rc, replay, &matches))
		return false;
	return !matches;
}

/* A tree status file says why the tree left the upatch not loaded. */
static bool keepalive_upatch_not_ok(const char *name)
{
	char path[PATH_MAX];

	if (strsprintf(path, sizeof(path), "%s/%s", BPM_TREE_STATUS_DIR,
		       name) < 0)
		return false;
	return access(path, F_OK) == 0;
}

struct loaded_set {
	struct measured_upatch	*set;
	size_t			n;
	size_t			cap;
	__u64			not_ok;
};

static struct measured_upatch *loaded_set_next(struct loaded_set *l)
{
	size_t cap = l->cap ? 2 * l->cap : 16;
	struct measured_upatch *set;

	if (l->n == l->cap) {
		set = xreallocarray(l->set, l->cap, cap, sizeof(*set));
		if (!set)
			return NULL;
		l->set = set;
		l->cap = cap;
	}
	return &l->set[l->n];
}

static void loaded_set_take(struct loaded_set *l)
{
	if (keepalive_upatch_not_ok(l->set[l->n].name))
		l->not_ok++;
	l->n++;
}

static int loaded_set_pins(struct loaded_set *l)
{
	struct dirent **ups = NULL;
	int n, i, ret = 0;

	n = scandir(BPFFS_UPATCHES_DIR, &ups, notdot, alphasort);
	for (i = 0; i < n; i++) {
		struct measured_upatch *u = ret ? NULL : loaded_set_next(l);

		if (!u) {
			ret = -ENOMEM;
		} else if (!upatch_name_from_bpffs(u->name, sizeof(u->name),
						   ups[i]->d_name)) {
			upatch_payload_sha256(u->name, u->payload_hex,
					      sizeof(u->payload_hex));
			loaded_set_take(l);
		}
		libc_free(ups[i]);
	}
	libc_free(ups);
	return ret;
}

/*
 * The member carries no type: the tree operation a collector compares the
 * set with names an upatch and its payload, not what kind it is.
 */
static int loaded_set_java(const char *name,
			   const __u8 payload[UPATCH_PAYLOAD_HASH_LEN],
			   void *ctx)
{
	struct loaded_set *l = ctx;
	struct measured_upatch *u = loaded_set_next(l);

	if (!u)
		return -ENOMEM;
	strscpy(u->name, name, sizeof(u->name));
	hex_encode(payload, UPATCH_PAYLOAD_HASH_LEN, u->payload_hex);
	loaded_set_take(l);
	return 0;
}

/*
 * The set_digest form of an init event, over every upatch loaded now:
 * the pinned ones and the Java agents installed as archived.
 */
static int keepalive_loaded_set(struct keepalive_view *v)
{
	__u8 none[CHAIN_DIGEST_LEN] = {}, digest[CHAIN_DIGEST_LEN];
	__u8 event[CHAIN_DIGEST_LEN];
	struct loaded_set l = {};
	int ret;

	v->not_ok = 0;
	ret = loaded_set_pins(&l);
	if (!ret)
		ret = java_agents_each_loaded(loaded_set_java, &l);
	if (!ret)
		ret = chain_init_event(none, l.set, l.n, none, digest, event);
	if (!ret) {
		hex_encode(digest, sizeof(digest), v->set_sha256);
		v->count = l.n;
		v->not_ok = l.not_ok;
	}
	xfree(l.set, l.cap * sizeof(*l.set));
	return ret;
}

static int keepalive_collect(void *ctx, const struct tree_state *state,
			     int state_rc)
{
	struct keepalive_view *v = ctx;

	if (!state_rc)
		keepalive_window(v, state);
	v->log_mismatch = keepalive_log_mismatch(state, state_rc);
	return keepalive_loaded_set(v);
}

static const struct keepalive_snapshot_ops keepalive_ops = {
	.read_state	= keepalive_read_state,
	.pending	= keepalive_pending,
	.collect	= keepalive_collect,
};

/* What the guards counted this boot, and each set's read error. */
struct guard_counts {
	struct tamper_counts	tamper;
	struct integrity_counts	integrity;
	int			tamper_rc;
	int			integrity_rc;
};

static __u32 keepalive_flags(const struct chain_status *cst,
			     const struct guard_counts *counts,
			     const struct keepalive_view *v, int state_rc)
{
	__u32 flags = 0;

	if (cst->rebound)
		flags |= KEEPALIVE_REGISTER_REBOUND;
	if (cst->logged && !cst->init.initrd)
		flags |= KEEPALIVE_BOUND_LATE;
	if (v->log_mismatch || (!state_rc && v->outcomes_rc))
		flags |= KEEPALIVE_TREE_LOG_MISMATCH;
	if (counts->tamper_rc)
		flags |= KEEPALIVE_TAMPER_UNAVAILABLE;
	if (counts->integrity_rc)
		flags |= KEEPALIVE_INTEGRITY_UNAVAILABLE;
	return flags;
}

/* A tree state that cannot be read is a node that follows no tree. */
static noinline_for_stack int
keepalive_body(const struct conditions_input *cin,
	       const struct chain_status *cst,
	       const struct guard_counts *counts,
	       const char *config_root_hex, char body[KEEPALIVE_BODY_MAX],
	       size_t *len)
{
	struct condition conds[CONDITIONS_MAX];
	struct keepalive_input in = {};
	struct keepalive_view v = {};
	struct sysinfo_image img;
	struct tree_state state;
	struct sysinfo si = {};
	int state_rc, ret;
	__u32 flags = 0;
	size_t nc;

	ret = keepalive_snapshot(&keepalive_ops, &v, &state, &state_rc,
				 &flags);
	if (ret) {
		pr_err("status: read the keepalive inputs: %s", strerror(-ret));
		return ret;
	}
	sysinfo_gather(&si);
	sysinfo_image_read(&img);
	nc = conditions(cin, conds, ARRAY_SIZE(conds));
	in = (struct keepalive_input){
		.boot_id		= si.boot_id,
		.version_id		= shirudo_version_id,
		.config_root		= config_root_hex,
		.kernel_release		= si.kernel_release,
		.image_id		= img.id,
		.image_version		= img.version,
		.image_root		= img.root,
		.verdict		= status_verdict(cin),
		.cond			= keepalive_cond(conds, nc),
		.flags			= flags | keepalive_flags(cst, counts,
								  &v, state_rc),
		.tamper			= counts->tamper_rc ? NULL :
					  counts->tamper.count,
		.integrity		= counts->integrity_rc ? NULL :
					  counts->integrity.count,
		.set_sha256		= v.set_sha256,
		.count			= v.count,
		.not_ok			= v.not_ok,
	};
	if (!state_rc) {
		in.tree = true;
		in.tree_id = state.tree_id;
		in.generation = (__u64)state.generation;
		in.base_seq = (__u64)v.base_seq;
		in.last_seq = (__u64)state.last_seq;
		in.base_root = v.outcomes_rc ? NULL : v.base_root;
		in.projection_root = state.projection_root;
		in.mask = v.outcomes_rc ? NULL : v.mask;
	}
	ret = keepalive_emit(&in, body, KEEPALIVE_BODY_MAX, len);
	if (ret)
		pr_err("status: build the keepalive body: %s", strerror(-ret));
	return ret;
}

/*
 * One OTLP log: the body as a string and its quote as the one attribute.
 * Without a quote nothing is sent: the backend has no use for a
 * keepalive it cannot check.
 */
static int send_keepalive(const struct otel_opts *opts, const char *verdict,
			  const char *body, size_t len)
{
	char quote[KEEPALIVE_QUOTE_MAX];
	const char *severity_text;
	int severity, ret;

	ret = keepalive_quote(body, len, quote, sizeof(quote));
	if (ret) {
		pr_err("status: quote the keepalive: %s; nothing is sent",
		       strerror(-ret));
		return ret;
	}
	severity = status_otel_severity(verdict, &severity_text);
	ret = otel_send_log_string(opts, "shirudo.keepalive",
				   "shirudo.keepalive", severity,
				   severity_text, body, len, "shirudo.quote",
				   quote);
	if (ret)
		pr_err("status: send the keepalive: %s", strerror(-ret));
	return ret;
}

/* Prints the body, or with opts quotes it and sends it there. */
static noinline_for_stack int
status_keepalive(const struct conditions_input *cin,
		 const struct chain_status *cst,
		 const struct guard_counts *counts,
		 const char *config_root_hex, const struct otel_opts *opts)
{
	char body[KEEPALIVE_BODY_MAX];
	size_t len;

	if (keepalive_body(cin, cst, counts, config_root_hex, body, &len))
		return 1;
	if (!opts) {
		printf("%s\n", body);
		return 0;
	}
	return send_keepalive(opts, status_verdict(cin), body, len) ? 1 : 0;
}

#define STATUS_SUBJECT_MAX	256

/* A certificate a keyring should hold, and the link that holds it. */
struct status_cert {
	__u8	sha256[32];
	__u8	fingerprint[32];
	bool	primary;
	int	info_rc;
	char	subject[STATUS_SUBJECT_MAX];
	char	algorithm[32];
	char	not_before[11];
	long	link;			/* into the keyring's links, or -1 */
};

struct status_link {
	bool	frozen;
	bool	cert;			/* holds one of the certificates */
};

/*
 * A keyring init froze: its live and frozen serials, every link it holds
 * and which of those init froze, and the certificates it should hold.
 */
struct status_keyring {
	key_serial_t		serial;		/* live, or -errno */
	key_serial_t		pinned;		/* frozen, 0 for none, -errno */
	struct keyring_link	*links;
	struct status_link	*state;
	size_t			n_links;
	int			links_rc;
	struct status_cert	certs[KEYS_MAX];
	size_t			n_certs;
	int			certs_rc;
	size_t			n_unfrozen;
	size_t			n_asymmetric;
	bool			key_missing;
};

static void keyring_view_links(struct status_keyring *k,
			       const __s32 *frozen, size_t n_frozen)
{
	size_t i, j;

	k->links_rc = k->serial >= 0 ?
		      keyring_links(k->serial, &k->links, &k->n_links) :
		      k->serial;
	if (k->links_rc || !k->n_links)
		return;
	k->state = xcalloc(k->n_links, sizeof(*k->state));
	if (!k->state) {
		xfree(k->links, k->n_links * sizeof(*k->links));
		k->links = NULL;
		k->n_links = 0;
		k->links_rc = -ENOMEM;
		return;
	}
	for (i = 0; i < k->n_links; i++) {
		for (j = 0; j < n_frozen; j++)
			if (k->links[i].serial == frozen[j])
				k->state[i].frozen = true;
		if (!k->state[i].frozen)
			k->n_unfrozen++;
		if (!k->links[i].err &&
		    !strcmp(k->links[i].type, "asymmetric"))
			k->n_asymmetric++;
	}
}

static void keyring_view_free(struct status_keyring *k)
{
	xfree(k->links, k->n_links * sizeof(*k->links));
	xfree(k->state, k->n_links * sizeof(*k->state));
}

/* Its subject, key and dates, and the link whose key it is. */
static void keyring_view_cert(struct status_keyring *k, struct status_cert *c,
			      const __u8 *der, size_t len)
{
	struct cert cert = {};
	char desc[KEYRING_DESC_MAX];
	size_t i;

	c->link = -1;
	c->info_rc = cert_read_der(der, len, &cert);
	if (!c->info_rc) {
		c->info_rc = cert_subject(&cert, c->subject,
					  sizeof(c->subject));
		if (!c->info_rc)
			c->info_rc = cert_key_algorithm(&cert, c->algorithm,
							sizeof(c->algorithm));
		if (!c->info_rc)
			c->info_rc = cert_not_before(&cert, c->not_before);
		cert_free(&cert);
	}
	if (k->links_rc || keyring_cert_description(der, len, desc))
		return;
	for (i = 0; i < k->n_links; i++) {
		if (k->links[i].err || k->state[i].cert ||
		    strcmp(k->links[i].type, "asymmetric") ||
		    strcmp(k->links[i].description, desc))
			continue;
		k->state[i].cert = true;
		c->link = (long)i;
		break;
	}
}

static void keyring_view_bpf(struct status_keyring *k,
			     const struct identity *ident,
			     const struct trusted_set *certs,
			     int certs_rc)
{
	size_t i, n_frozen = 0;

	if (k->pinned >= 1)
		n_frozen = min(ident->n_keys, IDENTITY_KEYS_MAX);
	keyring_view_links(k, ident->key_serials, n_frozen);
	k->certs_rc = certs_rc;
	for (i = 0; certs_rc == 0 && i < certs->n; i++) {
		struct status_cert *c = &k->certs[k->n_certs++];
		const __u8 *der;
		size_t len;

		memcpy(c->sha256, certs->certs[i].sha256, 32);
		memcpy(c->fingerprint, certs->certs[i].fingerprint, 32);
		c->primary = certs->certs[i].primary;
		c->link = -1;
		c->info_rc = keys_cert_der(&certs->certs[i], &der, &len);
		if (!c->info_rc)
			keyring_view_cert(k, c, der, len);
	}
}

/* The config certificates come from the runtime image's bootstrap. */
static noinline_for_stack void
keyring_view_dm_verity(struct status_keyring *k,
		       const struct identity *ident)
{
	struct image_bootstrap boot = {};
	size_t i, j, n_frozen = 0;

	if (k->pinned >= 1)
		n_frozen = min(ident->n_dm_verity_keys, IDENTITY_KEYS_MAX);
	keyring_view_links(k, ident->dm_verity_keys, n_frozen);
	for (i = 0; !k->links_rc && i < n_frozen; i++) {
		for (j = 0; j < k->n_links; j++)
			if (k->links[j].serial == ident->dm_verity_keys[i])
				break;
		if (j == k->n_links)
			k->key_missing = true;
	}
	k->certs_rc = image_bootstrap_read(RUNTIME_CONF_PATH,
					   &boot, false);
	if (!k->certs_rc && !boot.n_certificates)
		k->certs_rc = -ENOENT;
	for (i = 0; !k->certs_rc && i < boot.n_certificates; i++) {
		struct status_cert *c = &k->certs[k->n_certs];
		__u8 *der = NULL;
		size_t len = 0;

		k->certs_rc = keys_read_der(boot.certificates[i], &der, &len);
		if (!k->certs_rc)
			k->certs_rc = keys_digest_der(der, len, c->sha256,
						      c->fingerprint);
		if (!k->certs_rc) {
			c->primary = true;
			keyring_view_cert(k, c, der, len);
			k->n_certs++;
		}
		xfree(der, len);
	}
}

static void keyring_cond_input(struct conditions_input *in,
			       const struct status_keyring *bpf,
			       const struct status_keyring *dmv)
{
	in->bpf_unfrozen = (int)bpf->n_unfrozen;
	in->dmv_present = dmv->serial >= 0;
	in->dmv_serial = dmv->serial;
	in->dmvp_seen = dmv->pinned >= 1;
	in->dmv_serial_pinned = in->dmvp_seen ? dmv->pinned : 0;
	in->dmvm_seen = in->dmv_present && in->dmvp_seen;
	in->dmv_serial_matches = in->dmvm_seen && dmv->serial == dmv->pinned;
	in->dmv_unfrozen = (int)dmv->n_unfrozen;
	in->dmv_key_missing = dmv->key_missing;
}

static void keyring_emit_json(struct json_emit *e, const char *key,
			      const struct status_keyring *k,
			      const char *role)
{
	size_t i;

	json_obj_open_key(e, key);
	json_kv_bool(e, "present", k->serial >= 0);
	if (k->serial >= 0)
		json_kv_int(e, "serial", k->serial);
	else
		json_kv_null(e, "serial");
	if (k->pinned >= 1)
		json_kv_int(e, "serial_pinned", k->pinned);
	else
		json_kv_null(e, "serial_pinned");
	if (k->serial >= 0 && k->pinned >= 1)
		json_kv_bool(e, "serial_matches", k->serial == k->pinned);
	else
		json_kv_null(e, "serial_matches");
	json_arr_open(e, "certs");
	for (i = 0; i < k->n_certs; i++) {
		const struct status_cert *c = &k->certs[i];
		char sha_hex[65], fp_hex[65];

		hex_encode(c->sha256, 32, sha_hex);
		hex_encode(c->fingerprint, 32, fp_hex);
		json_obj_open(e);
		json_kv_string(e, "sha256", sha_hex);
		json_kv_string(e, "fingerprint", fp_hex);
		json_kv_bool(e, role, c->primary);
		if (c->info_rc) {
			json_kv_null(e, "subject");
			json_kv_null(e, "algorithm");
			json_kv_null(e, "not_before");
		} else {
			json_kv_string(e, "subject", c->subject);
			json_kv_string(e, "algorithm", c->algorithm);
			json_kv_string(e, "not_before", c->not_before);
		}
		if (c->link >= 0) {
			const struct keyring_link *l = &k->links[c->link];

			json_kv_int(e, "key_serial", l->serial);
			json_kv_string(e, "key_description", l->description);
			json_kv_bool(e, "frozen", k->state[c->link].frozen);
		} else {
			json_kv_null(e, "key_serial");
			json_kv_null(e, "key_description");
			json_kv_null(e, "frozen");
		}
		json_obj_close(e);
	}
	json_arr_close(e);
	json_arr_open(e, "other_links");
	for (i = 0; i < k->n_links; i++) {
		const struct keyring_link *l = &k->links[i];

		if (k->state[i].cert)
			continue;
		json_obj_open(e);
		json_kv_int(e, "serial", l->serial);
		if (l->err) {
			json_kv_null(e, "type");
			json_kv_null(e, "description");
		} else {
			json_kv_string(e, "type", l->type);
			json_kv_string(e, "description", l->description);
		}
		json_kv_bool(e, "frozen", k->state[i].frozen);
		json_obj_close(e);
	}
	json_arr_close(e);
	json_obj_close(e);
}

static void print_link(const struct status_keyring *k, size_t i,
		       const char *indent)
{
	const struct keyring_link *l = &k->links[i];

	if (l->err) {
		printf("%slink %d  (cannot describe: %s)", indent,
		       (int)l->serial, strerror(-l->err));
	} else {
		printf("%s%s %d  ", indent,
		       strcmp(l->type, "asymmetric") ? l->type : "key",
		       (int)l->serial);
		fputs_sanitized(l->description, stdout);
	}
	printf("  (%s)\n", k->state[i].frozen ? "frozen" : "not frozen");
}

static void print_keyring_certs(const struct status_keyring *k,
				const char *role, const char *unlinked)
{
	size_t i;

	for (i = 0; i < k->n_certs; i++) {
		const struct status_cert *c = &k->certs[i];
		char fp_hex[65];

		hex_encode(c->fingerprint, 32, fp_hex);
		printf("    %s%s%s%s\n", fp_hex, c->primary ? "  (" : "",
		       c->primary ? role : "", c->primary ? ")" : "");
		if (c->info_rc)
			printf("      (details unreadable: %s)\n",
			       strerror(-c->info_rc));
		else
			printf("      %s, %s, issued %s\n", c->subject,
			       c->algorithm, c->not_before);
		if (c->link >= 0)
			print_link(k, (size_t)c->link, "      ");
		else if (!k->links_rc)
			printf("      not in the keyring  (%s)\n", unlinked);
	}
}

static void print_other_links(const struct status_keyring *k)
{
	bool header = false;
	size_t i;

	for (i = 0; i < k->n_links; i++) {
		if (k->state[i].cert)
			continue;
		if (!header)
			printf("  Other links:\n");
		header = true;
		print_link(k, i, "    ");
	}
}

static void print_keyring_serials(const struct status_keyring *k)
{
	if (k->serial >= 0)
		printf("  %-22s %lld\n", "Serial:", (__s64)k->serial);
	else if (k->pinned == -ENOENT)
		printf("  %-22s %s\n", "Serial:", "absent before init");
	else if (k->serial == -ENOKEY)
		printf("  %-22s %s\n", "Serial:", "absent");
	else
		printf("  %-22s lookup error: %s\n", "Serial:",
		       strerror(-k->serial));
	if (k->pinned == -ENOENT || k->pinned == 0)
		printf("  %-22s %s\n", "Frozen serial:", "(none this boot)");
	else if (k->pinned < 0)
		printf("  %-22s unreadable: %s\n", "Frozen serial:",
		       strerror(-k->pinned));
	else
		printf("  %-22s %lld%s\n", "Frozen serial:",
		       (__s64)k->pinned, k->serial < 0 ? "  (gone)" :
		       k->serial == k->pinned ? "  (matches)" : "  (swapped)");
	if (k->links_rc && k->serial >= 0)
		printf("  %-22s unreadable: %s\n", "Links:",
		       strerror(-k->links_rc));
}

/* The options of one status run. */
struct status_args {
	bool	json_stdout;
	bool	otel;
	bool	keepalive;
	bool	check;
	bool	show_full;
	bool	include_system;
	bool	include_eventlog;
};

/* What the checks of the pins against the records found, or -errno. */
struct status_pins {
	char	unmeasured_names[UNMEASURED_NAMES];
	char	xdp_tampered_names[UNMEASURED_NAMES];
	char	links_lost_names[UNMEASURED_NAMES];
	char	xdp_uncovered_names[UNMEASURED_NAMES];
	int	unmeasured;
	int	xdp_tampered;
	int	links_lost;
	int	xdp_uncovered;
	int	checks_rc;
	int	xdp_coverage_rc;
};

/* The measurement register and the eventlog it must match. */
struct status_tpm {
	struct chain_status	cst;
	char			tcti[TPM_TCTI_MAX];
	char			nv_index[16];
	char			chain_hex[2 * CHAIN_DIGEST_LEN + 1];
	char			name_hex[2 * TPM_NAME_LEN + 1];
	char			pcr_before_hex[2 * CHAIN_DIGEST_LEN + 1];
	char			phase_before_hex[2 * CHAIN_DIGEST_LEN + 1];
	int			chain_rc;
	int			ev_rc;
	long			ev_entries;
	long			ev_bytes;
	int			match;	/* -1 unknown, 0 mismatch, 1 match */
};

/*
 * What one report reads of the host. cin points into the names, the NV
 * index and the config root, so the view lives as long as cin is used.
 * At over 80 KB it goes by pointer only.
 */
struct status_view {
	struct conditions_input	cin;
	char			hostname[256];
	bool			lsm_attached;
	bool			is_operator;
	bool			cert_present;
	bool			is_target;
	key_serial_t		keyring_serial;
	key_serial_t		keyring_pinned;
	const char		*keyring_mode;
	bool			keyring_present;
	struct trusted_set	certs;
	int			certs_rc;
	int			certs_enrolled;	/* -1 when unread */
	struct status_keyring	bpf;
	struct status_keyring	dmv;
	struct dirent		**ups;
	int			n_ups;
	struct java_rows	java;
	struct status_pins	pins;
	struct asset_view	assets;
	struct guard_counts	counts;
	int			config_state;
	char			config_root_hex[65];
	struct status_tpm	tpm;
	struct sysinfo		sysi;
};

/* 0 to go on, OPT_DONE once help is printed, or OPT_USAGE, reported. */
static int status_parse_args(struct status_args *a, int argc,
			     const char **argv)
{
	struct opt_parser p;
	int opt;

	OPT_INIT(&p, "status", status_opts, &status_help, argc, argv, 1);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case STATUS_JSON:
			a->json_stdout = true;
			break;
		case STATUS_OTEL:
			a->otel = true;
			break;
		case STATUS_KEEPALIVE:
			a->keepalive = true;
			break;
		case STATUS_CHECK:
			a->check = true;
			break;
		case STATUS_SHOW_FULL:
			a->show_full = true;
			break;
		case STATUS_INCLUDE_SYSTEM:
			a->include_system = true;
			break;
		case STATUS_INCLUDE_EVENTLOG:
			a->include_eventlog = true;
			break;
		case OPT_ARG:
			opt_usage(&p, "unexpected argument '%s'", p.value);
			return OPT_USAGE;
		case OPT_DONE:
			return OPT_DONE;
		default:
			return OPT_USAGE;
		}
	}
	if (a->keepalive && (a->json_stdout || a->otel)) {
		opt_usage(&p, "--keepalive goes without --json and --otel");
		return OPT_USAGE;
	}
	if (a->show_full) {
		a->include_system = true;
		a->include_eventlog = true;
	}
	return 0;
}

/* 0, or the exit status for a configuration that cannot be used. */
static int status_otel_load(struct config *cfg, struct otel_opts *opts)
{
	int err = config_load(cfg);

	if (err) {
		pr_err("status: load OTEL configuration: %s", strerror(-err));
		return 1;
	}
	if (!cfg->map_export_valid) {
		pr_err("status: invalid OTEL configuration");
		return 2;
	}
	opts->endpoint = cfg->map_export_otel_endpoint[0] ?
		cfg->map_export_otel_endpoint : NULL;
	opts->tenant_id = cfg->map_export_tenant_id[0] ?
		cfg->map_export_tenant_id : NULL;
	opts->allow_insecure = cfg->map_export_otel_insecure;
	opts->retries = cfg->map_export_otel_retries;
	opts->otlp_max_bytes = cfg->map_export_otlp_max_bytes;
	return 0;
}

static bool lsm_link_pinned(void)
{
	int fd = bpf_obj_get(LSM_LINK_PIN);

	if (fd >= 0)
		close(fd);
	return fd >= 0;
}

static void status_read_keyrings(struct status_view *v)
{
	struct identity ident = {};

	/*
	 * The anchor init froze is the kernel's record; the live keyring
	 * of that kind is what a load would name, and the two must agree.
	 */
	v->keyring_pinned = identity_read(&ident);
	if (!v->keyring_pinned)
		v->keyring_pinned = ident.keyring_serial;
	v->keyring_serial = v->keyring_pinned >= 1 ? keyring_bpf_serial() :
			    -ENOKEY;
	v->keyring_mode = v->keyring_serial >= 0 ? "bpf" : "none";
	v->keyring_present = v->keyring_serial >= 0;
	/*
	 * The certificates the keyring of that kind would have been given,
	 * and how many keys the bpf keyring holds right now: the two part
	 * when a certificate was added or revoked since the boot.
	 */
	v->certs_rc = keys_load(KEYS_DIR, NULL,
				!strcmp(v->keyring_mode, "bpf"), &v->certs);
	v->bpf.serial = v->keyring_serial;
	v->bpf.pinned = v->keyring_pinned;
	keyring_view_bpf(&v->bpf, &ident, &v->certs, v->certs_rc);
	v->certs_enrolled = -1;
	if (!v->bpf.links_rc)
		v->certs_enrolled = (int)v->bpf.n_asymmetric;
	v->dmv.pinned = v->keyring_pinned < 0 ? v->keyring_pinned :
			ident.dm_verity_ring;
	v->dmv.serial = v->dmv.pinned >= 1 ? keyring_dm_verity_serial() :
			-ENOKEY;
	keyring_view_dm_verity(&v->dmv, &ident);
}

static int count_unmeasured(const struct measured_set *mset, char *names)
{
	int unmeasured;

	unmeasured = measured_unmeasured_pins(mset, note_unmeasured, names);
	if (unmeasured >= 0) {
		int archived;

		archived = measured_unmeasured_archives(mset,
							note_unmeasured_archive,
							names);
		unmeasured = archived < 0 ? archived :
			     unmeasured + archived;
	}
	if (unmeasured >= 0) {
		int jars = java_agents_unbacked(note_unmeasured, names);

		unmeasured = jars < 0 ? jars : unmeasured + jars;
	}
	return unmeasured;
}

static void status_check_pins(struct status_pins *pins)
{
	struct upatch_checks checks = {
		.changed = note_unmeasured,
		.changed_ctx = pins->xdp_tampered_names,
		.lost = note_unmeasured,
		.lost_ctx = pins->links_lost_names,
		.uncovered = note_uncovered,
		.uncovered_ctx = pins->xdp_uncovered_names,
	};
	struct measured_set *mset = NULL;
	int lock;

	lock = eventlog_lock();
	pins->unmeasured = lock < 0 ? lock : measured_set_boot(&mset);
	if (!pins->unmeasured) {
		pins->unmeasured = count_unmeasured(mset,
						    pins->unmeasured_names);
		upatch_checks_run(mset, &checks);
		pins->xdp_tampered = checks.nr_changed;
		pins->links_lost = upatch_unpinned(mset, note_unmeasured,
						   pins->links_lost_names);
		pins->links_lost = pins->links_lost < 0 ? pins->links_lost :
				   pins->links_lost + checks.nr_lost;
		pins->xdp_uncovered = checks.nr_uncovered;
		pins->checks_rc = checks.check_err;
		pins->xdp_coverage_rc = checks.coverage_err;
		measured_set_free(mset);
	}
	eventlog_unlock(lock);
}

static void status_read_config(struct status_view *v)
{
	__u8 config_root[32];

	v->config_state = image_config_state(config_root);
	if (v->config_state != -ENODEV)
		hex_encode(config_root, sizeof(config_root),
			   v->config_root_hex);
}

/*
 * Tamper check: the live register must be the index init
 * bound this boot and equal this boot's eventlog records
 * replayed from zero. A replay failure (malformed log, or
 * no init record while a register exists) is a mismatch.
 */
static int chain_matches_eventlog(const struct status_tpm *t)
{
	__u8 replay[CHAIN_DIGEST_LEN];

	if (t->chain_rc)
		return -1;
	return t->cst.anchored && !t->cst.rebound &&
	       eventlog_replay(replay) == 0 &&
	       !memneq_explicit(t->cst.value, replay, sizeof(replay));
}

static void status_read_tpm(struct status_tpm *t)
{
	if (strsprintf(t->nv_index, sizeof(t->nv_index), "0x%08X",
		       NV_INDEX) < 0)
		strscpy(t->nv_index, "?", sizeof(t->nv_index));
	if (tpm_tcti(t->tcti, sizeof(t->tcti)))
		strscpy(t->tcti, "?", sizeof(t->tcti));
	t->chain_rc = chain_status(&t->cst);
	if (t->chain_rc == 0 && !(t->cst.defined && t->cst.written))
		t->chain_rc = -ENODEV;
	if (t->chain_rc == 0) {
		hex_encode(t->cst.value, sizeof(t->cst.value), t->chain_hex);
		hex_encode(t->cst.name, t->cst.name_len, t->name_hex);
	}
	if (t->cst.logged) {
		hex_encode(t->cst.init.pcr_before,
			   sizeof(t->cst.init.pcr_before),
			   t->pcr_before_hex);
		hex_encode(t->cst.init.phase_before,
			   sizeof(t->cst.init.phase_before),
			   t->phase_before_hex);
	}
	t->ev_rc = count_eventlog(&t->ev_entries, &t->ev_bytes);
	t->match = chain_matches_eventlog(t);
}

/* Status runs on the host: reachable and parsed are trivially true. */
static void status_cond_input(struct status_view *v)
{
	const struct status_pins *pins = &v->pins;
	const struct status_tpm *t = &v->tpm;

	v->cin = (struct conditions_input){
		.reachable		= true,
		.parsed			= true,
		.lsm_attached		= v->lsm_attached,
		.keyring_present	= v->keyring_present,
		.keyring_mode		= v->keyring_mode,
		.keyring_serial		= v->keyring_serial,
		.keyring_serial_pinned	= v->keyring_pinned >= 1 ?
					  v->keyring_pinned : 0,
		.keyring_serial_matches	= v->keyring_present &&
					  v->keyring_pinned >= 1 &&
					  v->keyring_serial == v->keyring_pinned,
		.tpm_reachable		= t->cst.tpm,
		.ks_seen		= v->keyring_present,
		.ksp_seen		= v->keyring_pinned >= 1,
		.ksm_seen		= v->keyring_present &&
					  v->keyring_pinned >= 1,
		.chain_seen		= t->chain_rc == 0,
		.chain_matches		= t->match == 1,
		.cm_seen		= t->match >= 0,
		.nv_index		= t->nv_index,
		.config_seen		= v->config_state != -ENODEV,
		.config_state		= v->config_state,
		.config_root		= v->config_root_hex,
		.pins_rc		= min(pins->unmeasured, 0),
		.pins_unmeasured	= max(pins->unmeasured, 0),
		.pins_detail		= pins->unmeasured_names,
		.xdp_tampered		= max(pins->xdp_tampered, 0),
		.xdp_tampered_detail	= pins->xdp_tampered_names,
		.links_lost		= max(pins->links_lost, 0),
		.links_lost_detail	= pins->links_lost_names,
		.checks_rc		= pins->checks_rc,
		.xdp_uncovered		= max(pins->xdp_uncovered, 0),
		.xdp_uncovered_detail	= pins->xdp_uncovered_names,
		.xdp_coverage_rc	= pins->xdp_coverage_rc,
	};
	keyring_cond_input(&v->cin, &v->bpf, &v->dmv);
}

static void status_gather(struct status_view *v, bool include_system)
{
	if (include_system)
		sysinfo_gather(&v->sysi);
	if (gethostname(v->hostname, sizeof(v->hostname)))
		strscpy(v->hostname, "?", sizeof(v->hostname));
	v->hostname[sizeof(v->hostname) - 1] = '\0';
	v->lsm_attached = lsm_link_pinned();
	status_read_keyrings(v);
	v->is_operator = access(SIGNING_KEY_PATH, F_OK) == 0;
	v->cert_present = access(get_cert_path(), F_OK) == 0;
	v->is_target = v->cert_present || v->lsm_attached || v->keyring_present;
	v->n_ups = scandir(BPFFS_UPATCHES_DIR, &v->ups, notdot, alphasort);
	if (v->n_ups < 0)
		v->n_ups = 0;
	if (java_agents_each_loaded(java_row, &v->java))
		pr_warn("status: the Java agents could not all be read");
	status_check_pins(&v->pins);
	gather_assets(&v->assets);
	v->counts.tamper_rc = tamper_read(&v->counts.tamper);
	v->counts.integrity_rc = integrity_read(&v->counts.integrity);
	status_read_config(v);
	status_read_tpm(&v->tpm);
	status_cond_input(v);
}

static void status_view_free(struct status_view *v)
{
	int i;

	keyring_view_free(&v->bpf);
	keyring_view_free(&v->dmv);
	for (i = 0; i < v->n_ups; i++)
		libc_free(v->ups[i]);
	libc_free(v->ups);
	xfree(v->java.rows, v->java.n * sizeof(*v->java.rows));
}

static void emit_verdict_json(struct json_emit *e,
			      const struct conditions_input *cin)
{
	struct condition conds[CONDITIONS_MAX];
	char reason[160];
	size_t nc, ci;

	json_kv_string(e, "status", status_verdict(cin));
	status_reason(cin, reason, sizeof(reason));
	if (reason[0])
		json_kv_string(e, "reason", reason);
	else
		json_kv_null(e, "reason");
	nc = conditions(cin, conds, ARRAY_SIZE(conds));
	json_arr_open(e, "conditions");
	for (ci = 0; ci < nc; ci++) {
		json_obj_open(e);
		json_kv_string(e, "type", conds[ci].type);
		json_kv_string(e, "status", conds[ci].status);
		json_kv_string(e, "detail", conds[ci].detail);
		json_obj_close(e);
	}
	json_arr_close(e);
}

static void emit_anchor_json(struct json_emit *e, const struct status_view *v)
{
	json_kv_string(e, "keyring_mode", v->keyring_mode);
	json_kv_bool(e, "keyring_present", v->keyring_present);
	if (v->keyring_present)
		json_kv_int(e, "keyring_serial", v->keyring_serial);
	else
		json_kv_null(e, "keyring_serial");
	if (v->keyring_pinned >= 1)
		json_kv_int(e, "keyring_serial_pinned", v->keyring_pinned);
	else
		json_kv_null(e, "keyring_serial_pinned");
	if (v->keyring_present && v->keyring_pinned >= 1)
		json_kv_bool(e, "keyring_serial_matches",
			     v->keyring_serial == v->keyring_pinned);
	else
		json_kv_null(e, "keyring_serial_matches");
}

static void emit_certs_json(struct json_emit *e, const struct status_view *v)
{
	int i;

	json_arr_open(e, "certs");
	for (i = 0; v->certs_rc == 0 && i < (int)v->certs.n; i++) {
		char sha_hex[65], fp_hex[65];

		hex_encode(v->certs.certs[i].sha256, 32, sha_hex);
		hex_encode(v->certs.certs[i].fingerprint, 32, fp_hex);
		json_obj_open(e);
		json_kv_string(e, "sha256", sha_hex);
		json_kv_string(e, "fingerprint", fp_hex);
		json_kv_bool(e, "primary", v->certs.certs[i].primary);
		json_obj_close(e);
	}
	json_arr_close(e);
	json_kv_int(e, "certs_revoked",
		    v->certs_rc == 0 ? (int)v->certs.n_revoked : 0);
	json_kv_int(e, "certs_unvouched",
		    v->certs_rc == 0 ? (int)v->certs.n_unvouched : 0);
	if (v->certs_enrolled >= 0)
		json_kv_int(e, "certs_enrolled", v->certs_enrolled);
	else
		json_kv_null(e, "certs_enrolled");
}

/* The rows of the pinned upatches, then those of the Java agents. */
static size_t build_upatches_table(const struct status_view *v,
				   struct upatch_table_row **out)
{
	size_t n_rows = (size_t)v->n_ups + v->java.n;
	struct dirent **ups = v->ups;
	struct upatch_table_row *rows;
	int n_ups = v->n_ups;
	struct btf *vbtf;
	int i;

	*out = NULL;
	if (!n_rows)
		return 0;
	rows = xcalloc(n_rows, sizeof(*rows));
	if (!rows)
		return 0;
	if (v->java.n)
		memcpy(&rows[n_ups], v->java.rows,
		       v->java.n * sizeof(*rows));
	/*
	 * vmlinux BTF loaded once; per-upatch reload would burn syscalls
	 * for no gain since every shirudo upatch attaches to vmlinux.
	 */
	vbtf = btf__load_vmlinux_btf();
	for (i = 0; i < n_ups; i++) {
		struct upatch_table_row *r = &rows[i];
		struct map_summary *list = NULL;
		char raw_name[UPATCH_NAME_MAX + 1];
		size_t nm = 0;
		const char *name = ups[i]->d_name;

		if (upatch_name_from_bpffs(raw_name, sizeof(raw_name),
					   ups[i]->d_name) == 0)
			name = raw_name;

		strscpy(r->name, name, sizeof(r->name));
		upatch_resolve_location(vbtf, name,
					r->location,
					sizeof(r->location));
		upatch_loaded_at(name, r->loaded_at,
				 sizeof(r->loaded_at));
		upatch_payload_sha256(name,
				      r->payload_sha256,
				      sizeof(r->payload_sha256));
		upatch_maps_list_one(name, &list, &nm);
		r->n_maps = (__u32)nm;
		map_summary_free(list, nm);
		r->missed_ret = upatch_missed_runs(name, &r->missed_counted,
						   &r->missed_runs);
		r->age_sec = upatch_age_sec(r->loaded_at);
	}
	btf__free(vbtf);
	*out = rows;
	return n_rows;
}

static void emit_upatches_json(struct json_emit *e,
			       const struct status_view *v)
{
	struct upatch_table_row *rows = NULL;
	size_t n_rows = build_upatches_table(v, &rows);

	upatch_table_emit_json(e, rows, n_rows);
	xfree(rows, n_rows * sizeof(*rows));
}

static void emit_assets_json(struct json_emit *e,
			     const struct asset_view *assets)
{
	json_obj_open_key(e, "assets");
	json_kv_string(e, "root", VAR_LIB);
	json_kv_bool(e, "cert", assets->cert);
	json_kv_bool(e, "signing_key", assets->signing_key);
	json_kv_bool(e, "eventlog", assets->eventlog);
	json_kv_int(e, "eventlog_bytes", assets->eventlog_bytes);
	if (assets->n_upatches >= 0)
		json_kv_int(e, "upatches", assets->n_upatches);
	else
		json_kv_null(e, "upatches");
	json_kv_bool(e, "bpffs_mounted", assets->bpffs_mounted);
	json_obj_close(e);
}

/*
 * What the guards counted this boot, every counter by name
 * so a collector's keys stay the same from one record to
 * the next; null until init has pinned the map.
 */
static void emit_guard_counts_json(struct json_emit *e,
				   const struct guard_counts *counts)
{
	int i;

	if (counts->tamper_rc == 0) {
		json_obj_open_key(e, "tamper_attempts");
		json_kv_int(e, "total", (__s64)counts->tamper.total);
		json_obj_open_key(e, "counters");
		for (i = 0; i < TAMPER_MAX; i++)
			json_kv_int(e, tamper_name(i),
				    (__s64)counts->tamper.count[i]);
		json_obj_close(e);
		json_obj_close(e);
	} else {
		json_kv_null(e, "tamper_attempts");
	}
	if (counts->integrity_rc == 0) {
		json_obj_open_key(e, "integrity_attempts");
		json_kv_int(e, "total", (__s64)counts->integrity.total);
		json_obj_open_key(e, "counters");
		for (i = 0; i < INTEGRITY_MAX; i++)
			json_kv_int(e, integrity_name(i),
				    (__s64)counts->integrity.count[i]);
		json_obj_close(e);
		json_obj_close(e);
	} else {
		json_kv_null(e, "integrity_attempts");
	}
}

static void emit_config_json(struct json_emit *e, int config_state,
			     const char *config_root_hex)
{
	if (config_state != -ENODEV) {
		json_obj_open_key(e, "config");
		json_kv_string(e, "root_hash", config_root_hex);
		json_kv_bool(e, "activation_pending",
			     config_state == -EINPROGRESS);
		if (config_state && config_state != -EINPROGRESS)
			json_kv_string(e, "error", strerror(-config_state));
		else
			json_kv_null(e, "error");
		json_obj_close(e);
	} else {
		json_kv_null(e, "config");
	}
}

static void emit_tpm_json(struct json_emit *e, const struct status_tpm *t,
			  bool include_eventlog)
{
	json_obj_open_key(e, "tpm");
	json_kv_bool(e, "reachable", t->cst.tpm);
	json_kv_string(e, "nv_index", t->nv_index);
	if (t->chain_rc == 0)
		json_kv_string(e, "chain", t->chain_hex);
	else
		json_kv_null(e, "chain");
	if (t->chain_rc == 0)
		json_kv_string(e, "nv_name", t->name_hex);
	else
		json_kv_null(e, "nv_name");
	json_kv_bool(e, "register_bound", t->chain_rc == 0);
	json_kv_bool(e, "register_anchored", t->cst.anchored);
	json_kv_int(e, "init_records",
		    t->cst.logged ? (int)t->cst.init.records : 0);
	json_kv_bool(e, "register_rebound", t->cst.rebound);
	json_kv_int(e, "pcr", CHAIN_PCR);
	json_kv_int(e, "phase_pcr", CHAIN_PHASE_PCR);
	if (t->cst.logged) {
		json_kv_string(e, "pcr_before", t->pcr_before_hex);
		json_kv_string(e, "phase_before", t->phase_before_hex);
		json_kv_string(e, "bound_in",
			       t->cst.init.initrd ? "initrd" : "root");
	} else {
		json_kv_null(e, "pcr_before");
		json_kv_null(e, "phase_before");
		json_kv_null(e, "bound_in");
	}
	if (t->match < 0)
		json_kv_null(e, "chain_matches_eventlog");
	else
		json_kv_bool(e, "chain_matches_eventlog", t->match);
	json_obj_open_key(e, "eventlog");
	json_kv_bool(e, "present", t->ev_rc == 0);
	json_kv_int(e, "entries", t->ev_rc == 0 ? t->ev_entries : 0);
	json_kv_int(e, "bytes", t->ev_rc == 0 ? t->ev_bytes : 0);
	if (include_eventlog)
		emit_eventlog_events(e);
	json_obj_close(e);
	json_obj_close(e);
}

static void status_emit_json(struct json_emit *e, const struct status_view *v,
			     const struct status_args *a)
{
	json_obj_open(e);
	json_kv_int(e, "schema", 1);
	json_kv_string(e, "version_id", shirudo_version_id);
	json_kv_string(e, "host", v->hostname);
	json_kv_bool(e, "is_target", v->is_target);
	json_kv_bool(e, "is_operator", v->is_operator);
	emit_verdict_json(e, &v->cin);
	json_kv_bool(e, "lsm_attached", v->lsm_attached);
	emit_anchor_json(e, v);
	json_kv_bool(e, "cert_present", v->cert_present);
	emit_certs_json(e, v);
	keyring_emit_json(e, "bpf_keyring", &v->bpf, "primary");
	keyring_emit_json(e, "dm_verity_keyring", &v->dmv, "config");
	json_kv_bool(e, "signing_key_present", v->is_operator);
	emit_upatches_json(e, v);
	emit_assets_json(e, &v->assets);
	emit_guard_counts_json(e, &v->counts);
	emit_config_json(e, v->config_state, v->config_root_hex);
	if (a->include_system)
		sysinfo_emit_json(e, &v->sysi);
	emit_tpm_json(e, &v->tpm, a->include_eventlog);
	tree_emit_status(e);
	json_obj_close(e);
}

/*
 * Every loaded upatch adds a row, every certificate and link
 * of the keyrings an entry, whose strings JSON escaping can
 * grow sixfold, and the events[] dump re-emits the log. The
 * clamp below keeps it under JSON_MAX_BYTES.
 */
static size_t status_json_cap(const struct status_view *v,
			      const struct status_args *a)
{
	size_t json_cap;

	json_cap = 16384 + ((size_t)v->n_ups + v->java.n) *
		   (6 * sizeof(struct upatch_table_row) + 256);
	json_cap += (v->bpf.n_certs + v->bpf.n_links + v->dmv.n_certs +
		     v->dmv.n_links) *
		    (6 * (KEYRING_DESC_MAX + STATUS_SUBJECT_MAX) + 512);
	if (a->include_eventlog && v->tpm.ev_rc == 0)
		json_cap += 65536 + 3 * (size_t)v->tpm.ev_bytes;
	if (a->include_system)
		json_cap += 1024 * 1024;
	if (json_cap > JSON_MAX_BYTES)
		json_cap = JSON_MAX_BYTES;
	return json_cap;
}

/* 0, or 1 when the document could not be built. */
static int status_print_json(const struct status_view *v,
			     const struct status_args *a)
{
	size_t json_cap = status_json_cap(v, a);
	struct json_emit e;
	char *json_buf;
	int ret = 0;

	json_buf = xmalloc(json_cap);
	if (!json_buf) {
		fprintf(stderr, "status: out of memory\n");
		return 1;
	}
	e = (struct json_emit){ .buf = json_buf, .cap = json_cap };
	status_emit_json(&e, v, a);
	if (e.err) {
		fprintf(stderr, "status: json encode failed: %s\n",
			strerror(-e.err));
		ret = 1;
	} else {
		printf("%s\n", json_buf);
	}
	xfree(json_buf, json_cap);
	return ret;
}

static void unfold_sections(const struct condition *conds, size_t nc,
			    bool *keyrings_open, bool *tpm_open)
{
	size_t ci;

	for (ci = 0; ci < nc; ci++) {
		if (!strcmp(conds[ci].status, "OK"))
			continue;
		if (!strcmp(conds[ci].type, "KeyringSealed"))
			*keyrings_open = true;
		else if (!strcmp(conds[ci].type, "ChainIntact") ||
			 !strcmp(conds[ci].type, "TpmMeasured"))
			*tpm_open = true;
	}
}

static void print_summary(const struct status_view *v, const char *verdict,
			  const char *reason)
{
	printf("%-22s %s\n", "Host:", v->hostname);
	printf("%-22s %s\n", "Roles:",
	       roles_str(v->is_target, v->is_operator));
	if (reason[0])
		printf("%-22s %s  (%s)\n", "Status:", verdict, reason);
	else
		printf("%-22s %s\n", "Status:", verdict);
	printf("%-22s %s\n", "Version ID:", shirudo_version_id);
	printf("\n");
}

static void print_guard_counts(const struct guard_counts *counts)
{
	printf("\nTamper attempts (this boot):\n");
	print_counters(counts->tamper_rc, counts->tamper.total,
		       counts->tamper.count, TAMPER_MAX, tamper_name,
		       tamper_meaning);
	printf("\nIntegrity attempts (this boot):\n");
	print_counters(counts->integrity_rc, counts->integrity.total,
		       counts->integrity.count, INTEGRITY_MAX,
		       integrity_name, integrity_meaning);
}

static void print_keyrings(const struct status_view *v)
{
	printf("\nKeyring (.bpf):\n");
	print_keyring_serials(&v->bpf);
	if (v->certs_rc == 0) {
		printf("  %-22s %zu trusted, %zu revoked, %zu "
		       "unvouched", "Certificates:", v->certs.n,
		       v->certs.n_revoked, v->certs.n_unvouched);
		if (v->certs_enrolled >= 0)
			printf(", %d in the bpf keyring", v->certs_enrolled);
		printf("\n");
		print_keyring_certs(&v->bpf, "primary",
				    "enrolled at the next boot");
	}
	print_other_links(&v->bpf);
	printf("\nKeyring (.dm-verity):\n");
	print_keyring_serials(&v->dmv);
	if (v->dmv.certs_rc == 0) {
		printf("  %-22s %zu trusted", "Certificates:",
		       v->dmv.n_certs);
		if (!v->dmv.links_rc)
			printf(", %zu in the dm-verity keyring",
			       v->dmv.n_asymmetric);
		printf("\n");
		print_keyring_certs(&v->dmv, "config", "missing");
	} else if (v->dmv.certs_rc != -ENOENT) {
		printf("  %-22s unreadable: %s\n", "Certificates:",
		       strerror(-v->dmv.certs_rc));
	}
	print_other_links(&v->dmv);
}

static void print_tpm(const struct status_tpm *t)
{
	printf("\nTPM measurement:\n");
	printf("  %-22s %s (%s)\n", "TPM:",
	       t->cst.tpm ? "reachable" : "not reachable", t->tcti);
	printf("  %-22s %s (anchored in PCR %u)\n", "NV index:",
	       t->nv_index, CHAIN_PCR);
	if (t->chain_rc == 0) {
		printf("  %-22s %s\n", "Chain:", t->chain_hex);
		printf("  %-22s %s\n", "Register name:", t->name_hex);
		printf("  %-22s %s\n", "Anchored:",
		       t->cst.anchored ? "yes, name on record" :
		       "no, the index is not the one init bound");
	} else if (!t->cst.tpm) {
		printf("  %-22s %s\n", "Chain:",
		       "unavailable, no TPM answered");
	} else if (t->chain_rc == -ENODEV) {
		printf("  %-22s %s\n", "Chain:",
		       "unavailable, register not bound this "
		       "boot");
	} else {
		printf("  %-22s unavailable, TPM error: %s\n",
		       "Chain:", strerror(-t->chain_rc));
	}
	if (t->cst.logged) {
		printf("  %-22s %s\n", "PCR before init:",
		       t->pcr_before_hex);
		printf("  %-22s %s (PCR %u)\n", "Phase at init:",
		       t->phase_before_hex, CHAIN_PHASE_PCR);
		printf("  %-22s %s\n", "Bound in:",
		       t->cst.init.initrd ? "initrd" :
		       "root file system");
	}
	if (t->cst.rebound)
		printf("  %-22s %u for this TPM reset, "
		       "rebound after init\n",
		       "Init records:",
		       t->cst.init.records_epoch);
	printf("  %-22s %s\n", "Chain vs eventlog:",
	       t->match < 0 ? "not evaluated" :
	       t->match ? "matches" : "mismatch");
	if (t->ev_rc == 0)
		printf("  %-22s %s  (%ld entries, %ld bytes)\n",
		       "Eventlog:", eventlog_path(),
		       t->ev_entries, t->ev_bytes);
	else
		printf("  %-22s absent\n", "Eventlog:");
}

static void print_assets(const struct asset_view *assets)
{
	printf("\nAssets (%s):\n", VAR_LIB);
	printf("  %-22s %s\n", "keys/cert.der",
	       assets->cert ? "present" : "absent");
	printf("  %-22s %s\n", "keys/signing_key.pem",
	       assets->signing_key ? "present" : "absent");
	if (assets->eventlog)
		printf("  %-22s present (%ld bytes)\n",
		       "eventlog", assets->eventlog_bytes);
	else
		printf("  %-22s absent\n", "eventlog");
	if (assets->n_upatches < 0)
		printf("  %-22s absent\n", "upatches/");
	else
		printf("  %-22s %d archived\n", "upatches/",
		       assets->n_upatches);
	printf("  %-22s %s\n", "bpffs/",
	       assets->bpffs_mounted ? "mounted" :
	       "not mounted");
}

static void print_folded(const char *const *folded, size_t nf)
{
	size_t i;

	printf("\nFolded:");
	for (i = 0; i < nf; i++)
		printf("%s %s", i ? "," : "", folded[i]);
	printf(" (--show-full)\n");
}

static void status_print_text(const struct status_view *v,
			      const struct status_args *a)
{
	struct condition conds[CONDITIONS_MAX];
	struct upatch_table_row *rows = NULL;
	bool keyrings_open, tpm_open;
	const char *folded[3];
	size_t n_rows = 0;
	size_t nc, nf = 0;
	const char *verdict;
	char reason[160];

	verdict = status_verdict(&v->cin);
	status_reason(&v->cin, reason, sizeof(reason));
	nc = conditions(&v->cin, conds, ARRAY_SIZE(conds));
	n_rows = build_upatches_table(v, &rows);
	/*
	 * A section a condition vouches for says nothing the
	 * condition did not: it unfolds when that condition is not
	 * OK on a target, or on request.
	 */
	keyrings_open = a->show_full;
	tpm_open = a->show_full;
	if (v->is_target)
		unfold_sections(conds, nc, &keyrings_open, &tpm_open);
	print_summary(v, verdict, reason);
	conditions_print(conds, nc);
	print_guard_counts(&v->counts);
	upatch_table_print(rows, n_rows);
	xfree(rows, n_rows * sizeof(*rows));
	rows = NULL;
	if (keyrings_open)
		print_keyrings(v);
	else
		folded[nf++] = "keyrings";
	if (tpm_open)
		print_tpm(&v->tpm);
	else
		folded[nf++] = "TPM measurement";
	if (a->include_eventlog)
		print_eventlog_table();
	if (a->show_full)
		print_assets(&v->assets);
	else
		folded[nf++] = "assets";
	if (a->include_system)
		print_system_human(&v->sysi);
	if (nf)
		print_folded(folded, nf);
}

int cmd_status(int argc, const char **argv)
{
	struct config otel_cfg __cleanup(config_clear) = {};
	bool otel_endpoint_configured = false;
	struct otel_opts otel_opts = {};
	struct status_args a = {};
	struct status_view v = {};
	int ret;

	ret = status_parse_args(&a, argc, argv);
	if (ret)
		return ret == OPT_DONE ? 0 : EXIT_USAGE;
	if (a.otel) {
		ret = status_otel_load(&otel_cfg, &otel_opts);
		if (ret)
			return ret;
		otel_endpoint_configured =
			status_otel_endpoint_configured(&otel_cfg);
	}

	status_gather(&v, a.include_system);
	if (a.keepalive || (a.otel && otel_endpoint_configured))
		ret = status_keepalive(&v.cin, &v.tpm.cst, &v.counts,
				       v.config_state ? NULL :
				       v.config_root_hex,
				       a.otel ? &otel_opts : NULL);
	if (a.otel && !otel_endpoint_configured && v.config_state &&
	    v.config_state != -ENODEV)
		pr_warn("status: no keepalive is sent: with the config activation %s, no export endpoint is known, since a config image is used only when its activation record vouches for it; OTEL_EXPORTER_OTLP_ENDPOINT in /etc/shirudo/map-export.env still names one",
			v.config_state == -EINPROGRESS ? "pending" :
			"unverifiable");
	if (a.json_stdout) {
		if (status_print_json(&v, &a))
			ret = 1;
	} else if (!a.keepalive && !a.otel) {
		status_print_text(&v, &a);
	}
	if (a.check && !ret && !strcmp(status_verdict(&v.cin), "tampered"))
		ret = 1;
	status_view_free(&v);
	return ret;
}
