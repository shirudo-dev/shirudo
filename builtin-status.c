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
#include "util/json.h"
#include "util/identity.h"
#include "util/image_bootstrap.h"
#include "util/image_runtime.h"
#include "util/keyring.h"
#include "util/keys.h"
#include "util/log.h"
#include "util/malloc.h"
#include "util/paths.h"
#include "util/initrd.h"
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
	int n_incoming;
	bool cert;
	bool signing_key;
	bool eventlog;
	bool bpffs_mounted;
};

static int count_dir(const char *dir, bool upatch_only)
{
	struct dirent **list = NULL;
	int n, i, count = 0;

	n = scandir(dir, &list, notdot, alphasort);
	if (n < 0)
		return -1;	/* directory absent */
	for (i = 0; i < n; i++) {
		if (!upatch_only || upatch_select(list[i]))
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
	a->n_upatches = count_dir(UPATCHES_DIR, true);
	a->n_incoming = count_dir(INCOMING_DIR, false);
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

static const struct help_item status_options[] = {
	{ "--json",             "print the report as one JSON document" },
	{ "--otel",             "send the JSON report as an OTLP keepalive log" },
	{ "--check",            "exit 1 when the verdict is tampered" },
	{ "--show-full",        "print every section, folded or not, and the "
				"system and eventlog sections" },
	{ "--include-system",   "add the system section: OS, kernel, machine, "
				"memory, disk, uptime" },
	{ "--include-eventlog", "add the eventlog records, all boots" },
};

static const struct help_section status_help_sections[] = {
	{ "options:", status_options,
	  ARRAY_SIZE(status_options) },
};

static const struct help status_help = {
	.usage      = "shirudo status [--json | --otel] [--check] "
		      "[--show-full]\n"
		      "                       [--include-system] "
		      "[--include-eventlog]",
	.summary    = "Report the state of this host: the verdict, the "
		      "conditions behind it, the\ntamper counters and the "
		      "loaded upatches. A section whose condition is not OK\n"
		      "unfolds below them. Safe to run before init, on a target "
		      "or an operator host.",
	.sections   = status_help_sections,
	.n_sections = ARRAY_SIZE(status_help_sections),
};

static void usage(void)
{
	fprintf(stderr, "usage: %s\n", status_help.usage);
}

static size_t build_upatches_table(struct dirent **ups, int n_ups,
				   struct upatch_table_row **out)
{
	struct upatch_table_row *rows;
	struct btf *vbtf;
	int i;

	if (n_ups <= 0) {
		*out = NULL;
		return 0;
	}
	rows = xcalloc((size_t)n_ups, sizeof(*rows));
	if (!rows) {
		*out = NULL;
		return 0;
	}
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
		r->age_sec = upatch_age_sec(r->loaded_at);
	}
	btf__free(vbtf);
	*out = rows;
	return (size_t)n_ups;
}

/* Status runs on the host, so reachable and parsed are trivially true. */
static void local_cond_input(struct conditions_input *in,
			     int lsm_attached, int keyring_present,
			     const char *keyring_mode,
			     __s64 keyring_serial,
			     __s64 keyring_serial_pinned,
			     int ks_seen, int ksp_seen, int ksm_seen,
			     int ks_matches, int tpm_reachable,
			     int chain_seen, int chain_matches, int cm_seen,
			     const char *nv_index)
{
	*in = (struct conditions_input){
		.reachable		= true,
		.parsed			= true,
		.lsm_attached		= lsm_attached,
		.keyring_present	= keyring_present,
		.keyring_mode		= keyring_mode,
		.keyring_serial		= keyring_serial,
		.keyring_serial_pinned	= keyring_serial_pinned,
		.keyring_serial_matches	= ks_matches,
		.tpm_reachable		= tpm_reachable,
		.ks_seen		= ks_seen,
		.ksp_seen		= ksp_seen,
		.ksm_seen		= ksm_seen,
		.chain_seen		= chain_seen,
		.chain_matches		= chain_matches,
		.cm_seen		= cm_seen,
		.nv_index		= nv_index,
	};
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
		const struct keyring_link *l = c->link >= 0 ?
					       &k->links[c->link] : NULL;
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
		if (l) {
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

int cmd_status(int argc, const char **argv)
{
	bool json = false;
	bool json_stdout = false, otel = false;
	bool include_system = false, include_eventlog = false;
	bool show_full = false, check = false;
	char hostname[256] = "?";
	char reason[160];
	bool lsm_attached, keyring_present, is_operator, cert_present, is_target;
	key_serial_t keyring_serial, keyring_pinned;
	const char *keyring_mode;
	struct sysinfo sysi = {};
	struct trusted_set certs = {};
	int certs_enrolled = -1;
	struct status_keyring bpf = {}, dmv = {};
	struct identity ident = {};
	int certs_rc = -ENOENT;
	struct config otel_cfg __cleanup(config_clear) = {};
	struct otel_opts otel_opts = {};
	struct asset_view assets;
	struct tamper_counts tamper = {};
	struct conditions_input cin;
	int tamper_rc = -ENOENT;
	struct dirent **ups = NULL;
	char pcr_before_hex[2 * CHAIN_DIGEST_LEN + 1] = "";
	char phase_before_hex[2 * CHAIN_DIGEST_LEN + 1] = "";
	char chain_hex[2 * CHAIN_DIGEST_LEN + 1] = "";
	char name_hex[2 * TPM_NAME_LEN + 1] = "";
	struct chain_status cst = {};
	char tcti[TPM_TCTI_MAX];
	char nv_index[16];
	char *json_buf = NULL;
	size_t json_cap = 0;
	long ev_entries = 0, ev_bytes = 0;
	int chain_rc = 0, ev_rc = -ENOENT;
	int match = -1;		/* -1 unknown, 0 mismatch, 1 match */
	int n_ups, i, fd, ret = 0;
	const char *otel_status = NULL;
	bool otel_endpoint_configured = false;
	char unmeasured_names[UNMEASURED_NAMES] = "";
	char xdp_tampered_names[UNMEASURED_NAMES] = "";
	struct measured_set *mset = NULL;
	int xdp_tampered = 0;
	char config_root_hex[65] = "";
	__u8 config_root[32];
	int unmeasured, lock;
	int config_state;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--json") == 0) {
			json_stdout = true;
		} else if (strcmp(argv[i], "--otel") == 0) {
			otel = true;
		} else if (strcmp(argv[i], "--include-system") == 0) {
			include_system = true;
		} else if (strcmp(argv[i], "--include-eventlog") == 0) {
			include_eventlog = true;
		} else if (strcmp(argv[i], "--check") == 0) {
			check = true;
		} else if (strcmp(argv[i], "--show-full") == 0) {
			show_full = true;
		} else if (is_help(argv[i])) {
			print_help(&status_help);
			return 0;
		} else {
			fprintf(stderr, "status: unknown option '%s'\n", argv[i]);
			usage();
			return 2;
		}
	}
	json = json_stdout || otel;
	if (otel) {
		int err = config_load(&otel_cfg);

		if (err) {
			pr_err("status: load OTEL configuration: %s", strerror(-err));
			return 1;
		}
		if (!otel_cfg.map_export_valid) {
			pr_err("status: invalid OTEL configuration");
			return 2;
		}
		otel_opts.endpoint = otel_cfg.map_export_otel_endpoint[0] ?
			otel_cfg.map_export_otel_endpoint : NULL;
		otel_opts.tenant_id = otel_cfg.map_export_tenant_id[0] ?
			otel_cfg.map_export_tenant_id : NULL;
		otel_opts.allow_insecure = otel_cfg.map_export_otel_insecure;
		otel_opts.retries = otel_cfg.map_export_otel_retries;
		otel_opts.otlp_max_bytes = otel_cfg.map_export_otlp_max_bytes;
		otel_endpoint_configured =
			status_otel_endpoint_configured(&otel_cfg);
	}

	if (show_full) {
		include_system = true;
		include_eventlog = true;
	}
	if (include_system)
		sysinfo_gather(&sysi);
	if (gethostname(hostname, sizeof(hostname)))
		strscpy(hostname, "?", sizeof(hostname));
	hostname[sizeof(hostname) - 1] = '\0';

	fd = bpf_obj_get(LSM_LINK_PIN);
	lsm_attached = fd >= 0;
	if (fd >= 0)
		close(fd);
	/*
	 * The anchor init froze is the kernel's record; the live keyring
	 * of that kind is what a load would name, and the two must agree.
	 */
	keyring_pinned = identity_read(&ident);
	if (!keyring_pinned)
		keyring_pinned = ident.keyring_serial;
	keyring_serial = keyring_pinned >= 1 ? keyring_bpf_serial() : -ENOKEY;
	keyring_mode = keyring_serial >= 0 ? "bpf" : "none";
	keyring_present = keyring_serial >= 0;
	/*
	 * The certificates the keyring of that kind would have been given,
	 * and how many keys the bpf keyring holds right now: the two part
	 * when a certificate was added or revoked since the boot.
	 */
	certs_rc = keys_load(KEYS_DIR, NULL,
			     !strcmp(keyring_mode, "bpf"), &certs);
	bpf.serial = keyring_serial;
	bpf.pinned = keyring_pinned;
	keyring_view_bpf(&bpf, &ident, &certs, certs_rc);
	if (!bpf.links_rc)
		certs_enrolled = (int)bpf.n_asymmetric;
	dmv.pinned = keyring_pinned < 0 ? keyring_pinned : ident.dm_verity_ring;
	dmv.serial = dmv.pinned >= 1 ? keyring_dm_verity_serial() :
		     -ENOKEY;
	keyring_view_dm_verity(&dmv, &ident);
	is_operator = access(SIGNING_KEY_PATH, F_OK) == 0;
	cert_present = access(get_cert_path(), F_OK) == 0;
	is_target = cert_present || lsm_attached || keyring_present;

	n_ups = scandir(BPFFS_UPATCHES_DIR, &ups, notdot, alphasort);
	if (n_ups < 0)
		n_ups = 0;
	lock = eventlog_lock();
	unmeasured = lock < 0 ? lock : measured_set_boot(&mset);
	if (!unmeasured) {
		unmeasured = measured_unmeasured_pins(mset, note_unmeasured,
						      unmeasured_names);
		if (unmeasured >= 0) {
			int archived;

			archived = measured_unmeasured_archives(mset,
								note_unmeasured_archive,
								unmeasured_names);
			unmeasured = archived < 0 ? archived :
				     unmeasured + archived;
		}
		xdp_tampered = upatch_xdp_archives_changed(mset, note_unmeasured,
							   xdp_tampered_names);
		measured_set_free(mset);
	}
	eventlog_unlock(lock);

	gather_assets(&assets);
	tamper_rc = tamper_read(&tamper);
	config_state = image_config_state(config_root);
	if (config_state != -ENODEV)
		hex_encode(config_root, sizeof(config_root), config_root_hex);

	{
		if (strsprintf(nv_index, sizeof(nv_index), "0x%08X",
			       NV_INDEX) < 0)
			strscpy(nv_index, "?", sizeof(nv_index));
		if (tpm_tcti(tcti, sizeof(tcti)))
			strscpy(tcti, "?", sizeof(tcti));
		chain_rc = chain_status(&cst);
		if (chain_rc == 0 && !(cst.defined && cst.written))
			chain_rc = -ENODEV;
		if (chain_rc == 0) {
			hex_encode(cst.value, sizeof(cst.value),
				   chain_hex);
			hex_encode(cst.name, cst.name_len, name_hex);
		}
		if (cst.logged) {
			hex_encode(cst.init.pcr_before,
				   sizeof(cst.init.pcr_before),
				   pcr_before_hex);
			hex_encode(cst.init.phase_before,
				   sizeof(cst.init.phase_before),
				   phase_before_hex);
		}
		ev_rc = count_eventlog(&ev_entries, &ev_bytes);

		/*
		 * Tamper check: the live register must be the index init
		 * bound this boot and equal this boot's eventlog records
		 * replayed from zero. A replay failure (malformed log, or
		 * no init record while a register exists) is a mismatch.
		 */
		if (chain_rc == 0) {
			__u8 replay[CHAIN_DIGEST_LEN];

			match = cst.anchored && !cst.rebound &&
				eventlog_replay(replay) == 0 &&
				!memneq_explicit(cst.value, replay,
						 sizeof(replay));
		}
	}

	local_cond_input(&cin, lsm_attached, keyring_present, keyring_mode,
			 keyring_serial,
			 keyring_pinned >= 1 ? keyring_pinned : 0,
			 keyring_present, keyring_pinned >= 1,
			 keyring_present && keyring_pinned >= 1,
			 keyring_present && keyring_pinned >= 1 &&
			 keyring_serial == keyring_pinned,
			 cst.tpm, chain_rc == 0, match == 1, match >= 0,
			 nv_index);
	cin.config_seen = config_state != -ENODEV;
	cin.config_state = config_state;
	cin.config_root = config_root_hex;
	cin.pins_rc = min(unmeasured, 0);
	cin.pins_unmeasured = max(unmeasured, 0);
	cin.pins_detail = unmeasured_names;
	cin.xdp_tampered = max(xdp_tampered, 0);
	cin.xdp_tampered_detail = xdp_tampered_names;
	keyring_cond_input(&cin, &bpf, &dmv);

	if (json) {
		struct json_emit e;

		/*
		 * Every loaded upatch adds a row, every certificate and link
		 * of the keyrings an entry, whose strings JSON escaping can
		 * grow sixfold, and the events[] dump re-emits the log. The
		 * clamp below keeps it under JSON_MAX_BYTES.
		 */
		json_cap = 16384 + (size_t)n_ups *
			   (6 * sizeof(struct upatch_table_row) + 256);
		json_cap += (bpf.n_certs + bpf.n_links + dmv.n_certs +
			     dmv.n_links) *
			    (6 * (KEYRING_DESC_MAX + STATUS_SUBJECT_MAX) + 512);
		if (include_eventlog && ev_rc == 0)
			json_cap += 65536 + 3 * (size_t)ev_bytes;
		if (include_system)
			json_cap += 1024 * 1024;
		if (json_cap > JSON_MAX_BYTES)
			json_cap = JSON_MAX_BYTES;
		json_buf = xmalloc(json_cap);
		if (!json_buf) {
			fprintf(stderr, "status: out of memory\n");
			ret = 1;
			goto out;
		}
		e = (struct json_emit){ .buf = json_buf, .cap = json_cap };

		json_obj_open(&e);
		json_kv_int(&e, "schema", 1);
		json_kv_string(&e, "version_id", shirudo_version_id);
		json_kv_string(&e, "host", hostname);
		json_kv_bool(&e, "is_target", is_target);
		json_kv_bool(&e, "is_operator", is_operator);
		{
			struct condition conds[CONDITIONS_MAX];
			size_t nc, ci;

			otel_status = status_verdict(&cin);
			json_kv_string(&e, "status",
				       otel_status);
			status_reason(&cin, reason, sizeof(reason));
			if (reason[0])
				json_kv_string(&e, "reason", reason);
			else
				json_kv_null(&e, "reason");
			nc = conditions(&cin, conds,
					ARRAY_SIZE(conds));
			json_arr_open(&e, "conditions");
			for (ci = 0; ci < nc; ci++) {
				json_obj_open(&e);
				json_kv_string(&e, "type",
					       conds[ci].type);
				json_kv_string(&e, "status",
					       conds[ci].status);
				json_kv_string(&e, "detail",
					       conds[ci].detail);
				json_obj_close(&e);
			}
			json_arr_close(&e);
		}
		json_kv_bool(&e, "lsm_attached", lsm_attached);
		json_kv_string(&e, "keyring_mode", keyring_mode);
		json_kv_bool(&e, "keyring_present", keyring_present);
		if (keyring_present)
			json_kv_int(&e, "keyring_serial",
				    keyring_serial);
		else
			json_kv_null(&e, "keyring_serial");
		if (keyring_pinned >= 1)
			json_kv_int(&e, "keyring_serial_pinned",
				    keyring_pinned);
		else
			json_kv_null(&e, "keyring_serial_pinned");
		if (keyring_present && keyring_pinned >= 1)
			json_kv_bool(&e, "keyring_serial_matches",
				     keyring_serial == keyring_pinned);
		else
			json_kv_null(&e, "keyring_serial_matches");
		json_kv_bool(&e, "cert_present", cert_present);
		json_arr_open(&e, "certs");
		for (i = 0; certs_rc == 0 && i < (int)certs.n; i++) {
			char sha_hex[65], fp_hex[65];

			hex_encode(certs.certs[i].sha256, 32, sha_hex);
			hex_encode(certs.certs[i].fingerprint, 32,
				   fp_hex);
			json_obj_open(&e);
			json_kv_string(&e, "sha256", sha_hex);
			json_kv_string(&e, "fingerprint", fp_hex);
			json_kv_bool(&e, "primary",
				     certs.certs[i].primary);
			json_obj_close(&e);
		}
		json_arr_close(&e);
		json_kv_int(&e, "certs_revoked",
			    certs_rc == 0 ? (int)certs.n_revoked : 0);
		json_kv_int(&e, "certs_unvouched",
			    certs_rc == 0 ? (int)certs.n_unvouched : 0);
		if (certs_enrolled >= 0)
			json_kv_int(&e, "certs_enrolled",
				    certs_enrolled);
		else
			json_kv_null(&e, "certs_enrolled");
		keyring_emit_json(&e, "bpf_keyring", &bpf, "primary");
		keyring_emit_json(&e, "dm_verity_keyring", &dmv, "config");
		json_kv_bool(&e, "signing_key_present", is_operator);
		{
			struct upatch_table_row *rows = NULL;
			size_t n_rows = build_upatches_table(ups, n_ups, &rows);

			upatch_table_emit_json(&e, rows, n_rows);
			xfree(rows, n_rows * sizeof(*rows));
		}
		json_obj_open_key(&e, "assets");
		json_kv_string(&e, "root", VAR_LIB);
		json_kv_bool(&e, "cert", assets.cert);
		json_kv_bool(&e, "signing_key", assets.signing_key);
		json_kv_bool(&e, "eventlog", assets.eventlog);
		json_kv_int(&e, "eventlog_bytes", assets.eventlog_bytes);
		if (assets.n_upatches >= 0)
			json_kv_int(&e, "upatches", assets.n_upatches);
		else
			json_kv_null(&e, "upatches");
		if (assets.n_incoming >= 0)
			json_kv_int(&e, "incoming", assets.n_incoming);
		else
			json_kv_null(&e, "incoming");
		json_kv_bool(&e, "bpffs_mounted", assets.bpffs_mounted);
		json_obj_close(&e);
		/*
		 * What the guards counted this boot, every counter by name
		 * so a collector's keys stay the same from one record to
		 * the next; null until init has pinned the map.
		 */
		if (tamper_rc == 0) {
			json_obj_open_key(&e, "tamper_attempts");
			json_kv_int(&e, "total", (__s64)tamper.total);
			json_obj_open_key(&e, "counters");
			for (i = 0; i < TAMPER_MAX; i++)
				json_kv_int(&e, tamper_name(i),
					    (__s64)tamper.count[i]);
			json_obj_close(&e);
			json_obj_close(&e);
		} else {
			json_kv_null(&e, "tamper_attempts");
		}
		if (config_state != -ENODEV) {
			json_obj_open_key(&e, "config");
			json_kv_string(&e, "root_hash", config_root_hex);
			json_kv_bool(&e, "activation_pending",
				     config_state == -EINPROGRESS);
			if (config_state && config_state != -EINPROGRESS)
				json_kv_string(&e, "error",
					       strerror(-config_state));
			else
				json_kv_null(&e, "error");
			json_obj_close(&e);
		} else {
			json_kv_null(&e, "config");
		}
		if (include_system)
			sysinfo_emit_json(&e, &sysi);
		{
			json_obj_open_key(&e, "tpm");
			json_kv_bool(&e, "reachable", cst.tpm);
			json_kv_string(&e, "nv_index", nv_index);
			if (chain_rc == 0)
				json_kv_string(&e, "chain", chain_hex);
			else
				json_kv_null(&e, "chain");
			if (chain_rc == 0)
				json_kv_string(&e, "nv_name", name_hex);
			else
				json_kv_null(&e, "nv_name");
			json_kv_bool(&e, "register_bound",
				     chain_rc == 0);
			json_kv_bool(&e, "register_anchored",
				     cst.anchored);
			json_kv_int(&e, "init_records",
				    cst.logged ? (int)cst.init.records :
				    0);
			json_kv_bool(&e, "register_rebound",
				     cst.rebound);
			json_kv_int(&e, "pcr", CHAIN_PCR);
			json_kv_int(&e, "phase_pcr",
				    CHAIN_PHASE_PCR);
			if (cst.logged) {
				json_kv_string(&e, "pcr_before",
					       pcr_before_hex);
				json_kv_string(&e, "phase_before",
					       phase_before_hex);
				json_kv_string(&e, "bound_in",
					       cst.init.initrd ?
					       "initrd" : "root");
			} else {
				json_kv_null(&e, "pcr_before");
				json_kv_null(&e, "phase_before");
				json_kv_null(&e, "bound_in");
			}
			if (match < 0)
				json_kv_null(&e, "chain_matches_eventlog");
			else
				json_kv_bool(&e, "chain_matches_eventlog",
					     match);
			json_obj_open_key(&e, "eventlog");
			json_kv_bool(&e, "present", ev_rc == 0);
			json_kv_int(&e, "entries",
				    ev_rc == 0 ? ev_entries : 0);
			json_kv_int(&e, "bytes", ev_rc == 0 ? ev_bytes : 0);
			if (include_eventlog)
				emit_eventlog_events(&e);
			json_obj_close(&e);
			json_obj_close(&e);
			tree_emit_status(&e);
		}
		json_obj_close(&e);

		if (e.err) {
			fprintf(stderr, "status: json encode failed: %s\n",
				strerror(-e.err));
			ret = 1;
		} else {
			if (otel && otel_endpoint_configured) {
				__s64 refused = tamper_rc == 0 ?
						  (__s64)tamper.total : -1;
				const char *severity_text;
				int severity_number;
				int err;

				severity_number =
					status_otel_severity(otel_status,
							     &severity_text);
				err = otel_send_log_json(&otel_opts,
							 "shirudo.keepalive",
							 "shirudo.keepalive",
							 severity_number,
							 severity_text,
							 otel_status,
							 shirudo_version_id,
							refused, json_buf,
							strlen(json_buf));
				if (err) {
					pr_err("status: OTEL export failed: %s",
					       strerror(-err));
					ret = 1;
				}
			}
			if (otel && !otel_endpoint_configured && config_state &&
			    config_state != -ENODEV)
				pr_warn("status: no keepalive is sent: with the config activation %s, no export endpoint is known, since a config image is used only when its activation record vouches for it; OTEL_EXPORTER_OTLP_ENDPOINT in /etc/shirudo/map-export.env still names one",
					config_state == -EINPROGRESS ?
					"pending" : "unverifiable");
			if (json_stdout)
				printf("%s\n", json_buf);
		}
	} else {
		struct condition conds[CONDITIONS_MAX];
		struct upatch_table_row *rows = NULL;
		bool keyrings_open, tpm_open;
		const char *folded[3];
		size_t n_rows = 0;
		size_t nc, ci, nf = 0;
		const char *verdict;

		verdict = status_verdict(&cin);
		status_reason(&cin, reason, sizeof(reason));
		nc = conditions(&cin, conds, ARRAY_SIZE(conds));
		n_rows = build_upatches_table(ups, n_ups, &rows);
		/*
		 * A section a condition vouches for says nothing the
		 * condition did not: it unfolds when that condition is not
		 * OK on a target, or on request.
		 */
		keyrings_open = show_full;
		tpm_open = show_full;
		for (ci = 0; is_target && ci < nc; ci++) {
			if (!strcmp(conds[ci].status, "OK"))
				continue;
			if (!strcmp(conds[ci].type, "KeyringSealed"))
				keyrings_open = true;
			else if (!strcmp(conds[ci].type, "ChainIntact") ||
				 !strcmp(conds[ci].type, "TpmMeasured"))
				tpm_open = true;
		}
		printf("%-22s %s\n", "Host:", hostname);
		printf("%-22s %s\n", "Roles:",
		       roles_str(is_target, is_operator));
		if (reason[0])
			printf("%-22s %s  (%s)\n", "Status:", verdict,
			       reason);
		else
			printf("%-22s %s\n", "Status:", verdict);
		printf("%-22s %s\n", "Version ID:", shirudo_version_id);
		printf("\n");
		conditions_print(conds, nc);
		printf("\nTamper attempts (this boot):\n");
		if (tamper_rc == -ENOENT)
			printf("  none recorded before init\n");
		else if (tamper_rc)
			printf("  unavailable: %s\n", strerror(-tamper_rc));
		else if (tamper.total == 0)
			printf("  none\n");
		for (i = 0; tamper_rc == 0 && i < TAMPER_MAX; i++) {
			if (tamper.count[i])
				printf("  %-20s %6llu  %s\n",
				       tamper_name(i),
				       (__u64)tamper.count[i],
				       tamper_meaning(i));
		}
		upatch_table_print(rows, n_rows);
		xfree(rows, n_rows * sizeof(*rows));
		rows = NULL;
		if (keyrings_open) {
			printf("\nKeyring (.bpf):\n");
			print_keyring_serials(&bpf);
			if (certs_rc == 0) {
				printf("  %-22s %zu trusted, %zu revoked, %zu "
				       "unvouched", "Certificates:", certs.n,
				       certs.n_revoked, certs.n_unvouched);
				if (certs_enrolled >= 0)
					printf(", %d in the bpf keyring",
					       certs_enrolled);
				printf("\n");
				print_keyring_certs(&bpf, "primary",
						    "enrolled at the next boot");
			}
			print_other_links(&bpf);
			printf("\nKeyring (.dm-verity):\n");
			print_keyring_serials(&dmv);
			if (dmv.certs_rc == 0) {
				printf("  %-22s %zu trusted", "Certificates:",
				       dmv.n_certs);
				if (!dmv.links_rc)
					printf(", %zu in the dm-verity keyring",
					       dmv.n_asymmetric);
				printf("\n");
				print_keyring_certs(&dmv, "config", "missing");
			} else if (dmv.certs_rc != -ENOENT) {
				printf("  %-22s unreadable: %s\n",
				       "Certificates:",
				       strerror(-dmv.certs_rc));
			}
			print_other_links(&dmv);
		} else {
			folded[nf++] = "keyrings";
		}
		if (tpm_open) {
			printf("\nTPM measurement:\n");
			printf("  %-22s %s (%s)\n", "TPM:",
			       cst.tpm ? "reachable" : "not reachable", tcti);
			printf("  %-22s %s (anchored in PCR %u)\n", "NV index:",
			       nv_index, CHAIN_PCR);
			if (chain_rc == 0) {
				printf("  %-22s %s\n", "Chain:", chain_hex);
				printf("  %-22s %s\n", "Register name:",
				       name_hex);
				printf("  %-22s %s\n", "Anchored:",
				       cst.anchored ? "yes, name on record" :
				       "no, the index is not the one init bound");
			} else if (!cst.tpm) {
				printf("  %-22s %s\n", "Chain:",
				       "unavailable, no TPM answered");
			} else if (chain_rc == -ENODEV) {
				printf("  %-22s %s\n", "Chain:",
				       "unavailable, register not bound this "
				       "boot");
			} else {
				printf("  %-22s unavailable, TPM error: %s\n",
				       "Chain:", strerror(-chain_rc));
			}
			if (cst.logged) {
				printf("  %-22s %s\n", "PCR before init:",
				       pcr_before_hex);
				printf("  %-22s %s (PCR %u)\n", "Phase at init:",
				       phase_before_hex, CHAIN_PHASE_PCR);
				printf("  %-22s %s\n", "Bound in:",
				       cst.init.initrd ? "initrd" :
				       "root file system");
			}
			if (cst.rebound)
				printf("  %-22s %u for this TPM reset, "
				       "rebound after init\n",
				       "Init records:",
				       cst.init.records_epoch);
			printf("  %-22s %s\n", "Chain vs eventlog:",
			       match < 0 ? "not evaluated" :
			       match ? "matches" : "mismatch");
			if (ev_rc == 0)
				printf("  %-22s %s  (%ld entries, %ld bytes)\n",
				       "Eventlog:", eventlog_path(),
				       ev_entries, ev_bytes);
			else
				printf("  %-22s absent\n", "Eventlog:");
		} else {
			folded[nf++] = "TPM measurement";
		}
		if (include_eventlog)
			print_eventlog_table();
		if (show_full) {
			printf("\nAssets (%s):\n", VAR_LIB);
			printf("  %-22s %s\n", "keys/cert.der",
			       assets.cert ? "present" : "absent");
			printf("  %-22s %s\n", "keys/signing_key.pem",
			       assets.signing_key ? "present" : "absent");
			if (assets.eventlog)
				printf("  %-22s present (%ld bytes)\n",
				       "eventlog", assets.eventlog_bytes);
			else
				printf("  %-22s absent\n", "eventlog");
			if (assets.n_upatches < 0)
				printf("  %-22s absent\n", "upatches/");
			else
				printf("  %-22s %d archived\n", "upatches/",
				       assets.n_upatches);
			if (assets.n_incoming < 0)
				printf("  %-22s absent\n", "incoming/");
			else if (assets.n_incoming == 0)
				printf("  %-22s empty\n", "incoming/");
			else
				printf("  %-22s %d staged\n", "incoming/",
				       assets.n_incoming);
			printf("  %-22s %s\n", "bpffs/",
			       assets.bpffs_mounted ? "mounted" :
			       "not mounted");
		} else {
			folded[nf++] = "assets";
		}
		if (include_system)
			print_system_human(&sysi);
		if (nf) {
			printf("\nFolded:");
			for (ci = 0; ci < nf; ci++)
				printf("%s %s", ci ? "," : "", folded[ci]);
			printf(" (--show-full)\n");
		}
	}
	if (check && !ret && !strcmp(status_verdict(&cin), "tampered"))
		ret = 1;
out:
	keyring_view_free(&bpf);
	keyring_view_free(&dmv);
	for (i = 0; i < n_ups; i++)
		libc_free(ups[i]);
	libc_free(ups);
	xfree(json_buf, json_cap);
	return ret;
}
