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
#include "util/config.h"
#include "util/eventlog.h"

#define SHIRUDO_KERNEL_LOG_MAX 100
#include "util/help.h"
#include "util/io.h"
#include "util/json.h"
#include "util/macros.h"
#include "util/identity.h"
#include "util/keyring.h"
#include "util/keys.h"
#include "util/log.h"
#include "util/malloc.h"
#include "util/paths.h"
#include "util/kmodules.h"
#include "util/kmsg.h"
#include "util/format.h"
#include "util/sysinfo.h"
#include "util/timefmt.h"
#include "util/tpm.h"
#include "util/upatch_maps.h"
#include "util/upatch_maps_otel.h"
#include "util/tamper.h"
#include "util/upatch_resolve.h"
#include "util/upatch_table.h"
#include "util/version.h"

static int notdot(const struct dirent *e)
{
	return strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0;
}

static int count_eventlog(long *entries, long *bytes)
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
		const char *nm = list[i]->d_name;
		size_t len = strlen(nm);

		if (!upatch_only ||
		    (len > 7 && strcmp(nm + len - 7, ".upatch") == 0))
			count++;
		libc_free(list[i]);
	}
	libc_free(list);
	return count;
}

static bool bpffs_is_mounted(void)
{
	char line[4096];
	bool found = false;
	FILE *f;

	f = fopen("/proc/self/mounts", "r");
	if (!f)
		return false;
	while (fgets(line, sizeof(line), f)) {
		char *mp = strchr(line, ' ');	/* field 2 = mountpoint */

		if (mp && strncmp(mp + 1, SHIRUDO_BPFFS_DIR " ",
				  strlen(SHIRUDO_BPFFS_DIR) + 1) == 0) {
			found = true;
			break;
		}
	}
	fclose(f);
	return found;
}

static void gather_assets(struct asset_view *a)
{
	struct stat st;

	*a = (struct asset_view){};
	a->cert = access(SHIRUDO_CERT_PATH, F_OK) == 0;
	a->signing_key = access(SHIRUDO_SIGNING_KEY_PATH, F_OK) == 0;
	if (stat(eventlog_path(), &st) == 0) {
		a->eventlog = true;
		a->eventlog_bytes = (long)st.st_size;
	}
	a->n_upatches = count_dir(SHIRUDO_UPATCHES_DIR, true);
	a->n_incoming = count_dir(SHIRUDO_INCOMING_DIR, false);
	a->bpffs_mounted = bpffs_is_mounted();
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
	char up_name[128];
	char up_payload[65];
};

static int parse_event_line(const char *line, size_t len, struct ev_proj *ev)
{
	struct shirudo_json_field up[] = {
		{ "name", SHIRUDO_JSON_T_STRING, ev->up_name,
		  sizeof(ev->up_name), 0, NULL, 0 },
		{ "payload_sha256", SHIRUDO_JSON_T_STRING, ev->up_payload,
		  sizeof(ev->up_payload), 0, NULL, 0 },
	};
	struct shirudo_json_field f[] = {
		{ "ts", SHIRUDO_JSON_T_STRING, ev->ts, sizeof(ev->ts),
		  0, NULL, 0 },
		{ "type", SHIRUDO_JSON_T_STRING, ev->type, sizeof(ev->type),
		  0, NULL, 0 },
		{ "digest", SHIRUDO_JSON_T_STRING, ev->digest,
		  sizeof(ev->digest), 0, NULL, 0 },
		{ "set_digest", SHIRUDO_JSON_T_STRING, ev->set_digest,
		  sizeof(ev->set_digest), 0, NULL, 0 },
		{ "upatch", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, up, 2 },
	};

	*ev = (struct ev_proj){};
	return json_parse(line, len, f, ARRAY_SIZE(f));
}

static void emit_eventlog_events(struct shirudo_json_emit *e)
{
	char *save, *line, *buf;
	size_t len;

	json_arr_open(e, "events");
	if (read_file(eventlog_path(), SHIRUDO_JSON_MAX_BYTES,
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

static void event_detail(const struct ev_proj *ev, char *out, size_t cap)
{
	if (ev->up_name[0])
		snprintf(out, cap, "%s payload=%.12s..", ev->up_name,
			 ev->up_payload);
	else if (ev->set_digest[0])
		snprintf(out, cap, "set_digest=%.12s..", ev->set_digest);
	else
		out[0] = '\0';
}

static void print_eventlog_table(void)
{
	char *save, *line, *buf;
	size_t len;

	if (read_file(eventlog_path(), SHIRUDO_JSON_MAX_BYTES,
		      &buf, &len) != 0)
		return;
	printf("\nEventlog (audit trail):\n");
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

static void print_system_human(const struct shirudo_sysinfo *si)
{
	printf("\nSystem Info:\n");
	printf("  %-16s %s\n", "OS:", si->os_pretty);
	printf("  %-16s %s\n", "Kernel:", si->kernel_release);
	if (si->kernel_version[0])
		printf("  %-16s %s\n", "Kernel Version:", si->kernel_version);
	if (si->kernel_build_id[0])
		printf("  %-16s %s\n", "Kernel Build ID:",
		       si->kernel_build_id);
	printf("  %-16s %s\n", "Architecture:", si->machine);
	if (si->nproc > 0)
		printf("  %-16s %ld\n", "CPUs:", si->nproc);
	if (si->mem_total_kb > 0) {
		char tot[16], used[16];

		human_size((__u64)si->mem_total_kb * 1024,
			   tot, sizeof(tot));
		if (si->mem_avail_kb >= 0 &&
		    si->mem_avail_kb <= si->mem_total_kb) {
			human_size((__u64)(si->mem_total_kb -
					   si->mem_avail_kb) * 1024,
				   used, sizeof(used));
			printf("  %-16s %s/%s\n", "Memory:", used, tot);
		} else {
			printf("  %-16s %s\n", "Memory:", tot);
		}
	}
	if (si->disk_total_kb > 0) {
		char tot[16], used[16];

		human_size((__u64)si->disk_total_kb * 1024,
			   tot, sizeof(tot));
		human_size((__u64)si->disk_used_kb * 1024,
			   used, sizeof(used));
		printf("  %-16s %s/%s\n", "Disk:", used, tot);
	}
	if (si->uptime_sec >= 0)
		printf("  %-16s %ldd %ldh %ldm\n", "Uptime:",
		       si->uptime_sec / 86400,
		       (si->uptime_sec % 86400) / 3600,
		       (si->uptime_sec % 3600) / 60);
	if (si->hostname[0])
		printf("  %-16s %s\n", "Hostname:", si->hostname);
	if (si->machine_id[0])
		printf("  %-16s %s\n", "Machine ID:", si->machine_id);
	if (si->boot_id[0])
		printf("  %-16s %s\n", "Boot ID:", si->boot_id);
}

static void print_kernel_config_entry(void *ctx, const char *key,
				      const char *value)
{
	(void)ctx;
	printf("    %s=%s\n", key, value);
}

static void print_kernel_config_human(const struct shirudo_sysinfo *si)
{
	printf("  Kernel Config:\n");
	if (sysinfo_kernel_config_foreach(si->kernel_release,
					  print_kernel_config_entry,
					  NULL) < 0)
		printf("    (unavailable)\n");
}

static const struct shirudo_help_item status_options[] = {
	{ "--json",                 "machine-readable JSON output" },
	{ "--otel",                 "export the status report as an OTLP log" },
	{ "--include-system",       "add a `system` block (hostname, kernel, arch, cpus, ...)" },
	{ "--include-eventlog",     "dump eventlog entries" },
	{ "--include-kernellog[=N]", "last N lines of the kernel ring buffer "
				     "(default 10, max 100)" },
	{ "--include-modules",
	  "loaded kernel modules (10 most recent; --show-full for tree)" },
	{ "--show-full",            "opt into a full dump: implies every --include-* flag and "
				    "expands the loaded-modules dependency tree" },
};

static const struct shirudo_help_section status_help_sections[] = {
	{ "options:", status_options,
	  ARRAY_SIZE(status_options) },
};

static const struct shirudo_help status_help = {
	.usage      = "shirudo status [--json] [--otel] "
		      "[--include-system] [--include-eventlog]\n"
		      "                       [--include-kernellog[=N]] "
		      "[--include-modules] [--show-full]",
	.summary    = "Local readiness + state report. Auto-detects target "
		      "vs operator role.\nSafe to run before `shirudo init`.",
	.sections   = status_help_sections,
	.n_sections = sizeof(status_help_sections) /
		      sizeof(status_help_sections[0]),
};

static void usage(void)
{
	fprintf(stderr, "usage: %s\n", status_help.usage);
}

static size_t build_upatches_table(struct dirent **ups, int n_ups,
				   struct shirudo_upatch_table_row **out)
{
	struct shirudo_upatch_table_row *rows;
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
		struct shirudo_upatch_table_row *r = &rows[i];
		struct shirudo_map_summary *list = NULL;
		char raw_name[SHIRUDO_UPATCH_NAME_MAX + 1];
		size_t nm = 0;
		const char *name = ups[i]->d_name;

		if (upatch_name_from_bpffs(raw_name, sizeof(raw_name),
					   ups[i]->d_name) == 0)
			name = raw_name;

		snprintf(r->name, sizeof(r->name), "%.*s",
			 (int)(sizeof(r->name) - 1), name);
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
	if (vbtf)
		btf__free(vbtf);
	*out = rows;
	return (size_t)n_ups;
}

/* Status runs on the host, so reachable and parsed are trivially true. */
static void local_cond_input(struct shirudo_conditions_input *in,
			     int lsm_attached, int keyring_present,
			     const char *keyring_mode, int staging,
			     __s64 keyring_serial,
			     __s64 keyring_serial_pinned,
			     int ks_seen, int ksp_seen, int ksm_seen,
			     int ks_matches, int tpm_reachable,
			     int chain_seen, int chain_matches, int cm_seen,
			     const char *nv_index)
{
	*in = (struct shirudo_conditions_input){
		.reachable		= true,
		.parsed			= true,
		.lsm_attached		= lsm_attached,
		.keyring_present	= keyring_present,
		.keyring_mode		= keyring_mode,
		.staging		= staging,
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

static int status_otel_severity(const char *status, const char **text)
{
	if (strcmp(status, "ok") == 0) {
		*text = "INFO";
		return 9;
	}
	if (strcmp(status, "degraded") == 0 ||
	    strcmp(status, "init-pending") == 0) {
		*text = "WARN";
		return 13;
	}
	*text = "ERROR";
	return 17;
}

/*
 * Unlike the general OTLP exporter, the periodic status keepalive must not
 * silently turn an absent configuration into a request to localhost. Keep
 * the exporter fallback unchanged for map commands, but make status export
 * conditional on an explicitly configured endpoint.
 */
static bool status_otel_endpoint_configured(const struct shirudo_config *cfg)
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

static void count_asymmetric(key_serial_t serial, const char *type,
			     const char *description, void *ud)
{
	size_t *n = ud;

	(void)serial;
	(void)description;
	if (strcmp(type, "asymmetric") == 0)
		(*n)++;
}

int cmd_status(int argc, const char **argv)
{
	bool json = false;
	bool json_stdout = false, otel = false;
	bool include_system = false, include_eventlog = false;
	bool include_kernel_log = false, include_modules = false;
	bool show_full = false, locked;
	__u32 kernel_log_lines = 10;
	bool lsm_attached, keyring_present, is_operator, cert_present, is_target;
	key_serial_t keyring_serial, keyring_pinned;
	const char *keyring_mode, *mode;
	struct shirudo_sysinfo sysi = {};
	struct shirudo_trusted_set certs = {};
	int certs_enrolled = -1;
	struct shirudo_identity ident;
	int certs_rc = -ENOENT;
	struct shirudo_config otel_cfg = {};
	struct shirudo_otel_opts otel_opts = {};
	struct asset_view assets;
	struct shirudo_tamper_counts tamper = {};
	int tamper_rc = -ENOENT;
	struct dirent **ups = NULL;
	char pcr_before_hex[2 * SHIRUDO_CHAIN_DIGEST_LEN + 1] = "";
	char phase_before_hex[2 * SHIRUDO_CHAIN_DIGEST_LEN + 1] = "";
	char chain_hex[2 * SHIRUDO_CHAIN_DIGEST_LEN + 1] = "";
	char name_hex[2 * SHIRUDO_TPM_NAME_LEN + 1] = "";
	struct chain_status cst = {};
	char tcti[SHIRUDO_TPM_TCTI_MAX];
	char nv_index[16];
	char *json_buf = NULL;
	size_t json_cap = 0;
	long ev_entries = 0, ev_bytes = 0;
	int chain_rc = 0, ev_rc = -ENOENT;
	int match = -1;		/* -1 unknown, 0 mismatch, 1 match */
	int n_ups, i, fd, ret = 0;
	const char *otel_status = NULL;
	bool otel_endpoint_configured = false;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--json") == 0) {
			json_stdout = true;
		} else if (strcmp(argv[i], "--otel") == 0) {
			otel = true;
		} else if (strcmp(argv[i], "--include-system") == 0) {
			include_system = true;
		} else if (strcmp(argv[i], "--include-eventlog") == 0) {
			include_eventlog = true;
		} else if (strcmp(argv[i], "--include-kernellog") == 0) {
			include_kernel_log = true;
		} else if (strncmp(argv[i], "--include-kernellog=", 20) == 0) {
			const char *n = argv[i] + 20;
			__u64 v;

			if (parse_u64(n, strlen(n), SHIRUDO_KERNEL_LOG_MAX, &v) ||
			    v < 1) {
				fprintf(stderr, "status: --include-kernellog=N "
					"must be 1..%d\n",
					SHIRUDO_KERNEL_LOG_MAX);
				return 2;
			}
			include_kernel_log = true;
			kernel_log_lines = (__u32)v;
		} else if (strcmp(argv[i], "--include-modules") == 0) {
			include_modules = true;
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
		int rc = config_load(&otel_cfg);

		if (rc) {
			pr_err("status: load OTEL configuration: %s", strerror(-rc));
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

	/*
	 * --show-full is the one-switch verbose mode: every section the
	 * --include-* flags can opt into, plus the modules dep-tree. Stack
	 * it on first so any individual --include-* already given is a no-op.
	 */
	if (show_full) {
		include_system = true;
		include_eventlog = true;
		include_kernel_log = true;
		include_modules = true;
	}
	if (include_system)
		sysinfo_gather(&sysi);

	fd = bpf_obj_get(SHIRUDO_LSM_LINK_PIN);
	lsm_attached = fd >= 0;
	if (fd >= 0)
		close(fd);
	/*
	 * The anchor init froze is the kernel's record; the live keyring
	 * of that kind is what a load would name, and the two must agree.
	 */
	keyring_pinned = identity_read(&ident);
	if (keyring_pinned == 0) {
		keyring_pinned = ident.keyring_serial;
		if (ident.keyring_type == SHIRUDO_SIG_KEYRING_BPF) {
			keyring_serial = keyring_bpf_serial();
			keyring_mode = "bpf";
		} else {
			keyring_serial =
				keyring_find(SHIRUDO_KEYRING_NAME);
			keyring_mode = "user";
		}
	} else {
		keyring_serial = keyring_find(SHIRUDO_KEYRING_NAME);
		keyring_mode = keyring_serial >= 0 ? "user" : "none";
	}
	keyring_present = keyring_serial >= 0;
	/*
	 * The certificates the keyring of that kind would have been given,
	 * and how many keys the bpf keyring holds right now: the two part
	 * when a certificate was added or revoked since the boot.
	 */
	certs_rc = keys_load(SHIRUDO_KEYS_DIR, NULL,
			     !strcmp(keyring_mode, "bpf"), &certs);
	if (!strcmp(keyring_mode, "bpf") && keyring_present) {
		size_t n = 0;

		if (keyring_list(keyring_serial, count_asymmetric,
				 &n) == 0)
			certs_enrolled = (int)n;
	}
	/*
	 * Enforcing with the certificate in the user keyring is staging:
	 * the kernel's bpf keyring was sealed empty at boot, so the trust
	 * anchor is what init could seal from the root file system.
	 */
	mode = !lsm_attached ? "inactive" :
	       !strcmp(keyring_mode, "bpf") ? "production" : "staging";
	is_operator = access(SHIRUDO_SIGNING_KEY_PATH, F_OK) == 0;
	cert_present = access(SHIRUDO_CERT_PATH, F_OK) == 0;
	is_target = cert_present || lsm_attached || keyring_present;

	n_ups = scandir(SHIRUDO_BPFFS_UPATCHES_DIR, &ups, notdot, alphasort);
	if (n_ups < 0)
		n_ups = 0;

	gather_assets(&assets);
	tamper_rc = tamper_read(&tamper);

	{
		snprintf(nv_index, sizeof(nv_index), "0x%08X", SHIRUDO_NV_INDEX);
		if (tpm_tcti(tcti, sizeof(tcti)))
			strscpy(tcti, "?", sizeof(tcti));
		locked = eventlog_lock(false) == 0;
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
			__u8 replay[SHIRUDO_CHAIN_DIGEST_LEN];

			match = cst.anchored && !cst.rebound &&
				eventlog_replay(replay) == 0 &&
				ct_eq(cst.value, replay,
				      sizeof(replay));
		}
		if (locked)
			eventlog_unlock();
	}

	if (json) {
		struct shirudo_json_emit e;

		/*
		 * The events[] dump re-emits the log, so size the buffer
		 * from it with headroom for the fixed fields and the
		 * optional sections; the clamp below keeps it under
		 * SHIRUDO_JSON_MAX_BYTES.
		 */
		json_cap = 16384;
		if (include_eventlog && ev_rc == 0)
			json_cap = 65536 + 3 * (size_t)ev_bytes;
		if (include_kernel_log)
			json_cap += (size_t)kernel_log_lines * 1024 + 4096;
		if (include_modules)
			json_cap += 64 * 1024;
		if (include_system)
			json_cap += 1024 * 1024;
		if (json_cap > SHIRUDO_JSON_MAX_BYTES)
			json_cap = SHIRUDO_JSON_MAX_BYTES;
		json_buf = xmalloc(json_cap);
		if (!json_buf) {
			fprintf(stderr, "status: out of memory\n");
			ret = 1;
			goto out;
		}
		e = (struct shirudo_json_emit){ .buf = json_buf, .cap = json_cap };

		json_obj_open(&e);
		json_kv_int(&e, "schema", 1);
		json_kv_string(&e, "version_id", shirudo_version_id);
		json_kv_bool(&e, "is_target", is_target);
		json_kv_bool(&e, "is_operator", is_operator);
		{
			struct shirudo_conditions_input cin;
			struct shirudo_condition conds[SHIRUDO_CONDITIONS_MAX];
			size_t nc, ci;

			local_cond_input(&cin, lsm_attached, keyring_present,
					 keyring_mode,
					 lsm_attached && strcmp(keyring_mode, "bpf") != 0,
					 keyring_serial,
					 keyring_pinned >= 1 ? keyring_pinned : 0,
					 keyring_present, keyring_pinned >= 1,
					 keyring_present && keyring_pinned >= 1,
					 keyring_present && keyring_pinned >= 1 &&
					 keyring_serial == keyring_pinned,
					 cst.tpm, chain_rc == 0,
					 match == 1, match >= 0,
					 nv_index);
			otel_status = status_verdict(&cin);
			json_kv_string(&e, "status",
				       otel_status);
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
		json_kv_string(&e, "mode", mode);
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
		json_kv_bool(&e, "signing_key_present", is_operator);
		{
			struct shirudo_upatch_table_row *rows = NULL;
			size_t n_rows = build_upatches_table(ups, n_ups, &rows);

			upatch_table_emit_json(&e, rows, n_rows);
			xfree(rows, n_rows * sizeof(*rows));
		}
		json_obj_open_key(&e, "assets");
		json_kv_string(&e, "root", SHIRUDO_VAR_LIB);
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
		 * What the guards refused this boot, every counter by name
		 * so a collector's keys stay the same from one record to
		 * the next; null until init has pinned the map.
		 */
		if (tamper_rc == 0) {
			json_obj_open_key(&e, "tamper_attempts");
			json_kv_int(&e, "total", (__s64)tamper.total);
			json_obj_open_key(&e, "counters");
			for (i = 0; i < SHIRUDO_TAMPER_MAX; i++)
				json_kv_int(&e, tamper_name(i),
					    (__s64)tamper.count[i]);
			json_obj_close(&e);
			json_obj_close(&e);
		} else {
			json_kv_null(&e, "tamper_attempts");
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
			json_kv_int(&e, "pcr", SHIRUDO_CHAIN_PCR);
			json_kv_int(&e, "phase_pcr",
				    SHIRUDO_CHAIN_PHASE_PCR);
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
		if (include_kernel_log) {
			size_t bytes = (size_t)kernel_log_lines *
				       sizeof(struct shirudo_kmsg_record);
			struct shirudo_kmsg_record *recs = xmalloc(bytes);
			int nr = recs ? kmsg_tail(recs, kernel_log_lines)
				      : -ENOMEM;
			int j;

			json_arr_open(&e, "kernel_log");
			for (j = 0; j < nr; j++) {
				json_obj_open(&e);
				json_kv_string(&e, "ts", recs[j].ts);
				json_kv_string(&e, "msg", recs[j].msg);
				json_obj_close(&e);
			}
			json_arr_close(&e);
			xfree(recs, bytes);
		}
		if (include_modules) {
			struct shirudo_kmod_set ks = {};
			int mrc = kmodules_read(&ks);
			struct timespec rt = {}, bt = {};
			__s64 boot_sec = 0;
			char boot_iso[32] = "";
			size_t mi;

			if (clock_gettime(CLOCK_REALTIME, &rt) == 0 &&
			    clock_gettime(CLOCK_BOOTTIME, &bt) == 0) {
				boot_sec = (__s64)rt.tv_sec - bt.tv_sec;
				iso8601((time_t)boot_sec, boot_iso,
					sizeof(boot_iso));
			}
			json_kv_string(&e, "boot_at",
				       boot_iso[0] ? boot_iso : "");
			json_arr_open(&e, "modules");
			if (mrc == 0) {
				for (mi = 0; mi < ks.n; mi++) {
					const struct shirudo_kmod *m =
						&ks.mods[mi];
					time_t at = m->loaded_at_sec;
					char iso[32] = "";
					__u16 di;

					if (at > 0)
						iso8601(at, iso,
							sizeof(iso));
					json_obj_open(&e);
					json_kv_string(&e, "name",
						       m->name);
					json_kv_int(&e, "size",
						    (__s64)m->size);
					json_kv_int(&e, "refcount",
						    m->refcount);
					json_kv_string(&e, "loaded_at",
						       iso);
					if (boot_sec > 0 &&
					    m->loaded_at_sec >= boot_sec)
						json_kv_int(&e,
							    "since_boot_sec",
							    m->loaded_at_sec - boot_sec);
					else
						json_kv_null(&e,
							     "since_boot_sec");
					json_arr_open(&e, "deps");
					for (di = 0; di < m->n_deps; di++) {
						size_t dk = ks.deps[m->deps_off
								    + di];
						json_str(&e,
							 ks.mods[dk].name);
					}
					json_arr_close(&e);
					json_obj_close(&e);
				}
			}
			json_arr_close(&e);
			kmodules_free(&ks);
		}
		json_obj_close(&e);

		if (e.err) {
			fprintf(stderr, "status: json encode failed: %s\n",
				strerror(-e.err));
		} else {
			if (otel && otel_endpoint_configured) {
				__s64 refused = tamper_rc == 0 ?
						  (__s64)tamper.total : -1;
				const char *severity_text;
				int severity_number;
				int rc;

				severity_number = status_otel_severity(otel_status,
								       &severity_text);
				rc = otel_send_log_json(&otel_opts,
							"shirudo.keepalive",
							"shirudo.keepalive",
							severity_number,
							severity_text,
							otel_status,
							shirudo_version_id,
							refused, json_buf,
							strlen(json_buf));
				if (rc) {
					pr_err("status: OTEL export failed: %s",
					       strerror(-rc));
					ret = 1;
				}
			}
			if (json_stdout)
				printf("%s\n", json_buf);
		}
	} else {
		struct shirudo_conditions_input cin;
		struct shirudo_condition conds[SHIRUDO_CONDITIONS_MAX];
		struct shirudo_upatch_table_row *rows = NULL;
		size_t n_rows = 0;
		size_t nc;
		char hostname[256] = "?";
		char reason[160];
		const char *verdict;

		local_cond_input(&cin, lsm_attached, keyring_present,
				 keyring_mode,
				 lsm_attached && strcmp(keyring_mode, "bpf") != 0,
				 keyring_serial,
				 keyring_pinned >= 1 ? keyring_pinned : 0,
				 keyring_present, keyring_pinned >= 1,
				 keyring_present && keyring_pinned >= 1,
				 keyring_present && keyring_pinned >= 1 &&
				 keyring_serial == keyring_pinned,
				 cst.tpm, chain_rc == 0,
				 match == 1, match >= 0,
				 nv_index);
		verdict = status_verdict(&cin);
		status_reason(&cin, reason, sizeof(reason));
		nc = conditions(&cin, conds, ARRAY_SIZE(conds));
		n_rows = build_upatches_table(ups, n_ups, &rows);
		(void)gethostname(hostname, sizeof(hostname));
		hostname[sizeof(hostname) - 1] = '\0';

		printf("Host:              %s\n", hostname);
		printf("Roles:             %s\n",
		       roles_str(is_target, is_operator));
		if (!strcmp(mode, "staging"))
			printf("Mode:              STAGING (certificate in the "
			       "user keyring; boot with bpf.keyring_unsealed=1 "
			       "and run init from the initrd)\n");
		else
			printf("Mode:              %s\n", mode);
		if (reason[0])
			printf("Status:            %s  (%s)\n", verdict,
			       reason);
		else
			printf("Status:            %s\n", verdict);
		printf("Version-ID:        %s\n", shirudo_version_id);

		printf("\n");
		conditions_print(conds, nc);

		printf("\nTamper attempts (refused this boot):\n");
		if (tamper_rc == -ENOENT)
			printf("  (none recorded: init has not pinned the counters "
			       "this boot)\n");
		else if (tamper_rc)
			printf("  (unavailable: %s)\n", strerror(-tamper_rc));
		else if (tamper.total == 0)
			printf("  none\n");
		for (i = 0; tamper_rc == 0 && i < SHIRUDO_TAMPER_MAX; i++) {
			if (tamper.count[i])
				printf("  %-20s %6llu  %s\n",
				       tamper_name(i),
				       (__u64)tamper.count[i],
				       tamper_meaning(i));
		}

		printf("\nKeyring (%s):\n", !strcmp(keyring_mode, "bpf") ?
		       ".bpf" : SHIRUDO_KEYRING_NAME);
		if (keyring_present)
			printf("  %-22s %lld\n", "Serial:",
			       (__s64)keyring_serial);
		else if (keyring_pinned == -ENOENT)
			printf("  %-22s %s\n", "Serial:",
			       "absent  (operator host, or `shirudo init` "
			       "not yet run)");
		else if (keyring_serial == -ENOKEY)
			printf("  %-22s %s\n", "Serial:", "absent");
		else
			printf("  %-22s lookup error: %s\n", "Serial:",
			       strerror(-keyring_serial));
		if (keyring_pinned == -ENOENT)
			printf("  %-22s %s\n", "Frozen serial:",
			       "(none this boot)");
		else if (keyring_pinned < 0)
			printf("  %-22s unreadable: %s\n", "Frozen serial:",
			       strerror(-keyring_pinned));
		else
			printf("  %-22s %lld%s\n", "Frozen serial:",
			       (__s64)keyring_pinned, !keyring_present ?
			       "  (GONE -- removed?)" :
			       keyring_serial == keyring_pinned ?
			       "  (matches)" :
			       "  (MISMATCH -- swapped?)");
		if (certs_rc == 0) {
			printf("  %-22s %zu trusted, %zu revoked, %zu "
			       "unvouched", "Certificates:", certs.n,
			       certs.n_revoked, certs.n_unvouched);
			if (certs_enrolled >= 0)
				printf(", %d in the bpf keyring",
				       certs_enrolled);
			printf("\n");
			for (i = 0; i < (int)certs.n; i++) {
				char fp_hex[65];

				hex_encode(certs.certs[i].fingerprint,
					   32, fp_hex);
				printf("    %s%s\n", fp_hex,
				       certs.certs[i].primary ? "  (primary)" :
				       "");
			}
		}

		if (include_system) {
			print_system_human(&sysi);
			print_kernel_config_human(&sysi);
		}

		upatch_table_print(rows, n_rows);
		xfree(rows, n_rows * sizeof(*rows));
		rows = NULL;

		{
			printf("\nTPM Measurement:\n");
			printf("  %-18s %s (%s)\n", "TPM:",
			       cst.tpm ? "reachable" : "NOT reachable", tcti);
			printf("  %-18s %s (anchored in PCR %u)\n", "NV index:",
			       nv_index, SHIRUDO_CHAIN_PCR);
			if (chain_rc == 0) {
				printf("  %-18s %s\n", "Chain:", chain_hex);
				printf("  %-18s %s\n", "Register name:",
				       name_hex);
				printf("  %-18s %s\n", "Anchored:",
				       cst.anchored ? "yes (name on record)" :
				       "NO (index is not the one init bound)");
			} else if (!cst.tpm) {
				printf("  %-18s %s\n", "Chain:",
				       "unavailable (no TPM answered)");
			} else if (chain_rc == -ENODEV) {
				printf("  %-18s %s\n", "Chain:",
				       "unavailable (register not bound this "
				       "boot)");
			} else {
				printf("  %-18s unavailable (TPM error: %s)\n",
				       "Chain:", strerror(-chain_rc));
			}
			if (cst.logged) {
				printf("  %-18s %s\n", "PCR before init:",
				       pcr_before_hex);
				printf("  %-18s %s (PCR %u)\n", "Phase at init:",
				       phase_before_hex, SHIRUDO_CHAIN_PHASE_PCR);
				printf("  %-18s %s\n", "Bound in:",
				       cst.init.initrd ? "initrd" :
				       "root file system");
			}
			if (cst.rebound)
				printf("  %-18s %u for this TPM reset "
				       "(REBOUND after init; tamper?)\n",
				       "Init records:",
				       cst.init.records_epoch);
			printf("  %-18s %s\n", "Chain vs eventlog:",
			       match < 0 ? "n/a" :
			       match ? "matches" : "MISMATCH (tamper?)");
			if (ev_rc == 0)
				printf("  %-18s %s  (%ld entries, %ld bytes)\n",
				       "Eventlog:", eventlog_path(),
				       ev_entries, ev_bytes);
			else
				printf("  %-18s absent\n", "Eventlog:");
		}

		if (include_eventlog)
			print_eventlog_table();

		printf("\nAssets (%s):\n", SHIRUDO_VAR_LIB);
		printf("  %-22s %s\n", "keys/cert.der",
		       assets.cert ? "present" : "absent");
		printf("  %-22s %s\n", "keys/signing_key.pem",
		       assets.signing_key ? "present" : "absent");
		if (assets.eventlog)
			printf("  %-22s present (%ld bytes)\n", "eventlog",
			       assets.eventlog_bytes);
		else
			printf("  %-22s absent\n", "eventlog");
		if (assets.n_upatches < 0)
			printf("  %-22s absent\n", "upatches/");
		else
			printf("  %-22s %d .upatch\n", "upatches/",
			       assets.n_upatches);
		if (assets.n_incoming < 0)
			printf("  %-22s absent\n", "incoming/");
		else if (assets.n_incoming == 0)
			printf("  %-22s empty\n", "incoming/");
		else
			printf("  %-22s %d staged\n", "incoming/",
			       assets.n_incoming);
		printf("  %-22s %s\n", "bpffs/",
		       assets.bpffs_mounted ? "mounted" : "not mounted");

		if (include_kernel_log) {
			size_t bytes = (size_t)kernel_log_lines *
				       sizeof(struct shirudo_kmsg_record);
			struct shirudo_kmsg_record *recs = xmalloc(bytes);
			int nr = recs ? kmsg_tail(recs, kernel_log_lines)
				      : -ENOMEM;
			int j;

			printf("\nKernel log (last %u lines, newest first):\n",
			       kernel_log_lines);
			if (nr <= 0) {
				printf("  (unavailable)\n");
			} else {
				for (j = nr; j-- > 0;)
					printf("  [%s]  %s\n", recs[j].ts,
					       recs[j].msg);
			}
			xfree(recs, bytes);
		}
		if (include_modules) {
			struct shirudo_kmod_set ks = {};
			int mrc = kmodules_read(&ks);
			struct timespec rt = {}, bt = {};
			__s64 boot_sec = 0;
			size_t last = 10;
			size_t shown = ks.n < last ? ks.n : last;

			if (clock_gettime(CLOCK_REALTIME, &rt) == 0 &&
			    clock_gettime(CLOCK_BOOTTIME, &bt) == 0)
				boot_sec = (__s64)rt.tv_sec - bt.tv_sec;

			if (mrc != 0) {
				printf("\nLoaded modules:\n");
				printf("  (unavailable: %s)\n", strerror(-mrc));
			} else {
				printf("\nLoaded modules (total %zu, "
				       "last %zu loads, newest first):\n",
				       ks.n, shown);
				kmodules_print_recent(&ks, last,
						      boot_sec);
				if (!show_full) {
					printf("  (Use --show-full to show "
					       "all loaded modules in a "
					       "dependency tree)\n");
				} else {
					printf("\nDependency tree:\n");
					kmodules_print_tree(&ks);
				}
			}
			kmodules_free(&ks);
		}
	}

out:
	for (i = 0; i < n_ups; i++)
		libc_free(ups[i]);
	libc_free(ups);
	if (json_buf)
		xfree(json_buf, json_cap);
	return ret;
}
