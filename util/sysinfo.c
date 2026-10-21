// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Host system overview from /proc, /etc and uname(2). No subprocess.
 */

#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "json.h"
#include "kernel_build_id.h"
#include "malloc.h"
#include "sysinfo.h"

static void read_first_line(const char *path, char *buf, size_t cap)
{
	ssize_t n;
	int fd;

	buf[0] = '\0';
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	n = read(fd, buf, cap - 1);
	close(fd);
	if (n <= 0) {
		buf[0] = '\0';
		return;
	}
	buf[n] = '\0';
	buf[strcspn(buf, "\r\n")] = '\0';
}

static void read_os_pretty(char *buf, size_t cap)
{
	char line[512];
	FILE *f;

	buf[0] = '\0';
	f = fopen("/etc/os-release", "re");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		const char *v;
		size_t len;

		if (strncmp(line, "PRETTY_NAME=", 12) != 0)
			continue;
		v = line + 12;
		if (*v == '"')
			v++;
		snprintf(buf, cap, "%.*s", (int)(cap - 1), v);
		len = strlen(buf);
		while (len && (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
			       buf[len - 1] == '"'))
			buf[--len] = '\0';
		break;
	}
	fclose(f);
}

/* /proc/uptime holds the seconds since boot, with a fraction. */
static long read_uptime_sec(void)
{
	char buf[64];
	ssize_t n;
	__u64 sec;
	int fd;

	fd = open("/proc/uptime", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	if (parse_u64(buf, digits(buf, (size_t)n), LONG_MAX, &sec))
		return -1;
	return (long)sec;
}

static void read_mem(long *total_kb, long *avail_kb)
{
	char line[256];
	FILE *f;

	*total_kb = -1;
	*avail_kb = -1;
	f = fopen("/proc/meminfo", "re");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		long kb;

		if (*total_kb < 0 &&
		    sscanf(line, "MemTotal: %ld kB", &kb) == 1)
			*total_kb = kb;
		else if (*avail_kb < 0 &&
			 sscanf(line, "MemAvailable: %ld kB", &kb) == 1)
			*avail_kb = kb;
		if (*total_kb >= 0 && *avail_kb >= 0)
			break;
	}
	fclose(f);
}

static void read_root_disk(long *total_kb, long *used_kb)
{
	struct statvfs s;
	__u64 tot_b, free_b;

	*total_kb = -1;
	*used_kb = -1;
	if (statvfs("/", &s) != 0)
		return;
	/*
	 * f_frsize is the fragment size statvfs reports its block counts
	 * against; tot/used in raw bytes, then KiB so the JSON wire type
	 * matches mem_*_kb.
	 */
	tot_b  = (__u64)s.f_blocks * s.f_frsize;
	free_b = (__u64)s.f_bfree     * s.f_frsize;
	*total_kb = (long)(tot_b / 1024);
	*used_kb  = (long)((tot_b - free_b) / 1024);
}

static char *trim_config_text(char *text)
{
	char *end;

	while (*text && isspace((__u8)*text))
		text++;
	end = text + strlen(text);
	while (end > text && isspace((__u8)end[-1]))
		*--end = '\0';
	return text;
}

struct kernel_config_entry {
	char *key;
	char *value;
};

static int kernel_config_entry_cmp(const void *a, const void *b)
{
	const struct kernel_config_entry *ea = a;
	const struct kernel_config_entry *eb = b;

	return strcmp(ea->key, eb->key);
}

static void kernel_config_entries_free(struct kernel_config_entry *entries,
				       size_t n, size_t cap)
{
	size_t i;

	for (i = 0; i < n; i++) {
		xstrfree(entries[i].key);
		xstrfree(entries[i].value);
	}
	xfree(entries, cap * sizeof(*entries));
}

int sysinfo_kernel_config_foreach(const char *kernel_release,
				  shirudo_kernel_config_cb cb,
				  void *ctx)
{
	char path[PATH_MAX];
	char line[8192];
	struct kernel_config_entry *entries = NULL;
	size_t n = 0, cap = 0;
	FILE *f;
	size_t i;

	if (!kernel_release || !kernel_release[0] || !cb ||
	    strsprintf(path, sizeof(path), "/boot/config-%s", kernel_release) < 0)
		return -1;
	f = fopen(path, "re");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char *key, *value, *eq, *not_set;

		line[strcspn(line, "\r\n")] = '\0';
		key = trim_config_text(line);
		if (!*key)
			continue;

		if (strncmp(key, "# CONFIG_", 9) == 0) {
			key += 2;
			not_set = strstr(key, " is not set");
			if (!not_set || trim_config_text(not_set + 11)[0] != '\0')
				continue;
			*not_set = '\0';
			value = "n";
		} else {
			eq = strchr(key, '=');
			if (!eq)
				continue;
			*eq = '\0';
			key = trim_config_text(key);
			if (strncmp(key, "CONFIG_", 7) != 0 || !key[7])
				continue;
			value = trim_config_text(eq + 1);
			{
				size_t len = strlen(value);

				if (len >= 2 && value[0] == '"' && value[len - 1] == '"') {
					value[len - 1] = '\0';
					value++;
				}
			}
		}
		if (strncmp(key, "CONFIG_", 7) != 0 || !key[7])
			continue;
		if (n == cap) {
			struct kernel_config_entry *next;
			size_t grown = cap ? 2 * cap : 256;

			next = xreallocarray(entries, cap, grown,
					     sizeof(*entries));
			if (!next) {
				fclose(f);
				kernel_config_entries_free(entries, n, cap);
				return -1;
			}
			entries = next;
			cap = grown;
		}
		entries[n].key = xstrdup(key);
		entries[n].value = xstrdup(value);
		if (!entries[n].key || !entries[n].value) {
			xstrfree(entries[n].key);
			xstrfree(entries[n].value);
			entries[n].key = NULL;
			entries[n].value = NULL;
			fclose(f);
			kernel_config_entries_free(entries, n + 1, cap);
			return -1;
		}
		n++;
	}
	fclose(f);

	if (n)
		qsort(entries, n, sizeof(*entries), kernel_config_entry_cmp);
	for (i = 0; i < n; i++)
		cb(ctx, entries[i].key, entries[i].value);
	kernel_config_entries_free(entries, n, cap);
	return (int)n;
}

static void emit_kernel_config_entry(void *ctx, const char *key,
				     const char *value)
{
	json_kv_string(ctx, key, value);
}

static void emit_kernel_config(struct shirudo_json_emit *e,
			       const char *kernel_release)
{
	json_obj_open_key(e, "kernel_config");
	sysinfo_kernel_config_foreach(kernel_release,
				      emit_kernel_config_entry, e);

	json_obj_close(e);
}

void sysinfo_gather(struct shirudo_sysinfo *si)
{
	struct utsname u;

	*si = (struct shirudo_sysinfo){};
	si->nproc = -1;
	si->mem_total_kb = -1;
	si->mem_avail_kb = -1;
	si->uptime_sec = -1;
	si->disk_total_kb = -1;
	si->disk_used_kb = -1;

	if (gethostname(si->hostname, sizeof(si->hostname)) != 0)
		si->hostname[0] = '\0';
	si->hostname[sizeof(si->hostname) - 1] = '\0';

	if (uname(&u) == 0) {
		strscpy(si->kernel_release, u.release,
			sizeof(si->kernel_release));
		strscpy(si->kernel_version, u.version,
			sizeof(si->kernel_version));
		strscpy(si->machine, u.machine, sizeof(si->machine));
		if (si->hostname[0] == '\0')
			strscpy(si->hostname, u.nodename,
				sizeof(si->hostname));
	}

	read_os_pretty(si->os_pretty, sizeof(si->os_pretty));
	read_first_line("/etc/machine-id", si->machine_id,
			sizeof(si->machine_id));
	read_first_line("/proc/sys/kernel/random/boot_id", si->boot_id,
			sizeof(si->boot_id));
	(void)kernel_build_id_read(si->kernel_build_id);

	si->nproc = sysconf(_SC_NPROCESSORS_ONLN);
	read_mem(&si->mem_total_kb, &si->mem_avail_kb);
	read_root_disk(&si->disk_total_kb, &si->disk_used_kb);
	si->uptime_sec = read_uptime_sec();
}

void sysinfo_emit_json(struct shirudo_json_emit *e,
		       const struct shirudo_sysinfo *si)
{
	json_obj_open_key(e, "system");
	json_kv_string(e, "hostname", si->hostname);
	json_kv_string(e, "os", si->os_pretty);
	json_kv_string(e, "kernel_release", si->kernel_release);
	json_kv_string(e, "kernel_version", si->kernel_version);
	json_kv_string(e, "kernel_build_id", si->kernel_build_id);
	emit_kernel_config(e, si->kernel_release);
	json_kv_string(e, "architecture", si->machine);
	json_kv_string(e, "machine_id", si->machine_id);
	json_kv_string(e, "boot_id", si->boot_id);
	json_kv_int(e, "nproc", si->nproc);
	json_kv_int(e, "mem_total_kb", si->mem_total_kb);
	json_kv_int(e, "mem_avail_kb", si->mem_avail_kb);
	json_kv_int(e, "disk_total_kb", si->disk_total_kb);
	json_kv_int(e, "disk_used_kb", si->disk_used_kb);
	json_kv_int(e, "uptime_seconds", si->uptime_sec);
	json_obj_close(e);
}
