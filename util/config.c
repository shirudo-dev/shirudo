// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Minimal shirudo.conf reader: `key = value` lines, '#' comments,
 * dotted keys. No third-party parser -- the config surface is tiny.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "config.h"
#include "hex.h"
#include "io.h"
#include "malloc.h"
#include "json.h"
#include "image_config.h"
#include "log.h"
#include "paths.h"

static char *trim(char *s)
{
	char *e;

	while (*s == ' ' || *s == '\t')
		s++;
	e = s + strlen(s);
	while (e > s && (e[-1] == ' ' || e[-1] == '\t' ||
			 e[-1] == '\n' || e[-1] == '\r'))
		*--e = '\0';
	return s;
}

static void map_export_bad(struct config *cfg, const char *key,
			   const char *val, const char *reason)
{
	cfg->map_export_valid = false;
	pr_warn("config: %s: bad value '%s' (%s)", key, val, reason);
}

static bool parse_bool(const char *val, bool *out)
{
	if (strcmp(val, "true") == 0) {
		*out = true;
		return true;
	}
	if (strcmp(val, "false") == 0) {
		*out = false;
		return true;
	}
	return false;
}

static __must_check bool set_string(char *dst, size_t cap, const char *val)
{
	return strscpy(dst, val, cap) >= 0;
}

/* An ignored value must leave the one set before intact. */
static bool set_tcti(struct config *cfg, const char *val)
{
	char tcti[sizeof(cfg->tpm_tcti)];
	ssize_t len = strscpy(tcti, val, sizeof(tcti));

	if (len < 0)
		return false;
	memcpy(cfg->tpm_tcti, tcti, len + 1);
	return true;
}

static bool tls_classical_hosts_valid(const char *value)
{
	const char *host = value;

	if (!*value)
		return true;
	while (*host) {
		const char *end = strchr(host, ',');
		size_t len = end ? (size_t)(end - host) : strlen(host);
		char name[254];

		if (!len || len >= sizeof(name))
			return false;
		memcpy(name, host, len);
		name[len] = '\0';
		if (!dns_name_valid(name))
			return false;
		if (!end)
			break;
		host = end + 1;
		if (!*host)
			return false;
	}
	return true;
}

static void config_defaults(struct config *cfg)
{
	*cfg = (struct config){};
	cfg->map_export_valid = true;
	cfg->tls_classical_hosts_valid = true;
	cfg->map_export_otel_retries = 3;
	cfg->map_export_log_record_max_bytes = MAP_EXPORT_LOG_RECORD_MAX_DEFAULT;
	cfg->map_export_otlp_max_bytes = MAP_EXPORT_OTLP_MAX_DEFAULT;
}

/*
 * Owner auth is a literal passphrase, or "hex:<even hex>" for a binary
 * auth value (what provisioning tools that randomise owner auth emit).
 */
static void set_owner_auth(struct config *cfg, const char *val)
{
	size_t l;

	if (str_skip_prefix(&val, "hex:")) {
		__u8 auth[sizeof(cfg->tpm_owner_auth)];
		size_t n;

		/* An ignored value must leave the one set before intact. */
		if (!hex_decode_max(val, auth, sizeof(auth), &n)) {
			memcpy(cfg->tpm_owner_auth, auth, n);
			cfg->tpm_owner_auth_len = n;
		} else {
			pr_warn("config: tpm.owner_auth: not an even count of up to %zu hex digits (ignored)",
				2 * sizeof(auth));
		}
		memzero_explicit(auth, sizeof(auth));
		return;
	}

	l = strlen(val);
	if (l > sizeof(cfg->tpm_owner_auth)) {
		pr_warn("config: tpm.owner_auth too long (ignored)");
		return;
	}
	memcpy(cfg->tpm_owner_auth, val, l);
	cfg->tpm_owner_auth_len = l;
}

/*
 * The stream, which passed check_trusted(), is consumed and closed; the
 * file is named for the log.
 */
static int config_parse(struct config *cfg, FILE *f,
			const char *path)
{
	const size_t max = MAP_EXPORT_PATH_MAX + 127;
	char buffer[BUFSIZ];
	size_t capacity = 0;
	char *line = NULL;
	int got, ret = 0;

	/* stdio's own buffer would keep the owner's authorization after fclose(). */
	setvbuf(f, buffer, _IOFBF, sizeof(buffer));
	while ((got = read_text_line(f, &line, &capacity, max)) != 0) {
		char *p, *eq, *key, *val;

		if (got == -E2BIG) {
			pr_warn("config: line longer than %zu bytes (ignored)",
				max);
			continue;
		}
		if (got < 0) {
			pr_err("config: %s: unreadable line: %s", path,
			       strerror(-got));
			ret = got;
			break;
		}
		p = trim(line);
		if (*p == '\0' || *p == '#')
			continue;
		eq = strchr(p, '=');
		if (!eq)
			continue;
		*eq = '\0';
		key = trim(p);
		val = trim(eq + 1);
		if (strcmp(key, "eventlog.max_bytes") == 0) {
			__u64 v;

			if (parse_u64(val, strlen(val), UINT64_MAX, &v))
				pr_warn("config: eventlog.max_bytes: "
					"bad value '%s' (ignored)", val);
			else
				cfg->eventlog_max_bytes = v;
		} else if (strcmp(key, "tpm.owner_auth") == 0) {
			set_owner_auth(cfg, val);
		} else if (strcmp(key, "tpm.tcti") == 0) {
			if (!set_tcti(cfg, val))
				pr_warn("config: tpm.tcti too long (ignored)");
		} else if (strcmp(key, "tls.classical_hosts") == 0) {
			if (!set_string(cfg->tls_classical_hosts,
					sizeof(cfg->tls_classical_hosts), val) ||
			    !tls_classical_hosts_valid(val)) {
				cfg->tls_classical_hosts_valid = false;
				pr_warn("config: tls.classical_hosts: invalid exact "
					"DNS host list");
			}
		} else if (strcmp(key, "map_export.json_path") == 0) {
			if (!set_string(cfg->map_export_json_path,
					sizeof(cfg->map_export_json_path), val))
				map_export_bad(cfg, key, val, "value too long");
			else if (val[0] && val[0] != '/')
				map_export_bad(cfg, key, val,
					       "path must be absolute");
		} else if (strcmp(key, "map_export.otel_endpoint") == 0) {
			if (!set_string(cfg->map_export_otel_endpoint,
					sizeof(cfg->map_export_otel_endpoint), val))
				map_export_bad(cfg, key, val, "value too long");
		} else if (strcmp(key, "map_export.tenant_id") == 0) {
			if (val[0] && !tenant_id_valid(val))
				map_export_bad(cfg, key, val,
					       "expected 1..128 characters from "
					       "A-Z, a-z, 0-9, '.', '_', '-'");
			else if (!set_string(cfg->map_export_tenant_id,
					     sizeof(cfg->map_export_tenant_id),
					     val))
				map_export_bad(cfg, key, val, "value too long");
		} else if (strcmp(key, "map_export.otel_insecure") == 0) {
			if (!parse_bool(val,
					&cfg->map_export_otel_insecure))
				map_export_bad(cfg, key, val,
					       "expected true or false");
		} else if (strcmp(key, "map_export.otel_retries") == 0) {
			__u64 v;

			if (parse_u64(val, strlen(val), 10, &v))
				map_export_bad(cfg, key, val,
					       "expected 0..10");
			else
				cfg->map_export_otel_retries =
					(__u32)v;
		} else if (strcmp(key, "map_export.s3_uri") == 0) {
			if (!set_string(cfg->map_export_s3_uri,
					sizeof(cfg->map_export_s3_uri), val))
				map_export_bad(cfg, key, val, "value too long");
		} else if (strcmp(key, "map_export.log_record_max_bytes") == 0 ||
			   strcmp(key, "map_export.otlp_max_bytes") == 0) {
			__u64 v;

			if (parse_u64(val, strlen(val), JSON_MAX_BYTES,
				      &v) || v == 0)
				map_export_bad(cfg, key, val, "expected 1..8388608 bytes");
			else if (strcmp(key, "map_export.log_record_max_bytes") == 0)
				cfg->map_export_log_record_max_bytes = (__u32)v;
			else
				cfg->map_export_otlp_max_bytes = (__u32)v;
		} else if (str_has_prefix(key, "config.") ||
			   str_has_prefix(key, "runtime.") ||
			   str_has_prefix(key, "enforcement.")) {
			continue;
		} else {
			if (str_has_prefix(key, "map_export.")) {
				map_export_bad(cfg, key, val, "unknown key");
			} else if (str_has_prefix(key, "tls.")) {
				cfg->tls_classical_hosts_valid = false;
				pr_warn("config: %s: unknown TLS setting", key);
			} else {
				pr_warn("config: unknown key '%s' (ignored)",
					key);
			}
		}
	}
	if (ferror(f) && !ret)
		ret = -EIO;
	/* The TPM owner's authorization is for no other user's eyes. */
	if (cfg->tpm_owner_auth_len && check_secret(fileno(f), path)) {
		memzero_explicit(cfg->tpm_owner_auth,
				 sizeof(cfg->tpm_owner_auth));
		cfg->tpm_owner_auth_len = 0;
		ret = -EPERM;
	}
	if (line) {
		/* The owner's authorization may have been read into it. */
		memzero_explicit(line, capacity);
		libc_free(line);
	}
	if (fclose(f) && !ret)
		ret = -errno;
	memzero_explicit(buffer, sizeof(buffer));
	return ret;
}

void config_clear(struct config *cfg)
{
	memzero_explicit(cfg, sizeof(*cfg));
}

static int config_finish(struct config *cfg, int ret)
{
	if (cfg->map_export_s3_uri[0] && !cfg->map_export_otel_endpoint[0])
		map_export_bad(cfg, "map_export.s3_uri", "",
			       "requires map_export.otel_endpoint for its reference event");
	if (cfg->map_export_log_record_max_bytes > cfg->map_export_otlp_max_bytes)
		map_export_bad(cfg, "map_export.log_record_max_bytes", "",
			       "must not exceed otlp_max_bytes");
	return ret;
}

/* The settings at path, or 0 with none there. */
static int config_read(struct config *cfg, const char *path)
{
	int fd, ret;
	FILE *f;

	fd = open_trusted(path, O_RDONLY);
	if (fd < 0)
		return fd == -ENOENT ? 0 : fd;
	f = fdopen(fd, "r");
	if (!f) {
		ret = -errno;
		close(fd);
		return ret;
	}
	return config_parse(cfg, f, path);
}

int config_load_path(struct config *cfg, const char *path)
{
	if (!cfg || !path)
		return -EINVAL;
	config_defaults(cfg);
	return config_finish(cfg, config_read(cfg, path));
}

/* A copy of the descriptor is read from its start; the caller keeps its own. */
int config_load_fd(struct config *cfg, int fd, const char *label)
{
	int copy, ret;
	FILE *f;

	if (!cfg || fd < 0)
		return -EINVAL;
	config_defaults(cfg);
	copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
	if (copy < 0)
		return -errno;
	if (lseek(copy, 0, SEEK_SET) < 0) {
		ret = -errno;
		close(copy);
		return ret;
	}
	ret = check_trusted(copy, label);
	if (ret) {
		close(copy);
		return config_finish(cfg, -EPERM);
	}
	f = fdopen(copy, "r");
	if (!f) {
		ret = -errno;
		close(copy);
		return ret;
	}
	return config_finish(cfg, config_parse(cfg, f, label));
}

int config_load(struct config *cfg)
{
	const char *env;
	int ret;

	if (image_config_get(cfg))
		return 0;
	ret = config_load_path(cfg, CONF_PATH);
	if (ret && ret != -ENOENT)
		return ret;

	/* Env override (handy for tests / not persisting a secret to disk). */
	env = getenv("SHIRUDO_TPM_OWNER_AUTH");
	if (env)
		set_owner_auth(cfg, env);

	/*
	 * The env wins over the file, as in util/tpm.c, so one dev run can
	 * point at swtpm while the file is shared.
	 */
	env = getenv("SHIRUDO_TPM_TCTI");
	if (env && *env && !set_tcti(cfg, env))
		pr_warn("SHIRUDO_TPM_TCTI too long (ignored)");

	return ret == -ENOENT ? 0 : ret;
}
