// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Minimal shirudo.conf reader: `key = value` lines, '#' comments,
 * dotted keys. No third-party parser -- the config surface is tiny.
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "config.h"
#include "hex.h"
#include "io.h"
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

static void map_export_bad(struct shirudo_config *cfg, const char *key,
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

static bool set_string(char *dst, size_t cap, const char *val)
{
	return strscpy(dst, val, cap) >= 0;
}

static bool numeric_dns_label(const char *label, size_t len)
{
	size_t i = 0;
	bool hex = len > 2 && label[0] == '0' &&
		   (label[1] == 'x' || label[1] == 'X');

	if (!len)
		return false;
	if (hex)
		i = 2;
	for (; i < len; i++) {
		__u8 c = label[i];

		if (c >= '0' && c <= '9')
			continue;
		if (hex && ((c >= 'a' && c <= 'f') ||
			    (c >= 'A' && c <= 'F')))
			continue;
		return false;
	}
	return !hex || i > 2;
}

static bool tls_dns_name_valid(const char *name)
{
	size_t len = strlen(name), label_len = 0, label_start = 0;
	bool numeric_address = true;
	size_t i;

	if (!len || len > 253)
		return false;
	for (i = 0; i < len; i++) {
		__u8 c = name[i];

		if (c == '.') {
			if (!label_len || label_len > 63 || name[i - 1] == '-')
				return false;
			if (!numeric_dns_label(name + label_start, label_len))
				numeric_address = false;
			label_start = i + 1;
			label_len = 0;
			continue;
		}
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '-') ||
		    (!label_len && c == '-'))
			return false;
		label_len++;
	}
	if (!label_len || label_len > 63 || name[len - 1] == '-')
		return false;
	if (!numeric_dns_label(name + label_start, label_len))
		numeric_address = false;
	return !numeric_address;
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
		if (!tls_dns_name_valid(name))
			return false;
		if (!end)
			break;
		host = end + 1;
		if (!*host)
			return false;
	}
	return true;
}

static void config_defaults(struct shirudo_config *cfg)
{
	*cfg = (struct shirudo_config){};
	cfg->map_export_valid = true;
	cfg->tls_classical_hosts_valid = true;
	cfg->map_export_otel_retries = 3;
	cfg->map_export_log_record_max_bytes = SHIRUDO_MAP_EXPORT_LOG_RECORD_MAX_DEFAULT;
	cfg->map_export_otlp_max_bytes = SHIRUDO_MAP_EXPORT_OTLP_MAX_DEFAULT;
}

/*
 * Owner auth is a literal passphrase, or "hex:<even hex>" for a binary
 * auth value (what provisioning tools that randomise owner auth emit).
 */
static void set_owner_auth(struct shirudo_config *cfg, const char *val)
{
	size_t l;

	if (strncmp(val, "hex:", 4) == 0) {
		char auth[sizeof(cfg->tpm_owner_auth)];
		const char *h = val + 4;
		size_t hl = strlen(h), i;

		if (hl % 2 || hl / 2 > sizeof(cfg->tpm_owner_auth)) {
			pr_warn("config: tpm.owner_auth: bad hex length "
				"(ignored)");
			return;
		}
		/* An ignored value must leave the one set before intact. */
		for (i = 0; i < hl / 2; i++) {
			int hi = hex_nibble(h[2 * i]);
			int lo = hex_nibble(h[2 * i + 1]);

			if (hi < 0 || lo < 0) {
				pr_warn("config: tpm.owner_auth: bad hex "
					"(ignored)");
				explicit_bzero(auth, sizeof(auth));
				return;
			}
			auth[i] = (char)((hi << 4) | lo);
		}
		memcpy(cfg->tpm_owner_auth, auth, hl / 2);
		cfg->tpm_owner_auth_len = hl / 2;
		explicit_bzero(auth, sizeof(auth));
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

int config_load_path(struct shirudo_config *cfg, const char *path)
{
	char line[SHIRUDO_MAP_EXPORT_PATH_MAX + 128];
	int rc = 0;
	FILE *f;

	if (!cfg || !path)
		return -EINVAL;
	config_defaults(cfg);

	f = fopen(path, "r");
	if (!f) {
		if (errno != ENOENT)
			rc = -errno;	/* still apply env override below */
	} else if (check_trusted(fileno(f), path, false)) {
		fclose(f);
		return -EPERM;
	} else {
		while (fgets(line, sizeof(line), f)) {
			char *p, *eq, *key, *val;
			int c;

			/* Never take a line the buffer cut short. */
			if (!strchr(line, '\n') && !feof(f)) {
				pr_warn("config: line longer than %zu bytes "
					"(ignored)", sizeof(line) - 1);
				while ((c = fgetc(f)) != EOF && c != '\n')
					continue;
				continue;
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
				if (strlen(val) >= sizeof(cfg->tpm_tcti))
					pr_warn("config: tpm.tcti too long "
						"(ignored)");
				else
					strscpy(cfg->tpm_tcti, val,
						sizeof(cfg->tpm_tcti));
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
				else
					(void)set_string(cfg->map_export_tenant_id,
							 sizeof(cfg->map_export_tenant_id),
							 val);
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

				if (parse_u64(val, strlen(val), SHIRUDO_JSON_MAX_BYTES,
					      &v) || v == 0)
					map_export_bad(cfg, key, val, "expected 1..8388608 bytes");
				else if (strcmp(key, "map_export.log_record_max_bytes") == 0)
					cfg->map_export_log_record_max_bytes = (__u32)v;
				else
					cfg->map_export_otlp_max_bytes = (__u32)v;
			} else if (!strncmp(key, "config.", 7) ||
				   !strncmp(key, "runtime.", 8)) {
				continue;
			} else {
				if (strncmp(key, "map_export.", 11) == 0)
					map_export_bad(cfg, key, val, "unknown key");
				else if (strncmp(key, "tls.", 4) == 0) {
					cfg->tls_classical_hosts_valid = false;
					pr_warn("config: %s: unknown TLS setting", key);
				} else {
					pr_warn("config: unknown key '%s' (ignored)",
						key);
				}
			}
		}
		if (ferror(f) && !rc)
			rc = -EIO;
		/* The TPM owner's authorization is for no other user's eyes. */
		if (cfg->tpm_owner_auth_len &&
		    check_trusted(fileno(f), path, true)) {
			explicit_bzero(cfg->tpm_owner_auth,
				       sizeof(cfg->tpm_owner_auth));
			cfg->tpm_owner_auth_len = 0;
			rc = -EPERM;
		}
		if (fclose(f) && !rc)
			rc = -errno;
	}
	if (cfg->map_export_s3_uri[0] && !cfg->map_export_otel_endpoint[0])
		map_export_bad(cfg, "map_export.s3_uri", "",
			       "requires map_export.otel_endpoint for its reference event");
	if (cfg->map_export_log_record_max_bytes > cfg->map_export_otlp_max_bytes)
		map_export_bad(cfg, "map_export.log_record_max_bytes", "",
			       "must not exceed otlp_max_bytes");
	return rc;
}

int config_load(struct shirudo_config *cfg)
{
	const char *env;
	int rc;

	if (shirudo_image_config_get(cfg))
		return 0;
	rc = config_load_path(cfg, SHIRUDO_CONF_PATH);
	if (rc && rc != -ENOENT)
		return rc;

	/* Env override (handy for tests / not persisting a secret to disk). */
	env = getenv("SHIRUDO_TPM_OWNER_AUTH");
	if (env)
		set_owner_auth(cfg, env);

	/*
	 * The env wins over the file, as in util/tpm.c, so one dev run can
	 * point at swtpm while the file is shared.
	 */
	env = getenv("SHIRUDO_TPM_TCTI");
	if (env && *env) {
		if (strlen(env) < sizeof(cfg->tpm_tcti))
			strscpy(cfg->tpm_tcti, env, sizeof(cfg->tpm_tcti));
		else
			pr_warn("SHIRUDO_TPM_TCTI too long (ignored)");
	}

	return rc == -ENOENT ? 0 : rc;
}
