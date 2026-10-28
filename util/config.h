/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * /etc/shirudo/shirudo.conf reader.
 */

#ifndef SHIRUDO_CONFIG_H
#define SHIRUDO_CONFIG_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/misc.h>

#include "tenant_id.h"

#define SHIRUDO_OWNER_AUTH_MAX	256
#define SHIRUDO_TPM_TCTI_MAX	256
#define SHIRUDO_TLS_HOSTS_MAX	1024
#define SHIRUDO_MAP_EXPORT_PATH_MAX	4096
#define SHIRUDO_MAP_EXPORT_ENDPOINT_MAX	2048
#define SHIRUDO_MAP_EXPORT_URI_MAX	2048
#define SHIRUDO_MAP_EXPORT_LOG_RECORD_MAX_DEFAULT	(1u * 1024u * 1024u)
#define SHIRUDO_MAP_EXPORT_OTLP_MAX_DEFAULT		(4u * 1024u * 1024u)

struct shirudo_config {
	__u64		eventlog_max_bytes;	/* 0 = unlimited */
	/*
	 * Owner-hierarchy auth used to define the NV index on TPMs whose
	 * owner auth is set. Empty (len 0) = empty-password session.
	 */
	char		tpm_owner_auth[SHIRUDO_OWNER_AUTH_MAX];
	size_t		tpm_owner_auth_len;
	/*
	 * The TCTI of util/tpm.c, empty for /dev/tpmrm0; the environment
	 * overrides it.
	 */
	char		tpm_tcti[SHIRUDO_TPM_TCTI_MAX];
	/* Exact DNS names that may negotiate classical TLS key exchange. */
	bool		tls_classical_hosts_valid;
	char		tls_classical_hosts[SHIRUDO_TLS_HOSTS_MAX];
	/* Empty sinks are idle. */
	bool		map_export_valid;
	char		map_export_json_path[SHIRUDO_MAP_EXPORT_PATH_MAX];
	char		map_export_otel_endpoint[SHIRUDO_MAP_EXPORT_ENDPOINT_MAX];
	char		map_export_tenant_id[SHIRUDO_TENANT_ID_MAX + 1];
	bool		map_export_otel_insecure;
	__u32		map_export_otel_retries;
	char		map_export_s3_uri[SHIRUDO_MAP_EXPORT_URI_MAX];
	__u32		map_export_log_record_max_bytes;
	__u32		map_export_otlp_max_bytes;
};

/* A missing file is not an error. */
int config_load(struct shirudo_config *cfg);

/* Testable path-specific loader; unlike config_load(), no env. */
int config_load_path(struct shirudo_config *cfg, const char *path);

#endif /* SHIRUDO_CONFIG_H */
