// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Focused tests for map_export.* configuration parsing.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util/config.h"
#include "util/io.h"

static int write_config(const char *path, const char *contents)
{
	int fd, rc;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -errno;
	rc = write_complete(fd, contents, strlen(contents));
	if (rc) {
		close(fd);
		return rc;
	}
	return close(fd) == 0 ? 0 : -errno;
}

static int check_defaults(const char *path)
{
	struct shirudo_config cfg;

	unlink(path);
	if (config_load_path(&cfg, path) != 0)
		return 1;
	return !cfg.map_export_valid || cfg.map_export_json_path[0] ||
	       cfg.map_export_tenant_id[0] ||
	       cfg.map_export_otel_retries != 3 ||
	       cfg.map_export_log_record_max_bytes !=
			SHIRUDO_MAP_EXPORT_LOG_RECORD_MAX_DEFAULT ||
	       cfg.map_export_otlp_max_bytes !=
			SHIRUDO_MAP_EXPORT_OTLP_MAX_DEFAULT;
}

static int check_valid(const char *path)
{
	static const char input[] =
		"map_export.json_path = /var/log/shirudo/maps.ndjson\n"
		"map_export.otel_endpoint = https://collector.example:4318\n"
		"map_export.tenant_id = tenant-uuid-1234\n"
		"map_export.otel_insecure = true\n"
		"map_export.otel_retries = 7\n"
		"map_export.s3_uri = s3://bucket/prefix\n"
		"map_export.log_record_max_bytes = 1024\n"
		"map_export.otlp_max_bytes = 2048\n"
		"map_export.s3_uri = s3://bucket/prefix\n";
	struct shirudo_config cfg;

	if (write_config(path, input) != 0 ||
	    config_load_path(&cfg, path) != 0)
		return 1;
	return !cfg.map_export_valid ||
	       strcmp(cfg.map_export_json_path,
		      "/var/log/shirudo/maps.ndjson") != 0 ||
	       strcmp(cfg.map_export_otel_endpoint,
		      "https://collector.example:4318") != 0 ||
	       strcmp(cfg.map_export_tenant_id, "tenant-uuid-1234") != 0 ||
	       !cfg.map_export_otel_insecure ||
	       cfg.map_export_otel_retries != 7 ||
	       strcmp(cfg.map_export_s3_uri, "s3://bucket/prefix") != 0 ||
	       cfg.map_export_log_record_max_bytes != 1024 ||
	       cfg.map_export_otlp_max_bytes != 2048;
}

static int check_invalid(const char *path, const char *input)
{
	struct shirudo_config cfg;

	return write_config(path, input) != 0 ||
	       config_load_path(&cfg, path) != 0 ||
	       cfg.map_export_valid;
}

/* A bad eventlog.max_bytes is ignored, leaving the default of 0. */
static int check_max_bytes(const char *path, const char *value,
			   __u64 expected)
{
	struct shirudo_config cfg;
	char input[128];

	snprintf(input, sizeof(input), "eventlog.max_bytes = %s\n", value);
	return write_config(path, input) != 0 ||
	       config_load_path(&cfg, path) != 0 ||
	       cfg.eventlog_max_bytes != expected;
}

int main(void)
{
	char path[] = "/tmp/shirudo-config-test.XXXXXX";
	int fd, failed = 0;

	fd = mkstemp(path);
	if (fd < 0)
		return EXIT_FAILURE;
	close(fd);
	failed += check_defaults(path);
	failed += check_valid(path);
	failed += check_invalid(path, "map_export.json_path = relative.json\n");
	failed += check_invalid(path, "map_export.otel_retries = 11\n");
	failed += check_invalid(path, "map_export.otel_retries = +5\n");
	failed += check_invalid(path, "map_export.otel_retries = -1\n");
	failed += check_invalid(path, "map_export.otel_insecure = yes\n");
	failed += check_invalid(path, "map_export.otlp_max_bytes = 0\n");
	failed += check_invalid(path, "map_export.otlp_max_bytes = +1024\n");
	failed += check_invalid(path, "map_export.otlp_max_bytes = 0x400\n");
	failed += check_invalid(path, "map_export.otlp_max_bytes = 1024\n"
				"map_export.log_record_max_bytes = 2048\n");
	failed += check_invalid(path, "map_export.tenant_id = tenant uuid\n");
	failed += check_invalid(path, "map_export.tenant_id = tenant/id\n");
	failed += check_invalid(path,
		"map_export.tenant_id = "
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"a\n");
	failed += check_invalid(path, "map_export.unknown = value\n");
	failed += check_max_bytes(path, "1048576", 1048576);
	failed += check_max_bytes(path, "010", 10);
	failed += check_max_bytes(path, "0x10", 0);
	failed += check_max_bytes(path, "+16", 0);
	failed += check_max_bytes(path, "-1", 0);
	failed += check_max_bytes(path, "", 0);
	unlink(path);
	return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
