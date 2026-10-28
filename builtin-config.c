// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * `shirudo config`: the effective shirudo.conf, or without one the
 * defaults in the same syntax, as a template.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "builtin.h"
#include "util/config.h"
#include "util/help.h"
#include "util/log.h"
#include "util/macros.h"
#include "util/paths.h"

static const struct shirudo_help config_help = {
	.usage   = "shirudo config",
	.summary = "Print the effective shirudo configuration in shirudo.conf "
		   "syntax.\nWhen " SHIRUDO_CONF_PATH " is absent, prints "
		   "the defaults.\nLocal-only.",
	.footer  = "Starting point for a new config file:\n"
		   "  shirudo config > " SHIRUDO_CONF_PATH,
};

static void usage(void)
{
	fprintf(stderr, "usage: %s\n", config_help.usage);
}

int cmd_config(int argc, const char **argv)
{
	bool image_mode = shirudo_image_config_active();
	struct shirudo_config cfg;
	bool file_present;
	int rc;
	int i;

	for (i = 1; i < argc; i++) {
		if (is_help(argv[i])) {
			print_help(&config_help);
			return 0;
		}
		pr_err("config: unknown option '%s'", argv[i]);
		usage();
		return 2;
	}

	file_present = access(SHIRUDO_CONF_PATH, F_OK) == 0;
	rc = config_load(&cfg);
	if (rc && rc != -ENOENT) {
		pr_err("config: load %s: %s",
		       SHIRUDO_CONF_PATH, strerror(-rc));
		return 1;
	}

	if (image_mode)
		printf("# shirudo config (authenticated config image; "
		       "TPM settings from runtime image)\n\n");
	else if (file_present)
		printf("# shirudo config (effective, loaded from %s)\n\n",
		       SHIRUDO_CONF_PATH);
	else
		printf("# shirudo config (no %s present; defaults shown)\n\n",
		       SHIRUDO_CONF_PATH);

	printf("# Eventlog cap; 0 = unlimited. When the log would exceed this,\n"
	       "# the state-changing op refuses with category: eventlog_full.\n");
	printf("eventlog.max_bytes = %llu\n\n", cfg.eventlog_max_bytes);

	printf("# TPM owner-hierarchy password used at NV-index define time.\n"
	       "# Empty by default (works on fresh TPMs, swtpm, most cloud VMs);\n"
	       "# set on TPMs whose owner auth was already provisioned by\n"
	       "# another tool. Literal string, or `hex:<even hex>` for a\n"
	       "# binary auth value. May also be supplied via the\n"
	       "# SHIRUDO_TPM_OWNER_AUTH env var; that override wins.\n");
	if (cfg.tpm_owner_auth_len > 0) {
		const char *env = image_mode ? NULL :
			getenv("SHIRUDO_TPM_OWNER_AUTH");

		printf("# tpm.owner_auth = (set, %zu bytes; redacted%s)\n\n",
		       cfg.tpm_owner_auth_len,
		       image_mode ? "; from runtime image" :
		       env ? "; from $SHIRUDO_TPM_OWNER_AUTH" :
		       "; from " SHIRUDO_CONF_PATH);
	} else {
		printf("# tpm.owner_auth = (unset)\n\n");
	}

	printf("# TCTI override for the TPM library connection. Empty (default)\n"
	       "# means the kernel resource manager at `device:/dev/tpmrm0`.\n"
	       "# Set to `swtpm:host=<addr>,port=<port>` for a software TPM\n"
	       "# emulator (dev/CI without real hardware); see\n"
	       "# Documentation/getting-started.rst \"TPM in development\"\n"
	       "# for a worked recipe. Pre-flight skips the /dev/tpmrm0 check\n"
	       "# when this is set. The SHIRUDO_TPM_TCTI env var overrides\n"
	       "# this in turn.\n");
	if (cfg.tpm_tcti[0]) {
		const char *env = image_mode ? NULL :
			getenv("SHIRUDO_TPM_TCTI");

		printf("tpm.tcti = %s  # from %s\n\n", cfg.tpm_tcti,
		       image_mode ? "runtime image" :
		       env && *env ? "$SHIRUDO_TPM_TCTI" : SHIRUDO_CONF_PATH);
	} else {
		printf("# tpm.tcti = (unset -- using device:/dev/tpmrm0)\n\n");
	}

	printf("# Exact DNS hosts that may use classical TLS key exchange.\n"
	       "# Targets honor this only from the immutable runtime image;\n"
	       "# operators use the root-managed /etc/shirudo/shirudo.conf.\n"
	       "# Leave empty for hybrid-only TLS.\n");
	printf("tls.classical_hosts = %s\n\n",
	       cfg.tls_classical_hosts);

	printf("# Periodic `shirudo upatch map --all` export. Empty JSON and\n"
	       "# OTLP destinations leave the installed timer idle. Every emitted\n"
	       "# map must carry a signed Lua decoder declaring log or metric.\n"
	       "# OTEL headers, TLS material, and AWS credentials belong in\n"
	       "# /etc/shirudo/map-export.env for the systemd service.\n");
	printf("map_export.json_path = %s\n", cfg.map_export_json_path);
	printf("map_export.otel_endpoint = %s\n",
	       cfg.map_export_otel_endpoint);
	printf("map_export.tenant_id = %s\n", cfg.map_export_tenant_id);
	printf("map_export.otel_insecure = %s\n",
	       cfg.map_export_otel_insecure ? "true" : "false");
	printf("map_export.otel_retries = %u\n",
	       cfg.map_export_otel_retries);
	printf("map_export.s3_uri = %s\n", cfg.map_export_s3_uri);
	printf("map_export.log_record_max_bytes = %u\n",
	       cfg.map_export_log_record_max_bytes);
	printf("map_export.otlp_max_bytes = %u\n",
	       cfg.map_export_otlp_max_bytes);

	return cfg.map_export_valid && cfg.tls_classical_hosts_valid ? 0 : 1;
}
