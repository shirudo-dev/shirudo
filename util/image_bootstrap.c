// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config_measure.h"
#include "hex.h"
#include "image_bootstrap.h"
#include "paths.h"

bool shirudo_image_path_valid(const char *path)
{
	return path && path[0] == '/' && !strstr(path, "/../") &&
	       !strstr(path, "/./") && !strstr(path, "//") &&
	       strcmp(path, "/") &&
	       (strlen(path) < 3 || strcmp(path + strlen(path) - 3, "/.."));
}

static char *trim(char *text)
{
	char *end;

	while (*text == ' ' || *text == '\t')
		text++;
	end = text + strlen(text);
	while (end > text && (end[-1] == '\n' || end[-1] == '\r' ||
			      end[-1] == ' ' || end[-1] == '\t'))
		*--end = 0;
	return text;
}

int shirudo_image_bootstrap_read(const char *path,
				 struct shirudo_image_bootstrap *boot,
				 bool initial)
{
	char line[PATH_MAX + 128];
	FILE *file;
	int rc = 0;

	file = fopen(path, "re");
	if (!file)
		return -errno;
	while (fgets(line, sizeof(line), file)) {
		char *key, *value;

		if (!strchr(line, '\n') && !feof(file)) {
			rc = -E2BIG;
			break;
		}
		key = trim(line);
		if (!*key || *key == '#')
			continue;
		value = strchr(key, '=');
		if (!value) {
			rc = -EINVAL;
			break;
		}
		*value++ = 0;
		key = trim(key);
		value = trim(value);
		if (!strcmp(key, "runtime.root_hash")) {
			if (!initial || boot->have_root ||
			    hex_decode(value, boot->runtime_root, 32)) {
				rc = -EINVAL;
				break;
			}
			boot->have_root = true;
		} else if (!strcmp(key, "runtime.image") && initial) {
			if (!shirudo_image_path_valid(value) ||
			    boot->runtime[0])
				rc = -EINVAL;
			else
				strscpy(boot->runtime, value, sizeof(boot->runtime));
		} else if (!strcmp(key, "config.image")) {
			if (!shirudo_image_path_valid(value))
				rc = -EINVAL;
			else
				strscpy(boot->config, value, sizeof(boot->config));
		} else if (!strcmp(key, "config.verification_key")) {
			if (strncmp(value, SHIRUDO_RUNTIME_DIR "/",
				    sizeof(SHIRUDO_RUNTIME_DIR)) ||
			    !shirudo_image_path_valid(value))
				rc = -EPERM;
			else
				strscpy(boot->certificate, value, sizeof(boot->certificate));
		} else if (!strcmp(key, "config.pcr")) {
			__u64 pcr;

			if (parse_u64(value, strlen(value), 23, &pcr) ||
			    shirudo_config_measure_pcr_valid(pcr)) {
				rc = -EINVAL;
			} else {
				boot->pcr = pcr;
				boot->have_pcr = true;
			}
		} else if (!strncmp(key, "config.", 7) ||
			   !strncmp(key, "runtime.", 8)) {
			rc = -EINVAL;
		}
		if (rc)
			break;
	}
	if (ferror(file) && !rc)
		rc = -EIO;
	fclose(file);
	return rc;
}
