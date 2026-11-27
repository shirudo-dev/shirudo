// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <shirudo/enforcement.h>
#include <shirudo/misc.h>
#include <shirudo/string.h>
#include <shirudo/tpm.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config_measure.h"
#include "hex.h"
#include "image_bootstrap.h"
#include "io.h"
#include "malloc.h"
#include "paths.h"

bool image_path_valid(const char *path)
{
	return path && path[0] == '/' && !str_contains(path, "/../") &&
	       !str_contains(path, "/./") && !str_contains(path, "//") &&
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

static int bootstrap_add_certificate(struct image_bootstrap *boot,
				     const char *path)
{
	size_t i;

	if (!str_has_prefix(path, RUNTIME_DIR "/") ||
	    !image_path_valid(path))
		return -EPERM;
	if (boot->n_certificates == KEYS_MAX)
		return -E2BIG;
	for (i = 0; i < boot->n_certificates; i++)
		if (!strcmp(boot->certificates[i], path))
			return -EEXIST;
	if (strscpy(boot->certificates[i], path,
		    sizeof(boot->certificates[i])) < 0)
		return -ENAMETOOLONG;
	boot->n_certificates++;
	return 0;
}

static int bootstrap_enforcement(struct image_bootstrap *boot,
				 const char *mode)
{
	if (boot->have_enforcement)
		return -EINVAL;
	boot->have_enforcement = true;
	if (!strcmp(mode, "strict"))
		boot->enforcement = ENFORCEMENT_STRICT;
	else if (!strcmp(mode, "shared"))
		boot->enforcement = ENFORCEMENT_SHARED;
	else
		return -EINVAL;
	return 0;
}

/* The stream is consumed and closed. */
static int bootstrap_parse(FILE *file, struct image_bootstrap *boot,
			   bool initial)
{
	size_t capacity = 0;
	char *line = NULL;
	int got, ret = 0;

	if (!initial) {
		boot->enforcement = ENFORCEMENT_STRICT;
		boot->have_enforcement = false;
	}
	while ((got = read_text_line(file, &line, &capacity,
				     PATH_MAX + 127)) != 0) {
		char *key, *value;

		if (got < 0) {
			ret = got;
			break;
		}
		key = trim(line);
		if (!*key || *key == '#')
			continue;
		value = strchr(key, '=');
		if (!value) {
			ret = -EINVAL;
			break;
		}
		*value++ = 0;
		key = trim(key);
		value = trim(value);
		if (!strcmp(key, "runtime.root_hash")) {
			if (!initial || boot->have_root ||
			    hex_decode(value, boot->runtime_root, 32)) {
				ret = -EINVAL;
				break;
			}
			boot->have_root = true;
		} else if (!strcmp(key, "runtime.image") && initial) {
			if (!image_path_valid(value) ||
			    boot->runtime[0])
				ret = -EINVAL;
			else if (strscpy(boot->runtime, value,
					 sizeof(boot->runtime)) < 0)
				ret = -ENAMETOOLONG;
		} else if (!strcmp(key, "config.image")) {
			if (!image_path_valid(value))
				ret = -EINVAL;
			else if (strscpy(boot->config, value,
					 sizeof(boot->config)) < 0)
				ret = -ENAMETOOLONG;
		} else if (!strcmp(key, "config.verification_key")) {
			ret = bootstrap_add_certificate(boot, value);
		} else if (!strcmp(key, "config.pcr")) {
			__u64 pcr;

			if (parse_u64(value, strlen(value), 23, &pcr) ||
			    config_measure_pcr_valid(pcr)) {
				ret = -EINVAL;
			} else {
				boot->pcr = pcr;
				boot->have_pcr = true;
			}
		} else if (!strcmp(key, "config.nvpcr")) {
			if (strcmp(value, TPM_CONFIG_NVPCR_NAME)) {
				ret = -EINVAL;
			} else {
				boot->pcr = TPM_CONFIG_NVPCR_INDEX;
				boot->have_pcr = true;
			}
		} else if (!strcmp(key, "enforcement.mode") && !initial) {
			ret = bootstrap_enforcement(boot, value);
		} else if (str_has_prefix(key, "config.") ||
			   str_has_prefix(key, "runtime.") ||
			   str_has_prefix(key, "enforcement.")) {
			ret = -EINVAL;
		}
		if (ret)
			break;
	}
	if (ferror(file) && !ret)
		ret = -EIO;
	libc_free(line);
	fclose(file);
	return ret;
}

int image_bootstrap_read(const char *path,
			 struct image_bootstrap *boot,
			 bool initial)
{
	FILE *file = fopen(path, "re");

	if (!file)
		return -errno;
	return bootstrap_parse(file, boot, initial);
}

/* A copy of the descriptor is read from its start; the caller keeps its own. */
int image_bootstrap_read_fd(int fd,
			    struct image_bootstrap *boot,
			    bool initial)
{
	int copy, ret;
	FILE *file;

	copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
	if (copy < 0)
		return -errno;
	if (lseek(copy, 0, SEEK_SET) < 0) {
		ret = -errno;
		close(copy);
		return ret;
	}
	file = fdopen(copy, "r");
	if (!file) {
		ret = -errno;
		close(copy);
		return ret;
	}
	return bootstrap_parse(file, boot, initial);
}
