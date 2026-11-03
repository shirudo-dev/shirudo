// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * shirudo.conf, and the lines of a registry source and of upatch-tree.conf.
 */

#include <string.h>

#include "bpm_oci.h"
#include "bpm_source_config.h"
#include "config.h"
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	char line[PATH_MAX], copy[PATH_MAX], key_file[BPM_MAX_KEY];
	char endpoint[BPM_MAX_ENDPOINT], reference[BPM_MAX_DIGEST];
	char index_repository[BPM_MAX_ENDPOINT] = {};
	struct config cfg;
	char path[64];
	FILE *fp;
	int fd;

	fd = fuzz_file(data, size, path, sizeof(path));
	if (fd < 0)
		return 0;
	config_load_path(&cfg, path);
	/* Read as load_source() and load_tree_config() read their files. */
	fp = fopen(path, "r");
	while (fp && fgets(line, sizeof(line), fp)) {
		memcpy(copy, line, sizeof(line));
		bpm_parse_source_line(copy, endpoint, sizeof(endpoint),
				      index_repository,
				      sizeof(index_repository), key_file,
				      sizeof(key_file));
		bpm_parse_tree_line(line, endpoint, sizeof(endpoint),
				    reference, sizeof(reference));
	}
	if (fp)
		fclose(fp);
	close(fd);
	return 0;
}
