/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 */

#ifndef SHIRUDO_BPM_SOURCE_CONFIG_H
#define SHIRUDO_BPM_SOURCE_CONFIG_H

#include <stddef.h>

int bpm_parse_source_line(char *line,
			  char *endpoint, size_t endpoint_sz,
			  char *index_repository, size_t index_repository_sz,
			  char *key_file, size_t key_file_sz);
/* A line of upatch-tree.conf: endpoint and reference, either quoted. */
int bpm_parse_tree_line(char *line,
			char *endpoint, size_t endpoint_sz,
			char *reference, size_t reference_sz);

#endif /* SHIRUDO_BPM_SOURCE_CONFIG_H */
