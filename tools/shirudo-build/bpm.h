/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Operator-only BPM commands and the Beefile model they share.
 */

#ifndef SHIRUDO_BUILD_BPM_H
#define SHIRUDO_BUILD_BPM_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

#include <shirudo/misc.h>

#include "bpm_tree.h"
#include "crypto.h"
#include "upatch.h"

#define BPM_BUILD_MAX_ENTRIES 128
#define BPM_BUILD_MAX_RODATA 16
#define BPM_BUILD_MAX_COMMAND_ARGS 16

struct bpm_build_rodata {
	char symbol[128];
	char input[PATH_MAX];
	char generator[BPM_BUILD_MAX_COMMAND_ARGS][SHIRUDO_TREE_STRING_MAX];
	char update[BPM_BUILD_MAX_COMMAND_ARGS][SHIRUDO_TREE_STRING_MAX];
	int n_generator;
	int n_update;
};

struct bpm_build_input_override {
	char name[128];
	char path[PATH_MAX];
};

struct bpm_build_file {
	char source[PATH_MAX];
	char target[PATH_MAX];
};

/*
 * Optional [upatches.tree] table. Publication metadata read by `bpm tree
 * append` on the operator; the target consumes the signed publication and
 * never sees the Beefile. The selector lives on the heap because it is
 * large and rarely present.
 */
struct bpm_build_tree {
	bool present;
	char id[SHIRUDO_UPATCH_NAME_MAX];
	char load_artifact[PATH_MAX];
	char unload_artifact[PATH_MAX];
	struct shirudo_tree_selector *selector;
};

struct bpm_build_upatch {
	char source[PATH_MAX];
	char type[16];
	char load_target[PATH_MAX];
	char unload_target[PATH_MAX];
	char load_path[PATH_MAX];
	char unload_path[PATH_MAX];
	char name[SHIRUDO_UPATCH_NAME_MAX];
	char payload_sha256[SHIRUDO_CRYPTO_SHA256_LEN * 2 + 1];
	struct bpm_build_tree tree;
	struct bpm_build_rodata *rodata;
	size_t n_rodata;
};

struct bpm_build_spec {
	char name[128];
	char scope[PATH_MAX];
	char stage[PATH_MAX];
	__u8 *build_file;
	size_t build_file_len;
	struct bpm_build_file files[BPM_BUILD_MAX_ENTRIES];
	size_t n_files;
	struct bpm_build_upatch upatches[BPM_BUILD_MAX_ENTRIES];
	size_t n_upatches;
};

/*
 * Parse a Beefile into spec. The spec keeps a copy of the original bytes
 * in build_file (the archive embeds them verbatim). Release with
 * bpm_build_spec_free(); the spec itself is large and belongs on the heap.
 */
int bpm_build_parse_beefile(const __u8 *body, size_t len,
			    struct bpm_build_spec *spec);
void bpm_build_spec_free(struct bpm_build_spec *spec);

int shirudo_build_bpm(int argc, char **argv);
int shirudo_build_bpm_config_update(int argc, char **argv);
int shirudo_build_bpm_push(int argc, char **argv);
int shirudo_build_bpm_tree(int argc, char **argv);
bool shirudo_build_is_help(const char *arg);

int shirudo_build_check_keys(const char *pkey, const char *cert);

int shirudo_build_keys_vouch(int argc, char **argv);

#endif /* SHIRUDO_BUILD_BPM_H */
