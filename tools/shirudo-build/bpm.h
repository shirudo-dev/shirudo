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
#define BPM_BUILD_MAX_POLICIES 64
#define BPM_BUILD_MAX_FIXES 16
#define BPM_FIX_ID_CHARS \
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"

struct bpm_build_policy {
	char id[UPATCH_POLICY_NAME_MAX];
	char paths[16][TREE_STRING_MAX];
	int n_paths;
	__u64 bit;
};

struct bpm_build_rodata {
	char symbol[128];
	char input[PATH_MAX];
	char generator[BPM_BUILD_MAX_COMMAND_ARGS][TREE_STRING_MAX];
	char update[BPM_BUILD_MAX_COMMAND_ARGS][TREE_STRING_MAX];
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

struct bpm_fixes {
	char ids[BPM_BUILD_MAX_FIXES][TREE_STRING_MAX];
	int n;
};

/*
 * Optional [upatches.tree] table. Publication metadata read by `bpm tree
 * append` on the operator; the target consumes the signed publication and
 * never sees the Beefile. The selector lives on the heap because it is
 * large and rarely present.
 */
struct bpm_build_tree {
	bool present;
	char id[UPATCH_NAME_MAX];
	char load_artifact[PATH_MAX];
	char unload_artifact[PATH_MAX];
	struct bpm_fixes fixes;
	struct tree_selector *selector;
};

struct bpm_build_upatch {
	char source[PATH_MAX];
	char type[16];
	char load_target[PATH_MAX];
	char unload_target[PATH_MAX];
	char load_path[PATH_MAX];
	char unload_path[PATH_MAX];
	char name[UPATCH_NAME_MAX + 1];
	char payload_sha256[CRYPTO_SHA256_LEN * 2 + 1];
	struct bpm_build_tree tree;
	struct bpm_build_rodata *rodata;
	size_t n_rodata;
	struct bpm_build_policy *policies;
	size_t n_policies;
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
void bpm_strings_sort(char strings[][TREE_STRING_MAX], int n);
bool bpm_fix_id_ok(const char *id);

int build_bpm(int argc, const char **argv);
int build_bpm_push(int argc, const char **argv);
int build_bpm_tree(int argc, const char **argv);
int build_bpm_tree_show(int argc, const char **argv);

struct bpm_buffer;
struct bpm_oci_client;
struct trusted_set;

/*
 * build_tree_fetch_checked() fetches the publication at reference, a tag
 * or a manifest digest, checks it against trusted, or cert_path when
 * trusted is NULL, as tree sync does and parses it into pub. document,
 * when not NULL, keeps the checked bytes for bpm_buffer_free().
 *
 * build_tree_fetch_sealed() fetches the sealed segment succ names as a
 * node walking back does: by digest, checked, and the one that ends where
 * succ starts.
 */
int build_tree_fetch_checked(struct bpm_oci_client *c, const char *repository,
			     const char *reference, const char *cert_path,
			     const struct trusted_set *trusted,
			     struct bpm_buffer *document,
			     struct tree_publication *pub,
			     char *manifest_digest, size_t digest_sz);
int build_tree_fetch_sealed(struct bpm_oci_client *c, const char *repository,
			    const char *cert_path,
			    const struct trusted_set *trusted,
			    const struct tree_publication *succ,
			    struct tree_publication *pred,
			    char *manifest_digest, size_t digest_sz);

int build_check_keys(const char *pkey, const char *cert);

/*
 * Downloads the package layer of the manifest at reference, an
 * oci://host/repository:tag, into a new file made from the mkstemp()
 * template path, and checks it against want, the manifest digest the
 * operator named: a tag is the registry's to point at any package the
 * key ever signed, an older one included. Messages start with cmd. 0, or
 * a negative errno with no file left behind; -EKEYREJECTED when the
 * registry serves other bytes.
 */
int build_download_package(const char *cmd, const char *reference,
			   const char *want, char *path);

/* The file name of source less .bpf.c, .bpf.o or .o. 0 or -E2BIG. */
int build_upatch_name(const char *source, char *out, size_t cap);

int build_keys_vouch(int argc, const char **argv);

#endif /* SHIRUDO_BUILD_BPM_H */
