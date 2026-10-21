/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * OCI distribution client for BPM packages, indexes and upatch trees.
 */

#ifndef SHIRUDO_BPM_OCI_H
#define SHIRUDO_BPM_OCI_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "crypto.h"

struct shirudo_json_emit;

#define BPM_MAX_NAME 128
#define BPM_MAX_ENDPOINT 512
#define BPM_MAX_KEY 256
#define BPM_MAX_DIGEST 128
#define BPM_MAX_MEDIA 192
#define BPM_MAX_ENTRIES 512
#define BPM_MAX_STATE 256
#define BPM_MAX_HTTP_BODY (256u * 1024u * 1024u)
#define BPM_OCI_USERNAME_SIZE 256
#define BPM_OCI_PASSWORD_SIZE 4096
#define BPM_OCI_TOKEN_SIZE 4096
#define BPM_OCI_BASIC_RAW_SIZE (BPM_OCI_USERNAME_SIZE + BPM_OCI_PASSWORD_SIZE)
#define BPM_OCI_BASIC_ENCODED_SIZE \
	(4u * ((BPM_OCI_BASIC_RAW_SIZE + 2u) / 3u) + 1u)
#define BPM_OCI_AUTH_VALUE_SIZE \
	(BPM_OCI_BASIC_ENCODED_SIZE + sizeof("Basic "))
#define BPM_OCI_BASIC_HEADER_SIZE \
	(BPM_OCI_AUTH_VALUE_SIZE + sizeof("Authorization: ") - 1u)
#define BPM_INDEX_REPOSITORY "shirudo/bpm-index"
#define BPM_INDEX_TAG "stable"
#define BPM_INDEX_MEDIA "application/vnd.shirudo.bpm.index.v1+json"
#define BPM_INDEX_SIG_MEDIA "application/vnd.shirudo.bpm.index.signature.v1"
#define BPM_INDEX_ARTIFACT "application/vnd.shirudo.bpm.index.v1"
#define BPM_PACKAGE_MEDIA "application/vnd.shirudo.bpm.package.v1+gzip"
#define BPM_CONFIG_MEDIA "application/vnd.shirudo.bpm.config.v1+json"
#define BPM_EMPTY_CONFIG_MEDIA "application/vnd.oci.empty.v1+json"
#define BPM_PUBLIC_KEY_ARTIFACT "application/vnd.shirudo.bpm.public-key.v1+der"
#define BPM_PUBLIC_KEY_MEDIA "application/pkix-cert"
#define BPM_TREE_MEDIA "application/vnd.shirudo.upatch.tree.v2+json"
#define BPM_TREE_SIG_MEDIA "application/vnd.shirudo.upatch.tree.signature.v2"
#define BPM_TREE_ARTIFACT "application/vnd.shirudo.upatch.tree.v2"
#define BPM_MANIFEST_MEDIA "application/vnd.oci.image.manifest.v1+json"
#define BPM_UPATCH_MEDIA "application/vnd.shirudo.upatch.v1"

struct bpm_buffer {
	unsigned char *data;
	size_t len;
	size_t cap;
};

struct bpm_http_response {
	struct bpm_buffer body;
	char www_auth[2048];
	char content_type[BPM_MAX_MEDIA];
	char location[PATH_MAX];
	long status;
};

struct bpm_oci_client {
	char base_url[BPM_MAX_ENDPOINT];
	char registry[BPM_MAX_ENDPOINT];
	char username[BPM_OCI_USERNAME_SIZE];
	char password[BPM_OCI_PASSWORD_SIZE];
	char token[BPM_OCI_TOKEN_SIZE];
	char ca_file[PATH_MAX];
	struct shirudo_tls_ca tls_ca;
};

struct bpm_descriptor {
	char media[BPM_MAX_MEDIA];
	char digest[BPM_MAX_DIGEST];
	char title[PATH_MAX];
	int64_t size;
};

void bpm_copy_string(char *dst, size_t dst_sz, const char *src);
void bpm_trim(const char *in, char *out, size_t out_sz);
bool bpm_name_ok(const char *s);
bool bpm_version_ok(const char *s);
bool bpm_package_name_ok(const char *s);
int bpm_sha256_hex(const void *data, size_t len, char *hex, size_t hex_sz);
/* want is "sha256:<hex>" or bare hex; hex is the computed digest. */
bool bpm_digest_matches(const char *want, const char *hex);
void bpm_buffer_free(struct bpm_buffer *b);

/*
 * Registry access. Endpoints are oci://host[:port]; BPM_OCI_SCHEME,
 * BPM_OCI_CA_FILE, BPM_OCI_USERNAME/PASSWORD, REGISTRY_AUTH_FILE and
 * DOCKER_CONFIG are honoured. Every request enforces the TLS policy.
 */
int bpm_oci_parse_endpoint(const char *endpoint, struct bpm_oci_client *c);
int bpm_oci_parse_pull_ref(const char *raw, struct bpm_oci_client *c,
			   char *repository, size_t repository_sz,
			   char *tag, size_t tag_sz);
int bpm_oci_parse_push_repo(const char *raw, struct bpm_oci_client *c,
			    char *repository, size_t repository_sz);
int bpm_oci_url(const struct bpm_oci_client *c, const char *repo,
		const char *kind, const char *ref, char *out, size_t sz);
/* 2xx fills out; 404 is -ENOENT, other failures -EACCES. */
int bpm_oci_get_memory(struct bpm_oci_client *c, const char *url,
		       const char *accept, struct bpm_buffer *out);
int bpm_oci_get_file(struct bpm_oci_client *c, const char *url,
		     const char *accept, const char *path);
int bpm_oci_push_blob(struct bpm_oci_client *c, const char *repository,
		      const void *body, size_t body_len, const char *media,
		      struct bpm_descriptor *out);
int bpm_oci_put_manifest(struct bpm_oci_client *c, const char *repository,
			 const char *reference, const unsigned char *body,
			 size_t body_len, char *digest, size_t digest_sz);
int bpm_oci_parse_manifest(const unsigned char *body, size_t len,
			   struct bpm_descriptor *layers, int *n_layers,
			   char *package_name, size_t package_name_sz);
void bpm_oci_emit_descriptor(struct shirudo_json_emit *e, const char *key,
			     const struct bpm_descriptor *d, const char *title);

#endif /* SHIRUDO_BPM_OCI_H */
