// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Operator-only publishing: `bpm push` with the signed repository index
 * and `bpm tree append`. Signing is a direct call into the CMS signer.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <curl/curl.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include "bpm.h"
#include "bpm_oci.h"
#include "bpm_package.h"
#include "bpm_tree.h"
#include "crypto.h"
#include "hex.h"
#include "io.h"
#include "json.h"
#include "log.h"
#include "malloc.h"
#include "paths.h"
#include "sign.h"
#include "timefmt.h"
#include "upatch.h"

#define BPM_MANIFEST_CAP	8192u
#define BPM_SIGN_MAX		(64u * 1024u)

static void tree_append_usage(void)
{
	fprintf(stderr,
		"usage: shirudo bpm tree append <package-file> <repository>\n"
		"                               [--keys-dir <dir>] [--key <signing_key.pem>]\n"
		"                               [--cert <cert.der>] [--previous-cert <cert.der>]\n"
		"                               [--tree-id <id>]\n"
		"                               [--reference <ref>] [--op add|delete]\n\n"
		"Publishes the [upatches.tree] entries of a built package as the next\n"
		"operations of the signed tree at <repository>:<ref> (default stable).\n"
		"The key defaults to --keys-dir, SHIRUDO_KEYS_DIR or %s.\n",
		KEYS_DIR);
}

static int publish_fail(const char *action, int ret)
{
	if (ret < 0)
		pr_err("bpm %s: %s", action, strerror(-ret));
	else
		pr_err("bpm %s failed", action);
	return 1;
}

/*
 * Detached CMS over payload with the operator key, in the same form as
 * a loader signature so the target verifies both with one code path.
 */
static int sign_detached(const void *payload, size_t len,
			 const char *key, const char *cert,
			 __u8 **sig, size_t *sig_len)
{
	struct sign_io io = {
		.insns = payload, .insns_sz = len, .signature_sz = BPM_SIGN_MAX,
	};
	int ret;

	io.signature = xmalloc(io.signature_sz);
	if (!io.signature)
		return -ENOMEM;
	ret = cms_sign(&io, key, cert);
	if (ret) {
		xfree(io.signature, BPM_SIGN_MAX);
		return ret;
	}
	*sig = io.signature;
	*sig_len = io.signature_sz;
	return 0;
}

static void sig_free(__u8 *sig)
{
	xfree(sig, BPM_SIGN_MAX);
}

static int index_entry_compare(const void *left, const void *right)
{
	const struct bpm_index_entry *a = left, *b = right;
	int ret = strcmp(a->name, b->name);

	return ret ? ret : strcmp(a->version, b->version);
}

static int index_repository_for_package(const char *repository, char *out, size_t out_sz)
{
	const char *name = strrchr(repository, '/');
	size_t namespace_len;

	if (!name || name == repository)
		return -EINVAL;
	namespace_len = (size_t)(name - repository);
	if (strsprintf(out, out_sz, "%.*s/%s", (int)namespace_len, repository,
		       BPM_INDEX_REPOSITORY_NAME) < 0)
		return -ENAMETOOLONG;
	return 0;
}

/* -ENOENT when the registry has no index there. */
static int fetch_index(struct bpm_oci_client *c, const char *repository,
		       const char *cert,
		       struct bpm_index_entry *entries, int *n)
{
	struct bpm_buffer manifest = {}, payload = {}, sig = {};
	struct bpm_descriptor *layers = NULL;
	char url[PATH_MAX], hex[65];
	int nl = 0, ret = 0;

	*n = 0;
	ret = bpm_oci_url(c, repository, "manifests", BPM_INDEX_TAG,
			  url, sizeof(url));
	if (ret)
		return ret;
	ret = bpm_oci_get_memory(c, url, BPM_MANIFEST_MEDIA, &manifest);
	if (ret)
		return ret;
	layers = xcalloc(BPM_MAX_ENTRIES, sizeof(*layers));
	if (!layers) {
		ret = -ENOMEM;
		goto out;
	}
	ret = bpm_oci_parse_manifest(manifest.data, manifest.len, layers,
				     BPM_MAX_ENTRIES, &nl, NULL, 0);
	if (ret)
		goto out;
	for (int i = 0; i < nl; i++) {
		struct bpm_buffer *dst;

		if (!strcmp(layers[i].media, BPM_INDEX_MEDIA))
			dst = &payload;
		else if (!strcmp(layers[i].media, BPM_INDEX_SIG_MEDIA))
			dst = &sig;
		else
			continue;
		if (dst->data) {
			ret = -EINVAL;
			goto out;
		}
		ret = bpm_oci_url(c, repository, "blobs", layers[i].digest,
				  url, sizeof(url));
		if (ret)
			goto out;
		ret = bpm_oci_get_blob(c, url, layers[i].media, dst);
		if (ret)
			goto out;
		if ((layers[i].size >= 0 && (__s64)dst->len != layers[i].size) ||
		    bpm_sha256_hex(dst->data, dst->len, hex, sizeof(hex)) ||
		    !bpm_digest_matches(layers[i].digest, hex)) {
			ret = -EKEYREJECTED;
			goto out;
		}
	}
	if (!payload.data || !sig.data) {
		ret = -EINVAL;
		goto out;
	}
	if (bpm_verify_cms(payload.data, payload.len, sig.data, sig.len, cert)) {
		pr_err("bpm push: the published repository index is not signed by %s",
		       cert);
		ret = -EKEYREJECTED;
		goto out;
	}
	ret = bpm_index_parse(payload.data, payload.len, entries, n);
out:
	xfree(layers, BPM_MAX_ENTRIES * sizeof(*layers));
	bpm_buffer_free(&manifest);
	bpm_buffer_free(&payload);
	bpm_buffer_free(&sig);
	return ret;
}

/*
 * Add or refresh the package's entry in the signed index beside its
 * repository namespace. A version already listed with different content
 * is refused: published versions are immutable. The operator keeps no
 * state, so only new_index tells a namespace without an index from a
 * registry that hides one: the index pushed then would be signed without
 * every package listed before.
 */
static int push_index(struct bpm_oci_client *c, const char *index_repository,
		      const char *repository,
		      const struct bpm_package_info *info,
		      const char *manifest_digest,
		      const struct bpm_descriptor *layer,
		      const char *key, const char *cert, bool new_index)
{
	struct bpm_descriptor config, payload_layer, sig_layer;
	struct bpm_index_entry *entries, *entry = NULL;
	char *body = NULL, *manifest = NULL;
	struct json_emit e = {};
	char timestamp[32], digest[72];
	char empty_config[] = "{}";
	size_t cap = 0, sig_len = 0;
	time_t now = time(NULL);
	__u8 *sig = NULL;
	int n = 0, ret = 0;

	entries = xcalloc(BPM_MAX_ENTRIES, sizeof(*entries));
	if (!entries)
		return -ENOMEM;
	ret = fetch_index(c, index_repository, cert, entries, &n);
	if (ret == -ENOENT && new_index) {
		ret = 0;
	} else if (ret == -ENOENT) {
		pr_err("bpm push: %s has no repository index; pass --new-index to start one, and only for a namespace that never had one",
		       index_repository);
	} else if (!ret && new_index) {
		pr_err("bpm push: %s has a repository index already; --new-index starts one only where there is none",
		       index_repository);
		ret = -EEXIST;
	}
	if (ret)
		goto out;
	for (int i = 0; i < n; i++) {
		if (strcmp(entries[i].name, info->name) ||
		    strcmp(entries[i].version, info->version))
			continue;
		if (strcmp(entries[i].manifest_digest, manifest_digest) ||
		    strcmp(entries[i].package_digest, layer->digest)) {
			pr_err("bpm push: the repository index already lists %s %s "
				  "with different content", info->name, info->version);
			ret = -EEXIST;
			goto out;
		}
		entry = &entries[i];
	}
	if (!entry) {
		if (n >= BPM_MAX_ENTRIES) {
			ret = -E2BIG;
			goto out;
		}
		entry = &entries[n++];
	}
	*entry = (struct bpm_index_entry){ .package_size = layer->size };
	bpm_copy_string(entry->name, sizeof(entry->name), info->name);
	bpm_copy_string(entry->version, sizeof(entry->version), info->version);
	bpm_copy_string(entry->repository, sizeof(entry->repository), repository);
	bpm_copy_string(entry->manifest_digest, sizeof(entry->manifest_digest),
			manifest_digest);
	bpm_copy_string(entry->package_digest, sizeof(entry->package_digest),
			layer->digest);
	bpm_copy_string(entry->signer, sizeof(entry->signer), info->signer);
	qsort(entries, (size_t)n, sizeof(*entries), index_entry_compare);

	if (iso8601(now, timestamp, sizeof(timestamp))) {
		ret = -EIO;
		goto out;
	}
	cap = 4096 + (size_t)n * 4096;
	body = xmalloc(cap);
	if (!body) {
		ret = -ENOMEM;
		goto out;
	}
	e = (struct json_emit){ .buf = body, .cap = cap };
	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_kv_string(&e, "generated_at", timestamp);
	json_arr_open(&e, "packages");
	for (int i = 0; i < n; i++) {
		json_obj_open(&e);
		json_kv_string(&e, "name", entries[i].name);
		json_kv_string(&e, "version", entries[i].version);
		json_kv_string(&e, "repository", entries[i].repository);
		json_kv_string(&e, "manifest_digest", entries[i].manifest_digest);
		json_kv_string(&e, "package_digest", entries[i].package_digest);
		json_kv_int(&e, "package_size", entries[i].package_size);
		json_kv_string(&e, "signer_fingerprint", entries[i].signer);
		json_obj_close(&e);
	}
	json_arr_close(&e);
	json_obj_close(&e);
	if (e.err) {
		ret = e.err;
		goto out;
	}
	ret = sign_detached(body, e.len, key, cert, &sig, &sig_len);
	if (ret)
		goto out;
	ret = bpm_oci_push_blob(c, index_repository, empty_config,
				strlen(empty_config), BPM_EMPTY_CONFIG_MEDIA,
				  &config);
	if (ret)
		goto out;
	ret = bpm_oci_push_blob(c, index_repository, body, e.len,
				BPM_INDEX_MEDIA, &payload_layer);
	if (ret)
		goto out;
	ret = bpm_oci_push_blob(c, index_repository, sig, sig_len,
				BPM_INDEX_SIG_MEDIA, &sig_layer);
	if (ret)
		goto out;
	manifest = xmalloc(BPM_MANIFEST_CAP);
	if (!manifest) {
		ret = -ENOMEM;
		goto out;
	}
	e = (struct json_emit){ .buf = manifest, .cap = BPM_MANIFEST_CAP };
	json_obj_open(&e);
	json_kv_int(&e, "schemaVersion", 2);
	json_kv_string(&e, "mediaType", BPM_MANIFEST_MEDIA);
	json_kv_string(&e, "artifactType", BPM_INDEX_ARTIFACT);
	bpm_oci_emit_descriptor(&e, "config", &config, NULL);
	json_arr_open(&e, "layers");
	bpm_oci_emit_descriptor(&e, NULL, &payload_layer, NULL);
	bpm_oci_emit_descriptor(&e, NULL, &sig_layer, NULL);
	json_arr_close(&e);
	json_obj_close(&e);
	if (e.err) {
		ret = e.err;
		goto out;
	}
	ret = bpm_oci_put_manifest(c, index_repository, BPM_INDEX_TAG,
				   (const __u8 *)manifest, e.len, digest,
				sizeof(digest));
out:
	xfree(manifest, BPM_MANIFEST_CAP);
	sig_free(sig);
	xfree(body, cap);
	xfree(entries, BPM_MAX_ENTRIES * sizeof(*entries));
	return ret;
}

static int push_package(const char *package_path, const char *raw_repository,
			const char *index_key, const char *index_cert,
			bool new_index, const char **reference_out)
{
	struct bpm_oci_client c __cleanup(bpm_oci_client_clear) = {};
	struct bpm_package_info info = {};
	struct bpm_descriptor config, layer, key_config, key_layer, subject;
	struct json_emit e = {};
	__u8 *archive = NULL, *manifest = NULL;
	const char *base;
	char repository[BPM_MAX_ENDPOINT], package_digest[72], key_digest[72];
	char index_repository[BPM_MAX_ENDPOINT] = {};
	char hex[65];
	char reference[PATH_MAX];
	char config_body[] = "{\"mediaType\":\"" BPM_CONFIG_MEDIA "\"}";
	char empty_config[] = "{}";
	char package_title[PATH_MAX];
	char *manifest_body;
	char *key_manifest_body = NULL;
	struct stat st;
	size_t archive_len, manifest_len, key_manifest_len;
	size_t index_repo_sz = sizeof(index_repository);
	int ret;

	if (!package_path || !*package_path)
		return -EINVAL;
	if (stat(package_path, &st))
		return -errno;
	if (!S_ISREG(st.st_mode))
		return -EINVAL;
	ret = read_file(package_path, BPM_MAX_HTTP_BODY, &archive,
			&archive_len);
	if (ret)
		return ret;
	ret = bpm_pkg_load_info(package_path, &info);
	if (ret)
		goto out;
	ret = bpm_oci_parse_push_repo(raw_repository, &c, repository,
				      sizeof(repository));
	if (ret)
		goto out;
	if (index_key && index_cert) {
		ret = index_repository_for_package(repository, index_repository, index_repo_sz);
		if (ret)
			goto out;
	}
	base = strrchr(package_path, '/');
	base = base ? base + 1 : package_path;
	if (!*base || strlen(base) >= sizeof(package_title)) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	bpm_copy_string(package_title, sizeof(package_title), base);

	ret = bpm_oci_push_blob(&c, repository, config_body, strlen(config_body),
				BPM_CONFIG_MEDIA, &config);
	if (ret)
		goto out;
	ret = bpm_oci_push_blob(&c, repository, archive, archive_len,
				BPM_PACKAGE_MEDIA, &layer);
	if (ret)
		goto out;

	manifest_body = xmalloc(BPM_MANIFEST_CAP);
	if (!manifest_body) {
		ret = -ENOMEM;
		goto out;
	}
	e.buf = manifest_body;
	e.cap = BPM_MANIFEST_CAP;
	json_obj_open(&e);
	json_kv_int(&e, "schemaVersion", 2);
	json_kv_string(&e, "mediaType", "application/vnd.oci.image.manifest.v1+json");
	bpm_oci_emit_descriptor(&e, "config", &config, NULL);
	json_arr_open(&e, "layers");
	bpm_oci_emit_descriptor(&e, NULL, &layer, package_title);
	json_arr_close(&e);
	json_obj_open_key(&e, "annotations");
	json_kv_string(&e, "dev.shirudo.bpm.package.name", info.name);
	json_kv_string(&e, "dev.shirudo.bpm.package.version", info.version);
	json_kv_string(&e, "org.opencontainers.image.title", info.name);
	json_kv_string(&e, "org.opencontainers.image.version", info.version);
	json_obj_close(&e);
	json_obj_close(&e);
	if (e.err) {
		xfree(manifest_body, BPM_MANIFEST_CAP);
		ret = e.err;
		goto out;
	}
	manifest_len = e.len;
	manifest = (__u8 *)manifest_body;
	if (bpm_sha256_hex(manifest, manifest_len, hex, sizeof(hex)) ||
	    strsprintf(package_digest, sizeof(package_digest), "sha256:%s", hex) < 0) {
		ret = -EINVAL;
		goto out;
	}
	/*
	 * By digest until the index takes the version, so a refused re-push
	 * leaves the tag on the package already published.
	 */
	ret = bpm_oci_put_manifest(&c, repository, package_digest, manifest,
				   manifest_len, key_digest, sizeof(key_digest));
	if (ret)
		goto out;

	/*
	 * Publish the package certificate as an OCI referrer so `bpm key add`
	 * can fetch it without downloading the package.
	 */
	ret = bpm_oci_push_blob(&c, repository, empty_config,
				strlen(empty_config), BPM_EMPTY_CONFIG_MEDIA,
				&key_config);
	if (ret)
		goto out;
	ret = bpm_oci_push_blob(&c, repository, info.cert, info.cert_len,
				BPM_PUBLIC_KEY_MEDIA, &key_layer);
	if (ret)
		goto out;
	subject = (struct bpm_descriptor){
		.media = "application/vnd.oci.image.manifest.v1+json",
	};
	bpm_copy_string(subject.digest, sizeof(subject.digest), package_digest);
	subject.size = (__s64)manifest_len;
	key_manifest_body = xmalloc(BPM_MANIFEST_CAP);
	if (!key_manifest_body) {
		ret = -ENOMEM;
		goto out;
	}
	e = (struct json_emit){ .buf = key_manifest_body, .cap = BPM_MANIFEST_CAP };
	json_obj_open(&e);
	json_kv_int(&e, "schemaVersion", 2);
	json_kv_string(&e, "mediaType", "application/vnd.oci.image.manifest.v1+json");
	json_kv_string(&e, "artifactType", BPM_PUBLIC_KEY_ARTIFACT);
	bpm_oci_emit_descriptor(&e, "config", &key_config, NULL);
	json_arr_open(&e, "layers");
	bpm_oci_emit_descriptor(&e, NULL, &key_layer, NULL);
	json_arr_close(&e);
	json_obj_open_key(&e, "subject");
	json_kv_string(&e, "mediaType", subject.media);
	json_kv_string(&e, "digest", subject.digest);
	json_kv_int(&e, "size", subject.size);
	json_obj_close(&e);
	json_obj_close(&e);
	if (e.err) {
		ret = e.err;
		goto out;
	}
	key_manifest_len = e.len;
	if (bpm_sha256_hex(key_manifest_body, key_manifest_len, hex,
			   sizeof(hex)) ||
	    strsprintf(key_digest, sizeof(key_digest), "sha256:%s", hex) < 0) {
		ret = -EINVAL;
		goto out;
	}
	ret = bpm_oci_put_manifest(&c, repository, key_digest,
				   (const __u8 *)key_manifest_body,
				   key_manifest_len, key_digest,
				   sizeof(key_digest));
	if (ret)
		goto out;
	if (index_key && index_cert) {
		ret = push_index(&c, index_repository, repository, &info,
				 package_digest, &layer, index_key, index_cert,
				 new_index);
		if (ret)
			goto out;
	}
	ret = bpm_oci_put_manifest(&c, repository, info.version, manifest,
				   manifest_len, package_digest,
				   sizeof(package_digest));
	if (ret)
		goto out;
	if (strsprintf(reference, sizeof(reference), "oci://%s/%s:%s",
		       c.registry, repository, info.version) < 0) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	*reference_out = xstrdup(reference);
	ret = *reference_out ? 0 : -ENOMEM;
out:
	xfree(key_manifest_body, BPM_MANIFEST_CAP);
	xfree(manifest, BPM_MANIFEST_CAP);
	xfree(info.cert, info.cert_len + 1);
	xfree(archive, archive_len + 1);
	return ret;
}

static int tree_string_compare(const void *left, const void *right)
{
	return strcmp(left, right);
}

/* Selector lists are sets: sort them so equal Beefiles digest equally. */
static void tree_selector_canonicalize(struct tree_selector *s)
{
	qsort(s->kernel_release_prefix, (size_t)s->n_kernel_release_prefix,
	      TREE_STRING_MAX, tree_string_compare);
	qsort(s->kernel_build_id, (size_t)s->n_kernel_build_id,
	      TREE_STRING_MAX, tree_string_compare);
	qsort(s->architecture, (size_t)s->n_architecture,
	      TREE_STRING_MAX, tree_string_compare);
	for (int i = 0; i < s->n_kconfig; i++)
		qsort(s->kconfig[i].values, (size_t)s->kconfig[i].n_values,
		      TREE_STRING_MAX, tree_string_compare);
	for (int i = 0; i < s->n_labels; i++)
		qsort(s->labels[i].values, (size_t)s->labels[i].n_values,
		      TREE_STRING_MAX, tree_string_compare);
}

/*
 * Publish one immutable upatch artifact and describe it for the tree.
 * The bytes are checked to be the directive the operation claims (same
 * name, load versus unload) before anything is uploaded, so a target
 * never meets an operation its own tree_verify_upatch() would reject.
 */
static int tree_push_artifact(struct bpm_oci_client *c, const char *repository,
			      const char *raw_repository,
			      const __u8 *body, size_t len,
			      const char *id, bool unload,
			      struct tree_artifact *out)
{
	char name[UPATCH_NAME_MAX + 1], title[UPATCH_NAME_MAX + 16];
	char temporary[] = "/tmp/shirudo-bpm-tree-XXXXXX";
	struct bpm_descriptor layer, config;
	char empty_config[] = "{}";
	struct json_emit e;
	struct upatch u;
	char hex[65], tag[160];
	char *manifest;
	int fd, ret;

	fd = mkstemp(temporary);
	if (fd < 0)
		return -errno;
	ret = write_complete(fd, body, len);
	close(fd);
	if (!ret)
		ret = upatch_open(temporary, &u);
	unlink(temporary);
	if (ret) {
		pr_err("bpm tree append: %s is not a valid upatch", id);
		return ret;
	}
	upatch_header_name(&u, name);
	hex_encode(u.hdr.payload_sha256, 32, hex);
	if (strcmp(name, id) || upatch_is_unload(&u) != unload)
		ret = -EKEYREJECTED;
	upatch_close(&u);
	if (ret) {
		pr_err("bpm tree append: the %s artifact for %s is a %s directive named %s",
		       unload ? "unload" : "load", id,
		       unload ? "load" : "unload", name);
		return ret;
	}
	if (strsprintf(tag, sizeof(tag), "upatch-%s-%.16s", id, hex) < 0 || strlen(tag) > 128)
		return -ENAMETOOLONG;
	if (strsprintf(title, sizeof(title), "%s.upatch", id) < 0)
		return -ENAMETOOLONG;
	ret = bpm_oci_push_blob(c, repository, body, len, BPM_UPATCH_MEDIA,
				&layer);
	if (ret)
		return ret;
	ret = bpm_oci_push_blob(c, repository, empty_config,
				strlen(empty_config), BPM_EMPTY_CONFIG_MEDIA,
				&config);
	if (ret)
		return ret;
	manifest = xmalloc(BPM_MANIFEST_CAP);
	if (!manifest)
		return -ENOMEM;
	e = (struct json_emit){ .buf = manifest, .cap = BPM_MANIFEST_CAP };
	json_obj_open(&e);
	json_kv_int(&e, "schemaVersion", 2);
	json_kv_string(&e, "mediaType", BPM_MANIFEST_MEDIA);
	json_kv_string(&e, "artifactType", BPM_UPATCH_MEDIA);
	bpm_oci_emit_descriptor(&e, "config", &config, NULL);
	json_arr_open(&e, "layers");
	bpm_oci_emit_descriptor(&e, NULL, &layer, NULL);
	json_arr_close(&e);
	json_obj_open_key(&e, "annotations");
	json_kv_string(&e, "org.opencontainers.image.title", title);
	json_obj_close(&e);
	json_obj_close(&e);
	ret = e.err;
	if (!ret)
		ret = bpm_oci_put_manifest(c, repository, tag,
					   (const __u8 *)manifest, e.len,
					   out->manifest_digest,
					   sizeof(out->manifest_digest));
	xfree(manifest, BPM_MANIFEST_CAP);
	if (ret)
		return ret;
	bpm_copy_string(out->repository, sizeof(out->repository), raw_repository);
	bpm_copy_string(out->layer_digest, sizeof(out->layer_digest), layer.digest);
	if (strsprintf(out->payload_sha256, sizeof(out->payload_sha256),
		       "sha256:%s", hex) < 0)
		return -E2BIG;
	return 0;
}

static int cmd_bpm_tree_append(int argc, char **argv)
{
	const char *package = NULL, *raw_repository = NULL, *keys_dir_arg = NULL;
	char repository[BPM_MAX_ENDPOINT], repo_ref[BPM_MAX_ENDPOINT];
	struct bpm_descriptor config, payload_layer, sig_layer;
	const char *key = NULL, *cert = NULL, *tree_id = NULL;
	const char *previous_cert = NULL;
	const char *reference = "stable", *operation = "add";
	char key_path[PATH_MAX], cert_path[PATH_MAX];
	char parent[BPM_MAX_DIGEST] = {}, digest[72];
	struct tree_publication pub = {};
	struct tree_operation *op = NULL;
	size_t len, payload_len = 0, sig_len = 0;
	char *payload = NULL, *manifest = NULL;
	struct bpm_build_spec *spec = NULL;
	__u8 *beefile = NULL, *sig = NULL;
	struct bpm_package_info info = {};
	struct bpm_oci_client c __cleanup(bpm_oci_client_clear) = {};
	struct json_emit e;
	char empty_config[] = "{}";
	char package_dir[101];
	int appended = 0, ret;
	bool unload;

	for (int i = 2; i < argc; i++) {
		const char *a = argv[i];

		if (!strcmp(a, "--keys-dir") && i + 1 < argc) {
			keys_dir_arg = argv[++i];
		} else if (!strncmp(a, "--keys-dir=", 11)) {
			keys_dir_arg = a + 11;
		} else if (!strcmp(a, "--key") && i + 1 < argc) {
			key = argv[++i];
		} else if (!strncmp(a, "--key=", 6)) {
			key = a + 6;
		} else if (!strcmp(a, "--cert") && i + 1 < argc) {
			cert = argv[++i];
		} else if (!strncmp(a, "--cert=", 7)) {
			cert = a + 7;
		} else if (!strcmp(a, "--previous-cert") && i + 1 < argc) {
			previous_cert = argv[++i];
		} else if (!strncmp(a, "--previous-cert=", 16)) {
			previous_cert = a + 16;
		} else if (!strcmp(a, "--tree-id") && i + 1 < argc) {
			tree_id = argv[++i];
		} else if (!strncmp(a, "--tree-id=", 10)) {
			tree_id = a + 10;
		} else if (!strcmp(a, "--reference") && i + 1 < argc) {
			reference = argv[++i];
		} else if (!strncmp(a, "--reference=", 12)) {
			reference = a + 12;
		} else if (!strcmp(a, "--op") && i + 1 < argc) {
			operation = argv[++i];
		} else if (!strncmp(a, "--op=", 5)) {
			operation = a + 5;
		} else if (a[0] == '-' || (package && raw_repository)) {
			tree_append_usage();
			return -EINVAL;
		} else if (!package) {
			package = a;
		} else {
			raw_repository = a;
		}
	}
	if (!package || !raw_repository) {
		tree_append_usage();
		return -EINVAL;
	}
	if (strcmp(operation, "add") && strcmp(operation, "delete")) {
		pr_err("bpm tree append: --op must be add or delete");
		return -EINVAL;
	}
	if (tree_id && !bpm_package_name_ok(tree_id)) {
		pr_err("bpm tree append: invalid --tree-id %s", tree_id);
		return -EINVAL;
	}
	unload = !strcmp(operation, "delete");
	if (!key || !cert) {
		const char *keys_dir = keys_dir_resolve(keys_dir_arg);

		if (!key) {
			if (format_key_path(key_path, sizeof(key_path), keys_dir,
					    SIGNING_KEY_FILE))
				return -EINVAL;
			key = key_path;
		}
		if (!cert) {
			if (format_key_path(cert_path, sizeof(cert_path), keys_dir,
					    CERT_FILE))
				return -EINVAL;
			cert = cert_path;
		}
	}
	if (build_check_keys(key, cert))
		return -EACCES;
	if (!previous_cert)
		previous_cert = cert;
	if (bpm_trim(raw_repository, repo_ref, sizeof(repo_ref))) {
		pr_err("bpm tree append: repository is longer than %zu bytes",
		       sizeof(repo_ref) - 1);
		return -ENAMETOOLONG;
	}

	ret = bpm_pkg_load_info(package, &info);
	if (ret)
		return ret;
	ret = bpm_pkg_read_member_in(package, "Beefile", NULL, package_dir,
				     sizeof(package_dir), &beefile, &len,
				     4u * 1024u * 1024u);
	if (ret) {
		pr_err("bpm tree append: package %s does not include Beefile", package);
		goto out;
	}
	spec = xmalloc(sizeof(*spec));
	if (!spec) {
		ret = -ENOMEM;
		goto out;
	}
	ret = bpm_build_parse_beefile(beefile, len, spec);
	if (ret) {
		pr_err("bpm tree append: cannot parse the Beefile of %s", package);
		goto out;
	}
	ret = bpm_oci_parse_push_repo(repo_ref, &c, repository, sizeof(repository));
	if (ret) {
		pr_err("bpm tree append: the repository must be oci://registry/repository");
		goto out;
	}
	ret = bpm_tree_fetch_publication(&c, repository, reference, previous_cert,
					 NULL, &pub, parent, sizeof(parent));
	if (ret == -ENOENT) {
		pub = (struct tree_publication){ .schema = 1,
							 .generation = 1 };
		parent[0] = '\0';
		if (tree_id)
			bpm_copy_string(pub.tree_id, sizeof(pub.tree_id), tree_id);
	} else if (ret) {
		pr_err("bpm tree append: cannot read the publication at %s:%s",
		       repo_ref, reference);
		goto out;
	} else {
		if (tree_id && strcmp(pub.tree_id, tree_id)) {
			pr_err("bpm tree append: tree id mismatch: existing %s, requested %s",
			       pub.tree_id, tree_id);
			ret = -EINVAL;
			goto out;
		}
		if (check_add_overflow(pub.generation, 1, &pub.generation) ||
		    pub.generation == INT64_MAX) {
			pr_err("bpm tree append: the tree's generation is exhausted");
			ret = -EOVERFLOW;
			goto out;
		}
	}
	pub.schema = 1;
	if (!pub.tree_id[0])
		bpm_copy_string(pub.tree_id, sizeof(pub.tree_id), info.name);
	bpm_copy_string(pub.parent_manifest_digest,
			sizeof(pub.parent_manifest_digest), parent);

	op = xmalloc(sizeof(*op));
	if (!op) {
		ret = -ENOMEM;
		goto out;
	}
	for (size_t i = 0; i < spec->n_upatches; i++) {
		const struct bpm_build_upatch *u = &spec->upatches[i];
		const char *member;
		__u8 *body = NULL;
		size_t body_len;
		__s64 seq;

		if (!u->tree.present)
			continue;
		if (check_add_overflow(pub.head_seq, 1, &seq) ||
		    seq == INT64_MAX) {
			pr_err("bpm tree append: the tree's sequence is exhausted");
			ret = -EOVERFLOW;
			goto out;
		}
		member = unload ? u->tree.unload_artifact : u->tree.load_artifact;
		ret = bpm_pkg_read_member_in(package, member, package_dir, NULL, 0,
					     &body, &body_len, BPM_MAX_HTTP_BODY);
		if (ret) {
			pr_err("bpm tree append: package entry %s not found", member);
			goto out;
		}
		tree_selector_free(&op->selector);
		*op = (struct tree_operation){ .seq = seq };
		bpm_copy_string(op->op, sizeof(op->op), operation);
		bpm_copy_string(op->id, sizeof(op->id), u->tree.id);
		if (u->tree.selector) {
			ret = tree_selector_copy(&op->selector, u->tree.selector);
			if (ret) {
				xfree(body, body_len + 1);
				goto out;
			}
		}
		tree_selector_canonicalize(&op->selector);
		ret = tree_push_artifact(&c, repository, repo_ref, body, body_len,
					 u->tree.id, unload, &op->artifact);
		xfree(body, body_len + 1);
		if (ret)
			goto out;
		ret = tree_operation_digest(op, op->operation_digest);
		if (!ret)
			ret = tree_publication_append(&pub, op);
		if (ret)
			goto out;
		pub.head_seq = op->seq;
		appended++;
	}
	if (!appended) {
		pr_err("bpm tree append: %s has no [upatches.tree] entries", package);
		ret = -ENOENT;
		goto out;
	}
	ret = tree_emit_publication(&pub, &payload, &payload_len);
	if (ret)
		goto out;
	ret = sign_detached(payload, payload_len, key, cert, &sig, &sig_len);
	if (ret)
		goto out;
	ret = bpm_oci_push_blob(&c, repository, empty_config,
				strlen(empty_config), BPM_EMPTY_CONFIG_MEDIA,
				&config);
	if (ret)
		goto out;
	ret = bpm_oci_push_blob(&c, repository, payload, payload_len,
				BPM_TREE_MEDIA, &payload_layer);
	if (ret)
		goto out;
	ret = bpm_oci_push_blob(&c, repository, sig, sig_len, BPM_TREE_SIG_MEDIA,
				&sig_layer);
	if (ret)
		goto out;
	manifest = xmalloc(BPM_MANIFEST_CAP);
	if (!manifest) {
		ret = -ENOMEM;
		goto out;
	}
	e = (struct json_emit){ .buf = manifest, .cap = BPM_MANIFEST_CAP };
	json_obj_open(&e);
	json_kv_int(&e, "schemaVersion", 2);
	json_kv_string(&e, "mediaType", BPM_MANIFEST_MEDIA);
	json_kv_string(&e, "artifactType", BPM_TREE_ARTIFACT);
	bpm_oci_emit_descriptor(&e, "config", &config, NULL);
	json_arr_open(&e, "layers");
	bpm_oci_emit_descriptor(&e, NULL, &payload_layer, NULL);
	bpm_oci_emit_descriptor(&e, NULL, &sig_layer, NULL);
	json_arr_close(&e);
	json_obj_close(&e);
	ret = e.err;
	if (!ret)
		ret = bpm_oci_put_manifest(&c, repository, reference,
					   (const __u8 *)manifest, e.len,
					   digest, sizeof(digest));
	if (!ret)
		printf("oci://%s/%s:%s %s\n", c.registry, repository, reference,
		       digest);
out:
	xfree(manifest, BPM_MANIFEST_CAP);
	sig_free(sig);
	xfree(payload, payload_len);
	if (op)
		tree_selector_free(&op->selector);
	xfree(op, sizeof(*op));
	tree_publication_free(&pub);
	bpm_build_spec_free(spec);
	xfree(beefile, len + 1);
	xfree(info.cert, info.cert_len + 1);
	return ret;
}

static void bpm_push_usage(void)
{
	fprintf(stderr,
		"usage: shirudo bpm push <package-file> <repository>\n"
		"                        [--keys-dir <dir> | --index-cert <cert.der>\n"
		"                         --index-key <signing_key.pem>] [--new-index]\n\n"
		"The repository must start with oci:// and must not include a tag.\n"
		"With signing material the registry's signed index at\n"
		"<namespace>/bpm-index:stable gains the package entry, signed with the\n"
		"operator key; without it only the package is published. A namespace\n"
		"without an index is refused unless --new-index starts one, which in\n"
		"turn is refused where an index exists.\n"
		"Examples:\n"
		"  shirudo bpm push ./package.bee oci://quay.io/namespace/package\n"
		"  shirudo bpm push ./package.bee oci://quay.io/namespace/package \\\n"
		"      --keys-dir /var/lib/shirudo/keys\n");
}

int build_bpm_push(int argc, char **argv)
{
	const char *package = NULL, *repository = NULL, *reference = NULL;
	const char *keys_dir_arg = NULL, *index_cert = NULL, *index_key = NULL;
	char cert_path[PATH_MAX], key_path[PATH_MAX];
	bool new_index = false;
	int ret;

	if (argc == 2 && build_is_help(argv[1])) {
		bpm_push_usage();
		return 0;
	}
	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (!strcmp(a, "--keys-dir") && i + 1 < argc) {
			keys_dir_arg = argv[++i];
		} else if (!strncmp(a, "--keys-dir=", 11)) {
			keys_dir_arg = a + 11;
		} else if (!strcmp(a, "--index-cert") && i + 1 < argc) {
			index_cert = argv[++i];
		} else if (!strncmp(a, "--index-cert=", 13)) {
			index_cert = a + 13;
		} else if (!strcmp(a, "--index-key") && i + 1 < argc) {
			index_key = argv[++i];
		} else if (!strncmp(a, "--index-key=", 12)) {
			index_key = a + 12;
		} else if (!strcmp(a, "--new-index")) {
			new_index = true;
		} else if (a[0] == '-' || (package && repository)) {
			bpm_push_usage();
			return 2;
		} else if (!package) {
			package = a;
		} else {
			repository = a;
		}
	}
	if (!package || !repository) {
		bpm_push_usage();
		return 2;
	}
	if (keys_dir_arg) {
		if ((!index_cert &&
		     format_key_path(cert_path, sizeof(cert_path),
				     keys_dir_arg, CERT_FILE)) ||
		    (!index_key &&
		     format_key_path(key_path, sizeof(key_path),
				     keys_dir_arg, SIGNING_KEY_FILE)))
			return publish_fail("push", -EINVAL);
		if (!index_cert)
			index_cert = cert_path;
		if (!index_key)
			index_key = key_path;
	}
	if (!index_cert != !index_key) {
		pr_err("bpm push: --index-cert and --index-key must be supplied together");
		return 2;
	}
	if (new_index && !index_key) {
		pr_err("bpm push: --new-index needs --keys-dir, or --index-cert and --index-key");
		return 2;
	}
	if (index_key && build_check_keys(index_key, index_cert))
		return 1;
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return publish_fail("initialize curl", -EIO);
	ret = push_package(package, repository, index_key, index_cert,
			   new_index, &reference);
	curl_global_cleanup();
	if (ret)
		return publish_fail("push", ret);
	printf("%s\n", reference);
	xstrfree((char *)reference);
	return 0;
}

int build_bpm_tree(int argc, char **argv)
{
	int ret;

	if (argc < 2 || strcmp(argv[1], "append")) {
		tree_append_usage();
		return argc >= 2 && build_is_help(argv[1]) ? 0 : 2;
	}
	if (argc == 3 && build_is_help(argv[2])) {
		tree_append_usage();
		return 0;
	}
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return publish_fail("initialize curl", -EIO);
	ret = cmd_bpm_tree_append(argc, argv);
	curl_global_cleanup();
	return ret ? publish_fail("tree append", ret) : 0;
}
