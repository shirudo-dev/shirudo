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
#include "macros.h"
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
		"                               [--cert <cert.der>] [--tree-id <id>]\n"
		"                               [--reference <ref>] [--op add|delete]\n\n"
		"Publishes the [upatches.tree] entries of a built package as the next\n"
		"operations of the signed tree at <repository>:<ref> (default stable).\n"
		"The key defaults to --keys-dir, SHIRUDO_KEYS_DIR or %s.\n",
		SHIRUDO_KEYS_DIR);
}

static int publish_fail(const char *action, int rc)
{
	if (rc < 0)
		pr_err("bpm %s: %s", action, strerror(-rc));
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
	struct shirudo_sign_io io = {
		.insns = payload, .insns_sz = len, .signature_sz = BPM_SIGN_MAX,
	};
	int rc;

	io.signature = xmalloc(io.signature_sz);
	if (!io.signature)
		return -ENOMEM;
	rc = cms_sign(&io, key, cert);
	if (rc) {
		xfree(io.signature, BPM_SIGN_MAX);
		return rc;
	}
	*sig = io.signature;
	*sig_len = io.signature_sz;
	return 0;
}

static void sig_free(__u8 *sig)
{
	if (sig)
		xfree(sig, BPM_SIGN_MAX);
}

static int index_entry_compare(const void *left, const void *right)
{
	const struct bpm_index_entry *a = left, *b = right;
	int rc = strcmp(a->name, b->name);

	return rc ? rc : strcmp(a->version, b->version);
}

/* A registry without an index yields an empty one. */
static int fetch_index(struct bpm_oci_client *c, const char *cert,
		       struct bpm_index_entry *entries, int *n)
{
	struct bpm_buffer manifest = {}, payload = {}, sig = {};
	struct bpm_descriptor *layers = NULL;
	char url[PATH_MAX], hex[65];
	int nl = 0, rc;

	*n = 0;
	rc = bpm_oci_url(c, BPM_INDEX_REPOSITORY, "manifests", BPM_INDEX_TAG,
			 url, sizeof(url));
	if (rc)
		return rc;
	rc = bpm_oci_get_memory(c, url, BPM_MANIFEST_MEDIA, &manifest);
	if (rc == -ENOENT)
		return 0;
	if (rc)
		return rc;
	layers = xcalloc(BPM_MAX_ENTRIES, sizeof(*layers));
	if (!layers) {
		rc = -ENOMEM;
		goto out;
	}
	rc = bpm_oci_parse_manifest(manifest.data, manifest.len, layers,
				    BPM_MAX_ENTRIES, &nl, NULL, 0);
	if (rc)
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
			rc = -EINVAL;
			goto out;
		}
		rc = bpm_oci_url(c, BPM_INDEX_REPOSITORY, "blobs", layers[i].digest,
				 url, sizeof(url));
		if (rc)
			goto out;
		rc = bpm_oci_get_blob(c, url, layers[i].media, dst);
		if (rc)
			goto out;
		if ((layers[i].size >= 0 && (__s64)dst->len != layers[i].size) ||
		    bpm_sha256_hex(dst->data, dst->len, hex, sizeof(hex)) ||
		    !bpm_digest_matches(layers[i].digest, hex)) {
			rc = -EKEYREJECTED;
			goto out;
		}
	}
	if (!payload.data || !sig.data) {
		rc = -EINVAL;
		goto out;
	}
	if (bpm_verify_cms(payload.data, payload.len, sig.data, sig.len, cert)) {
		pr_err("bpm push: the published repository index is not signed by %s",
		       cert);
		rc = -EKEYREJECTED;
		goto out;
	}
	rc = bpm_index_parse(payload.data, payload.len, entries, n);
out:
	if (layers)
		xfree(layers, BPM_MAX_ENTRIES * sizeof(*layers));
	bpm_buffer_free(&manifest);
	bpm_buffer_free(&payload);
	bpm_buffer_free(&sig);
	return rc;
}

/*
 * Add or refresh the package's entry in the registry's signed index at
 * shirudo/bpm-index:stable, the document `bpm repo update` consumes. A
 * version already listed with different content is refused: published
 * versions are immutable.
 */
static int push_index(struct bpm_oci_client *c, const char *repository,
		      const struct bpm_package_info *info,
		      const char *manifest_digest,
		      const struct bpm_descriptor *layer,
		      const char *key, const char *cert)
{
	struct bpm_descriptor config, payload_layer, sig_layer;
	struct bpm_index_entry *entries, *entry = NULL;
	char *body = NULL, *manifest = NULL;
	struct shirudo_json_emit e = {};
	char timestamp[32], digest[72];
	char empty_config[] = "{}";
	size_t cap, sig_len = 0;
	time_t now = time(NULL);
	__u8 *sig = NULL;
	int n = 0, rc;

	entries = xcalloc(BPM_MAX_ENTRIES, sizeof(*entries));
	if (!entries)
		return -ENOMEM;
	rc = fetch_index(c, cert, entries, &n);
	if (rc)
		goto out;
	for (int i = 0; i < n; i++) {
		if (strcmp(entries[i].name, info->name) ||
		    strcmp(entries[i].version, info->version))
			continue;
		if (strcmp(entries[i].manifest_digest, manifest_digest) ||
		    strcmp(entries[i].package_digest, layer->digest)) {
			pr_err("bpm push: the repository index already lists %s %s "
			       "with different content", info->name, info->version);
			rc = -EEXIST;
			goto out;
		}
		entry = &entries[i];
	}
	if (!entry) {
		if (n >= BPM_MAX_ENTRIES) {
			rc = -E2BIG;
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
		rc = -EIO;
		goto out;
	}
	cap = 4096 + (size_t)n * 4096;
	body = xmalloc(cap);
	if (!body) {
		rc = -ENOMEM;
		goto out;
	}
	e = (struct shirudo_json_emit){ .buf = body, .cap = cap };
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
		rc = e.err;
		goto out;
	}
	rc = sign_detached(body, e.len, key, cert, &sig, &sig_len);
	if (rc)
		goto out;
	rc = bpm_oci_push_blob(c, BPM_INDEX_REPOSITORY, empty_config,
			       strlen(empty_config), BPM_EMPTY_CONFIG_MEDIA,
			       &config);
	if (rc)
		goto out;
	rc = bpm_oci_push_blob(c, BPM_INDEX_REPOSITORY, body, e.len,
			       BPM_INDEX_MEDIA, &payload_layer);
	if (rc)
		goto out;
	rc = bpm_oci_push_blob(c, BPM_INDEX_REPOSITORY, sig, sig_len,
			       BPM_INDEX_SIG_MEDIA, &sig_layer);
	if (rc)
		goto out;
	manifest = xmalloc(BPM_MANIFEST_CAP);
	if (!manifest) {
		rc = -ENOMEM;
		goto out;
	}
	e = (struct shirudo_json_emit){ .buf = manifest, .cap = BPM_MANIFEST_CAP };
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
		rc = e.err;
		goto out;
	}
	rc = bpm_oci_put_manifest(c, BPM_INDEX_REPOSITORY, BPM_INDEX_TAG,
				  (const __u8 *)manifest, e.len, digest,
				  sizeof(digest));
out:
	if (manifest)
		xfree(manifest, BPM_MANIFEST_CAP);
	sig_free(sig);
	if (body)
		xfree(body, cap);
	xfree(entries, BPM_MAX_ENTRIES * sizeof(*entries));
	return rc;
}

static int push_package(const char *package_path, const char *raw_repository,
			const char *index_key, const char *index_cert,
			const char **reference_out)
{
	struct bpm_oci_client c = {};
	struct bpm_package_info info = {};
	struct bpm_descriptor config, layer, key_config, key_layer, subject;
	struct shirudo_json_emit e = {};
	__u8 *archive = NULL, *manifest = NULL;
	const char *base;
	char repository[BPM_MAX_ENDPOINT], package_digest[72], key_digest[72];
	char hex[65];
	char reference[PATH_MAX];
	char config_body[] = "{\"mediaType\":\"" BPM_CONFIG_MEDIA "\"}";
	char empty_config[] = "{}";
	char package_title[PATH_MAX];
	char *manifest_body;
	char *key_manifest_body = NULL;
	struct stat st;
	size_t archive_len, manifest_len, key_manifest_len;
	int rc;

	if (!package_path || !*package_path)
		return -EINVAL;
	if (stat(package_path, &st))
		return -errno;
	if (!S_ISREG(st.st_mode))
		return -EINVAL;
	rc = read_file(package_path, BPM_MAX_HTTP_BODY, &archive,
		       &archive_len);
	if (rc)
		return rc;
	rc = bpm_pkg_load_info(package_path, &info);
	if (rc)
		goto out;
	rc = bpm_oci_parse_push_repo(raw_repository, &c, repository,
				     sizeof(repository));
	if (rc)
		goto out;
	base = strrchr(package_path, '/');
	base = base ? base + 1 : package_path;
	if (!*base || strlen(base) >= sizeof(package_title)) {
		rc = -ENAMETOOLONG;
		goto out;
	}
	bpm_copy_string(package_title, sizeof(package_title), base);

	rc = bpm_oci_push_blob(&c, repository, config_body, strlen(config_body),
			       BPM_CONFIG_MEDIA, &config);
	if (rc)
		goto out;
	rc = bpm_oci_push_blob(&c, repository, archive, archive_len,
			       BPM_PACKAGE_MEDIA, &layer);
	if (rc)
		goto out;

	manifest_body = xmalloc(BPM_MANIFEST_CAP);
	if (!manifest_body) {
		rc = -ENOMEM;
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
		rc = e.err;
		goto out;
	}
	manifest_len = e.len;
	manifest = (__u8 *)manifest_body;
	if (bpm_sha256_hex(manifest, manifest_len, hex, sizeof(hex)) ||
	    strsprintf(package_digest, sizeof(package_digest), "sha256:%s", hex) < 0) {
		rc = -EINVAL;
		goto out;
	}
	/*
	 * By digest until the index takes the version, so a refused re-push
	 * leaves the tag on the package already published.
	 */
	rc = bpm_oci_put_manifest(&c, repository, package_digest, manifest,
				  manifest_len, key_digest, sizeof(key_digest));
	if (rc)
		goto out;

	/*
	 * Publish the package certificate as an OCI referrer so `bpm key add`
	 * can fetch it without downloading the package.
	 */
	rc = bpm_oci_push_blob(&c, repository, empty_config,
			       strlen(empty_config), BPM_EMPTY_CONFIG_MEDIA,
			       &key_config);
	if (rc)
		goto out;
	rc = bpm_oci_push_blob(&c, repository, info.cert, info.cert_len,
			       BPM_PUBLIC_KEY_MEDIA, &key_layer);
	if (rc)
		goto out;
	subject = (struct bpm_descriptor){
		.media = "application/vnd.oci.image.manifest.v1+json",
	};
	bpm_copy_string(subject.digest, sizeof(subject.digest), package_digest);
	subject.size = (__s64)manifest_len;
	key_manifest_body = xmalloc(BPM_MANIFEST_CAP);
	if (!key_manifest_body) {
		rc = -ENOMEM;
		goto out;
	}
	e = (struct shirudo_json_emit){ .buf = key_manifest_body, .cap = BPM_MANIFEST_CAP };
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
		rc = e.err;
		goto out;
	}
	key_manifest_len = e.len;
	if (bpm_sha256_hex(key_manifest_body, key_manifest_len, hex,
			   sizeof(hex)) ||
	    strsprintf(key_digest, sizeof(key_digest), "sha256:%s", hex) < 0) {
		rc = -EINVAL;
		goto out;
	}
	rc = bpm_oci_put_manifest(&c, repository, key_digest,
				  (const __u8 *)key_manifest_body,
				  key_manifest_len, key_digest,
				  sizeof(key_digest));
	if (rc)
		goto out;
	if (index_key && index_cert) {
		rc = push_index(&c, repository, &info, package_digest, &layer,
				index_key, index_cert);
		if (rc)
			goto out;
	}
	rc = bpm_oci_put_manifest(&c, repository, info.version, manifest,
				  manifest_len, package_digest,
				  sizeof(package_digest));
	if (rc)
		goto out;
	if (strsprintf(reference, sizeof(reference), "oci://%s/%s:%s",
		       c.registry, repository, info.version) < 0) {
		rc = -ENAMETOOLONG;
		goto out;
	}
	*reference_out = xstrdup(reference);
	rc = *reference_out ? 0 : -ENOMEM;
out:
	if (key_manifest_body)
		xfree(key_manifest_body, BPM_MANIFEST_CAP);
	if (manifest)
		xfree(manifest, BPM_MANIFEST_CAP);
	if (info.cert)
		xfree(info.cert, info.cert_len + 1);
	xfree(archive, archive_len + 1);
	return rc;
}

static int tree_string_compare(const void *left, const void *right)
{
	return strcmp(left, right);
}

/* Selector lists are sets: sort them so equal Beefiles digest equally. */
static void tree_selector_canonicalize(struct shirudo_tree_selector *s)
{
	qsort(s->kernel_release_prefix, (size_t)s->n_kernel_release_prefix,
	      SHIRUDO_TREE_STRING_MAX, tree_string_compare);
	qsort(s->kernel_build_id, (size_t)s->n_kernel_build_id,
	      SHIRUDO_TREE_STRING_MAX, tree_string_compare);
	qsort(s->architecture, (size_t)s->n_architecture,
	      SHIRUDO_TREE_STRING_MAX, tree_string_compare);
	for (int i = 0; i < s->n_kconfig; i++)
		qsort(s->kconfig[i].values, (size_t)s->kconfig[i].n_values,
		      SHIRUDO_TREE_STRING_MAX, tree_string_compare);
	for (int i = 0; i < s->n_labels; i++)
		qsort(s->labels[i].values, (size_t)s->labels[i].n_values,
		      SHIRUDO_TREE_STRING_MAX, tree_string_compare);
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
			      struct shirudo_tree_artifact *out)
{
	char name[SHIRUDO_UPATCH_NAME_MAX + 1], title[SHIRUDO_UPATCH_NAME_MAX + 16];
	char temporary[] = "/tmp/shirudo-bpm-tree-XXXXXX";
	struct bpm_descriptor layer, config;
	char empty_config[] = "{}";
	struct shirudo_json_emit e;
	struct shirudo_upatch u;
	char hex[65], tag[160];
	char *manifest;
	int fd, rc;

	fd = mkstemp(temporary);
	if (fd < 0)
		return -errno;
	rc = write_complete(fd, body, len);
	close(fd);
	if (!rc)
		rc = upatch_open(temporary, &u);
	unlink(temporary);
	if (rc) {
		pr_err("bpm tree append: %s is not a valid upatch", id);
		return rc;
	}
	memcpy(name, u.hdr.name, SHIRUDO_UPATCH_NAME_MAX);
	name[SHIRUDO_UPATCH_NAME_MAX] = '\0';
	hex_encode(u.hdr.payload_sha256, 32, hex);
	if (strcmp(name, id) || upatch_is_unload(&u) != unload)
		rc = -EKEYREJECTED;
	upatch_close(&u);
	if (rc) {
		pr_err("bpm tree append: the %s artifact for %s is a %s directive named %s",
		       unload ? "unload" : "load", id,
		       unload ? "load" : "unload", name);
		return rc;
	}
	if (strsprintf(tag, sizeof(tag), "upatch-%s-%.16s", id, hex) < 0 || strlen(tag) > 128)
		return -ENAMETOOLONG;
	snprintf(title, sizeof(title), "%s.upatch", id);
	rc = bpm_oci_push_blob(c, repository, body, len, BPM_UPATCH_MEDIA,
			       &layer);
	if (rc)
		return rc;
	rc = bpm_oci_push_blob(c, repository, empty_config,
			       strlen(empty_config), BPM_EMPTY_CONFIG_MEDIA,
			       &config);
	if (rc)
		return rc;
	manifest = xmalloc(BPM_MANIFEST_CAP);
	if (!manifest)
		return -ENOMEM;
	e = (struct shirudo_json_emit){ .buf = manifest, .cap = BPM_MANIFEST_CAP };
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
	rc = e.err;
	if (!rc)
		rc = bpm_oci_put_manifest(c, repository, tag,
					  (const __u8 *)manifest, e.len,
					  out->manifest_digest,
					  sizeof(out->manifest_digest));
	xfree(manifest, BPM_MANIFEST_CAP);
	if (rc)
		return rc;
	bpm_copy_string(out->repository, sizeof(out->repository), raw_repository);
	bpm_copy_string(out->layer_digest, sizeof(out->layer_digest), layer.digest);
	snprintf(out->payload_sha256, sizeof(out->payload_sha256), "sha256:%s", hex);
	return 0;
}

static int cmd_bpm_tree_append(int argc, char **argv)
{
	const char *package = NULL, *raw_repository = NULL, *keys_dir_arg = NULL;
	char repository[BPM_MAX_ENDPOINT], repo_ref[BPM_MAX_ENDPOINT];
	struct bpm_descriptor config, payload_layer, sig_layer;
	const char *key = NULL, *cert = NULL, *tree_id = NULL;
	const char *reference = "stable", *operation = "add";
	char key_path[PATH_MAX], cert_path[PATH_MAX];
	char parent[BPM_MAX_DIGEST] = {}, digest[72];
	struct shirudo_tree_publication pub = {};
	struct shirudo_tree_operation *op = NULL;
	size_t len, payload_len = 0, sig_len = 0;
	char *payload = NULL, *manifest = NULL;
	struct bpm_build_spec *spec = NULL;
	__u8 *beefile = NULL, *sig = NULL;
	struct bpm_package_info info = {};
	struct bpm_oci_client c = {};
	struct shirudo_json_emit e;
	char empty_config[] = "{}";
	char package_dir[101];
	int appended = 0, rc;
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
			if (shirudo_key_path(key_path, sizeof(key_path), keys_dir,
					     SHIRUDO_SIGNING_KEY_FILE))
				return -EINVAL;
			key = key_path;
		}
		if (!cert) {
			if (shirudo_key_path(cert_path, sizeof(cert_path), keys_dir,
					     SHIRUDO_CERT_FILE))
				return -EINVAL;
			cert = cert_path;
		}
	}
	if (shirudo_build_check_keys(key, cert))
		return -EACCES;
	bpm_trim(raw_repository, repo_ref, sizeof(repo_ref));

	rc = bpm_pkg_load_info(package, &info);
	if (rc)
		return rc;
	rc = bpm_pkg_read_member_in(package, "Beefile", NULL, package_dir,
				    sizeof(package_dir), &beefile, &len,
				    4u * 1024u * 1024u);
	if (rc) {
		pr_err("bpm tree append: package %s does not include Beefile", package);
		goto out;
	}
	spec = xmalloc(sizeof(*spec));
	if (!spec) {
		rc = -ENOMEM;
		goto out;
	}
	rc = bpm_build_parse_beefile(beefile, len, spec);
	if (rc) {
		pr_err("bpm tree append: cannot parse the Beefile of %s", package);
		goto out;
	}
	rc = bpm_oci_parse_push_repo(repo_ref, &c, repository, sizeof(repository));
	if (rc) {
		pr_err("bpm tree append: the repository must be oci://registry/repository");
		goto out;
	}
	rc = bpm_tree_fetch_publication(&c, repository, reference, cert, &pub,
					parent, sizeof(parent));
	if (rc == -ENOENT) {
		pub = (struct shirudo_tree_publication){ .schema = 2,
							 .generation = 1 };
		parent[0] = '\0';
		if (tree_id)
			bpm_copy_string(pub.tree_id, sizeof(pub.tree_id), tree_id);
	} else if (rc) {
		pr_err("bpm tree append: cannot read the publication at %s:%s",
		       repo_ref, reference);
		goto out;
	} else {
		if (tree_id && strcmp(pub.tree_id, tree_id)) {
			pr_err("bpm tree append: tree id mismatch: existing %s, requested %s",
			       pub.tree_id, tree_id);
			rc = -EINVAL;
			goto out;
		}
		pub.generation++;
	}
	pub.schema = 2;
	if (!pub.tree_id[0])
		bpm_copy_string(pub.tree_id, sizeof(pub.tree_id), info.name);
	bpm_copy_string(pub.parent_manifest_digest,
			sizeof(pub.parent_manifest_digest), parent);

	op = xmalloc(sizeof(*op));
	if (!op) {
		rc = -ENOMEM;
		goto out;
	}
	for (size_t i = 0; i < spec->n_upatches; i++) {
		const struct bpm_build_upatch *u = &spec->upatches[i];
		const char *member;
		__u8 *body = NULL;
		size_t body_len;

		if (!u->tree.present)
			continue;
		member = unload ? u->tree.unload_artifact : u->tree.load_artifact;
		rc = bpm_pkg_read_member_in(package, member, package_dir, NULL, 0,
					    &body, &body_len, BPM_MAX_HTTP_BODY);
		if (rc) {
			pr_err("bpm tree append: package entry %s not found", member);
			goto out;
		}
		*op = (struct shirudo_tree_operation){ .seq = pub.head_seq + 1 };
		bpm_copy_string(op->op, sizeof(op->op), operation);
		bpm_copy_string(op->id, sizeof(op->id), u->tree.id);
		if (u->tree.selector)
			op->selector = *u->tree.selector;
		tree_selector_canonicalize(&op->selector);
		rc = tree_push_artifact(&c, repository, repo_ref, body, body_len,
					u->tree.id, unload, &op->artifact);
		xfree(body, body_len + 1);
		if (rc)
			goto out;
		rc = tree_operation_digest(op, op->operation_digest);
		if (!rc)
			rc = tree_publication_append(&pub, op);
		if (rc)
			goto out;
		pub.head_seq = op->seq;
		appended++;
	}
	if (!appended) {
		pr_err("bpm tree append: %s has no [upatches.tree] entries", package);
		rc = -ENOENT;
		goto out;
	}
	rc = tree_emit_publication(&pub, &payload, &payload_len);
	if (rc)
		goto out;
	rc = sign_detached(payload, payload_len, key, cert, &sig, &sig_len);
	if (rc)
		goto out;
	rc = bpm_oci_push_blob(&c, repository, empty_config,
			       strlen(empty_config), BPM_EMPTY_CONFIG_MEDIA,
			       &config);
	if (rc)
		goto out;
	rc = bpm_oci_push_blob(&c, repository, payload, payload_len,
			       BPM_TREE_MEDIA, &payload_layer);
	if (rc)
		goto out;
	rc = bpm_oci_push_blob(&c, repository, sig, sig_len, BPM_TREE_SIG_MEDIA,
			       &sig_layer);
	if (rc)
		goto out;
	manifest = xmalloc(BPM_MANIFEST_CAP);
	if (!manifest) {
		rc = -ENOMEM;
		goto out;
	}
	e = (struct shirudo_json_emit){ .buf = manifest, .cap = BPM_MANIFEST_CAP };
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
	rc = e.err;
	if (!rc)
		rc = bpm_oci_put_manifest(&c, repository, reference,
					  (const __u8 *)manifest, e.len,
					  digest, sizeof(digest));
	if (!rc)
		printf("oci://%s/%s:%s %s\n", c.registry, repository, reference,
		       digest);
out:
	if (manifest)
		xfree(manifest, BPM_MANIFEST_CAP);
	sig_free(sig);
	if (payload)
		xfree(payload, payload_len);
	if (op)
		xfree(op, sizeof(*op));
	tree_publication_free(&pub);
	bpm_build_spec_free(spec);
	if (beefile)
		xfree(beefile, len + 1);
	if (info.cert)
		xfree(info.cert, info.cert_len + 1);
	return rc;
}

static void bpm_push_usage(void)
{
	fprintf(stderr,
		"usage: shirudo bpm push <package-file> <repository>\n"
		"                        [--keys-dir <dir> | --index-cert <cert.der>\n"
		"                         --index-key <signing_key.pem>]\n\n"
		"The repository must start with oci:// and must not include a tag.\n"
		"With signing material the registry's signed index at\n"
		"shirudo/bpm-index:stable gains the package entry, signed with the\n"
		"operator key; without it only the package is published.\n"
		"Examples:\n"
		"  shirudo bpm push ./package.bee oci://quay.io/namespace/package\n"
		"  shirudo bpm push ./package.bee oci://quay.io/namespace/package \\\n"
		"      --keys-dir /var/lib/shirudo/keys\n");
}

int shirudo_build_bpm_push(int argc, char **argv)
{
	const char *package = NULL, *repository = NULL, *reference = NULL;
	const char *keys_dir_arg = NULL, *index_cert = NULL, *index_key = NULL;
	char cert_path[PATH_MAX], key_path[PATH_MAX];
	int rc;

	if (argc == 2 && shirudo_build_is_help(argv[1])) {
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
		     shirudo_key_path(cert_path, sizeof(cert_path),
				      keys_dir_arg, SHIRUDO_CERT_FILE)) ||
		    (!index_key &&
		     shirudo_key_path(key_path, sizeof(key_path),
				      keys_dir_arg, SHIRUDO_SIGNING_KEY_FILE)))
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
	if (index_key && shirudo_build_check_keys(index_key, index_cert))
		return 1;
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return publish_fail("initialize curl", -EIO);
	rc = push_package(package, repository, index_key, index_cert, &reference);
	curl_global_cleanup();
	if (rc)
		return publish_fail("push", rc);
	printf("%s\n", reference);
	xstrfree((char *)reference);
	return 0;
}

int shirudo_build_bpm_tree(int argc, char **argv)
{
	int rc;

	if (argc < 2 || strcmp(argv[1], "append")) {
		tree_append_usage();
		return argc >= 2 && shirudo_build_is_help(argv[1]) ? 0 : 2;
	}
	if (argc == 3 && shirudo_build_is_help(argv[2])) {
		tree_append_usage();
		return 0;
	}
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return publish_fail("initialize curl", -EIO);
	rc = cmd_bpm_tree_append(argc, argv);
	curl_global_cleanup();
	return rc ? publish_fail("tree append", rc) : 0;
}
