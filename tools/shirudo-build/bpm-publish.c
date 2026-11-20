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
#include "bpm_tree_overlap.h"
#include "crypto.h"
#include "hex.h"
#include "io.h"
#include "json.h"
#include "help.h"
#include "log.h"
#include "options.h"
#include "malloc.h"
#include "paths.h"
#include "sign.h"
#include "timefmt.h"
#include "upatch.h"

#define BPM_MANIFEST_CAP	8192u
#define BPM_SIGN_MAX		(64u * 1024u)
#define TREE_SEGMENT_OPS	64

/* One append never splits across segments, so it fits in one. */
BUILD_BUG_ON(BPM_BUILD_MAX_ENTRIES > TREE_MAX_OPS);

enum tree_append_opt {
	TREE_APPEND_KEYS_DIR,
	TREE_APPEND_KEY,
	TREE_APPEND_CERT,
	TREE_APPEND_PREVIOUS_CERT,
	TREE_APPEND_TREE_ID,
	TREE_APPEND_REFERENCE,
	TREE_APPEND_OP,
	TREE_APPEND_SEGMENT_OPS,
	TREE_APPEND_PACKAGE_DIGEST,
};

static const struct opt_spec tree_append_opts[] = {
	[TREE_APPEND_KEYS_DIR] = { "--keys-dir", 0, 0, "<dir>",
		"read signing_key.pem and cert.der from <dir>" },
	[TREE_APPEND_KEY] = { "--key", 0, 0, "<signing_key.pem>",
		"the signing key, over --keys-dir" },
	[TREE_APPEND_CERT] = { "--cert", 0, 0, "<cert.der>",
		"the certificate, over --keys-dir" },
	[TREE_APPEND_PREVIOUS_CERT] = { "--previous-cert", 0, 0, "<cert.der>",
		"the certificate the tree was signed with so far" },
	[TREE_APPEND_TREE_ID] = { "--tree-id", 0, 0, "<id>",
		"the tree to extend, which an existing tree needs" },
	[TREE_APPEND_REFERENCE] = { "--reference", 0, 0, "<ref>",
		"the tag of the publication (default stable)" },
	[TREE_APPEND_OP] = { "--op", 0, 0, "add|delete",
		"add the entries, or delete them (default add)" },
	[TREE_APPEND_SEGMENT_OPS] = { "--segment-ops", 0, 0, "<n>",
		"seal a segment holding n operations and start the next, 1 to "
		__stringify(TREE_MAX_OPS) " (default "
		__stringify(TREE_SEGMENT_OPS) ")" },
	[TREE_APPEND_PACKAGE_DIGEST] = { "--package-digest", 0, 0,
		"<sha256:hex>", "the manifest digest of an oci:// package" },
};

static const struct help_section tree_append_sections[] = {
	HELP_OPTIONS("options:", tree_append_opts),
};

static const struct help tree_append_help = {
	.usage	    = "shirudo bpm tree append <package-file|oci://host/repo:tag> "
		      "<repository> [options]",
	.summary    = "Publish the [upatches.tree] entries of a built package "
		      "as the next\noperations of the signed tree at "
		      "<repository>:<ref>. The key defaults to\n--keys-dir, "
		      KEYS_DIR_ENV " or " KEYS_DIR ". An oci:// package needs "
		      "--package-digest,\nthe digest of its manifest.",
	.sections   = tree_append_sections,
	.n_sections = ARRAY_SIZE(tree_append_sections),
};

/* Indexed by what each stands for, so that a value names itself. */
static const struct opt_name tree_append_ops[] = {
	[false] = { "add", false },
	[true] = { "delete", true },
};

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
	char repository[BPM_MAX_ENDPOINT];
	char package_digest[SHA256_DIGEST_STR_SIZE];
	char key_digest[SHA256_DIGEST_STR_SIZE];
	char index_repository[BPM_MAX_ENDPOINT] = {};
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
	ret = read_file(package_path, BPM_MAX_PACKAGE_BYTES, &archive,
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
	if (bpm_sha256_digest(manifest, manifest_len, package_digest,
			      sizeof(package_digest))) {
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
	if (bpm_sha256_digest(key_manifest_body, key_manifest_len, key_digest,
			      sizeof(key_digest))) {
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
	if (strsprintf(reference, sizeof(reference), "oci://%s/%s:%s %s",
		       c.registry, repository, info.version,
		       package_digest) < 0) {
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

/* Selector lists are sets: sort them so equal Beefiles digest equally. */
static void tree_selector_canonicalize(struct tree_selector *s)
{
	bpm_strings_sort(s->kernel_release_prefix, s->n_kernel_release_prefix);
	bpm_strings_sort(s->kernel_build_id, s->n_kernel_build_id);
	bpm_strings_sort(s->architecture, s->n_architecture);
	for (int i = 0; i < s->n_kconfig; i++)
		bpm_strings_sort(s->kconfig[i].values, s->kconfig[i].n_values);
	for (int i = 0; i < s->n_labels; i++)
		bpm_strings_sort(s->labels[i].values, s->labels[i].n_values);
}

/* An artifact that is described for its operation and not uploaded yet. */
struct tree_upload {
	__u8	*body;
	size_t	body_len;
	char	tag[160];
	char	*manifest;
	size_t	manifest_len;
};

static int tree_describe_blob(const void *body, size_t len, const char *media,
			      struct bpm_descriptor *out)
{
	if (bpm_sha256_digest(body, len, out->digest, sizeof(out->digest)))
		return -EINVAL;
	bpm_copy_string(out->media, sizeof(out->media), media);
	out->size = (__s64)len;
	return 0;
}

static bool tree_fixes_valid(const struct bpm_fixes *fixes)
{
	if (!fixes->n)
		return false;
	for (int i = 0; i < fixes->n; i++) {
		if (!bpm_fix_id_ok(fixes->ids[i]) ||
		    (i && strcmp(fixes->ids[i - 1], fixes->ids[i]) >= 0))
			return false;
	}
	return true;
}

struct tree_fixes_reader {
	const struct tree_publication	*pub;
	struct bpm_fixes		*fixes;
	int				n;
	struct json_field		*fixes_key;
	__s64				seq;
	struct bpm_fixes		op;
	char				id[TREE_STRING_MAX];
};

static int tree_fixes_take_id(void *ctx)
{
	struct tree_fixes_reader *r = ctx;

	if (r->op.n >= BPM_BUILD_MAX_FIXES)
		return -E2BIG;
	memcpy(r->op.ids[r->op.n++], r->id, sizeof(r->id));
	return 0;
}

static int tree_fixes_take_operation(void *ctx)
{
	struct tree_fixes_reader *r = ctx;
	const struct tree_operation *op;

	if (r->n >= r->pub->n_operations)
		return -EINVAL;
	op = &r->pub->operations[r->n];
	if (r->seq != op->seq)
		return -EINVAL;
	if (r->fixes_key->seen &&
	    (strcmp(op->op, "add") || !tree_fixes_valid(&r->op)))
		return -EINVAL;
	r->fixes[r->n++] = r->op;
	r->seq = 0;
	r->op.n = 0;
	return 0;
}

static int tree_fixes_parse(struct tree_fixes_reader *r,
			    const struct bpm_buffer *document)
{
	struct json_array id_sink = { tree_fixes_take_id, r };
	struct json_array operation_sink = { tree_fixes_take_operation, r };
	struct json_field id[] = {
		{ "", JSON_T_STRING, r->id, sizeof(r->id), 0, NULL, 0 },
	};
	struct json_field operation[] = {
		{ "seq", JSON_T_INT, &r->seq, 0, 0, NULL, 0 },
		{ "fixes", JSON_T_ARRAY, &id_sink, 0, 0, id, ARRAY_SIZE(id) },
	};
	struct json_field root[] = {
		{ "operations", JSON_T_ARRAY, &operation_sink, 0, 0,
		  operation, ARRAY_SIZE(operation) },
	};

	r->fixes_key = &operation[1];
	return json_parse((const char *)document->data, document->len, root,
			  ARRAY_SIZE(root));
}

/*
 * tree_parse() is the node's parser and keeps no key a node does not
 * use, so the fixes of the previous publication come from a second read
 * of its bytes. fixes has room for every operation of pub.
 */
static int tree_read_fixes(const struct bpm_buffer *document,
			   const struct tree_publication *pub,
			   struct bpm_fixes *fixes)
{
	struct tree_fixes_reader *r;
	int ret;

	r = xcalloc(1, sizeof(*r));
	if (!r)
		return -ENOMEM;
	r->pub = pub;
	r->fixes = fixes;
	ret = tree_fixes_parse(r, document);
	if (!ret && r->n != pub->n_operations)
		ret = -EINVAL;
	xfree(r, sizeof(*r));
	return ret;
}

static int tree_emit_fixes(struct json_emit *e, int index, void *ctx)
{
	const struct bpm_fixes *fixes = (const struct bpm_fixes *)ctx + index;

	if (!fixes->n)
		return 0;
	json_arr_open(e, "fixes");
	for (int i = 0; i < fixes->n; i++)
		json_str(e, fixes->ids[i]);
	json_arr_close(e);
	return 0;
}

/*
 * Describe one immutable upatch artifact for the tree, with the manifest
 * its upload will put. The bytes are checked to be the directive the
 * operation claims, same name and load versus unload, so that a target
 * never meets an operation its own tree_verify_upatch() would reject.
 */
static int tree_describe_artifact(const char *raw_repository,
				  const __u8 *body, size_t len,
				  const char *id, bool unload,
				  struct tree_artifact *out,
				  struct tree_upload *up)
{
	char name[UPATCH_NAME_MAX + 1], title[UPATCH_NAME_MAX + 16];
	struct bpm_descriptor layer = {}, config = {};
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN];
	struct json_emit e;
	char hex[65];
	struct upatch u;
	bool is_unload;
	int ret;

	ret = upatch_open_memory(body, len, &u);
	if (ret) {
		pr_err("bpm tree append: %s is not a valid upatch", id);
		return ret;
	}
	upatch_header_name(&u, name);
	memcpy(payload, u.hdr.payload_sha256, sizeof(payload));
	hex_encode(payload, sizeof(payload), hex);
	is_unload = upatch_is_unload(&u);
	if (strcmp(name, id) || is_unload != unload)
		ret = -EKEYREJECTED;
	upatch_close(&u);
	if (ret) {
		pr_err("bpm tree append: the %s artifact for %s is %s directive named %s",
		       unload ? "unload" : "load", id,
		       is_unload ? "an unload" : "a load", name);
		return ret;
	}
	if (strsprintf(up->tag, sizeof(up->tag), "upatch-%s-%.16s", id, hex) < 0 ||
	    strlen(up->tag) > 128)
		return -ENAMETOOLONG;
	if (strsprintf(title, sizeof(title), "%s.upatch", id) < 0)
		return -ENAMETOOLONG;
	ret = tree_describe_blob(body, len, BPM_UPATCH_MEDIA, &layer);
	if (!ret)
		ret = tree_describe_blob("{}", 2, BPM_EMPTY_CONFIG_MEDIA,
					 &config);
	if (ret)
		return ret;
	up->manifest = xmalloc(BPM_MANIFEST_CAP);
	if (!up->manifest)
		return -ENOMEM;
	e = (struct json_emit){ .buf = up->manifest, .cap = BPM_MANIFEST_CAP };
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
	if (e.err)
		return e.err;
	up->manifest_len = e.len;
	ret = bpm_sha256_digest(up->manifest, e.len, out->manifest_digest,
				sizeof(out->manifest_digest));
	if (ret)
		return ret;
	sha256_digest_encode(payload, out->payload_sha256);
	bpm_copy_string(out->repository, sizeof(out->repository), raw_repository);
	bpm_copy_string(out->layer_digest, sizeof(out->layer_digest), layer.digest);
	return 0;
}

static int tree_upload_artifact(struct bpm_oci_client *c, const char *repository,
				const struct tree_upload *up)
{
	struct bpm_descriptor layer, config;
	char empty_config[] = "{}";
	char digest[72];
	int ret;

	ret = bpm_oci_push_blob(c, repository, up->body, up->body_len,
				BPM_UPATCH_MEDIA, &layer);
	if (!ret)
		ret = bpm_oci_push_blob(c, repository, empty_config,
					strlen(empty_config),
					BPM_EMPTY_CONFIG_MEDIA, &config);
	if (!ret)
		ret = bpm_oci_put_manifest(c, repository, up->tag,
					   (const __u8 *)up->manifest,
					   up->manifest_len, digest,
					   sizeof(digest));
	return ret;
}

/*
 * The classes of a load upatch, none for one without an XDP program or
 * one that is not BPF.
 */
static int upatch_xdp_classes(const void *body, size_t len, __u32 *classes)
{
	struct prog_spec *specs = NULL;
	const void *attach;
	__u32 attach_len;
	struct upatch u;
	int ret;

	ret = upatch_open_memory(body, len, &u);
	if (ret)
		return ret;
	if (upatch_signed_type(&u) != UPATCH_TYPE_BPF) {
		*classes = 0;
		upatch_close(&u);
		return 0;
	}
	attach = upatch_signed_attach(&u, &attach_len);
	ret = attach ? prog_specs_parse(attach, attach_len, u.hdr.nr_maps,
					u.hdr.nr_progs, &specs) : -EINVAL;
	if (!ret) {
		*classes = prog_specs_xdp_classes(specs, u.hdr.nr_progs);
		prog_specs_free(specs, u.hdr.nr_progs);
	}
	upatch_close(&u);
	return ret;
}

static int tree_fetch_xdp_classes(struct bpm_oci_client *c,
				  const char *repository, const char *repo_ref,
				  const struct tree_operation *op,
				  __u32 *classes)
{
	struct bpm_oci_client elsewhere __cleanup(bpm_oci_client_clear) = {};
	char other_repository[BPM_MAX_ENDPOINT], url[PATH_MAX], hex[65];
	struct bpm_buffer blob = {};
	__u8 digest[32];
	int ret;

	if (sha256_digest_decode(op->artifact.layer_digest, digest))
		return -EINVAL;
	if (strcmp(op->artifact.repository, repo_ref)) {
		ret = bpm_oci_parse_tree_repo(op->artifact.repository,
					      &elsewhere, other_repository,
					      sizeof(other_repository));
		if (ret)
			return ret;
		c = &elsewhere;
		repository = other_repository;
	}
	ret = bpm_oci_url(c, repository, "blobs", op->artifact.layer_digest,
			  url, sizeof(url));
	if (!ret)
		ret = bpm_oci_get_blob(c, url, BPM_UPATCH_MEDIA, &blob);
	if (!ret && (bpm_sha256_hex(blob.data, blob.len, hex, sizeof(hex)) ||
		     !bpm_digest_matches(op->artifact.layer_digest, hex)))
		ret = -EKEYREJECTED;
	if (!ret)
		ret = upatch_xdp_classes(blob.data, blob.len, classes);
	bpm_buffer_free(&blob);
	return ret;
}

/* The classes of the publication's operations, read once each. */
struct tree_xdp_classes {
	__u32	classes[TREE_MAX_OPS];
	bool	known[TREE_MAX_OPS];
};

/* The deletes of the segments after the one being checked. */
struct tree_later {
	struct tree_operation	*deletes;
	int			n;
	int			cap;
};

static void tree_later_free(struct tree_later *later)
{
	for (int i = 0; i < later->n; i++)
		tree_selector_free(&later->deletes[i].selector);
	xfree(later->deletes, (size_t)later->cap * sizeof(*later->deletes));
	*later = (struct tree_later){};
}

static int tree_later_take(struct tree_later *later,
			   const struct tree_publication *pub)
{
	for (int i = 0; i < pub->n_operations; i++) {
		const struct tree_operation *op = &pub->operations[i];
		struct tree_operation *deletes, *d;
		int cap;

		if (strcmp(op->op, "delete"))
			continue;
		if (later->n == later->cap) {
			if (check_mul_overflow(later->cap ? later->cap : 8, 2,
					       &cap))
				return -E2BIG;
			deletes = xreallocarray(later->deletes,
						(size_t)later->cap, (size_t)cap,
						sizeof(*deletes));
			if (!deletes)
				return -ENOMEM;
			later->deletes = deletes;
			later->cap = cap;
		}
		d = &later->deletes[later->n];
		*d = (struct tree_operation){ .seq = op->seq };
		if (tree_selector_copy(&d->selector, &op->selector))
			return -ENOMEM;
		bpm_copy_string(d->op, sizeof(d->op), op->op);
		bpm_copy_string(d->id, sizeof(d->id), op->id);
		later->n++;
	}
	return 0;
}

/*
 * A device runs one native XDP program. The second of two upatches that
 * select a class fails its load on every node with such a device, and
 * tree sync stops at the first operation that fails. later, NULL for
 * none, holds the deletes published after pub.
 */
static int tree_refuse_shared_xdp_class(struct bpm_oci_client *c,
					const char *repository,
					const char *repo_ref,
					const struct tree_publication *pub,
					const struct tree_later *later,
					struct tree_xdp_classes *seen,
					const struct tree_operation *op,
					__u32 classes)
{
	for (int i = 0; classes && i < pub->n_operations; i++) {
		const struct tree_operation *other = &pub->operations[i];
		int ret;

		if (strcmp(other->op, "add") || !strcmp(other->id, op->id) ||
		    !tree_add_live(pub, i) ||
		    (later && tree_add_withdrawn(other, later->deletes,
						 later->n)) ||
		    tree_selectors_disjoint(&other->selector, &op->selector))
			continue;
		if (!seen->known[i]) {
			ret = tree_fetch_xdp_classes(c, repository, repo_ref,
						     other, &seen->classes[i]);
			if (ret) {
				pr_err("bpm tree append: cannot read the artifact of %s (seq %lld) to compare its XDP device classes",
				       other->id, (long long)other->seq);
				return ret;
			}
			seen->known[i] = true;
		}
		if (!(seen->classes[i] & classes))
			continue;
		pr_err("bpm tree append: %s and %s (seq %lld) both select XDP device classes %u on nodes their selectors share; a device runs one XDP program, so give each class to one upatch or the two selectors that exclude each other",
		       op->id, other->id, (long long)other->seq,
		       seen->classes[i] & classes);
		return -EBUSY;
	}
	return 0;
}

/* The sealed segment succ names, as a node walking back fetches it. */
static int tree_fetch_sealed(struct bpm_oci_client *c, const char *repository,
			     const char *cert,
			     const struct tree_publication *succ,
			     struct tree_publication *pred)
{
	char digest[BPM_MAX_DIGEST];
	int ret;

	ret = build_tree_fetch_sealed(c, repository, cert, NULL, succ, pred,
				      digest, sizeof(digest));
	if (ret)
		pr_err("bpm tree append: the sealed segment %s, which ends at seq %lld, does not verify",
		       succ->segment_manifest_digest,
		       (long long)succ->base_seq);
	return ret;
}

/*
 * The shared class check of an add over the sealed segments before cur,
 * back to seq 0: sealed when this append seals it, the others fetched
 * by digest. An add stays live until a delete of any later segment
 * withdraws it, so the deletes of every segment walked are kept.
 */
static int tree_refuse_sealed_xdp_class(struct bpm_oci_client *c,
					const char *repository,
					const char *repo_ref, const char *cert,
					const struct tree_publication *cur,
					const struct tree_publication *sealed,
					const struct tree_operation *op,
					__u32 classes)
{
	const struct tree_publication *succ = cur, *segment = sealed;
	struct tree_publication fetched[2] = {};
	struct tree_xdp_classes *seen;
	struct tree_later later = {};
	int next = 0, ret;

	ret = tree_walk_within(cur->base_seq, 0);
	if (ret) {
		pr_err("bpm tree append: a joining node walks back %lld operations, past the limit of %d, so the XDP device classes of the sealed segments cannot be checked",
		       (long long)cur->base_seq, TREE_MAX_JOIN_OPS);
		return ret;
	}
	seen = xmalloc(sizeof(*seen));
	if (!seen)
		return -ENOMEM;
	ret = tree_later_take(&later, cur);
	while (!ret) {
		if (!segment) {
			if (!succ->base_seq)
				break;
			tree_publication_free(&fetched[next]);
			ret = tree_fetch_sealed(c, repository, cert, succ,
						&fetched[next]);
			if (ret)
				break;
			segment = &fetched[next];
			next ^= 1;
		}
		memset(seen, 0, sizeof(*seen));
		ret = tree_refuse_shared_xdp_class(c, repository, repo_ref,
						   segment, &later, seen, op,
						   classes);
		if (!ret)
			ret = tree_later_take(&later, segment);
		succ = segment;
		segment = NULL;
	}
	tree_later_free(&later);
	tree_publication_free(&fetched[0]);
	tree_publication_free(&fetched[1]);
	xfree(seen, sizeof(*seen));
	return ret;
}

static int tree_segment_tag(__u64 k, char *tag, size_t tag_sz)
{
	return strsprintf(tag, tag_sz, "segment-%llu", k) < 0 ?
	       -ENAMETOOLONG : 0;
}

/* The digest of the manifest segment-<k> tags, -ENOENT without the tag. */
static int tree_segment_tag_digest(struct bpm_oci_client *c,
				   const char *repository, __u64 k,
				   char digest[72])
{
	struct bpm_buffer manifest = {};
	__u8 sum[CRYPTO_SHA256_LEN];
	char tag[32], url[PATH_MAX];
	int ret;

	ret = tree_segment_tag(k, tag, sizeof(tag));
	if (!ret)
		ret = bpm_oci_url(c, repository, "manifests", tag, url,
				  sizeof(url));
	if (!ret)
		ret = bpm_oci_get_memory(c, url, BPM_MANIFEST_MEDIA, &manifest);
	if (!ret && sha256_buffer(manifest.data, manifest.len, sum))
		ret = -EINVAL;
	if (!ret)
		sha256_digest_encode(sum, digest);
	bpm_buffer_free(&manifest);
	return ret;
}

/*
 * The k of the next segment-<k> tag: doubling, then halving, finds a k
 * without a tag in about 2 log2 k requests, so no tag is ever moved. 0
 * when the last tag already names the sealed manifest, which a run that
 * failed after tagging leaves behind.
 */
static int tree_next_segment_tag(struct bpm_oci_client *c,
				 const char *repository,
				 const char *sealed_digest, __u64 *k)
{
	char digest[BPM_MAX_DIGEST], last[BPM_MAX_DIGEST] = {};
	__u64 present = 0, absent = 1, probe;
	bool doubling = true;
	int ret;

	while (doubling || absent - present > 1) {
		probe = doubling ? absent : present + (absent - present) / 2;
		ret = tree_segment_tag_digest(c, repository, probe, digest);
		if (ret == -ENOENT) {
			absent = probe;
			doubling = false;
			continue;
		}
		if (ret)
			return ret;
		present = probe;
		bpm_copy_string(last, sizeof(last), digest);
		if (doubling && check_mul_overflow(absent, 2, &absent))
			return -EOVERFLOW;
	}
	*k = present && !strcmp(last, sealed_digest) ? 0 : absent;
	return 0;
}

/*
 * Tag the sealed manifest segment-<k> so that registry garbage collection
 * keeps it; nodes walk back to it by digest and never read the tag.
 */
static int tree_tag_sealed(struct bpm_oci_client *c, const char *repository,
			   const char *sealed_digest)
{
	char tag[32] = {}, url[PATH_MAX], digest[BPM_MAX_DIGEST], hex[65];
	struct bpm_buffer manifest = {};
	__u64 k;
	int ret;

	ret = tree_next_segment_tag(c, repository, sealed_digest, &k);
	if (ret || !k)
		goto out;
	ret = tree_segment_tag(k, tag, sizeof(tag));
	if (!ret)
		ret = bpm_oci_url(c, repository, "manifests", sealed_digest,
				  url, sizeof(url));
	if (!ret)
		ret = bpm_oci_get_memory(c, url, BPM_MANIFEST_MEDIA, &manifest);
	if (!ret && (bpm_sha256_hex(manifest.data, manifest.len, hex,
				    sizeof(hex)) ||
		     !bpm_digest_matches(sealed_digest, hex)))
		ret = -EKEYREJECTED;
	if (!ret)
		ret = bpm_oci_put_manifest(c, repository, tag, manifest.data,
					   manifest.len, digest, sizeof(digest));
out:
	bpm_buffer_free(&manifest);
	if (ret)
		pr_err("bpm tree append: cannot tag the sealed segment %s",
		       sealed_digest);
	return ret;
}

/*
 * The segment after sealed, whose manifest is sealed_digest, as it
 * starts: at the sealed head, with the history root there.
 */
static int tree_start_segment(const struct tree_publication *sealed,
			      const char *sealed_digest,
			      struct tree_publication *pub)
{
	__u8 root[32];
	int ret;

	*pub = (struct tree_publication){
		.schema = 1,
		.generation = sealed->generation,
		.base_seq = sealed->head_seq,
		.head_seq = sealed->head_seq,
	};
	bpm_copy_string(pub->tree_id, sizeof(pub->tree_id), sealed->tree_id);
	bpm_copy_string(pub->segment_manifest_digest,
			sizeof(pub->segment_manifest_digest), sealed_digest);
	ret = tree_history_at(sealed, sealed->head_seq, root);
	if (!ret)
		hex_encode(root, sizeof(root), pub->history_root);
	return ret;
}

/*
 * A new tree's id: the one --tree-id gives, else the package's at stable
 * and the package's with the reference elsewhere, so that a canary tree
 * one key publishes beside stable does not take stable's id, which an
 * append checks to tell the two apart.
 */
static int tree_new_id(const char *tree_id, const char *package,
		       const char *reference, char *out, size_t cap)
{
	if (tree_id)
		return strscpy(out, tree_id, cap) < 0 ? -E2BIG : 0;
	if (!strcmp(reference, "stable"))
		return strscpy(out, package, cap) < 0 ? -E2BIG : 0;
	if (strsprintf(out, cap, "%s-%s", package, reference) < 0 ||
	    !bpm_package_name_ok(out)) {
		pr_err("bpm tree append: %s-%s is no tree id; name the tree with --tree-id",
		       package, reference);
		return -EINVAL;
	}
	return 0;
}

#define TREE_APPEND_DOWNLOAD	"/tmp/shirudo-bpm-append-XXXXXX"

/* One bpm tree append, filled in by its steps in turn. */
struct tree_append {
	const char		*package;
	const char		*package_digest;
	const char		*package_file;
	char			download[sizeof(TREE_APPEND_DOWNLOAD)];
	bool			downloaded;
	const char		*raw_repository;
	const char		*keys_dir_arg;
	const char		*key;
	const char		*cert;
	const char		*previous_cert;
	const char		*tree_id;
	const char		*reference;
	int			segment_ops;
	bool			unload;
	char			key_path[PATH_MAX];
	char			cert_path[PATH_MAX];
	char			repo_ref[BPM_MAX_ENDPOINT];
	struct bpm_package_info	info;
	__u8			*beefile;
	size_t			beefile_len;
	char			package_dir[101];
	struct bpm_build_spec	*spec;
	size_t			entries;
	struct bpm_oci_client	c;
	char			repository[BPM_MAX_ENDPOINT];
	struct bpm_buffer	previous;
	char			parent[BPM_MAX_DIGEST];
	struct tree_publication	pub;
	struct tree_publication	*sealed;
	struct bpm_fixes	*fixes;
	size_t			n_fixes;
	struct tree_operation	*op;
	struct tree_xdp_classes	*seen;
	struct tree_upload	*uploads;
	int			appended;
	char			*payload;
	size_t			payload_len;
	__u8			*sig;
	size_t			sig_len;
};

static bool package_digest_ok(const char *digest)
{
	char canonical[SHA256_DIGEST_STR_SIZE];
	__u8 raw[CRYPTO_SHA256_LEN];

	if (sha256_digest_decode(digest, raw))
		return false;
	sha256_digest_encode(raw, canonical);
	return !strcmp(digest, canonical);
}

/*
 * 0, or EXIT_USAGE for a usage error, reported, or OPT_DONE where help
 * or the option list was printed.
 */
static int tree_append_parse(struct tree_append *ta, int argc,
			     const char **argv)
{
	int opt, op_delete = false;
	struct opt_parser p;
	__u64 n_ops;

	OPT_INIT(&p, "bpm tree append", tree_append_opts, &tree_append_help,
		 argc, argv, 2);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case TREE_APPEND_KEYS_DIR:
			ta->keys_dir_arg = p.value;
			break;
		case TREE_APPEND_KEY:
			ta->key = p.value;
			break;
		case TREE_APPEND_CERT:
			ta->cert = p.value;
			break;
		case TREE_APPEND_PREVIOUS_CERT:
			ta->previous_cert = p.value;
			break;
		case TREE_APPEND_TREE_ID:
			if (!bpm_package_name_ok(p.value)) {
				opt_usage(&p, "invalid --tree-id %s", p.value);
				return EXIT_USAGE;
			}
			ta->tree_id = p.value;
			break;
		case TREE_APPEND_REFERENCE:
			ta->reference = p.value;
			break;
		case TREE_APPEND_OP:
			if (OPT_CHOICE(&p, tree_append_ops, &op_delete))
				return EXIT_USAGE;
			break;
		case TREE_APPEND_SEGMENT_OPS:
			if (opt_u64(&p, 1, TREE_MAX_OPS, &n_ops))
				return EXIT_USAGE;
			ta->segment_ops = (int)n_ops;
			break;
		case TREE_APPEND_PACKAGE_DIGEST:
			if (!package_digest_ok(p.value)) {
				opt_usage(&p, "--package-digest %s is not sha256:<64 lowercase hex>",
					  p.value);
				return EXIT_USAGE;
			}
			ta->package_digest = p.value;
			break;
		case OPT_ARG:
			if (ta->raw_repository) {
				opt_usage(&p, "unexpected argument '%s'",
					  p.value);
				return EXIT_USAGE;
			}
			if (ta->package)
				ta->raw_repository = p.value;
			else
				ta->package = p.value;
			break;
		case OPT_DONE:
			return OPT_DONE;
		default:
			return EXIT_USAGE;
		}
	}
	if (!ta->package || !ta->raw_repository) {
		opt_usage(&p, "takes <package-file> and <repository>");
		return EXIT_USAGE;
	}
	if (!!str_has_prefix(ta->package, "oci://") != !!ta->package_digest) {
		opt_usage(&p, "--package-digest names the manifest of an oci:// package, and one needs it");
		return EXIT_USAGE;
	}
	ta->unload = op_delete;
	return 0;
}

static int tree_append_signing_keys(struct tree_append *ta)
{
	if (!ta->key || !ta->cert) {
		const char *keys_dir = keys_dir_resolve(ta->keys_dir_arg);

		if (!ta->key) {
			if (format_key_path(ta->key_path, sizeof(ta->key_path),
					    keys_dir, SIGNING_KEY_FILE))
				return -EINVAL;
			ta->key = ta->key_path;
		}
		if (!ta->cert) {
			if (format_key_path(ta->cert_path,
					    sizeof(ta->cert_path), keys_dir,
					    CERT_FILE))
				return -EINVAL;
			ta->cert = ta->cert_path;
		}
	}
	if (build_check_keys(ta->key, ta->cert))
		return -EACCES;
	if (!ta->previous_cert)
		ta->previous_cert = ta->cert;
	return 0;
}

static int tree_append_trim_repository(struct tree_append *ta)
{
	if (bpm_trim(ta->raw_repository, ta->repo_ref, sizeof(ta->repo_ref))) {
		pr_err("bpm tree append: repository is longer than %zu bytes",
		       sizeof(ta->repo_ref) - 1);
		return -ENAMETOOLONG;
	}
	return 0;
}

static int tree_append_fetch_package(struct tree_append *ta)
{
	int ret;

	ta->package_file = ta->package;
	if (!ta->package_digest)
		return 0;
	memcpy(ta->download, TREE_APPEND_DOWNLOAD, sizeof(ta->download));
	ret = build_download_package("bpm tree append", ta->package,
				     ta->package_digest, ta->download);
	if (ret)
		return ret;
	ta->downloaded = true;
	ta->package_file = ta->download;
	return 0;
}

static int tree_append_read_package(struct tree_append *ta)
{
	int ret;

	ret = bpm_pkg_load_info(ta->package_file, &ta->info);
	if (ret)
		return ret;
	ret = bpm_pkg_read_member_in(ta->package_file, "Beefile", NULL,
				     ta->package_dir, sizeof(ta->package_dir),
				     &ta->beefile, &ta->beefile_len,
				     4u * 1024u * 1024u);
	if (ret) {
		pr_err("bpm tree append: package %s does not include Beefile",
		       ta->package);
		return ret;
	}
	ta->spec = xmalloc(sizeof(*ta->spec));
	if (!ta->spec)
		return -ENOMEM;
	ret = bpm_build_parse_beefile(ta->beefile, ta->beefile_len, ta->spec);
	if (ret) {
		pr_err("bpm tree append: cannot parse the Beefile of %s",
		       ta->package);
		return ret;
	}
	for (size_t i = 0; i < ta->spec->n_upatches; i++)
		ta->entries += ta->spec->upatches[i].tree.present;
	return 0;
}

static int tree_append_seal_if_full(struct tree_append *ta)
{
	if (ta->pub.n_operations >= ta->segment_ops ||
	    (size_t)ta->pub.n_operations + ta->entries > TREE_MAX_OPS) {
		ta->sealed = xmalloc(sizeof(*ta->sealed));
		if (!ta->sealed)
			return -ENOMEM;
		*ta->sealed = ta->pub;
		return tree_start_segment(ta->sealed, ta->parent, &ta->pub);
	}
	return 0;
}

static int tree_append_extend(struct tree_append *ta)
{
	int ret;

	/*
	 * The registry chooses what the reference holds, another tree
	 * the key signs among it: only the operator can say which tree
	 * the signature it is about to make belongs to.
	 */
	if (!ta->tree_id) {
		pr_err("bpm tree append: %s:%s holds tree %s; name the tree to extend with --tree-id",
		       ta->repo_ref, ta->reference, ta->pub.tree_id);
		return -EINVAL;
	}
	if (strcmp(ta->pub.tree_id, ta->tree_id)) {
		pr_err("bpm tree append: %s:%s holds tree %s, not %s; refusing to extend another tree",
		       ta->repo_ref, ta->reference, ta->pub.tree_id,
		       ta->tree_id);
		return -EINVAL;
	}
	ret = tree_publication_verify(&ta->pub, NULL);
	if (ret) {
		pr_err("bpm tree append: the publication at %s:%s does not verify",
		       ta->repo_ref, ta->reference);
		return ret;
	}
	ret = tree_append_seal_if_full(ta);
	if (ret)
		return ret;
	if (check_add_overflow(ta->pub.generation, 1, &ta->pub.generation) ||
	    ta->pub.generation == INT64_MAX) {
		pr_err("bpm tree append: the tree's generation is exhausted");
		return -EOVERFLOW;
	}
	return 0;
}

/* The next generation of the tree at the reference, or a new tree's first. */
static int tree_append_head(struct tree_append *ta)
{
	int ret;

	ret = bpm_oci_parse_push_repo(ta->repo_ref, &ta->c, ta->repository,
				      sizeof(ta->repository));
	if (ret) {
		pr_err("bpm tree append: the repository must be oci://registry/repository");
		return ret;
	}
	ret = bpm_tree_fetch_document(&ta->c, ta->repository, ta->reference,
				      ta->previous_cert, NULL, &ta->previous,
				      ta->parent, sizeof(ta->parent));
	if (!ret)
		ret = tree_parse((const char *)ta->previous.data,
				 ta->previous.len, &ta->pub);
	if (ret == -ENOENT) {
		ta->pub = (struct tree_publication){ .schema = 1,
						     .generation = 1 };
		ta->parent[0] = '\0';
		ret = tree_new_id(ta->tree_id, ta->info.name, ta->reference,
				  ta->pub.tree_id, sizeof(ta->pub.tree_id));
	} else if (ret) {
		pr_err("bpm tree append: cannot read the publication at %s:%s",
		       ta->repo_ref, ta->reference);
	} else {
		ret = tree_append_extend(ta);
	}
	if (ret)
		return ret;
	ta->pub.schema = 1;
	bpm_copy_string(ta->pub.parent_manifest_digest,
			sizeof(ta->pub.parent_manifest_digest), ta->parent);
	return 0;
}

static int tree_append_carry_fixes(struct tree_append *ta)
{
	ta->n_fixes = min_t(size_t, ta->pub.n_operations + ta->spec->n_upatches,
			    TREE_MAX_OPS);
	ta->n_fixes = max(ta->n_fixes, 1U);
	ta->fixes = xcalloc(ta->n_fixes, sizeof(*ta->fixes));
	if (!ta->fixes)
		return -ENOMEM;
	if (ta->previous.data && !ta->sealed &&
	    tree_read_fixes(&ta->previous, &ta->pub, ta->fixes)) {
		pr_err("bpm tree append: the publication at %s:%s has a fixes list bpm tree append would not write, so it cannot carry it into the next generation",
		       ta->repo_ref, ta->reference);
		return -EINVAL;
	}
	return 0;
}

static int tree_operation_start(struct tree_append *ta,
				const struct bpm_build_upatch *u, __s64 seq)
{
	struct tree_operation *op = ta->op;
	int ret;

	tree_selector_free(&op->selector);
	*op = (struct tree_operation){ .seq = seq };
	bpm_copy_string(op->op, sizeof(op->op),
			tree_append_ops[ta->unload].name);
	bpm_copy_string(op->id, sizeof(op->id), u->tree.id);
	if (u->tree.selector) {
		ret = tree_selector_copy(&op->selector, u->tree.selector);
		if (ret)
			return ret;
	}
	tree_selector_canonicalize(&op->selector);
	return 0;
}

static int tree_refuse_xdp_classes(struct tree_append *ta, const char *id,
				   const __u8 *body, size_t body_len,
				   __u32 *classes)
{
	int ret;

	ret = upatch_xdp_classes(body, body_len, classes);
	if (ret)
		pr_err("bpm tree append: %s is not a valid upatch", id);
	else
		ret = tree_refuse_shared_xdp_class(&ta->c, ta->repository,
						   ta->repo_ref, &ta->pub,
						   NULL, ta->seen, ta->op,
						   *classes);
	if (!ret && *classes)
		ret = tree_refuse_sealed_xdp_class(&ta->c, ta->repository,
						   ta->repo_ref,
						   ta->previous_cert,
						   &ta->pub, ta->sealed,
						   ta->op, *classes);
	return ret;
}

static int tree_append_commit(struct tree_append *ta,
			      const struct bpm_build_upatch *u, __u32 classes)
{
	struct tree_publication *pub = &ta->pub;
	struct tree_operation *op = ta->op;
	int ret;

	ret = tree_operation_digest(op, op->operation_digest);
	if (!ret)
		ret = tree_operation_validate(op);
	if (ret) {
		pr_err("bpm tree append: the tree entry of %s makes an operation no target takes",
		       u->tree.id);
		return ret;
	}
	ret = tree_publication_append(pub, op);
	if (ret)
		return ret;
	ta->seen->classes[pub->n_operations - 1] = classes;
	ta->seen->known[pub->n_operations - 1] = true;
	if (!ta->unload)
		ta->fixes[pub->n_operations - 1] = u->tree.fixes;
	pub->head_seq = op->seq;
	ta->appended++;
	return 0;
}

static int tree_append_entry(struct tree_append *ta,
			     const struct bpm_build_upatch *u)
{
	struct tree_upload *up = &ta->uploads[ta->appended];
	const char *member;
	__u8 *body = NULL;
	__u32 classes = 0;
	size_t body_len;
	__s64 seq;
	int ret;

	if (check_add_overflow(ta->pub.head_seq, 1, &seq) ||
	    seq == INT64_MAX) {
		pr_err("bpm tree append: the tree's sequence is exhausted");
		return -EOVERFLOW;
	}
	member = ta->unload ? u->tree.unload_artifact : u->tree.load_artifact;
	ret = bpm_pkg_read_member_in(ta->package_file, member, ta->package_dir,
				     NULL, 0, &body, &body_len,
				     UPATCH_FILE_MAX);
	if (ret) {
		pr_err("bpm tree append: package entry %s not found", member);
		return ret;
	}
	ret = tree_operation_start(ta, u, seq);
	if (!ret && !ta->unload)
		ret = tree_refuse_xdp_classes(ta, u->tree.id, body, body_len,
					      &classes);
	if (!ret)
		ret = tree_describe_artifact(ta->repo_ref, body, body_len,
					     u->tree.id, ta->unload,
					     &ta->op->artifact, up);
	if (ret) {
		xfree(body, body_len + 1);
		return ret;
	}
	up->body = body;
	up->body_len = body_len;
	return tree_append_commit(ta, u, classes);
}

static int tree_append_operations(struct tree_append *ta)
{
	int ret;

	ta->op = xmalloc(sizeof(*ta->op));
	ta->seen = xcalloc(1, sizeof(*ta->seen));
	ta->uploads = xcalloc(BPM_BUILD_MAX_ENTRIES, sizeof(*ta->uploads));
	if (!ta->op || !ta->seen || !ta->uploads)
		return -ENOMEM;
	for (size_t i = 0; i < ta->spec->n_upatches; i++) {
		if (!ta->spec->upatches[i].tree.present)
			continue;
		ret = tree_append_entry(ta, &ta->spec->upatches[i]);
		if (ret)
			return ret;
	}
	if (!ta->appended) {
		pr_err("bpm tree append: %s has no [upatches.tree] entries",
		       ta->package);
		return -ENOENT;
	}
	return 0;
}

static int tree_append_sign(struct tree_append *ta)
{
	struct tree_emit_extra extra = { tree_emit_fixes, ta->fixes };
	int ret;

	ret = tree_emit_publication(&ta->pub, &extra, &ta->payload,
				    &ta->payload_len);
	if (ret)
		return ret;
	return sign_detached(ta->payload, ta->payload_len, ta->key, ta->cert,
			     &ta->sig, &ta->sig_len);
}

static int tree_upload_artifacts(struct tree_append *ta)
{
	int ret;

	for (int i = 0; i < ta->appended; i++) {
		ret = tree_upload_artifact(&ta->c, ta->repository, &ta->uploads[i]);
		if (ret)
			return ret;
	}
	return 0;
}

static int tree_push_document(struct tree_append *ta)
{
	struct bpm_descriptor config, payload_layer, sig_layer;
	char empty_config[] = "{}";
	size_t manifest_len;
	char digest[72];
	char *manifest;
	int ret;

	ret = bpm_oci_push_blob(&ta->c, ta->repository, empty_config,
				strlen(empty_config), BPM_EMPTY_CONFIG_MEDIA,
				&config);
	if (ret)
		return ret;
	ret = bpm_oci_push_blob(&ta->c, ta->repository, ta->payload,
				ta->payload_len, BPM_TREE_MEDIA, &payload_layer);
	if (ret)
		return ret;
	ret = bpm_oci_push_blob(&ta->c, ta->repository, ta->sig, ta->sig_len,
				BPM_TREE_SIG_MEDIA, &sig_layer);
	if (ret)
		return ret;
	manifest = xmalloc(BPM_TREE_MANIFEST_CAP);
	if (!manifest)
		return -ENOMEM;
	ret = bpm_tree_manifest(&payload_layer, &sig_layer, manifest,
				BPM_TREE_MANIFEST_CAP, &manifest_len);
	if (!ret && ta->sealed)
		ret = tree_tag_sealed(&ta->c, ta->repository, ta->parent);
	if (!ret)
		ret = bpm_oci_put_manifest(&ta->c, ta->repository,
					   ta->reference,
					   (const __u8 *)manifest, manifest_len,
					   digest, sizeof(digest));
	if (!ret)
		printf("oci://%s/%s:%s %s\n", ta->c.registry, ta->repository,
		       ta->reference, digest);
	xfree(manifest, BPM_TREE_MANIFEST_CAP);
	return ret;
}

static int tree_append_publish(struct tree_append *ta)
{
	int ret;

	ret = tree_append_sign(ta);
	if (ret)
		return ret;
	/* Nothing is uploaded before all of it is known to be publishable. */
	ret = tree_upload_artifacts(ta);
	if (ret)
		return ret;
	return tree_push_document(ta);
}

static int tree_append_run(struct tree_append *ta)
{
	int ret;

	ret = tree_append_signing_keys(ta);
	if (!ret)
		ret = tree_append_trim_repository(ta);
	if (!ret)
		ret = tree_append_fetch_package(ta);
	if (!ret)
		ret = tree_append_read_package(ta);
	if (!ret)
		ret = tree_append_head(ta);
	if (!ret)
		ret = tree_append_carry_fixes(ta);
	if (!ret)
		ret = tree_append_operations(ta);
	if (!ret)
		ret = tree_append_publish(ta);
	return ret;
}

static void tree_append_free(struct tree_append *ta)
{
	sig_free(ta->sig);
	xfree(ta->payload, ta->payload_len);
	if (ta->op)
		tree_selector_free(&ta->op->selector);
	xfree(ta->op, sizeof(*ta->op));
	xfree(ta->seen, sizeof(*ta->seen));
	for (size_t i = 0; ta->uploads && i < BPM_BUILD_MAX_ENTRIES; i++) {
		xfree(ta->uploads[i].manifest, BPM_MANIFEST_CAP);
		xfree(ta->uploads[i].body, ta->uploads[i].body_len + 1);
	}
	xfree(ta->uploads, BPM_BUILD_MAX_ENTRIES * sizeof(*ta->uploads));
	xfree(ta->fixes, ta->n_fixes * sizeof(*ta->fixes));
	bpm_buffer_free(&ta->previous);
	tree_publication_free(&ta->pub);
	tree_publication_free(ta->sealed);
	xfree(ta->sealed, sizeof(*ta->sealed));
	bpm_build_spec_free(ta->spec);
	xfree(ta->beefile, ta->beefile_len + 1);
	xfree(ta->info.cert, ta->info.cert_len + 1);
	bpm_oci_client_clear(&ta->c);
	if (ta->downloaded)
		unlink(ta->download);
}

static int cmd_bpm_tree_append(int argc, const char **argv)
{
	struct tree_append ta = {
		.reference = "stable",
		.segment_ops = TREE_SEGMENT_OPS,
	};
	int ret;

	ret = tree_append_parse(&ta, argc, argv);
	/* OPT_DONE is -ESRCH, an error a later step can return. */
	if (ret)
		return ret == OPT_DONE ? 0 : ret;
	ret = tree_append_run(&ta);
	tree_append_free(&ta);
	return ret;
}

enum push_opt {
	PUSH_KEYS_DIR,
	PUSH_INDEX_CERT,
	PUSH_INDEX_KEY,
	PUSH_NEW_INDEX,
};

static const struct opt_spec push_opts[] = {
	[PUSH_KEYS_DIR] = { "--keys-dir", 0, 0, "<dir>",
		"sign the index entry with signing_key.pem and cert.der there" },
	[PUSH_INDEX_CERT] = { "--index-cert", 0, 0, "<cert.der>",
		"the index certificate, with --index-key" },
	[PUSH_INDEX_KEY] = { "--index-key", 0, 0, "<signing_key.pem>",
		"the index key, with --index-cert" },
	[PUSH_NEW_INDEX] = { "--new-index", 0, 0, NULL,
		"start the index of a namespace that has none" },
};

static const struct help_section push_sections[] = {
	HELP_OPTIONS("options:", push_opts),
};

static const struct help push_help = {
	.usage	    = "shirudo bpm push <package-file> <repository> [options]",
	.summary    = "Publish a package to an oci:// repository without a tag. "
		      "With signing\nmaterial, the signed index at "
		      "<namespace>/bpm-index:stable gains the\npackage's "
		      "entry; without it, only the package is published. A "
		      "namespace\nwithout an index is refused unless "
		      "--new-index starts one, which is\nrefused where an "
		      "index exists.",
	.sections   = push_sections,
	.n_sections = ARRAY_SIZE(push_sections),
	.footer	    = "Examples:\n"
		      "  shirudo bpm push ./package.bee "
		      "oci://quay.io/namespace/package\n"
		      "  shirudo bpm push ./package.bee "
		      "oci://quay.io/namespace/package \\\n"
		      "      --keys-dir /var/lib/shirudo/keys",
};

int build_bpm_push(int argc, const char **argv)
{
	const char *package = NULL, *repository = NULL, *reference = NULL;
	const char *keys_dir_arg = NULL, *index_cert = NULL, *index_key = NULL;
	char cert_path[PATH_MAX], key_path[PATH_MAX];
	bool new_index = false;
	struct opt_parser p;
	int ret, opt;

	OPT_INIT(&p, "bpm push", push_opts, &push_help, argc, argv, 1);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case PUSH_KEYS_DIR:
			keys_dir_arg = p.value;
			break;
		case PUSH_INDEX_CERT:
			index_cert = p.value;
			break;
		case PUSH_INDEX_KEY:
			index_key = p.value;
			break;
		case PUSH_NEW_INDEX:
			new_index = true;
			break;
		case OPT_ARG:
			if (repository) {
				opt_usage(&p, "unexpected argument '%s'",
					  p.value);
				return EXIT_USAGE;
			}
			if (package)
				repository = p.value;
			else
				package = p.value;
			break;
		case OPT_DONE:
			return 0;
		default:
			return EXIT_USAGE;
		}
	}
	if (!package || !repository) {
		opt_usage(&p, "takes <package-file> and <repository>");
		return EXIT_USAGE;
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
		opt_usage(&p, "--index-cert and --index-key must be supplied together");
		return EXIT_USAGE;
	}
	if (new_index && !index_key) {
		opt_usage(&p, "--new-index needs --keys-dir, or --index-cert and --index-key");
		return EXIT_USAGE;
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

int build_bpm_tree(int argc, const char **argv)
{
	int ret;

	if (argc >= 2 && !strcmp(argv[1], "show"))
		return build_bpm_tree_show(argc - 1, argv + 1);
	if (argc < 2 || strcmp(argv[1], "append")) {
		print_help(&tree_append_help);
		return argc >= 2 && is_help(argv[1]) ? 0 : EXIT_USAGE;
	}
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return publish_fail("initialize curl", -EIO);
	ret = cmd_bpm_tree_append(argc, argv);
	curl_global_cleanup();
	if (ret == EXIT_USAGE)
		return EXIT_USAGE;
	return ret ? publish_fail("tree append", ret) : 0;
}
