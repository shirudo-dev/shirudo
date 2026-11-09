// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The target's package manager; build, push and tree append are the
 * operator's and are dispatched to shirudo-build.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include "builtin.h"
#include "util/bpm_oci.h"
#include "util/bpm_package.h"
#include "util/bpm_state.h"
#include "util/bpm_tree.h"
#include "util/bpm_source_config.h"
#include "util/chain.h"
#include "util/crypto.h"
#include "util/eventlog.h"
#include "util/help.h"
#include "util/hex.h"
#include "util/io.h"
#include "util/initrd.h"
#include "util/image_config.h"
#include "util/image_keys.h"
#include "util/keys.h"
#include "util/json.h"
#include "util/log.h"
#include "util/malloc.h"
#include "util/paths.h"
#include "util/seal.h"
#include "util/upatch.h"
#include "util/upatch_rodata.h"

struct bpm_source {
	char name[BPM_MAX_NAME];
	char endpoint[BPM_MAX_ENDPOINT];
	char index_repository[BPM_MAX_ENDPOINT];
	char key_file[BPM_MAX_KEY];
};

static int sha256_file_hex(const char *path, char *hex, size_t hex_sz);
static int remove_tree(const char *path);

static int prepare_direct_install(const char *raw, struct bpm_source *source,
				  struct bpm_index_entry *entry)
{
	struct bpm_oci_client c __cleanup(bpm_oci_client_clear) = {};
	struct bpm_descriptor layers[8];
	struct bpm_buffer manifest = {};
	char repository[BPM_MAX_ENDPOINT], tag[BPM_MAX_NAME];
	char package_name[BPM_MAX_NAME] = {};
	char endpoint[BPM_MAX_ENDPOINT];
	char url[PATH_MAX];
	int n_layers, ret;

	ret = bpm_oci_parse_pull_ref(raw, &c, repository, sizeof(repository), tag,
				     sizeof(tag));
	if (ret)
		return ret;
	ret = bpm_oci_url(&c, repository, "manifests", tag, url, sizeof(url));
	if (ret)
		return ret;
	ret = bpm_oci_get_memory(&c, url,
				 "application/vnd.oci.image.manifest.v1+json",
				 &manifest);
	if (ret)
		goto out;
	ret = bpm_oci_parse_manifest(manifest.data, manifest.len, layers,
				     ARRAY_SIZE(layers), &n_layers, package_name,
				     sizeof(package_name));
	if (ret)
		goto out;
	if (!package_name[0]) {
		const char *base = strrchr(repository, '/');

		bpm_copy_string(package_name, sizeof(package_name),
				base ? base + 1 : repository);
	}
	if (!bpm_package_name_ok(package_name)) {
		ret = -EINVAL;
		goto out;
	}
	if (strsprintf(endpoint, sizeof(endpoint), "oci://%s", c.registry) < 0) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	memset(source, 0, sizeof(*source));
	bpm_copy_string(source->name, sizeof(source->name), "direct");
	bpm_copy_string(source->endpoint, sizeof(source->endpoint), endpoint);
	memset(entry, 0, sizeof(*entry));
	bpm_copy_string(entry->name, sizeof(entry->name), package_name);
	bpm_copy_string(entry->version, sizeof(entry->version), tag);
	bpm_copy_string(entry->repository, sizeof(entry->repository), repository);
	/* package_install treats a non-digest reference as a tag. */
	bpm_copy_string(entry->manifest_digest, sizeof(entry->manifest_digest), tag);
	entry->package_size = -1;
	ret = 0;
out:
	bpm_buffer_free(&manifest);
	return ret;
}

/*
 * The registry names the layer without a signature, so its title names
 * the file only when it is a package name ending in .bee: never a path,
 * a hidden file, an option or a terminal control sequence.
 */
static bool bee_title_ok(const char *title)
{
	size_t n = strlen(title);

	return bpm_package_name_ok(title) && name_has_suffix(title, n, ".bee");
}

/*
 * Into the file open on fd at destination, or, without one, a new file
 * in the working directory named after the package. The registry picks
 * that name, so it is created, never an existing file replaced, and
 * opened as output root may ask for: never a sealed file nor one
 * reached through a link.
 */
static int download_package(const char *raw, const char *destination, int fd)
{
	struct bpm_oci_client c __cleanup(bpm_oci_client_clear) = {};
	struct bpm_descriptor layers[8];
	struct bpm_buffer manifest = {};
	char repository[BPM_MAX_ENDPOINT], tag[BPM_MAX_NAME];
	char url[PATH_MAX], filename[PATH_MAX], title[PATH_MAX];
	char digest[65], package_name[BPM_MAX_NAME] = {};
	int n_layers = 0, out = fd, ret;

	ret = bpm_oci_parse_pull_ref(raw, &c, repository, sizeof(repository),
				     tag, sizeof(tag));
	if (ret)
		return ret;
	ret = bpm_oci_url(&c, repository, "manifests", tag, url, sizeof(url));
	if (ret)
		return ret;
	ret = bpm_oci_get_memory(&c, url,
				 "application/vnd.oci.image.manifest.v1+json",
				 &manifest);
	if (ret)
		goto out;
	ret = bpm_oci_parse_manifest(manifest.data, manifest.len, layers,
				     ARRAY_SIZE(layers), &n_layers, package_name,
				     sizeof(package_name));
	if (ret)
		goto out;
	bpm_trim(package_name, package_name, sizeof(package_name));
	for (int i = 0; i < n_layers; i++) {
		if (strcmp(layers[i].media, BPM_PACKAGE_MEDIA))
			continue;
		ret = bpm_oci_url(&c, repository, "blobs", layers[i].digest,
				  url, sizeof(url));
		if (ret)
			goto out;
		/* A cut title would name another file; fall back to the package name. */
		if (bpm_trim(layers[i].title, title, sizeof(title)))
			title[0] = '\0';
		if (destination) {
			bpm_copy_string(filename, sizeof(filename), destination);
		} else if (bee_title_ok(title)) {
			bpm_copy_string(filename, sizeof(filename), title);
		} else {
			const char *base = strrchr(repository, '/');

			base = base ? base + 1 : repository;
			if (package_name[0])
				base = package_name;
			if (!bpm_package_name_ok(base)) {
				ret = -EINVAL;
				goto out;
			}
			if (strsprintf(filename, sizeof(filename), "%s-%s.bee",
				       base, tag) < 0) {
				ret = -ENAMETOOLONG;
				goto out;
			}
		}
		if (!destination) {
			out = seal_output_open(filename,
					       O_WRONLY | O_CREAT | O_EXCL,
					       0644);
			if (out < 0) {
				ret = out;
				goto out;
			}
		}
		ret = bpm_oci_get_file(&c, url, BPM_PACKAGE_MEDIA, out,
				       layers[i].size);
		if (!destination)
			close(out);
		if (!ret && (sha256_file_hex(filename, digest, sizeof(digest)) ||
			     !bpm_digest_matches(layers[i].digest, digest)))
			ret = -EKEYREJECTED;
		if (!ret && layers[i].size >= 0) {
			struct stat st;

			if (stat(filename, &st) || st.st_size != layers[i].size)
				ret = -EKEYREJECTED;
		}
		if (ret && !destination)
			unlink(filename);
		goto out;
	}
	ret = -EINVAL;
out:
	bpm_buffer_free(&manifest);
	return ret;
}

static int pull_package(const char *raw)
{
	return download_package(raw, NULL, -1);
}

static int copy_file_ex(const char *src, const char *dst, mode_t mode,
			bool exclusive)
{
	struct stat in_st, out_st;
	int in, out, ret = 0;
	__u8 buf[65536];
	ssize_t n;

	in = open(src, O_RDONLY | O_CLOEXEC);
	if (in < 0)
		return -errno;
	/* O_TRUNC on a destination that is the source would empty both. */
	if (!fstat(in, &in_st) && !stat(dst, &out_st) &&
	    in_st.st_dev == out_st.st_dev && in_st.st_ino == out_st.st_ino) {
		close(in);
		return exclusive ? -EEXIST : 0;
	}
	out = seal_open(dst, O_WRONLY | O_CREAT |
			(exclusive ? O_EXCL : O_TRUNC), mode);
	if (out < 0) {
		close(in);
		return out;
	}
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		ret = write_complete(out, buf, (size_t)n);
		if (ret)
			break;
	}
	if (n < 0 && !ret)
		ret = -errno;
	if (fsync(out) && !ret)
		ret = -errno;
	close(in);
	close(out);
	if (ret)
		unlink(dst);
	return ret;
}

static int copy_file(const char *src, const char *dst, mode_t mode)
{
	return copy_file_ex(src, dst, mode, false);
}

static int source_path(const char *name, char *out, size_t out_sz)
{
	if (!bpm_name_ok(name))
		return -EINVAL;
	if (strsprintf(out, out_sz, "%s/%s.conf", BPM_REGISTRIES_DIR, name) < 0)
		return -ENAMETOOLONG;
	return 0;
}

/*
 * What comes from the config image is authenticated content, and the
 * host path it is named by in messages is not where it was read from;
 * only a host file has an owner and mode to check.
 */
static int stream_untrusted(FILE *fp, const char *path)
{
	if (image_config_active())
		return 0;
	return check_trusted(fileno(fp), path, false);
}

/* A source's file, from the config image's root when one is active. */
static FILE *source_open(const char *path)
{
	int fd;

	if (!image_config_active())
		return fopen(path, "re");
	fd = image_open_relative(path + 1, O_RDONLY);
	if (fd < 0) {
		errno = -fd;
		return NULL;
	}
	return fdopen(fd, "r");
}

static DIR *registries_opendir(void)
{
	int fd;

	if (!image_config_active())
		return opendir(BPM_REGISTRIES_DIR);
	fd = image_open(IMAGE_REGISTRIES,
			O_RDONLY | O_DIRECTORY);
	if (fd < 0) {
		errno = -fd;
		return NULL;
	}
	return fdopendir(fd);
}

static int source_index_repository_valid(const char *endpoint,
					 const char *repository)
{
	struct bpm_oci_client c __cleanup(bpm_oci_client_clear) = {};
	char raw[PATH_MAX], parsed[BPM_MAX_ENDPOINT];
	const char *name = strrchr(repository, '/');
	int rc;

	if (!name || name == repository ||
	    strcmp(name + 1, BPM_INDEX_REPOSITORY_NAME))
		return -EINVAL;
	if (strsprintf(raw, sizeof(raw), "%s/%s", endpoint, repository) < 0)
		return -ENAMETOOLONG;
	rc = bpm_oci_parse_push_repo(raw, &c, parsed, sizeof(parsed));
	if (rc)
		return rc;
	return strcmp(parsed, repository) ? -EINVAL : 0;
}

static FILE *tree_conf_open(void)
{
	int fd;

	if (!image_config_active())
		return fopen(BPM_TREE_ETC_PATH, "re");
	fd = image_open(IMAGE_TREE_CONF, O_RDONLY);
	if (fd < 0) {
		errno = -fd;
		return NULL;
	}
	return fdopen(fd, "r");
}

static int load_source(const char *name, struct bpm_source *s)
{
	char path[PATH_MAX], *line = NULL;
	size_t capacity = 0;
	int got, ret = 0;
	FILE *fp;

	memset(s, 0, sizeof(*s));
	ret = source_path(name, path, sizeof(path));
	if (ret)
		return ret;
	fp = source_open(path);
	if (!fp)
		return -errno;
	if (stream_untrusted(fp, path)) {
		fclose(fp);
		return -EPERM;
	}
	if (strscpy(s->name, name, sizeof(s->name)) < 0)
		ret = -ENAMETOOLONG;
	while (!ret && (got = read_text_line(fp, &line, &capacity,
					     PATH_MAX - 1)) != 0) {
		ret = got < 0 ? got :
		     bpm_parse_source_line(line,
					   s->endpoint, sizeof(s->endpoint),
					   s->index_repository,
					   sizeof(s->index_repository),
					   s->key_file, sizeof(s->key_file));
	}
	libc_free(line);
	fclose(fp);
	if (ret)
		return ret;
	if (!s->endpoint[0] || !s->key_file[0])
		return -EINVAL;
	if (!s->index_repository[0] &&
	    strsprintf(s->index_repository, sizeof(s->index_repository),
		       "%s/%s", s->name, BPM_INDEX_REPOSITORY_NAME) < 0)
		return -E2BIG;
	ret = source_index_repository_valid(s->endpoint,
					    s->index_repository);
	if (ret)
		return ret;
	/* With a config image the key file is the image's, named from its root. */
	if (image_config_active()) {
		if (!strncmp(s->key_file, "/etc/shirudo/bpm/keys/", 22))
			memmove(s->key_file, s->key_file + 1,
				strlen(s->key_file));
		if (s->key_file[0] == '/' || strstr(s->key_file, ".."))
			return -EINVAL;
	}
	return 0;
}

static int verify_with_source_key(const struct bpm_source *s,
				  const __u8 *data, size_t len,
				  const __u8 *sig, size_t sig_len)
{
	int fd, ret;

	if (!image_config_active())
		return bpm_verify_cms(data, len, sig, sig_len, s->key_file);
	fd = image_open_relative(s->key_file, O_RDONLY);
	if (fd < 0)
		return fd;
	ret = bpm_verify_cms_fd(data, len, sig, sig_len, fd);
	close(fd);
	return ret;
}

static int save_source(const struct bpm_source *s)
{
	char path[PATH_MAX], data[PATH_MAX * 2];
	int ret = source_path(s->name, path, sizeof(path));

	if (ret)
		return ret;
	if (strsprintf(data, sizeof(data),
		       "endpoint = %s\nindex_repository = %s\nkey_file = %s\n",
		       s->endpoint, s->index_repository, s->key_file) < 0)
		return -E2BIG;
	return seal_write_file(path, data, strlen(data), 0644);
}

static int with_bpm_lock(void)
{
	int ret;

	ret = seal_mkdir_p(LOCKS_DIR, 0700);
	return ret ? ret : seal_lock(BPM_LOCK_PATH);
}

static int bpm_fail(const char *action, int ret)
{
	if (ret < 0)
		pr_err("bpm %s: %s", action, strerror(-ret));
	else
		pr_err("bpm %s failed", action);
	return 1;
}

static int cache_path(const char *source, char *out, size_t sz)
{
	if (!bpm_name_ok(source))
		return -EINVAL;
	if (strsprintf(out, sz, "%s/%s/index.json", BPM_REPOS_DIR, source) < 0)
		return -ENAMETOOLONG;
	return 0;
}

static int sha256_file_hex(const char *path, char *hex, size_t hex_sz)
{
	struct sha256_ctx ctx;
	__u8 digest[CRYPTO_SHA256_LEN];
	__u8 buf[65536];
	ssize_t nr;
	int fd, ret = -EIO;

	if (hex_sz < 65 || sha256_init(&ctx) != 0)
		return -EINVAL;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		sha256_free(&ctx);
		return -errno;
	}
	while ((nr = read(fd, buf, sizeof(buf))) > 0) {
		if (sha256_update(&ctx, buf, (size_t)nr) != 0)
			goto done;
	}
	if (nr < 0 || sha256_final(&ctx, digest) != 0)
		goto done;
	hex_encode(digest, sizeof(digest), hex);
	ret = 0;
done:
	close(fd);
	sha256_free(&ctx);
	return ret;
}

static int print_package_readme(const char *source)
{
	char temporary[] = "/tmp/shirudo-bpm-info-XXXXXX";
	size_t beefile_len = 0, readme_len = 0;
	__u8 *beefile = NULL, *readme = NULL;
	const char *archive = source;
	char package_dir[101];
	int fd, ret;

	if (!strncmp(source, "oci://", 6)) {
		fd = mkstemp(temporary);
		if (fd < 0)
			return -errno;
		archive = temporary;
		ret = download_package(source, archive, fd);
		close(fd);
		if (ret)
			goto out;
	}
	ret = bpm_pkg_read_member_in(archive, "Beefile", NULL, package_dir,
				     sizeof(package_dir), &beefile, &beefile_len,
				     4u * 1024u * 1024u);
	if (ret) {
		if (ret == -ENOENT)
			pr_err("bpm info: package %s does not include Beefile", source);
		goto out;
	}
	ret = bpm_pkg_read_member_in(archive, "README.md", package_dir, NULL, 0,
				     &readme, &readme_len, 4u * 1024u * 1024u);
	if (ret) {
		if (ret == -ENOENT)
			pr_err("bpm info: package %s does not include README.md", source);
		goto out;
	}
	text_sanitize((char *)readme, readme_len, true);
	ret = write_complete(STDOUT_FILENO, readme, readme_len);
out:
	xfree(beefile, beefile_len + 1);
	xfree(readme, readme_len + 1);
	if (archive == temporary)
		unlink(temporary);
	return ret;
}

struct bpm_upatches_ctx {
	bool all;
	char *list;
	size_t len;
	size_t cap;
};

static int print_upatch_member(void *ctx, const char *member, char type)
{
	struct bpm_upatches_ctx *opts = ctx;
	static const char prefix[] = "upatches/";
	size_t len = strlen(member), need, cap;
	enum bpm_upatch_member kind;
	const char *base;
	char *next;

	if (type != '0' || strncmp(member, prefix, sizeof(prefix) - 1))
		return 0;
	base = member + sizeof(prefix) - 1;
	if (strchr(base, '/'))
		return 0;
	kind = bpm_upatch_member(base, strlen(base));
	if (kind == BPM_UPATCH_OTHER ||
	    (!opts->all && kind == BPM_UPATCH_UNLOAD))
		return 0;
	if (check_add_overflow(opts->len, len, &need) ||
	    check_add_overflow(need, 1, &need))
		return -EOVERFLOW;
	if (need > opts->cap) {
		cap = opts->cap ? opts->cap : 4096;
		while (cap < need) {
			if (cap > JSON_MAX_BYTES / 2) {
				cap = JSON_MAX_BYTES;
				break;
			}
			cap *= 2;
		}
		if (cap < need)
			return -E2BIG;
		next = xreallocarray(opts->list, opts->cap, cap, 1);
		if (!next)
			return -ENOMEM;
		opts->list = next;
		opts->cap = cap;
	}
	memcpy(opts->list + opts->len, member, len);
	text_sanitize(opts->list + opts->len, len, false);
	opts->list[opts->len + len] = '\n';
	opts->len = need;
	return 0;
}

static int bpm_info_archive(const char *source, char temporary[])
{
	int fd, ret;

	if (strncmp(source, "oci://", 6))
		return 0;
	fd = mkstemp(temporary);
	if (fd < 0)
		return -errno;
	ret = download_package(source, temporary, fd);
	close(fd);
	if (ret)
		unlink(temporary);
	return ret;
}

static int print_package_upatches(const char *source, bool all)
{
	char temporary[] = "/tmp/shirudo-bpm-upatches-XXXXXX";
	size_t beefile_len = 0;
	__u8 *beefile = NULL;
	const char *archive = source;
	char package_dir[101];
	struct bpm_upatches_ctx ctx = { .all = all };
	int ret = 0;

	ret = bpm_info_archive(source, temporary);
	if (ret)
		return ret;
	if (!strncmp(source, "oci://", 6))
		archive = temporary;
	ret = bpm_pkg_read_member_in(archive, "Beefile", NULL, package_dir,
				     sizeof(package_dir), &beefile, &beefile_len,
				     4u * 1024u * 1024u);
	if (!ret)
		ret = bpm_pkg_visit_members(archive, package_dir,
					    print_upatch_member, &ctx);
	if (!ret && ctx.len)
		ret = write_complete(STDOUT_FILENO, ctx.list, ctx.len);
	if (ret == -ENOENT)
		pr_err("bpm info upatches: package %s does not include Beefile",
		       source);
	xfree(beefile, beefile_len + 1);
	xfree(ctx.list, ctx.cap);
	if (archive == temporary)
		unlink(temporary);
	return ret;
}

static int print_package_upatch_data(const char *source, const char *member,
				     bool json)
{
	char temporary[] = "/tmp/shirudo-bpm-data-XXXXXX";
	size_t beefile_len = 0, upatch_len = 0;
	__u8 *beefile = NULL, *bytes = NULL;
	const char *archive = source;
	char package_dir[101];
	struct upatch u = {};
	int ret;

	if (!bpm_archive_rel_ok(member) || strncmp(member, "upatches/", 9) ||
	    strchr(member + 9, '/') ||
	    bpm_upatch_member(member + 9, strlen(member + 9)) ==
	    BPM_UPATCH_OTHER)
		return -EINVAL;
	ret = bpm_info_archive(source, temporary);
	if (ret)
		return ret;
	if (!strncmp(source, "oci://", 6))
		archive = temporary;
	ret = bpm_pkg_read_member_in(archive, "Beefile", NULL, package_dir,
				     sizeof(package_dir), &beefile, &beefile_len,
				     4u * 1024u * 1024u);
	if (ret) {
		if (ret == -ENOENT)
			pr_err("bpm info data: package %s does not include Beefile",
			       source);
		goto out;
	}
	ret = bpm_pkg_read_member_in(archive, member, package_dir, NULL, 0,
				     &bytes, &upatch_len,
				     UPATCH_FILE_MAX);
	if (ret) {
		if (ret == -ENOENT)
			pr_err("bpm info data: package %s has no member %s",
			       source, member);
		goto out;
	}
	ret = upatch_open_memory(bytes, upatch_len, &u);
	if (ret) {
		pr_err("bpm info data: %s is not a valid upatch", member);
		goto out;
	}
	if (upatch_is_unload(&u)) {
		pr_err("bpm info data: %s is an unload directive", member);
		ret = -EINVAL;
		goto out;
	}
	ret = upatch_rodata_print(&u, member, json);
	if (ret == -ENODATA)
		pr_err("bpm info data: %s has no loader .rodata map data", member);
	else if (ret == -ENOENT || ret == -EOPNOTSUPP)
		pr_err("bpm info data: %s has no supported BTF .rodata data", member);
	else if (ret == -EINVAL)
		pr_err("bpm info data: cannot decode .rodata in %s", member);
out:
	upatch_close(&u);
	xfree(beefile, beefile_len + 1);
	xfree(bytes, upatch_len + 1);
	if (archive == temporary)
		unlink(temporary);
	return ret;
}

static int cert_matches_active(const char *path)
{
	struct cert a = {}, b = {};
	__u8 da[CRYPTO_SHA256_LEN], db[CRYPTO_SHA256_LEN];
	int ret = -EINVAL;

	if (!cert_read_file(path, &a) &&
	    !cert_read_file(CERT_PATH, &b) &&
	    !cert_pubkey_digest(&a, da) &&
	    !cert_pubkey_digest(&b, db) &&
	    !memcmp(da, db, sizeof(da)))
		ret = 0;
	cert_free(&a);
	cert_free(&b);
	return ret;
}

static int key_file_fingerprint(const char *path, char hex[65])
{
	struct cert cert = {};
	__u8 digest[CRYPTO_SHA256_LEN];
	int ret;

	ret = cert_read_file(path, &cert);
	if (!ret)
		ret = cert_pubkey_digest(&cert, digest);
	cert_free(&cert);
	if (ret)
		return ret;
	hex_encode(digest, sizeof(digest), hex);
	return 0;
}

static int install_key_file(const char *src)
{
	char hex[65], dst[PATH_MAX];
	bool active, made = false;
	struct stat st;
	int ret;

	ret = key_file_fingerprint(src, hex);
	if (ret)
		return ret;
	ret = seal_mkdir_p(KEYS_DIR, 0700);
	if (ret)
		return ret;
	active = lstat(CERT_PATH, &st) == 0;
	if (!active && errno != ENOENT)
		return -errno;
	if (active && cert_matches_active(src))
		return -EPERM;
	if (strsprintf(dst, sizeof(dst), "%s/%s.der", KEYS_DIR,
		       hex) < 0)
		return -ENAMETOOLONG;
	if (lstat(dst, &st) == 0) {
		char existing[65];

		if (!S_ISREG(st.st_mode) || key_file_fingerprint(dst, existing) ||
		    strcmp(existing, hex))
			return -EKEYREJECTED;
	} else {
		if (errno != ENOENT)
			return -errno;
		ret = copy_file_ex(src, dst, 0644, true);
		if (ret)
			return ret;
		made = true;
	}
	if (active)
		return 0;
	if (symlink(dst, CERT_PATH)) {
		if (errno != EEXIST) {
			ret = -errno;
			goto undo;
		}
		ret = cert_matches_active(src) ? -EPERM : 0;
		goto undo;
	}
	ret = seal_inherit_path(CERT_PATH);
undo:
	if (ret && made)
		unlink(dst);
	return ret;
}

static int extract_package_cert(const char *archive, char *out, size_t out_sz)
{
	char tmp[] = "/tmp/shirudo-bpm-cert-XXXXXX";
	__u8 *body = NULL;
	size_t len = 0;
	int fd, ret;

	ret = bpm_pkg_read_member(archive, "cert.der", &body, &len, 1024 * 1024);
	if (ret)
		return ret;
	if (sizeof(tmp) > out_sz) {
		xfree(body, len + 1);
		return -ENAMETOOLONG;
	}
	fd = mkstemp(tmp);
	if (fd < 0) {
		xfree(body, len + 1);
		return -errno;
	}
	ret = write_complete(fd, body, len);
	if (close(fd) && !ret)
		ret = -errno;
	xfree(body, len + 1);
	if (ret)
		unlink(tmp);
	else
		bpm_copy_string(out, out_sz, tmp);
	return ret;
}

static int key_source_file(const char *source, char *temp, size_t temp_sz)
{
	char archive[] = "/tmp/shirudo-bpm-key-XXXXXX";
	size_t len = strlen(source);
	int fd, ret;

	if (!strncmp(source, "oci://", 6)) {
		fd = mkstemp(archive);
		if (fd < 0)
			return -errno;
		ret = download_package(source, archive, fd);
		close(fd);
		if (!ret)
			ret = extract_package_cert(archive, temp, temp_sz);
		unlink(archive);
		return ret;
	}
	if (name_has_suffix(source, len, ".bee"))
		return extract_package_cert(source, temp, temp_sz);
	return 0;
}

static int key_fingerprint_compare(const void *a, const void *b)
{
	return strcmp(*(char * const *)a, *(char * const *)b);
}

static int list_keys(bool json)
{
	char **fingerprints = NULL;
	size_t count = 0, cap = 0;
	struct dirent *entry;
	DIR *dir;
	int ret = 0;

	dir = opendir(KEYS_DIR);
	if (!dir && errno != ENOENT)
		return -errno;
	while (dir) {
		char path[PATH_MAX], hex[65], **next;
		struct stat st;
		bool valid = true;

		errno = 0;
		entry = readdir(dir);
		if (!entry) {
			ret = -errno;
			break;
		}
		if (strlen(entry->d_name) != 68 ||
		    strcasecmp(entry->d_name + 64, ".der"))
			continue;
		for (size_t i = 0; i < 64; i++) {
			if (!isxdigit((__u8)entry->d_name[i]))
				valid = false;
		}
		if (!valid || strsprintf(path, sizeof(path), "%s/%s",
					 KEYS_DIR, entry->d_name) < 0)
			continue;
		if (lstat(path, &st) || !S_ISREG(st.st_mode) ||
		    key_file_fingerprint(path, hex) ||
		    strncasecmp(entry->d_name, hex, 64))
			continue;
		next = xreallocarray(fingerprints, cap, count + 1,
				     sizeof(*next));
		if (!next) {
			ret = -ENOMEM;
			break;
		}
		fingerprints = next;
		cap = count + 1;
		fingerprints[count] = xstrdup(hex);
		if (!fingerprints[count]) {
			ret = -ENOMEM;
			break;
		}
		count++;
	}
	if (dir)
		closedir(dir);
	if (!ret && count)
		qsort(fingerprints, count, sizeof(*fingerprints),
		      key_fingerprint_compare);
	if (!ret && json) {
		char buf[8192];
		struct json_emit e = { .buf = buf, .cap = sizeof(buf) };

		json_obj_open(&e);
		json_kv_int(&e, "schema", 1);
		json_arr_open(&e, "fingerprints");
		for (size_t i = 0; i < count; i++)
			json_str(&e, fingerprints[i]);
		json_arr_close(&e);
		json_obj_close(&e);
		if (e.err)
			ret = e.err;
		else
			puts(buf);
	} else if (!ret) {
		printf("Package certificates:\n");
		if (!count)
			printf("  none\n");
		for (size_t i = 0; i < count; i++)
			printf("  %s\n", fingerprints[i]);
	}
	for (size_t i = 0; i < count; i++)
		xstrfree(fingerprints[i]);
	xfree(fingerprints, cap * sizeof(*fingerprints));
	return ret;
}

static int load_cached_index(const char *source, struct bpm_index_entry *entries, int *n)
{
	char path[PATH_MAX];
	__u8 *body;
	size_t len;
	int ret;

	ret = cache_path(source, path, sizeof(path));
	if (ret)
		return ret;
	ret = read_file(path, 64u * 1024u * 1024u, &body, &len);
	if (ret)
		return ret;
	ret = bpm_index_parse(body, len, entries, n);
	xfree(body, len + 1);
	return ret;
}

static int repo_update_one(const char *name)
{
	struct bpm_source s;
	struct bpm_oci_client c __cleanup(bpm_oci_client_clear) = {};
	struct bpm_descriptor layers[8];
	int nl = 0;
	struct bpm_buffer manifest = {}, index = {}, sig = {};
	char url[PATH_MAX], cache[PATH_MAX], dir[PATH_MAX];
	int ret = 0;

	ret = load_source(name, &s);
	if (ret)
		return ret;
	ret = bpm_oci_parse_endpoint(s.endpoint, &c);
	if (ret)
		return ret;
	ret = bpm_oci_url(&c, s.index_repository, "manifests", BPM_INDEX_TAG,
			  url, sizeof(url));
	if (ret)
		return ret;
	ret = bpm_oci_get_memory(&c, url, "application/vnd.oci.image.manifest.v1+json", &manifest);
	if (ret)
		goto out;
	ret = bpm_oci_parse_manifest(manifest.data, manifest.len, layers,
				     ARRAY_SIZE(layers), &nl, NULL, 0);
	if (ret)
		goto out;
	if (nl < 2) {
		ret = -EINVAL;
		goto out;
	}
	for (int i = 0; i < nl; i++) {
		if (!strcmp(layers[i].media, BPM_INDEX_MEDIA)) {
			char layer_hex[65];

			ret = bpm_oci_url(&c, s.index_repository, "blobs",
					  layers[i].digest, url, sizeof(url));
			if (ret)
				goto out;
			ret = bpm_oci_get_blob(&c, url, BPM_INDEX_MEDIA, &index);
			if (!ret)
				ret = bpm_sha256_hex(index.data, index.len, layer_hex,
						     sizeof(layer_hex));
			if (!ret && !bpm_digest_matches(layers[i].digest, layer_hex))
				ret = -EKEYREJECTED;
			break;
		}
	}
	if (ret)
		goto out;
	for (int i = 0; i < nl; i++) {
		if (!strcmp(layers[i].media, BPM_INDEX_SIG_MEDIA)) {
			char sig_hex[65];

			ret = bpm_oci_url(&c, s.index_repository, "blobs",
					  layers[i].digest, url, sizeof(url));
			if (ret)
				goto out;
			ret = bpm_oci_get_blob(&c, url, BPM_INDEX_SIG_MEDIA, &sig);
			if (!ret)
				ret = bpm_sha256_hex(sig.data, sig.len, sig_hex,
						     sizeof(sig_hex));
			if (!ret && !bpm_digest_matches(layers[i].digest, sig_hex))
				ret = -EKEYREJECTED;
			break;
		}
	}
	if (!ret && !sig.data)
		ret = -EINVAL;
	if (ret)
		goto out;
	if (verify_with_source_key(&s, index.data, index.len, sig.data,
				   sig.len)) {
		ret = -EKEYREJECTED;
		goto out;
	}
	{
		struct bpm_index_entry *checked;
		int checked_n = 0;

		checked = xcalloc(BPM_MAX_ENTRIES, sizeof(*checked));
		if (!checked) {
			ret = -ENOMEM;
			goto out;
		}
		ret = bpm_index_parse(index.data, index.len, checked,
				      &checked_n) ? -EINVAL : 0;
		xfree(checked, BPM_MAX_ENTRIES * sizeof(*checked));
		if (ret)
			goto out;
	}
	if (strsprintf(dir, sizeof(dir), "%s/%s", BPM_REPOS_DIR, name) < 0) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	ret = seal_mkdir_p(dir, 0700);
	if (ret)
		goto out;
	ret = cache_path(name, cache, sizeof(cache));
	if (ret)
		goto out;
	ret = seal_write_file(cache, index.data, index.len, 0600);
out:
	bpm_buffer_free(&manifest);
	bpm_buffer_free(&index);
	bpm_buffer_free(&sig);
	return ret;
}

static int find_entry(const struct bpm_index_entry *e, int n, const char *name,
		      const char *version, struct bpm_index_entry *out)
{
	int found = -1;

	for (int i = 0; i < n; i++) {
		if (strcmp(e[i].name, name))
			continue;
		if (version && strcmp(e[i].version, version))
			continue;
		if (found < 0 ||
		    (!version && bpm_semver_compare(e[found].version,
						    e[i].version) < 0))
			found = i;
	}
	if (found < 0)
		return -ENOENT;
	*out = e[found];
	return 0;
}

static int path_compare(const void *left, const void *right)
{
	return strcmp(left, right);
}

/*
 * The old version's unload directives in reverse name order, as
 * uninstall runs them, each kept beside the load it undoes.
 */
static void sort_old_pairs(char (*unloads)[PATH_MAX], char (*loads)[PATH_MAX],
			   int n)
{
	char tmp[PATH_MAX];

	for (int i = 1; i < n; i++) {
		for (int j = i; j > 0 && strcmp(unloads[j - 1], unloads[j]) < 0;
		     j--) {
			memcpy(tmp, unloads[j], PATH_MAX);
			memcpy(unloads[j], unloads[j - 1], PATH_MAX);
			memcpy(unloads[j - 1], tmp, PATH_MAX);
			memcpy(tmp, loads[j], PATH_MAX);
			memcpy(loads[j], loads[j - 1], PATH_MAX);
			memcpy(loads[j - 1], tmp, PATH_MAX);
		}
	}
}

#define INSTALL_PATHS_MAX	128

static int package_install(const struct bpm_source *s, const struct bpm_index_entry *entry,
			   const char *old_path, const char *old_version)
{
	struct bpm_oci_client c __cleanup(bpm_oci_client_clear) = {};
	struct bpm_descriptor layers[8];
	int nl = 0;
	struct bpm_buffer manifest = {};
	char url[PATH_MAX], archive[PATH_MAX] = {}, dir[PATH_MAX], package_dir[PATH_MAX];
	char digest[65];
	int fd, ret;
	DIR *d;
	struct dirent *de;
	bool found_package = false, extracted = false;
	char (*loaded)[PATH_MAX], (*old_loads)[PATH_MAX], (*old_unloads)[PATH_MAX];
	int nloaded = 0, nactive = 0, nold = 0, nold_removed = 0;

	/* 1.5 MiB of paths, which a stack frame should not carry. */
	loaded = xcalloc(3 * INSTALL_PATHS_MAX, PATH_MAX);
	if (!loaded)
		return -ENOMEM;
	old_loads = loaded + INSTALL_PATHS_MAX;
	old_unloads = old_loads + INSTALL_PATHS_MAX;
	ret = bpm_oci_parse_endpoint(s->endpoint, &c);
	if (ret)
		goto out;
	ret = bpm_oci_url(&c, entry->repository[0] ? entry->repository : entry->name,
			  "manifests", entry->manifest_digest, url, sizeof(url));
	if (ret)
		goto out;
	ret = bpm_oci_get_memory(&c, url, "application/vnd.oci.image.manifest.v1+json", &manifest);
	if (ret)
		goto out;
	/*
	 * Repository indexes carry a sha256 manifest digest; direct OCI
	 * references carry the tag in this field and cannot be digest-checked.
	 */
	if (!strncmp(entry->manifest_digest, "sha256:", 7)) {
		char manifest_hex[65];

		if (bpm_sha256_hex(manifest.data, manifest.len, manifest_hex,
				   sizeof(manifest_hex)) ||
		    !bpm_digest_matches(entry->manifest_digest, manifest_hex)) {
			ret = -EKEYREJECTED;
			goto out;
		}
	}
	ret = bpm_oci_parse_manifest(manifest.data, manifest.len, layers,
				     ARRAY_SIZE(layers), &nl, NULL, 0);
	if (ret)
		goto out;
	for (int i = 0; i < nl; i++) {
		if (strcmp(layers[i].media, BPM_PACKAGE_MEDIA))
			continue;
		found_package = true;
		if (entry->package_digest[0] && strcmp(entry->package_digest, layers[i].digest)) {
			ret = -EKEYREJECTED;
			goto out;
		}
		if (entry->package_size > 0 && entry->package_size != layers[i].size) {
			ret = -EKEYREJECTED;
			goto out;
		}
		ret = bpm_oci_url(&c, entry->repository[0] ? entry->repository : entry->name,
				  "blobs", layers[i].digest, url, sizeof(url));
		if (ret)
			goto out;
		if (strsprintf(dir, sizeof(dir), "%s/%s", BPM_PACKAGES_DIR,
			       entry->name) < 0) {
			ret = -ENAMETOOLONG;
			goto out;
		}
		ret = seal_mkdir_p(dir, 0700);
		if (ret)
			goto out;
		if (strsprintf(package_dir, sizeof(package_dir), "%s/%s", dir,
			       entry->version) < 0) {
			ret = -ENAMETOOLONG;
			goto out;
		}
		ret = seal_mkdir_p(BPM_STAGING_DIR, 0700);
		if (ret)
			goto out;
		if (strsprintf(archive, sizeof(archive), "%s/%s-%s.bee",
			       BPM_STAGING_DIR, entry->name,
			       entry->version) < 0) {
			ret = -ENAMETOOLONG;
			goto out;
		}
		fd = seal_open(archive, O_WRONLY | O_CREAT | O_TRUNC |
			       O_NOFOLLOW, 0600);
		if (fd < 0) {
			ret = fd;
			goto out;
		}
		ret = bpm_oci_get_file(&c, url, BPM_PACKAGE_MEDIA, fd,
				       layers[i].size);
		close(fd);
		if (ret) {
			unlink(archive);
			goto out;
		}
		if (sha256_file_hex(archive, digest, sizeof(digest)) ||
		    !bpm_digest_matches(layers[i].digest, digest)) {
			ret = -EKEYREJECTED;
			goto out;
		}
		if (access(package_dir, F_OK) == 0) {
			ret = -EEXIST;
			goto out;
		}
		extracted = true;
		ret = bpm_pkg_extract(archive, package_dir);
		if (ret)
			goto out;
		{
			char cert[PATH_MAX];

			if (strsprintf(cert, sizeof(cert), "%s/cert.der",
				       package_dir) < 0) {
				ret = -ENAMETOOLONG;
				goto out;
			}
			if (cert_matches_active(cert)) {
				ret = -EKEYREJECTED;
				goto out;
			}
		}
		{
			char updir[PATH_MAX];

			if (strsprintf(updir, sizeof(updir), "%s/upatches",
				       package_dir) < 0) {
				ret = -ENAMETOOLONG;
				goto out;
			}
			d = opendir(updir);
			if (!d) {
				ret = -errno;
				goto out;
			}
		}
		while ((de = readdir(d))) {
			char up[PATH_MAX];
			struct stat st;

			if (bpm_upatch_member(de->d_name, strlen(de->d_name)) !=
			    BPM_UPATCH_LOAD)
				continue;
			if (strsprintf(up, sizeof(up), "%s/upatches/%s", package_dir,
				       de->d_name) < 0) {
				ret = -ENAMETOOLONG;
				break;
			}
			if (stat(up, &st) || !S_ISREG(st.st_mode))
				continue;
			if (nloaded >= INSTALL_PATHS_MAX) {
				ret = -E2BIG;
				break;
			}
			strscpy(loaded[nloaded], up, sizeof(loaded[nloaded]));
			nloaded++;
		}
		closedir(d);
		if (ret || !nloaded) {
			if (!ret)
				ret = -EINVAL;
			goto out;
		}
		/* Measured in name order, not in the file system's. */
		qsort(loaded, (size_t)nloaded, sizeof(loaded[0]), path_compare);
		if (old_path && old_path[0]) {
			char olddir[PATH_MAX];

			if (strsprintf(olddir, sizeof(olddir), "%s/upatches",
				       old_path) < 0) {
				ret = -ENAMETOOLONG;
				goto out;
			}
			d = opendir(olddir);
			if (d) {
				while ((de = readdir(d))) {
					size_t len = strlen(de->d_name);
					char load[NAME_MAX + 1];

					if (bpm_upatch_member(de->d_name, len) !=
					    BPM_UPATCH_UNLOAD || nold >= INSTALL_PATHS_MAX)
						continue;
					if (bpm_upatch_pair(de->d_name, len, load,
							    sizeof(load)) ||
					    strsprintf(old_unloads[nold],
						       sizeof(old_unloads[nold]), "%s/%s",
						       olddir, de->d_name) < 0 ||
					    strsprintf(old_loads[nold],
						       sizeof(old_loads[nold]), "%s/%s",
						       olddir, load) < 0) {
						ret = -ENAMETOOLONG;
						break;
					}
					nold++;
				}
				closedir(d);
			}
			sort_old_pairs(old_unloads, old_loads, nold);
			for (int old_i = 0; old_i < nold; old_i++) {
				if (upatch_remove(old_unloads[old_i])) {
					ret = -EIO;
					for (int restore_i = nold_removed - 1;
					     restore_i >= 0; restore_i--)
						upatch_install(old_loads[restore_i]);
					goto out;
				}
				nold_removed++;
			}
		}
		for (int loaded_i = 0; loaded_i < nloaded; loaded_i++) {
			if (upatch_install(loaded[loaded_i])) {
				ret = -EIO;
				goto rollback;
			}
			nactive++;
		}
		{
			char saved[PATH_MAX];

			if (strsprintf(saved, sizeof(saved), "%s/%s-%s.bee", dir,
				       entry->name, entry->version) < 0 ||
			    rename(archive, saved)) {
				pr_warn("bpm: cannot keep %s; dropping it",
					archive);
				unlink(archive);
			}
		}
		break;
	}
	if (!ret && !found_package)
		ret = -EINVAL;
	goto out;
rollback:
	for (int active_i = nactive - 1; active_i >= 0; active_i--) {
		const char *base = strrchr(loaded[active_i], '/');
		char unload[PATH_MAX], name[NAME_MAX + 1];

		if (!base ||
		    bpm_upatch_pair(base + 1, strlen(base + 1), name,
				    sizeof(name)) ||
		    strsprintf(unload, sizeof(unload), "%.*s/%s",
			       (int)(base - loaded[active_i]), loaded[active_i],
			       name) < 0)
			continue;
		upatch_remove(unload);
	}
	for (int restore_i = nold - 1; restore_i >= 0; restore_i--)
		upatch_install(old_loads[restore_i]);
out:
	bpm_buffer_free(&manifest);
	if (ret && archive[0])
		unlink(archive);
	/* What failed to install must not block the next attempt. */
	if (ret && extracted)
		remove_tree(package_dir);
	xfree(loaded, 3 * INSTALL_PATHS_MAX * PATH_MAX);
	return ret;
}

static int parse_package_ref(const char *raw, char *source, size_t ssz,
			     char *name, size_t nsz, char *version, size_t vsz)
{
	const char *slash, *at;

	if (!raw)
		return -EINVAL;
	slash = strchr(raw, '/');
	if (!slash || slash == raw)
		return -EINVAL;
	if ((size_t)(slash - raw) >= ssz)
		return -ENAMETOOLONG;
	memcpy(source, raw, slash - raw);
	source[slash - raw] = 0;
	at = strchr(slash + 1, '@');
	if (!at) {
		if (strscpy(name, slash + 1, nsz) < 0)
			return -ENAMETOOLONG;
		version[0] = 0;
	} else {
		if ((size_t)(at - slash - 1) >= nsz)
			return -ENAMETOOLONG;
		memcpy(name, slash + 1, at - slash - 1);
		name[at - slash - 1] = 0;
		if (strscpy(version, at + 1, vsz) < 0)
			return -ENAMETOOLONG;
	}
	return bpm_name_ok(source) && bpm_name_ok(name) &&
		(!version[0] || bpm_version_ok(version)) ? 0 : -EINVAL;
}

static int cmd_bpm_config(int argc, const char **argv)
{
	const char *op = argc > 1 ? argv[1] : NULL;

	if (!op || is_help(op)) {
		fprintf(stderr,
			"usage: shirudo bpm config register add <source> "
			"oci://<registry> [--index-repository <repository>] "
			"--cert <certificate>\n"
			"       shirudo bpm config register {list|remove} ...\n"
			"       shirudo bpm config update --base-package "
			"<package.bee|oci://host/repo:tag> --version <version> "
			"[--file <name>.bee] [options]\n");
		return op ? 0 : 2;
	}
	if (strcmp(op, "register"))
		return 2;
	if (argc < 3)
		return 2;
	if (!strcmp(argv[2], "list")) {
		bool json = argc == 4 && !strcmp(argv[3], "--json");
		char buf[8192];
		struct json_emit je = { .buf = buf, .cap = sizeof(buf) };
		DIR *d = registries_opendir();
		struct dirent *e;
		size_t count = 0;

		if (argc != 3 && !json)
			return 2;
		if (json) {
			json_obj_open(&je);
			json_kv_int(&je, "schema", 1);
			json_arr_open(&je, "sources");
		} else {
			printf("Registered sources:\n");
		}
		while (d && (e = readdir(d))) {
			size_t n = strlen(e->d_name);
			char name[NAME_MAX + 1];

			if (!name_has_suffix(e->d_name, n, ".conf") ||
			    strsprintf(name, sizeof(name), "%.*s",
				       (int)(n - 5), e->d_name) < 0)
				continue;
			if (json)
				json_str(&je, name);
			else
				printf("  %s\n", name);
			count++;
		}
		if (d)
			closedir(d);
		if (json) {
			json_arr_close(&je);
			json_obj_close(&je);
			if (je.err)
				return 1;
			puts(buf);
		} else if (!count) {
			printf("  none\n");
		}
		return 0;
	}
	if (image_config_active() &&
	    (!strcmp(argv[2], "add") || !strcmp(argv[2], "remove") ||
	     !strcmp(argv[2], "rm"))) {
		pr_err("image mode: change repository definitions and keys in "
		       "a signed config image, then run `shirudo image update`");
		return 1;
	}
	if ((!strcmp(argv[2], "remove") || !strcmp(argv[2], "rm")) && argc == 4) {
		char p[PATH_MAX], key[PATH_MAX];
		struct bpm_source s;

		if (source_path(argv[3], p, sizeof(p)))
			return 2;
		if (load_source(argv[3], &s) == 0 && s.key_file[0])
			unlink(s.key_file);
		if (unlink(p) && errno != ENOENT)
			return 1;
		if (strsprintf(key, sizeof(key), "%s/%s.der", BPM_KEYS_DIR,
			       argv[3]) >= 0)
			unlink(key);
		return 0;
	}
	if (!strcmp(argv[2], "add") && argc >= 5) {
		struct bpm_oci_client probe __cleanup(bpm_oci_client_clear) = {};
		struct bpm_source s = {};
		const char *key = NULL;
		char managed[PATH_MAX];
		struct cert cert = {};

		if (strscpy(s.name, argv[3], sizeof(s.name)) < 0 ||
		    strscpy(s.endpoint, argv[4], sizeof(s.endpoint)) < 0) {
			pr_err("bpm: register add: name or endpoint too long");
			return 2;
		}
		for (int i = 5; i < argc; i++) {
			if (!strncmp(argv[i], "--cert=", 7)) {
				key = argv[i] + 7;
			} else if (!strcmp(argv[i], "--cert") && i + 1 < argc) {
				key = argv[++i];
			} else if (!strncmp(argv[i], "--index-repository=", 19)) {
				if (strscpy(s.index_repository,
					    argv[i] + 19,
					    sizeof(s.index_repository)) < 0)
					return 2;
			} else if (!strcmp(argv[i], "--index-repository") &&
				   i + 1 < argc) {
				if (strscpy(s.index_repository,
					    argv[++i],
					    sizeof(s.index_repository)) < 0)
					return 2;
			} else if (!strcmp(argv[i], "--index-repository")) {
				return 2;
			} else {
				pr_err("bpm: register add: unknown option '%s'",
				       argv[i]);
				return 2;
			}
		}
		if (!s.index_repository[0] &&
		    strsprintf(s.index_repository, sizeof(s.index_repository),
			       "%s/%s", s.name,
			       BPM_INDEX_REPOSITORY_NAME) < 0)
			return 2;
		if (!key || cert_read_file(key, &cert) ||
		    !bpm_name_ok(s.name) ||
		    bpm_oci_parse_endpoint(s.endpoint, &probe) ||
		    source_index_repository_valid(s.endpoint,
						  s.index_repository)) {
			cert_free(&cert);
			pr_err("bpm: register add requires a valid endpoint, index repository and --cert certificate");
			return 2;
		}
		cert_free(&cert);
		if (seal_mkdir_p(BPM_REGISTRIES_DIR, 0700) ||
		    seal_mkdir_p(BPM_KEYS_DIR, 0700))
			return 1;
		if (strsprintf(managed, sizeof(managed), "%s/%s.der",
			       BPM_KEYS_DIR, s.name) < 0)
			return 1;
		if (copy_file(key, managed, 0644))
			return 1;
		if (strlen(managed) >= sizeof(s.key_file))
			return 1;
		bpm_copy_string(s.key_file, sizeof(s.key_file), managed);
		return save_source(&s) ? 1 : 0;
	}
	return 2;
}

struct bpm_tree_config {
	char endpoint[BPM_MAX_ENDPOINT];
	char reference[BPM_MAX_DIGEST];
};

static int load_tree_config(struct bpm_tree_config *cfg)
{
	size_t capacity = 0;
	char *line = NULL;
	int got, ret = 0;
	FILE *fp;

	*cfg = (struct bpm_tree_config){};
	fp = tree_conf_open();
	if (!fp)
		return -errno;
	if (stream_untrusted(fp, BPM_TREE_ETC_PATH)) {
		fclose(fp);
		return -EPERM;
	}
	while (!ret && (got = read_text_line(fp, &line, &capacity,
					     PATH_MAX - 1)) != 0) {
		if (got < 0 ||
		    bpm_parse_tree_line(line, cfg->endpoint,
					sizeof(cfg->endpoint),
					cfg->reference,
					sizeof(cfg->reference)))
			ret = -EINVAL;
	}
	libc_free(line);
	fclose(fp);
	if (ret)
		return ret;
	if (!cfg->endpoint[0] || !cfg->reference[0])
		return -EINVAL;
	return 0;
}

static bool tree_digest_valid(const char *digest)
{
	__u8 raw[32];

	return !sha256_digest_decode(digest, raw);
}

static int tree_fetch_publication(const struct bpm_tree_config *cfg,
				  struct tree_publication *pub,
				  char *manifest_digest, size_t digest_sz)
{
	struct bpm_oci_client c __cleanup(bpm_oci_client_clear) = {};
	struct trusted_set *trusted = NULL;
	char repository[BPM_MAX_ENDPOINT];
	int ret;

	ret = bpm_oci_parse_tree_repo(cfg->endpoint, &c,
				      repository, sizeof(repository));
	if (ret)
		return ret;
	if (image_config_active()) {
		trusted = xcalloc(1, sizeof(*trusted));
		if (!trusted)
			return -ENOMEM;
		ret = keys_load_image_root(get_cert_path(), image_config_root_fd(),
					   true, trusted);
		if (!ret && (!trusted->n || trusted->n_unvouched))
			ret = -EKEYREJECTED;
		if (!ret)
			ret = keys_check_image_set(trusted);
		if (ret)
			goto out;
	}
	ret = bpm_tree_fetch_publication(&c, repository, cfg->reference,
					 get_cert_path(), trusted, pub,
					 manifest_digest, digest_sz);
out:
	xfree(trusted, sizeof(*trusted));
	return ret;
}

static int tree_verify_upatch(const char *path, const char *expected,
			      const char *id, bool unload)
{
	struct upatch u;
	char name[UPATCH_NAME_MAX + 1];
	char actual[65];
	int ret = upatch_open(path, &u);

	if (ret)
		return ret;
	upatch_header_name(&u, name);
	hex_encode(u.hdr.payload_sha256, 32, actual);
	if (!bpm_digest_matches(expected, actual) ||
	    (id && strcmp(name, id)) ||
	    upatch_is_unload(&u) != unload)
		ret = -EKEYREJECTED;
	upatch_close(&u);
	return ret;
}

static int tree_pull_artifact(const struct tree_operation *op,
			      char *path, size_t path_sz)
{
	struct bpm_oci_client c __cleanup(bpm_oci_client_clear) = {};
	char repository[BPM_MAX_ENDPOINT], url[PATH_MAX], cache[PATH_MAX];
	struct bpm_buffer manifest = {}, blob = {};
	struct bpm_descriptor *layers = NULL;
	char hex[65];
	int nl = 0, ret;

	if (!tree_digest_valid(op->artifact.layer_digest))
		return -EINVAL;
	/*
	 * The cache holds the blob exactly as fetched, so its content
	 * address names it. The payload digest would not: equally built
	 * upatches published under different names share it.
	 */
	if (strsprintf(cache, sizeof(cache), "%s/%s.upatch",
		       BPM_TREE_ARTIFACTS_DIR,
		       op->artifact.layer_digest + strlen("sha256:")) < 0)
		return -ENAMETOOLONG;
	if (!access(cache, R_OK)) {
		bpm_copy_string(path, path_sz, cache);
		return tree_verify_upatch(path, op->artifact.payload_sha256, op->id,
					  !strcmp(op->op, "delete"));
	}
	ret = bpm_oci_parse_tree_repo(op->artifact.repository, &c, repository,
				      sizeof(repository));
	if (ret)
		return ret;
	ret = bpm_oci_url(&c, repository, "manifests",
			  op->artifact.manifest_digest, url, sizeof(url));
	if (ret)
		return ret;
	ret = bpm_oci_get_memory(&c, url,
				 "application/vnd.oci.image.manifest.v1+json", &manifest);
	if (ret)
		goto out;
	if (bpm_sha256_hex(manifest.data, manifest.len, hex, sizeof(hex)) ||
	    !bpm_digest_matches(op->artifact.manifest_digest, hex)) {
		ret = -EKEYREJECTED;
		goto out;
	}
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
		if (strcmp(layers[i].digest, op->artifact.layer_digest) ||
		    strcmp(layers[i].media, BPM_UPATCH_MEDIA))
			continue;
		ret = bpm_oci_url(&c, repository, "blobs", layers[i].digest,
				  url, sizeof(url));
		if (ret)
			goto out;
		ret = bpm_oci_get_blob(&c, url, layers[i].media, &blob);
		if (ret)
			goto out;
		if (bpm_sha256_hex(blob.data, blob.len, hex, sizeof(hex)) ||
		    !bpm_digest_matches(layers[i].digest, hex) ||
		    (layers[i].size >= 0 && (__s64)blob.len != layers[i].size))
			ret = -EKEYREJECTED;
		if (ret)
			goto out;
		ret = seal_mkdir_p(BPM_TREE_ARTIFACTS_DIR, 0700);
		if (ret)
			goto out;
		ret = seal_write_file(cache, blob.data, blob.len, 0600);
		if (ret)
			goto out;
		bpm_copy_string(path, path_sz, cache);
		ret = tree_verify_upatch(path, op->artifact.payload_sha256, op->id,
					 !strcmp(op->op, "delete"));
		goto out;
	}
	ret = -ENOENT;
out:
	xfree(layers, BPM_MAX_ENTRIES * sizeof(*layers));
	bpm_buffer_free(&manifest);
	bpm_buffer_free(&blob);
	return ret;
}

static int tree_write_report(const char *path, const struct tree_state *s,
			     int selected, int skipped, int applied,
			     int module_skipped, int dry_run,
			     int tpm_available)
{
	char buf[4096];
	struct json_emit e = { .buf = buf, .cap = sizeof(buf) };

	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_kv_bool(&e, "dry_run", dry_run);
	json_kv_int(&e, "selected", selected);
	json_kv_int(&e, "skipped", skipped);
	json_kv_int(&e, "applied", applied);
	json_kv_int(&e, "module_skipped", module_skipped);
	json_kv_bool(&e, "tpm_available", tpm_available);
	json_kv_int(&e, "last_seq", s->last_seq);
	if (tpm_available)
		json_kv_string(&e, "projection_root_tpm",
			       s->projection_root_tpm);
	else
		json_kv_null(&e, "projection_root_tpm");
	json_obj_close(&e);
	if (e.err)
		return e.err;
	if (path) {
		struct seal_output out;
		int ret;

		ret = seal_output_create(&out, path, 0600);
		return ret ? ret : seal_output_commit(&out, buf, e.len);
	}
	printf("%s\n", buf);
	return 0;
}

static int tree_status_write(const char *id, const char *status)
{
	char path[PATH_MAX];
	int ret;

	if (!id || !upatch_name_valid(id) || !status || !status[0])
		return -EINVAL;
	ret = seal_mkdir_p(BPM_TREE_STATUS_DIR, 0700);
	if (ret)
		return ret;
	if (strsprintf(path, sizeof(path), "%s/%s",
		       BPM_TREE_STATUS_DIR, id) < 0)
		return -ENAMETOOLONG;
	return seal_write_file(path, status, strlen(status), 0600);
}

static void tree_status_clear(const char *id)
{
	char path[PATH_MAX];

	if (!id || !upatch_name_valid(id) ||
	    strsprintf(path, sizeof(path), "%s/%s",
		       BPM_TREE_STATUS_DIR, id) < 0)
		return;
	unlink(path);
}

/*
 * event = SHA256("shirudo-tree\0" || seq || operation_digest). The
 * tree's own projection stays a file chain; the register is what an
 * operator attests.
 */
static int tree_measure_locked(const struct tree_operation *op,
			       const __u8 operation_digest[32])
{
	__u8 event[32], chain[32];
	struct json_emit e;
	char line[4096], chain_hex[65];
	int ret;

	ret = chain_tree_event(op->seq, operation_digest, event);
	if (!ret)
		ret = chain_extend(event, chain);
	if (ret)
		return ret;

	hex_encode(chain, 32, chain_hex);
	e = (struct json_emit){ .buf = line, .cap = sizeof(line) };
	eventlog_record_open(&e, "tree_op", event);
	json_obj_open_key(&e, "tree");
	json_kv_int(&e, "seq", op->seq);
	json_kv_string(&e, "op", op->op);
	json_kv_string(&e, "id", op->id);
	json_kv_string(&e, "operation_digest", op->operation_digest);
	json_obj_close(&e);
	json_kv_string(&e, "chain", chain_hex);
	json_obj_close(&e);
	if (e.err)
		return e.err;
	return eventlog_append(line);
}

static int tree_measure_operation(const struct tree_operation *op,
				  const __u8 operation_digest[32])
{
	int lock, ret;

	lock = eventlog_lock();
	if (lock < 0)
		return lock;
	ret = tree_measure_locked(op, operation_digest);
	eventlog_unlock(lock);
	return ret;
}

/*
 * Complete the only non-idempotent window: the process may have
 * measured the operation, or appended its tree event too, before the
 * sealed cursor was committed. Applying it again would extend the
 * register with it a second time this boot.
 */
static int tree_recover_pending(const struct tree_publication *pub,
				struct tree_state *state)
{
	struct tree_pending pending;
	const struct tree_operation *op = NULL;
	__u8 digest[32], previous[32], next[32], replay[32];
	bool applied = false, event_present = false;
	int ret;

	ret = tree_pending_read(&pending);
	if (ret == -ENOENT)
		return 0;
	if (ret)
		return ret;
	for (int i = 0; i < pub->n_operations; i++) {
		if (pub->operations[i].seq == pending.seq &&
		    !strcmp(pub->operations[i].id, pending.id) &&
		    !strcmp(pub->operations[i].operation_digest,
			    pending.operation_digest)) {
			op = &pub->operations[i];
			break;
		}
	}
	if (!op)
		return -ERANGE;
	if (pending.seq <= state->last_seq) {
		unlink(BPM_TREE_PENDING_PATH);
		return 0;
	}
	if (sha256_digest_decode(pending.operation_digest, digest) ||
	    hex_decode(state->projection_root, previous, 32))
		return -EINVAL;
	ret = sha256_2(previous, sizeof(previous), digest, sizeof(digest),
		       next);
	if (ret)
		return ret;

	ret = tree_event_replay(replay);
	if (!ret) {
		if (!memneq_explicit(replay, next, sizeof(replay))) {
			applied = true;
			event_present = true;
		} else if (memneq_explicit(replay, previous, sizeof(replay))) {
			return -EKEYREJECTED;
		}
	} else if (ret != -ENOENT) {
		return -EKEYREJECTED;
	}
	if (!applied) {
		ret = eventlog_tree_op_measured(op->seq, op->operation_digest);
		if (ret < 0)
			return -EKEYREJECTED;
		/* Still pre-operation; retry normally. */
		if (!ret)
			return 0;
		applied = true;
	}
	if (!event_present) {
		ret = tree_event_append(op->seq, op->operation_digest, next);
		if (ret)
			return ret;
	}
	hex_encode(next, sizeof(next), state->projection_root);
	hex_encode(next, sizeof(next), state->projection_root_tpm);
	state->last_seq = op->seq;
	ret = tree_state_write(state);
	if (ret)
		return ret;
	unlink(BPM_TREE_PENDING_PATH);
	return 0;
}

static void tree_sync_report_error(const char *phase,
				   const struct tree_operation *op, int ret)
{
	int err;

	if (ret > 0) {
		if (op)
			pr_err("bpm tree sync: phase=%s seq=%lld id=%s rc=%d "
			       "(command status)", phase, (__s64)op->seq,
			       op->id, ret);
		else
			pr_err("bpm tree sync: phase=%s rc=%d (command status)",
			       phase, ret);
		return;
	}
	err = ret < 0 ? -ret : 0;

	if (op)
		pr_err("bpm tree sync: phase=%s seq=%lld id=%s rc=%d (%s)",
		       phase, (__s64)op->seq, op->id, ret,
		       err ? strerror(err) : "success");
	else
		pr_err("bpm tree sync: phase=%s rc=%d (%s)", phase, ret,
		       err ? strerror(err) : "success");
}

static int cmd_bpm_tree_sync(int argc, const char **argv)
{
	struct bpm_tree_config cfg;
	struct tree_publication pub = {};
	struct tree_state state = {};
	char manifest_digest[BPM_MAX_DIGEST];
	char report[PATH_MAX] = {};
	bool dry_run = false, have_state = false;
	int selected = 0, skipped = 0, applied = 0, module_skipped = 0;
	int tpm_available = 0;
	int ret;

	if (argc < 2 || strcmp(argv[1], "sync")) {
		ret = -EINVAL;
		goto out;
	}
	for (int i = 2; i < argc; i++) {
		if (!strcmp(argv[i], "--dry-run")) {
			dry_run = true;
		} else if (!strncmp(argv[i], "--report=", 9) ||
			   (!strcmp(argv[i], "--report") && i + 1 < argc)) {
			const char *path = argv[i][8] == '=' ? argv[i] + 9 :
							       argv[++i];

			if (strscpy(report, path, sizeof(report)) < 0) {
				pr_err("bpm tree sync: report path too long");
				return 2;
			}
		} else if (is_help(argv[i])) {
			fprintf(stderr, "usage: shirudo bpm tree sync [--dry-run] [--report=<path>]\n");
			ret = 0;
			goto out;
		} else {
			ret = -EINVAL;
			goto out;
		}
	}
	ret = load_tree_config(&cfg);
	/* Optional integration: manual `shirudo upatch` remains valid. */
	if (ret == -ENOENT) {
		ret = 0;
		goto out;
	}
	if (ret)
		goto out;
	ret = tree_state_read(&state);
	if (!ret)
		have_state = true;
	else if (ret != -ENOENT)
		goto out;
	ret = tree_fetch_publication(&cfg, &pub, manifest_digest,
				     sizeof(manifest_digest));
	if (ret)
		goto out;
	/*
	 * The node records the tree ID in its state, which takes names
	 * alone: one that is not would be applied, measured and logged
	 * and then never recorded, failing every later sync.
	 */
	if (!bpm_package_name_ok(pub.tree_id)) {
		ret = -EINVAL;
		goto out;
	}
	ret = tree_publication_check(&pub);
	if (ret)
		goto out;
	for (int i = 0; i < pub.n_operations; i++) {
		ret = tree_operation_validate(&pub.operations[i]);
		if (ret) {
			tree_sync_report_error("operation_validate", &pub.operations[i], ret);
			goto out;
		}
	}
	ret = tree_publication_follows(&pub, have_state ? &state : NULL,
				       manifest_digest);
	if (ret)
		goto out;
	if (!have_state) {
		state.schema = 1;
		bpm_copy_string(state.tree_id, sizeof(state.tree_id), pub.tree_id);
		memset(state.projection_root, '0', 64);
		state.projection_root[64] = '\0';
		memset(state.projection_root_tpm, '0', 64);
		state.projection_root_tpm[64] = '\0';
	}
	ret = tree_recover_pending(&pub, &state);
	if (ret) {
		tree_sync_report_error("pending_recovery", NULL, ret);
		goto out;
	}
	tpm_available = chain_bound();
	for (int i = 0; i < pub.n_operations; i++) {
		struct tree_operation *op = &pub.operations[i];
		__u8 digest[32], previous[32], next[32];
		char artifact[PATH_MAX];
		bool skipped_module = false;

		if (op->seq <= state.last_seq)
			continue;
		ret = tree_selector_matches(&op->selector);
		if (ret < 0) {
			tree_sync_report_error("selector_evaluate", op, ret);
			goto out;
		}
		if (!ret) {
			skipped++;
			if (!dry_run)
				state.last_seq = op->seq;
			continue;
		}
		selected++;
		if (dry_run)
			continue;
		ret = sha256_digest_decode(op->operation_digest, digest);
		if (ret) {
			tree_sync_report_error("operation_digest_parse", op, ret);
			ret = -EINVAL;
			goto out;
		}
		ret = tree_pending_write(op);
		if (ret) {
			tree_sync_report_error("pending_write", op, ret);
			goto out;
		}
		ret = tree_pull_artifact(op, artifact, sizeof(artifact));
		if (ret) {
			tree_sync_report_error("artifact_fetch_or_verify", op, ret);
			goto out;
		}
		if (!strcmp(op->op, "add")) {
			ret = upatch_install(artifact);
		} else if (!strcmp(op->op, "delete")) {
			ret = upatch_remove(artifact);
		} else {
			ret = -EINVAL;
			goto out;
		}
		if (ret == UPATCH_INSTALL_TARGET_MISSING &&
		    !strcmp(op->op, "add")) {
			skipped_module = true;
			ret = 0;
			module_skipped++;
			pr_warn("bpm tree: skipped %s: module not loaded", op->id);
		}
		if (ret) {
			tree_sync_report_error("upatch_install", op, ret);
			goto out;
		}
		if (hex_decode(state.projection_root, previous, 32)) {
			tree_sync_report_error("projection_root_decode", op, -EINVAL);
			ret = -EINVAL;
			goto out;
		}
		ret = sha256_2(previous, 32, digest, 32, next);
		if (ret) {
			tree_sync_report_error("projection_root_hash", op, ret);
			goto out;
		}
		ret = tree_measure_operation(op, digest);
		if (ret) {
			tree_sync_report_error("register_extend", op, ret);
			goto out;
		}
		hex_encode(next, 32, state.projection_root);
		hex_encode(next, 32, state.projection_root_tpm);
		ret = tree_event_append(op->seq, op->operation_digest, next);
		if (ret) {
			tree_sync_report_error("tree_event_append", op, ret);
			goto out;
		}
		state.last_seq = op->seq;
		applied++;
		ret = tree_state_write(&state);
		if (ret) {
			tree_sync_report_error("tree_state_commit", op, ret);
			goto out;
		}
		if (skipped_module)
			ret = tree_status_write(op->id, "skipped: module not loaded");
		else
			tree_status_clear(op->id);
		if (ret) {
			tree_sync_report_error("tree_status_write", op, ret);
			goto out;
		}
		unlink(BPM_TREE_PENDING_PATH);
	}
	if (!dry_run) {
		state.generation = pub.generation;
		bpm_copy_string(state.manifest_digest, sizeof(state.manifest_digest),
				manifest_digest);
		if (!state.tree_id[0])
			bpm_copy_string(state.tree_id, sizeof(state.tree_id), pub.tree_id);
		ret = tree_state_write(&state);
		if (ret) {
			tree_sync_report_error("tree_state_commit_final", NULL, ret);
			goto out;
		}
	}
	/* "-" is standard output, where the report goes without --report. */
	ret = tree_write_report(report[0] && strcmp(report, "-") ? report : NULL,
				&state, selected, skipped, applied,
				module_skipped, dry_run, tpm_available);
out:
	tree_publication_free(&pub);
	return ret;
}

static void bpm_tree_usage(void)
{
	fprintf(stderr,
		"usage: shirudo bpm tree sync [--dry-run] [--report=<path>]\n"
		"       shirudo bpm tree append <package-file> <repository> [options]\n\n"
		"sync applies the configured tree on a target. append is operator-only:\n"
		"it runs in shirudo-build and publishes the [upatches.tree] entries of a\n"
		"built package as the next operations of the signed tree; see\n"
		"`shirudo bpm tree append --help` where the operator package is installed.\n");
}

static int remove_tree_entry(const char *path, const struct stat *st,
			     int type, struct FTW *ftw)
{
	if (type == FTW_DP || type == FTW_D)
		return rmdir(path) ? -1 : 0;
	return unlink(path) ? -1 : 0;
}

static int remove_tree(const char *path)
{
	if (nftw(path, remove_tree_entry, 32, FTW_DEPTH | FTW_PHYS))
		return errno ? -errno : -EIO;
	return 0;
}

static int path_compare_desc(const void *left, const void *right)
{
	return strcmp(right, left);
}

/*
 * Detach a package's upatches through the signed unload directives it
 * shipped, in reverse name order, then remove the package tree. The
 * caller drops the state entry only after this succeeded, so a failed
 * detach leaves the package listed and loadable again.
 */
static int package_uninstall(const struct bpm_state_entry *st)
{
	char dir[PATH_MAX], updir[PATH_MAX];
	char (*unloads)[PATH_MAX];
	struct dirent *de;
	int n = 0, ret = 0;
	DIR *d;

	if (strsprintf(updir, sizeof(updir), "%s/upatches", st->path) < 0)
		return -ENAMETOOLONG;
	unloads = xcalloc(128, PATH_MAX);
	if (!unloads)
		return -ENOMEM;
	/*
	 * A tree already gone, from an uninstall that died before it
	 * wrote the state, leaves nothing to unload: the retry converges.
	 */
	d = opendir(updir);
	if (!d && errno != ENOENT) {
		ret = -errno;
		goto out;
	}
	while (d && (de = readdir(d))) {
		if (bpm_upatch_member(de->d_name, strlen(de->d_name)) !=
		    BPM_UPATCH_UNLOAD)
			continue;
		if (n >= 128) {
			ret = -E2BIG;
			break;
		}
		if (strsprintf(unloads[n], PATH_MAX, "%s/%s", updir, de->d_name) < 0) {
			ret = -ENAMETOOLONG;
			break;
		}
		n++;
	}
	if (d)
		closedir(d);
	if (ret)
		goto out;
	qsort(unloads, (size_t)n, PATH_MAX, path_compare_desc);
	for (int i = 0; i < n; i++) {
		if (upatch_remove(unloads[i])) {
			pr_err("bpm uninstall: unload %s failed", unloads[i]);
			ret = -EIO;
			goto out;
		}
	}
	if (strsprintf(dir, sizeof(dir), "%s/%s", BPM_PACKAGES_DIR,
		       st->name) < 0) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	ret = remove_tree(dir);
	if (ret == -ENOENT)
		ret = 0;
out:
	xfree(unloads, 128 * PATH_MAX);
	return ret;
}

static const struct help_item bpm_subcmds[] = {
	{ "config", "manage package inputs and OCI repositories" },
	{ "repo", "refresh signed repository indexes" },
	{ "tree", "synchronize or publish the signed upatch tree" },
	{ "key", "add, fingerprint, and list package certificates" },
	{ "pull", "download an OCI package into the current directory" },
	{ "info", "print a local or OCI package README" },
	{ "push", "publish an OCI package and its signed index entry" },
	{ "build", "build a signed OCI package from a Beefile" },
	{ "install", "download and activate a repository or OCI package" },
	{ "upgrade", "activate newer cached package versions" },
	{ "list", "list installed packages" },
	{ "uninstall", "unload and remove an installed package" },
};

static const struct help_item bpm_target_subcmds[] = {
	{ "config", "register and manage OCI repositories" },
	{ "repo", "refresh signed repository indexes" },
	{ "tree", "synchronize the optional signed upatch tree" },
	{ "key", "add, fingerprint, and list package certificates" },
	{ "pull", "download an OCI package into the current directory" },
	{ "info", "print a local or OCI package README" },
	{ "install", "download and activate a repository or OCI package" },
	{ "upgrade", "activate newer cached package versions" },
	{ "list", "list installed packages" },
	{ "uninstall", "unload and remove an installed package" },
};

/*
 * Operator-only subcommands live in shirudo-build; hand the bpm argument
 * vector over unchanged so the helper parses it itself.
 */
static int bpm_exec_operator(const char *sub, int argc, const char **argv)
{
	char label[64];

	if (strsprintf(label, sizeof(label), "bpm %s", sub) < 0)
		return bpm_fail(sub, -E2BIG);
	return build_forward(label, (const char *const[]){ "bpm", sub, NULL },
			     argc - 2, argv + 2);
}

static const struct help bpm_target_help = {
	.usage = "shirudo bpm <config|repo|tree|key|pull|info|install|upgrade|list|uninstall>",
	.summary = "Manage signed target-local BPM packages backed by OCI repositories.",
	.sections = (const struct help_section[]) {
		{ "subcommands:", bpm_target_subcmds, ARRAY_SIZE(bpm_target_subcmds) },
	},
	.n_sections = 1,
};

static const struct help bpm_operator_help = {
	.usage = "shirudo bpm <config|repo|tree|key|pull|info|push|build|install|upgrade|list|uninstall>",
	.summary = "Manage signed OCI packages and publish packages from the operator.",
	.sections = (const struct help_section[]) {
		{ "subcommands:", bpm_subcmds, ARRAY_SIZE(bpm_subcmds) },
	},
	.n_sections = 1,
};

static void bpm_pull_usage(void)
{
	fprintf(stderr,
		"usage: shirudo bpm pull <package-reference>\n\n"
		"The package reference must start with oci://.\n"
		"Example:\n"
		"  shirudo bpm pull oci://quay.io/namespace/package:tag\n");
}

static void bpm_info_usage(void)
{
	fprintf(stderr,
		"usage: shirudo bpm info <package-file|package-reference>\n"
		"       shirudo bpm info upatches <package> [--all]\n"
		"       shirudo bpm info data <package> <upatch-member> [--json]\n\n"
		"Prints package README.md, lists packaged upatches, or decodes\n"
		"the BPF .rodata initial data using its BTF types.\n"
		"Examples:\n"
		"  shirudo bpm info ./package.bee\n"
		"  shirudo bpm info upatches ./package.bee\n"
		"  shirudo bpm info upatches ./package.bee --all\n"
		"  shirudo bpm info data ./package.bee upatches/kernel-obs.upatch\n"
		"  shirudo bpm info data ./package.bee upatches/kernel-obs.upatch --json\n"
		"Package may be a local .bee file or an oci:// reference.\n");
}

static int bpm_finish(int lock, int ret, const char *action)
{
	if (lock >= 0) {
		flock(lock, LOCK_UN);
		close(lock);
	}
	curl_global_cleanup();
	return ret ? bpm_fail(action, ret) : 0;
}

static const struct help_item bpm_key_subcmds[] = {
	{ "add", "install a trusted package certificate and print its fingerprint" },
	{ "fingerprint", "print the SHA-256 fingerprint of a certificate's SPKI" },
	{ "list", "list installed certificate fingerprints" },
};

static const struct help bpm_key_help = {
	.usage = "shirudo bpm key <add|fingerprint|list>",
	.summary = "Manage package signing certificates.",
	.sections = (const struct help_section[]) {
		{ "subcommands:", bpm_key_subcmds, ARRAY_SIZE(bpm_key_subcmds) },
	},
	.n_sections = 1,
	.footer = "add and fingerprint accept a certificate file, .bee package, or\n"
		  "oci://registry/repository:tag. list reads /var/lib/shirudo/keys.\n"
		  "Examples:\n"
		  "  shirudo bpm key fingerprint ./package.bee\n"
		  "  shirudo bpm key add oci://quay.io/namespace/package:tag\n"
		  "  shirudo bpm key list",
};

static int cmd_bpm_key(int argc, const char **argv)
{
	char temp[PATH_MAX] = {}, hex[65];
	const char *sub, *src;
	int ret;

	if (argc < 2 || is_help(argv[1])) {
		print_help(&bpm_key_help);
		return argc < 2 ? 2 : 0;
	}
	if (is_list_cmds(argv[1])) {
		print_subcmd_list(bpm_key_subcmds,
				  ARRAY_SIZE(bpm_key_subcmds));
		return 0;
	}
	sub = resolve_subcommand("bpm key", argv[1], bpm_key_subcmds,
				 ARRAY_SIZE(bpm_key_subcmds));
	if (!sub)
		return 2;
	if (argc == 3 && is_help(argv[2])) {
		print_help(&bpm_key_help);
		return 0;
	}
	if ((!strcmp(sub, "list") && argc != 2 &&
	     !(argc == 3 && !strcmp(argv[2], "--json"))) ||
	    (strcmp(sub, "list") && argc != 3)) {
		print_help(&bpm_key_help);
		return 2;
	}
	if (!strcmp(sub, "add") && image_config_active()) {
		pr_err("image mode: add vouched BPF signers to the signed "
		       "config selected for boot and reboot to enroll them");
		return 1;
	}
	if (!strcmp(sub, "list")) {
		ret = list_keys(argc == 3);
		return ret ? bpm_fail("key list", ret) : 0;
	}
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return bpm_fail("initialize curl", -EIO);
	src = argv[2];
	ret = key_source_file(src, temp, sizeof(temp));
	if (!ret) {
		if (temp[0])
			src = temp;
		ret = key_file_fingerprint(src, hex);
		if (!ret && !strcmp(sub, "add"))
			ret = install_key_file(src);
		if (!ret)
			puts(hex);
	}
	if (temp[0])
		unlink(temp);
	return bpm_finish(-1, ret, !strcmp(sub, "add") ?
			  "key add" : "key fingerprint");
}

/* The package index and the state take over a MiB between them. */
struct bpm_tables {
	struct bpm_index_entry	entries[BPM_MAX_ENTRIES];
	struct bpm_state_entry	state[BPM_MAX_STATE];
};

static int with_tables(int (*fn)(const char *, struct bpm_tables *),
		       const char *arg, const char *what)
{
	struct bpm_tables *t;
	int ret;

	t = xcalloc(1, sizeof(*t));
	if (!t)
		return bpm_fail(what, -ENOMEM);
	ret = fn(arg, t);
	xfree(t, sizeof(*t));
	return ret;
}

static int bpm_install(const char *ref, struct bpm_tables *t)
{
	char source[BPM_MAX_NAME], name[BPM_MAX_NAME], version[BPM_MAX_NAME];
	struct bpm_index_entry *entries = t->entries;
	struct bpm_state_entry *state = t->state;
	bool direct = !strncmp(ref, "oci://", 6);
	struct bpm_index_entry selected;
	struct bpm_source source_cfg;
	int n_entries, n_state, lock, ret, i;

	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return bpm_fail("initialize curl", -EIO);
	lock = with_bpm_lock();
	if (lock < 0)
		return bpm_finish(-1, lock, "lock");
	if (direct) {
		ret = prepare_direct_install(ref, &source_cfg, &selected);
	} else {
		ret = parse_package_ref(ref, source, sizeof(source), name,
					sizeof(name), version, sizeof(version));
	}
	if (!ret)
		ret = bpm_state_read(state, &n_state);
	if (ret)
		return bpm_finish(lock, ret, "install");
	for (i = 0; i < n_state; i++) {
		if (!strcmp(state[i].name, direct ? selected.name : name))
			/*
			 * Installation is idempotent by package name.
			 * This also avoids contacting the repository
			 * for a package that is already active.  Use
			 * `bpm upgrade` to change versions.
			 */
			return bpm_finish(lock, 0, "install");
	}
	if (!direct) {
		ret = load_source(source, &source_cfg);
		if (!ret)
			ret = load_cached_index(source, entries, &n_entries);
		if (!ret)
			ret = find_entry(entries, n_entries, name,
					 version[0] ? version : NULL, &selected);
	}
	if (ret)
		return bpm_finish(lock, ret, "install");
	if (n_state >= BPM_MAX_STATE)
		return bpm_finish(lock, -E2BIG, "install");
	ret = package_install(&source_cfg, &selected, NULL, NULL);
	if (ret)
		return bpm_finish(lock, ret, "install");
	bpm_copy_string(state[n_state].name, sizeof(state[n_state].name),
			direct ? selected.name : name);
	bpm_copy_string(state[n_state].version, sizeof(state[n_state].version),
			selected.version);
	bpm_copy_string(state[n_state].source, sizeof(state[n_state].source),
			direct ? "direct" : source);
	if (strsprintf(state[n_state].path, sizeof(state[n_state].path),
		       "%s/%s/%s", BPM_PACKAGES_DIR,
		       direct ? selected.name : name,
		       selected.version) < 0)
		return bpm_finish(lock, -ENAMETOOLONG, "install");
	ret = bpm_state_write(state, n_state + 1);
	if (ret) {
		/* Unlisted, the package could never be removed. */
		if (package_uninstall(&state[n_state]))
			pr_err("bpm install: %s stays installed but "
			       "unlisted", state[n_state].name);
		else
			pr_err("bpm install: %s removed again, the "
			       "state could not be written",
			       state[n_state].name);
	}
	return bpm_finish(lock, ret, "write state");
}

static int bpm_upgrade(const char *unused, struct bpm_tables *t)
{
	struct bpm_state_entry *state = t->state;
	int n_state, lock, ret, wrc, i;

	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return bpm_fail("initialize curl", -EIO);
	lock = with_bpm_lock();
	if (lock < 0)
		return bpm_finish(-1, lock, "lock");
	ret = bpm_state_read(state, &n_state);
	if (ret)
		return bpm_finish(lock, ret, "read state");
	for (i = 0; i < n_state; i++) {
		struct bpm_index_entry *entries = t->entries, selected;
		struct bpm_source source_cfg;
		char path[PATH_MAX];
		int n_entries;

		if (!strcmp(state[i].source, "direct"))
			continue;
		ret = load_source(state[i].source, &source_cfg);
		if (!ret)
			ret = load_cached_index(state[i].source, entries, &n_entries);
		if (!ret)
			ret = find_entry(entries, n_entries, state[i].name, NULL,
					 &selected);
		if (ret == -ENOENT) {
			ret = 0;
			continue;
		}
		if (ret)
			break;
		if (bpm_semver_compare(selected.version, state[i].version) <= 0)
			continue;
		ret = package_install(&source_cfg, &selected, state[i].path,
				      state[i].version);
		if (ret)
			break;
		bpm_copy_string(state[i].version, sizeof(state[i].version),
				selected.version);
		if (strsprintf(path, sizeof(path), "%s/%s/%s",
			       BPM_PACKAGES_DIR, state[i].name,
			       selected.version) < 0) {
			ret = -ENAMETOOLONG;
			break;
		}
		bpm_copy_string(state[i].path, sizeof(state[i].path), path);
	}
	/* Packages upgraded before a failure stay on record. */
	wrc = bpm_state_write(state, n_state);
	if (ret)
		return bpm_finish(lock, ret, "upgrade");
	return bpm_finish(lock, wrc, "write state");
}

int cmd_bpm(int argc, const char **argv)
{
	const struct help *help = build_available() ?
		&bpm_operator_help : &bpm_target_help;
	const struct help_item *subcmds = build_available() ?
		bpm_subcmds : bpm_target_subcmds;
	size_t n_subcmds = build_available() ? ARRAY_SIZE(bpm_subcmds) :
		ARRAY_SIZE(bpm_target_subcmds);
	const char *sub;

	if (argc < 2 || is_help(argv[1])) {
		print_help(help);
		return argc < 2 ? 2 : 0;
	}
	if (is_list_cmds(argv[1])) {
		print_subcmd_list(subcmds, n_subcmds);
		return 0;
	}
	sub = resolve_subcommand("shirudo bpm", argv[1], subcmds,
				 n_subcmds);
	if (!sub)
		return 2;
	if (!strcmp(sub, "config") && argc >= 3 &&
	    !strcmp(argv[2], "update"))
		return bpm_exec_operator("config", argc, argv);
	if (!strcmp(sub, "config"))
		return cmd_bpm_config(argc - 1, argv + 1);
	if (!strcmp(sub, "info")) {
		bool json = false, all = false;
		const char *source;
		int ret;

		if (argc == 3 && is_help(argv[2])) {
			bpm_info_usage();
			return 0;
		}
		if (argc < 3) {
			bpm_info_usage();
			return 2;
		}
		if (!strcmp(argv[2], "upatches")) {
			if ((argc != 4 && argc != 5) ||
			    (argc == 5 && strcmp(argv[4], "--all"))) {
				bpm_info_usage();
				return 2;
			}
			source = argv[3];
			all = argc == 5;
		} else if (!strcmp(argv[2], "data")) {
			if ((argc != 5 && argc != 6) ||
			    (argc == 6 && strcmp(argv[5], "--json"))) {
				bpm_info_usage();
				return 2;
			}
			source = argv[3];
			json = argc == 6;
		} else {
			if (argc != 3) {
				bpm_info_usage();
				return 2;
			}
			source = argv[2];
		}
		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
			return bpm_fail("initialize curl", -EIO);
		if (!strcmp(argv[2], "upatches"))
			ret = print_package_upatches(source, all);
		else if (!strcmp(argv[2], "data"))
			ret = print_package_upatch_data(source, argv[4], json);
		else
			ret = print_package_readme(source);
		return bpm_finish(-1, ret, "info");
	}
	if (!strcmp(sub, "tree") && (argc < 3 || is_help(argv[2]))) {
		bpm_tree_usage();
		return argc < 3 ? 2 : 0;
	}
	if (!strcmp(sub, "tree") && !strcmp(argv[2], "append"))
		return bpm_exec_operator(sub, argc, argv);
	if (!strcmp(sub, "tree") && strcmp(argv[2], "sync")) {
		bpm_tree_usage();
		return 2;
	}
	if (!strcmp(sub, "build") || !strcmp(sub, "push"))
		return bpm_exec_operator(sub, argc, argv);
	if (!strcmp(sub, "pull")) {
		int ret;

		if (argc == 3 && is_help(argv[2])) {
			bpm_pull_usage();
			return 0;
		}
		if (argc != 3) {
			bpm_pull_usage();
			return 2;
		}
		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
			return bpm_fail("initialize curl", -EIO);
		ret = pull_package(argv[2]);
		return bpm_finish(-1, ret, "pull");
	}
	if (!strcmp(sub, "repo") && argc >= 3 && !strcmp(argv[2], "update")) {
		int lock, ret = 0;

		if (argc == 4 && is_help(argv[3])) {
			fprintf(stderr, "usage: shirudo bpm repo update [<source>]\n");
			return 0;
		}
		if (argc > 4)
			return 2;
		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
			return bpm_fail("initialize curl", -EIO);
		lock = with_bpm_lock();
		if (lock < 0)
			return bpm_finish(-1, lock, "lock");
		if (argc == 3) {
			DIR *d = registries_opendir();
			struct dirent *entry;

			if (!d && errno != ENOENT)
				ret = -errno;
			/* One unreachable registry must not hold back the others. */
			while (d && (entry = readdir(d))) {
				size_t len = strlen(entry->d_name);
				char source[BPM_MAX_NAME];

				if (!name_has_suffix(entry->d_name, len, ".conf"))
					continue;
				if (strsprintf(source, sizeof(source), "%.*s",
					       (int)(len - 5), entry->d_name) < 0) {
					ret = -ENAMETOOLONG;
					continue;
				}
				if (repo_update_one(source))
					ret = -EIO;
			}
			if (d)
				closedir(d);
		} else {
			ret = repo_update_one(argv[3]);
		}
		return bpm_finish(lock, ret, "repo update");
	}
	if (!strcmp(sub, "tree")) {
		int lock, ret;

		if (argc > 6)
			return 2;
		if (argc == 4 && is_help(argv[3])) {
			bpm_tree_usage();
			return 0;
		}
		/*
		 * The tree is optional. Avoid taking the BPM lock (and
		 * avoid requiring writable state directories) when it is
		 * not configured.
		 */
		if (!tree_configured())
			return 0;
		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
			return bpm_fail("initialize curl", -EIO);
		lock = with_bpm_lock();
		if (lock < 0)
			return bpm_finish(-1, lock, "lock");
		ret = cmd_bpm_tree_sync(argc - 1, argv + 1);
		return bpm_finish(lock, ret, "tree sync");
	}
	if (!strcmp(sub, "key"))
		return cmd_bpm_key(argc - 1, argv + 1);
	if (!strcmp(sub, "install") && argc == 3 && is_help(argv[2])) {
		fprintf(stderr, "usage: shirudo bpm install <package>\n");
		return 0;
	}
	if (!strcmp(sub, "install") && argc == 3)
		return with_tables(bpm_install, argv[2], "install");
	if (!strcmp(sub, "list")) {
		bool json = argc == 3 && !strcmp(argv[2], "--json");
		struct bpm_state_entry *state;
		int n_state, ret;

		if (argc != 2 && !json) {
			fprintf(stderr, "usage: shirudo bpm list [--json]\n");
			return argc == 3 && is_help(argv[2]) ? 0 : 2;
		}
		state = xcalloc(BPM_MAX_STATE, sizeof(*state));
		if (!state)
			return bpm_fail("list", -ENOMEM);
		ret = bpm_state_read(state, &n_state);
		if (!ret && json) {
			size_t cap = 256 + (size_t)n_state * 3 * BPM_MAX_NAME;
			char *buf = xmalloc(cap);
			struct json_emit e = { .buf = buf, .cap = cap };

			if (!buf) {
				ret = -ENOMEM;
			} else {
				json_obj_open(&e);
				json_kv_int(&e, "schema", 1);
				json_arr_open(&e, "packages");
				for (int i = 0; i < n_state; i++) {
					json_obj_open(&e);
					json_kv_string(&e, "name",
						       state[i].name);
					json_kv_string(&e, "version",
						       state[i].version);
					json_kv_string(&e, "source",
						       state[i].source);
					json_obj_close(&e);
				}
				json_arr_close(&e);
				json_obj_close(&e);
				if (e.err)
					ret = e.err;
				else
					puts(buf);
				xfree(buf, cap);
			}
		} else if (!ret) {
			printf("Installed packages:\n");
			if (!n_state)
				printf("  none\n");
			else
				printf("  %-24s  %-12s  %s\n", "NAME",
				       "VERSION", "SOURCE");
			for (int i = 0; i < n_state; i++)
				printf("  %-24s  %-12s  %s\n", state[i].name,
				       state[i].version, state[i].source);
		}
		xfree(state, BPM_MAX_STATE * sizeof(*state));
		return ret ? bpm_fail("list", ret) : 0;
	}
	if (!strcmp(sub, "uninstall")) {
		struct bpm_state_entry *state;
		int n_state, lock, ret, i;

		if (argc != 3 || is_help(argv[2])) {
			fprintf(stderr, "usage: shirudo bpm uninstall <package>\n");
			return argc == 3 ? 0 : 2;
		}
		if (!bpm_name_ok(argv[2]))
			return bpm_fail("uninstall", -EINVAL);
		state = xcalloc(BPM_MAX_STATE, sizeof(*state));
		if (!state)
			return bpm_fail("uninstall", -ENOMEM);
		lock = with_bpm_lock();
		if (lock < 0) {
			xfree(state, BPM_MAX_STATE * sizeof(*state));
			return bpm_finish(-1, lock, "lock");
		}
		ret = bpm_state_read(state, &n_state);
		for (i = 0; !ret && i < n_state; i++) {
			if (!strcmp(state[i].name, argv[2]))
				break;
		}
		if (!ret && i == n_state)
			ret = -ENOENT;
		if (!ret)
			ret = package_uninstall(&state[i]);
		if (!ret) {
			memmove(&state[i], &state[i + 1],
				(size_t)(n_state - i - 1) * sizeof(*state));
			ret = bpm_state_write(state, n_state - 1);
		}
		xfree(state, BPM_MAX_STATE * sizeof(*state));
		return bpm_finish(lock, ret, "uninstall");
	}
	if (!strcmp(sub, "upgrade") && argc == 2)
		return with_tables(bpm_upgrade, NULL, "upgrade");
	return 2;
}
