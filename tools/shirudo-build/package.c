// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * gen_loader + CMS sign + .upatch container writer.
 */

#include <endian.h>
#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>
#include <shirudo/upatch.h>

#include "bpf/lib/shirudo_serializer.h"
#include "bpm_package.h"
#include "elf_target.h"
#include "io.h"
#include "loader.h"
#include "log.h"
#include "macros.h"
#include "malloc.h"
#include "package.h"
#include "paths.h"
#include "sign.h"
#include "upatch.h"
#include "upatch_rodata.h"

/*
 * A detached CMS over an ML-DSA-87 signature is about 5 KiB (4627-byte
 * signature plus SignerInfo); the kernel caps attr.signature_size at
 * 64 KiB (BPF_PROG_MAX_SIGNATURE_SIZE).
 */
#define SHIRUDO_MAX_SIG_SIZE	16384
#define SHIRUDO_SERIALIZER_PREFIX	"shirudo_serialize__"
#define SHIRUDO_TEST_RUN_PREFIX	"shirudo_test__"

static struct bpf_map *find_rodata(struct bpf_object *obj);

struct shirudo_unload_params {
	char	name[SHIRUDO_UPATCH_NAME_MAX];
	__u8	expected_sha256[SHIRUDO_UPATCH_PAYLOAD_HASH_LEN];
};

struct decoder_manifest_view {
	__u32		language;
	__u32		api_version;
	__u32		input_format;
	__u32		export_signal;
	char		upatch[64];
	char		map[16];
	char		source[64];
	char		entrypoint[32];
};

struct decoder_file {
	struct decoder_manifest_view	manifest;
	char				*path;
	char				*source;
	__u32				source_len;
};

struct decoder_set {
	struct decoder_file	*items;
	__u32			nr_items;
};

static void pack_header(struct shirudo_upatch_header *h,
			const char *name, __u32 type, __u32 flags,
			const __u8 *payload_sha256,
			__u32 loader_off, __u32 loader_len,
			__u32 sig_off, __u32 sig_len,
			__u32 meta_off, __u32 meta_len,
			__u32 data_off, __u32 data_len,
			__u32 log_buf_sz,
			__u32 rodata_data_off, __u32 nr_maps, __u32 nr_progs)
{
	memset(h, 0, sizeof(*h));
	h->magic   = htole64(SHIRUDO_UPATCH_MAGIC);
	h->version = htole32(SHIRUDO_UPATCH_VERSION);
	h->flags   = htole32(flags);
	strscpy(h->name, name, sizeof(h->name));
	memcpy(h->payload_sha256, payload_sha256,
	       SHIRUDO_UPATCH_PAYLOAD_HASH_LEN);
	h->loader_insns_off = htole32(loader_off);
	h->loader_insns_len = htole32(loader_len);
	h->signature_off    = htole32(sig_off);
	h->signature_len    = htole32(sig_len);
	h->metadata_off     = htole32(meta_off);
	h->metadata_len     = htole32(meta_len);
	h->data_off         = htole32(data_off);
	h->data_len         = htole32(data_len);
	h->log_buf_sz       = htole32(log_buf_sz);
	h->nr_maps          = htole32(nr_maps);
	h->nr_progs         = htole32(nr_progs);
	h->rodata_data_off  = htole32(rodata_data_off);
	h->type             = htole32(type);
	h->reserved1        = 0;
}

static int package_resign_symbols(const char *original,
				  const char *modified, const char *output,
				  const struct shirudo_data_range *ranges,
				  size_t nr_ranges, const char *const *symbols,
				  size_t nr_symbols, const char *pkey_path,
				  const char *cert_path)
{
	struct shirudo_upatch_header hdr;
	struct shirudo_sign_io sio = {};
	struct shirudo_upatch src = {}, mod = {};
	struct shirudo_rodata_range expected[16] = {};
	const __u8 *src_data, *mod_data;
	bool range_found[16] = {};
	__u8 digest[SHIRUDO_SHA256_LEN], *payload = NULL, *sig_buf = NULL;
	char name[SHIRUDO_UPATCH_NAME_MAX + 1];
	__u32 loader_off, sig_off, data_off, meta_off;
	__u32 digest_len;
	__u64 total, payload_len;
	size_t i, j;
	int fd = -1;
	int rc;

	if (!original || !modified || !output || !ranges || !symbols ||
	    !nr_ranges || nr_ranges > ARRAY_SIZE(expected) ||
	    nr_symbols != nr_ranges || !strcmp(original, output) ||
	    !strcmp(modified, output))
		return -EINVAL;
	rc = upatch_open(original, &src);
	if (rc)
		return rc;
	rc = upatch_open(modified, &mod);
	if (rc)
		goto out;
	src_data = upatch_data(&src);
	mod_data = upatch_data(&mod);
	if (upatch_is_unload(&src) || upatch_is_unload(&mod) ||
	    memcmp(src.map, mod.map, SHIRUDO_UPATCH_HEADER_SIZE) ||
	    src.hdr.loader_insns_len != mod.hdr.loader_insns_len ||
	    src.hdr.signature_len != mod.hdr.signature_len ||
	    src.hdr.data_len != mod.hdr.data_len ||
	    src.hdr.metadata_len != mod.hdr.metadata_len ||
	    memcmp(upatch_loader(&src), upatch_loader(&mod),
		   src.hdr.loader_insns_len) ||
	    memcmp(upatch_signature(&src), upatch_signature(&mod),
		   src.hdr.signature_len) ||
	    (src.hdr.metadata_len &&
	     memcmp(upatch_metadata(&src), upatch_metadata(&mod),
		    src.hdr.metadata_len))) {
		rc = -EINVAL;
		goto out;
	}
	for (i = 0; i < nr_ranges; i++) {
		if (!ranges[i].length || ranges[i].offset > src.hdr.data_len ||
		    ranges[i].length > src.hdr.data_len - ranges[i].offset ||
		    (i && ranges[i].offset <
		     ranges[i - 1].offset + ranges[i - 1].length)) {
			rc = -EINVAL;
			goto out;
		}
	}
	for (i = 0; i < src.hdr.data_len; i++) {
		bool allowed = false;

		for (j = 0; j < nr_ranges; j++)
			if (i >= ranges[j].offset &&
			    i - ranges[j].offset < ranges[j].length) {
				allowed = true;
				break;
			}
		if (!allowed && src_data[i] != mod_data[i]) {
			rc = -EPERM;
			goto out;
		}
	}
	if (!memchr(src.hdr.name, '\0', sizeof(src.hdr.name))) {
		rc = -EINVAL;
		goto out;
	}
	if ((__u64)src.hdr.loader_insns_len + src.hdr.data_len > SIZE_MAX) {
		rc = -EOVERFLOW;
		goto out;
	}
	payload_len = (__u64)src.hdr.loader_insns_len + src.hdr.data_len;
	payload = xmalloc((size_t)payload_len);
	if (!payload) {
		rc = -ENOMEM;
		goto out;
	}
	memcpy(payload, upatch_loader(&src), src.hdr.loader_insns_len);
	memcpy(payload + src.hdr.loader_insns_len, upatch_data(&src),
	       src.hdr.data_len);
	rc = bpm_verify_cms(payload, (size_t)payload_len,
			    upatch_signature(&src), src.hdr.signature_len,
			    cert_path);
	if (rc)
		goto out;
	if (EVP_Digest(payload, (size_t)payload_len, digest, &digest_len,
		       EVP_sha256(), NULL) != 1 ||
	    digest_len != sizeof(digest) ||
	    memcmp(digest, src.hdr.payload_sha256, sizeof(digest))) {
		rc = -EBADMSG;
		goto out;
	}
	for (i = 0; i < nr_symbols; i++) {
		rc = upatch_rodata_symbol_range(&src, symbols[i], &expected[i]);
		if (rc)
			goto out;
	}
	for (i = 0; i < nr_ranges; i++) {
		for (j = 0; j < nr_symbols; j++)
			if (ranges[i].offset == expected[j].offset &&
			    ranges[i].length == expected[j].size &&
			    !range_found[j]) {
				range_found[j] = true;
				break;
			}
		if (j == nr_symbols) {
			rc = -EPERM;
			goto out;
		}
	}
	sig_buf = xmalloc(SHIRUDO_MAX_SIG_SIZE);
	if (!sig_buf) {
		rc = -ENOMEM;
		goto out;
	}
	sio.insns = upatch_loader(&mod);
	sio.insns_sz = mod.hdr.loader_insns_len;
	sio.data = upatch_data(&mod);
	sio.data_sz = mod.hdr.data_len;
	sio.signature = sig_buf;
	sio.signature_sz = SHIRUDO_MAX_SIG_SIZE;
	rc = cms_sign(&sio, pkey_path, cert_path);
	if (rc)
		goto out;
	loader_off = sizeof(hdr);
	if ((__u64)loader_off + sio.insns_sz > UINT32_MAX) {
		rc = -EOVERFLOW;
		goto out;
	}
	sig_off = loader_off + (__u32)sio.insns_sz;
	if ((__u64)sig_off + sio.signature_sz > UINT32_MAX) {
		rc = -EOVERFLOW;
		goto out;
	}
	data_off = sig_off + (__u32)sio.signature_sz;
	if ((__u64)data_off + sio.data_sz > UINT32_MAX) {
		rc = -EOVERFLOW;
		goto out;
	}
	meta_off = data_off + (__u32)sio.data_sz;
	total = (__u64)meta_off + mod.hdr.metadata_len;
	if (total > SHIRUDO_UPATCH_FILE_MAX) {
		rc = -E2BIG;
		goto out;
	}
	memcpy(name, mod.hdr.name, SHIRUDO_UPATCH_NAME_MAX);
	name[SHIRUDO_UPATCH_NAME_MAX] = '\0';
	pack_header(&hdr, name, mod.hdr.type, mod.hdr.flags,
		    sio.payload_sha256,
		    loader_off, (__u32)sio.insns_sz,
		    sig_off, (__u32)sio.signature_sz,
		    mod.hdr.metadata_len ? meta_off : 0, mod.hdr.metadata_len,
		    sio.data_sz ? data_off : 0, (__u32)sio.data_sz,
		    mod.hdr.log_buf_sz, mod.hdr.rodata_data_off,
		    mod.hdr.nr_maps, mod.hdr.nr_progs);
	fd = open(output, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		rc = -errno;
		goto out;
	}
	rc = write_complete(fd, &hdr, sizeof(hdr));
	if (!rc)
		rc = write_complete(fd, sio.insns, sio.insns_sz);
	if (!rc)
		rc = write_complete(fd, sig_buf, sio.signature_sz);
	if (!rc && sio.data_sz)
		rc = write_complete(fd, sio.data, sio.data_sz);
	if (!rc && mod.hdr.metadata_len)
		rc = write_complete(fd, upatch_metadata(&mod), mod.hdr.metadata_len);
	if (!rc && fsync(fd) != 0)
		rc = -errno;
out:
	if (fd >= 0)
		close(fd);
	if (sig_buf)
		xfree(sig_buf, SHIRUDO_MAX_SIG_SIZE);
	if (payload)
		xfree(payload, (size_t)payload_len);
	upatch_close(&mod);
	upatch_close(&src);
	return rc;
}

int shirudo_build_package_resign(const char *original,
				 const char *modified, const char *output,
				 const struct shirudo_data_range *ranges,
				 size_t nr_ranges, const char *pkey_path,
				 const char *cert_path)
{
	static const char *const symbols[] = {
		"obs_watch_v4", "obs_watch_v6",
	};

	return package_resign_symbols(original, modified, output, ranges,
				      nr_ranges, symbols, ARRAY_SIZE(symbols),
				      pkey_path, cert_path);
}

int shirudo_build_package_patch_rodata(const char *input, const char *output,
				       const char *symbol, const __u8 *value,
				      size_t value_len, const char *pkey_path,
				      const char *cert_path)
{
	struct shirudo_upatch src = {};
	struct shirudo_rodata_range range = {};
	struct shirudo_data_range allowed = {};
	const char *symbols[1] = { symbol };
	__u8 digest[SHIRUDO_SHA256_LEN], *payload = NULL, *candidate = NULL;
	char modified[] = "/tmp/shirudo-rodata-XXXXXX";
	__u64 payload_len;
	__u32 digest_len;
	int fd = -1;
	int rc;

	if (!input || !output || !symbol || !value || !value_len ||
	    !strcmp(input, output))
		return -EINVAL;
	rc = upatch_open(input, &src);
	if (rc)
		return rc;
	if (upatch_is_unload(&src)) {
		rc = -EINVAL;
		goto out;
	}
	payload_len = (__u64)src.hdr.loader_insns_len + src.hdr.data_len;
	if (payload_len > SIZE_MAX) {
		rc = -EOVERFLOW;
		goto out;
	}
	payload = xmalloc((size_t)payload_len);
	if (!payload) {
		rc = -ENOMEM;
		goto out;
	}
	memcpy(payload, upatch_loader(&src), src.hdr.loader_insns_len);
	memcpy(payload + src.hdr.loader_insns_len, upatch_data(&src),
	       src.hdr.data_len);
	rc = bpm_verify_cms(payload, (size_t)payload_len,
			    upatch_signature(&src), src.hdr.signature_len,
			    cert_path);
	if (rc)
		goto out;
	if (EVP_Digest(payload, (size_t)payload_len, digest, &digest_len,
		       EVP_sha256(), NULL) != 1 ||
	    digest_len != sizeof(digest) ||
	    memcmp(digest, src.hdr.payload_sha256, sizeof(digest))) {
		rc = -EBADMSG;
		goto out;
	}
	rc = upatch_rodata_symbol_range(&src, symbol, &range);
	if (rc)
		goto out;
	if (value_len != range.size || range.offset > src.hdr.data_len ||
	    value_len > src.hdr.data_len - range.offset) {
		rc = -EINVAL;
		goto out;
	}
	candidate = xmalloc(src.map_size);
	if (!candidate) {
		rc = -ENOMEM;
		goto out;
	}
	memcpy(candidate, src.map, src.map_size);
	memcpy(candidate + src.hdr.data_off + range.offset, value, value_len);
	fd = mkstemp(modified);
	if (fd < 0) {
		rc = -errno;
		goto out;
	}
	rc = write_complete(fd, candidate, src.map_size);
	if (!rc && fsync(fd))
		rc = -errno;
	if (close(fd) && !rc)
		rc = -errno;
	fd = -1;
	if (rc)
		goto out;
	allowed.offset = range.offset;
	allowed.length = range.size;
	rc = package_resign_symbols(input, modified, output, &allowed, 1,
				    symbols, ARRAY_SIZE(symbols), pkey_path,
				    cert_path);
out:
	if (fd >= 0)
		close(fd);
	if (modified[0] && access(modified, F_OK) == 0)
		unlink(modified);
	if (candidate)
		xfree(candidate, src.map_size);
	if (payload)
		xfree(payload, (size_t)payload_len);
	upatch_close(&src);
	return rc;
}

int shirudo_build_package_verify(const char *input, const char *cert_path)
{
	struct shirudo_upatch upatch = {};
	__u8 digest[SHIRUDO_SHA256_LEN], *payload = NULL;
	__u64 payload_len;
	__u32 digest_len;
	int rc;

	rc = upatch_open(input, &upatch);
	if (rc)
		return rc;
	if (upatch_is_unload(&upatch)) {
		rc = -EINVAL;
		goto out;
	}
	payload_len = (__u64)upatch.hdr.loader_insns_len + upatch.hdr.data_len;
	if (payload_len > SIZE_MAX) {
		rc = -EOVERFLOW;
		goto out;
	}
	payload = xmalloc((size_t)payload_len);
	if (!payload) {
		rc = -ENOMEM;
		goto out;
	}
	memcpy(payload, upatch_loader(&upatch), upatch.hdr.loader_insns_len);
	memcpy(payload + upatch.hdr.loader_insns_len, upatch_data(&upatch),
	       upatch.hdr.data_len);
	rc = bpm_verify_cms(payload, (size_t)payload_len,
			    upatch_signature(&upatch), upatch.hdr.signature_len,
			    cert_path);
	if (rc)
		goto out;
	if (EVP_Digest(payload, (size_t)payload_len, digest, &digest_len,
		       EVP_sha256(), NULL) != 1 ||
	    digest_len != sizeof(digest) ||
	    memcmp(digest, upatch.hdr.payload_sha256, sizeof(digest)))
		rc = -EBADMSG;
out:
	if (payload)
		xfree(payload, (size_t)payload_len);
	upatch_close(&upatch);
	return rc;
}

int shirudo_build_upatch_cli(int argc, char **argv)
{
	const char *keys_dir = NULL, *original = NULL, *modified = NULL;
	const char *output = NULL;
	const char *pkey = SHIRUDO_SIGNING_KEY_PATH;
	const char *cert = SHIRUDO_CERT_PATH;
	struct shirudo_data_range ranges[16] = {};
	char pkey_buf[PATH_MAX], cert_buf[PATH_MAX];
	int pkey_explicit = 0, cert_explicit = 0;
	size_t nr_ranges = 0;
	int i;
	int rc;

	if (argc < 2 || strcmp(argv[1], "rewrite-rodata")) {
		fprintf(stderr,
			"usage: shirudo-build upatch rewrite-rodata "
			"<original.upatch> <modified.upatch> -o <output.upatch> "
			"--data-range <offset:length>... [--keys-dir <dir>] "
			"[--key <signing_key.pem>] [--cert <cert.der>]\n");
		return 2;
	}
	for (i = 2; i < argc; i++) {
		if (!strcmp(argv[i], "-o") && i + 1 < argc) {
			output = argv[++i];
		} else if (!strcmp(argv[i], "--data-range") && i + 1 < argc) {
			const char *range = argv[++i];
			size_t off_len = digits(range, strlen(range));
			const char *length;
			size_t len_len;
			__u64 offset, len;

			if (nr_ranges == ARRAY_SIZE(ranges) || !off_len ||
			    off_len >= strlen(range) ||
			    range[off_len] != ':')
				return 2;
			length = range + off_len + 1;
			len_len = digits(length, strlen(length));
			if (!len_len || length[len_len] ||
			    parse_u64(range, off_len, UINT32_MAX, &offset) ||
			    parse_u64(length, len_len, UINT32_MAX, &len) || !len)
				return 2;
			ranges[nr_ranges].offset = (__u32)offset;
			ranges[nr_ranges].length = (__u32)len;
			nr_ranges++;
		} else if (!strcmp(argv[i], "--keys-dir") && i + 1 < argc) {
			keys_dir = argv[++i];
		} else if (!strcmp(argv[i], "--key") && i + 1 < argc) {
			pkey = argv[++i];
			pkey_explicit = 1;
		} else if (!strcmp(argv[i], "--cert") && i + 1 < argc) {
			cert = argv[++i];
			cert_explicit = 1;
		} else if (argv[i][0] == '-') {
			pr_err("upatch rewrite-rodata: unknown option %s", argv[i]);
			return 2;
		} else if (!original) {
			original = argv[i];
		} else if (!modified) {
			modified = argv[i];
		} else {
			pr_err("upatch rewrite-rodata: unexpected argument %s",
			       argv[i]);
			return 2;
		}
	}
	if (!original || !modified || !output || !nr_ranges) {
		pr_err("upatch rewrite-rodata requires two inputs, -o, and data ranges");
		return 2;
	}
	keys_dir = keys_dir_resolve(keys_dir);
	if (keys_dir) {
		if (!pkey_explicit) {
			rc = shirudo_key_path(pkey_buf, sizeof(pkey_buf), keys_dir,
					      SHIRUDO_SIGNING_KEY_FILE);
			if (rc)
				return 2;
			pkey = pkey_buf;
		}
		if (!cert_explicit) {
			rc = shirudo_key_path(cert_buf, sizeof(cert_buf), keys_dir,
					      SHIRUDO_CERT_FILE);
			if (rc)
				return 2;
			cert = cert_buf;
		}
	}
	rc = shirudo_build_package_resign(original, modified, output,
					  ranges, nr_ranges, pkey, cert);
	if (rc)
		pr_err("upatch rewrite-rodata: %s", strerror(-rc));
	return rc ? 1 : 0;
}

static bool unsupported_kprobe_section(const char *sec)
{
	if (sec && sec[0] == '?')
		sec++;
	return sec &&
	       (strcmp(sec, "kprobe") == 0 ||
		strcmp(sec, "kretprobe") == 0 ||
		strcmp(sec, "kprobe/") == 0 ||
		strcmp(sec, "kretprobe/") == 0 ||
		strncmp(sec, "kprobe.multi", 12) == 0 ||
		strncmp(sec, "kretprobe.multi", 15) == 0);
}

static bool unsupported_uprobe_section(const char *sec)
{
	if (sec && sec[0] == '?')
		sec++;
	if (!sec)
		return false;
	if (strncmp(sec, "uprobe.multi/", 13) == 0 && sec[13])
		return false;
	return strcmp(sec, "uprobe") == 0 ||
	       strncmp(sec, "uprobe/", 7) == 0 ||
	       strncmp(sec, "uprobe.", 7) == 0 ||
	       strcmp(sec, "uretprobe") == 0 ||
	       strncmp(sec, "uretprobe/", 10) == 0 ||
	       strncmp(sec, "uretprobe.", 10) == 0;
}

static bool unsupported_sk_skb_section(const char *sec)
{
	if (sec && sec[0] == '?')
		sec++;
	return sec && (strcmp(sec, "sk_skb") == 0 ||
		       strncmp(sec, "sk_skb/", 7) == 0);
}

static bool unsupported_socket_filter_section(const char *sec)
{
	if (sec && sec[0] == '?')
		sec++;
	return sec && (strcmp(sec, "socket") == 0 ||
		       strcmp(sec, "socket_filter") == 0 ||
		       strncmp(sec, "socket/", 7) == 0 ||
		       strncmp(sec, "socket_filter/", 14) == 0);
}

static bool unsupported_cgroup_skb_section(const char *sec)
{
	if (!sec)
		return false;
	if (sec[0] == '?')
		sec++;
	if (strcmp(sec, "cgroup_skb/ingress") == 0 ||
	    strcmp(sec, "cgroup_skb/egress") == 0)
		return false;
	return strcmp(sec, "cgroup/skb") == 0 ||
	       strcmp(sec, "cgroup_skb") == 0 ||
	       strncmp(sec, "cgroup_skb/", 11) == 0;
}

static bool unsupported_fmod_ret_section(const char *sec)
{
	if (!sec)
		return false;
	if (sec[0] == '?')
		sec++;
	return strcmp(sec, "fmod_ret") == 0 ||
	       strcmp(sec, "fmod_ret/") == 0 ||
	       strcmp(sec, "fmod_ret.s") == 0 ||
	       strcmp(sec, "fmod_ret.s/") == 0;
}

/*
 * The sections the target attaches by their BTF target alone, through
 * BPF_RAW_TRACEPOINT_OPEN or a BPF_LSM_MAC link; every other type fails
 * there.
 */
static bool default_attach_section(const char *sec)
{
	static const char * const prefixes[] = {
		"fentry/", "fentry.s/", "fexit/", "fexit.s/",
		"lsm/", "lsm.s/", "tp_btf/",
	};
	size_t i, n;

	if (!sec)
		return false;
	if (sec[0] == '?')
		sec++;
	for (i = 0; i < ARRAY_SIZE(prefixes); i++) {
		n = strlen(prefixes[i]);
		if (!strncmp(sec, prefixes[i], n) && sec[n])
			return true;
	}
	return false;
}

static __u32 attach_kind_from_section(const char *sec,
				      const char **target)
{
	*target = NULL;
	if (!sec)
		return SHIRUDO_UPATCH_ATTACH_RAW_TRACEPOINT;
	if (sec[0] == '?')
		sec++;
	if (strncmp(sec, "kprobe/", 7) == 0 && sec[7]) {
		*target = sec + 7;
		return SHIRUDO_UPATCH_ATTACH_KPROBE;
	}
	if (strncmp(sec, "kretprobe/", 10) == 0 && sec[10]) {
		*target = sec + 10;
		return SHIRUDO_UPATCH_ATTACH_KRETPROBE;
	}
	if (strncmp(sec, "uprobe.multi/", 13) == 0 && sec[13]) {
		*target = sec + 13;
		return SHIRUDO_UPATCH_ATTACH_UPROBE_MULTI;
	}
	if (strcmp(sec, "cgroup_skb/ingress") == 0)
		return SHIRUDO_UPATCH_ATTACH_CGROUP_SKB_INGRESS;
	if (strcmp(sec, "cgroup_skb/egress") == 0)
		return SHIRUDO_UPATCH_ATTACH_CGROUP_SKB_EGRESS;
	if (strncmp(sec, "fmod_ret/", 9) == 0 && sec[9])
		return SHIRUDO_UPATCH_ATTACH_FMOD_RET;
	if (strncmp(sec, "fmod_ret.s/", 11) == 0 && sec[11])
		return SHIRUDO_UPATCH_ATTACH_FMOD_RET;
	if (strcmp(sec, "netfilter") == 0)
		return SHIRUDO_UPATCH_ATTACH_NETFILTER_IPV6_PRE_ROUTING;
	return SHIRUDO_UPATCH_ATTACH_RAW_TRACEPOINT;
}

static int split_uprobe_target(const char *src, char **path,
			       __u32 *path_len, char *pattern,
			       size_t pattern_sz)
{
	const char *colon;
	size_t plen, pat_len;

	*path = NULL;
	*path_len = 0;
	if (!src || src[0] != '/')
		return -EINVAL;
	colon = strchr(src, ':');
	if (!colon || colon == src || colon[1] == '\0')
		return -EINVAL;
	plen = (size_t)(colon - src);
	pat_len = strlen(colon + 1);
	if (plen >= SHIRUDO_UPATCH_UPROBE_PATH_MAX ||
	    pat_len == 0 || pat_len >= pattern_sz)
		return -ENAMETOOLONG;
	if (strchr(colon + 1, ',') || strchr(colon + 1, '|'))
		return -EOPNOTSUPP;
	*path = xstrndup(src, plen);
	if (!*path)
		return -ENOMEM;
	*path_len = (__u32)plen;
	memcpy(pattern, colon + 1, pat_len + 1);
	return 0;
}

/*
 * "<symbol>[+<offset>]", the offset in decimal or 0x hexadecimal; a
 * leading zero is refused rather than read as octal.
 */
static int split_probe_target(const char *src, char *target,
			      size_t target_sz, __u64 *offset)
{
	const char *plus = strrchr(src, '+');
	size_t len;

	*offset = 0;
	if (!src || !src[0])
		return -EINVAL;
	if (plus) {
		const char *num = plus + 1;
		size_t n = strlen(num);
		int rc;

		if (plus == src)
			return -EINVAL;
		if (n > 2 && num[0] == '0' && (num[1] == 'x' || num[1] == 'X'))
			rc = parse_x64(num + 2, n - 2, UINT64_MAX, offset);
		else if (n > 1 && num[0] == '0')
			rc = -EINVAL;
		else
			rc = parse_u64(num, n, UINT64_MAX, offset);
		if (rc)
			return -EINVAL;
		len = (size_t)(plus - src);
	} else {
		len = strlen(src);
	}
	if (len == 0 || len >= target_sz)
		return -EINVAL;
	memcpy(target, src, len);
	target[len] = '\0';
	return 0;
}

static bool is_syscall_section(const char *sec)
{
	return sec && strcmp(sec, "syscall") == 0;
}

static const char *serializer_map_name(const struct bpf_program *p)
{
	const char *name = bpf_program__name(p);
	size_t prefix_len = strlen(SHIRUDO_SERIALIZER_PREFIX);

	if (!name || strncmp(name, SHIRUDO_SERIALIZER_PREFIX, prefix_len) != 0)
		return NULL;
	return name + prefix_len;
}

static bool object_has_map(struct bpf_object *obj, const char *want)
{
	struct bpf_map *m;

	bpf_object__for_each_map(m, obj) {
		const char *name = bpf_map__name(m);

		if (name && strcmp(name, want) == 0)
			return true;
	}
	return false;
}

static bool fixed_cstr_nonempty(const char *s, size_t n)
{
	return n && s[0] && memchr(s, '\0', n);
}

static void copy_fixed_cstr(char *dst, size_t dst_sz,
			    const char *src, size_t src_sz)
{
	size_t n = strnlen(src, src_sz);

	if (n >= dst_sz)
		n = dst_sz - 1;
	memcpy(dst, src, n);
	dst[n] = '\0';
}

static bool relpath_unsafe(const char *path)
{
	const char *p = path;

	if (!path[0] || path[0] == '/' || strchr(path, '\\'))
		return true;
	while (*p) {
		const char *slash = strchr(p, '/');
		size_t len = slash ? (size_t)(slash - p) : strlen(p);

		if (len == 0 || (len == 1 && p[0] == '.') ||
		    (len == 2 && p[0] == '.' && p[1] == '.'))
			return true;
		if (!slash)
			break;
		p = slash + 1;
	}
	return false;
}

static int make_decoder_path(const char *src_path, const char *rel,
			     char **out)
{
	const char *slash;
	size_t dir_len = 0, rel_len = strlen(rel), len;
	char *path;

	*out = NULL;
	if (relpath_unsafe(rel))
		return -EINVAL;
	if (src_path) {
		slash = strrchr(src_path, '/');
		if (slash)
			dir_len = (size_t)(slash - src_path) + 1;
	}
	if (dir_len > UINT32_MAX || rel_len > UINT32_MAX - 1 ||
	    dir_len > UINT32_MAX - rel_len - 1)
		return -EOVERFLOW;
	len = dir_len + rel_len + 1;
	path = xmalloc(len);
	if (!path)
		return -ENOMEM;
	if (dir_len)
		memcpy(path, src_path, dir_len);
	memcpy(path + dir_len, rel, rel_len);
	path[dir_len + rel_len] = '\0';
	*out = path;
	return 0;
}

static bool parse_decoder_manifest(const __u8 *p, size_t n,
				   struct decoder_manifest_view *out)
{
	const struct shirudo_decoder_manifest *m = (const void *)p;

	if (n < sizeof(*m))
		return false;
	if (rd_le32(p + offsetof(struct shirudo_decoder_manifest, magic)) !=
	    SHIRUDO_DECODER_MANIFEST_MAGIC)
		return false;
	if (rd_le16(p + offsetof(struct shirudo_decoder_manifest, version)) !=
	    SHIRUDO_UPATCH_DECODER_VERSION)
		return false;
	if (!fixed_cstr_nonempty(m->upatch, sizeof(m->upatch)) ||
	    !fixed_cstr_nonempty(m->map, sizeof(m->map)) ||
	    !fixed_cstr_nonempty(m->source, sizeof(m->source)) ||
	    !fixed_cstr_nonempty(m->entrypoint, sizeof(m->entrypoint)))
		return false;

	memset(out, 0, sizeof(*out));
	out->language = rd_le16(p + offsetof(struct shirudo_decoder_manifest,
					     language));
	out->api_version = rd_le16(p + offsetof(struct shirudo_decoder_manifest,
						api_version));
	out->input_format = rd_le16(p + offsetof(struct shirudo_decoder_manifest,
						 input_format));
	out->export_signal = rd_le16(p + offsetof(struct shirudo_decoder_manifest,
						  export_signal));
	if (out->language == 0 || out->api_version == 0 ||
	    out->input_format == 0 || out->export_signal == 0 ||
	    rd_le16(p + offsetof(struct shirudo_decoder_manifest, reserved)) != 0)
		return false;
	copy_fixed_cstr(out->upatch, sizeof(out->upatch),
			m->upatch, sizeof(m->upatch));
	copy_fixed_cstr(out->map, sizeof(out->map), m->map, sizeof(m->map));
	copy_fixed_cstr(out->source, sizeof(out->source),
			m->source, sizeof(m->source));
	copy_fixed_cstr(out->entrypoint, sizeof(out->entrypoint),
			m->entrypoint, sizeof(m->entrypoint));
	return true;
}

static void free_decoder_set(struct decoder_set *set)
{
	__u32 i;

	for (i = 0; i < set->nr_items; i++) {
		xstrfree(set->items[i].path);
		xfree(set->items[i].source, set->items[i].source_len + 1);
	}
	xfree(set->items, (size_t)set->nr_items * sizeof(set->items[0]));
	memset(set, 0, sizeof(*set));
}

static int decoder_set_add(struct decoder_set *set,
			   const struct decoder_manifest_view *manifest,
			   const char *src_path)
{
	struct decoder_file *items;
	struct decoder_file *item;
	char *path = NULL;
	size_t source_len = 0;
	char *source = NULL;
	int err;

	err = make_decoder_path(src_path, manifest->source, &path);
	if (err) {
		pr_err("decoder source path '%s' is invalid", manifest->source);
		return err;
	}
	err = read_file(path, 16u * 1024u * 1024u, &source,
			&source_len);
	if (!err && !source_len)
		err = -EINVAL;
	if (err) {
		pr_err("read decoder source %s: %s", path, strerror(-err));
		xstrfree(path);
		return err;
	}

	items = xreallocarray(set->items, set->nr_items, set->nr_items + 1,
			      sizeof(set->items[0]));
	if (!items) {
		xstrfree(path);
		xfree(source, source_len + 1);
		return -ENOMEM;
	}
	set->items = items;
	item = &set->items[set->nr_items++];
	item->manifest = *manifest;
	item->path = path;
	item->source = source;
	item->source_len = (__u32)source_len;
	return 0;
}

static int collect_decoder_manifests(struct bpf_object *obj,
				     const char *src_path,
				     const char *upatch_name,
				     struct decoder_set *out)
{
	struct bpf_map *rodata = find_rodata(obj);
	size_t data_sz, off;
	const __u8 *data;
	int err;

	memset(out, 0, sizeof(*out));
	if (!rodata)
		return 0;
	data = bpf_map__initial_value(rodata, &data_sz);
	if (!data || data_sz < sizeof(struct shirudo_decoder_manifest))
		return 0;

	for (off = 0; off + sizeof(struct shirudo_decoder_manifest) <= data_sz;
	     off += 4) {
		struct decoder_manifest_view manifest;

		if (!parse_decoder_manifest(data + off, data_sz - off,
					    &manifest))
			continue;
		if (manifest.language != SHIRUDO_UPATCH_DECODER_LANG_LUA ||
		    manifest.api_version != 1 ||
		    manifest.input_format != SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1 ||
		    (manifest.export_signal != SHIRUDO_UPATCH_DECODER_EXPORT_LOG &&
		     manifest.export_signal != SHIRUDO_UPATCH_DECODER_EXPORT_METRIC)) {
			pr_err("unsupported decoder ABI for '%s/%s'",
			       manifest.upatch, manifest.map);
			err = -EOPNOTSUPP;
			goto err_free;
		}
		if (strcmp(manifest.upatch, upatch_name) != 0) {
			pr_err("decoder upatch '%s' does not match package name '%s'",
			       manifest.upatch, upatch_name);
			err = -EINVAL;
			goto err_free;
		}
		if (!object_has_map(obj, manifest.map)) {
			pr_err("decoder manifest for missing map '%s'",
			       manifest.map);
			err = -EINVAL;
			goto err_free;
		}
		for (__u32 i = 0; i < out->nr_items; i++) {
			if (strcmp(out->items[i].manifest.upatch,
				   manifest.upatch) == 0 &&
			    strcmp(out->items[i].manifest.map,
				   manifest.map) == 0) {
				pr_err("duplicate decoder for '%s/%s'",
				       manifest.upatch, manifest.map);
				err = -EEXIST;
				goto err_free;
			}
		}
		err = decoder_set_add(out, &manifest, src_path);
		if (err)
			goto err_free;
	}
	return 0;

err_free:
	free_decoder_set(out);
	return err;
}

static int build_decoder_blob(const struct decoder_set *set,
			      void **out, __u32 *out_len)
{
	struct shirudo_upatch_decoder_blob *blob;
	__u64 entries_end, total;
	__u32 off;
	size_t i;

	*out = NULL;
	*out_len = 0;
	if (set->nr_items == 0)
		return 0;
	entries_end = sizeof(*blob) +
		      (__u64)set->nr_items *
		      sizeof(struct shirudo_upatch_decoder_entry);
	total = entries_end;
	for (i = 0; i < set->nr_items; i++)
		total += set->items[i].source_len;
	if (total > UINT32_MAX)
		return -EOVERFLOW;

	blob = xmalloc((size_t)total);
	if (!blob)
		return -ENOMEM;
	blob->magic = htole32(SHIRUDO_UPATCH_DECODER_MAGIC);
	blob->version = htole32(SHIRUDO_UPATCH_DECODER_VERSION);
	blob->nr_decoders = htole32(set->nr_items);
	blob->reserved = 0;

	off = (__u32)entries_end;
	for (i = 0; i < set->nr_items; i++) {
		const struct decoder_file *file = &set->items[i];
		struct shirudo_upatch_decoder_entry *d = &blob->decoders[i];

		d->language = htole32(file->manifest.language);
		d->api_version = htole32(file->manifest.api_version);
		d->input_format = htole32(file->manifest.input_format);
		d->export_signal = htole32(file->manifest.export_signal);
		strscpy(d->upatch, file->manifest.upatch, sizeof(d->upatch));
		strscpy(d->map, file->manifest.map, sizeof(d->map));
		strscpy(d->source, file->manifest.source, sizeof(d->source));
		strscpy(d->entrypoint, file->manifest.entrypoint,
			sizeof(d->entrypoint));
		d->source_off = htole32(off);
		d->source_len = htole32(file->source_len);
		memcpy((__u8 *)blob + off, file->source,
		       file->source_len);
		off += file->source_len;
	}

	*out = blob;
	*out_len = (__u32)total;
	return 0;
}

static int compose_signed_data(const void *data, __u32 data_len,
			       const void *decoder_blob,
			       __u32 decoder_blob_len,
			       void **out, __u32 *out_len)
{
	struct shirudo_upatch_decoder_trailer trailer = {};
	__u64 payload_len, total;
	__u32 pad_len;
	char *buf;

	*out = NULL;
	*out_len = data_len;
	if (!decoder_blob_len)
		return 0;
	payload_len = (__u64)data_len + decoder_blob_len;
	pad_len = (__u32)((8 - (payload_len & 7)) & 7);
	total = payload_len + pad_len;
	total += sizeof(trailer);
	if (total > UINT32_MAX)
		return -EOVERFLOW;
	buf = xmalloc((size_t)total);
	if (!buf)
		return -ENOMEM;
	if (data_len)
		memcpy(buf, data, data_len);
	memcpy(buf + data_len, decoder_blob, decoder_blob_len);
	memset(buf + data_len + decoder_blob_len, 0, pad_len);

	trailer.magic = htole32(SHIRUDO_UPATCH_DECODER_TRAILER_MAGIC);
	trailer.version = htole32(SHIRUDO_UPATCH_DECODER_VERSION);
	trailer.decoder_off = htole32(data_len);
	trailer.decoder_len = htole32(decoder_blob_len);
	memcpy(buf + data_len + decoder_blob_len + pad_len, &trailer,
	       sizeof(trailer));

	*out = buf;
	*out_len = (__u32)total;
	return 0;
}

static int validate_serializer_output_map(struct bpf_object *obj)
{
	struct bpf_map *m;

	bpf_object__for_each_map(m, obj) {
		const char *name = bpf_map__name(m);

		if (!name || strcmp(name, SHIRUDO_SERIAL_MAP_NAME) != 0)
			continue;
		if (bpf_map__type(m) != BPF_MAP_TYPE_ARRAY) {
			pr_err("%s must be BPF_MAP_TYPE_ARRAY",
			       SHIRUDO_SERIAL_MAP_NAME);
			return -EINVAL;
		}
		if (bpf_map__key_size(m) != sizeof(__u32)) {
			pr_err("%s must use a u32 key",
			       SHIRUDO_SERIAL_MAP_NAME);
			return -EINVAL;
		}
		if (bpf_map__value_size(m) !=
		    sizeof(struct shirudo_serial_chunk)) {
			pr_err("%s value must be struct shirudo_serial_chunk",
			       SHIRUDO_SERIAL_MAP_NAME);
			return -EINVAL;
		}
		if (bpf_map__max_entries(m) == 0 ||
		    bpf_map__max_entries(m) > SHIRUDO_SERIAL_MAX_CHUNKS) {
			pr_err("%s max_entries must be 1..%u",
			       SHIRUDO_SERIAL_MAP_NAME,
			       SHIRUDO_SERIAL_MAX_CHUNKS);
			return -EINVAL;
		}
		return 0;
	}
	pr_err("serializer upatch requires %s output map",
	       SHIRUDO_SERIAL_MAP_NAME);
	return -EINVAL;
}

static int build_prog_metadata(struct bpf_object *obj, __u32 nr_progs,
			       void **out, __u32 *out_len)
{
	struct build_uprobe_target {
		__u32 prog_idx;
		char *path;
		__u32 path_len;
		struct shirudo_elf_target elf;
	};
	struct shirudo_upatch_prog_metadata *md;
	struct build_uprobe_target *uprobe_targets = NULL;
	char (*seen_maps)[SHIRUDO_UPATCH_PROG_MAP_MAX] = NULL;
	struct bpf_program *p;
	size_t len, base_len, md_alloc_len;
	__u32 i = 0, n_seen = 0, nr_uprobe_targets = 0;
	bool has_serializer = false, has_test_run = false;
	int err;

	*out = NULL;
	*out_len = 0;
	bpf_object__for_each_program(p, obj) {
		if (serializer_map_name(p)) {
			has_serializer = true;
			break;
		}
	}
	if (has_serializer) {
		err = validate_serializer_output_map(obj);
		if (err)
			return err;
	}
	if (nr_progs >
	    (UINT32_MAX - sizeof(*md)) / sizeof(md->progs[0]))
		return -EOVERFLOW;
	base_len = sizeof(*md) + (size_t)nr_progs * sizeof(md->progs[0]);
	len = base_len;
	md_alloc_len = base_len;
	md = xmalloc(len);
	if (!md)
		return -ENOMEM;
	memset(md, 0, len);
	md->magic = htole32(SHIRUDO_UPATCH_PROG_MAGIC);
	md->version = htole32(SHIRUDO_UPATCH_PROG_VERSION);
	md->nr_progs = htole32(nr_progs);
	seen_maps = xcalloc(nr_progs, sizeof(*seen_maps));
	if (!seen_maps) {
		err = -ENOMEM;
		goto err_free;
	}
	uprobe_targets = xcalloc(nr_progs, sizeof(*uprobe_targets));
	if (!uprobe_targets) {
		err = -ENOMEM;
		goto err_free;
	}

	bpf_object__for_each_program(p, obj) {
		const char *sec = bpf_program__section_name(p);
		const char *ser_map = serializer_map_name(p);
		const char *target = NULL;
		__u64 offset = 0;
		__u32 kind, j;

		if (ser_map) {
			size_t ser_len = strlen(ser_map);

			if (!is_syscall_section(sec)) {
				pr_err("serializer '%s' must use SEC(\"syscall\")",
				       bpf_program__name(p));
				err = -EINVAL;
				goto err_free;
			}
			if (ser_len == 0 ||
			    ser_len >= SHIRUDO_UPATCH_PROG_MAP_MAX) {
				pr_err("serializer '%s' has invalid target map '%s'",
				       bpf_program__name(p), ser_map);
				err = -EINVAL;
				goto err_free;
			}
			if (strcmp(ser_map, SHIRUDO_SERIAL_MAP_NAME) == 0) {
				pr_err("serializer cannot target reserved map %s",
				       SHIRUDO_SERIAL_MAP_NAME);
				err = -EINVAL;
				goto err_free;
			}
			if (!object_has_map(obj, ser_map)) {
				pr_err("serializer '%s' targets missing map '%s'",
				       bpf_program__name(p), ser_map);
				err = -EINVAL;
				goto err_free;
			}
			for (j = 0; j < n_seen; j++) {
				if (strcmp(seen_maps[j], ser_map) == 0) {
					pr_err("duplicate serializer for map '%s'",
					       ser_map);
					err = -EINVAL;
					goto err_free;
				}
			}
			strscpy(seen_maps[n_seen++], ser_map, sizeof(seen_maps[0]));
			md->progs[i].role =
				htole32(SHIRUDO_UPATCH_PROG_ROLE_SERIALIZER);
			strscpy(md->progs[i].map, ser_map,
				sizeof(md->progs[i].map));
			i++;
			continue;
		}
		if (is_syscall_section(sec)) {
			const char *prog_name = bpf_program__name(p);
			size_t prefix_len = strlen(SHIRUDO_TEST_RUN_PREFIX);

			if (!prog_name || strncmp(prog_name, SHIRUDO_TEST_RUN_PREFIX,
						  prefix_len) != 0 ||
			    prog_name[prefix_len] == '\0') {
				pr_err("SEC(\"syscall\") program '%s' must be named %s<id>",
				       prog_name ?: "?", SHIRUDO_TEST_RUN_PREFIX);
				err = -EINVAL;
				goto err_free;
			}
			if (has_test_run) {
				pr_err("only one %s test-run program is supported",
				       SHIRUDO_TEST_RUN_PREFIX);
				err = -EINVAL;
				goto err_free;
			}
			has_test_run = true;
			md->progs[i].role =
				htole32(SHIRUDO_UPATCH_PROG_ROLE_TEST_RUN);
			i++;
			continue;
		}
		if (unsupported_kprobe_section(sec)) {
			pr_err("unsupported kprobe section '%s'; use kprobe/<symbol> or kretprobe/<symbol>",
			       sec);
			err = -EOPNOTSUPP;
			goto err_free;
		}
		if (unsupported_uprobe_section(sec)) {
			pr_err("unsupported uprobe section '%s'; use uprobe.multi//absolute/path:function_glob (entry probes only)",
			       sec);
			err = -EOPNOTSUPP;
			goto err_free;
		}
		if (unsupported_sk_skb_section(sec)) {
			pr_err("unsupported sk_skb section '%s'; supported network packet sections are cgroup_skb/ingress, cgroup_skb/egress, and netfilter",
			       sec);
			err = -EOPNOTSUPP;
			goto err_free;
		}
		if (unsupported_socket_filter_section(sec)) {
			pr_err("unsupported socket filter section '%s'; Shirudo upatches require a pinnable bpf_link lifecycle",
			       sec);
			err = -EOPNOTSUPP;
			goto err_free;
		}
		if (unsupported_cgroup_skb_section(sec)) {
			pr_err("unsupported cgroup_skb section '%s'; use cgroup_skb/ingress or cgroup_skb/egress",
			       sec);
			err = -EOPNOTSUPP;
			goto err_free;
		}
		if (unsupported_fmod_ret_section(sec)) {
			pr_err("unsupported fmod_ret section '%s'; use fmod_ret/<symbol> or fmod_ret.s/<symbol>",
			       sec);
			err = -EOPNOTSUPP;
			goto err_free;
		}
		kind = attach_kind_from_section(sec, &target);
		if (kind == SHIRUDO_UPATCH_ATTACH_RAW_TRACEPOINT &&
		    !default_attach_section(sec)) {
			pr_err("unsupported section '%s'; supported are fentry, fexit, fmod_ret, lsm, tp_btf, kprobe, kretprobe, uprobe.multi, cgroup_skb and netfilter",
			       sec);
			err = -EOPNOTSUPP;
			goto err_free;
		}
		md->progs[i].role =
			htole32(SHIRUDO_UPATCH_PROG_ROLE_ATTACH);
		md->progs[i].kind = htole32(kind);
		if (kind == SHIRUDO_UPATCH_ATTACH_UPROBE_MULTI) {
			struct build_uprobe_target *ut =
				&uprobe_targets[nr_uprobe_targets];

			err = split_uprobe_target(target, &ut->path,
						  &ut->path_len,
						  md->progs[i].target,
						  sizeof(md->progs[i].target));
			if (err) {
				if (err == -EOPNOTSUPP)
					pr_err("invalid uprobe.multi section '%s': ',' and '|' alternation are unsupported; use one '*'/'?' glob",
					       sec);
				else
					pr_err("invalid uprobe.multi section '%s'; expected uprobe.multi//absolute/path:function_glob",
					       sec);
				goto err_free;
			}
			ut->prog_idx = i;
			nr_uprobe_targets++;
			err = elf_target_resolve(ut->path,
						 md->progs[i].target, &ut->elf);
			if (err) {
				if (err == -ENOENT)
					pr_err("uprobe.multi pattern '%s' matched no functions in %s (or the ELF has no GNU build ID)",
					       md->progs[i].target, ut->path);
				else
					pr_err("cannot resolve uprobe.multi target %s:%s: %s",
					       ut->path, md->progs[i].target,
					       strerror(-err));
				goto err_free;
			}
		} else if (target) {
			err = split_probe_target(target, md->progs[i].target,
						 sizeof(md->progs[i].target),
						 &offset);
			if (err) {
				pr_err("invalid kprobe target in section '%s'",
				       sec);
				goto err_free;
			}
			if (kind == SHIRUDO_UPATCH_ATTACH_KRETPROBE && offset) {
				pr_err("kretprobe offsets are unsupported in section '%s'",
				       sec);
				err = -EINVAL;
				goto err_free;
			}
		}
		md->progs[i].offset = htole64(offset);
		i++;
	}

	if (nr_uprobe_targets) {
		struct shirudo_upatch_uprobe_targets targets = {};
		__u8 *cursor;
		__u32 j;

		if (len > UINT32_MAX - sizeof(targets)) {
			err = -EOVERFLOW;
			goto err_free;
		}
		len += sizeof(targets);
		for (j = 0; j < nr_uprobe_targets; j++) {
			const struct build_uprobe_target *ut = &uprobe_targets[j];
			size_t record_len = sizeof(struct shirudo_upatch_uprobe_target) +
				ut->path_len + ut->elf.build_id_len +
				(size_t)ut->elf.nr_offsets * sizeof(__u64);

			if (record_len > UINT32_MAX || len > UINT32_MAX - record_len) {
				err = -EOVERFLOW;
				goto err_free;
			}
			len += record_len;
		}
		{
			void *grown = xreallocarray(md, base_len, len, 1);

			if (!grown) {
				err = -ENOMEM;
				goto err_free;
			}
			md = grown;
			md_alloc_len = len;
		}
		targets.magic = htole32(SHIRUDO_UPATCH_UPROBE_TARGET_MAGIC);
		targets.version = htole32(SHIRUDO_UPATCH_UPROBE_TARGET_VERSION);
		targets.nr_targets = htole32(nr_uprobe_targets);
		cursor = (__u8 *)md + base_len;
		memcpy(cursor, &targets, sizeof(targets));
		cursor += sizeof(targets);
		for (j = 0; j < nr_uprobe_targets; j++) {
			const struct build_uprobe_target *ut = &uprobe_targets[j];
			struct shirudo_upatch_uprobe_target record = {};
			__u32 k;

			record.prog_idx = htole32(ut->prog_idx);
			record.path_len = htole32(ut->path_len);
			record.build_id_len = htole32(ut->elf.build_id_len);
			record.nr_offsets = htole32(ut->elf.nr_offsets);
			memcpy(cursor, &record, sizeof(record));
			cursor += sizeof(record);
			memcpy(cursor, ut->path, ut->path_len);
			cursor += ut->path_len;
			memcpy(cursor, ut->elf.build_id, ut->elf.build_id_len);
			cursor += ut->elf.build_id_len;
			for (k = 0; k < ut->elf.nr_offsets; k++) {
				__u64 offset = htole64(ut->elf.offsets[k]);

				memcpy(cursor, &offset, sizeof(offset));
				cursor += sizeof(offset);
			}
		}
	}

	*out = md;
	*out_len = (__u32)len;
	xfree(seen_maps, (size_t)nr_progs * sizeof(*seen_maps));
	for (i = 0; i < nr_uprobe_targets; i++) {
		xstrfree(uprobe_targets[i].path);
		elf_target_free(&uprobe_targets[i].elf);
	}
	xfree(uprobe_targets, (size_t)nr_progs * sizeof(*uprobe_targets));
	return 0;

err_free:
	xfree(seen_maps, (size_t)nr_progs * sizeof(*seen_maps));
	for (i = 0; i < nr_uprobe_targets; i++) {
		xstrfree(uprobe_targets[i].path);
		elf_target_free(&uprobe_targets[i].elf);
	}
	xfree(uprobe_targets, (size_t)nr_progs * sizeof(*uprobe_targets));
	xfree(md, md_alloc_len);
	return err;
}

/*
 * The generated loader is executed on the target kernel, while libbpf's
 * feature probing happens on the build host.  Preserve the attach type for
 * cgroup_skb programs explicitly so a host that lacks expected_attach_type
 * support cannot silently produce a loader that the target rejects.
 */
static int set_target_attach_types(struct bpf_object *obj)
{
	struct bpf_program *p;

	bpf_object__for_each_program(p, obj) {
		const char *sec = bpf_program__section_name(p);
		enum bpf_attach_type type;

		if (strcmp(sec, "cgroup_skb/ingress") == 0)
			type = BPF_CGROUP_INET_INGRESS;
		else if (strcmp(sec, "cgroup_skb/egress") == 0)
			type = BPF_CGROUP_INET_EGRESS;
		else
			continue;

		if (bpf_program__set_expected_attach_type(p, type) != 0) {
			pr_err("set expected attach type for program '%s'",
			       bpf_program__name(p));
			return -EINVAL;
		}
	}
	return 0;
}

static int register_target_attach_types(int handler_ids[2])
{
	handler_ids[0] = libbpf_register_prog_handler("cgroup_skb/ingress",
						      BPF_PROG_TYPE_CGROUP_SKB,
						      BPF_CGROUP_INET_INGRESS,
						      NULL);
	if (handler_ids[0] < 0)
		return handler_ids[0];

	handler_ids[1] = libbpf_register_prog_handler("cgroup_skb/egress",
						      BPF_PROG_TYPE_CGROUP_SKB,
						      BPF_CGROUP_INET_EGRESS,
						      NULL);
	if (handler_ids[1] < 0) {
		libbpf_unregister_prog_handler(handler_ids[0]);
		handler_ids[0] = -1;
		return handler_ids[1];
	}
	return 0;
}

static void unregister_target_attach_types(int handler_ids[2])
{
	if (handler_ids[1] >= 0)
		libbpf_unregister_prog_handler(handler_ids[1]);
	if (handler_ids[0] >= 0)
		libbpf_unregister_prog_handler(handler_ids[0]);
	handler_ids[0] = -1;
	handler_ids[1] = -1;
}

/*
 * Takes ownership of obj. src_path anchors relative decoder paths;
 * NULL for a .bpf.o input or an unload directive.
 */
static int finalize_object(struct bpf_object *obj, const char *out_path,
			   const char *upatch_name, __u32 flags,
			   const void *meta, __u32 meta_len,
			   const char *src_path,
			   const char *pkey_path, const char *cert_path)
{
	LIBBPF_OPTS(gen_loader_opts, opts);
	__u32 loader_off, sig_off, data_off, data_len, meta_off;
	__u32 write_meta_len = meta_len, attach_meta_len = 0;
	__u32 decoder_blob_len = 0, signed_data_len = 0;
	__u32 nr_maps = 0, nr_progs = 0;
	__u32 rodata_data_off = 0;
	struct shirudo_upatch_header hdr;
	struct shirudo_upatch rodata_upatch = {};
	struct decoder_set decoders = {};
	struct shirudo_sign_io sio = {};
	const void *signed_data = NULL;
	const void *write_meta = meta;
	size_t loader_data_len;
	void *signed_data_buf = NULL;
	void *loader_data_buf = NULL;
	void *decoder_blob = NULL;
	__u32 nr_decoders = 0;
	void *attach_meta = NULL;
	struct bpf_program *p;
	void *sig_buf = NULL;
	struct bpf_map *m;
	int err = 0;
	int fd = -1;

	/*
	 * The loader writes map_fd/prog_fd back into descriptor arrays
	 * trailing its ctx, in the same order libbpf iterates the
	 * object. The target needs these counts to locate prog_fd[]
	 * after BPF_PROG_TEST_RUN -- it has only the .upatch, not the
	 * object. Iteration order here matches gen_loader's. Build
	 * attach metadata before loader generation so unsupported section
	 * names fail with Shirudo's own diagnostics instead of depending
	 * on host kernel load behavior.
	 */
	bpf_object__for_each_map(m, obj)
		nr_maps++;
	bpf_object__for_each_program(p, obj)
		nr_progs++;

	if (!(flags & SHIRUDO_DIRECTIVE_UNLOAD)) {
		err = set_target_attach_types(obj);
		if (err)
			goto out;

		err = build_prog_metadata(obj, nr_progs,
					  &attach_meta, &attach_meta_len);
		if (err)
			goto out;
		write_meta = attach_meta;
		write_meta_len = attach_meta_len;

		err = collect_decoder_manifests(obj, src_path, upatch_name,
						&decoders);
		if (err)
			goto out;
		err = build_decoder_blob(&decoders, &decoder_blob,
					 &decoder_blob_len);
		nr_decoders = decoders.nr_items;
		free_decoder_set(&decoders);
		if (err)
			goto out;
	}

	opts.gen_hash = true;
	err = bpf_object__gen_loader(obj, &opts);
	if (err) {
		pr_err("bpf_object__gen_loader: %d", err);
		goto out;
	}
	err = bpf_object__load(obj);
	if (err) {
		pr_err("bpf_object__load: %d", err);
		goto out;
	}
	if (opts.insns_sz > UINT32_MAX || opts.data_sz > UINT32_MAX) {
		err = -EOVERFLOW;
		goto out;
	}
	err = compose_signed_data(opts.data, (__u32)opts.data_sz,
				  decoder_blob, decoder_blob_len,
				  &signed_data_buf, &signed_data_len);
	if (err)
		goto out;
	signed_data = signed_data_buf ? signed_data_buf : opts.data;
	if (__builtin_add_overflow(opts.insns_sz, (size_t)signed_data_len,
				   &loader_data_len)) {
		err = -EOVERFLOW;
		goto out;
	}
	loader_data_buf = xmalloc(loader_data_len);
	if (!loader_data_buf) {
		err = -ENOMEM;
		goto out;
	}
	memcpy(loader_data_buf, opts.insns, opts.insns_sz);
	if (signed_data_len)
		memcpy((__u8 *)loader_data_buf + opts.insns_sz, signed_data,
		       signed_data_len);
	rodata_upatch.map = loader_data_buf;
	rodata_upatch.hdr.loader_insns_len = (__u32)opts.insns_sz;
	rodata_upatch.hdr.data_off = (__u32)opts.insns_sz;
	rodata_upatch.hdr.data_len = signed_data_len;
	err = upatch_rodata_data_offset(&rodata_upatch, &rodata_data_off);
	if (err == -ENOENT)
		err = 0;
	if (err)
		goto out;

	sig_buf = xmalloc(SHIRUDO_MAX_SIG_SIZE);
	if (!sig_buf) {
		err = -ENOMEM;
		goto out;
	}
	sio.insns        = opts.insns;
	sio.insns_sz     = opts.insns_sz;
	sio.data         = signed_data;
	sio.data_sz      = signed_data_len;
	sio.signature    = sig_buf;
	sio.signature_sz = SHIRUDO_MAX_SIG_SIZE;
	err = cms_sign(&sio, pkey_path, cert_path);
	if (err) {
		pr_err("cms_sign: %d", err);
		goto out;
	}

	loader_off = (__u32)sizeof(hdr);
	sig_off    = loader_off + opts.insns_sz;
	data_off   = sig_off + (__u32)sio.signature_sz;
	data_len   = signed_data_len;
	meta_off   = data_off + data_len;

	pack_header(&hdr, upatch_name, SHIRUDO_UPATCH_TYPE_BPF, flags,
		    sio.payload_sha256,
		    loader_off, opts.insns_sz,
		    sig_off, (__u32)sio.signature_sz,
		    write_meta_len ? meta_off : 0, write_meta_len,
		    data_len ? data_off : 0, data_len,
		    1u * 1024u * 1024u,
		    rodata_data_off, nr_maps, nr_progs);

	fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		err = -errno;
		pr_err("open %s: %s", out_path, strerror(errno));
		goto out;
	}
	err = write_complete(fd, &hdr, sizeof(hdr));
	if (!err)
		err = write_complete(fd, opts.insns, opts.insns_sz);
	if (!err)
		err = write_complete(fd, sig_buf, sio.signature_sz);
	if (!err && data_len)
		err = write_complete(fd, signed_data, data_len);
	if (!err && write_meta_len)
		err = write_complete(fd, write_meta, write_meta_len);
	if (!err && fsync(fd) != 0)
		err = -errno;
	close(fd);
	fd = -1;
	if (err) {
		unlink(out_path);
		goto out;
	}

	pr_info("wrote %s (insns=%u sig=%zu data=%u meta=%u maps=%u "
		"progs=%u decoders=%u name=%s%s)",
		out_path, opts.insns_sz, sio.signature_sz, data_len,
		write_meta_len, nr_maps, nr_progs, nr_decoders,
		upatch_name,
		(flags & SHIRUDO_DIRECTIVE_UNLOAD) ? " UNLOAD" : "");
out:
	if (fd >= 0)
		close(fd);
	if (loader_data_buf)
		xfree(loader_data_buf, loader_data_len);
	free_decoder_set(&decoders);
	xfree(signed_data_buf, signed_data_len);
	xfree(decoder_blob, decoder_blob_len);
	xfree(sig_buf, SHIRUDO_MAX_SIG_SIZE);
	bpf_object__close(obj);
	xfree(attach_meta, attach_meta_len);
	return err;
}

int shirudo_build_package_load(const char *bpf_o, const char *src_path,
			       const char *out_path, const char *upatch_name,
			       const char *pkey_path, const char *cert_path)
{
	struct bpf_object *obj;
	int handler_ids[2] = {-1, -1};
	int err;

	err = register_target_attach_types(handler_ids);
	if (err) {
		pr_err("register cgroup_skb section handlers: %d", err);
		return err;
	}

	obj = bpf_object__open_file(bpf_o, NULL);
	err = libbpf_get_error(obj);

	if (err) {
		pr_err("open %s: %d", bpf_o, err);
		unregister_target_attach_types(handler_ids);
		return err;
	}
	err = finalize_object(obj, out_path, upatch_name, 0,
			      NULL, 0, src_path, pkey_path, cert_path);
	unregister_target_attach_types(handler_ids);
	return err;
}

/* Locate the BPF .rodata map. libbpf names it "<objname>.rodata". */
static struct bpf_map *find_rodata(struct bpf_object *obj)
{
	struct bpf_map *m;

	bpf_object__for_each_map(m, obj) {
		const char *name = bpf_map__name(m);
		size_t n = strlen(name);

		if (n >= 7 && strcmp(name + n - 7, ".rodata") == 0)
			return m;
	}
	return NULL;
}

int shirudo_build_package_unload(const char *upatch_name,
				 const __u8 payload_sha256[32],
				 const char *out_upatch,
				 const char *pkey_path,
				 const char *cert_path)
{
	const struct shirudo_embedded_bpf *blob = unload_blob();
	struct shirudo_unload_params params = {};
	struct bpf_object *obj;
	struct bpf_map *rodata;
	int err;

	if (!blob || !blob->data || !blob->size) {
		pr_err("embedded unload template missing");
		return -ENOENT;
	}

	obj = bpf_object__open_mem(blob->data, blob->size, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		pr_err("open embedded unload template: %d", err);
		return err;
	}

	rodata = find_rodata(obj);
	if (!rodata) {
		pr_err("unload template has no .rodata map");
		bpf_object__close(obj);
		return -EINVAL;
	}

	strscpy(params.name, upatch_name, sizeof(params.name));
	memcpy(params.expected_sha256, payload_sha256,
	       sizeof(params.expected_sha256));
	err = bpf_map__set_initial_value(rodata, &params, sizeof(params));
	if (err) {
		pr_err("set_initial_value(.rodata): %d", err);
		bpf_object__close(obj);
		return err;
	}

	/*
	 * Carry the target's expected payload_sha256 as metadata so the
	 * target can compute the unload chain event (and a future
	 * payload_mismatch check) without parsing the loader data blob.
	 * The metadata is not signature-covered; tampering only produces
	 * a chain value the operator's expectation rejects.
	 */
	return finalize_object(obj, out_upatch, upatch_name,
			       SHIRUDO_DIRECTIVE_UNLOAD,
			       payload_sha256, 32,
			       NULL, pkey_path, cert_path);
}
