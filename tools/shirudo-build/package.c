// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * gen_loader + CMS sign + .upatch container writer.
 */

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

#include <linux/bpf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>
#include <shirudo/upatch.h>

#include "bpf/lib/serializer.h"
#include "bpm_package.h"
#include "elf_target.h"
#include "io.h"
#include "jar.h"
#include "loader.h"
#include "help.h"
#include "log.h"
#include "options.h"
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
#define MAX_SIG_SIZE	16384
#define SERIALIZER_PREFIX	"shirudo_serialize__"
#define TEST_RUN_PREFIX	"shirudo_test__"

static struct bpf_map *find_rodata(struct bpf_object *obj);

struct data_range {
	__u32 offset;
	__u32 length;
};

struct unload_params {
	char	name[UPATCH_NAME_MAX];
	__u8	expected_sha256[UPATCH_PAYLOAD_HASH_LEN];
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

static __must_check int
pack_header(struct upatch_header *h,
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
	if (strscpy(h->name, name, sizeof(h->name)) < 0)
		return -ENAMETOOLONG;
	h->magic   = cpu_to_le64(UPATCH_MAGIC);
	h->version = cpu_to_le32(UPATCH_VERSION);
	h->flags   = cpu_to_le32(flags);
	memcpy(h->payload_sha256, payload_sha256,
	       UPATCH_PAYLOAD_HASH_LEN);
	h->loader_insns_off = cpu_to_le32(loader_off);
	h->loader_insns_len = cpu_to_le32(loader_len);
	h->signature_off    = cpu_to_le32(sig_off);
	h->signature_len    = cpu_to_le32(sig_len);
	h->metadata_off     = cpu_to_le32(meta_off);
	h->metadata_len     = cpu_to_le32(meta_len);
	h->data_off         = cpu_to_le32(data_off);
	h->data_len         = cpu_to_le32(data_len);
	h->log_buf_sz       = cpu_to_le32(log_buf_sz);
	h->nr_maps          = cpu_to_le32(nr_maps);
	h->nr_progs         = cpu_to_le32(nr_progs);
	h->rodata_data_off  = cpu_to_le32(rodata_data_off);
	h->type             = cpu_to_le32(type);
	h->reserved1        = 0;
	return 0;
}

/*
 * An output that is one of the inputs, under whatever name, is refused
 * before it is truncated, so that a write that fails cannot take the
 * input with it.
 */
static bool output_is_input(int fd, const char *original,
			    const char *modified)
{
	struct stat out, in;

	if (fstat(fd, &out))
		return true;
	if (!stat(original, &in) && in.st_dev == out.st_dev &&
	    in.st_ino == out.st_ino)
		return true;
	return !stat(modified, &in) && in.st_dev == out.st_dev &&
	       in.st_ino == out.st_ino;
}

/*
 * The CMS covers the loader and the data but not the header, whose
 * payload digest the target measures, so the digest is compared as well.
 */
static int verify_payload(const struct upatch *u,
			  const char *cert_path)
{
	__u8 digest[SHA256_LEN], *payload;
	size_t payload_len;
	__u32 digest_len;
	int ret;

	if (check_add_overflow(u->hdr.loader_insns_len, u->hdr.data_len,
			       &payload_len))
		return -EOVERFLOW;
	payload = xmalloc(payload_len);
	if (!payload)
		return -ENOMEM;
	memcpy(payload, upatch_loader(u), u->hdr.loader_insns_len);
	memcpy(payload + u->hdr.loader_insns_len, upatch_data(u),
	       u->hdr.data_len);
	ret = bpm_verify_cms(payload, payload_len,
			     upatch_signature(u), u->hdr.signature_len,
			     cert_path);
	if (!ret && (EVP_Digest(payload, payload_len, digest,
				&digest_len, EVP_sha256(), NULL) != 1 ||
		     digest_len != sizeof(digest) ||
		     memcmp(digest, u->hdr.payload_sha256, sizeof(digest))))
		ret = -EBADMSG;
	xfree(payload, payload_len);
	return ret;
}

static int package_resign_symbols(const char *original,
				  const char *modified, const char *output,
				  const struct data_range *ranges,
				  size_t nr_ranges, const char *const *symbols,
				  size_t nr_symbols, const char *pkey_path,
				  const char *cert_path)
{
	struct upatch_header hdr;
	struct sign_io sio = {};
	struct upatch src = {}, mod = {};
	struct rodata_range expected[16] = {};
	const __u8 *src_data, *mod_data;
	bool range_found[16] = {};
	char name[UPATCH_NAME_MAX + 1];
	__u32 loader_off, sig_off, data_off, meta_off;
	__u8 *sig_buf = NULL;
	size_t i, j;
	__u64 total;
	bool wrote = false;
	int fd = -1;
	int ret;

	if (!original || !modified || !output || !ranges || !symbols ||
	    !nr_ranges || nr_ranges > ARRAY_SIZE(expected) ||
	    nr_symbols != nr_ranges || !strcmp(original, output) ||
	    !strcmp(modified, output))
		return -EINVAL;
	ret = upatch_open(original, &src);
	if (ret)
		return ret;
	ret = upatch_open(modified, &mod);
	if (ret)
		goto out;
	src_data = upatch_data(&src);
	mod_data = upatch_data(&mod);
	if (upatch_is_unload(&src) || upatch_is_unload(&mod) ||
	    memcmp(src.map, mod.map, UPATCH_HEADER_SIZE) ||
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
		ret = -EINVAL;
		goto out;
	}
	for (i = 0; i < nr_ranges; i++) {
		if (!ranges[i].length || ranges[i].offset > src.hdr.data_len ||
		    ranges[i].length > src.hdr.data_len - ranges[i].offset ||
		    (i && ranges[i].offset <
		     ranges[i - 1].offset + ranges[i - 1].length)) {
			ret = -EINVAL;
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
			ret = -EPERM;
			goto out;
		}
	}
	if (!memchr(src.hdr.name, '\0', sizeof(src.hdr.name))) {
		ret = -EINVAL;
		goto out;
	}
	ret = verify_payload(&src, cert_path);
	if (ret)
		goto out;
	for (i = 0; i < nr_symbols; i++) {
		ret = upatch_rodata_symbol_range(&src, symbols[i], &expected[i]);
		if (ret)
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
			ret = -EPERM;
			goto out;
		}
	}
	sig_buf = xmalloc(MAX_SIG_SIZE);
	if (!sig_buf) {
		ret = -ENOMEM;
		goto out;
	}
	sio.insns = upatch_loader(&mod);
	sio.insns_sz = mod.hdr.loader_insns_len;
	sio.data = upatch_data(&mod);
	sio.data_sz = mod.hdr.data_len;
	sio.signature = sig_buf;
	sio.signature_sz = MAX_SIG_SIZE;
	ret = cms_sign(&sio, pkey_path, cert_path);
	if (ret)
		goto out;
	loader_off = sizeof(hdr);
	if (check_add_overflow(loader_off, sio.insns_sz, &sig_off) ||
	    check_add_overflow(sig_off, sio.signature_sz, &data_off) ||
	    check_add_overflow(data_off, sio.data_sz, &meta_off)) {
		ret = -EOVERFLOW;
		goto out;
	}
	total = (__u64)meta_off + mod.hdr.metadata_len;
	if (total > UPATCH_FILE_MAX) {
		ret = -E2BIG;
		goto out;
	}
	upatch_header_name(&mod, name);
	ret = pack_header(&hdr, name, mod.hdr.type, mod.hdr.flags,
			  sio.payload_sha256,
			  loader_off, (__u32)sio.insns_sz,
			  sig_off, (__u32)sio.signature_sz,
			  mod.hdr.metadata_len ? meta_off : 0,
			  mod.hdr.metadata_len,
			  sio.data_sz ? data_off : 0, (__u32)sio.data_sz,
			  mod.hdr.log_buf_sz, mod.hdr.rodata_data_off,
			  mod.hdr.nr_maps, mod.hdr.nr_progs);
	if (ret)
		goto out;
	fd = open(output, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
	if (fd < 0) {
		ret = -errno;
		goto out;
	}
	ret = output_is_input(fd, original, modified) ? -EINVAL : 0;
	if (!ret && ftruncate(fd, 0))
		ret = -errno;
	wrote = !ret;
	if (!ret)
		ret = write_complete(fd, &hdr, sizeof(hdr));
	if (!ret)
		ret = write_complete(fd, sio.insns, sio.insns_sz);
	if (!ret)
		ret = write_complete(fd, sig_buf, sio.signature_sz);
	if (!ret && sio.data_sz)
		ret = write_complete(fd, sio.data, sio.data_sz);
	if (!ret && mod.hdr.metadata_len)
		ret = write_complete(fd, upatch_metadata(&mod), mod.hdr.metadata_len);
	if (!ret && fsync(fd) != 0)
		ret = -errno;
out:
	if (fd >= 0)
		close(fd);
	if (ret && wrote)
		unlink(output);
	xfree(sig_buf, MAX_SIG_SIZE);
	upatch_close(&mod);
	upatch_close(&src);
	return ret;
}

static int build_package_resign(const char *original,
				const char *modified,
				const char *output,
				const struct data_range *ranges,
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

int build_package_patch_rodata(const char *input, const char *output,
			       const char *symbol, const __u8 *value,
				      size_t value_len, const char *pkey_path,
				      const char *cert_path)
{
	struct upatch src = {};
	struct rodata_range range = {};
	struct data_range allowed = {};
	const char *symbols[1] = { symbol };
	char modified[] = "/tmp/shirudo-rodata-XXXXXX";
	__u8 *candidate = NULL;
	bool created = false;
	int fd, ret;

	if (!input || !output || !symbol || !value || !value_len ||
	    !strcmp(input, output))
		return -EINVAL;
	ret = upatch_open(input, &src);
	if (ret)
		return ret;
	if (upatch_is_unload(&src)) {
		ret = -EINVAL;
		goto out;
	}
	ret = verify_payload(&src, cert_path);
	if (ret)
		goto out;
	ret = upatch_rodata_symbol_range(&src, symbol, &range);
	if (ret)
		goto out;
	if (value_len != range.size || range.offset > src.hdr.data_len ||
	    value_len > src.hdr.data_len - range.offset) {
		ret = -EINVAL;
		goto out;
	}
	candidate = xmalloc(src.map_size);
	if (!candidate) {
		ret = -ENOMEM;
		goto out;
	}
	memcpy(candidate, src.map, src.map_size);
	memcpy(candidate + src.hdr.data_off + range.offset, value, value_len);
	fd = mkstemp(modified);
	if (fd < 0) {
		ret = -errno;
		goto out;
	}
	created = true;
	ret = write_complete(fd, candidate, src.map_size);
	if (!ret && fsync(fd))
		ret = -errno;
	if (close(fd) && !ret)
		ret = -errno;
	if (ret)
		goto out;
	allowed.offset = range.offset;
	allowed.length = range.size;
	ret = package_resign_symbols(input, modified, output, &allowed, 1,
				     symbols, ARRAY_SIZE(symbols), pkey_path,
				     cert_path);
out:
	if (created)
		unlink(modified);
	xfree(candidate, src.map_size);
	upatch_close(&src);
	return ret;
}

int build_package_verify(const char *input, const char *cert_path)
{
	struct upatch upatch = {};
	int ret;

	ret = upatch_open(input, &upatch);
	if (ret)
		return ret;
	ret = upatch_is_unload(&upatch) ? -EINVAL :
	     verify_payload(&upatch, cert_path);
	upatch_close(&upatch);
	return ret;
}

enum rewrite_opt {
	REWRITE_OUTPUT,
	REWRITE_DATA_RANGE,
	REWRITE_KEYS_DIR,
	REWRITE_KEY,
	REWRITE_CERT,
};

static const struct opt_spec rewrite_opts[] = {
	[REWRITE_OUTPUT] = { "--output", 'o', 0, "<output.upatch>",
		"where to write the re-signed upatch" },
	[REWRITE_DATA_RANGE] = { "--data-range", 0, OPT_REPEAT,
		"<offset:length>",
		"a range of the loader data that may differ (repeatable)" },
	[REWRITE_KEYS_DIR] = { "--keys-dir", 0, 0, "<dir>",
		"read signing_key.pem and cert.der from <dir>" },
	[REWRITE_KEY] = { "--key", 0, 0, "<signing_key.pem>",
		"the signing key, over --keys-dir" },
	[REWRITE_CERT] = { "--cert", 0, 0, "<cert.der>",
		"the certificate, over --keys-dir" },
};

static const struct help_section rewrite_sections[] = {
	HELP_OPTIONS("options:", rewrite_opts),
};

static const struct help rewrite_help = {
	.usage	    = "shirudo-build upatch rewrite-rodata <original.upatch> "
		      "<modified.upatch>\n"
		      "              -o <output.upatch> "
		      "--data-range <offset:length>... [options]",
	.summary    = "Re-sign an upatch whose loader data changed inside the "
		      "given ranges.",
	.sections   = rewrite_sections,
	.n_sections = ARRAY_SIZE(rewrite_sections),
};

/* An <offset:length> of --data-range, both in 32 bits, length not 0. */
static int parse_data_range(const char *range, struct data_range *out)
{
	size_t off_len = digits(range, strlen(range));
	const char *length;
	size_t len_len;
	__u64 offset, len;

	if (!off_len || range[off_len] != ':')
		return -EINVAL;
	length = range + off_len + 1;
	len_len = digits(length, strlen(length));
	if (!len_len || length[len_len] ||
	    parse_u64(range, off_len, UINT32_MAX, &offset) ||
	    parse_u64(length, len_len, UINT32_MAX, &len) || !len)
		return -EINVAL;
	out->offset = (__u32)offset;
	out->length = (__u32)len;
	return 0;
}

int build_upatch_cli(int argc, const char **argv)
{
	const char *keys_dir = NULL, *original = NULL, *modified = NULL;
	const char *output = NULL;
	const char *pkey = SIGNING_KEY_PATH;
	const char *cert = CERT_PATH;
	struct data_range ranges[16] = {};
	char pkey_buf[PATH_MAX], cert_buf[PATH_MAX];
	size_t nr_ranges = 0;
	struct opt_parser p;
	int ret, opt;

	if (argc < 2 || strcmp(argv[1], "rewrite-rodata")) {
		print_help(&rewrite_help);
		return EXIT_USAGE;
	}
	OPT_INIT(&p, "upatch rewrite-rodata", rewrite_opts, &rewrite_help,
		 argc, argv, 2);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case REWRITE_OUTPUT:
			output = p.value;
			break;
		case REWRITE_DATA_RANGE:
			if (nr_ranges == ARRAY_SIZE(ranges)) {
				opt_usage(&p, "at most %zu --data-range",
					  ARRAY_SIZE(ranges));
				return EXIT_USAGE;
			}
			if (parse_data_range(p.value, &ranges[nr_ranges])) {
				opt_usage(&p, "--data-range takes <offset:length>, length not 0");
				return EXIT_USAGE;
			}
			nr_ranges++;
			break;
		case REWRITE_KEYS_DIR:
			keys_dir = p.value;
			break;
		case REWRITE_KEY:
			pkey = p.value;
			break;
		case REWRITE_CERT:
			cert = p.value;
			break;
		case OPT_ARG:
			if (modified) {
				opt_usage(&p, "unexpected argument '%s'",
					  p.value);
				return EXIT_USAGE;
			}
			if (original)
				modified = p.value;
			else
				original = p.value;
			break;
		case OPT_DONE:
			return 0;
		default:
			return EXIT_USAGE;
		}
	}
	if (!original || !modified || !output || !nr_ranges) {
		opt_usage(&p, "takes two inputs, -o and data ranges");
		return EXIT_USAGE;
	}
	keys_dir = keys_dir_resolve(keys_dir);
	if (keys_dir) {
		if (!opt_given(&p, REWRITE_KEY)) {
			ret = format_key_path(pkey_buf, sizeof(pkey_buf), keys_dir,
					      SIGNING_KEY_FILE);
			if (ret)
				return 2;
			pkey = pkey_buf;
		}
		if (!opt_given(&p, REWRITE_CERT)) {
			ret = format_key_path(cert_buf, sizeof(cert_buf), keys_dir,
					      CERT_FILE);
			if (ret)
				return 2;
			cert = cert_buf;
		}
	}
	ret = build_package_resign(original, modified, output,
				   ranges, nr_ranges, pkey, cert);
	if (ret)
		pr_err("upatch rewrite-rodata: %s", strerror(-ret));
	return ret ? 1 : 0;
}

static const char *kprobe_multi_section_target(const char *sec, __u32 *kind)
{
	size_t n;

	n = str_has_prefix(sec, "kprobe.multi/");
	if (n && sec[n]) {
		*kind = UPATCH_ATTACH_KPROBE_MULTI;
		return sec + n;
	}
	n = str_has_prefix(sec, "kretprobe.multi/");
	if (n && sec[n]) {
		*kind = UPATCH_ATTACH_KRETPROBE_MULTI;
		return sec + n;
	}
	return NULL;
}

static bool unsupported_kprobe_section(const char *sec)
{
	__u32 kind;

	if (sec && sec[0] == '?')
		sec++;
	if (sec && kprobe_multi_section_target(sec, &kind))
		return false;
	return sec &&
	       (strcmp(sec, "kprobe") == 0 ||
		strcmp(sec, "kretprobe") == 0 ||
		strcmp(sec, "kprobe/") == 0 ||
		strcmp(sec, "kretprobe/") == 0 ||
		str_has_prefix(sec, "kprobe.multi") ||
		str_has_prefix(sec, "kretprobe.multi"));
}

/*
 * The sleepable forms take the same attach kinds: BPF_F_SLEEPABLE is a
 * load flag, which the signed loader carries, not part of the link.
 */
static const char *uprobe_section_target(const char *sec, __u32 *kind)
{
	static const struct {
		const char *prefix;
		__u32 kind;
	} forms[] = {
		{ "uprobe/", UPATCH_ATTACH_UPROBE },
		{ "uprobe.s/", UPATCH_ATTACH_UPROBE },
		{ "uretprobe/", UPATCH_ATTACH_URETPROBE },
		{ "uretprobe.s/", UPATCH_ATTACH_URETPROBE },
		{ "uprobe.multi/", UPATCH_ATTACH_UPROBE_MULTI },
		{ "uprobe.multi.s/", UPATCH_ATTACH_UPROBE_MULTI },
		{ "uretprobe.multi/", UPATCH_ATTACH_URETPROBE_MULTI },
		{ "uretprobe.multi.s/", UPATCH_ATTACH_URETPROBE_MULTI },
	};
	const char *target;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(forms); i++) {
		target = str_after_prefix(sec, forms[i].prefix);
		if (target && *target) {
			*kind = forms[i].kind;
			return target;
		}
	}
	return NULL;
}

static bool unsupported_uprobe_section(const char *sec)
{
	__u32 kind;

	if (sec && sec[0] == '?')
		sec++;
	if (!sec)
		return false;
	if (uprobe_section_target(sec, &kind))
		return false;
	return strcmp(sec, "uprobe") == 0 ||
	       str_has_prefix(sec, "uprobe/") ||
	       str_has_prefix(sec, "uprobe.") ||
	       strcmp(sec, "uretprobe") == 0 ||
	       str_has_prefix(sec, "uretprobe/") ||
	       str_has_prefix(sec, "uretprobe.");
}

static bool unsupported_sk_skb_section(const char *sec)
{
	if (sec && sec[0] == '?')
		sec++;
	return sec && (strcmp(sec, "sk_skb") == 0 ||
		       str_has_prefix(sec, "sk_skb/"));
}

static bool unsupported_socket_filter_section(const char *sec)
{
	if (sec && sec[0] == '?')
		sec++;
	return sec && (strcmp(sec, "socket") == 0 ||
		       strcmp(sec, "socket_filter") == 0 ||
		       str_has_prefix(sec, "socket/") ||
		       str_has_prefix(sec, "socket_filter/"));
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
	       str_has_prefix(sec, "cgroup_skb/");
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
	const char *target;
	size_t i;

	if (!sec)
		return false;
	if (sec[0] == '?')
		sec++;
	for (i = 0; i < ARRAY_SIZE(prefixes); i++) {
		target = str_after_prefix(sec, prefixes[i]);
		if (target && *target)
			return true;
	}
	return false;
}

static __u32 attach_kind_from_section(const char *sec,
				      const char **target)
{
	__u32 kind;
	size_t n;

	*target = NULL;
	if (!sec)
		return UPATCH_ATTACH_RAW_TRACEPOINT;
	if (sec[0] == '?')
		sec++;
	n = str_has_prefix(sec, "kprobe/");
	if (n && sec[n]) {
		*target = sec + n;
		return UPATCH_ATTACH_KPROBE;
	}
	n = str_has_prefix(sec, "kretprobe/");
	if (n && sec[n]) {
		*target = sec + n;
		return UPATCH_ATTACH_KRETPROBE;
	}
	*target = uprobe_section_target(sec, &kind);
	if (*target)
		return kind;
	*target = kprobe_multi_section_target(sec, &kind);
	if (*target)
		return kind;
	if (strcmp(sec, "cgroup_skb/ingress") == 0)
		return UPATCH_ATTACH_CGROUP_SKB_INGRESS;
	if (strcmp(sec, "cgroup_skb/egress") == 0)
		return UPATCH_ATTACH_CGROUP_SKB_EGRESS;
	n = str_has_prefix(sec, "fmod_ret/");
	if (n && sec[n])
		return UPATCH_ATTACH_FMOD_RET;
	n = str_has_prefix(sec, "fmod_ret.s/");
	if (n && sec[n])
		return UPATCH_ATTACH_FMOD_RET;
	if (strcmp(sec, "netfilter") == 0)
		return UPATCH_ATTACH_NETFILTER_IPV6_PRE_ROUTING;
	n = str_has_prefix(sec, "xdp/");
	if (n && sec[n]) {
		*target = sec + n;
		return UPATCH_ATTACH_XDP;
	}
	return UPATCH_ATTACH_RAW_TRACEPOINT;
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
	if (plen >= UPATCH_UPROBE_PATH_MAX ||
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
	const char *plus;
	size_t len;

	*offset = 0;
	if (!src || !src[0])
		return -EINVAL;
	plus = strrchr(src, '+');
	if (plus) {
		const char *num = plus + 1;
		size_t n = strlen(num);
		int ret;

		if (plus == src)
			return -EINVAL;
		if (n > 2 && num[0] == '0' && (num[1] == 'x' || num[1] == 'X'))
			ret = parse_x64(num + 2, n - 2, UINT64_MAX, offset);
		else if (n > 1 && num[0] == '0')
			ret = -EINVAL;
		else
			ret = parse_u64(num, n, UINT64_MAX, offset);
		if (ret)
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

/*
 * <path>:<function>[+<offset>] or <path>:0x<file offset> of a uprobe or
 * uretprobe section into prog's target and offset and one file offset
 * in elf.
 */
static int resolve_single_uprobe(const char *sec, __u32 kind, const char *src,
				 struct upatch_prog_entry *prog, char **path,
				 __u32 *path_len, struct elf_target *elf)
{
	char loc[UPATCH_ATTACH_TARGET_MAX];
	const char *func = NULL;
	__u64 offset = 0;
	int err;

	err = split_uprobe_target(src, path, path_len, loc, sizeof(loc));
	if (err)
		goto invalid;
	if (loc[0] == '0' && (loc[1] == 'x' || loc[1] == 'X')) {
		err = parse_x64(loc + 2, strlen(loc + 2), UINT64_MAX, &offset);
		if (err || strscpy(prog->target, loc, sizeof(prog->target)) < 0)
			goto invalid;
	} else {
		err = split_probe_target(loc, prog->target, sizeof(prog->target), &offset);
		if (err)
			goto invalid;
		if (kind == UPATCH_ATTACH_URETPROBE && offset) {
			pr_err("uretprobe offsets are unsupported in section '%s'", sec);
			return -EINVAL;
		}
		func = prog->target;
		prog->offset = cpu_to_le64(offset);
	}
	err = elf_target_resolve_func(*path, func, offset, elf);
	if (err == -ENOENT)
		pr_err("uprobe function '%s' not found in %s (or the ELF has no GNU build ID)",
		       prog->target, *path);
	else if (err == -ERANGE)
		pr_err("uprobe offset in section '%s' lies outside %s", sec, *path);
	else if (err)
		pr_err("cannot resolve uprobe target %s:%s: %s", *path, prog->target,
		       strerror(-err));
	if (err)
		return err;
	/* The kernel reports a uprobe link's offset in 32 bits. */
	if (elf->offsets[0] > UINT32_MAX) {
		pr_err("uprobe offset in section '%s' is beyond 4 GiB of %s", sec, *path);
		return -ERANGE;
	}
	return 0;
invalid:
	pr_err("invalid uprobe section '%s'; expected uprobe[.s]//absolute/path:function[+offset], uretprobe[.s]//absolute/path:function or a 0x file offset in place of the function",
	       sec);
	return -EINVAL;
}

struct build_uprobe_target {
	__u32 prog_idx;
	char *path;
	__u32 path_len;
	struct elf_target elf;
};

static void free_uprobe_targets(struct build_uprobe_target *targets,
				__u32 nr_targets, __u32 nr_progs)
{
	__u32 i;

	if (!targets)
		return;
	for (i = 0; i < nr_targets; i++) {
		xstrfree(targets[i].path);
		elf_target_free(&targets[i].elf);
	}
	xfree(targets, (size_t)nr_progs * sizeof(*targets));
}

static size_t uprobe_targets_block_len(const struct build_uprobe_target *targets,
				       __u32 nr_targets)
{
	size_t len = sizeof(struct upatch_uprobe_targets);
	__u32 i;

	for (i = 0; i < nr_targets; i++) {
		const struct build_uprobe_target *ut = &targets[i];
		size_t record_len;

		record_len = size_add(sizeof(struct upatch_uprobe_target),
				      size_add(ut->path_len, ut->elf.build_id_len));
		record_len = size_add(record_len,
				      size_mul(ut->elf.nr_offsets, sizeof(__u64)));
		len = size_add(len, record_len);
	}
	return len;
}

static __u8 *write_uprobe_targets(__u8 *cursor, const struct build_uprobe_target *targets,
				  __u32 nr_targets)
{
	struct upatch_uprobe_targets header = {
		.magic = cpu_to_le32(UPATCH_UPROBE_TARGET_MAGIC),
		.version = cpu_to_le32(UPATCH_UPROBE_TARGET_VERSION),
		.nr_targets = cpu_to_le32(nr_targets),
	};
	__u32 i, j;

	memcpy(cursor, &header, sizeof(header));
	cursor += sizeof(header);
	for (i = 0; i < nr_targets; i++) {
		const struct build_uprobe_target *ut = &targets[i];
		struct upatch_uprobe_target record = {
			.prog_idx = cpu_to_le32(ut->prog_idx),
			.path_len = cpu_to_le32(ut->path_len),
			.build_id_len = cpu_to_le32(ut->elf.build_id_len),
			.nr_offsets = cpu_to_le32(ut->elf.nr_offsets),
		};

		memcpy(cursor, &record, sizeof(record));
		cursor += sizeof(record);
		memcpy(cursor, ut->path, ut->path_len);
		cursor += ut->path_len;
		memcpy(cursor, ut->elf.build_id, ut->elf.build_id_len);
		cursor += ut->elf.build_id_len;
		for (j = 0; j < ut->elf.nr_offsets; j++) {
			__le64 offset = cpu_to_le64(ut->elf.offsets[j]);

			memcpy(cursor, &offset, sizeof(offset));
			cursor += sizeof(offset);
		}
	}
	return cursor;
}

struct build_kprobe_target {
	__u32 prog_idx;
	char *buf;
	size_t buf_len;
	char **syms;
	__u32 nr_syms;
};

static void free_kprobe_targets(struct build_kprobe_target *targets,
				__u32 nr_targets, __u32 nr_progs)
{
	__u32 i;

	if (!targets)
		return;
	for (i = 0; i < nr_targets; i++) {
		xfree(targets[i].buf, targets[i].buf_len);
		xfree(targets[i].syms, (size_t)targets[i].nr_syms * sizeof(*targets[i].syms));
	}
	xfree(targets, (size_t)nr_progs * sizeof(*targets));
}

static int sym_cmp(const void *a, const void *b)
{
	return strcmp(*(char * const *)a, *(char * const *)b);
}

/*
 * Splits "<name>[,<name>...]" into sorted names. The buffer keeps them in
 * the order given; it is as long as the signed record, which
 * write_kprobe_targets() fills in sorted order. On failure kt owns
 * nothing: -EOPNOTSUPP for a glob, -EEXIST for a name given twice, -E2BIG
 * for too many names, -EINVAL for an invalid one.
 */
static int split_kprobe_multi_target(const char *list, struct build_kprobe_target *kt)
{
	size_t list_len = strlen(list), buf_len;
	__u32 nr_syms = 1, i;
	const char *comma;
	char **syms;
	char *buf, *name;
	int ret = -EINVAL;

	if (strchr(list, '*') || strchr(list, '?'))
		return -EOPNOTSUPP;
	for (comma = strchr(list, ','); comma; comma = strchr(comma + 1, ','))
		if (++nr_syms > UPATCH_KPROBE_SYMS_MAX)
			return -E2BIG;
	if (check_add_overflow(list_len, 1, &buf_len) || buf_len > UINT32_MAX)
		return -E2BIG;
	buf = xstrndup(list, list_len);
	if (!buf)
		return -ENOMEM;
	syms = xcalloc(nr_syms, sizeof(*syms));
	if (!syms) {
		ret = -ENOMEM;
		goto err_buf;
	}
	name = buf;
	for (i = 0; i < nr_syms; i++) {
		char *end = strchr(name, ',');
		size_t len = end ? (size_t)(end - name) : strlen(name);

		if (!kprobe_sym_valid(name, len))
			goto err_syms;
		name[len] = '\0';
		syms[i] = name;
		name += len + 1;
	}
	qsort(syms, nr_syms, sizeof(*syms), sym_cmp);
	for (i = 1; i < nr_syms; i++) {
		if (!strcmp(syms[i - 1], syms[i])) {
			ret = -EEXIST;
			goto err_syms;
		}
	}
	kt->buf = buf;
	kt->buf_len = buf_len;
	kt->syms = syms;
	kt->nr_syms = nr_syms;
	return 0;
err_syms:
	xfree(syms, (size_t)nr_syms * sizeof(*syms));
err_buf:
	xfree(buf, buf_len);
	return ret;
}

static size_t kprobe_targets_block_len(const struct build_kprobe_target *targets, __u32 nr_targets)
{
	size_t len = sizeof(struct upatch_kprobe_targets);
	__u32 i;

	for (i = 0; i < nr_targets; i++)
		len = size_add(len, size_add(sizeof(struct upatch_kprobe_target),
					     targets[i].buf_len));
	return len;
}

static __u8 *write_kprobe_targets(__u8 *cursor, const struct build_kprobe_target *targets,
				  __u32 nr_targets)
{
	struct upatch_kprobe_targets header = {
		.magic = cpu_to_le32(UPATCH_KPROBE_TARGET_MAGIC),
		.version = cpu_to_le32(UPATCH_KPROBE_TARGET_VERSION),
		.nr_targets = cpu_to_le32(nr_targets),
	};
	__u32 i, j;

	memcpy(cursor, &header, sizeof(header));
	cursor += sizeof(header);
	for (i = 0; i < nr_targets; i++) {
		const struct build_kprobe_target *kt = &targets[i];
		struct upatch_kprobe_target record = {
			.prog_idx = cpu_to_le32(kt->prog_idx),
			.nr_syms = cpu_to_le32(kt->nr_syms),
			.syms_len = cpu_to_le32((__u32)kt->buf_len),
		};

		memcpy(cursor, &record, sizeof(record));
		cursor += sizeof(record);
		for (j = 0; j < kt->nr_syms; j++) {
			size_t sym_size = strlen(kt->syms[j]) + 1;

			memcpy(cursor, kt->syms[j], sym_size);
			cursor += sym_size;
		}
	}
	return cursor;
}

static bool is_syscall_section(const char *sec)
{
	return sec && strcmp(sec, "syscall") == 0;
}

static const char *serializer_map_name(const struct bpf_program *p)
{
	const char *name = bpf_program__name(p);

	if (!name || !str_skip_prefix(&name, SERIALIZER_PREFIX))
		return NULL;
	return name;
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
	if (check_add_overflow(dir_len, rel_len, &len) ||
	    check_add_overflow(len, 1, &len) || len > UINT32_MAX)
		return -EOVERFLOW;
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
	const struct decoder_manifest *m = (const void *)p;

	if (n < sizeof(*m))
		return false;
	if (get_le32(&m->magic) != DECODER_MANIFEST_MAGIC ||
	    get_le16(&m->version) != UPATCH_DECODER_VERSION)
		return false;
	if (!memchr(m->upatch, '\0', sizeof(m->upatch)) ||
	    !fixed_cstr_nonempty(m->map, sizeof(m->map)) ||
	    !fixed_cstr_nonempty(m->source, sizeof(m->source)) ||
	    !fixed_cstr_nonempty(m->entrypoint, sizeof(m->entrypoint)))
		return false;

	memset(out, 0, sizeof(*out));
	out->language = get_le16(&m->language);
	out->api_version = get_le16(&m->api_version);
	out->input_format = get_le16(&m->input_format);
	out->export_signal = get_le16(&m->export_signal);
	if (out->language == 0 || out->api_version == 0 ||
	    out->input_format == 0 || out->export_signal == 0 ||
	    get_le16(&m->reserved) != 0)
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
		xfree(source, source_len + 1);
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

/* 0 when the build takes a manifest it found beside those of set. */
static int check_decoder_manifest(struct bpf_object *obj,
				  const struct decoder_set *set,
				  const struct decoder_manifest_view *manifest,
				  const char *upatch_name)
{
	if (manifest->language != UPATCH_DECODER_LANG_LUA ||
	    manifest->api_version != 1 ||
	    manifest->input_format != UPATCH_DECODER_INPUT_MAP_V1 ||
	    (manifest->export_signal != UPATCH_DECODER_EXPORT_LOG &&
	     manifest->export_signal != UPATCH_DECODER_EXPORT_METRIC)) {
		pr_err("unsupported decoder ABI for '%s/%s'",
		       upatch_name, manifest->map);
		return -EOPNOTSUPP;
	}
	/*
	 * The signature binds a decoder to the upatch whose data carries
	 * it, so the name is optional: a upatch whose name the field cannot
	 * hold leaves it empty. One given has to be this upatch's.
	 */
	if (manifest->upatch[0] && strcmp(manifest->upatch, upatch_name) != 0) {
		pr_err("decoder upatch '%s' does not match package name '%s'",
		       manifest->upatch, upatch_name);
		return -EINVAL;
	}
	if (!object_has_map(obj, manifest->map)) {
		pr_err("decoder manifest for missing map '%s'",
		       manifest->map);
		return -EINVAL;
	}
	for (__u32 i = 0; i < set->nr_items; i++) {
		if (strcmp(set->items[i].manifest.map, manifest->map) == 0) {
			pr_err("duplicate decoder for '%s/%s'",
			       upatch_name, manifest->map);
			return -EEXIST;
		}
	}
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
	if (!data || data_sz < sizeof(struct decoder_manifest))
		return 0;

	for (off = 0; off + sizeof(struct decoder_manifest) <= data_sz;
	     off += 4) {
		struct decoder_manifest_view manifest;

		if (!parse_decoder_manifest(data + off, data_sz - off,
					    &manifest))
			continue;
		err = check_decoder_manifest(obj, out, &manifest, upatch_name);
		if (err)
			goto err_free;
		err = decoder_set_add(out, &manifest, src_path);
		if (err)
			goto err_free;
	}
	return 0;

err_free:
	free_decoder_set(out);
	return err;
}

static int decoder_entry_names(struct upatch_decoder_entry *d,
			       const struct decoder_manifest_view *m)
{
	if (strscpy(d->upatch, m->upatch, sizeof(d->upatch)) < 0 ||
	    strscpy(d->map, m->map, sizeof(d->map)) < 0 ||
	    strscpy(d->source, m->source, sizeof(d->source)) < 0 ||
	    strscpy(d->entrypoint, m->entrypoint, sizeof(d->entrypoint)) < 0)
		return -E2BIG;
	return 0;
}

static int build_decoder_blob(const struct decoder_set *set,
			      void **out, __u32 *out_len)
{
	struct upatch_decoder_blob *blob;
	__u64 entries_end, total;
	__u32 off;
	size_t i;

	*out = NULL;
	*out_len = 0;
	if (set->nr_items == 0)
		return 0;
	entries_end = sizeof(*blob) +
		      (__u64)set->nr_items *
		      sizeof(struct upatch_decoder_entry);
	total = entries_end;
	for (i = 0; i < set->nr_items; i++)
		total += set->items[i].source_len;
	if (total > UINT32_MAX)
		return -EOVERFLOW;

	blob = xmalloc((size_t)total);
	if (!blob)
		return -ENOMEM;
	blob->magic = cpu_to_le32(UPATCH_DECODER_MAGIC);
	blob->version = cpu_to_le32(UPATCH_DECODER_VERSION);
	blob->nr_decoders = cpu_to_le32(set->nr_items);
	blob->reserved = 0;

	off = (__u32)entries_end;
	for (i = 0; i < set->nr_items; i++) {
		const struct decoder_file *file = &set->items[i];
		struct upatch_decoder_entry *d = &blob->decoders[i];

		d->language = cpu_to_le32(file->manifest.language);
		d->api_version = cpu_to_le32(file->manifest.api_version);
		d->input_format = cpu_to_le32(file->manifest.input_format);
		d->export_signal = cpu_to_le32(file->manifest.export_signal);
		if (decoder_entry_names(d, &file->manifest)) {
			xfree(blob, (size_t)total);
			return -E2BIG;
		}
		d->source_off = cpu_to_le32(off);
		d->source_len = cpu_to_le32(file->source_len);
		memcpy((__u8 *)blob + off, file->source,
		       file->source_len);
		off += file->source_len;
	}

	*out = blob;
	*out_len = (__u32)total;
	return 0;
}

struct signed_section {
	__u32		tag;
	const void	*data;
	__u32		len;
};

/*
 * data || sections, each at an 8-byte boundary || directory || trailer.
 * The loader addresses nothing past its own data, so the sections are
 * invisible to it and the kernel signs them with the rest.
 */
static int compose_signed_data(const void *data, __u32 data_len,
			       const struct signed_section *sections,
			       __u32 nr_sections, void **out, __u32 *out_len)
{
	struct upatch_signed_trailer trailer = {};
	__u64 total = data_len, dir_off;
	__u8 *buf;
	__u32 i;

	*out = NULL;
	*out_len = 0;
	if (nr_sections == 0 ||
	    nr_sections > UPATCH_SIGNED_SECTIONS_MAX)
		return -EINVAL;
	for (i = 0; i < nr_sections; i++) {
		total = (total + 7) & ~7ULL;
		total += sections[i].len;
	}
	dir_off = (total + 7) & ~7ULL;
	total = dir_off +
		(__u64)nr_sections *
		sizeof(struct upatch_signed_section) +
		sizeof(trailer);
	if (total > UINT32_MAX)
		return -EOVERFLOW;
	buf = xcalloc(1, (size_t)total);
	if (!buf)
		return -ENOMEM;
	if (data_len)
		memcpy(buf, data, data_len);
	total = data_len;
	for (i = 0; i < nr_sections; i++) {
		struct upatch_signed_section s = {};

		total = (total + 7) & ~7ULL;
		memcpy(buf + total, sections[i].data, sections[i].len);
		s.tag = cpu_to_le32(sections[i].tag);
		s.off = cpu_to_le32((__u32)total);
		s.len = cpu_to_le32(sections[i].len);
		memcpy(buf + dir_off + i * sizeof(s), &s, sizeof(s));
		total += sections[i].len;
	}
	trailer.magic = cpu_to_le32(UPATCH_SIGNED_TRAILER_MAGIC);
	trailer.version = cpu_to_le32(UPATCH_SIGNED_VERSION);
	trailer.dir_off = cpu_to_le32((__u32)dir_off);
	trailer.nr_sections = cpu_to_le32(nr_sections);
	total = dir_off +
		(__u64)nr_sections * sizeof(struct upatch_signed_section);
	memcpy(buf + total, &trailer, sizeof(trailer));

	*out = buf;
	*out_len = (__u32)(total + sizeof(trailer));
	return 0;
}

static int validate_serializer_output_map(struct bpf_object *obj)
{
	struct bpf_map *m;

	bpf_object__for_each_map(m, obj) {
		const char *name = bpf_map__name(m);

		if (!name || strcmp(name, SERIAL_MAP_NAME) != 0)
			continue;
		if (bpf_map__type(m) != BPF_MAP_TYPE_ARRAY) {
			pr_err("%s must be BPF_MAP_TYPE_ARRAY",
			       SERIAL_MAP_NAME);
			return -EINVAL;
		}
		if (bpf_map__key_size(m) != sizeof(__u32)) {
			pr_err("%s must use a u32 key",
			       SERIAL_MAP_NAME);
			return -EINVAL;
		}
		if (bpf_map__value_size(m) !=
		    sizeof(struct serial_chunk)) {
			pr_err("%s value must be struct serial_chunk",
			       SERIAL_MAP_NAME);
			return -EINVAL;
		}
		if (bpf_map__max_entries(m) == 0 ||
		    bpf_map__max_entries(m) > SERIAL_MAX_CHUNKS) {
			pr_err("%s max_entries must be 1..%u",
			       SERIAL_MAP_NAME,
			       SERIAL_MAX_CHUNKS);
			return -EINVAL;
		}
		return 0;
	}
	pr_err("serializer upatch requires %s output map",
	       SERIAL_MAP_NAME);
	return -EINVAL;
}

static int build_prog_metadata(struct bpf_object *obj, __u32 nr_maps,
			       __u32 nr_progs, void **out, __u32 *out_len)
{
	struct build_uprobe_target *uprobe_targets = NULL;
	struct build_kprobe_target *kprobe_targets = NULL;
	char (*seen_maps)[UPATCH_PROG_MAP_MAX] = NULL;
	struct upatch_prog_metadata *md;
	struct bpf_program *p;
	__u32 i = 0, n_seen = 0, nr_uprobe_targets = 0, nr_kprobe_targets = 0;
	__u32 xdp_classes = 0;
	size_t len, base_len;
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
	base_len = struct_size(md, progs, nr_progs);
	if (base_len > UINT32_MAX)
		return -EOVERFLOW;
	md = xmalloc(base_len);
	if (!md)
		return -ENOMEM;
	memset(md, 0, base_len);
	md->magic = cpu_to_le32(UPATCH_PROG_MAGIC);
	md->version = cpu_to_le32(UPATCH_PROG_VERSION);
	md->nr_progs = cpu_to_le32(nr_progs);
	md->nr_maps = cpu_to_le32(nr_maps);
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
	kprobe_targets = xcalloc(nr_progs, sizeof(*kprobe_targets));
	if (!kprobe_targets) {
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
			    ser_len >= UPATCH_PROG_MAP_MAX) {
				pr_err("serializer '%s' has invalid target map '%s'",
				       bpf_program__name(p), ser_map);
				err = -EINVAL;
				goto err_free;
			}
			if (strcmp(ser_map, SERIAL_MAP_NAME) == 0) {
				pr_err("serializer cannot target reserved map %s",
				       SERIAL_MAP_NAME);
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
			if (strscpy(seen_maps[n_seen], ser_map,
				    sizeof(seen_maps[0])) < 0 ||
			    strscpy(md->progs[i].map, ser_map,
				    sizeof(md->progs[i].map)) < 0) {
				err = -EINVAL;
				goto err_free;
			}
			n_seen++;
			md->progs[i].role =
				cpu_to_le32(UPATCH_PROG_ROLE_SERIALIZER);
			i++;
			continue;
		}
		if (is_syscall_section(sec)) {
			const char *prog_name = bpf_program__name(p);
			const char *id = prog_name;

			if (!id || !str_skip_prefix(&id, TEST_RUN_PREFIX) ||
			    !*id) {
				pr_err("SEC(\"syscall\") program '%s' must be named %s<id>",
				       prog_name ?: "?", TEST_RUN_PREFIX);
				err = -EINVAL;
				goto err_free;
			}
			if (has_test_run) {
				pr_err("only one %s test-run program is supported",
				       TEST_RUN_PREFIX);
				err = -EINVAL;
				goto err_free;
			}
			has_test_run = true;
			md->progs[i].role =
				cpu_to_le32(UPATCH_PROG_ROLE_TEST_RUN);
			i++;
			continue;
		}
		if (unsupported_kprobe_section(sec)) {
			pr_err("unsupported kprobe section '%s'; use kprobe/<symbol>, kretprobe/<symbol>, kprobe.multi/<symbol>[,<symbol>...] or kretprobe.multi/<symbol>[,<symbol>...]",
			       sec);
			err = -EOPNOTSUPP;
			goto err_free;
		}
		if (unsupported_uprobe_section(sec)) {
			pr_err("unsupported uprobe section '%s'; use uprobe[.s]//absolute/path:function[+offset], uretprobe[.s]//absolute/path:function, uprobe.multi[.s]//absolute/path:function_glob or uretprobe.multi[.s]//absolute/path:function_glob",
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
			pr_err("unsupported socket filter section '%s'; shirudo upatches require a pinnable bpf_link lifecycle",
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
		if (kind == UPATCH_ATTACH_RAW_TRACEPOINT &&
		    !default_attach_section(sec)) {
			pr_err("unsupported section '%s'; supported are fentry, fexit, fmod_ret, lsm, tp_btf, kprobe, kretprobe, kprobe.multi, kretprobe.multi, uprobe[.s], uretprobe[.s], uprobe.multi[.s], uretprobe.multi[.s], cgroup_skb, netfilter and xdp/<mask>",
			       sec);
			err = -EOPNOTSUPP;
			goto err_free;
		}
		md->progs[i].role =
			cpu_to_le32(UPATCH_PROG_ROLE_ATTACH);
		md->progs[i].kind = cpu_to_le32(kind);
		if (kind == UPATCH_ATTACH_XDP) {
			__u64 mask;

			err = parse_u64(target, strlen(target), UPATCH_XDP_ALL,
					&mask);
			if (err || !mask || (mask & ~(__u64)UPATCH_XDP_ALL)) {
				pr_err("invalid XDP device class mask in section '%s'; use xdp/<decimal-mask>, a sum of 1, 2, 8 and 16",
				       sec);
				err = -EINVAL;
				goto err_free;
			}
			/* A device takes one native XDP program at a time. */
			if (mask & xdp_classes) {
				pr_err("XDP section '%s' selects a device class another XDP program of this upatch selects; give each class to one program",
				       sec);
				err = -EINVAL;
				goto err_free;
			}
			xdp_classes |= (__u32)mask;
			md->progs[i].xdp.device_classes = cpu_to_le32((__u32)mask);
			i++;
			continue;
		} else if (kind_is_uprobe_single(kind)) {
			struct build_uprobe_target *ut = &uprobe_targets[nr_uprobe_targets++];

			ut->prog_idx = i;
			err = resolve_single_uprobe(sec, kind, target, &md->progs[i], &ut->path,
						    &ut->path_len, &ut->elf);
			if (err)
				goto err_free;
			i++;
			continue;
		} else if (kind_is_uprobe_multi(kind)) {
			struct build_uprobe_target *ut = &uprobe_targets[nr_uprobe_targets];

			err = split_uprobe_target(target, &ut->path,
						  &ut->path_len,
						  md->progs[i].target,
						  sizeof(md->progs[i].target));
			if (err) {
				if (err == -EOPNOTSUPP)
					pr_err("invalid uprobe multi section '%s': ',' and '|' alternation are unsupported; use one '*'/'?' glob",
					       sec);
				else
					pr_err("invalid uprobe multi section '%s'; expected uprobe.multi[.s]//absolute/path:function_glob or uretprobe.multi[.s]//absolute/path:function_glob",
					       sec);
				goto err_free;
			}
			ut->prog_idx = i;
			nr_uprobe_targets++;
			err = elf_target_resolve(ut->path,
						 md->progs[i].target, &ut->elf);
			if (err) {
				if (err == -ENOENT)
					pr_err("uprobe multi pattern '%s' matched no functions in %s (or the ELF has no GNU build ID)",
					       md->progs[i].target, ut->path);
				else
					pr_err("cannot resolve uprobe multi target %s:%s: %s",
					       ut->path, md->progs[i].target,
					       strerror(-err));
				goto err_free;
			}
		} else if (kind_is_kprobe_multi(kind)) {
			struct build_kprobe_target *kt = &kprobe_targets[nr_kprobe_targets];

			err = split_kprobe_multi_target(target, kt);
			if (err) {
				if (err == -ENOMEM)
					pr_err("kprobe multi section '%s': %s", sec,
					       strerror(-err));
				else if (err == -EOPNOTSUPP)
					pr_err("invalid kprobe multi section '%s': globs are unsupported; name each function",
					       sec);
				else if (err == -EEXIST)
					pr_err("invalid kprobe multi section '%s': a function is named twice",
					       sec);
				else
					pr_err("invalid kprobe multi section '%s'; expected a comma-separated list of 1 to %u function names of at most %u bytes",
					       sec, UPATCH_KPROBE_SYMS_MAX,
					       UPATCH_KPROBE_SYM_MAX - 1);
				goto err_free;
			}
			kt->prog_idx = i;
			nr_kprobe_targets++;
		} else if (target) {
			err = split_probe_target(target, md->progs[i].target,
						 sizeof(md->progs[i].target),
						 &offset);
			if (err) {
				pr_err("invalid kprobe target in section '%s'",
				       sec);
				goto err_free;
			}
			if (kind == UPATCH_ATTACH_KRETPROBE && offset) {
				pr_err("kretprobe offsets are unsupported in section '%s'",
				       sec);
				err = -EINVAL;
				goto err_free;
			}
		}
		md->progs[i].offset = cpu_to_le64(offset);
		i++;
	}

	len = base_len;
	if (nr_uprobe_targets &&
	    check_add_overflow(len, uprobe_targets_block_len(uprobe_targets, nr_uprobe_targets),
			       &len)) {
		err = -EOVERFLOW;
		goto err_free;
	}
	if (nr_kprobe_targets &&
	    check_add_overflow(len, kprobe_targets_block_len(kprobe_targets, nr_kprobe_targets),
			       &len)) {
		err = -EOVERFLOW;
		goto err_free;
	}
	if (len > UINT32_MAX) {
		err = -EOVERFLOW;
		goto err_free;
	}
	if (len != base_len) {
		__u8 *cursor;
		void *grown;

		grown = xreallocarray(md, base_len, len, 1);
		if (!grown) {
			err = -ENOMEM;
			goto err_free;
		}
		md = grown;
		cursor = (__u8 *)md + base_len;
		/* prog_specs_parse() reads the uprobe block first. */
		if (nr_uprobe_targets)
			cursor = write_uprobe_targets(cursor, uprobe_targets, nr_uprobe_targets);
		if (nr_kprobe_targets)
			write_kprobe_targets(cursor, kprobe_targets, nr_kprobe_targets);
	}

	*out = md;
	*out_len = (__u32)len;
	xfree(seen_maps, (size_t)nr_progs * sizeof(*seen_maps));
	free_uprobe_targets(uprobe_targets, nr_uprobe_targets, nr_progs);
	free_kprobe_targets(kprobe_targets, nr_kprobe_targets, nr_progs);
	return 0;

err_free:
	xfree(seen_maps, (size_t)nr_progs * sizeof(*seen_maps));
	free_uprobe_targets(uprobe_targets, nr_uprobe_targets, nr_progs);
	free_kprobe_targets(kprobe_targets, nr_kprobe_targets, nr_progs);
	xfree(md, base_len);
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
		else if (str_has_prefix(sec, "xdp/")) {
			type = BPF_XDP;
			if (bpf_program__set_flags(p, bpf_program__flags(p) |
						   BPF_F_XDP_HAS_FRAGS) != 0) {
				pr_err("set multi-buffer XDP for program '%s'",
				       bpf_program__name(p));
				return -EINVAL;
			}
		} else {
			continue;
		}

		if (bpf_program__set_expected_attach_type(p, type) != 0) {
			pr_err("set expected attach type for program '%s'",
			       bpf_program__name(p));
			return -EINVAL;
		}
	}
	return 0;
}

static int register_target_attach_types(int handler_ids[3])
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
	handler_ids[2] = libbpf_register_prog_handler("xdp/", BPF_PROG_TYPE_XDP,
						      BPF_XDP, NULL);
	if (handler_ids[2] < 0) {
		libbpf_unregister_prog_handler(handler_ids[1]);
		libbpf_unregister_prog_handler(handler_ids[0]);
		handler_ids[1] = -1;
		handler_ids[0] = -1;
		return handler_ids[2];
	}
	return 0;
}

static void unregister_target_attach_types(int handler_ids[3])
{
	if (handler_ids[2] >= 0)
		libbpf_unregister_prog_handler(handler_ids[2]);
	if (handler_ids[1] >= 0)
		libbpf_unregister_prog_handler(handler_ids[1]);
	if (handler_ids[0] >= 0)
		libbpf_unregister_prog_handler(handler_ids[0]);
	handler_ids[0] = -1;
	handler_ids[1] = -1;
	handler_ids[2] = -1;
}

/* Header, loader, signature and data, in the order the header names them. */
static int write_artifact(const char *out_path, const struct upatch_header *hdr,
			  const void *insns, size_t insns_sz,
			  const void *sig, size_t sig_sz,
			  const void *data, size_t data_len)
{
	int fd, err;

	fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		err = -errno;
		pr_err("open %s: %s", out_path, strerror(errno));
		return err;
	}
	err = write_complete(fd, hdr, sizeof(*hdr));
	if (!err && insns_sz)
		err = write_complete(fd, insns, insns_sz);
	if (!err)
		err = write_complete(fd, sig, sig_sz);
	if (!err)
		err = write_complete(fd, data, data_len);
	if (!err && fsync(fd) != 0)
		err = -errno;
	if (close(fd) && !err)
		err = -errno;
	if (err)
		unlink(out_path);
	return err;
}

/*
 * Takes ownership of obj. src_path anchors relative decoder paths;
 * NULL for a .bpf.o input or an unload directive.
 */
static int finalize_object(struct bpf_object *obj, const char *out_path,
			   const char *upatch_name, __u32 flags,
			   const __u8 *unload_payload, const char *src_path,
			   const void *policy_labels, __u32 policy_labels_len,
			   const char *pkey_path, const char *cert_path)
{
	LIBBPF_OPTS(gen_loader_opts, opts);
	struct signed_section sections[UPATCH_SIGNED_SECTIONS_MAX];
	__u32 loader_off, sig_off, data_off, data_len, attach_meta_len = 0;
	__u32 decoder_blob_len = 0, signed_data_len = 0, nr_sections = 0;
	char signed_name[UPATCH_NAME_MAX] = {};
	__u32 nr_maps = 0, nr_progs = 0;
	__u32 rodata_data_off = 0;
	struct upatch_header hdr;
	struct upatch rodata_upatch = {};
	struct decoder_set decoders = {};
	struct sign_io sio = {};
	void *signed_data = NULL;
	size_t loader_data_len = 0;
	void *loader_data_buf = NULL;
	void *decoder_blob = NULL;
	__u32 nr_decoders = 0;
	void *attach_meta = NULL;
	struct bpf_program *p;
	void *sig_buf = NULL;
	struct bpf_map *m;
	int err = 0;

	/*
	 * The loader writes map_fd/prog_fd back into descriptor arrays
	 * trailing its ctx, in the same order libbpf iterates the
	 * object. The target needs these counts to locate prog_fd[]
	 * after BPF_PROG_TEST_RUN -- it has only the .upatch, not the
	 * object. Iteration order here matches gen_loader's. Build
	 * attach metadata before loader generation so unsupported section
	 * names fail with shirudo's own diagnostics instead of depending
	 * on host kernel load behavior.
	 */
	bpf_object__for_each_map(m, obj)
		nr_maps++;
	bpf_object__for_each_program(p, obj)
		nr_progs++;

	if (!(flags & DIRECTIVE_UNLOAD)) {
		err = set_target_attach_types(obj);
		if (err)
			goto out;

		err = build_prog_metadata(obj, nr_maps, nr_progs,
					  &attach_meta, &attach_meta_len);
		if (err)
			goto out;

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
	if (policy_labels_len) {
		const struct upatch_policy_label_header *labels =
			policy_labels;
		__u32 map_idx = le32_to_cpu(labels->policy_map_idx);
		__u32 socket_map_idx =
			le32_to_cpu(labels->socket_policy_map_idx);

		if (map_idx >= nr_maps || map_idx >= UPATCH_MAPS_MAX ||
		    socket_map_idx >= nr_maps ||
		    socket_map_idx >= UPATCH_MAPS_MAX ||
		    map_idx == socket_map_idx) {
			err = -EINVAL;
			goto out;
		}
		opts.reuse_map_mask = (1ULL << map_idx) |
				      (1ULL << socket_map_idx);
	}
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
	/*
	 * The name the pin, the archive and the register event carry, the
	 * attach sites, the unload target: signed with the data, since the
	 * header is not.
	 */
	if (strscpy(signed_name, upatch_name, sizeof(signed_name)) < 0) {
		err = -ENAMETOOLONG;
		goto out;
	}
	sections[nr_sections++] = (struct signed_section){
		UPATCH_SECTION_NAME, signed_name, sizeof(signed_name),
	};
	if (flags & DIRECTIVE_UNLOAD) {
		sections[nr_sections++] = (struct signed_section){
			UPATCH_SECTION_UNLOAD, unload_payload,
			UPATCH_PAYLOAD_HASH_LEN,
		};
	} else {
		sections[nr_sections++] = (struct signed_section){
			UPATCH_SECTION_ATTACH, attach_meta,
			attach_meta_len,
		};
		if (decoder_blob_len)
			sections[nr_sections++] = (struct signed_section){
				UPATCH_SECTION_DECODERS, decoder_blob,
				decoder_blob_len,
			};
		if (policy_labels_len)
			sections[nr_sections++] = (struct signed_section){
				UPATCH_SECTION_POLICY_LABELS,
				policy_labels, policy_labels_len,
			};
	}
	err = compose_signed_data(opts.data, (__u32)opts.data_sz, sections,
				  nr_sections, &signed_data, &signed_data_len);
	if (err)
		goto out;
	if (check_add_overflow(opts.insns_sz, signed_data_len,
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

	sig_buf = xmalloc(MAX_SIG_SIZE);
	if (!sig_buf) {
		err = -ENOMEM;
		goto out;
	}
	sio.insns        = opts.insns;
	sio.insns_sz     = opts.insns_sz;
	sio.data         = signed_data;
	sio.data_sz      = signed_data_len;
	sio.signature    = sig_buf;
	sio.signature_sz = MAX_SIG_SIZE;
	err = cms_sign(&sio, pkey_path, cert_path);
	if (err) {
		pr_err("cms_sign: %d", err);
		goto out;
	}

	loader_off = (__u32)sizeof(hdr);
	data_len = signed_data_len;
	if (check_add_overflow(loader_off, opts.insns_sz, &sig_off) ||
	    check_add_overflow(sig_off, sio.signature_sz, &data_off) ||
	    data_off > UPATCH_FILE_MAX || data_len > UPATCH_FILE_MAX - data_off) {
		err = -E2BIG;
		goto out;
	}

	err = pack_header(&hdr, upatch_name, UPATCH_TYPE_BPF, flags,
			  sio.payload_sha256,
			  loader_off, opts.insns_sz,
			  sig_off, (__u32)sio.signature_sz,
			  0, 0,
			  data_off, data_len,
			  1u * 1024u * 1024u,
			  rodata_data_off, nr_maps, nr_progs);
	if (err)
		goto out;

	err = write_artifact(out_path, &hdr, opts.insns, opts.insns_sz,
			     sig_buf, sio.signature_sz, signed_data, data_len);
	if (err)
		goto out;

	pr_info("wrote %s (insns=%u sig=%zu data=%u sections=%u maps=%u "
		"progs=%u decoders=%u name=%s%s)",
		out_path, opts.insns_sz, sio.signature_sz, data_len,
		nr_sections, nr_maps, nr_progs, nr_decoders,
		upatch_name,
		(flags & DIRECTIVE_UNLOAD) ? " UNLOAD" : "");
out:
	xfree(loader_data_buf, loader_data_len);
	free_decoder_set(&decoders);
	xfree(signed_data, signed_data_len);
	xfree(decoder_blob, decoder_blob_len);
	xfree(sig_buf, MAX_SIG_SIZE);
	bpf_object__close(obj);
	xfree(attach_meta, attach_meta_len);
	return err;
}

/* Every target refuses a name upatch_name_valid() does not take. */
static int check_upatch_name(const char *name)
{
	if (upatch_name_valid(name))
		return 0;
	pr_err("upatch name '%s' is not 1 to %d characters of [A-Za-z0-9._-], each '.' counting as two, not starting with '.'",
	       name ? name : "", NAME_MAX);
	return -EINVAL;
}

int build_package_load(const char *bpf_o, const char *src_path,
		       const char *out_path, const char *upatch_name,
		       const struct upatch_policy_label_entry *policies,
		       __u32 nr_policies,
		       const char *pkey_path, const char *cert_path)
{
	__u32 label_len = 0, policy_map_idx = 0, socket_policy_map_idx = 0;
	struct upatch_policy_label_header *label_blob = NULL;
	struct bpf_map *map, *task_map, *sock_map;
	int handler_ids[3] = { -1, -1, -1 };
	struct bpf_object *obj;
	__u32 map_idx = 0;
	int err;

	err = check_upatch_name(upatch_name);
	if (err)
		return err;
	err = register_target_attach_types(handler_ids);
	if (err) {
		pr_err("register target section handlers: %d", err);
		return err;
	}

	obj = bpf_object__open_file(bpf_o, NULL);
	err = libbpf_get_error(obj);

	if (err) {
		pr_err("open %s: %d", bpf_o, err);
		unregister_target_attach_types(handler_ids);
		return err;
	}
	if (nr_policies) {
		task_map = bpf_object__find_map_by_name(obj,
							"shirudo_task_policy");
		sock_map = bpf_object__find_map_by_name(obj,
							"shirudo_sock_policy");
		if (!task_map ||
		    bpf_map__type(task_map) != BPF_MAP_TYPE_TASK_STORAGE ||
		    bpf_map__key_size(task_map) != sizeof(__s32) ||
		    bpf_map__value_size(task_map) != 2 * sizeof(__u64) ||
		    bpf_map__map_flags(task_map) != BPF_F_NO_PREALLOC) {
			pr_err("policy labels require a compatible shirudo_task_policy map");
			err = -EINVAL;
			goto out;
		}
		if (!sock_map ||
		    bpf_map__type(sock_map) != BPF_MAP_TYPE_SK_STORAGE ||
		    bpf_map__key_size(sock_map) != sizeof(__s32) ||
		    bpf_map__value_size(sock_map) != sizeof(__u64) ||
		    bpf_map__map_flags(sock_map) !=
				(BPF_F_NO_PREALLOC | BPF_F_CLONE)) {
			pr_err("policy labels require a compatible shirudo_sock_policy map");
			err = -EINVAL;
			goto out;
		}
		bpf_object__for_each_map(map, obj) {
			if (map == task_map)
				break;
			map_idx++;
		}
		if (map_idx >= UPATCH_MAPS_MAX || map != task_map) {
			err = -E2BIG;
			goto out;
		}
		policy_map_idx = map_idx;
		map_idx = 0;
		bpf_object__for_each_map(map, obj) {
			if (map == sock_map)
				break;
			map_idx++;
		}
		if (map_idx >= UPATCH_MAPS_MAX ||
		    map != sock_map || map_idx == policy_map_idx) {
			err = -E2BIG;
			goto out;
		}
		socket_policy_map_idx = map_idx;
		if (check_mul_overflow(nr_policies, sizeof(*policies),
				       &label_len) ||
		    check_add_overflow(label_len, sizeof(*label_blob),
				       &label_len)) {
			err = -EOVERFLOW;
			goto out;
		}
		label_blob = xcalloc(1, label_len);
		if (!label_blob) {
			err = -ENOMEM;
			goto out;
		}
		label_blob->magic = cpu_to_le32(UPATCH_POLICY_LABELS_MAGIC);
		label_blob->version = cpu_to_le32(UPATCH_POLICY_LABELS_VERSION);
		label_blob->count = cpu_to_le32(nr_policies);
		label_blob->policy_map_idx = cpu_to_le32(policy_map_idx);
		label_blob->socket_policy_map_idx =
			cpu_to_le32(socket_policy_map_idx);
		memcpy(label_blob + 1, policies,
		       label_len - sizeof(*label_blob));
	}
	err = finalize_object(obj, out_path, upatch_name, 0, NULL, src_path,
			      label_blob, label_len, pkey_path, cert_path);
	obj = NULL;
out:
	bpf_object__close(obj);
	xfree(label_blob, label_len);
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

int build_package_unload(const char *upatch_name,
			 const __u8 payload_sha256[32],
			 const char *out_upatch,
			 const char *pkey_path,
			 const char *cert_path)
{
	const struct embedded_bpf *blob = unload_blob();
	struct unload_params params = {};
	struct bpf_object *obj;
	struct bpf_map *rodata;
	int err;

	err = check_upatch_name(upatch_name);
	if (err)
		return err;
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

	if (strscpy(params.name, upatch_name, sizeof(params.name)) < 0) {
		bpf_object__close(obj);
		return -ENAMETOOLONG;
	}
	memcpy(params.expected_sha256, payload_sha256,
	       sizeof(params.expected_sha256));
	err = bpf_map__set_initial_value(rodata, &params, sizeof(params));
	if (err) {
		pr_err("set_initial_value(.rodata): %d", err);
		bpf_object__close(obj);
		return err;
	}

	/*
	 * The target reads the name and the expected payload from the
	 * signed sections, not from the loader's .rodata, which it has no
	 * portable way to locate in the data blob.
	 */
	return finalize_object(obj, out_upatch, upatch_name,
			       DIRECTIVE_UNLOAD, payload_sha256,
			       NULL, NULL, 0, pkey_path, cert_path);
}

/*
 * A Java upatch has no loader: its data is the signed sections alone,
 * NAME and PTYP, then the jar of a load or the digest an unload expects.
 * The target verifies the signature over that data in userspace.
 */
static int finalize_java(const char *out_path, const char *upatch_name,
			 __u32 flags, const struct signed_section *payload,
			 const char *pkey_path, const char *cert_path)
{
	__le32 type = cpu_to_le32(UPATCH_TYPE_JAVA);
	char signed_name[UPATCH_NAME_MAX] = {};
	__u32 signed_data_len = 0, data_off;
	struct signed_section sections[3];
	struct upatch_header hdr;
	void *signed_data = NULL;
	struct sign_io sio = {};
	void *sig_buf = NULL;
	int err;

	if (strscpy(signed_name, upatch_name, sizeof(signed_name)) < 0)
		return -ENAMETOOLONG;
	sections[0] = (struct signed_section){
		UPATCH_SECTION_NAME, signed_name, sizeof(signed_name),
	};
	sections[1] = (struct signed_section){
		UPATCH_SECTION_TYPE, &type, sizeof(type),
	};
	sections[2] = *payload;
	err = compose_signed_data(NULL, 0, sections, ARRAY_SIZE(sections),
				  &signed_data, &signed_data_len);
	if (err)
		return err;
	sig_buf = xmalloc(MAX_SIG_SIZE);
	if (!sig_buf) {
		err = -ENOMEM;
		goto out;
	}
	sio.insns	 = signed_data;
	sio.insns_sz	 = 0;
	sio.data	 = signed_data;
	sio.data_sz	 = signed_data_len;
	sio.signature	 = sig_buf;
	sio.signature_sz = MAX_SIG_SIZE;
	err = cms_sign(&sio, pkey_path, cert_path);
	if (err) {
		pr_err("cms_sign: %d", err);
		goto out;
	}
	if (check_add_overflow(sizeof(hdr), sio.signature_sz, &data_off) ||
	    data_off > UPATCH_FILE_MAX ||
	    signed_data_len > UPATCH_FILE_MAX - data_off) {
		pr_err("%s: the jar and its signature do not fit a upatch of %u bytes",
		       upatch_name, UPATCH_FILE_MAX);
		err = -E2BIG;
		goto out;
	}
	err = pack_header(&hdr, upatch_name, UPATCH_TYPE_JAVA, flags,
			  sio.payload_sha256, 0, 0,
			  (__u32)sizeof(hdr), (__u32)sio.signature_sz, 0, 0,
			  data_off, signed_data_len, 0, 0, 0, 0);
	if (!err)
		err = write_artifact(out_path, &hdr, NULL, 0, sig_buf,
				     sio.signature_sz, signed_data,
				     signed_data_len);
	if (!err)
		pr_info("wrote %s (java sig=%zu data=%u name=%s%s)", out_path,
			sio.signature_sz, signed_data_len, upatch_name,
			(flags & DIRECTIVE_UNLOAD) ? " UNLOAD" : "");
out:
	xfree(sig_buf, MAX_SIG_SIZE);
	xfree(signed_data, signed_data_len);
	return err;
}

/*
 * Refused here, where the operator sees it: on the target a jar a JVM
 * does not take as an agent stops every JVM the options reach.
 */
static int check_agent_jar(const char *path, const __u8 *buf, size_t len)
{
	int err = jar_premain_class(buf, len);

	if (err == -ENOENT)
		pr_err("%s has no Premain-Class in its manifest: a JVM does not start with it as -javaagent",
		       path);
	else if (err == -ENOTSUP)
		pr_err("%s: a zip64 jar or a manifest neither stored nor deflated is not supported",
		       path);
	else if (err == -EFBIG)
		pr_err("%s: the manifest is too large", path);
	else if (err)
		pr_err("%s is not a jar", path);
	return err;
}

int build_package_java_load(const char *jar_path, const char *out_path,
			    const char *upatch_name,
			    const char *pkey_path, const char *cert_path)
{
	struct signed_section jar;
	size_t len = 0;
	__u8 *buf;
	int err;

	err = check_upatch_name(upatch_name);
	if (err)
		return err;
	err = read_file(jar_path, UPATCH_FILE_MAX, &buf, &len);
	if (err) {
		pr_err("read %s: %s", jar_path, strerror(-err));
		return err;
	}
	err = check_agent_jar(jar_path, buf, len);
	if (err)
		goto out;
	jar = (struct signed_section){ UPATCH_SECTION_JAR, buf, (__u32)len };
	err = finalize_java(out_path, upatch_name, 0, &jar, pkey_path,
			    cert_path);
out:
	xfree(buf, len + 1);
	return err;
}

int build_package_java_unload(const char *upatch_name,
			      const __u8 payload_sha256[32],
			      const char *out_path,
			      const char *pkey_path, const char *cert_path)
{
	struct signed_section unload = {
		UPATCH_SECTION_UNLOAD, payload_sha256, UPATCH_PAYLOAD_HASH_LEN,
	};
	int err;

	err = check_upatch_name(upatch_name);
	if (err)
		return err;
	return finalize_java(out_path, upatch_name, DIRECTIVE_UNLOAD, &unload,
			     pkey_path, cert_path);
}
