// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * shirudo upatch {info,load,unload,list} -- subcommand router.
 */

#include <endian.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/keyctl.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include "builtin.h"
#include "util/chain.h"
#include "util/config.h"
#include "util/crypto.h"
#include "util/eventlog.h"
#include "util/elf_target.h"
#include "util/help.h"
#include "util/io.h"
#include "util/json.h"
#include "util/kernel_abi.h"
#include "util/identity.h"
#include "util/keyring.h"
#include "util/tpm.h"
#include "util/log.h"
#include "util/hex.h"
#include "util/malloc.h"
#include "util/paths.h"
#include "util/report.h"
#include "util/seal.h"
#include "util/timefmt.h"
#include "util/upatch.h"
#include "util/upatch_decode.h"
#include "util/upatch_maps.h"
#include "util/upatch_maps_otel.h"
#include "util/upatch_resolve.h"
#include "util/version.h"

static bool safe_upatch_name(const char *name);

#ifndef NFPROTO_IPV6
#define NFPROTO_IPV6			10
#endif
#ifndef NF_INET_PRE_ROUTING
#define NF_INET_PRE_ROUTING		0
#endif
#ifndef NF_IP6_PRI_RAW_BEFORE_DEFRAG
#define NF_IP6_PRI_RAW_BEFORE_DEFRAG	(-450)
#endif

static void rep_fail(struct op_report *rep, const char *phase,
		     const char *cat, int err, const char *msg)
{
	if (!rep)
		return;
	rep->ok = false;
	rep->phase = phase;
	rep->category = cat;
	rep->err = err < 0 ? -err : err;
	if (msg)
		strscpy(rep->message, msg, sizeof(rep->message));
}

/*
 * ENOPKG is the kernel's X.509 parser meeting an algorithm it was not
 * built with: an ML-DSA signature without CONFIG_CRYPTO_MLDSA.
 */
static const char *cat_from_load_errno(int e)
{
	switch (e) {
	case EKEYREJECTED:
		return "signature_rejected";
	case ENOKEY:
		return "keyring_missing";
	case ENOPKG:
		return "signature_unsupported";
	case EACCES:
	case EPERM:
		return "lsm_denied";
	default:
		return "verifier_rejected";
	}
}

static const char *flag_str(const struct upatch *u)
{
	return upatch_is_unload(u) ? "UNLOAD-directive" : "LOAD";
}

static const char *decoder_language_str(__u32 language)
{
	return language == UPATCH_DECODER_LANG_LUA ? "lua" : "unknown";
}

static const char *decoder_input_str(__u32 input_format)
{
	return input_format == UPATCH_DECODER_INPUT_MAP_V1 ?
		"shirudo.map.v1" : "unknown";
}

static const char *decoder_signal_str(__u32 signal)
{
	return signal == UPATCH_DECODER_EXPORT_LOG ? "log" :
		signal == UPATCH_DECODER_EXPORT_METRIC ? "metric" :
		"unknown";
}

static int print_sha256_hex(const __u8 hash[32])
{
	char hex[65];

	hex_encode(hash, 32, hex);
	return fputs(hex, stdout) < 0 ? -1 : 0;
}

static const struct help upatch_info_help = {
	.usage   = "shirudo upatch info [--json] <file.upatch>",
	.summary = "Describe a .upatch file: header, signature, payload "
		   "digest,\nattach metadata and signed decoders. Offline -- "
		   "no kernel state\nread, runs on any host. For the program as "
		   "actually loaded\n(authoritative, via kernel BTF line_info) "
		   "use `shirudo upatch get`.",
	.footer  =
"Examples:\n"
"  shirudo upatch info cve-2026-31431.upatch\n"
"  shirudo upatch info --json /var/lib/shirudo/upatches/foo.upatch",
};

static const struct help upatch_list_help = {
	.usage   = "shirudo upatch list [--json]",
	.summary = "List upatches on this host. Shows the persisted set\n"
		   "(under /var/lib/shirudo/upatches/, survives reboot) "
		   "alongside the\nbpffs-pinned active set (loaded now). "
		   "Drift in either direction\n(persisted-but-not-loaded "
		   "or loaded-but-not-persisted) is flagged.",
	.footer  =
"Examples:\n"
"  shirudo upatch list\n"
"  shirudo upatch list --json | jq",
};

static const struct help upatch_load_help = {
	.usage   = "shirudo upatch load [--expect-chain=<hex>] "
		   "[--expect-version-id=<hex>]\n"
		   "                       [--no-precheck] [--no-version-check] "
		   "[--report=<path>]\n"
		   "                       <file.upatch>",
	.summary = "Load a signed LOAD .upatch into the target kernel: verify "
		   "the\nsignature, run the loader, pin the resulting link, "
		   "and extend this\nboot's TPM measurement register. "
		   "Target-only.",
	.footer  =
"Examples:\n"
"  shirudo upatch load cve-2026-31431.upatch\n"
"  shirudo upatch load --expect-chain=$(...) foo.upatch\n"
"  shirudo upatch load --report=- foo.upatch | jq",
};

static const struct help upatch_unload_help = {
	.usage   = "shirudo upatch unload [--expect-chain=<hex>] "
		   "[--expect-version-id=<hex>]\n"
		   "                       [--no-precheck] [--no-version-check] "
		   "[--report=<path>]\n"
		   "                       <unload-directive.upatch>",
	.summary = "Apply a signed UNLOAD directive: detach the named upatch,\n"
		   "remove its pin, and extend the TPM measurement register "
		   "(unloads\nmove the register forward, never roll it back). "
		   "Target-only.",
	.footer  =
"Examples:\n"
"  shirudo upatch unload cve-2026-31431.unload.upatch\n"
"  shirudo upatch unload --report=- foo.unload.upatch | jq",
};

static const struct help_item upatch_map_options[] = {
	{ "--all", "export every map from every loaded upatch" },
	{ "--json[=<path>]", "print JSON or append it to path" },
	{ "--show-full",  "lift the per-map 256-entry truncation cap" },
	{ "--peek", "read serializer-backed maps without draining them" },
	{ "--otel", "export maps through signed decoders or automatic classification" },
	{ "--otel-endpoint=<url>", "OTLP base URL (signal path is appended)" },
	{ "--tenant-id=<id>", "add X-Tenant-ID to OTLP requests" },
	{ "--otel-insecure", "allow cleartext remote OTLP or disable HTTPS verification" },
	{ "--otel-retries=<0-10>", "OTLP retries after the first attempt (default: 3)" },
	{ "--s3-uri=<uri>", "S3 overflow destination for OTLP payloads" },
};

static const struct help_section upatch_map_sections[] = {
	{ "options:", upatch_map_options, ARRAY_SIZE(upatch_map_options) },
};

static const struct help upatch_map_help = {
	.usage      = "shirudo upatch map [--all] [<upatch>] [<map>] "
		      "[--json[=<path>]] [--show-full] [--peek]\n"
		      "                          [--otel] "
		      "[--otel-endpoint=<url>]\n"
		      "                          [--otel-insecure] "
		      "[--otel-retries=<0-10>] [--s3-uri=<uri>]",
	.summary    = "Read the contents of a pinned upatch map from the\n"
		      "target kernel. With no positional args, list every "
		      "pinned\nmap across every loaded upatch. With "
		      "<upatch>, list maps\nfor that upatch only. With "
		      "<upatch> <map>, dump the map's\ncontents -- BTF "
		      "type-aware where the build embedded `-g`. If the "
		      "upatch\npins a serializer for the map, run it and "
		      "print the serialized\npages. With --all, export detailed "
		      "contents for every loaded map\nusing command-line or "
		      "map_export.* configuration.",
	.sections   = upatch_map_sections,
	.n_sections = ARRAY_SIZE(upatch_map_sections),
	.footer     =
"Examples:\n"
"  shirudo upatch map\n"
"  shirudo upatch map --all\n"
"  shirudo upatch map kernel-obs exec --json\n"
"  shirudo upatch map cve-2026-31431-counter\n"
"  shirudo upatch map cve-2026-31431-counter blocked_af_alg\n"
"  shirudo upatch map cve-2026-31431-counter blocked_af_alg \\\n"
"    --json=/var/log/shirudo/maps.ndjson\n"
"  shirudo upatch map cve-2026-31431-counter blocked_af_alg --otel\n"
"  shirudo upatch map foo values --otel \\\n"
"    --otel-endpoint=https://collector:4318\n"
"  shirudo upatch map cve-2026-31431-counter big_hash --show-full",
};

static const struct help_item upatch_get_options[] = {
	{ "--json",       "machine-readable JSON output" },
	{ "--show-full",  "lift the per-map 256-entry truncation cap" },
};

static const struct help_section upatch_get_sections[] = {
	{ "options:", upatch_get_options, ARRAY_SIZE(upatch_get_options) },
};

static const struct help upatch_get_help = {
	.usage   = "shirudo upatch get <name> [--json] [--show-full]",
	.summary = "Describe a loaded upatch from the target kernel:\n"
		   "  - the SEC()-style attach hook (e.g. fexit/tcp_v4_connect),\n"
		   "  - the prog source via BTF line_info installed by the\n"
		   "    signed loader (authoritative, but sparse),\n"
		   "  - every pinned map: BTF key/value type definitions plus\n"
		   "    the live key/value contents.\n"
		   "Read-only; uses only LSM-allowed bpf() ops + xattr / stat.",
	.sections   = upatch_get_sections,
	.n_sections = ARRAY_SIZE(upatch_get_sections),
	.footer  =
"Examples:\n"
"  shirudo upatch get cve-2026-31431\n"
"  shirudo upatch get cve-2026-31431 --json | jq",
};

static int cmd_upatch_info(int argc, const char **argv)
{
	char name[UPATCH_NAME_MAX + 1];	/* not NUL-term on disk */
	const __u8 *unload_payload;
	struct upatch u;
	const char *path = NULL;
	bool json = false;
	int i, err, ret = 1;
	__u32 attach_len;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--json") == 0) {
			json = true;
		} else if (is_help(argv[i])) {
			print_help(&upatch_info_help);
			return 0;
		} else if (argv[i][0] == '-') {
			fprintf(stderr, "upatch info: unknown option '%s'\n",
				argv[i]);
			return 2;
		} else if (!path) {
			path = argv[i];
		} else {
			fprintf(stderr, "upatch info: unexpected argument '%s'\n",
				argv[i]);
			return 2;
		}
	}
	if (!path) {
		print_help(&upatch_info_help);
		return 2;
	}

	err = upatch_open(path, &u);
	if (err != 0) {
		pr_err("upatch info: %s: %s", path, strerror(-err));
		return 1;
	}

	memcpy(name, u.hdr.name, sizeof(u.hdr.name));
	name[UPATCH_NAME_MAX] = '\0';
	upatch_signed_attach(&u, &attach_len);
	unload_payload = upatch_signed_unload_payload(&u);

	if (json) {
		size_t cap = 8192 + (size_t)u.nr_decoders * 768;
		struct json_emit e = {};
		char payload_hex[2 * 32 + 1];
		char *buf = xmalloc(cap);

		if (!buf)
			goto out;
		e.buf = buf;
		e.cap = cap;
		hex_encode(u.hdr.payload_sha256, 32, payload_hex);
		json_obj_open(&e);
		json_kv_int(&e, "schema", 1);
		json_kv_string(&e, "path", path);
		json_kv_string(&e, "name", name);
		json_kv_string(&e, "type",
			       upatch_is_unload(&u) ? "unload"
								    : "load");
		json_kv_string(&e, "payload_type",
			       upatch_type_str(&u));
		json_kv_int(&e, "version", u.hdr.version);
		json_kv_string(&e, "payload_sha256", payload_hex);
		json_kv_int(&e, "loader_insns_len",
			    u.hdr.loader_insns_len);
		json_kv_int(&e, "signature_len", u.hdr.signature_len);
		json_kv_int(&e, "metadata_len", u.hdr.metadata_len);
		json_kv_int(&e, "data_len", u.hdr.data_len);
		json_kv_int(&e, "log_buf_sz", u.hdr.log_buf_sz);
		json_kv_int(&e, "file_size", (__s64)u.map_size);
		if (upatch_signed_name(&u)) {
			memcpy(name, upatch_signed_name(&u), sizeof(u.hdr.name));
			json_kv_string(&e, "signed_name", name);
		} else {
			json_kv_null(&e, "signed_name");
		}
		json_kv_int(&e, "attach_metadata_len", attach_len);
		if (unload_payload) {
			hex_encode(unload_payload, 32, payload_hex);
			json_kv_string(&e, "unload_payload_sha256", payload_hex);
		} else {
			json_kv_null(&e, "unload_payload_sha256");
		}
		json_arr_open(&e, "decoders");
		for (__u32 j = 0; j < u.nr_decoders; j++) {
			struct upatch_decoder_view d;

			if (upatch_decoder_view(&u, j, &d))
				continue;
			json_obj_open(&e);
			json_kv_string(&e, "language",
				       decoder_language_str(d.language));
			json_kv_int(&e, "api_version", d.api_version);
			json_kv_string(&e, "input_format",
				       decoder_input_str(d.input_format));
			json_kv_string(&e, "export_signal",
				       decoder_signal_str(d.export_signal));
			json_kv_string(&e, "upatch", d.upatch);
			json_kv_string(&e, "map", d.map);
			json_kv_string(&e, "source_file", d.source_name);
			json_kv_string(&e, "entrypoint", d.entrypoint);
			json_kv_int(&e, "source_len", d.source_len);
			json_obj_close(&e);
		}
		json_arr_close(&e);
		json_obj_close(&e);
		if (e.err)
			fprintf(stderr, "upatch info: json encode failed: %s\n",
				strerror(-e.err));
		else
			printf("%s\n", buf);
		xfree(buf, cap);
		ret = e.err ? 1 : 0;
		goto out;
	}

	printf("File:                  %s\n", path);
	printf("Name:                  %s\n", name);
	printf("Type:                  %s\n", flag_str(&u));
	printf("Payload type:          %s\n", upatch_type_str(&u));
	printf("Version:               %u\n", u.hdr.version);
	printf("Payload SHA256:        ");
	print_sha256_hex(u.hdr.payload_sha256);
	printf("\n");
	printf("File size:             %zu bytes\n", u.map_size);

	printf("\nLoader:\n");
	printf("  %-22s off=%u len=%u\n", "Instructions:",
	       u.hdr.loader_insns_off, u.hdr.loader_insns_len);
	printf("  %-22s %u\n", "Log buffer size:", u.hdr.log_buf_sz);
	if (u.hdr.metadata_len)
		printf("  %-22s off=%u len=%u\n", "Metadata:",
		       u.hdr.metadata_off, u.hdr.metadata_len);
	else
		printf("  %-22s (none)\n", "Metadata:");
	if (u.hdr.data_len)
		printf("  %-22s off=%u len=%u\n", "Data:",
		       u.hdr.data_off, u.hdr.data_len);
	else
		printf("  %-22s (none)\n", "Data:");

	printf("\nSignature:\n");
	printf("  %-22s %u\n", "Offset:", u.hdr.signature_off);
	printf("  %-22s %u bytes\n", "Length:", u.hdr.signature_len);

	printf("\nSigned sections:\n");
	if (upatch_signed_name(&u)) {
		memcpy(name, upatch_signed_name(&u), sizeof(u.hdr.name));
		printf("  %-22s %s\n", "Name:", name);
	} else {
		printf("  %-22s (none)\n", "Name:");
	}
	if (attach_len)
		printf("  %-22s %u bytes\n", "Attach metadata:", attach_len);
	else
		printf("  %-22s (none)\n", "Attach metadata:");
	if (unload_payload) {
		printf("  %-22s ", "Unload payload:");
		print_sha256_hex(unload_payload);
		printf("\n");
	} else {
		printf("  %-22s (none)\n", "Unload payload:");
	}

	printf("\nDecoders:\n");
	if (!upatch_has_decoders(&u)) {
		printf("  (none)\n");
	} else {
		for (__u32 j = 0; j < u.nr_decoders; j++) {
			struct upatch_decoder_view d;

			if (upatch_decoder_view(&u, j, &d))
				continue;
			printf("  %-22s %s/%s\n", "Target:", d.upatch, d.map);
			printf("    %-20s %s (api=%u)\n", "Language:",
			       decoder_language_str(d.language), d.api_version);
			printf("    %-20s %s\n", "Input:",
			       decoder_input_str(d.input_format));
			printf("    %-20s %s\n", "Export signal:",
			       decoder_signal_str(d.export_signal));
			printf("    %-20s %s:%s (%u bytes)\n", "Source:",
			       d.source_name, d.entrypoint, d.source_len);
		}
	}
	ret = 0;
out:
	upatch_close(&u);
	return ret;
}

static int is_upatch_file(const struct dirent *e)
{
	size_t len = strlen(e->d_name);

	return len > 7 && strcmp(e->d_name + len - 7, ".upatch") == 0;
}

static bool upatch_is_loaded(const char *name)
{
	char pin[PATH_MAX];
	char bpffs_name[UPATCH_BPFFS_NAME_MAX + 1];
	struct stat st;
	int fd;

	fd = upatch_open_first_link(name);
	if (fd < 0)
		goto test_pin;
	close(fd);
	return true;

test_pin:
	if (upatch_bpffs_name(bpffs_name, sizeof(bpffs_name), name))
		return false;
	if (strsprintf(pin, sizeof(pin), "%s/%s/test",
		       BPFFS_UPATCHES_DIR, bpffs_name) < 0)
		return false;
	return stat(pin, &st) == 0;
}

/*
 * Drift in either direction is the point: a persisted upatch that is
 * not loaded, or a loaded one with no persisted copy to survive a
 * reboot.
 */
static int cmd_upatch_list(int argc, const char **argv)
{
	struct dirent **persisted = NULL, **active = NULL;
	struct json_emit e = { .buf = NULL };
	int np, na, i, j, ret = 0;
	bool json = false;
	char *jbuf = NULL;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--json") == 0) {
			json = true;
		} else if (is_help(argv[i])) {
			print_help(&upatch_list_help);
			return 0;
		} else {
			fprintf(stderr, "upatch list: unknown option '%s'\n",
				argv[i]);
			return 2;
		}
	}

	np = scandir(UPATCHES_DIR, &persisted, is_upatch_file,
		     alphasort);
	if (np < 0)
		np = 0;
	na = scandir(BPFFS_UPATCHES_DIR, &active, NULL, alphasort);
	if (na < 0)
		na = 0;

	if (json) {
		jbuf = xmalloc(65536);
		if (!jbuf) {
			ret = 1;
			goto out;
		}
		e.buf = jbuf;
		e.cap = 65536;
		json_obj_open(&e);
		json_kv_int(&e, "schema", 1);
		json_arr_open(&e, "upatches");
	} else {
		printf("upatches (%s):\n", UPATCHES_DIR);
		if (np == 0)
			printf("  (none persisted)\n");
		else
			printf("  %-6s  %-6s  %-6s  %-18s  %s\n",
			       "loaded", "type", "kind", "payload-sha256", "name");
	}

	for (i = 0; i < np; i++) {
		char path[1024], name[UPATCH_NAME_MAX + 1];
		char payload_hex[2 * 32 + 1];
		struct upatch u;
		const char *type, *payload_type;
		bool loaded;

		if (strsprintf(path, sizeof(path), "%s/%s",
			       UPATCHES_DIR,
			       persisted[i]->d_name) < 0)
			continue;
		if (upatch_open(path, &u) != 0) {
			if (!json)
				printf("  %-6s  %-6s  %-18s  %s\n", "?", "?",
				       "(unreadable)", persisted[i]->d_name);
			continue;
		}
		memcpy(name, u.hdr.name, sizeof(u.hdr.name));
		name[UPATCH_NAME_MAX] = '\0';
		hex_encode(u.hdr.payload_sha256, 32, payload_hex);
		type = upatch_is_unload(&u) ? "unload" : "load";
		payload_type = upatch_type_str(&u);
		loaded = upatch_is_loaded(name);
		upatch_close(&u);

		if (json) {
			json_obj_open(&e);
			json_kv_string(&e, "name", name);
			json_kv_string(&e, "type", type);
			json_kv_string(&e, "payload_type", payload_type);
			json_kv_bool(&e, "loaded", loaded);
			json_kv_bool(&e, "persisted", 1);
			json_kv_string(&e, "payload_sha256", payload_hex);
			json_obj_close(&e);
		} else {
			char shown[19];

			memcpy(shown, payload_hex, 16);
			memcpy(shown + 16, "..", 3);
			printf("  %-6s  %-6s  %-6s  %-18s  %s\n",
			       loaded ? "yes" : "no", type, payload_type, shown, name);
		}
	}

	for (i = 0; i < na; i++) {
		char persist[1024];
		char raw_name[UPATCH_NAME_MAX + 1];
		const char *nm = active[i]->d_name;
		struct stat st;

		if (strcmp(nm, ".") == 0 || strcmp(nm, "..") == 0)
			continue;
		if (upatch_name_from_bpffs(raw_name, sizeof(raw_name), nm))
			continue;
		if (strsprintf(persist, sizeof(persist), "%s/%s.upatch",
			       UPATCHES_DIR, raw_name) < 0)
			continue;
		if (stat(persist, &st) == 0)
			continue;

		if (json) {
			json_obj_open(&e);
			json_kv_string(&e, "name", raw_name);
			json_kv_null(&e, "type");
			json_kv_bool(&e, "loaded", 1);
			json_kv_bool(&e, "persisted", 0);
			json_kv_null(&e, "payload_sha256");
			json_obj_close(&e);
		} else {
			printf("  %-6s  %-6s  %-18s  %s  (orphan: no persisted "
			       ".upatch, will not survive reboot)\n",
			       "yes", "?", "-", raw_name);
		}
	}

	if (json) {
		json_arr_close(&e);
		json_obj_close(&e);
		if (e.err) {
			fprintf(stderr, "upatch list: json encode failed: %s\n",
				strerror(-e.err));
			ret = 1;
		} else {
			printf("%s\n", jbuf);
		}
	}

out:
	for (i = 0; i < np; i++)
		libc_free(persisted[i]);
	libc_free(persisted);
	for (j = 0; j < na; j++)
		libc_free(active[j]);
	libc_free(active);
	xfree(jbuf, 65536);
	return ret;
}

/*
 * The context and the descriptors trailing it mirror
 * tools/lib/bpf/skel_internal.h, which the loader writes and
 * BPF_PROG_TEST_RUN copies back. libbpf's load wrapper exposes no
 * signature or keyring, so the attr is built by hand.
 */

struct loader_ctx {
	__u32		sz;
	__u32		flags;
	__u32		log_level;
	__u32		log_size;
	__u64		log_buf;
};

struct map_desc {
	int		map_fd;
	__u32		max_entries;
	__u64		initial_value;
};

struct prog_desc {
	int		prog_fd;
};

static int loader_map_create(const char *name, __u32 value_size,
			     const void *excl_prog_hash,
			     __u32 excl_prog_hash_sz)
{
	union bpf_attr attr = {};
	long fd;

	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = 4;
	attr.value_size = value_size ? value_size : 4;
	attr.max_entries = 1;
	attr.excl_prog_hash = ptr_to_u64(excl_prog_hash);
	attr.excl_prog_hash_size = excl_prog_hash_sz;
	strscpy(attr.map_name, name, sizeof(attr.map_name));

	fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
	return (int)fd;
}

static int loader_map_update(int map_fd, const void *value, __u32 value_sz)
{
	union bpf_attr attr = {};
	__u8 zero[4] = {};
	__u32 key = 0;
	long ret;

	attr.map_fd = map_fd;
	attr.key = ptr_to_u64(&key);
	attr.value = ptr_to_u64(value_sz ? value : zero);
	attr.flags = 0;
	ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
	return (int)ret;
}

static int loader_map_freeze(int map_fd)
{
	union bpf_attr attr = {};
	long ret;

	attr.map_fd = map_fd;
	ret = syscall(__NR_bpf, BPF_MAP_FREEZE, &attr, sizeof(attr));
	return (int)ret;
}

static int prog_load_signed(const struct bpf_insn *insns, size_t insn_cnt,
			    const char *prog_name,
			    const void *signature, __u32 signature_sz,
			    __s32 keyring_id, int loader_map_fd,
			    char *log_buf, size_t log_sz)
{
	union bpf_attr attr = {};
	int fd_array[1] = { loader_map_fd };
	long fd;

	attr.prog_type = BPF_PROG_TYPE_SYSCALL;
	attr.insn_cnt = (__u32)insn_cnt;
	attr.insns = ptr_to_u64(insns);
	attr.license = ptr_to_u64("Dual BSD/GPL");
	attr.prog_flags = BPF_F_SLEEPABLE;
	attr.log_level = log_buf ? 1 : 0;
	attr.log_size = (__u32)log_sz;
	attr.log_buf = ptr_to_u64(log_buf);
	attr.signature = ptr_to_u64(signature);
	attr.signature_size = signature_sz;
	attr.keyring_id = keyring_id;
	attr.fd_array = ptr_to_u64(fd_array);
	/*
	 * fd_array_cnt makes the verifier resolve the exclusive metadata
	 * map up front and fold its frozen contents into the signed buffer
	 * (insns || metadata). A signed load without it is rejected: the
	 * kernel refuses to bind a map through the sparse fd_array path.
	 */
	attr.fd_array_cnt = 1;
	memcpy(attr.prog_name, prog_name,
	       strnlen(prog_name, sizeof(attr.prog_name)));

	fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	return (int)fd;
}

/* A NULL name attaches at the attach_btf_id the signed program carries. */
static int prog_attach_raw_tp(int prog_fd)
{
	union bpf_attr attr = {};
	long fd;

	attr.raw_tracepoint.name = 0;
	attr.raw_tracepoint.prog_fd = (__u32)prog_fd;
	fd = syscall(__NR_bpf, BPF_RAW_TRACEPOINT_OPEN, &attr, sizeof(attr));
	return fd >= 0 ? (int)fd : -errno;
}

static int prog_attach_cgroup_skb(int prog_fd,
				  enum bpf_attach_type attach_type);

static int prog_attach_btf_link(int prog_fd, enum bpf_attach_type attach_type)
{
	union bpf_attr attr = {};
	long fd;

	attr.link_create.prog_fd = (__u32)prog_fd;
	attr.link_create.target_fd = 0;
	attr.link_create.attach_type = attach_type;
	fd = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
	return fd >= 0 ? (int)fd : -errno;
}

static int prog_func_name(int prog_fd, const struct bpf_prog_info *base,
			  char *out, size_t cap)
{
	struct bpf_prog_info info = {};
	struct bpf_func_info fi;
	struct btf *btf;
	const struct btf_type *t;
	const char *name;
	void *recs;
	size_t recs_sz;
	__u32 len;
	int ret = 0;

	if (!out || cap == 0)
		return -EINVAL;
	out[0] = '\0';
	if (base->nr_func_info == 0 || base->func_info_rec_size == 0 ||
	    base->btf_id == 0)
		return -ENOENT;
	if (base->func_info_rec_size < sizeof(struct bpf_func_info))
		return -EINVAL;
	recs_sz = (size_t)base->nr_func_info * base->func_info_rec_size;
	recs = xmalloc(recs_sz);
	if (!recs)
		return -ENOMEM;

	info.nr_func_info = base->nr_func_info;
	info.func_info_rec_size = base->func_info_rec_size;
	info.func_info = ptr_to_u64(recs);
	len = sizeof(info);
	if (bpf_prog_get_info_by_fd(prog_fd, &info, &len) != 0) {
		ret = -errno;
		goto out_free;
	}
	memcpy(&fi, recs, sizeof(fi));
	btf = btf__load_from_kernel_by_id(base->btf_id);
	if (!btf) {
		ret = -errno;
		goto out_free;
	}
	t = btf__type_by_id(btf, fi.type_id);
	name = t ? btf__name_by_offset(btf, t->name_off) : NULL;
	if (!name || !name[0]) {
		ret = -ENOENT;
	} else if (strlen(name) >= cap) {
		ret = -ENAMETOOLONG;
	} else {
		strscpy(out, name, cap);
		ret = 0;
	}
	btf__free(btf);
out_free:
	xfree(recs, recs_sz);
	return ret;
}

static int cgroup_skb_attach_type_from_name(const char *name,
					    enum bpf_attach_type *attach_type)
{
	if (!name || !name[0])
		return -EINVAL;
	if (strstr(name, "egress") || strstr(name, "query") ||
	    strstr(name, "send")) {
		*attach_type = BPF_CGROUP_INET_EGRESS;
		return 0;
	}
	if (strstr(name, "ingress") || strstr(name, "response") ||
	    strstr(name, "recv") || strstr(name, "receive")) {
		*attach_type = BPF_CGROUP_INET_INGRESS;
		return 0;
	}
	return -EINVAL;
}

static int prog_attach_cgroup_skb_fallback(int prog_fd,
					   const struct bpf_prog_info *info)
{
	enum bpf_attach_type attach_type;
	char func[128];
	int ret;

	strscpy(func, info->name, sizeof(func));
	ret = prog_func_name(prog_fd, info, func, sizeof(func));
	if (ret && !func[0]) {
		pr_err("program metadata says raw_tracepoint, but loaded "
		       "program type is cgroup_skb and function name is "
		       "unavailable; rebuild the upatch with cgroup_skb "
		       "metadata");
		return ret;
	}
	ret = cgroup_skb_attach_type_from_name(func, &attach_type);
	if (ret) {
		pr_err("program metadata says raw_tracepoint, but loaded "
		       "program type is cgroup_skb and function '%s' does "
		       "not identify ingress or egress; rebuild the upatch "
		       "with cgroup_skb metadata", func);
		return ret;
	}
	pr_warn("program metadata says raw_tracepoint, but loaded program "
		"type is cgroup_skb; inferring %s from function '%s'",
		attach_type == BPF_CGROUP_INET_EGRESS ? "egress" : "ingress",
		func);
	ret = prog_attach_cgroup_skb(prog_fd, attach_type);
	if (ret >= 0)
		pr_info("attached cgroup_skb fallback as %s",
			attach_type == BPF_CGROUP_INET_EGRESS ?
			"egress" : "ingress");
	return ret;
}

static int prog_attach_default(int prog_fd)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	enum bpf_attach_type attach_type;

	if (bpf_prog_get_info_by_fd(prog_fd, &info, &info_len) != 0)
		return -errno;

	switch (info.type) {
	case BPF_PROG_TYPE_LSM:
		attach_type = BPF_LSM_MAC;
		break;
	case BPF_PROG_TYPE_CGROUP_SKB:
		return prog_attach_cgroup_skb_fallback(prog_fd, &info);
	default:
		return prog_attach_raw_tp(prog_fd);
	}

	return prog_attach_btf_link(prog_fd, attach_type);
}

static int prog_attach_cgroup_skb(int prog_fd, enum bpf_attach_type attach_type)
{
	union bpf_attr attr = {};
	int cgroup_fd, ret;
	long fd;

	cgroup_fd = open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cgroup_fd < 0)
		return -errno;

	attr.link_create.prog_fd = (__u32)prog_fd;
	attr.link_create.target_fd = (__u32)cgroup_fd;
	attr.link_create.attach_type = attach_type;
	fd = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
	ret = fd >= 0 ? (int)fd : -errno;
	close(cgroup_fd);
	return ret;
}

static int prog_attach_netfilter_ipv6_pre_routing(int prog_fd)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .netfilter.pf = NFPROTO_IPV6,
		    .netfilter.hooknum = NF_INET_PRE_ROUTING,
		    .netfilter.priority = NF_IP6_PRI_RAW_BEFORE_DEFRAG,
		    .netfilter.flags = 0);

	return bpf_link_create(prog_fd, 0, BPF_NETFILTER, &opts);
}

/* The number after prefix in the file at path, up to INT_MAX. */
static int read_int_file(const char *path, const char *prefix)
{
	size_t skip = strlen(prefix);
	char buf[64];
	__u64 value;
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	n = read(fd, buf, sizeof(buf) - 1);
	if (n < 0) {
		int e = -errno;

		close(fd);
		return e;
	}
	close(fd);
	if (n == 0)
		return -EINVAL;
	buf[n] = '\0';
	if ((size_t)n < skip || memcmp(buf, prefix, skip) ||
	    parse_u64(buf + skip, digits(buf + skip, (size_t)n - skip),
		      INT_MAX, &value))
		return -EINVAL;
	return (int)value;
}

static int determine_kprobe_perf_type(void)
{
	return read_int_file("/sys/bus/event_source/devices/kprobe/type", "");
}

static int determine_kprobe_retprobe_bit(void)
{
	return read_int_file("/sys/bus/event_source/devices/kprobe/format/retprobe",
			     "config:");
}

static int perf_event_open_kprobe(const char *target, __u64 offset,
				  bool retprobe)
{
	struct perf_event_attr attr = {};
	int type, bit;
	long fd;

	type = determine_kprobe_perf_type();
	if (type < 0)
		return type;
	attr.size = sizeof(attr);
	attr.type = (__u32)type;
	attr.config1 = ptr_to_u64(target);
	attr.config2 = offset;
	if (retprobe) {
		bit = determine_kprobe_retprobe_bit();
		if (bit < 0)
			return bit;
		if (bit >= 64)
			return -EINVAL;
		attr.config |= 1ULL << bit;
	}

	fd = syscall(__NR_perf_event_open, &attr,
		     -1 /* pid */, 0 /* cpu */,
		     -1 /* group_fd */, PERF_FLAG_FD_CLOEXEC);
	return fd >= 0 ? (int)fd : -errno;
}

static int prog_attach_perf_event(int prog_fd, int perf_fd)
{
	union bpf_attr attr = {};
	long fd;

	attr.link_create.prog_fd = (__u32)prog_fd;
	attr.link_create.target_fd = (__u32)perf_fd;
	attr.link_create.attach_type = BPF_PERF_EVENT;
	fd = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
	return fd >= 0 ? (int)fd : -errno;
}

static const char *attach_kind_name(__u32 kind)
{
	switch (kind) {
	case UPATCH_ATTACH_RAW_TRACEPOINT:
		return "raw_tracepoint";
	case UPATCH_ATTACH_KPROBE:
		return "kprobe";
	case UPATCH_ATTACH_KRETPROBE:
		return "kretprobe";
	case UPATCH_ATTACH_CGROUP_SKB_INGRESS:
		return "cgroup_skb/ingress";
	case UPATCH_ATTACH_CGROUP_SKB_EGRESS:
		return "cgroup_skb/egress";
	case UPATCH_ATTACH_FMOD_RET:
		return "fmod_ret";
	case UPATCH_ATTACH_NETFILTER_IPV6_PRE_ROUTING:
		return "netfilter/ipv6-pre-routing";
	case UPATCH_ATTACH_UPROBE_MULTI:
		return "uprobe.multi";
	case UPATCH_ATTACH_BPF_PROG:
		return "bpf_prog";
	default:
		return "unknown";
	}
}

static int prepare_uprobe_targets(struct prog_spec *specs,
				  __u32 nr_progs)
{
	__u32 i;

	for (i = 0; i < nr_progs; i++) {
		struct prog_spec *spec = &specs[i];
		__u8 build_id[UPATCH_BUILD_ID_MAX];
		__u32 build_id_len = 0;
		char proc_path[64];
		struct stat opened_stat;
		int path_fd, fd, ret;

		if (spec->kind != UPATCH_ATTACH_UPROBE_MULTI)
			continue;
		path_fd = open(spec->uprobe_path, O_PATH | O_CLOEXEC);
		if (path_fd < 0)
			return -errno;
		if (fstat(path_fd, &spec->target_stat) != 0) {
			ret = -errno;
			close(path_fd);
			return ret;
		}
		if (!S_ISREG(spec->target_stat.st_mode)) {
			close(path_fd);
			return -ESTALE;
		}
		if (strsprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d",
			       path_fd) < 0) {
			close(path_fd);
			return -E2BIG;
		}
		fd = open(proc_path, O_RDONLY | O_CLOEXEC);
		ret = fd < 0 ? -errno : 0;
		close(path_fd);
		if (ret)
			return ret;
		if (fstat(fd, &opened_stat) != 0) {
			ret = -errno;
			close(fd);
			return ret;
		}
		if (opened_stat.st_dev != spec->target_stat.st_dev ||
		    opened_stat.st_ino != spec->target_stat.st_ino) {
			close(fd);
			return -ESTALE;
		}
		for (__u32 j = 0; j < spec->nr_uprobe_offsets; j++) {
			if (spec->uprobe_offsets[j] >= (__u64)opened_stat.st_size) {
				close(fd);
				return -ERANGE;
			}
		}
		ret = elf_build_id_fd(fd, build_id, &build_id_len);
		if (ret) {
			close(fd);
			return ret == -EACCES || ret == -EPERM ? ret : -ESTALE;
		}
		if (build_id_len != spec->build_id_len ||
		    memcmp(build_id, spec->build_id, build_id_len) != 0) {
			close(fd);
			return -ESTALE;
		}
		spec->target_fd = fd;
	}
	return 0;
}

static int prog_attach_uprobe_multi(int prog_fd,
				    const struct prog_spec *spec)
{
	union bpf_attr attr = {};
	long fd;

	if (spec->target_fd < 0 || !spec->uprobe_path ||
	    !spec->uprobe_offsets || !spec->nr_uprobe_offsets)
		return -EINVAL;
	attr.link_create.prog_fd = (__u32)prog_fd;
	attr.link_create.attach_type = BPF_TRACE_UPROBE_MULTI;
	attr.link_create.uprobe_multi.offsets =
		ptr_to_u64(spec->uprobe_offsets);
	attr.link_create.uprobe_multi.cnt = spec->nr_uprobe_offsets;
	attr.link_create.uprobe_multi.flags = BPF_F_UPROBE_MULTI_PATH_FD;
	attr.link_create.uprobe_multi.path_fd = (__u32)spec->target_fd;
	fd = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
	return fd >= 0 ? (int)fd : -errno;
}

static int prog_attach_for_spec(int prog_fd,
				const struct prog_spec *spec)
{
	int perf_fd, link_fd;

	switch (spec->kind) {
	case UPATCH_ATTACH_RAW_TRACEPOINT:
		return prog_attach_default(prog_fd);
	case UPATCH_ATTACH_CGROUP_SKB_INGRESS:
		return prog_attach_cgroup_skb(prog_fd,
					      BPF_CGROUP_INET_INGRESS);
	case UPATCH_ATTACH_CGROUP_SKB_EGRESS:
		return prog_attach_cgroup_skb(prog_fd,
					      BPF_CGROUP_INET_EGRESS);
	case UPATCH_ATTACH_FMOD_RET:
		return prog_attach_btf_link(prog_fd, BPF_MODIFY_RETURN);
	case UPATCH_ATTACH_NETFILTER_IPV6_PRE_ROUTING:
		return prog_attach_netfilter_ipv6_pre_routing(prog_fd);
	case UPATCH_ATTACH_UPROBE_MULTI:
		return prog_attach_uprobe_multi(prog_fd, spec);
	case UPATCH_ATTACH_BPF_PROG:
		/* The target was fixed by the signed loader at load time */
		return prog_attach_raw_tp(prog_fd);
	case UPATCH_ATTACH_KPROBE:
	case UPATCH_ATTACH_KRETPROBE:
		perf_fd = perf_event_open_kprobe(spec->target, spec->offset,
						 spec->kind == UPATCH_ATTACH_KRETPROBE);
		if (perf_fd < 0)
			return perf_fd;
		link_fd = prog_attach_perf_event(prog_fd, perf_fd);
		close(perf_fd);
		return link_fd;
	default:
		return -EINVAL;
	}
}

/* The initial network namespace's cookie, NET_NS_INIT_ID in linux/nsfs.h. */
#define NET_NS_INIT_COOKIE	7ULL
/* The root of the unified cgroup hierarchy. */
#define ROOT_CGROUP_ID		1ULL
#ifndef SO_NETNS_COOKIE
#define SO_NETNS_COOKIE			71
#endif

/* A netfilter link hooks the caller's network namespace. */
static int netns_initial(void)
{
	socklen_t len = sizeof(__u64);
	__u64 cookie = 0;
	int fd, ret;

	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	ret = getsockopt(fd, SOL_SOCKET, SO_NETNS_COOKIE, &cookie, &len) ?
	     -errno : 0;
	close(fd);
	if (ret)
		return ret;
	return cookie == NET_NS_INIT_COOKIE ? 0 : -EXDEV;
}

/*
 * The site a kprobe, uprobe, cgroup or netfilter program attaches at is
 * named by the caller, and the caller's cgroup namespace and mount of
 * the cgroup tree, network namespace and sysfs are root's to arrange:
 * a cgroup_skb program attached under a namespace root or a bind mount
 * of a subtree guards a corner, a netfilter program in a namespace of
 * its own guards nothing, a kprobe opened through a sysfs that names
 * another PMU lands elsewhere, and each is measured as loaded. What the
 * kernel reports about the link is compared with the spec before the
 * link is pinned; -EXDEV when they differ.
 */
static int link_matches_spec(int link_fd,
			     const struct prog_spec *spec)
{
	char func[UPATCH_ATTACH_TARGET_MAX] = {};
	struct bpf_link_info info = {};
	__u32 len = sizeof(info);
	bool ret;

	if (spec->kind == UPATCH_ATTACH_KPROBE ||
	    spec->kind == UPATCH_ATTACH_KRETPROBE) {
		info.perf_event.kprobe.func_name = ptr_to_u64(func);
		info.perf_event.kprobe.name_len = sizeof(func);
	}
	if (bpf_link_get_info_by_fd(link_fd, &info, &len))
		return -errno;
	if (info.type == BPF_LINK_TYPE_CGROUP)
		return info.cgroup.cgroup_id == ROOT_CGROUP_ID ?
		       0 : -EXDEV;
	switch (spec->kind) {
	case UPATCH_ATTACH_CGROUP_SKB_INGRESS:
	case UPATCH_ATTACH_CGROUP_SKB_EGRESS:
		return -EXDEV;
	case UPATCH_ATTACH_NETFILTER_IPV6_PRE_ROUTING:
		if (info.type != BPF_LINK_TYPE_NETFILTER ||
		    info.netfilter.pf != NFPROTO_IPV6 ||
		    info.netfilter.hooknum != NF_INET_PRE_ROUTING ||
		    info.netfilter.priority != NF_IP6_PRI_RAW_BEFORE_DEFRAG)
			return -EXDEV;
		return netns_initial();
	case UPATCH_ATTACH_KPROBE:
	case UPATCH_ATTACH_KRETPROBE:
		ret = spec->kind == UPATCH_ATTACH_KRETPROBE;
		if (info.type != BPF_LINK_TYPE_PERF_EVENT ||
		    info.perf_event.type != (ret ? BPF_PERF_EVENT_KRETPROBE :
						   BPF_PERF_EVENT_KPROBE) ||
		    info.perf_event.kprobe.name_len > sizeof(func) ||
		    info.perf_event.kprobe.offset != spec->offset ||
		    strcmp(func, spec->target))
			return -EXDEV;
		return 0;
	case UPATCH_ATTACH_UPROBE_MULTI:
		if (info.type != BPF_LINK_TYPE_UPROBE_MULTI ||
		    info.uprobe_multi.count != spec->nr_uprobe_offsets)
			return -EXDEV;
		return 0;
	case UPATCH_ATTACH_FMOD_RET:
		if (info.type != BPF_LINK_TYPE_TRACING ||
		    info.tracing.attach_type != BPF_MODIFY_RETURN)
			return -EXDEV;
		return 0;
	case UPATCH_ATTACH_BPF_PROG:
		if (info.type != BPF_LINK_TYPE_TRACING ||
		    !spec->bpf_prog_id ||
		    info.tracing.target_obj_id != spec->bpf_prog_id)
			return -EXDEV;
		return 0;
	default:
		if (info.type != BPF_LINK_TYPE_RAW_TRACEPOINT &&
		    info.type != BPF_LINK_TYPE_TRACING)
			return -EXDEV;
		return 0;
	}
}

static int obj_pin(int fd, const char *path)
{
	union bpf_attr attr = {};
	long ret;

	attr.pathname = ptr_to_u64(path);
	attr.bpf_fd = (__u32)fd;
	ret = syscall(__NR_bpf, BPF_OBJ_PIN, &attr, sizeof(attr));
	return ret >= 0 ? 0 : -errno;
}

static int mkdir_if_absent(const char *path, mode_t mode, bool *made)
{
	if (mkdir(path, mode) == 0) {
		if (made)
			*made = true;
		return 0;
	}
	return errno == EEXIST ? 0 : -errno;
}

static void count_attach_progs(const struct prog_spec *specs,
			       __u32 nr_progs, __u32 *out)
{
	__u32 i, n = 0;

	for (i = 0; i < nr_progs; i++) {
		if (specs[i].role == UPATCH_PROG_ROLE_ATTACH)
			n++;
	}
	*out = n;
}

static int prog_pin_path(char *pin, size_t sz, const char *dir,
			 const char *serializers_dir,
			 const struct prog_spec *spec,
			 __u32 attach_count, __u32 attach_idx)
{
	int n;

	if (spec->role == UPATCH_PROG_ROLE_SERIALIZER)
		n = strsprintf(pin, sz, "%s/%s", serializers_dir, spec->map);
	else if (spec->role == UPATCH_PROG_ROLE_TEST_RUN)
		n = strsprintf(pin, sz, "%s/test", dir);
	else if (attach_count == 1)
		n = strsprintf(pin, sz, "%s/link", dir);
	else
		n = strsprintf(pin, sz, "%s/link_%u", dir, attach_idx);
	return n < 0 ? -ENAMETOOLONG : 0;
}

/*
 * Serializers are pinned as programs for `upatch map`; the rest as links.
 * A failure unpins what this call pinned: the upatch is then neither
 * archived nor measured, so none of its programs may stay attached.
 */
static int attach_and_pin_progs(const struct loader_ctx *cx,
				size_t prog_desc_off, __u32 nr_progs,
				const char *name,
				const struct prog_spec *specs)
{
	char dir[PATH_MAX], serializers_dir[PATH_MAX + 16];
	bool made_dir = false, made_serializers = false;
	char bpffs_name[UPATCH_BPFFS_NAME_MAX + 1];
	__u32 i, attach_count = 0, attach_seen = 0;
	char progs_dir[PATH_MAX + 8];
	char pin[PATH_MAX + 32];
	bool made_progs = false;
	bool *made_prog = NULL;
	bool *made = NULL;
	int test_fd = -1;
	int ret;

	if (nr_progs == 0) {
		pr_warn("upatch carries no programs to attach");
		return 0;
	}
	if (upatch_bpffs_name(bpffs_name, sizeof(bpffs_name), name))
		return -ENAMETOOLONG;

	ret = mkdir_if_absent(BPFFS_UPATCHES_DIR, 0700, NULL);
	if (ret) {
		pr_err("mkdir %s: %s", BPFFS_UPATCHES_DIR,
		       strerror(-ret));
		return ret;
	}
	if (strsprintf(dir, sizeof(dir), "%s/%s",
		       BPFFS_UPATCHES_DIR, bpffs_name) < 0)
		return -ENAMETOOLONG;
	if (strsprintf(serializers_dir, sizeof(serializers_dir),
		       "%s/serializers", dir) < 0)
		return -ENAMETOOLONG;
	if (strsprintf(progs_dir, sizeof(progs_dir), "%s/progs", dir) < 0)
		return -ENAMETOOLONG;
	made = xcalloc(nr_progs, sizeof(*made));
	if (!made)
		return -ENOMEM;
	made_prog = xcalloc(nr_progs, sizeof(*made_prog));
	if (!made_prog) {
		xfree(made, nr_progs * sizeof(*made));
		return -ENOMEM;
	}
	ret = mkdir_if_absent(dir, 0700, &made_dir);
	if (ret) {
		pr_err("mkdir %s: %s", dir, strerror(-ret));
		goto out;
	}
	count_attach_progs(specs, nr_progs, &attach_count);

	for (i = 0; i < nr_progs; i++) {
		const struct prog_desc *pd =
			(const void *)((const char *)cx + prog_desc_off +
				       (size_t)i * sizeof(*pd));
		int inner_fd = pd->prog_fd;
		const struct prog_spec *spec = &specs[i];
		int link_fd;

		if (inner_fd <= 0) {
			pr_err("loader produced no fd for prog %u", i);
			ret = -EINVAL;
			goto out;
		}
		ret = prog_pin_path(pin, sizeof(pin), dir, serializers_dir,
				    spec, attach_count, attach_seen);
		if (ret)
			goto out;
		if (spec->role == UPATCH_PROG_ROLE_SERIALIZER) {
			struct stat st;

			ret = mkdir_if_absent(serializers_dir, 0700,
					      &made_serializers);
			if (ret) {
				pr_err("mkdir %s: %s", serializers_dir,
				       strerror(-ret));
				goto out;
			}
			/*
			 * A pin a load left when it died before its link is
			 * bound to maps nothing reaches any more: replace it.
			 */
			if (stat(pin, &st) == 0 && unlink(pin)) {
				ret = -errno;
				pr_err("unlink stale serializer pin %s: %s", pin,
				       strerror(-ret));
				goto out;
			}
			ret = obj_pin(inner_fd, pin);
			if (ret) {
				pr_err("pin serializer %s: %s", pin,
				       strerror(-ret));
				goto out;
			}
			made[i] = true;
			pr_info("pinned serializer prog %u -> %s", i, pin);
			continue;
		}
		if (spec->role == UPATCH_PROG_ROLE_TEST_RUN) {
			struct stat st;

			test_fd = inner_fd;
			if (stat(pin, &st) == 0 && unlink(pin)) {
				ret = -errno;
				pr_err("unlink stale test-run pin %s: %s", pin,
				       strerror(-ret));
				goto out;
			}
			ret = obj_pin(inner_fd, pin);
			if (ret) {
				pr_err("pin test-run program %s: %s", pin,
				       strerror(-ret));
				goto out;
			}
			made[i] = true;
			pr_info("pinned test-run prog %u -> %s", i, pin);
			continue;
		}
		attach_seen++;

		link_fd = prog_attach_for_spec(inner_fd, spec);
		if (link_fd < 0) {
			if (spec->kind == UPATCH_ATTACH_UPROBE_MULTI)
				pr_err("attach prog %u (%s %s:%s): %s", i,
				       attach_kind_name(spec->kind),
				       spec->uprobe_path, spec->target,
				       strerror(-link_fd));
			else if (spec->target[0])
				pr_err("attach prog %u (%s %s): %s",
				       i, attach_kind_name(spec->kind),
				       spec->target, strerror(-link_fd));
			else
				pr_err("attach prog %u (%s): %s",
				       i, attach_kind_name(spec->kind),
				       strerror(-link_fd));
			ret = link_fd;
			goto out;
		}
		/* Unpinned, a closed link detaches. */
		ret = link_matches_spec(link_fd, spec);
		if (ret) {
			pr_err("attach prog %u (%s %s): the link is not at "
			       "the site the metadata names: %s", i,
			       attach_kind_name(spec->kind), spec->target,
			       strerror(-ret));
			close(link_fd);
			goto out;
		}
		ret = obj_pin(link_fd, pin);
		close(link_fd);
		if (ret) {
			pr_err("pin %s: %s", pin, strerror(-ret));
			goto out;
		}
		made[i] = true;
		pr_info("attached + pinned prog %u (%s) -> %s",
			i, attach_kind_name(spec->kind), pin);

		/* Programs of other upatches attach to this one through its pin */
		ret = mkdir_if_absent(progs_dir, 0700, &made_progs);
		if (ret) {
			pr_err("mkdir %s: %s", progs_dir, strerror(-ret));
			goto out;
		}
		if (strsprintf(pin, sizeof(pin), "%s/prog_%u", progs_dir, i) < 0) {
			ret = -ENAMETOOLONG;
			goto out;
		}
		ret = obj_pin(inner_fd, pin);
		if (ret) {
			pr_err("pin %s: %s", pin, strerror(-ret));
			goto out;
		}
		made_prog[i] = true;
	}
	if (test_fd >= 0) {
		__u64 init_ctx[2] = {};
		__u32 retval = 0;

		/* A zero context is the load-time arena initialization call. */
		ret = prog_test_run(test_fd, init_ctx, sizeof(init_ctx),
				    &retval);
		if (ret || (__s32)retval < 0) {
			pr_err("initialize test-run arena: %s",
			       ret ? strerror(-ret) : strerror(-(__s32)retval));
			if (!ret)
				ret = (__s32)retval;
			goto out;
		}
	}
out:
	if (ret) {
		attach_seen = 0;
		for (i = 0; i < nr_progs; i++) {
			if (made[i] &&
			    !prog_pin_path(pin, sizeof(pin), dir,
					   serializers_dir, &specs[i],
					   attach_count, attach_seen))
				unlink(pin);
			if (specs[i].role == UPATCH_PROG_ROLE_ATTACH)
				attach_seen++;
			if (made_prog[i] &&
			    strsprintf(pin, sizeof(pin), "%s/prog_%u", progs_dir, i) >= 0)
				unlink(pin);
		}
		if (made_progs)
			rmdir(progs_dir);
		if (made_serializers)
			rmdir(serializers_dir);
		if (made_dir)
			rmdir(dir);
	}
	xfree(made_prog, nr_progs * sizeof(*made_prog));
	xfree(made, nr_progs * sizeof(*made));
	return ret;
}

/*
 * Best effort: the upatch is loaded, so a map that cannot be pinned is
 * logged and left unobservable until the next load. bpffs reserves dots
 * in path components, so libbpf's .bss, .data and .rodata are skipped.
 */
static int pin_upatch_maps(const struct loader_ctx *cx,
			   __u32 nr_maps, __u32 shared_policy_map_idx,
			   __u32 shared_socket_policy_map_idx,
			   const char *name)
{
	char dir[PATH_MAX], maps_dir[PATH_MAX + 8];
	char bpffs_name[UPATCH_BPFFS_NAME_MAX + 1];
	char pin[PATH_MAX + 32];
	__u32 i;
	int ret;

	if (nr_maps == 0)
		return 0;
	if (upatch_bpffs_name(bpffs_name, sizeof(bpffs_name), name))
		return 0;
	if (strsprintf(dir, sizeof(dir), "%s/%s",
		       BPFFS_UPATCHES_DIR, bpffs_name) < 0)
		return -ENAMETOOLONG;
	if (strsprintf(maps_dir, sizeof(maps_dir), "%s/maps", dir) < 0)
		return -ENAMETOOLONG;
	ret = mkdir_if_absent(maps_dir, 0700, NULL);
	if (ret) {
		pr_warn("upatch maps: mkdir %s: %s (continuing without "
			"map pins)", maps_dir, strerror(-ret));
		return 0;
	}
	for (i = 0; i < nr_maps; i++) {
		const struct map_desc *md =
			(const void *)((const char *)cx +
				       sizeof(struct loader_ctx) +
				       (size_t)i * sizeof(*md));
		struct bpf_map_info info = {};
		__u32 info_len = sizeof(info);
		struct stat st;
		int err;

		if (i == shared_policy_map_idx ||
		    i == shared_socket_policy_map_idx || md->map_fd <= 0)
			continue;
		err = bpf_map_get_info_by_fd(md->map_fd, &info, &info_len);
		if (err) {
			pr_warn("upatch maps: get_info(map %u): %s",
				i, strerror(errno));
			continue;
		}
		if (info.name[0] == '\0')
			continue;
		if (strchr(info.name, '.'))
			continue;
		/* upatch-private maps are intentionally not operator-visible. */
		if (strncmp(info.name, "obs_i_", 6) == 0)
			continue;
		if (strsprintf(pin, sizeof(pin), "%s/%s", maps_dir,
			       info.name) < 0)
			continue;
		if (stat(pin, &st) == 0)
			continue;	/* already pinned (idempotent) */
		if (obj_pin(md->map_fd, pin) != 0) {
			pr_warn("upatch maps: pin %s: %s", pin,
				strerror(errno));
			continue;
		}
		pr_info("pinned map %u (%s, type=%u) -> %s",
			i, info.name, (__u32)info.type, pin);
	}
	return 0;
}

static int open_shared_policy_map(const char *pin, __u32 type,
				  __u32 value_size, __u32 map_flags)
{
	struct bpf_map_info info = {};
	__u32 info_len = sizeof(info);
	int fd, ret;

	fd = bpf_obj_get(pin);
	if (fd < 0)
		return -errno;
	ret = bpf_map_get_info_by_fd(fd, &info, &info_len);
	if (ret) {
		ret = -errno;
		goto err;
	}
	if (info.type != type || info.key_size != sizeof(__s32) ||
	    info.value_size != value_size || info.map_flags != map_flags) {
		ret = -EINVAL;
		goto err;
	}
	if (fd == 0) {
		int copy_fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);

		if (copy_fd < 0) {
			ret = -errno;
			goto err;
		}
		close(fd);
		fd = copy_fd;
	}
	return fd;
err:
	close(fd);
	return ret;
}

/*
 * The value `upatch unload` checks, unforgeable behind bpf2's xattr
 * guard. The load stands, so a failure is not fatal, but it leaves the
 * upatch un-unloadable through the normal path: an error, not a warning.
 */
static void set_pin_payload(const char *name, const __u8 payload[32])
{
	char dir[PATH_MAX];
	char bpffs_name[UPATCH_BPFFS_NAME_MAX + 1];

	if (upatch_bpffs_name(bpffs_name, sizeof(bpffs_name), name))
		return;
	if (strsprintf(dir, sizeof(dir), "%s/%s", BPFFS_UPATCHES_DIR,
		       bpffs_name) < 0)
		return;
	if (setxattr(dir, XATTR_PAYLOAD, payload, 32, 0) != 0)
		pr_err("upatch: cannot record payload xattr on %s: %s "
		       "(unload of this upatch will refuse)",
		       dir, strerror(errno));
}

static int get_pin_payload(const char *name, __u8 out[32])
{
	char dir[PATH_MAX];
	char bpffs_name[UPATCH_BPFFS_NAME_MAX + 1];
	ssize_t n;

	if (upatch_bpffs_name(bpffs_name, sizeof(bpffs_name), name))
		return -ENAMETOOLONG;
	if (strsprintf(dir, sizeof(dir), "%s/%s", BPFFS_UPATCHES_DIR,
		       bpffs_name) < 0)
		return -ENAMETOOLONG;
	n = getxattr(dir, XATTR_PAYLOAD, out, 32);
	if (n < 0)
		return -errno;
	if (n != 32)
		return -EINVAL;
	return 0;
}

/*
 * The loader of a program attaching to a program of another upatch carries
 * a BTF ID found in that upatch's BTF, so only the build with the signed
 * payload may be the target. Only shirudo records the payload on a pin, and
 * the target's id is compared to the link's after the load, so a target
 * unloaded or replaced meanwhile is not attached to either.
 */
static int prepare_bpf_prog_targets(struct prog_spec *specs,
				    __u32 nr_progs)
{
	char bpffs_name[UPATCH_BPFFS_NAME_MAX + 1];
	__u8 live[UPATCH_PAYLOAD_HASH_LEN];
	char pin[PATH_MAX];
	__u32 i;
	int ret;

	for (i = 0; i < nr_progs; i++) {
		struct prog_spec *spec = &specs[i];
		struct bpf_prog_info info = {};
		__u32 info_len = sizeof(info);
		int fd;

		if (spec->kind != UPATCH_ATTACH_BPF_PROG)
			continue;
		ret = get_pin_payload(spec->bpf_upatch, live);
		if (ret)
			return ret == -ENODATA ? -ENOENT : ret;
		if (memneq_explicit(live, spec->bpf_payload, sizeof(live)))
			return -EBADMSG;
		if (upatch_bpffs_name(bpffs_name, sizeof(bpffs_name),
				      spec->bpf_upatch) ||
		    strsprintf(pin, sizeof(pin), "%s/%s/progs/prog_%u",
			       BPFFS_UPATCHES_DIR, bpffs_name,
			       spec->bpf_prog_idx) < 0)
			return -ENAMETOOLONG;
		fd = bpf_obj_get(pin);
		if (fd < 0)
			return fd;
		ret = bpf_prog_get_info_by_fd(fd, &info, &info_len);
		close(fd);
		if (ret)
			return ret;
		spec->bpf_prog_id = info.id;
	}
	return 0;
}

/* Resolve the kernel BPF keyring and compare it with the frozen record. */
static int trust_anchor_keyring(key_serial_t *keyring, key_serial_t *serial,
				struct op_report *rep)
{
	struct identity id;
	key_serial_t ring;
	int ret;

	ret = identity_read(&id);
	if (ret) {
		pr_err("no trust anchor frozen this boot: %s (run `shirudo "
		       "init`)", strerror(-ret));
		rep_fail(rep, "pre_flight", "keyring_missing", -ret,
			 "no trust anchor frozen this boot");
		return -1;
	}
	ring = keyring_bpf_serial();
	if (id.keyring_type != SIG_KEYRING_BPF ||
	    ring <= 0 || ring != id.keyring_serial) {
		pr_err("the kernel BPF keyring differs from the frozen anchor");
		rep_fail(rep, "pre_flight", "tampered", 0,
			 "BPF keyring is not the frozen anchor");
		return -1;
	}
	*keyring = KEY_SPEC_BPF_KEYRING;
	*serial = ring;
	return 0;
}

/*
 * The loader hands the programs and maps it created over to the caller,
 * whose pins keep them once attached; boot restore applies every archived
 * upatch in one process.
 */
static void close_loader_fds(const struct loader_ctx *cx,
			     __u32 nr_maps, __u32 nr_progs)
{
	const struct map_desc *md = (const void *)(cx + 1);
	const struct prog_desc *pd = (const void *)(md + nr_maps);
	__u32 i;

	for (i = 0; i < nr_maps; i++) {
		if (md[i].map_fd > 0)
			close(md[i].map_fd);
	}
	for (i = 0; i < nr_progs; i++) {
		if (pd[i].prog_fd > 0)
			close(pd[i].prog_fd);
	}
}

/*
 * From the copy the kernel's signature check covered, not from the file
 * again, which may hold other labels by now.
 */
static void apply_policy_labels(const struct upatch *u)
{
	struct upatch_policy_label_header header;
	struct upatch_policy_label_entry entry;
	const __u8 *labels;
	__u32 len, count;

	labels = upatch_signed_policy_labels(u, &len);
	if (!labels)
		return;
	memcpy(&header, labels, sizeof(header));
	count = le32_to_cpu(header.count);
	for (__u32 i = 0; i < count; i++) {
		__u64 current = 0;
		ssize_t n;
		int fd;

		memcpy(&entry, labels + sizeof(header) + i * sizeof(entry),
		       sizeof(entry));
		fd = open(entry.path, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			pr_warn("upatch: cannot label %s for policy %s: %s",
				entry.path, entry.policy, strerror(errno));
			continue;
		}
		n = fgetxattr(fd, XATTR_POLICY, &current, sizeof(current));
		if (n < 0 && (errno == ENODATA || errno == EOPNOTSUPP)) {
			current = 0;
		} else if (n != (ssize_t)sizeof(current)) {
			pr_warn("upatch: cannot read policy label on %s: %s",
				entry.path,
				n < 0 ? strerror(errno) : "invalid length");
			close(fd);
			continue;
		}
		current |= le64_to_cpu(entry.bit);
		if (fsetxattr(fd, XATTR_POLICY, &current, sizeof(current), 0))
			pr_warn("upatch: cannot set policy label on %s: %s",
				entry.path, strerror(errno));
		close(fd);
	}
}

/* Shared by `upatch load` and boot restore: one signature-verified path. */
static int __upatch_apply(const char *path, bool verify_only,
			  struct op_report *rep)
{
	struct upatch u;
	struct prog_spec *prog_specs = NULL;
	const struct bpf_insn *insns;
	const void *sig, *data;
	key_serial_t keyring, serial;
	char prog_name[BPF_OBJ_NAME_LEN];
	char upatch_name[UPATCH_NAME_MAX + 1];
	char *vlog;			/* shared PROG_LOAD / TEST_RUN log_buf */
	size_t insn_cnt, ctx_sz = 0, prog_desc_off;
	int prog_fd = -1, map_fd = -1, policy_map_fd = -1;
	int socket_policy_map_fd = -1, ret;
	struct loader_ctx *cx = NULL;
	__u32 retval = 0, shared_policy_map_idx = UPATCH_MAPS_MAX;
	__u32 shared_socket_policy_map_idx = UPATCH_MAPS_MAX;

	vlog = xmalloc(VERIFIER_LOG_MAX);
	if (!vlog) {
		rep_fail(rep, "parse", "unknown", ENOMEM, "out of memory");
		return 1;
	}
	vlog[0] = '\0';

	ret = upatch_open(path, &u);
	if (ret) {
		pr_err("open %s: %s", path, strerror(-ret));
		rep_fail(rep, "parse", "parser_rejected", -ret,
			 "cannot open .upatch");
		xfree(vlog, VERIFIER_LOG_MAX);
		return 1;
	}
	/*
	 * verify_only loads the signed loader purely to make the kernel
	 * verify its CMS signature (the unload-directive authorization
	 * gate) -- so it deliberately accepts an UNLOAD directive and
	 * stops before TEST_RUN/attach.
	 */
	if (!verify_only && upatch_is_unload(&u)) {
		pr_err("upatch load: %s is an UNLOAD directive; "
		       "use `shirudo upatch unload`", path);
		rep_fail(rep, "parse", "parser_rejected", 0,
			 "is an UNLOAD directive");
		ret = 1;
		goto out;
	}
	if (u.hdr.loader_insns_len % sizeof(struct bpf_insn)) {
		pr_err("upatch load: loader_insns_len=%u not a multiple of %zu",
		       u.hdr.loader_insns_len, sizeof(struct bpf_insn));
		rep_fail(rep, "parse", "parser_rejected", 0,
			 "loader_insns_len misaligned");
		ret = 1;
		goto out;
	}

	if (trust_anchor_keyring(&keyring, &serial, rep)) {
		ret = 1;
		goto out;
	}

	insns = upatch_loader(&u);
	sig   = upatch_signature(&u);
	data  = upatch_data(&u);
	insn_cnt = u.hdr.loader_insns_len / sizeof(struct bpf_insn);

	/* bpf_obj_name_cpy() takes alphanumerics, '_' and '.' alone. */
	memset(prog_name, 0, sizeof(prog_name));
	{
		size_t i, n = strnlen(u.hdr.name, sizeof(u.hdr.name));

		if (n > sizeof(prog_name) - 1)
			n = sizeof(prog_name) - 1;
		for (i = 0; i < n; i++) {
			char c = u.hdr.name[i];
			int ok = (c >= 'a' && c <= 'z') ||
				 (c >= 'A' && c <= 'Z') ||
				 (c >= '0' && c <= '9') ||
				 c == '_' || c == '.';
			prog_name[i] = ok ? c : '_';
		}
	}

	/*
	 * The pin directory, the archive and unload share the raw name. Boot
	 * restore reaches here without the command-level check, so validate it
	 * again.
	 */
	memcpy(upatch_name, u.hdr.name, UPATCH_NAME_MAX);
	upatch_name[UPATCH_NAME_MAX] = '\0';
	if (!safe_upatch_name(upatch_name)) {
		pr_err("upatch: refusing unsafe upatch name '%s'", upatch_name);
		rep_fail(rep, "parse", "parser_rejected", 0,
			 "unsafe upatch name");
		ret = 1;
		goto out;
	}
	/* The header's copy of the name is what everything else reads. */
	if (!upatch_signed_name(&u) ||
	    memcmp(upatch_signed_name(&u), u.hdr.name,
		   UPATCH_NAME_MAX)) {
		pr_err("upatch: the name of '%s' is not signature-covered or "
		       "differs from the signed one; rebuild the artifact",
		       upatch_name);
		rep_fail(rep, "parse", "parser_rejected", 0,
			 "name not signed");
		ret = 1;
		goto out;
	}

	/*
	 * The signature authorises the load, but payload_sha256 is what the pin
	 * xattr, the register event and the unload match record, so a header
	 * value that is not SHA-256(insns || data) is refused even when signed.
	 */
	{
		__u8 content_digest[UPATCH_PAYLOAD_HASH_LEN];

		sha256_2(insns, u.hdr.loader_insns_len,
			 data, u.hdr.data_len, content_digest);
		if (memneq_explicit(content_digest, u.hdr.payload_sha256,
				    sizeof(content_digest))) {
			pr_err("upatch: payload_sha256 does not match signed "
			       "content (insns || data); refusing");
			rep_fail(rep, "parse", "parser_rejected", 0,
				 "payload_sha256 mismatch");
			ret = 1;
			goto out;
		}
	}

	/*
	 * The attach metadata is signed with the data, which the kernel has
	 * not verified yet at this point: parsing it strictly here keeps a
	 * malformed artifact from the keyring, the load that follows keeps
	 * a forged one from the sites it names. Every uprobe target is bound
	 * to its recorded GNU build ID before any BPF program loads, and the
	 * open target fds stay live through link creation to prevent
	 * pathname replacement races.
	 */
	if (!verify_only) {
		const void *attach;
		__u32 attach_len;

		attach = upatch_signed_attach(&u, &attach_len);
		if (!attach) {
			pr_err("upatch: the attach metadata of '%s' is not "
			       "signature-covered; rebuild the artifact",
			       upatch_name);
			rep_fail(rep, "parse", "parser_rejected", 0,
				 "attach metadata not signed");
			ret = 1;
			goto out;
		}
		ret = prog_specs_parse(attach, attach_len, u.hdr.nr_maps,
				       u.hdr.nr_progs, &prog_specs);
		if (ret) {
			pr_err("upatch program metadata rejected: %s",
			       strerror(-ret));
			rep_fail(rep, "parse", "parser_rejected", -ret,
				 "invalid program attach metadata");
			ret = 1;
			goto out;
		}
		ret = prepare_uprobe_targets(prog_specs, u.hdr.nr_progs);
		if (ret) {
			int e = -ret;
			const char *cat;

			if (e == ENOENT || e == ENOTDIR)
				cat = "attach_target_missing";
			else if (e == ESTALE)
				cat = "binary_mismatch";
			else if (e == EACCES || e == EPERM)
				cat = "lsm_denied";
			else if (e == ERANGE || e == EINVAL || e == E2BIG)
				cat = "parser_rejected";
			else
				cat = "unknown";
			pr_err("uprobe target verification failed (%s): %s",
			       cat, strerror(e));
			rep_fail(rep, "target_verify", cat, e,
				 "uprobe target verification failed");
			ret = 1;
			goto out;
		}
		ret = prepare_bpf_prog_targets(prog_specs, u.hdr.nr_progs);
		if (ret) {
			int e = -ret;
			const char *cat;

			if (e == ENOENT || e == ENOTDIR)
				cat = "attach_target_missing";
			else if (e == EBADMSG)
				cat = "payload_mismatch";
			else if (e == EACCES || e == EPERM)
				cat = "lsm_denied";
			else
				cat = "unknown";
			pr_err("BPF program target verification failed (%s): %s",
			       cat, strerror(e));
			rep_fail(rep, "target_verify", cat, e,
				 "BPF program target verification failed");
			ret = 1;
			goto out;
		}
	}

	/*
	 * The metadata map is exclusive to the loader by the digest of its
	 * instructions alone, which the verifier enforces; payload_sha256
	 * covers insns || data.
	 */
	{
		__u8 loader_digest[UPATCH_PAYLOAD_HASH_LEN];

		if (sha256_calc(insns, u.hdr.loader_insns_len,
				loader_digest)) {
			pr_err("__loader.map: cannot hash the loader");
			rep_fail(rep, "signed_loader_load", "unknown", EIO,
				 "loader digest failed");
			ret = 1;
			goto out;
		}
		map_fd = loader_map_create("__loader.map", u.hdr.data_len,
					   loader_digest, sizeof(loader_digest));
	}
	if (map_fd < 0) {
		int err = errno;

		pr_err("__loader.map create: %s", strerror(err));
		rep_fail(rep, "signed_loader_load", cat_from_load_errno(err),
			 err, "__loader.map create failed");
		ret = 1;
		goto out;
	}

	ret = loader_map_update(map_fd, data, u.hdr.data_len);
	if (ret) {
		int err = errno;

		pr_err("__loader.map update: %s", strerror(err));
		rep_fail(rep, "signed_loader_load", cat_from_load_errno(err),
			 err, "__loader.map update failed");
		ret = 1;
		goto out;
	}

	/* The kernel refuses a signed load whose bound map is not frozen. */
	ret = loader_map_freeze(map_fd);
	if (ret) {
		int err = errno;

		pr_err("__loader.map freeze: %s", strerror(err));
		rep_fail(rep, "signed_loader_load", cat_from_load_errno(err),
			 err, "__loader.map freeze failed");
		ret = 1;
		goto out;
	}

	/*
	 * The kernel attests the metadata itself; the loader carries no
	 * self-check.
	 */
	vlog[0] = '\0';
	prog_fd = prog_load_signed(insns, insn_cnt, prog_name,
				   sig, u.hdr.signature_len,
				   (__s32)keyring, map_fd,
				   vlog, VERIFIER_LOG_MAX);
	if (prog_fd < 0) {
		int e = errno;

		pr_err("BPF_PROG_LOAD (signed loader): %s", strerror(e));
		if (vlog[0])
			fprintf(stderr, "loader verifier log:\n%s\n", vlog);
		rep_fail(rep, "signed_loader_load", cat_from_load_errno(e), e,
			 "BPF_PROG_LOAD of signed loader failed");
		report_set_log(rep, vlog);
		ret = 1;
		goto out;
	}

	pr_info("loaded signed loader: prog_fd=%d keyring=%d "
		"sig=%uB insns=%zu data=%uB",
		prog_fd, (int)serial, u.hdr.signature_len, insn_cnt,
		u.hdr.data_len);

	if (verify_only) {
		ret = 0;
		goto out;
	}

	/*
	 * The loader creates the programs and maps from kernel context but
	 * cannot attach or pin: gen_loader emits no link-create and
	 * bpf_sys_bpf() cannot BPF_OBJ_PIN. Its descriptors trail the context,
	 * sized from the header's counts.
	 */
	prog_desc_off = size_add(sizeof(struct loader_ctx),
				 size_mul(u.hdr.nr_maps,
					  sizeof(struct map_desc)));
	/*
	 * The loader's max_ctx_offset can exceed the descriptor tail, and
	 * TEST_RUN rejects a smaller ctx_size_in, so pad generously.
	 */
	ctx_sz = size_add(size_add(prog_desc_off,
				   size_mul(u.hdr.nr_progs,
					    sizeof(struct prog_desc))),
			  1024);
	/* TEST_RUN takes no larger a context for a syscall program. */
	if (ctx_sz > UINT16_MAX) {
		pr_err("upatch: %u maps and %u programs do not fit the loader context",
		       u.hdr.nr_maps, u.hdr.nr_progs);
		rep_fail(rep, "payload_load", "unknown", E2BIG,
			 "loader context too large");
		ctx_sz = 0;
		ret = 1;
		goto out;
	}
	cx = xmalloc(ctx_sz);
	if (!cx) {
		pr_err("ctx alloc");
		rep_fail(rep, "payload_load", "unknown", ENOMEM,
			 "ctx alloc failed");
		ret = 1;
		goto out;
	}
	vlog[0] = '\0';
	cx->sz = (__u32)ctx_sz;
	/*
	 * Keep inner verifier diagnostics enabled without bpftool's full
	 * accepted-program trace; the verbose mode can make valid payload
	 * loads fail with -ENOSPC when the log buffer fills.
	 */
	cx->log_level = 1;
	cx->log_size = VERIFIER_LOG_MAX;
	cx->log_buf = ptr_to_u64(vlog);
	if (u.signed_policy_labels) {
		struct map_desc *md;

		shared_policy_map_idx = u.signed_policy_map_idx;
		shared_socket_policy_map_idx =
			u.signed_socket_policy_map_idx;
		policy_map_fd =
			open_shared_policy_map(POLICY_PIN,
					       BPF_MAP_TYPE_TASK_STORAGE,
					       2 * sizeof(__u64),
					       BPF_F_NO_PREALLOC);
		if (policy_map_fd < 0) {
			pr_err("upatch load: open shirudo_task_policy: %s",
			       strerror(-policy_map_fd));
			rep_fail(rep, "payload_load", "unknown", -policy_map_fd,
				 "shirudo_task_policy binding failed");
			ret = 1;
			goto out;
		}
		socket_policy_map_fd =
			open_shared_policy_map(SOCKET_POLICY_PIN,
					       BPF_MAP_TYPE_SK_STORAGE, sizeof(__u64),
					       BPF_F_NO_PREALLOC | BPF_F_CLONE);
		if (socket_policy_map_fd < 0) {
			int err = -socket_policy_map_fd;

			pr_err("upatch load: open shirudo_sock_policy: %s",
			       strerror(err));
			rep_fail(rep, "payload_load", "unknown", err,
				 "shirudo_sock_policy binding failed");
			close(policy_map_fd);
			policy_map_fd = -1;
			ret = 1;
			goto out;
		}
		md = (struct map_desc *)((__u8 *)cx + sizeof(*cx)) +
			shared_policy_map_idx;
		md->map_fd = policy_map_fd;
		md = (struct map_desc *)((__u8 *)cx + sizeof(*cx)) +
			shared_socket_policy_map_idx;
		md->map_fd = socket_policy_map_fd;
	}

	ret = prog_test_run(prog_fd, cx, (__u32)ctx_sz, &retval);
	if (ret) {
		int err = errno;

		pr_err("BPF_PROG_TEST_RUN: %s", strerror(err));
		if (vlog[0])
			fprintf(stderr, "loader runtime log:\n%s\n", vlog);
		rep_fail(rep, "payload_load", "verifier_rejected", err,
			 "BPF_PROG_TEST_RUN failed");
		report_set_log(rep, vlog);
		ret = 1;
		goto out;
	}
	if ((__s32)retval < 0) {
		if (policy_map_fd >= 0) {
			close(policy_map_fd);
			policy_map_fd = -1;
		}
		if (socket_policy_map_fd >= 0) {
			close(socket_policy_map_fd);
			socket_policy_map_fd = -1;
		}
		/*
		 * The loader closed what it made before it failed; the
		 * numbers left in the context name nothing of ours now.
		 */
		memset(cx + 1, 0, ctx_sz - sizeof(*cx));
		pr_err("loader returned error: %d", (__s32)retval);
		fprintf(stderr, "loader runtime log (len=%zu):\n%.4096s\n",
			strnlen(vlog, VERIFIER_LOG_MAX), vlog);
		rep_fail(rep, "payload_load", "verifier_rejected",
			 -(__s32)retval, "inner loader returned error");
		if (rep)
			rep->loader_return = (__s32)retval;
		report_set_log(rep, vlog);
		ret = 1;
		goto out;
	}

	pr_info("loader ok, retval=%d (maps=%u progs=%u)", (__s32)retval,
		u.hdr.nr_maps, u.hdr.nr_progs);

	/*
	 * Without a pinned link a program detaches when this one-shot CLI
	 * exits.
	 */
	ret = attach_and_pin_progs(cx, prog_desc_off, u.hdr.nr_progs,
				   upatch_name, prog_specs);
	if (ret) {
		int e = -ret;
		const char *cat;

		if (e == ENOENT || e == ENOTDIR)
			cat = "attach_target_missing";
		else if (e == ESTALE)
			cat = "binary_mismatch";
		else if (e == EXDEV)
			cat = "attach_scope_mismatch";
		else if (e == EOPNOTSUPP)
			cat = "kernel_abi_unsupported";
		else if (e == EACCES || e == EPERM)
			cat = "lsm_denied";
		else
			cat = "unknown";

		rep_fail(rep, "link_create", cat, e, "attach or pin failed");
		ret = 1;
		goto out;
	}

	pin_upatch_maps(cx, u.hdr.nr_maps, shared_policy_map_idx,
			shared_socket_policy_map_idx, upatch_name);

	/* After attach and pin, so the value records a loaded upatch. */
	set_pin_payload(upatch_name, u.hdr.payload_sha256);
	apply_policy_labels(&u);

	pr_audit("upatch load: name=%s keyring=%d progs=%u", upatch_name,
		 (int)serial, u.hdr.nr_progs);
	if (rep)
		rep->loader_return = (__s32)retval;
	ret = 0;
out:
	prog_specs_free(prog_specs, u.hdr.nr_progs);
	xfree(vlog, VERIFIER_LOG_MAX);
	if (cx)
		close_loader_fds(cx, u.hdr.nr_maps, u.hdr.nr_progs);
	xfree(cx, ctx_sz);
	if (prog_fd >= 0)
		close(prog_fd);
	if (map_fd >= 0)
		close(map_fd);
	upatch_close(&u);
	return ret;
}

int upatch_apply(const char *path)
{
	return __upatch_apply(path, false, NULL);
}

/*
 * The tamper gate before any BPF_PROG_LOAD: a concurrent operator who
 * advanced the register, a detached LSM or a missing anchor surface
 * here, without touching kernel state.
 */
static int upatch_preflight(const char *expect_chain,
			    struct op_report *rep)
{
	__u8 want[CHAIN_DIGEST_LEN], have[CHAIN_DIGEST_LEN];
	char have_hex[2 * CHAIN_DIGEST_LEN + 1];
	char abi_detail[KERNEL_ABI_DETAIL_MAX];
	key_serial_t keyring, serial;
	int fd, ret;

	ret = kernel_abi_check(abi_detail, sizeof(abi_detail));
	if (ret) {
		pr_err("upatch: pre-flight refused (category: "
		       "kernel_abi_unsupported, message: %s)", abi_detail);
		rep_fail(rep, "pre_flight", "kernel_abi_unsupported",
			 EOPNOTSUPP, abi_detail);
		return ret;
	}

	if (trust_anchor_keyring(&keyring, &serial, rep))
		return -1;

	fd = bpf_obj_get(LSM_LINK_PIN);
	if (fd < 0) {
		pr_err("upatch load: pre-flight refused (category: tampered, "
		       "message: lsm_detached) -- %s not pinned",
		       LSM_LINK_PIN);
		return -1;
	}
	close(fd);

	if (!expect_chain)
		return 0;

	if (hex_decode(expect_chain, want, sizeof(want))) {
		pr_err("upatch load: --expect-chain must be %d hex chars",
		       2 * CHAIN_DIGEST_LEN);
		return -1;
	}
	ret = chain_read(have);
	if (ret == -ENODEV) {
		pr_err("upatch load: pre-flight refused (category: tampered, "
		       "message: chain_drift) -- register unreadable, cannot "
		       "confirm --expect-chain");
		return -1;
	}
	if (ret) {
		pr_err("upatch load: chain read failed: %s", strerror(-ret));
		return -1;
	}
	if (memneq_explicit(want, have, sizeof(want))) {
		hex_encode(have, sizeof(have), have_hex);
		pr_err("upatch load: pre-flight refused (category: tampered, "
		       "message: chain_drift) -- live chain %s != expected; "
		       "re-status and re-issue with the refreshed value",
		       have_hex);
		return -1;
	}
	return 0;
}

/*
 * The register and the log advance together, so an extend that could
 * not be logged must not happen: refuse before any state changes.
 */
static int eventlog_room(struct op_report *rep, const char *op)
{
	struct config cfg __cleanup(config_clear);

	config_load(&cfg);
	if (eventlog_would_exceed(cfg.eventlog_max_bytes)) {
		pr_err("upatch %s: eventlog %s would exceed "
		       "eventlog.max_bytes=%llu; refusing -- no load, no extend",
		       op, eventlog_path(), cfg.eventlog_max_bytes);
		rep_fail(rep, "pre_flight", "eventlog_full", ENOSPC,
			 "eventlog would exceed eventlog.max_bytes");
		return -1;
	}
	return 0;
}

/*
 * A caller built from other sources than this target makes every later
 * comparison meaningless, so the version check runs first.
 */
static int version_gate(const char *expect_version_id, bool no_version_check,
			struct op_report *rep, const char *op)
{
	if (no_version_check || !expect_version_id)
		return 0;
	if (strcmp(expect_version_id, shirudo_version_id) != 0) {
		pr_err("upatch %s: version mismatch -- operator expects %s, "
		       "target is %s; redeploy a matching shirudo or pass "
		       "--no-version-check", op, expect_version_id,
		       shirudo_version_id);
		rep_fail(rep, "pre_flight", "version_mismatch", EPERM,
			 "SHIRUDO_VERSION_ID mismatch (operator vs target)");
		return -1;
	}
	return 0;
}

/* Eventlog entry ("upatch_load" / "upatch_unload") mirroring an extend. */
static int format_upatch_event(const char *type, const char *name,
			       const __u8 payload[32],
			       const __u8 event[32], const char *reason,
			       char *buf, size_t size)
{
	struct json_emit e = { .buf = buf, .cap = size };
	char payload_hex[65];

	hex_encode(payload, 32, payload_hex);
	eventlog_record_open(&e, type, event);
	json_obj_open_key(&e, "upatch");
	json_kv_string(&e, "name", name);
	json_kv_string(&e, "payload_sha256", payload_hex);
	json_obj_close(&e);
	if (reason)
		json_kv_string(&e, "reason", reason);
	json_obj_close(&e);

	if (e.err) {
		pr_err("eventlog: %s entry encode failed: %s", type,
		       strerror(-e.err));
		return e.err;
	}
	return 0;
}

static int append_upatch_event(const char *type, const char *name,
			       const __u8 payload[32],
			       const __u8 event[32], const char *reason)
{
	char buf[4096];
	int ret;

	ret = format_upatch_event(type, name, payload, event, reason,
				  buf, sizeof(buf));
	return ret ? ret : eventlog_append(buf);
}

/*
 * Each operator operation is its own register event, where boot restore
 * coalesces into one. A missing TPM or register is an error, never an
 * unmeasured success: init guarantees the register exists. *measured
 * tells a failure after the register moved from one before it.
 */
static int upatch_chain_event_locked(const char *tag, const char *type,
				     const char *op, const char *name,
				     const __u8 payload[32],
				     const char *reason, char out_chain[65],
				     bool *measured)
{
	__u8 event[32], chain[32];
	char chain_hex[65];
	int ret;

	if (out_chain)
		out_chain[0] = '\0';
	if (measured)
		*measured = false;
	ret = chain_upatch_event(tag, name, payload, event);
	if (ret) {
		pr_err("upatch %s: cannot hash the event (category: tpm_error)",
		       op);
		return ret;
	}

	ret = chain_extend(event, chain);
	if (ret == -ENODEV) {
		pr_err("upatch %s: TPM/register unavailable (category: "
		       "tpm_error) -- op done but NOT measured; shirudo "
		       "requires the register init bound this boot", op);
		return ret;
	}
	if (ret == -EACCES) {
		pr_err("upatch %s: register is not the one init bound "
		       "(category: tampered) -- op done but NOT measured; "
		       "operator must reconcile", op);
		return ret;
	}
	if (ret) {
		pr_err("upatch %s: chain extend failed (category: tpm_error) "
		       "-- op done but chain NOT advanced; operator must "
		       "reconcile", op);
		return ret;
	}
	if (measured)
		*measured = true;
	ret = append_upatch_event(type, name, payload, event, reason);
	if (ret) {
		pr_err("upatch %s: eventlog append failed after extend -- "
		       "chain/log desync; operator must reconcile", op);
		return ret;
	}
	hex_encode(chain, 32, chain_hex);
	if (out_chain)
		memcpy(out_chain, chain_hex, sizeof(chain_hex));
	pr_info("upatch %s: chain extended, value=%s", op, chain_hex);
	pr_audit("upatch %s measured: name=%s chain=%s", op, name, chain_hex);
	return 0;
}

/* A register other than the one init set up is a verdict, not a TPM fault. */
static const char *chain_event_category(int ret, bool measured)
{
	return !measured && ret == -EACCES ? "tampered" : "tpm_error";
}

static int upatch_chain_event(const char *tag, const char *type,
			      const char *op, const char *name,
			      const __u8 payload[32], const char *reason,
			      char out_chain[65], bool *measured)
{
	int lock, ret;

	if (out_chain)
		out_chain[0] = '\0';
	if (measured)
		*measured = false;
	lock = eventlog_lock();
	if (lock < 0) {
		pr_err("upatch %s: cannot take the register lock: %s "
		       "(category: tpm_error) -- nothing measured", op,
		       strerror(-lock));
		return lock;
	}
	ret = upatch_chain_event_locked(tag, type, op, name, payload, reason,
					out_chain, measured);
	eventlog_unlock(lock);
	return ret;
}

/*
 * The name is not covered by the signature and becomes a path, so only
 * one safe component is allowed.
 */
static bool safe_upatch_name(const char *name)
{
	size_t i;

	if (name[0] == '\0' || name[0] == '.')
		return false;
	for (i = 0; name[i]; i++) {
		char c = name[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '.' || c == '_' ||
		      c == '-'))
			return false;
	}
	return true;
}

static int append_json_record(const char *path, const char *json, size_t len)
{
	struct stat st;
	char last;
	off_t original_size;
	int fd, ret = 0;

	if (!path || !path[0] || !json)
		return -EINVAL;
	fd = seal_output_open(path, O_RDWR | O_CREAT | O_APPEND, 0644);
	if (fd < 0)
		return fd;
	while (flock(fd, LOCK_EX) != 0) {
		if (errno != EINTR) {
			ret = -errno;
			goto out;
		}
	}
	if (fstat(fd, &st) != 0) {
		ret = -errno;
		goto out_unlock;
	}
	if (!S_ISREG(st.st_mode)) {
		ret = -EINVAL;
		goto out_unlock;
	}
	original_size = st.st_size;
	if (original_size > 0) {
		ssize_t n = pread(fd, &last, 1, original_size - 1);

		if (n != 1) {
			ret = n < 0 ? -errno : -EIO;
			goto out_unlock;
		}
		if (last != '\n')
			ret = write_complete(fd, "\n", 1);
	}
	if (!ret)
		ret = write_complete(fd, json, len);
	if (!ret)
		ret = write_complete(fd, "\n", 1);
	if (!ret && fsync(fd) != 0)
		ret = -errno;
	if (ret && ftruncate(fd, original_size) != 0)
		pr_warn("upatch map: could not roll back partial JSON append to %s: %s",
			path, strerror(errno));
out_unlock:
	flock(fd, LOCK_UN);
out:
	if (close(fd) != 0 && !ret)
		ret = -errno;
	return ret;
}

static int print_json_record(const char *json, size_t len)
{
	int ret;

	ret = write_complete(STDOUT_FILENO, json, len);
	if (!ret)
		ret = write_complete(STDOUT_FILENO, "\n", 1);
	return ret;
}

static int emit_json_record(const char *path, const char *json, size_t len)
{
	return path ? append_json_record(path, json, len) :
		print_json_record(json, len);
}

static int copy_file_atomic(const char *src, const char *dst)
{
	char tmp[PATH_MAX + 8], buf[65536];
	int in, out, dir, ret = 0;
	ssize_t r;

	if (strsprintf(tmp, sizeof(tmp), "%s.new", dst) < 0)
		return -ENAMETOOLONG;
	in = open(src, O_RDONLY | O_CLOEXEC);
	if (in < 0)
		return -errno;
	out = seal_open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW,
			0644);
	if (out < 0) {
		close(in);
		return out;
	}
	while ((r = read(in, buf, sizeof(buf))) > 0) {
		ret = write_complete(out, buf, (size_t)r);
		if (ret)
			break;
	}
	if (r < 0 && !ret)
		ret = -errno;
	if (!ret && fsync(out) != 0)
		ret = -errno;
	close(in);
	if (close(out) != 0 && !ret)
		ret = -errno;
	if (ret) {
		unlink(tmp);
		return ret;
	}
	if (rename(tmp, dst) != 0) {
		ret = -errno;
		unlink(tmp);
		return ret;
	}
	/* Persist the rename so a crash can't lose a "loaded" upatch. */
	dir = open(UPATCHES_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dir >= 0) {
		fsync(dir);
		close(dir);
	}
	return 0;
}

static int persist_upatch(const char *src, const char *name)
{
	char dst[PATH_MAX];
	struct stat ss, ds;
	int ret;

	ret = seal_mkdir_p(UPATCHES_DIR, 0700);
	if (ret) {
		pr_err("mkdir %s: %s", UPATCHES_DIR, strerror(-ret));
		return ret;
	}
	if (strsprintf(dst, sizeof(dst), "%s/%s.upatch", UPATCHES_DIR,
		       name) < 0)
		return -ENAMETOOLONG;

	if (stat(src, &ss) == 0 && stat(dst, &ds) == 0 &&
	    ss.st_ino == ds.st_ino && ss.st_dev == ds.st_dev)
		return 0;	/* already the installed copy */

	return copy_file_atomic(src, dst);
}

static int parse_op_args(int argc, const char **argv, const char *verb,
			 const struct help *help,
			 const char **file, const char **expect_chain,
			 const char **expect_version_id, bool *no_precheck,
			 bool *no_version_check, const char **report)
{
	int i;

	*file = NULL;
	*expect_chain = NULL;
	*expect_version_id = NULL;
	*no_precheck = false;
	*no_version_check = false;
	*report = NULL;
	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (strncmp(a, "--expect-chain=", 15) == 0) {
			*expect_chain = a + 15;
		} else if (strncmp(a, "--expect-version-id=", 20) == 0) {
			*expect_version_id = a + 20;
		} else if (strcmp(a, "--no-version-check") == 0) {
			*no_version_check = true;
		} else if (strncmp(a, "--report=", 9) == 0) {
			*report = a + 9;
		} else if (strcmp(a, "--no-precheck") == 0) {
			*no_precheck = true;
		} else if (a[0] == '-') {
			fprintf(stderr, "upatch %s: unknown option '%s'\n",
				verb, a);
			return 2;
		} else if (!*file) {
			*file = a;
		} else {
			fprintf(stderr, "upatch %s: unexpected argument '%s'\n",
				verb, a);
			return 2;
		}
	}
	if (!*file) {
		print_help(help);
		return 2;
	}
	if (*expect_chain) {
		__u8 want[CHAIN_DIGEST_LEN];

		if (hex_decode(*expect_chain, want, sizeof(want))) {
			fprintf(stderr, "upatch %s: --expect-chain must be %d hexadecimal characters\n",
				verb, 2 * CHAIN_DIGEST_LEN);
			return 2;
		}
	}
	return 0;
}

static int wipe_dir_flat(const char *dir)
{
	struct dirent *e;
	int dfd, ret = 0;
	DIR *d;

	d = opendir(dir);
	if (!d)
		return -errno;
	dfd = dirfd(d);
	while ((e = readdir(d))) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		if (unlinkat(dfd, e->d_name, 0) != 0 && errno != ENOENT) {
			ret = -errno;
			break;
		}
	}
	closedir(d);
	if (ret)
		return ret;
	if (rmdir(dir) != 0 && errno != ENOENT)
		return -errno;
	return 0;
}

/* Whether the upatch has its pin directory, loaded or part way there. */
static bool upatch_is_pinned(const char *name)
{
	char dir[PATH_MAX];
	char bpffs_name[UPATCH_BPFFS_NAME_MAX + 1];
	struct stat st;

	if (upatch_bpffs_name(bpffs_name, sizeof(bpffs_name), name))
		return false;
	if (strsprintf(dir, sizeof(dir), "%s/%s", BPFFS_UPATCHES_DIR,
		       bpffs_name) < 0)
		return false;
	return stat(dir, &st) == 0;
}

/* Unlinking the link pin drops its last reference, which detaches. */
static int remove_pin_dir(const char *name)
{
	char dir[PATH_MAX], maps_dir[PATH_MAX + 8];
	char serializers_dir[PATH_MAX + 16];
	char bpffs_name[UPATCH_BPFFS_NAME_MAX + 1];
	char progs_dir[PATH_MAX + 8];
	struct stat st;
	int ret;

	if (upatch_bpffs_name(bpffs_name, sizeof(bpffs_name), name))
		return -ENAMETOOLONG;
	if (strsprintf(dir, sizeof(dir), "%s/%s", BPFFS_UPATCHES_DIR,
		       bpffs_name) < 0)
		return -ENAMETOOLONG;
	if (strsprintf(maps_dir, sizeof(maps_dir), "%s/maps", dir) < 0)
		return -ENAMETOOLONG;
	if (strsprintf(serializers_dir, sizeof(serializers_dir),
		       "%s/serializers", dir) < 0)
		return -ENAMETOOLONG;
	if (strsprintf(progs_dir, sizeof(progs_dir), "%s/progs", dir) < 0)
		return -ENAMETOOLONG;
	if (stat(dir, &st) != 0)
		return -errno;
	if (stat(maps_dir, &st) == 0) {
		ret = wipe_dir_flat(maps_dir);
		if (ret)
			return ret;
	}
	if (stat(serializers_dir, &st) == 0) {
		ret = wipe_dir_flat(serializers_dir);
		if (ret)
			return ret;
	}
	if (stat(progs_dir, &st) == 0) {
		ret = wipe_dir_flat(progs_dir);
		if (ret)
			return ret;
	}
	return wipe_dir_flat(dir);
}

/*
 * The operator's file is read once: the name and payload measured, the
 * program loaded and the copy archived all come from that one read, in
 * a directory only shirudo writes, so another artifact renamed over the
 * path midway cannot set them apart.
 */
static int stage_upatch(const char *src, char *staged, size_t sz)
{
	__u8 *buf = NULL;
	size_t len = 0;
	int ret;

	ret = read_file(src, UPATCH_FILE_MAX, &buf, &len);
	if (ret)
		return ret;
	ret = seal_mkdir_p(INCOMING_DIR, 0700);
	if (!ret && strsprintf(staged, sz, "%s/load-%d.upatch",
			       INCOMING_DIR, (int)getpid()) < 0)
		ret = -ENAMETOOLONG;
	if (!ret)
		ret = seal_write_file(staged, buf, len, 0600);
	xfree(buf, len + 1);
	if (ret)
		staged[0] = '\0';
	return ret;
}

/* Take a load the register did not record back out: pins, then archive. */
static void unload_unmeasured(const char *name)
{
	char persisted[PATH_MAX];
	int ret;

	ret = remove_pin_dir(name);
	if (!ret && strsprintf(persisted, sizeof(persisted), "%s/%s.upatch",
			       UPATCHES_DIR, name) >= 0 &&
	    unlink(persisted) != 0 && errno != ENOENT)
		ret = -errno;
	if (ret)
		pr_err("upatch load: %s is loaded but not measured and could "
		       "not be undone: %s; operator must reconcile", name,
		       strerror(-ret));
	else
		pr_err("upatch load: %s was not measured; the load was undone",
		       name);
}

static int cmd_upatch_load(int argc, const char **argv)
{
	const char *file, *expect_chain, *expect_version_id, *report;
	char name[UPATCH_NAME_MAX + 1] = {};
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN], live[UPATCH_PAYLOAD_HASH_LEN];
	char staged[PATH_MAX] = {};
	struct upatch u;
	struct op_report rep = { .op = "upatch_load", .phase = "done" };
	bool no_precheck, no_version_check, have_id = false, measured;
	int err, ret = 1;

	for (int i = 1; i < argc; i++) {
		if (is_help(argv[i])) {
			print_help(&upatch_load_help);
			return 0;
		}
	}
	err = parse_op_args(argc, argv, "load", &upatch_load_help,
			    &file, &expect_chain, &expect_version_id,
			    &no_precheck, &no_version_check, &report);
	if (err)
		return err;
	rep.path = file;

	if (version_gate(expect_version_id, no_version_check, &rep, "load") != 0)
		goto done;

	err = stage_upatch(file, staged, sizeof(staged));
	if (err) {
		pr_err("upatch load: read %s: %s", file, strerror(-err));
		rep_fail(&rep, "parse", "parser_rejected", -err,
			 "cannot read .upatch");
		goto done;
	}
	file = staged;

	err = upatch_open(file, &u);
	if (err) {
		pr_err("open %s: %s", file, strerror(-err));
		rep_fail(&rep, "parse", "parser_rejected", -err,
			 "cannot open .upatch");
		goto done;
	}
	memcpy(name, u.hdr.name, UPATCH_NAME_MAX);
	name[UPATCH_NAME_MAX] = '\0';
	memcpy(payload, u.hdr.payload_sha256, sizeof(payload));
	hex_encode(payload, sizeof(payload), rep.payload_hex);
	rep.name = name;
	upatch_close(&u);
	have_id = true;

	if (no_precheck) {
		pr_warn("upatch load: --no-precheck, pre-flight state check "
			"skipped");
	} else if (upatch_preflight(expect_chain, &rep) != 0) {
		if (!rep.category)
			rep_fail(&rep, "pre_flight", "tampered", EPERM,
				 "pre-flight check failed");
		goto done;
	}

	if (eventlog_room(&rep, "load") != 0)
		goto done;
	if (have_id && !safe_upatch_name(name)) {
		pr_err("upatch load: refusing unsafe upatch name '%s'", name);
		rep_fail(&rep, "parse", "parser_rejected", 0,
			 "unsafe upatch name");
		goto done;
	}
	/*
	 * Only a completed load records the payload and only an unload
	 * removes it. A load over a live upatch rebinds its serializer pins
	 * to maps nothing reads, and an undo of that load would take the
	 * live one's pins and archive with it.
	 */
	if (have_id && !get_pin_payload(name, live)) {
		pr_err("upatch load: %s is already loaded; unload it with its signed directive first",
		       name);
		rep_fail(&rep, "pin", "already_loaded", EEXIST,
			 "upatch already loaded");
		goto done;
	}

	if (__upatch_apply(file, false, &rep) != 0)
		goto done;
	if (!have_id) {		/* loaded but couldn't read identity */
		ret = 0;
		rep.ok = true;
		goto done;
	}

	/*
	 * Persist before measuring: the archive is the intent boot restore
	 * replays, and an event for an upatch that will not survive a reboot
	 * would drift from it. A load whose archive copy fails, a file system
	 * root filled say, or one the register then refuses to take is
	 * undone, pins and archive, so that no upatch runs unmeasured; a
	 * caller who stops this process first gets the same at the next
	 * init, which refuses to restore what the register does not cover.
	 */
	err = persist_upatch(file, name);
	if (err) {
		pr_err("upatch load: loaded but failed to persist to %s: %s "
		       "-- not measured", UPATCHES_DIR, strerror(-err));
		unload_unmeasured(name);
		rep_fail(&rep, "persist", "unknown", -err,
			 "persist failed; the load was undone");
		goto done;
	}

	err = upatch_chain_event("shirudo-upatch", "upatch_load", "load",
				 name, payload, NULL, rep.chain_after,
				 &measured);
	if (err) {
		if (!measured)
			unload_unmeasured(name);
		rep_fail(&rep, "tpm_extend", chain_event_category(err, measured),
			 err, measured ?
			 "eventlog append failed after the extend" :
			 "chain extend failed; the load was undone");
		goto done;
	}
	rep.ok = true;
	rep.phase = "done";
	rep.tpm_present = rep.chain_after[0] != '\0';
	ret = 0;
done:
	if (ret == 1 && rep.category &&
	    !strcmp(rep.category, "attach_target_missing"))
		ret = UPATCH_INSTALL_TARGET_MISSING;
	if (staged[0])
		unlink(staged);
	if (report)
		report_emit(report, &rep);
	report_free(&rep);
	return ret;
}

static int cmd_upatch_unload(int argc, const char **argv)
{
	const char *file, *expect_chain, *expect_version_id, *report;
	char name[UPATCH_NAME_MAX + 1] = {};
	char staged[PATH_MAX] = {};
	char persisted[PATH_MAX];
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN] = {};
	struct upatch u;
	struct op_report rep = { .op = "upatch_unload", .phase = "done" };
	bool no_precheck, no_version_check;
	int err, ret = 1;

	for (int i = 1; i < argc; i++) {
		if (is_help(argv[i])) {
			print_help(&upatch_unload_help);
			return 0;
		}
	}
	err = parse_op_args(argc, argv, "unload", &upatch_unload_help,
			    &file, &expect_chain, &expect_version_id,
			    &no_precheck, &no_version_check, &report);
	if (err)
		return err;
	rep.path = file;

	if (version_gate(expect_version_id, no_version_check, &rep, "unload") != 0)
		goto done;

	/*
	 * Read once, as a load is: the target and the payload the kernel's
	 * signature check covers must be the bytes read back after it, and
	 * a file of root's is root's to rewrite between the two.
	 */
	err = stage_upatch(file, staged, sizeof(staged));
	if (err) {
		pr_err("upatch unload: read %s: %s", file, strerror(-err));
		rep_fail(&rep, "parse", "parser_rejected", -err,
			 "cannot read .upatch");
		goto done;
	}
	file = staged;

	err = upatch_open(file, &u);
	if (err) {
		pr_err("open %s: %s", file, strerror(-err));
		rep_fail(&rep, "parse", "parser_rejected", -err,
			 "cannot open .upatch");
		goto done;
	}
	if (!upatch_is_unload(&u)) {
		pr_err("upatch unload: %s is a LOAD upatch; use "
		       "`shirudo upatch load`", file);
		rep_fail(&rep, "parse", "parser_rejected", 0,
			 "is a LOAD upatch");
		upatch_close(&u);
		goto done;
	}
	/*
	 * The target's name and the payload it is expected to carry are the
	 * directive's signed sections; the header's name must be the same,
	 * since status and the package tooling read it.
	 */
	if (!upatch_signed_name(&u) || !upatch_signed_unload_payload(&u) ||
	    memcmp(upatch_signed_name(&u), u.hdr.name,
		   UPATCH_NAME_MAX)) {
		pr_err("upatch unload: the target of %s is not "
		       "signature-covered or differs from the header; rebuild "
		       "the directive", rep.path);
		rep_fail(&rep, "parse", "parser_rejected", 0,
			 "directive target not signed");
		upatch_close(&u);
		goto done;
	}
	memcpy(name, u.hdr.name, UPATCH_NAME_MAX);
	name[UPATCH_NAME_MAX] = '\0';
	memcpy(payload, upatch_signed_unload_payload(&u), sizeof(payload));
	upatch_close(&u);
	rep.name = name;
	hex_encode(payload, sizeof(payload), rep.payload_hex);

	if (!safe_upatch_name(name)) {
		pr_err("upatch unload: refusing unsafe upatch name '%s'", name);
		rep_fail(&rep, "parse", "parser_rejected", 0,
			 "unsafe upatch name");
		goto done;
	}
	if (strsprintf(persisted, sizeof(persisted), "%s/%s.upatch",
		       UPATCHES_DIR, name) < 0)
		goto done;

	if (no_precheck) {
		pr_warn("upatch unload: --no-precheck, pre-flight state check "
			"skipped");
	} else if (upatch_preflight(expect_chain, &rep) != 0) {
		if (!rep.category)
			rep_fail(&rep, "pre_flight", "tampered", EPERM,
				 "pre-flight check failed");
		goto done;
	}

	if (eventlog_room(&rep, "unload") != 0)
		goto done;

	/* A bad signature fails here, before anything is removed. */
	if (__upatch_apply(file, true, &rep) != 0) {
		pr_err("upatch unload: signature verification failed; refusing");
		goto done;
	}

	/*
	 * The live value is the xattr bpf2 guards; the expected one is
	 * signed, so a directive detaches the upatch its signer made it
	 * for and nothing else. A pin whose value cannot be read is refused;
	 * no pin at all is the already-unloaded case below.
	 */
	{
		__u8 live[UPATCH_PAYLOAD_HASH_LEN];
		int xrc;

		xrc = get_pin_payload(name, live);
		if (xrc == 0) {
			if (memneq_explicit(live, payload, sizeof(payload))) {
				pr_err("upatch unload: payload_mismatch -- the "
				       "upatch loaded under '%s' is not what the "
				       "directive expects; refusing", name);
				rep_fail(&rep, "pin", "payload_mismatch", EPERM,
					 "loaded payload does not match directive");
				goto done;
			}
			pr_info("upatch unload: payload matches for '%s'", name);
		} else if (xrc != -ENOENT) {
			pr_err("upatch unload: cannot read the payload "
			       "recorded for '%s': %s; refusing", name,
			       strerror(-xrc));
			rep_fail(&rep, "pin", "payload_mismatch", -xrc,
				 "payload xattr unreadable");
			goto done;
		}
	}

	if (!upatch_is_pinned(name)) {
		if (unlink(persisted) != 0 && errno != ENOENT)
			pr_warn("upatch unload: could not remove %s: %s",
				persisted, strerror(errno));
		pr_info("upatch unload: %s already unloaded (no pin)", name);
		pr_audit("upatch unload: name=%s already_unloaded", name);
		rep.ok = true;
		rep.phase = "done";
		rep.category = "already_unloaded";
		strscpy(rep.message, "already unloaded", sizeof(rep.message));
		ret = 0;
		goto done;
	}

	/*
	 * Measured before it happens: a detach the register does not know
	 * is what a caller who stops this process, or the TPM's path, at
	 * the right moment would get. The other way round, a detach that
	 * fails after the event leaves a shield the register says is gone,
	 * which the next status reports and the operator can repeat.
	 */
	err = upatch_chain_event("shirudo-unload", "upatch_unload", "unload",
				 name, payload, NULL, rep.chain_after, NULL);
	if (err) {
		rep_fail(&rep, "tpm_extend", chain_event_category(err, false),
			 err, "chain extend failed; nothing detached");
		goto done;
	}

	err = remove_pin_dir(name);
	if (err) {
		pr_err("upatch unload: measured, but failed to remove the pin "
		       "for %s: %s; repeat the unload", name, strerror(-err));
		rep_fail(&rep, "pin", "detach_failed", -err,
			 "pin removal failed after the event was measured");
		goto done;
	}
	pr_info("upatch unload: detached + unpinned %s", name);

	if (unlink(persisted) != 0 && errno != ENOENT)
		pr_warn("upatch unload: could not remove %s: %s",
			persisted, strerror(errno));
	rep.ok = true;
	rep.phase = "done";
	rep.tpm_present = rep.chain_after[0] != '\0';
	ret = 0;
done:
	if (ret != 0)
		pr_err("upatch unload failed: name=%s phase=%s category=%s "
		       "err=%d (%s) message=%s",
		       name[0] ? name : "(unknown)",
		       rep.phase ? rep.phase : "(unknown)",
		       rep.category ? rep.category : "(unknown)",
		       rep.err,
		       rep.err ? strerror(rep.err) : "none",
		       rep.message[0] ? rep.message : "(none)");
	if (staged[0])
		unlink(staged);
	if (report)
		report_emit(report, &rep);
	report_free(&rep);
	return ret;
}

int upatch_purge(const char *name, const char *reason)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN] = {};
	char persisted[PATH_MAX];
	struct upatch u;
	bool loaded;
	int fd, ret;

	if (!safe_upatch_name(name))
		return -EINVAL;
	if (strsprintf(persisted, sizeof(persisted), "%s/%s.upatch",
		       UPATCHES_DIR, name) < 0)
		return -ENAMETOOLONG;
	ret = seal_open_read(persisted);
	if (ret < 0)
		return ret;
	fd = ret;
	ret = upatch_open_fd(fd, &u);
	close(fd);
	if (ret)
		return ret;
	memcpy(payload, u.hdr.payload_sha256, sizeof(payload));
	upatch_close(&u);

	/* As for unload: the event first, then the detach it describes. */
	loaded = upatch_is_pinned(name);
	if (loaded) {
		ret = upatch_chain_event("shirudo-unload", "upatch_unload",
					 "purge", name, payload, reason, NULL,
					 NULL);
		if (ret)
			return ret;
		ret = remove_pin_dir(name);
		if (ret) {
			pr_err("upatch purge: measured, but failed to remove "
			       "the pin for %s: %s", name, strerror(-ret));
			return ret;
		}
	}
	if (unlink(persisted) != 0 && errno != ENOENT) {
		pr_err("upatch purge: could not remove %s: %s", persisted,
		       strerror(errno));
		return -errno;
	}
	pr_audit("upatch purge: name=%s reason=%s %s", name, reason,
		 loaded ? "detached" : "archive_only");
	return loaded ? 1 : 0;
}

/* Package installs take the same path as the upatch commands. */
int upatch_install(const char *path)
{
	const char *argv[] = { "load", "--no-precheck", path };

	return cmd_upatch_load(3, argv);
}

int upatch_remove(const char *path)
{
	const char *argv[] = { "unload", "--no-precheck", path };

	return cmd_upatch_unload(3, argv);
}

/*
 * Source lines from a program's BTF line_info. rec_size is the record
 * stride, since the kernel may grow struct bpf_line_info.
 */
struct li_entry {
	const char	*file;	/* into the BTF string section */
	const char	*src;
	__u32		line;
};

static int li_cmp(const void *a, const void *b)
{
	const struct li_entry *x = a, *y = b;
	int c = strcmp(x->file, y->file);

	if (c)
		return c;
	return (x->line > y->line) - (x->line < y->line);
}

/*
 * line_info is in instruction order, so a source line recurs and lines
 * come out of order; a source view wants unique lines sorted by file.
 */
static __u32 li_collect(const struct btf *btf, const void *recs,
			__u32 rec_size, __u32 n, struct li_entry **out)
{
	struct li_entry *e;
	__u32 i, c = 0, k;

	*out = NULL;
	if (!btf || !recs || n == 0 || rec_size < sizeof(struct bpf_line_info))
		return 0;
	e = xmalloc((size_t)n * sizeof(*e));
	if (!e)
		return 0;
	for (i = 0; i < n; i++) {
		const struct bpf_line_info *li = (const void *)
			((const char *)recs + (size_t)i * rec_size);
		const char *src = btf__name_by_offset(btf, li->line_off);
		const char *file = btf__name_by_offset(btf, li->file_name_off);

		if (src) {
			while (*src == ' ' || *src == '\t')
				src++;
		}
		if (!src || !*src)
			continue;
		e[c].file = (file && *file) ? file : "?";
		e[c].src = src;
		e[c].line = BPF_LINE_INFO_LINE_NUM(li->line_col);
		c++;
	}
	if (c == 0) {
		xfree(e, (size_t)n * sizeof(*e));
		return 0;
	}
	qsort(e, c, sizeof(*e), li_cmp);
	for (i = 0, k = 0; i < c; i++) {
		if (k && e[k - 1].line == e[i].line &&
		    strcmp(e[k - 1].file, e[i].file) == 0)
			continue;	/* same source line, different insns */
		e[k++] = e[i];
	}
	*out = e;
	return k;
}

static void dump_line_info_text(struct li_entry *ents, __u32 k)
{
	const char *last = NULL;
	__u32 i;

	if (k == 0) {
		printf("  (no line info)\n");
		return;
	}
	for (i = 0; i < k; i++) {
		if (!last || strcmp(ents[i].file, last) != 0) {
			printf("  %s:\n", ents[i].file);
			last = ents[i].file;
		}
		printf("    %5u: %s\n", ents[i].line, ents[i].src);
	}
}

static void emit_line_info_json(struct json_emit *e,
				struct li_entry *ents, __u32 k)
{
	__u32 i = 0;

	json_arr_open(e, "files");
	while (i < k) {
		const char *path = ents[i].file;
		__u32 j;

		json_obj_open(e);
		json_kv_string(e, "path", path);
		json_arr_open(e, "lines");
		for (j = i; j < k && strcmp(ents[j].file, path) == 0; j++) {
			json_obj_open(e);
			json_kv_int(e, "line", ents[j].line);
			json_kv_string(e, "src", ents[j].src);
			json_obj_close(e);
		}
		json_arr_close(e);
		json_obj_close(e);
		i = j;
	}
	json_arr_close(e);
}

static int append_one_map_json(const char *path,
			       const struct map_view *v)
{
	char *decoded = NULL;
	size_t decoded_len = 0, decoded_alloc;
	int ret;

	ret = upatch_decode_map_json(v, &decoded, &decoded_len);
	if (ret == 0) {
		decoded_alloc = decoded_len + 1;
		while (decoded_len && (decoded[decoded_len - 1] == '\n' ||
				       decoded[decoded_len - 1] == '\r'))
			decoded_len--;
		ret = emit_json_record(path, decoded, decoded_len);
		xfree(decoded, decoded_alloc);
		return ret;
	}
	return ret;
}

static int export_one_map(const char *upatch, const char *map,
			  bool json_output, const char *json_path, bool otel,
			  const struct otel_opts *otel_opts,
			  bool show_full, bool peek, bool print_detail)
{
	struct map_view v = {};
	__u32 cap = (show_full || json_output || otel) ? 0 :
		MAP_ENTRIES_DEFAULT;
	int err, ret = 0;

	err = upatch_maps_read(upatch, map, cap,
			       peek ? MAP_READ_PEEK : 0, &v);
	if (err) {
		pr_err("upatch map: read %s/%s: %s", upatch, map,
		       strerror(-err));
		map_view_free(&v);
		return 1;
	}
	if (json_output) {
		err = append_one_map_json(json_path, &v);
		if (err) {
			if (json_path)
				pr_err("upatch map: append JSON to %s: %s",
				       json_path, strerror(-err));
			else
				pr_err("upatch map: print JSON: %s",
				       strerror(-err));
			ret = 1;
		}
	}
	if (otel) {
		__u32 decoder_signal;

		err = upatch_decode_map_signal(&v, &decoder_signal);
		if (err == -ENODATA)
			err = upatch_maps_otel_send(&v, OTEL_AUTO,
						    otel_opts);
		else if (!err)
			err = upatch_maps_otel_send_decoded(&v, decoder_signal,
							    otel_opts);
		if (err) {
			pr_err("upatch map: OTLP export %s/%s: %s", upatch, map,
			       strerror(-err));
			ret = 1;
		}
	}
	if (print_detail) {
		upatch_maps_print_detail(&v);
		if (ferror(stdout))
			ret = 1;
	}
	map_view_free(&v);
	return ret;
}

static int cmd_upatch_map(int argc, const char **argv)
{
	struct config export_cfg __cleanup(config_clear) = {};
	struct map_summary *list = NULL;
	struct otel_opts otel_opts = {
		.retries = 3,
	};
	const char *upatch = NULL, *map = NULL, *json_path = NULL;
	bool all = false, json_output = false, show_full = false;
	bool otel = false, peek = false;
	bool insecure_set = false;
	bool retries_set = false;
	size_t n = 0;
	int i, ret = 0;

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (is_help(a)) {
			print_help(&upatch_map_help);
			return 0;
		}
		if (strcmp(a, "--all") == 0) {
			if (all) {
				fprintf(stderr, "upatch map: duplicate --all\n");
				return 2;
			}
			all = true;
		} else if (strncmp(a, "--json=", 7) == 0) {
			if (json_output || !a[7]) {
				fprintf(stderr,
					"upatch map: invalid or duplicate --json\n");
				return 2;
			}
			json_output = true;
			json_path = a + 7;
		} else if (strcmp(a, "--json") == 0) {
			if (json_output) {
				fprintf(stderr, "upatch map: duplicate --json\n");
				return 2;
			}
			json_output = true;
		} else if (strcmp(a, "--show-full") == 0) {
			show_full = true;
		} else if (strcmp(a, "--peek") == 0) {
			peek = true;
		} else if (strcmp(a, "--otel") == 0) {
			if (otel) {
				fprintf(stderr, "upatch map: duplicate --otel\n");
				return 2;
			}
			otel = true;
		} else if (strncmp(a, "--otel-endpoint=", 16) == 0) {
			if (otel_opts.endpoint || !a[16]) {
				fprintf(stderr, "upatch map: invalid or duplicate "
					"--otel-endpoint\n");
				return 2;
			}
			otel_opts.endpoint = a + 16;
		} else if (strncmp(a, "--tenant-id=", 12) == 0) {
			if (otel_opts.tenant_id ||
			    !tenant_id_valid(a + 12)) {
				fprintf(stderr, "upatch map: invalid or duplicate "
					"--tenant-id; expected 1..128 characters using "
					"A-Z, a-z, 0-9, '.', '_', or '-'\n");
				return 2;
			}
			otel_opts.tenant_id = a + 12;
		} else if (strcmp(a, "--otel-insecure") == 0) {
			if (insecure_set) {
				fprintf(stderr, "upatch map: duplicate --otel-insecure\n");
				return 2;
			}
			insecure_set = true;
			otel_opts.allow_insecure = true;
		} else if (strncmp(a, "--otel-retries=", 15) == 0) {
			__u64 value;

			if (retries_set || !a[15]) {
				fprintf(stderr, "upatch map: invalid or duplicate "
					"--otel-retries\n");
				return 2;
			}
			if (parse_u64(a + 15, strlen(a + 15), 10, &value)) {
				fprintf(stderr, "upatch map: --otel-retries must be 0..10\n");
				return 2;
			}
			otel_opts.retries = (__u32)value;
			retries_set = true;
		} else if (strncmp(a, "--s3-uri=", 9) == 0) {
			if (otel_opts.s3_uri || !a[9]) {
				fprintf(stderr, "upatch map: invalid or duplicate "
					"--s3-uri\n");
				return 2;
			}
			otel_opts.s3_uri = a + 9;
		} else if (a[0] == '-') {
			fprintf(stderr, "upatch map: unknown option '%s'\n", a);
			return 2;
		} else if (!upatch) {
			upatch = a;
		} else if (!map) {
			map = a;
		} else {
			fprintf(stderr, "upatch map: unexpected argument '%s'\n",
				a);
			return 2;
		}
	}
	if (all) {
		int err = config_load(&export_cfg);

		if (err) {
			pr_err("upatch map: load export configuration: %s",
			       strerror(-err));
			return 1;
		}
		if (!export_cfg.map_export_valid) {
			pr_err("upatch map: invalid map_export configuration");
			return 2;
		}
		if (!json_output && export_cfg.map_export_json_path[0]) {
			json_path = export_cfg.map_export_json_path;
			json_output = true;
		}
		if (!otel && export_cfg.map_export_otel_endpoint[0])
			otel = true;
		if (otel) {
			if (!otel_opts.endpoint &&
			    export_cfg.map_export_otel_endpoint[0])
				otel_opts.endpoint =
					export_cfg.map_export_otel_endpoint;
			if (!otel_opts.tenant_id &&
			    export_cfg.map_export_tenant_id[0])
				otel_opts.tenant_id =
					export_cfg.map_export_tenant_id;
			if (!insecure_set)
				otel_opts.allow_insecure =
					export_cfg.map_export_otel_insecure;
			if (!retries_set)
				otel_opts.retries =
					export_cfg.map_export_otel_retries;
			otel_opts.log_record_max_bytes =
				export_cfg.map_export_log_record_max_bytes;
			otel_opts.otlp_max_bytes =
				export_cfg.map_export_otlp_max_bytes;
			if (!otel_opts.s3_uri && export_cfg.map_export_s3_uri[0])
				otel_opts.s3_uri = export_cfg.map_export_s3_uri;
		}
	}

	{
		if ((otel_opts.endpoint || otel_opts.tenant_id || insecure_set ||
		     retries_set ||
		     otel_opts.s3_uri) && !otel) {
			fprintf(stderr, "upatch map: OTLP options require --otel\n");
			return 2;
		}
		if (all && (upatch || map)) {
			fprintf(stderr,
				"upatch map: --all does not accept positional arguments\n");
			return 2;
		}
		if (otel && !all && (!upatch || !map)) {
			fprintf(stderr, "upatch map: --otel requires <upatch> and <map>\n");
			return 2;
		}
	}
	if (upatch && map) {
		if (!safe_upatch_name(upatch)) {
			pr_err("upatch map: invalid upatch name '%s'", upatch);
			return 2;
		}
		return export_one_map(upatch, map, json_output, json_path, otel,
				      &otel_opts, show_full, peek,
				      !json_output && !otel);
	}

	if (all) {
		size_t k;

		upatch_maps_list_all(&list, &n);
		for (k = 0; k < n; k++) {
			if (export_one_map(list[k].upatch, list[k].name,
					   json_output, json_path, otel,
					   &otel_opts, show_full, peek,
					   !json_output && !otel) != 0)
				ret = 1;
		}
		map_summary_free(list, n);
		return ret;
	}

	if (upatch) {
		if (!safe_upatch_name(upatch)) {
			pr_err("upatch map: invalid upatch name '%s'", upatch);
			return 2;
		}
		upatch_maps_list_one(upatch, &list, &n);
	} else {
		upatch_maps_list_all(&list, &n);
	}

	if (json_output) {
		struct json_emit e = {};
		size_t cap = 8192 + 256 * n;
		char *buf;
		size_t k;

		buf = xmalloc(cap);
		if (!buf) {
			map_summary_free(list, n);
			return 1;
		}
		e.buf = buf;
		e.cap = cap;
		json_obj_open(&e);
		json_kv_int(&e, "schema", 1);
		json_arr_open(&e, "maps");
		for (k = 0; k < n; k++) {
			json_obj_open(&e);
			json_kv_string(&e, "upatch", list[k].upatch);
			json_kv_string(&e, "name", list[k].name);
			json_kv_string(&e, "type",
				       list[k].type_name);
			json_kv_int(&e, "max_entries",
				    list[k].max_entries);
			if (list[k].n_cpus > 1)
				json_kv_int(&e, "n_cpus",
					    list[k].n_cpus);
			json_obj_close(&e);
		}
		json_arr_close(&e);
		json_obj_close(&e);
		if (e.err) {
			ret = 1;
		} else {
			int err = emit_json_record(json_path, buf, e.len);

			if (err) {
				if (json_path)
					pr_err("upatch map: append JSON to %s: %s",
					       json_path, strerror(-err));
				else
					pr_err("upatch map: print JSON: %s",
					       strerror(-err));
				ret = 1;
			}
		}
		xfree(buf, cap);
	} else {
		upatch_maps_print_summary(list, n);
	}
	map_summary_free(list, n);
	return ret;
}

struct upatch_get_ctx {
	const char	*upatch;
	__u32		prog_id;
	char		location[160];
	char		loaded_at[32];
	char		payload[65];
	struct li_entry	*ents;	/* sorted unique source lines */
	__u32		n_ents;
	__u32		n_recs;	/* raw line_info record count, for free() */
	struct btf	*btf;
};

static void upatch_get_ctx_free(struct upatch_get_ctx *c)
{
	xfree(c->ents, (size_t)c->n_recs * sizeof(*c->ents));
	btf__free(c->btf);
	c->ents = NULL;
	c->btf = NULL;
}

/* Missing line_info is not a failure: the rest of the get still renders. */
static int upatch_get_collect(const char *want, struct upatch_get_ctx *c)
{
	struct bpf_link_info linfo = {};
	struct bpf_prog_info info = {};
	struct btf *vbtf = NULL;
	void *recs = NULL;
	size_t recs_sz = 0;
	__u32 len, nr, rec_size, btf_id;
	int link_fd = -1, prog_fd = -1, ret = 0;

	c->upatch = want;
	c->ents = NULL;
	c->n_ents = 0;
	c->n_recs = 0;
	c->btf = NULL;
	c->location[0] = '\0';
	c->loaded_at[0] = '\0';
	c->payload[0] = '\0';
	c->prog_id = 0;

	link_fd = upatch_open_first_link(want);
	if (link_fd < 0)
		return link_fd;
	len = sizeof(linfo);
	if (bpf_link_get_info_by_fd(link_fd, &linfo, &len) != 0) {
		ret = -errno;
		close(link_fd);
		return ret;
	}
	close(link_fd);
	if (linfo.prog_id == 0)
		return -EINVAL;
	c->prog_id = linfo.prog_id;
	upatch_loaded_at(want, c->loaded_at, sizeof(c->loaded_at));
	upatch_payload_sha256(want, c->payload, sizeof(c->payload));

	vbtf = btf__load_vmlinux_btf();
	upatch_resolve_location(vbtf, want, c->location,
				sizeof(c->location));
	btf__free(vbtf);

	prog_fd = bpf_prog_get_fd_by_id(linfo.prog_id);
	if (prog_fd < 0)
		return -errno;
	len = sizeof(info);
	if (bpf_prog_get_info_by_fd(prog_fd, &info, &len) != 0) {
		ret = -errno;
		close(prog_fd);
		return ret;
	}
	nr = info.nr_line_info;
	rec_size = info.line_info_rec_size;
	btf_id = info.btf_id;
	if (nr == 0 || btf_id == 0 || rec_size == 0) {
		close(prog_fd);
		return 0;	/* no source -- still a usable get */
	}
	recs_sz = (size_t)nr * rec_size;
	recs = xmalloc(recs_sz);
	if (!recs) {
		close(prog_fd);
		return -ENOMEM;
	}
	memset(&info, 0, sizeof(info));
	info.nr_line_info = nr;
	info.line_info_rec_size = rec_size;
	info.line_info = ptr_to_u64(recs);
	len = sizeof(info);
	if (bpf_prog_get_info_by_fd(prog_fd, &info, &len) != 0) {
		ret = -errno;
		xfree(recs, recs_sz);
		close(prog_fd);
		return ret;
	}
	close(prog_fd);
	c->btf = btf__load_from_kernel_by_id(btf_id);
	if (!c->btf) {
		xfree(recs, recs_sz);
		return -errno;
	}
	c->n_recs = nr;
	c->n_ents = li_collect(c->btf, recs, rec_size, nr, &c->ents);
	xfree(recs, recs_sz);
	return 0;
}

static void age_from_ts(const char *ts, char *out, size_t cap)
{
	struct tm tm = {};

	out[0] = '\0';
	if (!ts || !ts[0])
		return;
	if (!strptime(ts, "%Y-%m-%dT%H:%M:%SZ", &tm))
		return;
	format_duration((long)(time(NULL) - timegm(&tm)), out, cap);
}

static void render_one_map_text(const char *upatch, const char *map,
				__u32 cap)
{
	struct map_view v = {};
	int ret = upatch_maps_read(upatch, map, cap, MAP_READ_PEEK,
				   &v);

	printf("\n== Map: %s ==\n", map);
	if (ret != 0) {
		printf("  (read failed: %s)\n", strerror(-ret));
		map_view_free(&v);
		return;
	}
	upatch_maps_print_detail(&v);
	map_view_free(&v);
}

static void render_get_text(const struct upatch_get_ctx *c,
			    const struct map_summary *maps, size_t nm,
			    __u32 map_cap)
{
	char age[16] = "";
	size_t k;

	age_from_ts(c->loaded_at, age, sizeof(age));

	printf("upatch:        %s\n", c->upatch);
	printf("Location:      %s\n",
	       c->location[0] ? c->location : "?");
	printf("Prog id:       %u\n", c->prog_id);
	if (c->loaded_at[0])
		printf("Loaded at:     %s%s%s%s\n", c->loaded_at,
		       age[0] ? "  (" : "", age, age[0] ? " ago)" : "");
	if (c->payload[0])
		printf("Payload:       %s  (signature-bound)\n", c->payload);
	else
		printf("Payload:       (unavailable)\n");
	printf("Maps (%zu):    ", nm);
	for (k = 0; k < nm; k++)
		printf("%s%s", maps[k].name, k + 1 < nm ? ", " : "");
	printf("\n");

	printf("\nSource (kernel BTF line_info):\n\n");
	if (c->n_ents == 0)
		printf("  (no line info -- built without `clang -g`?)\n");
	else
		dump_line_info_text(c->ents, c->n_ents);

	for (k = 0; k < nm; k++)
		render_one_map_text(c->upatch, maps[k].name, map_cap);
}

static int render_get_json(const struct upatch_get_ctx *c,
			   const struct map_summary *maps, size_t nm,
			   __u32 map_cap)
{
	struct json_emit e = {};
	size_t cap = 64 * 1024 + 1024 * nm;
	char age[16] = "";
	char *buf;
	size_t k;
	int ret = 0;

	if (cap > JSON_MAX_BYTES)
		cap = JSON_MAX_BYTES;
	buf = xmalloc(cap);
	if (!buf)
		return 1;
	e.buf = buf;
	e.cap = cap;

	age_from_ts(c->loaded_at, age, sizeof(age));

	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_obj_open_key(&e, "upatch");
	json_kv_string(&e, "name", c->upatch);
	json_kv_string(&e, "location", c->location);
	json_kv_int(&e, "prog_id", c->prog_id);
	json_kv_string(&e, "loaded_at", c->loaded_at);
	json_kv_string(&e, "age", age);
	if (c->payload[0])
		json_kv_string(&e, "payload_sha256", c->payload);
	else
		json_kv_null(&e, "payload_sha256");
	json_obj_open_key(&e, "source");
	emit_line_info_json(&e, c->ents, c->n_ents);
	json_obj_close(&e);
	json_arr_open(&e, "maps");
	for (k = 0; k < nm; k++) {
		struct map_view v = {};
		int err;

		err = upatch_maps_read(c->upatch, maps[k].name, map_cap,
				       MAP_READ_PEEK, &v);
		if (err != 0) {
			json_obj_open(&e);
			json_kv_string(&e, "name", maps[k].name);
			json_kv_string(&e, "type",
				       maps[k].type_name);
			json_kv_int(&e, "max_entries",
				    maps[k].max_entries);
			json_kv_string(&e, "error", strerror(-err));
			json_obj_close(&e);
		} else {
			upatch_maps_emit_json_object(&e, &v);
		}
		map_view_free(&v);
	}
	json_arr_close(&e);
	json_obj_close(&e);	/* upatch */
	json_obj_close(&e);	/* root */
	if (e.err) {
		fprintf(stderr, "upatch get: json encode failed: %s\n",
			strerror(-e.err));
		ret = 1;
	} else {
		printf("%s\n", buf);
	}
	xfree(buf, cap);
	return ret;
}

static int cmd_upatch_get(int argc, const char **argv)
{
	struct map_summary *maps = NULL;
	struct upatch_get_ctx ctx = {};
	const char *want = NULL;
	bool json = false, show_full = false;
	size_t nm = 0;
	__u32 map_cap;
	int ret, i;

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (is_help(a)) {
			print_help(&upatch_get_help);
			return 0;
		}
		if (strcmp(a, "--json") == 0) {
			json = true;
		} else if (strcmp(a, "--show-full") == 0) {
			show_full = true;
		} else if (a[0] == '-') {
			fprintf(stderr, "upatch get: unknown option '%s'\n", a);
			return 2;
		} else if (!want) {
			want = a;
		} else {
			fprintf(stderr,
				"upatch get: unexpected argument '%s'\n", a);
			return 2;
		}
	}
	if (!want) {
		print_help(&upatch_get_help);
		return 2;
	}
	if (!safe_upatch_name(want)) {
		pr_err("upatch get: invalid name '%s'", want);
		return 2;
	}

	ret = upatch_get_collect(want, &ctx);
	if (ret != 0) {
		pr_err("upatch get: '%s': %s", want, strerror(-ret));
		upatch_get_ctx_free(&ctx);
		return 1;
	}
	upatch_maps_list_one(want, &maps, &nm);
	map_cap = show_full ? 0 : MAP_ENTRIES_DEFAULT;

	if (json) {
		ret = render_get_json(&ctx, maps, nm, map_cap);
	} else {
		render_get_text(&ctx, maps, nm, map_cap);
		ret = 0;
	}

	map_summary_free(maps, nm);
	upatch_get_ctx_free(&ctx);
	return ret;
}

static const struct help_item upatch_subcmds[] = {
	{ "load",   "load a signed .upatch into the target kernel (target-only)" },
	{ "unload", "apply a signed UNLOAD directive (forward chain extension)" },
	{ "list",   "list persisted + bpffs-pinned upatches on this host" },
	{ "info",   "describe a .upatch file (any host; offline, no kernel state)" },
	{ "get",    "dump source of a loaded upatch from the target kernel (BTF line_info)" },
	{ "map",    "read pinned map contents (target-only; BTF type-aware)" },
};

static const struct help_section upatch_help_sections[] = {
	{ "subcommands:", upatch_subcmds,
	  ARRAY_SIZE(upatch_subcmds) },
};

static const struct help upatch_help = {
	.usage      = "shirudo upatch <subcommand> [<args>...]",
	.summary    = "Manage signed BPF programs (.upatch). load/unload are "
		      "target-only;\nlist/info/get are read-only and run on "
		      "either side.",
	.sections   = upatch_help_sections,
	.n_sections = ARRAY_SIZE(upatch_help_sections),
};

int cmd_upatch(int argc, const char **argv)
{
	const char *canonical;

	if (argc < 2 || is_help(argv[1])) {
		print_help(&upatch_help);
		return argc < 2 ? 2 : 0;
	}
	if (is_list_cmds(argv[1])) {
		print_subcmd_list(upatch_subcmds,
				  ARRAY_SIZE(upatch_subcmds));
		return 0;
	}
	canonical = resolve_subcommand("shirudo upatch", argv[1],
				       upatch_subcmds,
				       ARRAY_SIZE(upatch_subcmds));
	if (!canonical)
		return 2;
	if (strcmp(canonical, "info") == 0)
		return cmd_upatch_info(argc - 1, argv + 1);
	if (strcmp(canonical, "load") == 0)
		return cmd_upatch_load(argc - 1, argv + 1);
	if (strcmp(canonical, "unload") == 0)
		return cmd_upatch_unload(argc - 1, argv + 1);
	if (strcmp(canonical, "list") == 0)
		return cmd_upatch_list(argc - 1, argv + 1);
	if (strcmp(canonical, "get") == 0)
		return cmd_upatch_get(argc - 1, argv + 1);
	if (strcmp(canonical, "map") == 0)
		return cmd_upatch_map(argc - 1, argv + 1);
	return 2;	/* unreachable */
}
