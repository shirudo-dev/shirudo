// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <endian.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/btf.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/upatch.h>

#include "json.h"
#include "io.h"
#include "malloc.h"
#include "upatch_decode.h"
#include "upatch_maps.h"
#include "upatch_maps_otel.h"
#include "version.h"

const char shirudo_version[] = "test-1";

struct fixture {
	struct shirudo_map_view view;
	struct shirudo_map_entry entry;
	struct btf *btf;
	__u32 key;
	__u8 values[16];
};

/* Build the smallest valid artifact carrying a decoder for offline tests. */
static int make_decoder(bool metric, bool counter, bool snapshot,
			char *path, size_t path_sz)
{
	static const char log_source[] =
		"function decode(input)\n"
		"\treturn { data = { entries = {{ "
		"values_per_cpu = { \"5\", \"7\" }, "
		"sum = \"12\" }} } }\n"
		"end\n";
	static const char snapshot_source[] =
		"function decode(input)\n"
		"\treturn input\n"
		"end\n";
	static const char gauge_source[] =
		"function decode(input)\n"
		"\treturn {{ name = \"shirudo.test.hits\", "
		"unit = \"1\", gauge = { dataPoints = "
		"{{ asInt = \"12\" }} } }}\n"
		"end\n";
	static const char counter_source[] =
		"function decode(input)\n"
		"\treturn {{ name = \"shirudo.test.hits\", "
		"unit = \"1\", sum = { aggregationTemporality = 2, "
		"isMonotonic = true, dataPoints = {{ "
		"startTimeUnixNano = \"1544712660300000000\", "
		"timeUnixNano = \"1700000000000000000\", "
		"asInt = \"12\" }} } }}\n"
		"end\n";
	const char *source = snapshot ? snapshot_source : metric ?
		(counter ? counter_source : gauge_source) : log_source;
	size_t source_len = strlen(source);
	size_t entries_end = sizeof(struct shirudo_upatch_decoder_blob) +
		sizeof(struct shirudo_upatch_decoder_entry);
	size_t decoder_len = entries_end + source_len;
	size_t data_len = decoder_len +
		sizeof(struct shirudo_upatch_decoder_trailer);
	size_t loader_off = sizeof(struct shirudo_upatch_header);
	size_t sig_off = loader_off + sizeof(struct bpf_insn);
	size_t data_off = sig_off + 1;
	size_t file_len = data_off + data_len;
	struct shirudo_upatch_decoder_trailer trailer = {};
	struct shirudo_upatch_decoder_entry entry = {};
	struct shirudo_upatch_decoder_blob blob = {};
	struct shirudo_upatch_header header = {};
	__u8 *file;
	char template[] = "/tmp/test-otel-map-decoder-XXXXXX";
	int fd, rc;

	if (file_len > UINT32_MAX || decoder_len > UINT32_MAX ||
	    source_len > UINT32_MAX || snprintf(path, path_sz, "%s", template) >=
	    (int)path_sz)
		return -EOVERFLOW;
	file = xcalloc(1, file_len);
	if (!file)
		return -ENOMEM;
	fd = mkstemp(path);
	if (fd < 0) {
		rc = -errno;
		xfree(file, file_len);
		return rc;
	}

	header.magic = htole64(SHIRUDO_UPATCH_MAGIC);
	header.version = htole32(SHIRUDO_UPATCH_VERSION);
	header.type = htole32(SHIRUDO_UPATCH_TYPE_BPF);
	strncpy(header.name, "test-upatch", sizeof(header.name) - 1);
	header.loader_insns_off = htole32(loader_off);
	header.loader_insns_len = htole32(sizeof(struct bpf_insn));
	header.signature_off = htole32(sig_off);
	header.signature_len = htole32(1);
	header.data_off = htole32(data_off);
	header.data_len = htole32(data_len);
	memcpy(file, &header, sizeof(header));
	file[data_off - 1] = 0;

	/* The sections start at odd offsets: build them aligned, then copy. */
	blob.magic = htole32(SHIRUDO_UPATCH_DECODER_MAGIC);
	blob.version = htole32(SHIRUDO_UPATCH_DECODER_VERSION);
	blob.nr_decoders = htole32(1);
	memcpy(file + data_off, &blob, sizeof(blob));
	entry.language = htole32(SHIRUDO_UPATCH_DECODER_LANG_LUA);
	entry.api_version = htole32(1);
	entry.input_format = htole32(SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1);
	entry.export_signal = htole32(metric ?
				      SHIRUDO_UPATCH_DECODER_EXPORT_METRIC :
				      SHIRUDO_UPATCH_DECODER_EXPORT_LOG);
	strncpy(entry.upatch, "test-upatch", sizeof(entry.upatch) - 1);
	strncpy(entry.map, "hits_total", sizeof(entry.map) - 1);
	strncpy(entry.source, "test.lua", sizeof(entry.source) - 1);
	strncpy(entry.entrypoint, "decode", sizeof(entry.entrypoint) - 1);
	entry.source_off = htole32(entries_end);
	entry.source_len = htole32(source_len);
	memcpy(file + data_off + sizeof(blob), &entry, sizeof(entry));
	memcpy(file + data_off + entries_end, source, source_len);
	trailer.magic = htole32(SHIRUDO_UPATCH_DECODER_TRAILER_MAGIC);
	trailer.version = htole32(SHIRUDO_UPATCH_DECODER_VERSION);
	trailer.decoder_off = htole32(0);
	trailer.decoder_len = htole32(decoder_len);
	memcpy(file + data_off + decoder_len, &trailer, sizeof(trailer));

	rc = write_complete(fd, file, file_len);
	if (close(fd) != 0 && rc == 0)
		rc = -errno;
	xfree(file, file_len);
	if (rc) {
		unlink(path);
		return rc;
	}
	return 0;
}

static int fixture_init(struct fixture *f, __u32 map_type, bool is_signed,
			bool with_btf)
{
	int key_int, value_int, key_type, value_type;
	__u32 cpu0 = 5, cpu1 = 7, poison = 0xdeadbeef;

	memset(f, 0, sizeof(*f));
	snprintf(f->view.upatch, sizeof(f->view.upatch), "test-upatch");
	snprintf(f->view.name, sizeof(f->view.name), "hits_total");
	snprintf(f->view.location, sizeof(f->view.location),
		 "fentry/test_hook");
	f->view.type = map_type;
	f->view.type_name = map_type == BPF_MAP_TYPE_ARRAY ? "array" :
		"percpu_array";
	f->view.key_size = 4;
	f->view.value_size = 4;
	f->view.value_stride = map_type == BPF_MAP_TYPE_ARRAY ? 4 : 8;
	f->view.max_entries = 1;
	f->view.n_entries = 1;
	f->view.n_cpus = map_type == BPF_MAP_TYPE_ARRAY ? 1 : 2;
	f->view.lifetime_start_ns = 1544712660300000000ULL;
	f->entry.key = &f->key;
	f->entry.value = f->values;
	f->view.entries = &f->entry;
	memcpy(f->values, &cpu0, 4);
	memcpy(f->values + 4, &poison, 4);
	memcpy(f->values + 8, &cpu1, 4);
	if (!with_btf)
		return 0;
	f->btf = btf__new_empty();
	if (libbpf_get_error(f->btf))
		return -ENOMEM;
	key_int = btf__add_int(f->btf, "unsigned int", 4, 0);
	value_int = btf__add_int(f->btf,
				 is_signed ? "int" : "unsigned int", 4,
				 is_signed ? BTF_INT_SIGNED : 0);
	key_type = btf__add_typedef(f->btf, "__u32", key_int);
	value_type = btf__add_typedef(f->btf,
				      is_signed ? "__s32" : "__u32", value_int);
	if (key_int < 0 || value_int < 0 || key_type < 0 || value_type < 0)
		return -EINVAL;
	f->view.btf = f->btf;
	f->view.key_type_id = (__u32)key_type;
	f->view.value_type_id = (__u32)value_type;
	snprintf(f->view.btf_key_type, sizeof(f->view.btf_key_type), "__u32");
	snprintf(f->view.btf_value_type, sizeof(f->view.btf_value_type), "%s",
		 is_signed ? "__s32" : "__u32");
	return 0;
}

static void fixture_destroy(struct fixture *f)
{
	btf__free(f->btf);
}

static int print_classification(__u32 type, bool is_signed, bool with_btf,
				bool serialized)
{
	struct fixture f;
	enum shirudo_otel_signal signal;
	char reason[160];
	int rc = fixture_init(&f, type, is_signed, with_btf);

	if (rc)
		return 1;
	f.view.serialized = serialized;
	rc = shirudo_upatch_maps_otel_classify(&f.view, &signal, reason,
					       sizeof(reason));
	if (!rc)
		printf("%s:%s\n", signal == SHIRUDO_OTEL_METRIC ?
		       "metric" : "log", reason);
	fixture_destroy(&f);
	return rc != 0;
}

static int print_payload(bool metric, bool counter, bool with_location)
{
	struct shirudo_otel_opts opts = {
		.metric_kind = counter ? SHIRUDO_OTEL_METRIC_COUNTER :
			SHIRUDO_OTEL_METRIC_GAUGE,
		.metric_kind_set = true,
		.metric_name = "shirudo.test.hits",
		.metric_unit = "1",
	};
	struct fixture f;
	char decoder_path[128] = {};
	char *buf = NULL;
	size_t len = 0;
	int rc = fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, false, true);

	if (rc)
		return 1;
	if (!with_location)
		f.view.location[0] = '\0';
	rc = make_decoder(metric, counter, false, decoder_path,
			  sizeof(decoder_path));
	if (!rc && metric)
		rc = shirudo_upatch_maps_otel_build_metric_file(decoder_path,
								&f.view, &opts,
								&buf, &len);
	else if (!rc)
		rc = shirudo_upatch_maps_otel_build_log_file(decoder_path,
							     &f.view, &buf,
							     &len);
	if (!rc && buf)
		fwrite(buf, 1, len, stdout);
	if (buf)
		xfree(buf, SHIRUDO_JSON_MAX_BYTES);
	if (decoder_path[0])
		unlink(decoder_path);
	fixture_destroy(&f);
	return rc != 0;
}

static int print_local_json(void)
{
	struct fixture f;
	struct shirudo_json_emit e = {};
	char buf[4096];

	if (fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, false, true))
		return 1;
	e.buf = buf;
	e.cap = sizeof(buf);
	json_obj_open(&e);
	upatch_maps_emit_json_fields(&e, &f.view);
	json_obj_close(&e);
	if (!e.err)
		printf("%s", buf);
	fixture_destroy(&f);
	return e.err != 0;
}

static int send_log_limits(const char *url, __u32 retries, __u32 record_max,
			   __u32 request_max, bool use_environment)
{
	struct shirudo_otel_opts opts = {
		.endpoint = use_environment ? NULL : url,
		.retries = retries,
		.log_record_max_bytes = record_max,
		.otlp_max_bytes = request_max,
	};
	struct fixture f;
	char decoder_path[128] = {};
	int rc;

	rc = fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, false, true);
	if (rc)
		return 1;
	rc = make_decoder(false, false, false, decoder_path,
			  sizeof(decoder_path));
	if (!rc)
		rc = shirudo_upatch_maps_otel_send_file(decoder_path, &f.view,
							SHIRUDO_OTEL_FORCE_LOG, &opts);
	if (decoder_path[0])
		unlink(decoder_path);
	fixture_destroy(&f);
	return rc ? 1 : 0;
}

static int send_log(const char *url, __u32 retries, bool insecure)
{
	struct shirudo_otel_opts opts = {
		.endpoint = url,
		.allow_insecure = insecure,
		.retries = retries,
	};
	struct fixture f;
	char decoder_path[128] = {};
	int rc;

	rc = fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, false, true);
	if (rc)
		return 1;
	rc = make_decoder(false, false, false, decoder_path,
			  sizeof(decoder_path));
	if (!rc)
		rc = shirudo_upatch_maps_otel_send_file(decoder_path, &f.view,
							SHIRUDO_OTEL_FORCE_LOG, &opts);
	if (decoder_path[0])
		unlink(decoder_path);
	fixture_destroy(&f);
	return rc ? 1 : 0;
}

static int print_record_size(void)
{
	struct fixture f;
	char decoder_path[128] = {};
	char *decoded = NULL;
	size_t decoded_len = 0;
	int rc;

	rc = fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, false, true);
	if (rc)
		return 1;
	rc = make_decoder(false, false, false, decoder_path,
			  sizeof(decoder_path));
	if (!rc)
		rc = upatch_decode_map_file_otel(decoder_path, &f.view,
						 &decoded, &decoded_len);
	if (!rc)
		printf("%zu\n", decoded_len);
	if (decoded)
		xfree(decoded, decoded_len + 1);
	if (decoder_path[0])
		unlink(decoder_path);
	fixture_destroy(&f);
	return rc != 0;
}

static int send_auto(const char *base, bool is_signed)
{
	struct shirudo_otel_opts opts = { .endpoint = base, .retries = 0 };
	struct fixture f;
	char decoder_path[128] = {};
	int rc;

	if (fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, is_signed, true))
		return 1;
	rc = make_decoder(!is_signed, !is_signed, false, decoder_path,
			  sizeof(decoder_path));
	if (!rc)
		rc = shirudo_upatch_maps_otel_send_file(decoder_path, &f.view,
							SHIRUDO_OTEL_AUTO, &opts);
	if (decoder_path[0])
		unlink(decoder_path);
	fixture_destroy(&f);
	return rc ? 1 : 0;
}

static int send_metric(const char *url)
{
	struct shirudo_otel_opts opts = {
		.endpoint = url,
		.retries = 0,
		.metric_kind = SHIRUDO_OTEL_METRIC_GAUGE,
		.metric_kind_set = true,
	};
	struct fixture f;
	char decoder_path[128] = {};
	int rc;

	if (fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, false, true))
		return 1;
	rc = make_decoder(true, false, false, decoder_path,
			  sizeof(decoder_path));
	if (!rc)
		rc = shirudo_upatch_maps_otel_send_file(decoder_path, &f.view,
							SHIRUDO_OTEL_FORCE_METRIC, &opts);
	if (decoder_path[0])
		unlink(decoder_path);
	fixture_destroy(&f);
	return rc ? 1 : 0;
}

static int send_status(const char *url, const char *status)
{
	struct shirudo_otel_opts opts = {
		.endpoint = url,
		.retries = 0,
	};
	const char *severity_text;
	char body[256];
	int severity, n;

	severity = shirudo_status_otel_severity(status, &severity_text);
	n = snprintf(body, sizeof(body),
		     "{\"schema\":1,\"status\":\"%s\",\"conditions\":[],\"tpm\":{}}",
		     status);
	if (n < 0 || (size_t)n >= sizeof(body))
		return 1;
	return shirudo_otel_send_log_json(&opts, "shirudo.keepalive",
					 "shirudo.keepalive", severity,
					 severity_text, status, "test-version", 2,
					 body, (size_t)n) != 0;
}

static int send_metric_env(void)
{
	struct shirudo_otel_opts opts = {
		.retries = 0,
		.metric_kind = SHIRUDO_OTEL_METRIC_GAUGE,
		.metric_kind_set = true,
	};
	struct fixture f;
	char decoder_path[128] = {};
	int rc;

	rc = fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, false, true);
	if (rc)
		return 1;
	rc = make_decoder(true, false, false, decoder_path,
			  sizeof(decoder_path));
	if (!rc)
		rc = shirudo_upatch_maps_otel_send_file(decoder_path, &f.view,
							SHIRUDO_OTEL_FORCE_METRIC, &opts);
	if (decoder_path[0])
		unlink(decoder_path);
	fixture_destroy(&f);
	return rc != 0;
}

static bool large_serialized_fixture(struct fixture *f)
{
	const __u32 pages = 1;
	const __u32 bytes = 1024;

	f->view.serialized = true;
	f->view.n_entries = 0;
	f->view.n_serial_pages = pages;
	f->view.serial_bytes_total = (__u64)pages * bytes;
	f->view.serial_pages = xcalloc(pages, sizeof(*f->view.serial_pages));
	if (!f->view.serial_pages)
		return false;
	for (__u32 i = 0; i < pages; i++) {
		struct shirudo_serial_page *page = &f->view.serial_pages[i];

		page->page_index = i;
		page->cursor = i;
		page->next_cursor = i + 1;
		page->done = i + 1 == pages;
		page->flags = page->done ? 1 : 0;
		page->chunks = 128;
		page->bytes = bytes;
		page->data = xmalloc(bytes);
		if (!page->data)
			return false;
		memset(page->data, (int)('A' + i), bytes);
	}
	return true;
}

static void large_serialized_destroy(struct fixture *f)
{
	if (!f->view.serial_pages)
		return;
	for (__u32 i = 0; i < f->view.n_serial_pages; i++)
		xfree(f->view.serial_pages[i].data,
		      f->view.serial_pages[i].bytes);
	xfree(f->view.serial_pages,
	      f->view.n_serial_pages * sizeof(*f->view.serial_pages));
	f->view.serial_pages = NULL;
}

static int send_s3(const char *endpoint, __u32 retries, bool large)
{
	struct shirudo_otel_opts opts = {
		.s3_uri = getenv("SHIRUDO_TEST_S3_URI") ?
			  getenv("SHIRUDO_TEST_S3_URI") : "s3://test-bucket/prefix",
		.tenant_id = large ? NULL : "tenant-uuid-1234",
		.otlp_max_bytes = large ? 1024 : 0,
		.retries = retries,
	};
	struct fixture f;
	char decoder_path[128] = {};
	int rc;

	if (setenv("AWS_ENDPOINT_URL_S3", endpoint, 1) != 0)
		return 1;
	rc = fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, false, true);
	if (rc)
		return 1;
	if (large) {
		if (!large_serialized_fixture(&f)) {
			large_serialized_destroy(&f);
			fixture_destroy(&f);
			return 1;
		}
	}
	rc = make_decoder(false, false, true, decoder_path,
			  sizeof(decoder_path));
	if (!rc)
		rc = shirudo_upatch_maps_otel_send_file(decoder_path, &f.view,
							SHIRUDO_OTEL_S3, &opts);
	if (decoder_path[0])
		unlink(decoder_path);
	large_serialized_destroy(&f);
	fixture_destroy(&f);
	return rc ? 1 : 0;
}

static int tenant_validation(void)
{
	struct shirudo_otel_opts opts = {
		.endpoint = "http://127.0.0.1:1",
		.retries = 0,
	};
	struct fixture f;
	int rc, failed = 0;

	if (fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, false, true))
		return 1;
	opts.tenant_id = "bad tenant";
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_FORCE_LOG,
					   &opts);
	failed += rc != -EINVAL;
	opts.tenant_id = NULL;
	setenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS",
	       "X-Tenant-ID=bad%20tenant", 1);
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_FORCE_LOG,
					   &opts);
	failed += rc != -EINVAL;
	setenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS",
	       "X-Tenant-ID=one,x-tenant-id=two", 1);
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_FORCE_LOG,
					   &opts);
	failed += rc != -EINVAL;
	opts.tenant_id = "tenant-cli-1234";
	setenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS",
	       "X-Tenant-ID=ignored%20invalid", 1);
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_FORCE_LOG,
					   &opts);
	failed += rc == -EINVAL;
	unsetenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS");
	fixture_destroy(&f);
	return failed ? 1 : 0;
}

static int s3_validation(void)
{
	struct shirudo_otel_opts opts = {
		.s3_uri = "s3://test-bucket/prefix",
		.retries = 0,
	};
	struct fixture f;
	int rc;

	if (fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, false, true))
		return 1;
	setenv("AWS_ENDPOINT_URL_S3", "http://127.0.0.1:1", 1);
	unsetenv("AWS_REGION");
	unsetenv("AWS_DEFAULT_REGION");
	unsetenv("AWS_ACCESS_KEY_ID");
	unsetenv("AWS_SECRET_ACCESS_KEY");
	unsetenv("AWS_SESSION_TOKEN");
	unsetenv("AWS_CA_BUNDLE");
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_S3, &opts);
	if (rc != -EACCES)
		goto fail;
	setenv("AWS_ACCESS_KEY_ID", "test", 1);
	setenv("AWS_SECRET_ACCESS_KEY", "bad\nsecret", 1);
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_S3, &opts);
	if (rc != -EACCES)
		goto fail;
	setenv("AWS_SECRET_ACCESS_KEY", "secret", 1);
	setenv("AWS_ACCESS_KEY_ID", "bad:key", 1);
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_S3, &opts);
	if (rc != -EACCES)
		goto fail;
	setenv("AWS_ACCESS_KEY_ID", "test", 1);
	setenv("AWS_REGION", "not_a_region", 1);
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_S3, &opts);
	if (rc != -EINVAL)
		goto fail;
	unsetenv("AWS_REGION");
	opts.s3_uri = "s3://test-bucket/../escape";
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_S3, &opts);
	if (rc != -EINVAL)
		goto fail;
	opts.s3_uri = "s3://test-bucket/prefix?query";
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_S3, &opts);
	if (rc != -EINVAL)
		goto fail;
	opts.s3_uri = "s3://BAD_BUCKET/prefix";
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_S3, &opts);
	if (rc != -EINVAL)
		goto fail;
	opts.s3_uri = "s3://test-bucket/prefix";
	f.view.truncated = true;
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_S3, &opts);
	f.view.truncated = false;
	if (rc != -E2BIG)
		goto fail;
	f.view.skipped = true;
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_S3, &opts);
	f.view.skipped = false;
	if (rc != -EOPNOTSUPP)
		goto fail;
	setenv("AWS_ENDPOINT_URL_S3", "http://storage.example", 1);
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_S3, &opts);
	if (rc != -EPERM)
		goto fail;
	fixture_destroy(&f);
	return 0;
fail:
	fixture_destroy(&f);
	return 1;
}

static int security_check(void)
{
	struct shirudo_otel_opts opts = {
		.endpoint = "http://collector.example",
		.retries = 0,
	};
	struct fixture f;
	int rc;

	if (fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, false, true))
		return 1;
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_FORCE_LOG,
					   &opts);
	fixture_destroy(&f);
	return rc != -EPERM;
}

int main(int argc, char **argv)
{
	if (argc == 2 && strcmp(argv[1], "record-size") == 0)
		return print_record_size();
	if (argc == 6 && strcmp(argv[1], "send-log-limits") == 0)
		return send_log_limits(argv[2], (__u32)strtoul(argv[3], NULL, 10),
					(__u32)strtoul(argv[4], NULL, 10),
					(__u32)strtoul(argv[5], NULL, 10), false);
	if (argc == 3 && strcmp(argv[1], "send-log-env") == 0)
		return send_log_limits(NULL, (__u32)strtoul(argv[2], NULL, 10),
					0, 0, true);
	if (argc == 2 && strcmp(argv[1], "send-metric-env") == 0)
		return send_metric_env();
	if (argc == 4 && strcmp(argv[1], "send-status") == 0)
		return send_status(argv[2], argv[3]);
	if (argc == 4 && strcmp(argv[1], "retry-after") == 0) {
		__u64 seconds;
		time_t now = (time_t)strtoll(argv[3], NULL, 10);
		int rc = shirudo_otel_retry_after(argv[2], now, &seconds);

		if (!rc)
			printf("%llu\n", seconds);
		return rc != 0;
	}
	if (argc < 2)
		return 2;
	if (strcmp(argv[1], "classify-unsigned") == 0)
		return print_classification(BPF_MAP_TYPE_PERCPU_ARRAY, false,
					    true, false);
	if (strcmp(argv[1], "classify-signed") == 0)
		return print_classification(BPF_MAP_TYPE_PERCPU_ARRAY, true,
					    true, false);
	if (strcmp(argv[1], "classify-array") == 0)
		return print_classification(BPF_MAP_TYPE_ARRAY, false, true,
					    false);
	if (strcmp(argv[1], "classify-hash") == 0)
		return print_classification(BPF_MAP_TYPE_PERCPU_HASH, false, true,
					    false);
	if (strcmp(argv[1], "classify-lru-hash") == 0)
		return print_classification(BPF_MAP_TYPE_LRU_PERCPU_HASH, false,
					    true, false);
	if (strcmp(argv[1], "classify-no-btf") == 0)
		return print_classification(BPF_MAP_TYPE_PERCPU_ARRAY, false,
					    false, false);
	if (strcmp(argv[1], "classify-serialized") == 0)
		return print_classification(BPF_MAP_TYPE_PERCPU_ARRAY, false,
					    true, true);
	if (strcmp(argv[1], "log") == 0)
		return print_payload(false, false, true);
	if (strcmp(argv[1], "log-no-location") == 0)
		return print_payload(false, false, false);
	if (strcmp(argv[1], "metric") == 0)
		return print_payload(true, false, true);
	if (strcmp(argv[1], "counter") == 0)
		return print_payload(true, true, true);
	if (strcmp(argv[1], "local-json") == 0)
		return print_local_json();
	if (strcmp(argv[1], "send-log") == 0 && argc == 4)
		return send_log(argv[2], (__u32)strtoul(argv[3], NULL, 10),
				false);
	if (strcmp(argv[1], "send-log-insecure") == 0 && argc == 4)
		return send_log(argv[2], (__u32)strtoul(argv[3], NULL, 10),
				true);
	if (strcmp(argv[1], "send-auto-log") == 0 && argc == 3)
		return send_auto(argv[2], true);
	if (strcmp(argv[1], "send-auto-metric") == 0 && argc == 3)
		return send_auto(argv[2], false);
	if (strcmp(argv[1], "send-metric") == 0 && argc == 3)
		return send_metric(argv[2]);
	if (strcmp(argv[1], "send-s3") == 0 && argc == 4)
		return send_s3(argv[2],
			       (__u32)strtoul(argv[3], NULL, 10), false);
	if (strcmp(argv[1], "send-s3-large") == 0 && argc == 4)
		return send_s3(argv[2],
			       (__u32)strtoul(argv[3], NULL, 10), true);
	if (strcmp(argv[1], "s3-validation") == 0)
		return s3_validation();
	if (strcmp(argv[1], "tenant-validation") == 0)
		return tenant_validation();
	if (strcmp(argv[1], "security") == 0)
		return security_check();
	return 2;
}
