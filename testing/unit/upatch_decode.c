// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#include <linux/bpf.h>

#include <shirudo/string.h>
#include <shirudo/upatch.h>

#include "upatch_decode.h"
#include "upatch_maps.h"
#include "malloc.h"
#include "unit.h"
#include "io.h"

struct decoder_fixture {
	struct upatch_header header;
	struct bpf_insn loader;
	__u8 signature[8];
	__u8 blob[sizeof(struct upatch_decoder_blob)];
	struct upatch_decoder_entry decoder;
	char source[256];
	struct upatch_signed_section section;
	struct upatch_signed_trailer trailer;
};

static void decode(const char *source, int expected, const char *json)
{
	const size_t data_off = offsetof(struct decoder_fixture, blob);
	char path[] = "/tmp/shirudo-unit-decoder-XXXXXX";
	struct upatch_decoder_blob blob = {};
	size_t source_len = strlen(source);
	struct decoder_fixture f = {};
	struct map_view view = {
		.upatch = "unit-decoder",
		.name = "records",
		.serialized = true,
		.max_entries = 1,
		.type_name = "array",
	};
	size_t out_len = 0;
	char *out = NULL;
	int fd, ret;

	f.header.magic = cpu_to_le64(UPATCH_MAGIC);
	f.header.version = cpu_to_le32(UPATCH_VERSION);
	f.header.type = cpu_to_le32(UPATCH_TYPE_BPF);
	ASSERT_TRUE(strscpy(f.header.name, view.upatch,
			    sizeof(f.header.name)) >= 0);
	f.header.loader_insns_off = cpu_to_le32(offsetof(struct decoder_fixture, loader));
	f.header.loader_insns_len = cpu_to_le32(sizeof(f.loader));
	f.header.signature_off = cpu_to_le32(offsetof(struct decoder_fixture, signature));
	f.header.signature_len = cpu_to_le32(sizeof(f.signature));
	f.header.data_off = cpu_to_le32(data_off);
	f.header.data_len = cpu_to_le32(sizeof(f) - data_off);
	f.loader.code = BPF_JMP | BPF_EXIT;
	blob.magic = cpu_to_le32(UPATCH_DECODER_MAGIC);
	blob.version = cpu_to_le32(UPATCH_DECODER_VERSION);
	blob.nr_decoders = cpu_to_le32(1);
	memcpy(f.blob, &blob, sizeof(blob));
	f.decoder.language = cpu_to_le32(UPATCH_DECODER_LANG_LUA);
	f.decoder.api_version = cpu_to_le32(1);
	f.decoder.input_format = cpu_to_le32(UPATCH_DECODER_INPUT_MAP_V1);
	f.decoder.export_signal = cpu_to_le32(UPATCH_DECODER_EXPORT_LOG);
	ASSERT_TRUE(strscpy(f.decoder.upatch, view.upatch,
			    sizeof(f.decoder.upatch)) >= 0);
	ASSERT_TRUE(strscpy(f.decoder.map, view.name, sizeof(f.decoder.map)) >= 0);
	ASSERT_TRUE(strscpy(f.decoder.source, "unit.lua", sizeof(f.decoder.source)) >= 0);
	ASSERT_TRUE(strscpy(f.decoder.entrypoint, "decode",
			    sizeof(f.decoder.entrypoint)) >= 0);
	ASSERT_TRUE(strscpy(f.source, source, sizeof(f.source)) >= 0);
	f.decoder.source_off = cpu_to_le32(offsetof(struct decoder_fixture, source) - data_off);
	f.decoder.source_len = cpu_to_le32(source_len);
	f.section.tag = cpu_to_le32(UPATCH_SECTION_DECODERS);
	f.section.len = cpu_to_le32(sizeof(f.blob) + sizeof(f.decoder) + source_len);
	f.trailer.magic = cpu_to_le32(UPATCH_SIGNED_TRAILER_MAGIC);
	f.trailer.version = cpu_to_le32(UPATCH_SIGNED_VERSION);
	f.trailer.dir_off = cpu_to_le32(offsetof(struct decoder_fixture, section) - data_off);
	f.trailer.nr_sections = cpu_to_le32(1);
	fd = mkstemp(path);
	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(write_complete(fd, &f, sizeof(f)), 0);
	ASSERT_EQ(close(fd), 0);
	ret = upatch_decode_map_file_json(path, &view, &out, &out_len);
	EXPECT_EQ(unlink(path), 0);
	EXPECT_EQ(ret, expected);
	if (!ret) {
		EXPECT_STREQ(out, json);
	} else {
		EXPECT_FALSE(out);
		EXPECT_UEQ(out_len, 0);
	}
	xfree(out, out_len + 1);
}

static void decoder_initializes_and_returns_json(void)
{
	decode("function decode(input) return {value = 42} end",
	       0, "{\"value\":42}");
}

static void decoder_instruction_limit_is_enforced(void)
{
	decode("function decode(input) while true do end end", -EINVAL, NULL);
}

static void decoder_memory_limit_is_enforced(void)
{
	decode("function decode(input) return string.rep('x', 64 * 1024 * 1024) end",
	       -EINVAL, NULL);
}

static void decoder_memory_limit_applies_to_finalizers(void)
{
	char output[128] = {};
	int capture, saved;
	ssize_t len;

	capture = memfd_create("decoder-finalizer", MFD_CLOEXEC);
	ASSERT_TRUE(capture >= 0);
	saved = dup(STDOUT_FILENO);
	ASSERT_TRUE(saved >= 0);
	ASSERT_EQ(fflush(stdout), 0);
	ASSERT_EQ(dup2(capture, STDOUT_FILENO), STDOUT_FILENO);
	decode("proxy = newproxy(true) "
	       "getmetatable(proxy).__gc = function() "
	       "local ok, s = pcall(string.rep, 'x', 64 * 1024 * 1024) "
	       "print(ok, ok and #s or s) end "
	       "function decode(input) return {value = 42} end", 0, "{\"value\":42}");
	ASSERT_EQ(fflush(stdout), 0);
	ASSERT_EQ(dup2(saved, STDOUT_FILENO), STDOUT_FILENO);
	EXPECT_EQ(close(saved), 0);
	ASSERT_EQ(lseek(capture, 0, SEEK_SET), 0);
	len = read(capture, output, sizeof(output) - 1);
	ASSERT_TRUE(len >= 0);
	EXPECT_STREQ(output, "false\tnot enough memory\n");
	EXPECT_EQ(close(capture), 0);
}

static const struct unit_case cases[] = {
	UNIT_CASE(decoder_initializes_and_returns_json),
	UNIT_CASE(decoder_instruction_limit_is_enforced),
	UNIT_CASE(decoder_memory_limit_is_enforced),
	UNIT_CASE(decoder_memory_limit_applies_to_finalizers),
	{}
};

UNIT_SUITE(upatch_decode, cases);
