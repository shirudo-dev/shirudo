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

/*
 * Runs source as the decoder of map records of upatch, from an artifact
 * whose decoder entry names decoder_upatch.
 */
static void decode_named(const char *upatch, const char *decoder_upatch,
			 const char *source, int expected, const char *json)
{
	const size_t data_off = offsetof(struct decoder_fixture, blob);
	char path[] = "/tmp/shirudo-unit-decoder-XXXXXX";
	struct upatch_decoder_blob blob = {};
	size_t source_len = strlen(source);
	struct decoder_fixture f = {};
	struct map_view view = {
		.name = "records",
		.serialized = true,
		.max_entries = 1,
		.type_name = "array",
	};
	size_t out_len = 0;
	char *out = NULL;
	int fd, ret;

	ASSERT_TRUE(strscpy(view.upatch, upatch, sizeof(view.upatch)) >= 0);
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
	ASSERT_TRUE(strscpy(f.decoder.upatch, decoder_upatch,
			    sizeof(f.decoder.upatch)) >= 0);
	ASSERT_TRUE(strscpy(f.decoder.map, view.name, sizeof(f.decoder.map)) >= 0);
	strscpy_literal(f.decoder.source, "unit.lua");
	strscpy_literal(f.decoder.entrypoint, "decode");
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

static void decode(const char *source, int expected, const char *json)
{
	decode_named("unit-decoder", "unit-decoder", source, expected, json);
}

static void decoder_initializes_and_returns_json(void)
{
	decode("function decode(input) return {value = 42} end",
	       0, "{\"value\":42}");
}

/*
 * A name of 255 characters, which the decoder entry cannot hold and
 * leaves out: the map alone picks the decoder, which gets the name whole.
 */
static void decoder_of_a_upatch_with_the_longest_name_runs(void)
{
	char name[UPATCH_NAME_MAX];

	memset(name, 'n', sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';
	decode_named(name, "", "function decode(input) "
		     "return {len = #input.upatch} end",
		     0, "{\"len\":255}");
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

static void decoder_protected_loops_hit_the_limit(void)
{
	decode("function decode(input) while true do "
	       "pcall(function() while true do end end) end end",
	       -EINVAL, NULL);
	decode("function decode(input) local co = coroutine.wrap(function() "
	       "while true do pcall(function() while true do end end) "
	       "coroutine.yield() end end) "
	       "while true do pcall(co) end end",
	       -EINVAL, NULL);
}

static void decoder_cannot_reach_unbudgeted_code(void)
{
	decode("function decode(input) return {reach = tostring(newproxy) .. "
	       "tostring(xpcall) .. tostring(print) .. tostring(string.find) .. "
	       "tostring(string.match) .. tostring(string.gmatch) .. "
	       "tostring(string.gsub)} end",
	       0, "{\"reach\":\"nilnilnilnilnilnilnil\"}");
	decode("function decode(input) local s = shirudo.page_slots("
	       "{chunks = '1', data_hex = string.rep('00', 64)}, 8) "
	       "return {mt = getmetatable(s[1])} end",
	       0, "{\"mt\":\"shirudo.slot\"}");
}

static void fixed_records_keep_the_first_slot_of_a_chunked_page(void)
{
	decode("function decode(input) local r = shirudo.fixed_records({{"
	       "cursor = '0', chunks = '2', "
	       "data_hex = '07' .. string.rep('00', 4041)}}, 5) "
	       "return {got = tostring(r[1] and r[1]:u8(0)) .. ',' .. "
	       "tostring(r[807] ~= nil)} end",
	       0, "{\"got\":\"7,true\"}");
}

static void decoder_error_is_sanitized(void)
{
	char output[256] = {};
	int capture, saved;
	ssize_t len;

	capture = memfd_create("decoder-error", MFD_CLOEXEC);
	ASSERT_TRUE(capture >= 0);
	saved = dup(STDERR_FILENO);
	ASSERT_TRUE(saved >= 0);
	ASSERT_EQ(dup2(capture, STDERR_FILENO), STDERR_FILENO);
	decode("function decode(input) error('\\27]0;title\\7', 0) end",
	       -EINVAL, NULL);
	ASSERT_EQ(dup2(saved, STDERR_FILENO), STDERR_FILENO);
	EXPECT_EQ(close(saved), 0);
	ASSERT_EQ(lseek(capture, 0, SEEK_SET), 0);
	len = read(capture, output, sizeof(output) - 1);
	ASSERT_TRUE(len > 0);
	EXPECT_TRUE(str_contains(output, "decoder failed: ?]0;title?\n"));
	EXPECT_FALSE(memchr(output, '\033', len));
	EXPECT_EQ(close(capture), 0);
}

/*
 * A map no decoder claims falls back to the BTF formatting: the cells
 * the text output prints, under JSON keys, with a format tag that
 * says no decoder ran. The artifact carries the trailer and the
 * section of a decoder archive with a zero decoder count, so the
 * archive opens and no decoder matches it.
 */
static void map_without_a_decoder_prints_btf_json(void)
{
	const size_t data_off = offsetof(struct decoder_fixture, blob);
	char path[] = "/tmp/shirudo-unit-decoder-XXXXXX";
	struct upatch_decoder_blob blob = {};
	struct decoder_fixture f = {};
	struct map_view view = {
		.name = "records",
		.max_entries = 1,
		.type_name = "array",
	};
	size_t out_len = 0;
	char *out = NULL;
	int fd, ret;

	ASSERT_TRUE(strscpy(view.upatch, "unit-no-decoder",
			    sizeof(view.upatch)) >= 0);
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
	blob.nr_decoders = cpu_to_le32(0);
	memcpy(f.blob, &blob, sizeof(blob));
	f.section.tag = cpu_to_le32(UPATCH_SECTION_DECODERS);
	f.section.len = cpu_to_le32(sizeof(f.blob));
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
	EXPECT_EQ(ret, 0);
	if (!ret) {
		EXPECT_TRUE(str_contains(out, "\"format\":\"btf\""));
		EXPECT_TRUE(str_contains(out, "\"name\":\"records\""));
		EXPECT_TRUE(str_contains(out, "\"n_entries\":0"));
	}
	xfree(out, out_len + 1);
}

static const struct unit_case cases[] = {
	UNIT_CASE(decoder_initializes_and_returns_json),
	UNIT_CASE(decoder_of_a_upatch_with_the_longest_name_runs),
	UNIT_CASE(decoder_instruction_limit_is_enforced),
	UNIT_CASE(decoder_memory_limit_is_enforced),
	UNIT_CASE(decoder_protected_loops_hit_the_limit),
	UNIT_CASE(decoder_cannot_reach_unbudgeted_code),
	UNIT_CASE(fixed_records_keep_the_first_slot_of_a_chunked_page),
	UNIT_CASE(decoder_error_is_sanitized),
	UNIT_CASE(map_without_a_decoder_prints_btf_json),
	{}
};

UNIT_SUITE(upatch_decode, cases);
