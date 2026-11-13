// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Offline checker for LOAD program metadata in a .upatch.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "upatch.h"

static int fail(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	return 1;
}

static int expect_attach(const struct upatch *u, __u32 kind,
			 const char *target, __u64 offset)
{
	struct upatch_prog_metadata md;
	struct upatch_prog_entry prog;
	const __u8 *raw;
	__u32 len;

	if (u->hdr.nr_progs != 1)
		return fail("unexpected metadata prog count");
	raw = upatch_signed_attach(u, &len);
	if (!raw)
		return fail("missing signed metadata");
	if (len != sizeof(md) + sizeof(prog))
		return fail("unexpected metadata length");
	memcpy(&md, raw, sizeof(md));
	memcpy(&prog, raw + sizeof(md), sizeof(prog));
	if (le32_to_cpu(md.magic) != UPATCH_PROG_MAGIC ||
	    le32_to_cpu(md.version) != UPATCH_PROG_VERSION)
		return fail("unexpected metadata magic/version");
	if (le32_to_cpu(md.nr_progs) != 1)
		return fail("unexpected metadata prog count");
	if (le32_to_cpu(prog.role) != UPATCH_PROG_ROLE_ATTACH)
		return fail("program is not an attach program");
	if (le32_to_cpu(prog.kind) != kind)
		return fail("attach kind mismatch");
	if (le64_to_cpu(prog.offset) != offset)
		return fail("unexpected attach offset");
	if (!memchr(prog.target, '\0', sizeof(prog.target)))
		return fail("unterminated attach target");
	if (target) {
		if (strcmp(prog.target, target) != 0)
			return fail("attach target mismatch");
	} else if (prog.target[0]) {
		return fail("unexpected attach target");
	}
	if (prog.map[0])
		return fail("unexpected attach map");
	return 0;
}

static int expect_serializer(const struct upatch *u)
{
	struct upatch_prog_entry progs[2];
	struct upatch_prog_metadata md;
	bool arena = false, error = false;
	const __u8 *raw;
	size_t i;
	__u32 len;

	if (u->hdr.nr_maps != 4 || u->hdr.nr_progs != 2)
		return fail("unexpected map/prog counts");
	raw = upatch_signed_attach(u, &len);
	if (!raw)
		return fail("missing signed metadata");
	if (len != sizeof(md) + sizeof(progs))
		return fail("unexpected metadata length");
	memcpy(&md, raw, sizeof(md));
	memcpy(progs, raw + sizeof(md), sizeof(progs));
	if (le32_to_cpu(md.magic) != UPATCH_PROG_MAGIC ||
	    le32_to_cpu(md.version) != UPATCH_PROG_VERSION ||
	    le32_to_cpu(md.nr_progs) != 2 || le32_to_cpu(md.nr_maps) != 4)
		return fail("unexpected metadata header");
	for (i = 0; i < 2; i++) {
		if (le32_to_cpu(progs[i].role) != UPATCH_PROG_ROLE_SERIALIZER ||
		    !memchr(progs[i].map, '\0', sizeof(progs[i].map)))
			return fail("program is not a named serializer");
		if (strcmp(progs[i].map, "tree_arena") == 0)
			arena = true;
		else if (strcmp(progs[i].map, "tree_error") == 0)
			error = true;
		else
			return fail("unexpected serializer target map");
	}
	return arena && error ? 0 : fail("serializer map mismatch");
}

/*
 * The one program attaches as kind to target in path at expected_offsets
 * file offsets, the first stored in *first; entry_offset is the offset
 * the entry records inside the function.
 */
static int expect_uprobe(const struct upatch *u, __u32 kind,
			 const char *path, const char *pattern,
			 __u64 entry_offset, __u32 expected_offsets, __u64 *first)
{
	struct upatch_uprobe_targets targets;
	struct upatch_uprobe_target record;
	struct upatch_prog_metadata md;
	struct upatch_prog_entry prog;
	const __u8 *raw, *cursor, *end;
	__u32 path_len, build_id_len, nr_offsets, len, i;
	__u64 previous = 0;

	if (u->hdr.nr_progs != 1)
		return fail("unexpected metadata prog count");
	raw = upatch_signed_attach(u, &len);
	if (!raw || len < sizeof(md) + sizeof(prog) +
	    sizeof(targets) + sizeof(record))
		return fail("missing uprobe metadata");
	memcpy(&md, raw, sizeof(md));
	memcpy(&prog, raw + sizeof(md), sizeof(prog));
	if (le32_to_cpu(md.magic) != UPATCH_PROG_MAGIC ||
	    le32_to_cpu(md.version) != UPATCH_PROG_VERSION ||
	    le32_to_cpu(md.nr_progs) != 1)
		return fail("unexpected metadata header");
	if (le32_to_cpu(prog.role) != UPATCH_PROG_ROLE_ATTACH ||
	    le32_to_cpu(prog.kind) != kind ||
	    le64_to_cpu(prog.offset) != entry_offset ||
	    !memchr(prog.target, '\0', sizeof(prog.target)) ||
	    strcmp(prog.target, pattern) != 0)
		return fail("uprobe program entry mismatch");
	cursor = raw + sizeof(md) + sizeof(prog);
	end = raw + len;
	memcpy(&targets, cursor, sizeof(targets));
	if (le32_to_cpu(targets.magic) != UPATCH_UPROBE_TARGET_MAGIC ||
	    le32_to_cpu(targets.version) != UPATCH_UPROBE_TARGET_VERSION ||
	    le32_to_cpu(targets.nr_targets) != 1 || targets.reserved)
		return fail("uprobe target header mismatch");
	cursor += sizeof(targets);
	memcpy(&record, cursor, sizeof(record));
	cursor += sizeof(record);
	path_len = le32_to_cpu(record.path_len);
	build_id_len = le32_to_cpu(record.build_id_len);
	nr_offsets = le32_to_cpu(record.nr_offsets);
	if (le32_to_cpu(record.prog_idx) != 0 || path_len != strlen(path) ||
	    !build_id_len || build_id_len > UPATCH_BUILD_ID_MAX ||
	    nr_offsets != expected_offsets)
		return fail("uprobe target record mismatch");
	if ((size_t)(end - cursor) != (size_t)path_len + build_id_len +
	    (size_t)nr_offsets * sizeof(__u64) ||
	    memcmp(cursor, path, path_len) != 0)
		return fail("uprobe path or metadata length mismatch");
	cursor += path_len + build_id_len;
	for (i = 0; i < nr_offsets; i++) {
		__u64 offset = get_le64(cursor);

		cursor += sizeof(__le64);
		if (i && offset <= previous)
			return fail("uprobe offsets are not sorted and unique");
		if (!i)
			*first = offset;
		previous = offset;
	}
	return cursor == end ? 0 : fail("trailing uprobe metadata");
}

static int expect_policy_labels(const struct upatch *u)
{
	static const char *const policies[] = {
		"executable", "ordinary-a", "ordinary-b", "socket-check",
	};
	static const char *const paths[] = {
		"/tmp/shirudo-policy-label-test/executable",
		"/tmp/shirudo-policy-label-test/ordinary",
		"/tmp/shirudo-policy-label-test/ordinary",
		"/tmp/shirudo-policy-label-test/socket-executable",
	};
	static const __u64 bits[] = { 1, 2, 4, 16 };
	struct upatch_policy_label_entry entry;
	struct upatch_policy_label_header header;
	const __u8 *raw, *cursor;
	__u32 len;
	size_t count = ARRAY_SIZE(bits);

	raw = upatch_signed_policy_labels(u, &len);
	if (!raw || len != sizeof(header) + count * sizeof(entry))
		return fail("policy label section length mismatch");
	memcpy(&header, raw, sizeof(header));
	if (le32_to_cpu(header.magic) != UPATCH_POLICY_LABELS_MAGIC ||
	    le32_to_cpu(header.version) != UPATCH_POLICY_LABELS_VERSION ||
	    le32_to_cpu(header.count) != count ||
	    le32_to_cpu(header.policy_map_idx) != 0 ||
	    le32_to_cpu(header.socket_policy_map_idx) != 1)
		return fail("policy label header mismatch");
	cursor = raw + sizeof(header);
	for (size_t i = 0; i < count; i++) {
		memcpy(&entry, cursor, sizeof(entry));
		cursor += sizeof(entry);
		if (le64_to_cpu(entry.bit) != bits[i] ||
		    strcmp(entry.policy, policies[i]) ||
		    strcmp(entry.path, paths[i]))
			return fail("policy label entry mismatch");
	}
	return cursor == raw + len ? 0 : fail("trailing policy label data");
}

int main(int argc, char **argv)
{
	struct upatch u;
	const char *mode = "serializer";
	int ret;

	if (argc != 2 && argc != 3 && argc != 4 && argc != 6)
		return fail("usage: test-upatch-prog-metadata <file.upatch> [mode [path pattern count]]");
	if (argc >= 3)
		mode = argv[2];

	ret = upatch_open(argv[1], &u);
	if (ret)
		return fail("open upatch failed");

	if (strcmp(mode, "serializer") == 0) {
		ret = expect_serializer(&u);
	} else if (strcmp(mode, "cgroup-ingress") == 0) {
		ret = expect_attach(&u,
				    UPATCH_ATTACH_CGROUP_SKB_INGRESS,
				    NULL, 0);
	} else if (strcmp(mode, "cgroup-egress") == 0) {
		ret = expect_attach(&u,
				    UPATCH_ATTACH_CGROUP_SKB_EGRESS,
				    NULL, 0);
	} else if (strcmp(mode, "kprobe-override") == 0) {
		ret = expect_attach(&u, UPATCH_ATTACH_KPROBE,
				    "bpf_modify_return_test", 0);
	} else if (strcmp(mode, "fmod-ret") == 0) {
		ret = expect_attach(&u, UPATCH_ATTACH_FMOD_RET,
				    NULL, 0);
	} else if (strcmp(mode, "netfilter-ipv6-pre-routing") == 0) {
		ret = expect_attach(&u,
				    UPATCH_ATTACH_NETFILTER_IPV6_PRE_ROUTING,
				    NULL, 0);
	} else if (strcmp(mode, "xdp") == 0 && argc == 4) {
		struct prog_spec *specs = NULL;
		const void *attach;
		__u32 len;
		__u64 mask;

		attach = upatch_signed_attach(&u, &len);
		ret = parse_u64(argv[3], strlen(argv[3]), UPATCH_XDP_ALL, &mask);
		if (!ret)
			ret = prog_specs_parse(attach, len, u.hdr.nr_maps,
					       u.hdr.nr_progs, &specs);
		if (!ret) {
			if (u.hdr.nr_progs != 1 || specs[0].kind != UPATCH_ATTACH_XDP ||
			    specs[0].device_classes != mask)
				ret = fail("XDP metadata mismatch");
			prog_specs_free(specs, u.hdr.nr_progs);
		}
	} else if ((strcmp(mode, "uprobe-multi") == 0 ||
		    strcmp(mode, "uretprobe-multi") == 0) && argc == 6) {
		__u32 kind = strcmp(mode, "uretprobe-multi") == 0 ?
			     UPATCH_ATTACH_URETPROBE_MULTI : UPATCH_ATTACH_UPROBE_MULTI;
		__u64 count, first;

		if (parse_u64(argv[5], strlen(argv[5]), UINT32_MAX, &count))
			ret = fail("invalid expected uprobe offset count");
		else
			ret = expect_uprobe(&u, kind, argv[3], argv[4], 0, (__u32)count, &first);
	} else if ((strcmp(mode, "uprobe") == 0 || strcmp(mode, "uretprobe") == 0) &&
		   argc == 6) {
		__u32 kind = strcmp(mode, "uretprobe") == 0 ?
			     UPATCH_ATTACH_URETPROBE : UPATCH_ATTACH_UPROBE;
		__u64 entry_offset, first;

		/* Prints the file offset, which the caller cannot know beforehand. */
		if (parse_u64(argv[5], strlen(argv[5]), UINT64_MAX, &entry_offset))
			ret = fail("invalid expected uprobe entry offset");
		else
			ret = expect_uprobe(&u, kind, argv[3], argv[4], entry_offset, 1, &first);
		if (!ret)
			printf("%llu\n", first);
	} else if (strcmp(mode, "policy-labels") == 0 && argc == 3) {
		ret = expect_policy_labels(&u);
	} else {
		ret = fail("unknown metadata check mode");
	}

	upatch_close(&u);
	if (ret)
		return ret;
	puts("ok");
	return 0;
}
