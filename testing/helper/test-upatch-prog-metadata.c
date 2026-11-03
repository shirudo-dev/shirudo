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

static int expect_uprobe_multi(const struct upatch *u,
			       const char *path, const char *pattern,
			       __u32 expected_offsets)
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
	    le32_to_cpu(prog.kind) != UPATCH_ATTACH_UPROBE_MULTI ||
	    le64_to_cpu(prog.offset) != 0 ||
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

/*
 * The program attaches to program target_idx of the target upatch, named
 * and hashed as in its .upatch, and the parser takes the metadata.
 */
static int expect_bpf_prog(const struct upatch *u,
			   const char *target_path, const char *func,
			   __u32 target_idx)
{
	struct upatch_bpf_targets targets;
	struct upatch_bpf_target record;
	struct upatch_prog_metadata md;
	struct upatch_prog_entry prog;
	struct prog_spec *specs = NULL;
	struct upatch target;
	const char *target_name;
	const __u8 *raw;
	__u32 len;
	int ret;

	if (u->hdr.nr_progs != 1)
		return fail("unexpected metadata prog count");
	raw = upatch_signed_attach(u, &len);
	if (!raw || len != sizeof(md) + sizeof(prog) + sizeof(targets) + sizeof(record))
		return fail("unexpected metadata length");
	memcpy(&md, raw, sizeof(md));
	memcpy(&prog, raw + sizeof(md), sizeof(prog));
	memcpy(&targets, raw + sizeof(md) + sizeof(prog), sizeof(targets));
	memcpy(&record, raw + sizeof(md) + sizeof(prog) + sizeof(targets), sizeof(record));
	if (le32_to_cpu(prog.role) != UPATCH_PROG_ROLE_ATTACH ||
	    le32_to_cpu(prog.kind) != UPATCH_ATTACH_BPF_PROG || prog.offset ||
	    !memchr(prog.target, '\0', sizeof(prog.target)) || strcmp(prog.target, func))
		return fail("bpf_prog program entry mismatch");
	if (le32_to_cpu(targets.magic) != UPATCH_BPF_TARGET_MAGIC ||
	    le32_to_cpu(targets.version) != UPATCH_BPF_TARGET_VERSION ||
	    le32_to_cpu(targets.nr_targets) != 1 || targets.reserved)
		return fail("bpf_prog target header mismatch");

	ret = upatch_open(target_path, &target);
	if (ret)
		return fail("open target upatch failed");
	target_name = upatch_signed_name(&target);
	ret = !target_name || le32_to_cpu(record.prog_idx) != 0 ||
	     le32_to_cpu(record.target_prog_idx) != target_idx ||
	     !memchr(record.upatch, '\0', sizeof(record.upatch)) ||
	     strcmp(record.upatch, target_name) ||
	     memcmp(record.payload_sha256, target.hdr.payload_sha256,
		    sizeof(record.payload_sha256));
	upatch_close(&target);
	if (ret)
		return fail("bpf_prog target record mismatch");

	if (prog_specs_parse(raw, len, u->hdr.nr_maps, 1, &specs))
		return fail("parser rejected bpf_prog metadata");
	ret = specs[0].kind != UPATCH_ATTACH_BPF_PROG ||
	     strcmp(specs[0].bpf_upatch, record.upatch) ||
	     specs[0].bpf_prog_idx != target_idx;
	prog_specs_free(specs, 1);
	return ret ? fail("parsed bpf_prog spec mismatch") : 0;
}

int main(int argc, char **argv)
{
	struct upatch u;
	const char *mode = "serializer";
	int ret;

	if (argc != 2 && argc != 3 && argc != 6)
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
	} else if (strcmp(mode, "bpf-prog") == 0 && argc == 6) {
		char *end = NULL;
		__u64 idx = strtoul(argv[5], &end, 10);

		if (!end || *end || idx > UINT32_MAX)
			ret = fail("invalid expected target program index");
		else
			ret = expect_bpf_prog(&u, argv[3], argv[4], (__u32)idx);
	} else if (strcmp(mode, "uprobe-multi") == 0 && argc == 6) {
		char *end = NULL;
		__u64 count = strtoul(argv[5], &end, 10);

		if (!end || *end || count > UINT32_MAX)
			ret = fail("invalid expected uprobe offset count");
		else
			ret = expect_uprobe_multi(&u, argv[3], argv[4],
						  (__u32)count);
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
