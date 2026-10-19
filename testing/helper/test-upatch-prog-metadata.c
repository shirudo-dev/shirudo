// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Offline checker for LOAD program metadata in a .upatch.
 */

#include <endian.h>
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

static int expect_attach(const struct shirudo_upatch *u, __u32 kind,
			 const char *target, __u64 offset)
{
	struct shirudo_upatch_prog_metadata md;
	struct shirudo_upatch_prog_entry prog;
	const __u8 *raw;

	if (u->hdr.nr_progs != 1)
		return fail("unexpected metadata prog count");
	if (u->hdr.metadata_len != sizeof(md) + sizeof(prog))
		return fail("unexpected metadata length");
	raw = shirudo_upatch_metadata(u);
	if (!raw)
		return fail("missing metadata");
	memcpy(&md, raw, sizeof(md));
	memcpy(&prog, raw + sizeof(md), sizeof(prog));
	if (le32toh(md.magic) != SHIRUDO_UPATCH_PROG_MAGIC ||
	    le32toh(md.version) != SHIRUDO_UPATCH_PROG_VERSION)
		return fail("unexpected metadata magic/version");
	if (le32toh(md.nr_progs) != 1)
		return fail("unexpected metadata prog count");
	if (le32toh(prog.role) != SHIRUDO_UPATCH_PROG_ROLE_ATTACH)
		return fail("program is not an attach program");
	if (le32toh(prog.kind) != kind)
		return fail("attach kind mismatch");
	if (le64toh(prog.offset) != offset)
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

static int expect_serializer(const struct shirudo_upatch *u)
{
	struct shirudo_upatch_prog_entry progs[2];
	struct shirudo_upatch_prog_metadata md;
	bool arena = false, error = false;
	const __u8 *raw;
	size_t i;

	if (u->hdr.nr_maps != 4 || u->hdr.nr_progs != 2)
		return fail("unexpected map/prog counts");
	if (u->hdr.metadata_len != sizeof(md) + sizeof(progs))
		return fail("unexpected metadata length");
	raw = shirudo_upatch_metadata(u);
	if (!raw)
		return fail("missing metadata");
	memcpy(&md, raw, sizeof(md));
	memcpy(progs, raw + sizeof(md), sizeof(progs));
	if (le32toh(md.magic) != SHIRUDO_UPATCH_PROG_MAGIC ||
	    le32toh(md.version) != SHIRUDO_UPATCH_PROG_VERSION ||
	    le32toh(md.nr_progs) != 2)
		return fail("unexpected metadata header");
	for (i = 0; i < 2; i++) {
		if (le32toh(progs[i].role) != SHIRUDO_UPATCH_PROG_ROLE_SERIALIZER ||
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

static int expect_uprobe_multi(const struct shirudo_upatch *u,
			       const char *path, const char *pattern,
			       __u32 expected_offsets)
{
	struct shirudo_upatch_uprobe_targets targets;
	struct shirudo_upatch_uprobe_target record;
	struct shirudo_upatch_prog_metadata md;
	struct shirudo_upatch_prog_entry prog;
	const __u8 *raw, *cursor, *end;
	__u32 path_len, build_id_len, nr_offsets, i;
	__u64 previous = 0;

	if (u->hdr.nr_progs != 1)
		return fail("unexpected metadata prog count");
	raw = shirudo_upatch_metadata(u);
	if (!raw || u->hdr.metadata_len < sizeof(md) + sizeof(prog) +
	    sizeof(targets) + sizeof(record))
		return fail("missing uprobe metadata");
	memcpy(&md, raw, sizeof(md));
	memcpy(&prog, raw + sizeof(md), sizeof(prog));
	if (le32toh(md.magic) != SHIRUDO_UPATCH_PROG_MAGIC ||
	    le32toh(md.version) != SHIRUDO_UPATCH_PROG_VERSION ||
	    le32toh(md.nr_progs) != 1)
		return fail("unexpected metadata header");
	if (le32toh(prog.role) != SHIRUDO_UPATCH_PROG_ROLE_ATTACH ||
	    le32toh(prog.kind) != SHIRUDO_UPATCH_ATTACH_UPROBE_MULTI ||
	    le64toh(prog.offset) != 0 ||
	    !memchr(prog.target, '\0', sizeof(prog.target)) ||
	    strcmp(prog.target, pattern) != 0)
		return fail("uprobe program entry mismatch");
	cursor = raw + sizeof(md) + sizeof(prog);
	end = raw + u->hdr.metadata_len;
	memcpy(&targets, cursor, sizeof(targets));
	if (le32toh(targets.magic) != SHIRUDO_UPATCH_UPROBE_TARGET_MAGIC ||
	    le32toh(targets.version) != SHIRUDO_UPATCH_UPROBE_TARGET_VERSION ||
	    le32toh(targets.nr_targets) != 1 || targets.reserved)
		return fail("uprobe target header mismatch");
	cursor += sizeof(targets);
	memcpy(&record, cursor, sizeof(record));
	cursor += sizeof(record);
	path_len = le32toh(record.path_len);
	build_id_len = le32toh(record.build_id_len);
	nr_offsets = le32toh(record.nr_offsets);
	if (le32toh(record.prog_idx) != 0 || path_len != strlen(path) ||
	    !build_id_len || build_id_len > SHIRUDO_UPATCH_BUILD_ID_MAX ||
	    nr_offsets != expected_offsets)
		return fail("uprobe target record mismatch");
	if ((size_t)(end - cursor) != (size_t)path_len + build_id_len +
	    (size_t)nr_offsets * sizeof(__u64) ||
	    memcmp(cursor, path, path_len) != 0)
		return fail("uprobe path or metadata length mismatch");
	cursor += path_len + build_id_len;
	for (i = 0; i < nr_offsets; i++) {
		__u64 offset;

		memcpy(&offset, cursor, sizeof(offset));
		cursor += sizeof(offset);
		offset = le64toh(offset);
		if (i && offset <= previous)
			return fail("uprobe offsets are not sorted and unique");
		previous = offset;
	}
	return cursor == end ? 0 : fail("trailing uprobe metadata");
}

int main(int argc, char **argv)
{
	struct shirudo_upatch u;
	const char *mode = "serializer";
	int rc;

	if (argc != 2 && argc != 3 && argc != 6)
		return fail("usage: test-upatch-prog-metadata <file.upatch> [mode [path pattern count]]");
	if (argc >= 3)
		mode = argv[2];

	rc = shirudo_upatch_open(argv[1], &u);
	if (rc)
		return fail("open upatch failed");

	if (strcmp(mode, "serializer") == 0) {
		rc = expect_serializer(&u);
	} else if (strcmp(mode, "cgroup-ingress") == 0) {
		rc = expect_attach(&u,
				   SHIRUDO_UPATCH_ATTACH_CGROUP_SKB_INGRESS,
				   NULL, 0);
	} else if (strcmp(mode, "cgroup-egress") == 0) {
		rc = expect_attach(&u,
				   SHIRUDO_UPATCH_ATTACH_CGROUP_SKB_EGRESS,
				   NULL, 0);
	} else if (strcmp(mode, "kprobe-override") == 0) {
		rc = expect_attach(&u, SHIRUDO_UPATCH_ATTACH_KPROBE,
				   "bpf_modify_return_test", 0);
	} else if (strcmp(mode, "fmod-ret") == 0) {
		rc = expect_attach(&u, SHIRUDO_UPATCH_ATTACH_FMOD_RET,
				   NULL, 0);
	} else if (strcmp(mode, "netfilter-ipv6-pre-routing") == 0) {
		rc = expect_attach(&u,
				   SHIRUDO_UPATCH_ATTACH_NETFILTER_IPV6_PRE_ROUTING,
				   NULL, 0);
	} else if (strcmp(mode, "uprobe-multi") == 0 && argc == 6) {
		char *end = NULL;
		__u64 count = strtoul(argv[5], &end, 10);

		if (!end || *end || count > UINT32_MAX)
			rc = fail("invalid expected uprobe offset count");
		else
			rc = expect_uprobe_multi(&u, argv[3], argv[4],
						 (__u32)count);
	} else {
		rc = fail("unknown metadata check mode");
	}

	shirudo_upatch_close(&u);
	if (rc)
		return rc;
	puts("ok");
	return 0;
}
