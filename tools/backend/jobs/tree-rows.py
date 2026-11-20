#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# jobs/tree-rows.py -- turn the output of `shirudo bpm tree show --walk`,
# read from standard input, into the rows jobs/tree-ingest inserts. It is
# the part of that job shell does not reach: parsing JSON.
#
#   tree-rows.py <directory>
#
# For the k-th segment, oldest first, writes <k>.pub.jsonl, <k>.ops.jsonl
# and <k>.fixes.jsonl into the directory, in ClickHouse's JSONEachRow
# format, and segments.tsv with k, generation, manifest digest and the
# number of operations and fixes of each, and prints the tree_id. Input
# that is not in the expected shape is refused with exit status 1 before
# anything is written. Nothing is verified here: `bpm tree show` has done
# that.

import json
import os
import re
import sys

from common import Refused, strict_decoder, utf8_text, write_rows

PROG = "tree-ingest"
DIGEST = re.compile(r"sha256:([0-9a-f]{64})")
ROOT = re.compile(r"[0-9a-f]{64}")
TREE_ID = re.compile(r"[A-Za-z0-9._-]{1,255}")
ZERO_ROOT = "0" * 64
UINT64_MAX = 2**64 - 1


def member(obj, key, kind, where):
    if key not in obj:
        raise Refused("%s has no %s" % (where, key))
    return typed(obj[key], kind, "%s of %s" % (key, where))


def typed(value, kind, what):
    if kind is int:
        if type(value) is not int or not 0 <= value <= UINT64_MAX:
            raise Refused("%s is not an unsigned 64-bit integer" % what)
    elif type(value) is not kind:
        names = {str: "a string", dict: "an object", list: "an array"}
        raise Refused("%s is not %s" % (what, names[kind]))
    return value


def digest(obj, key, where):
    match = DIGEST.fullmatch(member(obj, key, str, where))
    if not match:
        raise Refused('%s of %s is not "sha256:" and 64 lowercase hex digits'
                      % (key, where))
    return match.group(1)


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def fixes_of(operation, seq):
    """The advisory IDs of an operation; a malformed list costs only itself."""
    if "fixes" not in operation:
        return []
    fixes = operation["fixes"]
    if type(fixes) is not list or any(type(i) is not str for i in fixes):
        print("%s: operation %d: fixes is not an array of strings, "
              "loaded without fixes" % (PROG, seq), file=sys.stderr)
        return []
    return sorted(set(fixes))


def segment_base(doc):
    """base.seq, the predecessor's manifest digest and history_root there."""
    base = member(doc, "base", dict, "the document")
    base_seq = member(base, "seq", int, "base")
    if base_seq == 0:
        for key in ("segment_manifest_digest", "history_root"):
            if key in base:
                raise Refused("base has %s but its seq is 0" % key)
        return 0, "", ZERO_ROOT
    previous = digest(base, "segment_manifest_digest", "base")
    root = member(base, "history_root", str, "base")
    if not ROOT.fullmatch(root):
        raise Refused("history_root of base is not 64 lowercase hex digits")
    return base_seq, previous, root


def rows(show):
    typed(show, dict, "the input")
    manifest_digest = digest(show, "manifest_digest", "the input")
    doc = member(show, "document", dict, "the input")

    if member(doc, "schema", int, "the document") != 1:
        raise Refused("schema of the document is not 1")
    tree_id = member(doc, "tree_id", str, "the document")
    if not TREE_ID.fullmatch(tree_id):
        raise Refused("tree_id of the document is not 1 to 255 characters "
                      "of [A-Za-z0-9._-]")
    generation = member(doc, "generation", int, "the document")
    if generation < 1:
        raise Refused("generation of the document is 0")
    parent = ""
    if "parent_manifest_digest" in doc:
        parent = digest(doc, "parent_manifest_digest", "the document")
    base_seq, previous, history_root = segment_base(doc)
    head = member(doc, "head", dict, "the document")
    head_seq = member(head, "seq", int, "head")
    if head_seq < base_seq:
        raise Refused("seq of head is below base.seq")

    pub = {
        "tree_id": tree_id,
        "generation": generation,
        "manifest_digest": manifest_digest,
        "parent_manifest_digest": parent,
        "head_seq": head_seq,
        "segment_base_seq": base_seq,
        "segment_manifest_digest": previous,
        "history_root": history_root,
    }
    ops = []
    fixes = []
    seen = set()
    for n, operation in enumerate(member(doc, "operations", list,
                                         "the document"), 1):
        where = "operation %d of the document" % n
        typed(operation, dict, where)
        seq = member(operation, "seq", int, where)
        if seq in seen:
            raise Refused("seq of %s is used twice" % where)
        if not base_seq < seq <= head_seq:
            raise Refused("seq of %s is not above base.seq and at most "
                          "the seq of head" % where)
        seen.add(seq)
        where = "the operation with seq %d" % seq
        op = member(operation, "op", str, where)
        if op not in ("add", "delete"):
            raise Refused("op of %s is neither add nor delete" % where)
        op_id = member(operation, "id", str, where)
        selector = member(operation, "selector", dict, where)
        artifact = member(operation, "artifact", dict, where)
        ops.append({
            "tree_id": tree_id,
            "seq": seq,
            "op": op,
            "id": op_id,
            "selector": compact(selector),
            "repository": member(artifact, "repository", str,
                                 "artifact of " + where),
            "manifest_digest": digest(artifact, "manifest_digest",
                                      "artifact of " + where),
            "layer_digest": digest(artifact, "layer_digest",
                                   "artifact of " + where),
            "payload_sha256": digest(artifact, "payload_sha256",
                                     "artifact of " + where),
            "operation_digest": digest(operation, "operation_digest", where),
        })
        for advisory in fixes_of(operation, seq):
            fixes.append({
                "tree_id": tree_id,
                "seq": seq,
                "id": op_id,
                "advisory": advisory,
                "source": "fixes",
            })
    if base_seq > 0 and not ops:
        raise Refused("the document has no operations but its base.seq "
                      "is above 0")
    return pub, ops, fixes


def follows(pub, prev, k):
    """A walk's segment k (from 1) must continue segment k - 1 exactly."""
    where = "segment %d of the walk" % k
    if prev is None:
        if pub["segment_base_seq"] != 0:
            raise Refused("%s has base.seq %d: the walk does not reach "
                          "base.seq 0" % (where, pub["segment_base_seq"]))
        return
    if pub["tree_id"] != prev["tree_id"]:
        raise Refused("tree_id of %s is not that of segment %d"
                      % (where, k - 1))
    if pub["segment_base_seq"] != prev["head_seq"]:
        raise Refused("base.seq of %s is not the seq of head of segment %d"
                      % (where, k - 1))
    if pub["segment_manifest_digest"] != prev["manifest_digest"]:
        raise Refused("segment_manifest_digest of %s is not the manifest "
                      "digest of segment %d" % (where, k - 1))
    if pub["generation"] <= prev["generation"]:
        raise Refused("generation of %s is not above that of segment %d"
                      % (where, k - 1))


def walk(shows):
    segments = []
    prev = None
    for k, show in enumerate(shows, 1):
        try:
            segment = rows(show)
        except Refused as reason:
            if len(shows) == 1:
                raise
            raise Refused("segment %d of the walk: %s" % (k, reason))
        follows(segment[0], prev, k)
        prev = segment[0]
        segments.append(segment)
    return segments


def parse(data):
    text = utf8_text(data, "it")
    decoder = strict_decoder()
    shows = []
    end = 0
    while True:
        start = len(text) - len(text[end:].lstrip(" \t\r\n"))
        if start == len(text) and shows:
            return shows
        try:
            show, end = decoder.raw_decode(text, start)
        except (ValueError, RecursionError):
            raise Refused("it is not a JSON value")
        shows.append(show)


def main():
    if len(sys.argv) != 2:
        print("usage: tree-rows.py <directory>", file=sys.stderr)
        return 2
    try:
        segments = walk(parse(sys.stdin.buffer.read()))
    except Refused as reason:
        print("%s: input refused: %s" % (PROG, reason), file=sys.stderr)
        return 1
    with open(os.path.join(sys.argv[1], "segments.tsv"), "w",
              encoding="ascii") as out:
        for k, (pub, ops, fixes) in enumerate(segments, 1):
            path = os.path.join(sys.argv[1], "%d." % k)
            write_rows(path + "pub.jsonl", [pub])
            write_rows(path + "ops.jsonl", ops)
            write_rows(path + "fixes.jsonl", fixes)
            out.write("%d\t%d\t%s\t%d\t%d\n" % (k, pub["generation"],
                                                 pub["manifest_digest"],
                                                 len(ops), len(fixes)))
    print(segments[0][0]["tree_id"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
