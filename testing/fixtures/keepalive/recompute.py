#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# recompute.py -- recompute the keepalive example values from the fixtures
# beside it: the operation digests, the projection_root chain, the set
# hashes and the masks of tree-1.1.0.json, and with them the tree keys of
# the four node bodies. Exits non-zero on any mismatch.

import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ZEROS = "0" * 64
EMPTY_SET = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

BODY_KEYS = [
    "schema", "boot_id", "version_id", "config_root", "kernel_release",
    "image_id", "image_version", "image_root", "verdict", "cond", "flags",
    "tamper", "integrity", "tree_id", "generation", "base_seq", "last_seq",
    "base_root", "projection_root", "mask", "set_sha256", "count", "not_ok",
]
CANONICAL_KEYS = ["seq", "op", "id", "selector", "artifact"]
TAMPER_COUNTERS = 43
INTEGRITY_COUNTERS = 22
ALL_OK = 0x1555

OPERATION_DIGESTS = [
    "13b248d4a85d91150717e3e96dc9c2d7a8a43633e3b58f8f6168d408aed26c43",
    "5ce215313f29f87bfb87aa0cc65c237bf21bdc7702606e9cc29be187f950074b",
    "bd98b27dd5cfc9deeb0e4f49a7d4bd0f991762ec784be9ea838a59966d9dd0dc",
]
PROJECTION_ROOTS = [
    "04f83540c1727aefcf3c53449a99594c8fd1cc15e1466dbdbf3168cc8f9dc136",
    "a042a582b3a3d8c1b633b8ed0356e0b52f1f5aa25af85b06cc3f481562dcda93",
    "154522480ff8884daa95589e80f26f20248bbf9c192dfbb3cee04e03b4f136a1",
]
SET_1_0_0 = "6c9e113d02cd14646f617d7bba4a092b91bc3802dfdaae50e2fef7a01e0580aa"
SET_1_1_0 = "74e5bd2c665109f6d8f926af5476c266ad70ab07293ff13b1a13d0b89aa5c1bf"
FIXES = {1: ["EXAMPLE-0101"], 3: ["EXAMPLE-0101"]}

MASKS = [
    ("QA==", [1]),
    ("gA==", [2]),
    ("VA==", [1, 1, 1]),
    ("qA==", [2, 2, 2]),
    ("WdlZAA==", [1, 1, 2, 1, 3, 1, 2, 1, 1, 1, 2, 1, 0, 0, 0, 0]),
]

# The body the example pages print for node A after release 1.1.0: six
# conditions and no image keys.
PAGE_BODY_LEN = 802
PAGE_BODY_SHA256 = \
    "2e2a4ae6919b10ab71ac0f11857dadca0eb1dcc2f6c280c0c70f1a72fbf5ce59"
PAGE_COND = 0x555

VERSION_ID = "d6d918ad22ff597579e6678bef75adca84d30f9661e0b7bbdbf534eebc138c1f"
NODES = {
    "a": {
        "labels": {"role": "edge"},
        "identity": {
            "boot_id": "168d20a1-5011-4e1b-9924-d8b73c85aa4e",
            "version_id": VERSION_ID,
            "config_root": "1d8465c5b17838303fee92b3905420d2"
                           "94d2c22c576a0bdef0f69f190ed22807",
            "kernel_release": "7.4.2",
            "image_id": "fleet-os",
            "image_version": "2026.11.1",
            "image_root": "a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c"
                          "4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c",
        },
    },
    "b": {
        "labels": {"role": "core"},
        # The pages give only the ends of node B's config_root; the middle
        # is fixed here.
        "identity": {
            "boot_id": "9a6f14ea-0cc2-45e1-8e23-7b887120cf54",
            "version_id": VERSION_ID,
            "config_root": "ff2cbeff5d0e9c41a7b36f28d14ce09b"
                           "73a5182e6fc40d97b5e2a1683c0f7ff8",
            "kernel_release": "7.4.2",
            "image_id": "fleet-os",
            "image_version": "2026.11.1",
            "image_root": None,
        },
    },
}
# Release, the generation its last append published and that
# publication's head.seq.
RELEASES = [("1.0.0", 1, 1), ("1.1.0", 3, 3)]

failures = 0


def check(what, got, want):
    global failures

    if got == want:
        print(f"ok    {what}")
        return
    failures += 1
    print(f"FAIL  {what}\n        got  {got!r}\n        want {want!r}")


def compact(value):
    return json.dumps(value, separators=(",", ":"),
                      ensure_ascii=False).encode()


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def load(name):
    """Parse a fixture and check that its bytes are the compact form."""
    with open(os.path.join(HERE, name), "rb") as f:
        raw = f.read()
    value = json.loads(raw)
    check(f"{name}: compact, no trailing newline", raw, compact(value))
    return value, raw


def canonical(op):
    return compact({key: op[key] for key in CANONICAL_KEYS})


def projection_step(prev, digest):
    return sha256_hex(bytes.fromhex(prev) + bytes.fromhex(digest))


def selects(selector, labels):
    return all(labels.get(key) in values
               for key, values in selector.get("labels", {}).items())


def mask_encode(codes):
    raw = bytearray((len(codes) + 3) // 4)
    for i, code in enumerate(codes):
        raw[i // 4] |= code << (6 - 2 * (i % 4))
    return base64.b64encode(bytes(raw)).decode()


def set_sha256(loaded):
    lines = "".join(f"{payload} {name}\n"
                    for name, payload in sorted(loaded.items()))
    return sha256_hex(lines.encode())


def walk(operations, labels, head_seq):
    """The tree keys a node with these labels reports at head_seq."""
    root = ZEROS
    loaded = {}
    codes = []

    for op in operations[:head_seq]:
        if not selects(op["selector"], labels):
            codes.append(2)
            continue
        codes.append(1)
        root = projection_step(root, op["operation_digest"][len("sha256:"):])
        if op["op"] == "add":
            payload = op["artifact"]["payload_sha256"]
            loaded[op["id"]] = payload[len("sha256:"):]
        else:
            del loaded[op["id"]]
    return {
        "base_seq": 0,
        "last_seq": head_seq,
        "base_root": ZEROS,
        "projection_root": root,
        "mask": mask_encode(codes),
        "set_sha256": set_sha256(loaded),
        "count": len(loaded),
        "not_ok": 0,
    }


def check_tree(tree):
    operations = tree["operations"]
    root = ZEROS

    check("tree: top-level keys", list(tree),
          ["schema", "tree_id", "generation", "parent_manifest_digest",
           "base", "operations", "head"])
    check("tree: generation", tree["generation"], 3)
    check("tree: base.seq", tree["base"], {"seq": 0})
    check("tree: head.seq", tree["head"], {"seq": len(OPERATION_DIGESTS)})
    check("tree: operation seqs", [op["seq"] for op in operations],
          list(range(1, len(OPERATION_DIGESTS) + 1)))
    for op, want in zip(operations, OPERATION_DIGESTS):
        seq = op["seq"]
        keys = CANONICAL_KEYS + ["fixes"] * (seq in FIXES) + \
            ["operation_digest"]
        check(f"operation {seq}: keys", list(op), keys)
        check(f"operation {seq}: fixes", op.get("fixes"), FIXES.get(seq))
        digest = sha256_hex(canonical(op))
        check(f"operation {seq}: digest of the canonical form", digest, want)
        check(f"operation {seq}: operation_digest", op["operation_digest"],
              "sha256:" + digest)
        root = projection_step(root, digest)
        check(f"projection_root after {seq}, all applied", root,
              PROJECTION_ROOTS[seq - 1])


def check_sets(tree):
    payloads = [op["artifact"]["payload_sha256"][len("sha256:"):]
                for op in tree["operations"]]

    check("set_sha256 of the 1.0.0 set",
          set_sha256({"xfs-fix": payloads[0]}), SET_1_0_0)
    check("set_sha256 of the 1.1.0 set",
          set_sha256({"xfs-fix": payloads[2]}), SET_1_1_0)
    check("set_sha256 of the empty set", set_sha256({}), EMPTY_SET)


def check_masks():
    for mask, codes in MASKS:
        check(f"mask {mask}", mask_encode(codes), mask)


def check_health(name, body):
    check(f"{name}: keys", list(body), BODY_KEYS)
    check(f"{name}: schema", body["schema"], "shirudo.keepalive/1")
    check(f"{name}: verdict", body["verdict"], "ok")
    check(f"{name}: cond", body["cond"], ALL_OK)
    check(f"{name}: flags", body["flags"], 0)
    check(f"{name}: tamper", body["tamper"], [0] * TAMPER_COUNTERS)
    check(f"{name}: integrity", body["integrity"], [0] * INTEGRITY_COUNTERS)


def check_node(tree, node, release, generation, head_seq):
    name = f"node-{node}-{release}.json"
    body, raw = load(name)
    want = dict(NODES[node]["identity"])

    want.update(tree_id=tree["tree_id"], generation=generation)
    want.update(walk(tree["operations"], NODES[node]["labels"], head_seq))
    check_health(name, body)
    for key, value in want.items():
        check(f"{name}: {key}", body[key], value)
    print(f"      {name}: {len(raw)} bytes, sha256 {sha256_hex(raw)}")
    return body


def check_final(bodies):
    a = bodies[("a", "1.1.0")]
    b = bodies[("b", "1.1.0")]

    check("node A after 1.1.0: mask, root, set, count",
          [a["mask"], a["projection_root"], a["set_sha256"], a["count"]],
          ["VA==", PROJECTION_ROOTS[2], SET_1_1_0, 1])
    check("node B after 1.1.0: mask, root, set, count",
          [b["mask"], b["projection_root"], b["set_sha256"], b["count"]],
          ["qA==", ZEROS, EMPTY_SET, 0])

    page = {key: value for key, value in a.items()
            if not key.startswith("image_")}
    page["cond"] = PAGE_COND
    raw = compact(page)
    check("page body of node A after 1.1.0: length", len(raw), PAGE_BODY_LEN)
    check("page body of node A after 1.1.0: sha256", sha256_hex(raw),
          PAGE_BODY_SHA256)


def check_ops16():
    name = "ops-16.json"
    body, raw = load(name)
    codes = dict(MASKS)["WdlZAA=="]

    check_health(name, body)
    check(f"{name}: mask", body["mask"], mask_encode(codes))
    check(f"{name}: base_seq", body["base_seq"], 0)
    check(f"{name}: last_seq", body["last_seq"],
          sum(1 for code in codes if code))
    check(f"{name}: no operation reached after last_seq",
          any(codes[body["last_seq"]:]), False)
    check(f"{name}: base_root", body["base_root"], ZEROS)
    print(f"      {name}: {len(raw)} bytes, sha256 {sha256_hex(raw)}")


def main():
    tree, _ = load("tree-1.1.0.json")
    bodies = {}

    check_tree(tree)
    check_sets(tree)
    check_masks()
    for release, generation, head_seq in RELEASES:
        for node in NODES:
            bodies[(node, release)] = check_node(tree, node, release,
                                                 generation, head_seq)
    check_final(bodies)
    check_ops16()
    if failures:
        print(f"recompute: {failures} mismatches")
        return 1
    print("recompute: every value recomputes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
