#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Variants of the stored output that jobs/tree-ingest must load: a
# document without fixes, one whose first operation has a malformed
# fixes, and a first publication, without a parent, printed over many
# lines with a selector of several keys and two advisories.

set -eu

test=$(cd "$(dirname "$0")" && pwd)
job=$test/../jobs/tree-ingest
show=$test/tree-show-1.1.0.json

sed -e 's/"tree_id":"fleet-base"/"tree_id":"no-fixes"/' \
    -e 's/,"fixes":\["EXAMPLE-0101"\]//g' "$show" |
	"$job" --input - 2>&1

sed -e 's/"tree_id":"fleet-base"/"tree_id":"bad-fixes"/' \
    -e 's/"fixes":\["EXAMPLE-0101"\]/"fixes":"EXAMPLE-0101"/' "$show" |
	"$job" --input - 2>&1

sed -e 's/"tree_id":"fleet-base"/"tree_id":"mixed-fixes"/' \
    -e 's/"fixes":\["EXAMPLE-0101"\]/"fixes":["EXAMPLE-0101",101]/' "$show" |
	"$job" --input - 2>&1

"$job" --input - 2>&1 <<'END'

{
  "manifest_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  "document": {
    "schema": 1,
    "tree_id": "first.tree",
    "generation": 1,
    "base": {"seq": 0},
    "operations": [
      {
        "seq": 1,
        "op": "add",
        "id": "xfs-fix",
        "selector": {
          "architecture": ["x86_64", "aarch64"],
          "kernel_release_prefix": [ "7.4." ],
          "labels": {"role": ["edge"], "site": ["café \"1\""]}
        },
        "artifact": {
          "repository": "oci://registry.example.com/shirudo/first",
          "manifest_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
          "layer_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
          "payload_sha256": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
        },
        "fixes": ["EXAMPLE-0202", "EXAMPLE-0101", "EXAMPLE-0202"],
        "a_key_of_a_later_shirudo": [1, 2.5, null],
        "operation_digest": "sha256:5555555555555555555555555555555555555555555555555555555555555555"
      }
    ],
    "head": {"seq": 1}
  }
}
END
