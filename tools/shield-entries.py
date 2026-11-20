#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# tools/shield-entries.py -- the catalog entries of a pushed package, for
# tools/put-shields --catalog: one JSON object per line for each
# [upatches.tree] entry of its Beefile, as jobs/shields-put reads them.
#
#   shield-entries.py <beefile> <reference> <manifest_digest> <version>

import json
import sys
import tomllib


def selector_of(table):
    """The entry's selector as a publication spells it: lists sorted."""
    out = {}
    for key, value in table.items():
        if isinstance(value, dict):
            out[key] = {k: sorted(v) for k, v in value.items()}
        else:
            out[key] = sorted(value)
    return out


def main():
    if len(sys.argv) != 5:
        print("usage: shield-entries.py <beefile> <reference>"
              " <manifest_digest> <version>", file=sys.stderr)
        return 2
    path, reference, digest, version = sys.argv[1:]
    try:
        with open(path, "rb") as f:
            beefile = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as error:
        print("put-shields: cannot read %s: %s" % (path, error),
              file=sys.stderr)
        return 1
    package = beefile["package"]
    for upatch in beefile.get("upatches", []):
        tree = upatch.get("tree")
        if not tree:
            continue
        print(json.dumps({
            "id": tree["id"],
            "package": package["name"],
            "version": version,
            "reference": reference,
            "manifest_digest": digest,
            "fixes": sorted(tree.get("fixes", [])),
            "selector": selector_of(tree.get("selector", {})),
            "description": package.get("description", ""),
        }, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
