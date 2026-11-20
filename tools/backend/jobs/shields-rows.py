#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# jobs/shields-rows.py -- the part of jobs/shields-put that shell does not
# reach: reading and checking the catalog of shields.
#
#   shields-rows.py <catalog.json> <rows.jsonl> <put_at>
#
# Reads {"shields": [{"id": <upatch>, "package": <name>, "version":
# <version>, "reference": "oci://<registry>/<repository>:<version>",
# "manifest_digest": "sha256:<hex>", "fixes": [<advisory>, ...],
# "selector": {...}, "description": <text>}, ...]}, as tools/put-shields
# --catalog writes it, and writes one row of shirudo.shield_catalog per
# shield in ClickHouse's JSONEachRow format, with put_at, milliseconds
# since the epoch, on every row. Prints a line per shield. Each value
# follows the rule bpm build and bpm push hold it to, so that a row names
# a package bpm tree append can take.
#
# Exit status: 0; 1 when the file is refused, named on standard error,
# with nothing written; 2 for wrong usage.

import json
import re
import sys

PROG = "shields-put"
# As BPM_BUILD_MAX_FIXES, TREE_STRING_MAX and BPM_FIX_ID_CHARS of
# tools/shirudo-build/bpm.h, and the name rules of bpm-formats.rst.
MAX_FIXES = 16
MAX_TEXT = 255
MAX_DESCRIPTION = 1024
UPATCH = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,254}")
PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,126}")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,126}")
FIX = re.compile(r"[A-Za-z0-9._:-]{1,255}")
DIGEST = re.compile(r"sha256:([0-9a-f]{64})")
REFERENCE = re.compile(r"oci://([A-Za-z0-9.-]+(?::[0-9]{1,5})?)/"
                       r"((?:[A-Za-z0-9._-]+/)*([A-Za-z0-9._-]+)):([^:/]+)")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
KEYS = {"id", "package", "version", "reference", "manifest_digest", "fixes",
        "selector", "description"}


class Refused(Exception):
    pass


def unique_keys(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise Refused('the key "%s" is given twice in one object'
                          % printable(key))
        seen[key] = value
    return seen


def not_a_number(name):
    raise Refused("%s is not a JSON number" % name)


def printable(text):
    return "".join(c if c.isprintable() else "?" for c in str(text))


def parse(data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("the file is not UTF-8")
    decoder = json.JSONDecoder(object_pairs_hook=unique_keys,
                               parse_constant=not_a_number)
    try:
        return decoder.decode(text)
    except (ValueError, RecursionError):
        raise Refused("the file is not a JSON value")


def string(n, entry, key, pattern, form):
    value = entry.get(key)
    if type(value) is not str or not pattern.fullmatch(value):
        raise Refused("shield %d: %s is not %s" % (n, key, form))
    return value


def fixes_of(where, value):
    if type(value) is not list or len(value) > MAX_FIXES:
        raise Refused("%s: fixes is not an array of at most %d advisories"
                      % (where, MAX_FIXES))
    for fix in value:
        if type(fix) is not str or not FIX.fullmatch(fix):
            raise Refused("%s: the advisory %s is not 1 to %d bytes of"
                          " letters, digits, ., _, : and -"
                          % (where, printable(fix), MAX_TEXT))
    if len(set(value)) != len(value):
        raise Refused("%s: fixes names an advisory twice" % where)
    return sorted(value)


def shield_of(n, entry):
    if type(entry) is not dict:
        raise Refused("shield %d is not an object" % n)
    if set(entry) != KEYS:
        extra = sorted(set(entry) - KEYS)
        if extra:
            raise Refused('shield %d has the key "%s", which a shield does'
                          " not have" % (n, printable(extra[0])))
        raise Refused("shield %d does not have %s"
                      % (n, ", ".join(sorted(KEYS - set(entry)))))
    upatch = string(n, entry, "id", UPATCH,
                    "an upatch name: 1 to 255 of letters, digits, ., _"
                    " and -, not starting with .")
    where = "shield %s" % upatch
    package = string(n, entry, "package", PACKAGE, "a package name")
    version = string(n, entry, "version", VERSION, "a package version")
    digest = string(n, entry, "manifest_digest", DIGEST,
                    "sha256:<64 lowercase hex>")
    reference = entry["reference"]
    match = REFERENCE.fullmatch(reference) if type(reference) is str else None
    if not match or match.group(3) != package or match.group(4) != version:
        raise Refused("%s: reference is not oci://<registry>/<repository>:"
                      "<version> of package %s at %s"
                      % (where, package, printable(version)))
    if type(entry["selector"]) is not dict:
        raise Refused("%s: selector is not an object" % where)
    description = entry["description"]
    if (type(description) is not str or CONTROL.search(description)
            or len(description.encode("utf-8")) > MAX_DESCRIPTION):
        raise Refused("%s: description is not at most %d bytes of text"
                      " without a control character"
                      % (where, MAX_DESCRIPTION))
    return {
        "reference": reference,
        "id": upatch,
        "package": package,
        "version": version,
        "manifest_digest": DIGEST.fullmatch(digest).group(1),
        "fixes": fixes_of(where, entry["fixes"]),
        "selector": json.dumps(entry["selector"], sort_keys=True,
                               ensure_ascii=False, separators=(",", ":")),
        "description": description,
    }


def shields_of(doc):
    if type(doc) is not dict or set(doc) != {"shields"}:
        raise Refused('the file is not an object whose one key is "shields"')
    if type(doc["shields"]) is not list:
        raise Refused("shields is not an array")
    out, seen = [], set()
    for n, entry in enumerate(doc["shields"], 1):
        row = shield_of(n, entry)
        key = (row["reference"], row["id"])
        if key in seen:
            raise Refused("shield %s of %s is given twice"
                          % (row["id"], row["reference"]))
        seen.add(key)
        out.append(row)
    return out


def main():
    if len(sys.argv) != 4 or not sys.argv[3].isdigit():
        print("usage: shields-rows.py <catalog.json> <rows.jsonl> <put_at>",
              file=sys.stderr)
        return 2
    path, rows, put_at = sys.argv[1], sys.argv[2], int(sys.argv[3])
    try:
        with open(path, "rb") as f:
            shields = shields_of(parse(f.read()))
    except Refused as reason:
        print("%s: %s, nothing loaded" % (PROG, reason), file=sys.stderr)
        return 1
    except OSError as error:
        print("%s: cannot read %s, nothing loaded"
              % (PROG, printable(error.filename or path)), file=sys.stderr)
        return 1
    with open(rows, "w", encoding="utf-8") as f:
        for row in shields:
            f.write(json.dumps(dict(row, put_at=put_at / 1000),
                               ensure_ascii=False, separators=(",", ":")))
            f.write("\n")
    for row in shields:
        fixes = ", ".join(row["fixes"]) or "no advisory"
        print("%s: %s %s (%s)" % (PROG, row["reference"], row["id"], fixes))
    return 0


if __name__ == "__main__":
    sys.exit(main())
