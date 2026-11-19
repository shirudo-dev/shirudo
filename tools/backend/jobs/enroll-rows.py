#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# jobs/enroll-rows.py -- the part of jobs/enroll-put that shell does not
# reach: reading and checking a builder's bindings against the ones
# shirudo.enrollments already holds.
#
#   enroll-rows.py <bindings.json> <enrolled.jsonl> <rows.jsonl>
#
# Reads {"source": <builder>, "nodes": [{"ak_name": <name>, "ek_name":
# <name>, "node_id": <name>}, ...]}, where ek_name and node_id may be left
# out, and the enrollments already loaded, one JSONEachRow object of
# ak_name, ek_name and node_id per key. Writes one row per binding, with
# new set to 1 for a key not enrolled yet, and prints a line per binding.
# A key is bound once: a binding that differs from the one loaded is
# refused.
#
# Exit status: 0; 1 when the file is refused, named on standard error,
# with nothing written; 2 for wrong usage.

import json
import re
import sys

PROG = "enroll-put"
# 000b, TPM_ALG_SHA256, and the SHA-256 of the public area, as
# shirudo attest and shirudo-quote-check write a name.
TPM_NAME = re.compile(r"000b[0-9a-f]{64}")
TEXT = re.compile(r"[^\x00-\x1f\x7f]{1,255}")
KEYS = {"ak_name", "ek_name", "node_id"}


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
    return "".join(c if c.isprintable() else "?" for c in text)


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


def name_of(where, entry, key):
    """The binding's TPM name under key, "" for an ek_name left out."""
    name = entry.get(key, "")
    if key == "ek_name" and key not in entry:
        return name
    if type(name) is not str or not TPM_NAME.fullmatch(name):
        raise Refused("%s: %s is not 000b and 64 lowercase hex digits"
                      % (where, key))
    return name


def binding_of(n, entry):
    where = "binding %d" % n
    if type(entry) is not dict:
        raise Refused("%s is not an object" % where)
    extra = set(entry) - KEYS
    if extra:
        raise Refused('%s has the key "%s", which is not ak_name, ek_name'
                      ' or node_id' % (where, printable(sorted(extra)[0])))
    if "ak_name" not in entry:
        raise Refused("%s has no ak_name" % where)
    ak_name = name_of(where, entry, "ak_name")
    ek_name = name_of(where, entry, "ek_name")
    node_id = entry.get("node_id", "")
    if "node_id" in entry and (type(node_id) is not str
                               or not TEXT.fullmatch(node_id)):
        raise Refused("%s: node_id is not 1 to 255 characters with no"
                      " control character" % where)
    return ak_name, ek_name, node_id


def bindings_of(doc):
    if type(doc) is not dict or set(doc) != {"source", "nodes"}:
        raise Refused('the file is not an object whose keys are "source"'
                      ' and "nodes"')
    source = doc["source"]
    if type(source) is not str or not TEXT.fullmatch(source):
        raise Refused("source is not 1 to 255 characters with no control"
                      " character")
    if type(doc["nodes"]) is not list:
        raise Refused("nodes is not an array")
    out, seen = [], set()
    for n, entry in enumerate(doc["nodes"], 1):
        binding = binding_of(n, entry)
        if binding[0] in seen:
            raise Refused("%s is bound twice" % binding[0])
        seen.add(binding[0])
        out.append(binding)
    return source, out


def enrolled_of(path):
    enrolled = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            enrolled[row["ak_name"]] = (row["ak_name"], row["ek_name"],
                                        row["node_id"])
    return enrolled


def shown(binding):
    ak_name, ek_name, node_id = binding
    return "ek_name %s, node_id %s" % (ek_name or "none",
                                       printable(node_id) or "none")


def check_against(bindings, enrolled):
    """Refuse a key bound otherwise before; return the new ones."""
    new = set()
    for binding in bindings:
        before = enrolled.get(binding[0])
        if before is None:
            new.add(binding[0])
        elif before != binding:
            raise Refused("%s is enrolled with %s, not %s"
                          % (binding[0], shown(before), shown(binding)))
    return new


def main():
    if len(sys.argv) != 4:
        print("usage: enroll-rows.py <bindings.json> <enrolled.jsonl>"
              " <rows.jsonl>", file=sys.stderr)
        return 2
    path, enrolled_path, rows = sys.argv[1:]
    try:
        with open(path, "rb") as f:
            source, bindings = bindings_of(parse(f.read()))
        new = check_against(bindings, enrolled_of(enrolled_path))
    except Refused as reason:
        print("%s: %s, nothing loaded" % (PROG, reason), file=sys.stderr)
        return 1
    except OSError as error:
        print("%s: cannot read %s, nothing loaded"
              % (PROG, printable(error.filename or path)), file=sys.stderr)
        return 1
    with open(rows, "w", encoding="utf-8") as f:
        for ak_name, ek_name, node_id in bindings:
            f.write(json.dumps({"ak_name": ak_name, "ek_name": ek_name,
                                "node_id": node_id, "source": source,
                                "new": int(ak_name in new)},
                               ensure_ascii=False, separators=(",", ":")))
            f.write("\n")
    for binding in bindings:
        state = "enrolled" if binding[0] in new else "already enrolled"
        print("%s: %s (%s): %s" % (PROG, binding[0], shown(binding), state))
    return 0


if __name__ == "__main__":
    sys.exit(main())
