#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# jobs/labels-rows.py -- the part of jobs/labels-put that shell does not
# reach: reading and checking the label sets.
#
#   labels-rows.py <sets.json> <rows.jsonl> <put_at>
#
# Reads {"nodes": [{"node_id": <name>, "labels": {<key>: <value>, ...}},
# {"ak_name": <key>, "labels": {...}}, {"config_root": <hash>, "labels":
# {...}}, ...]} and writes one row of
# shirudo.label_sets per set, in ClickHouse's JSONEachRow format, with
# put_at, milliseconds since the epoch, on every row. Prints a line per
# set. A label is one that etc/shirudo/node.labels could hold, so that a
# set copied from that file loads as it is and a selector's key and value
# can match it.
#
# Exit status: 0; 1 when the file is refused, named on standard error,
# with nothing written; 2 for wrong usage.

import json
import re
import sys

PROG = "labels-put"
# As TREE_MAX_LABELS and TREE_STRING_MAX of util/bpm_tree.h.
MAX_LABELS = 64
MAX_TEXT = 255
NODE_ID = re.compile(r"[^\x00-\x1f\x7f]{1,255}")
AK_NAME = re.compile(r"[0-9a-f]{1,255}")
CONFIG_ROOT = re.compile(r"[0-9a-f]{64}")
NAMES = {
    "node_id": (NODE_ID, "1 to 255 characters with no control character"),
    "ak_name": (AK_NAME, "1 to 255 lowercase hex digits"),
    "config_root": (CONFIG_ROOT, "64 lowercase hex digits"),
}
CONTROL = re.compile(r"[\x00-\x1f\x7f]")


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


def text_ok(text):
    """What a node.labels line keeps of a key or value: no blank at either
    end, no control character, at most MAX_TEXT bytes."""
    return (text == text.strip() and not CONTROL.search(text)
            and len(text.encode("utf-8")) <= MAX_TEXT)


def check_label(where, key, value):
    if type(value) is not str:
        raise Refused("%s: the value of %s is not a string"
                      % (where, printable(key)))
    if not key or not text_ok(key) or "=" in key or key.startswith("#"):
        raise Refused('%s: the key "%s" is not one node.labels can hold: 1 to'
                      ' %d bytes, no "=", no "#" first, no blank at either'
                      ' end, no control character'
                      % (where, printable(key), MAX_TEXT))
    if not text_ok(value):
        raise Refused('%s: the value of %s is not one node.labels can hold:'
                      ' at most %d bytes, no blank at either end, no control'
                      ' character' % (where, printable(key), MAX_TEXT))


def node_of(n, entry):
    """The set's (by, node) from its one name."""
    if type(entry) is not dict:
        raise Refused("set %d is not an object" % n)
    extra = set(entry) - set(NAMES) - {"labels"}
    if extra:
        raise Refused('set %d has the key "%s", which is not node_id,'
                      ' ak_name, config_root or labels'
                      % (n, printable(sorted(extra)[0])))
    names = [k for k in NAMES if k in entry]
    if len(names) != 1:
        raise Refused("set %d does not name its node by exactly one of"
                      " node_id, ak_name and config_root" % n)
    by = names[0]
    node = entry[by]
    pattern, form = NAMES[by]
    if type(node) is not str or not pattern.fullmatch(node):
        raise Refused("set %d: %s is not %s" % (n, by, form))
    return by, node


def sets_of(doc):
    if type(doc) is not dict or set(doc) != {"nodes"}:
        raise Refused('the file is not an object whose one key is "nodes"')
    if type(doc["nodes"]) is not list:
        raise Refused("nodes is not an array")
    out, seen = [], set()
    for n, entry in enumerate(doc["nodes"], 1):
        by, node = node_of(n, entry)
        where = "%s %s" % (by, printable(node))
        if (by, node) in seen:
            raise Refused("%s has two sets" % where)
        seen.add((by, node))
        labels = entry.get("labels")
        if type(labels) is not dict:
            raise Refused("%s: labels is not an object" % where)
        if len(labels) > MAX_LABELS:
            raise Refused("%s: more than %d labels" % (where, MAX_LABELS))
        for key, value in labels.items():
            check_label(where, key, value)
        out.append((by, node, labels))
    return out


def count_of(n):
    if not n:
        return "cleared"
    return "1 label" if n == 1 else "%d labels" % n


def main():
    if len(sys.argv) != 4 or not sys.argv[3].isdigit():
        print("usage: labels-rows.py <sets.json> <rows.jsonl> <put_at>",
              file=sys.stderr)
        return 2
    path, rows, put_at = sys.argv[1], sys.argv[2], int(sys.argv[3])
    try:
        with open(path, "rb") as f:
            sets = sets_of(parse(f.read()))
    except Refused as reason:
        print("%s: %s, nothing loaded" % (PROG, reason), file=sys.stderr)
        return 1
    except OSError as error:
        print("%s: cannot read %s, nothing loaded"
              % (PROG, printable(error.filename or path)), file=sys.stderr)
        return 1
    with open(rows, "w", encoding="utf-8") as f:
        for by, node, labels in sets:
            f.write(json.dumps({"by": by, "node": node, "labels": labels,
                                "put_at": put_at / 1000},
                               ensure_ascii=False, separators=(",", ":")))
            f.write("\n")
    for by, node, labels in sets:
        print("%s: %s %s: %s" % (PROG, by, printable(node),
                                 count_of(len(labels))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
