# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# jobs/common.py -- what the *-rows.py scripts of the jobs share: JSON
# read strictly, text made safe for a message, and rows written in
# ClickHouse's JSONEachRow format.

import json


class Refused(Exception):
    pass


def printable(text):
    return "".join(c if c.isprintable() else "?" for c in str(text))


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


def utf8_text(data, what):
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("%s is not UTF-8" % what)


def strict_decoder():
    """A decoder that refuses a key given twice, NaN and Infinity."""
    return json.JSONDecoder(object_pairs_hook=unique_keys,
                            parse_constant=not_a_number)


def parse_json(data, what):
    text = utf8_text(data, what)
    try:
        return strict_decoder().decode(text)
    except (ValueError, RecursionError):
        raise Refused("%s is not a JSON value" % what)


def write_rows(path, table):
    with open(path, "w", encoding="ascii") as out:
        for row in table:
            out.write(json.dumps(row, separators=(",", ":")) + "\n")
