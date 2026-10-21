#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0008 -- paged serializer and detailed map JSON output shape.

cd "$(dirname "$0")"
. ./test-lib.sh

H=helper/test-upatch-serializer-pages
S=../shirudo

[ -x "$H" ] || test_skip_all "serializer pages helper not built"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

test_expect_success 'paged serializer JSON exposes pages and one data object' '
	"$H"
'

test_expect_success 'upatch map prints JSON to stdout by default' '
	"$S" upatch map --json >"$WORK/maps.stdout" &&
	python3 -c '\''
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["schema"] == 1 and isinstance(doc["maps"], list)
'\'' "$WORK/maps.stdout" &&
	! "$S" upatch map --json= >/dev/null 2>&1
'

test_expect_success 'upatch map appends schema-1 NDJSON records' '
	"$S" upatch map --json="$WORK/maps.ndjson" &&
	"$S" upatch map --json="$WORK/maps.ndjson" &&
	python3 -c '\''
import json, sys
lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
assert len(lines) == 2
for line in lines:
    doc = json.loads(line)
    assert doc["schema"] == 1 and isinstance(doc["maps"], list)
'\'' "$WORK/maps.ndjson"
'

test_expect_success 'upatch map rejects removed emitter option' '
	! "$S" upatch map --emit=json >/dev/null 2>&1
'

test_done
