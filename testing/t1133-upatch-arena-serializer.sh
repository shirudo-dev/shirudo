#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1133 -- real target arena serializer pagination and error result.

cd "$(dirname "$0")"
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
FIXTURES=$SHIRUDO_TEST_FIXTURES_DIR
NAME=shirudo-test-arena-tree
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME/link"
SERIALIZER="/run/shirudo/bpffs/upatches/$NAME/serializers/tree_arena"
WORK=/tmp/shirudo-upatch-arena-$$
TREE_JSON=$WORK.txt
CHECK=$WORK.py
restore() {
	if [ -e "$PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -f "$TREE_JSON" "$CHECK"
}
trap restore EXIT
[ -s "$LOAD" ] || test_skip_all "missing arena-tree fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing arena-tree unload fixture"
cat >"$CHECK" <<'PY'
import re, struct, sys
text = open(sys.argv[1], encoding="utf-8").read()
assert re.search(r"Serialized pages:\s+3", text), text
parts = re.split(r"\nPage (\d+):\n", text)
assert len(parts) == 7, len(parts)
records = []
for index in range(3):
    page_index = int(parts[1 + index * 2])
    body = parts[2 + index * 2]
    assert page_index == index, page_index
    cursor = int(re.search(r"Cursor:\s+(\d+)", body).group(1))
    next_cursor = int(re.search(r"Next cursor:\s+(\d+)", body).group(1))
    done = re.search(r"Done:\s+(true|false)", body).group(1)
    assert cursor == index * 64, cursor
    assert next_cursor == (index + 1) * 64, next_cursor
    assert done == ("true" if index == 2 else "false"), done
    raw_hex = "".join(line.split(":", 1)[1].replace(" ", "")
                      for line in body.splitlines()
                      if re.match(r"\s*[0-9a-fA-F]{8}:", line))
    raw = bytes.fromhex(raw_hex)
    assert len(raw) == 64 * 16, (index, len(raw))
    records.extend(struct.unpack_from("<IIii", raw, off)
                   for off in range(0, len(raw), 16))
assert len(records) == 192, len(records)
for key, value, left, right in records:
    assert value == key * 3 + 7, (key, value)
    assert left == (2 * key + 1 if 2 * key + 1 < 192 else -1), (key, left)
    assert right == (2 * key + 2 if 2 * key + 2 < 192 else -1), (key, right)
PY
test_expect_success 'loaded arena serializer returns all pages and records' '
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &&
	[ -e "$SERIALIZER" ] &&
	"$SHIRUDO_BIN" upatch map "$NAME" tree_arena >"$TREE_JSON" 2>&1 &&
	python3 "$CHECK" "$TREE_JSON" &&
	{
		if "$SHIRUDO_BIN" upatch map "$NAME" tree_error \
			>/dev/null 2>&1; then false; fi
	}
'
test_done
