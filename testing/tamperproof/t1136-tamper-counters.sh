#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1136 -- the tamper counters. Every guard counts what it refuses, by
# the point of refusal, in a frozen map init pins; `shirudo status`
# lists the non-zero counters and `status --json` carries them all, so
# an operator sees an attempt and not only its failure. Each refusal
# provoked here must move its own counter and the total, root must not
# be able to reset the map, and the human report must name what moved.
# Non-destructive: every operation is one the guards refuse.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

H=helper/test-bpf-load
C=helper/test-bpf-cmd
[ -x "$H" ] || test_skip_all "test-bpf-load helper not built"
[ -x "$C" ] || test_skip_all "test-bpf-cmd helper not built"
B=/run/shirudo/bpffs
[ -e "$B/tamper" ] || test_skip_all "no tamper map pinned at $B/tamper"
W=$(mktemp -d) || test_skip_all "cannot make a scratch directory"
trap 'rm -rf "$W"' EXIT

# The counter $1 (or "total") from status --json.
counter() {
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
d = json.load(sys.stdin)["tamper_attempts"]
print(d["total"] if sys.argv[1] == "total" else d["counters"][sys.argv[1]])
' "$1"
}

# Whether counter $1 has moved past $2.
grew() {
	[ "$(counter "$1")" -gt "$2" ]
}

RENAME='
import os, sys
try:
    os.rename(sys.argv[1], sys.argv[2])
except OSError:
    pass
'

test_expect_success 'status reports the counters and all start as numbers' '
	"$SHIRUDO_BIN" status --json | python3 -c "
import json, sys
d = json.load(sys.stdin)[\"tamper_attempts\"]
assert isinstance(d[\"total\"], int)
assert all(isinstance(v, int) for v in d[\"counters\"].values())
assert \"PinRename\" in d[\"counters\"] and \"ProgAttach\" in d[\"counters\"]
assert \"LoadNotLoader\" in d[\"counters\"]
"
'

test_expect_success 'an unsigned load of a plain program moves LoadNotLoader' '
	before=$(counter LoadNotLoader) && total=$(counter total) &&
	[ "$(./$H)" = "errno=13" ] &&
	grew LoadNotLoader "$before" && grew total "$total"
'

test_expect_success 'a rename inside the bpffs moves PinRename' '
	before=$(counter PinRename) &&
	python3 -c "$RENAME" "$B/identity" "$B/t1136" &&
	[ -e "$B/identity" ] &&
	grew PinRename "$before"
'

test_expect_success 'an unlink inside the bpffs moves PinUnlink' '
	before=$(counter PinUnlink) &&
	rm -f "$B/identity" 2>/dev/null
	[ -e "$B/identity" ] &&
	grew PinUnlink "$before"
'

test_expect_success 'an unmount of the bpffs moves BpffsUmount' '
	before=$(counter BpffsUmount) &&
	umount "$B" 2>/dev/null
	mountpoint -q "$B" &&
	grew BpffsUmount "$before"
'

test_expect_success 'a link creation moves ProgAttach and a pin moves ObjPin' '
	ProgAttach=$(counter ProgAttach) && pin=$(counter ObjPin) &&
	[ "$(./$C LINK_CREATE)" = "errno=13" ] &&
	[ "$(./$C OBJ_PIN)" = "errno=13" ] &&
	grew ProgAttach "$ProgAttach" && grew ObjPin "$pin"
'

test_expect_success 'a denied tear-down command moves BpfCommand' '
	before=$(counter BpfCommand) &&
	[ "$(./$C LINK_DETACH)" = "errno=13" ] &&
	grew BpfCommand "$before"
'

test_expect_success 'root cannot reset the counters' '
	before=$(counter total) &&
	[ "$(./$C MAP_UPDATE_ELEM)" = "errno=13" ] &&
	[ "$(counter total)" -ge "$before" ]
'

test_expect_success 'the human report lists the counters that moved' '
	"$SHIRUDO_BIN" status >"$W/status" &&
	grep -q "^Tamper attempts (refused this boot):" "$W/status" &&
	grep -q "^  PinRename  *[1-9][0-9]*  rename of a pin" "$W/status" &&
	grep -q "^  BpffsUmount  *[1-9][0-9]*  unmount of the private bpffs" \
		"$W/status" &&
	! grep -q "^  none$" "$W/status"
'

test_done
