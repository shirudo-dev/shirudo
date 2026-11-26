#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6160 -- the timer and reconcile services a target package ships start
# the runtime image's binary as shipped, with no drop-in, so that none of
# their runs is refused the identity pin or counts as ObjGet.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v systemctl >/dev/null 2>&1 || test_skip_all "no systemd"
RUNTIME=/run/shirudo/runtime/usr/bin/shirudo
UNITS="shirudo-keepalive shirudo-map-export shirudo-xdp-reconcile
	shirudo-bpm-repo-update shirudo-bpm-tree-sync"
W=$(mktemp -d) || test_skip_all "cannot make a scratch directory"
trap 'rm -rf "$W"' EXIT
counter() {
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
print(json.load(sys.stdin)["tamper_attempts"]["counters"][sys.argv[1]])
' "$1"
}
before=$(counter ObjGet) || test_skip_all "no tamper counters"

test_expect_success 'every shipped service starts the runtime image binary' '
	for u in $UNITS; do
		systemctl show -p ExecStart --value "$u.service" |
			grep -o "path=[^ ;]*" >"$W/$u.paths" &&
		[ -s "$W/$u.paths" ] &&
		! grep -vqxF "path=$RUNTIME" "$W/$u.paths" || return 1
	done
'

test_expect_success 'no run of them is refused the identity pin' '
	cursor=$(journalctl -n 0 --show-cursor --no-pager |
		sed -n "s/^-- cursor: //p") &&
	[ -n "$cursor" ] &&
	set -- &&
	for u in $UNITS; do
		systemctl start "$u.service" >/dev/null 2>&1 || :
		set -- "$@" -u "$u.service"
	done &&
	journalctl --after-cursor "$cursor" --no-pager -o cat "$@" \
		>"$W/journal" &&
	! grep -q "image state: Permission denied" "$W/journal"
'

test_expect_success 'the reconcile service runs to success' '
	systemctl start shirudo-xdp-reconcile.service &&
	[ "$(systemctl show -p Result --value shirudo-xdp-reconcile.service)" = success ]
'

test_expect_success 'their runs count no ObjGet' '
	[ "$(counter ObjGet)" -eq "$before" ]
'

test_done
