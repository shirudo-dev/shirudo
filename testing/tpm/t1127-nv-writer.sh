#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard
[ -x helper/test-nv-cphash ] ||
	test_skip_all "test-nv-cphash not built"
W=$(mktemp -d)
trap 'rm -f "$W/status.json" "$W/cphash.log"; rmdir "$W"' EXIT HUP INT TERM

test_expect_success 'kernel signatures enforce nonce and command binding on the vTPM' '
	before=$("$SHIRUDO_BIN" status --json |
		python3 -c "import json,sys; print(json.load(sys.stdin)[\"tpm\"][\"chain\"])") &&
	./helper/test-nv-cphash >"$W/cphash.log" &&
	grep -qx "PolicySigned: replay and corruption rejected; value unchanged" "$W/cphash.log" &&
	grep -qx "cpHash: authorized A; rejected B unchanged; extended A; scratch index removed" \
		"$W/cphash.log" &&
	"$SHIRUDO_BIN" status --json >"$W/status.json" &&
	after=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[\"tpm\"][\"chain\"])" \
		"$W/status.json") &&
	[ "$before" = "$after" ]
'

test_done
