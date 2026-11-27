#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6160 -- shared enforcement, which this family's runtime image selects.
# A root process that is not shirudo creates, writes, loads and pins BPF
# objects of its own, but no LSM program, whose kfuncs write the seal's
# labels, no modify-return program, which can skip every LSM, and no pin
# in shirudo's private bpffs. None of shirudo's maps, programs, links or
# pins opens for it, from userspace or from inside the kernel: bpf2's and
# seal's, which init recorded by id, and a upatch's, which shirudo
# recorded when it loaded them. A name plays no part: root's own objects
# are named shirudo_probe.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

H=helper/test-shared-bpf
C=helper/test-bpf-cmd
[ -x "$H" ] && [ -x "$C" ] || test_skip_all "test-shared-bpf helpers not built"
UPATCH_PINS=/run/shirudo/bpffs/upatches/shirudo-test-basic
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

counter() {
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
print(json.load(sys.stdin)["tamper_attempts"]["counters"][sys.argv[1]])
' "$1"
}

test_expect_success 'status reports shared enforcement' '
	"$SHIRUDO_BIN" status --json | report_field enforcement >"$WORK/mode" &&
	grep -qx shared "$WORK/mode" &&
	"$SHIRUDO_BIN" status | grep -Eq "^Enforcement: +shared$"
'

test_expect_success 'root creates, loads and pins objects of its own, named shirudo_' '
	[ "$(./$H own /sys/fs/bpf/t6160-map)" = ok ]
'

test_expect_success 'root loads no LSM or modify-return program' '
	[ "$(./$H load lsm)" = "errno=13" ] &&
	[ "$(./$H load fmodret)" = "errno=13" ]
'

test_expect_success 'an fentry program is left to the kernel' '
	[ "$(./$H load fentry)" != "errno=13" ]
'

test_expect_success 'links by id, tokens and unclassified commands stay refused' '
	[ "$(./$C LINK_GET_FD_BY_ID)" = "errno=13" ] &&
	[ "$(./$C TOKEN_CREATE)" = "errno=13" ]
'

test_expect_success 'the private bpffs lists, but its pins do not open' '
	ls /run/shirudo/bpffs | grep -qx lsm_link &&
	! cat /run/shirudo/bpffs/lsm_link >/dev/null 2>"$WORK/err" &&
	grep -q "Permission denied" "$WORK/err"
'

test_expect_success 'bpf2 and seal objects do not exist for root by id' '
	./$H objects >"$WORK/objects" &&
	grep -q "errno=2" "$WORK/objects" &&
	! grep -q "errno=13" "$WORK/objects" &&
	! grep -E "^(map|prog) [0-9]+ (shirudo_|seal_)" "$WORK/objects"
'

test_expect_success 'nor by id from a syscall program of root inside the kernel' '
	[ "$(./$H kernel-get own)" = fd ] &&
	id=$(sed -n "s/^map \([0-9]*\) errno=2$/\1/p" "$WORK/objects" | head -n 1) &&
	[ -n "$id" ] &&
	[ "$(./$H kernel-get "$id")" = "errno=2" ]
'

test_expect_success 'the programs of a upatch shirudo loads do not open' '
	./$H objects | grep "^prog " >"$WORK/before" &&
	require_loaded shirudo-test-basic &&
	./$H objects | grep "^prog " >"$WORK/after" &&
	sort "$WORK/before" >"$WORK/before.sorted" &&
	sort "$WORK/after" | comm -13 "$WORK/before.sorted" - >"$WORK/new" &&
	[ -s "$WORK/new" ] &&
	! grep -v "errno=2$" "$WORK/new"
'

test_expect_success 'root pins nothing into the private bpffs, and is counted' '
	require_loaded shirudo-test-basic &&
	verdict=$("$SHIRUDO_BIN" status --json | report_field status) &&
	before=$(counter PinEntry) &&
	[ "$(./$H pin /run/shirudo/bpffs/t6160)" = "errno=1" ] &&
	[ "$(./$H pin "$UPATCH_PINS/t6160")" = "errno=1" ] &&
	[ ! -e /run/shirudo/bpffs/t6160 ] &&
	[ ! -e "$UPATCH_PINS/t6160" ] &&
	[ "$(counter PinEntry)" -ge $((before + 2)) ] &&
	[ "$("$SHIRUDO_BIN" status --json | report_field status)" = "$verdict" ]
'

test_done
