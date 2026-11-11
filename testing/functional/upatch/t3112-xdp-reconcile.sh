#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
H=./helper/test-xdp
B=/run/shirudo/bpffs/upatches
NAME=shirudo-test-xdp-virtual
CONFLICT=shirudo-test-xdp-conflict
[ -x "$H" ] || test_skip_all "XDP helper unavailable"
command -v ip >/dev/null 2>&1 || test_skip_all "ip unavailable"
for name in "$NAME" "$CONFLICT"; do
	[ -s "$FIXTURES/$name.upatch" ] || test_skip_all "XDP fixture unavailable"
done

load() {
	"$SHIRUDO_BIN" upatch load "$FIXTURES/$1.upatch" --no-precheck
}

unload() {
	"$SHIRUDO_BIN" upatch unload "$FIXTURES/$1.unload.upatch" --no-precheck
}

reconcile() {
	"$SHIRUDO_BIN" upatch reconcile
}

add_pair() {
	ip link add "$1" index "$2" type veth peer name "$3" index "$4" &&
		ip link set "$1" up && ip link set "$3" up
}

cleanup() {
	for name in "$NAME" "$CONFLICT"; do
		unload "$name" >/dev/null 2>&1 || true
	done
	for dev in xdpa xdpb xdpc xdpd xdpe xdpf; do
		ip link del "$dev" >/dev/null 2>&1 || true
	done
	ip netns del xdp-test-a >/dev/null 2>&1 || true
}
trap cleanup EXIT

test_xdp_success() {
	cleanup
	test_expect_success "$@"
}

test_xdp_success 'a pass with no XDP upatch does nothing' '
	reconcile
'

test_xdp_success 'an upatch with no device yet attaches when one appears' '
	load "$NAME" &&
	[ -e "$B/$NAME/xdp_prog_0" ] && [ ! -e "$B/$NAME/link_0" ] &&
	"$SHIRUDO_BIN" upatch list | grep -q "$NAME" &&
	"$SHIRUDO_BIN" upatch get "$NAME" >/dev/null &&
	add_pair xdpa 30000 xdpb 30001 &&
	reconcile &&
	[ -e "$B/$NAME/link_0" ] &&
	[ "$("$H" query xdpa)" -gt 0 ]
'

test_xdp_success 'a device added after load is attached, once' '
	add_pair xdpa 30000 xdpb 30001 &&
	load "$NAME" &&
	add_pair xdpc 30010 xdpd 30011 &&
	[ "$("$H" query xdpc)" = 0 ] &&
	"$SHIRUDO_BIN" status | grep -q "XdpCovered *WARN .*$NAME on xdpc (not attached)" &&
	reconcile &&
	[ "$("$H" query xdpc)" -gt 0 ] &&
	[ "$("$H" query xdpd)" = 0 ] &&
	! "$SHIRUDO_BIN" status | grep -q "XdpCovered *WARN" &&
	[ -e "$B/$NAME/link_1" ] && [ ! -e "$B/$NAME/link_2" ] &&
	before=$(wc -l </var/lib/shirudo/eventlog) &&
	pins=$(ls "$B/$NAME" | wc -l) &&
	reconcile &&
	[ "$(wc -l </var/lib/shirudo/eventlog)" = "$before" ] &&
	[ "$(ls "$B/$NAME" | wc -l)" = "$pins" ]
'

test_xdp_success 'a device another program occupies is left alone' '
	add_pair xdpa 30000 xdpb 30001 &&
	load "$NAME" &&
	ip link del xdpa &&
	add_pair xdpc 30010 xdpd 30011 &&
	load "$CONFLICT" &&
	id=$("$H" query xdpc) && [ "$id" -gt 0 ] &&
	out=$(reconcile 2>&1) &&
	[ "$("$H" query xdpc)" = "$id" ] &&
	! printf "%s\n" "$out" | grep -q "attach xdpc" &&
	! ls "$B/$NAME" | grep -q "^link_" &&
	"$SHIRUDO_BIN" status |
		grep -q "XdpCovered *WARN .*$NAME on xdpc (another XDP program attached)" &&
	unload "$CONFLICT" &&
	reconcile &&
	[ -e "$B/$NAME/link_0" ] &&
	[ "$("$H" query xdpc)" -gt 0 ] &&
	! "$SHIRUDO_BIN" status | grep -q "XdpCovered *WARN"
'

test_xdp_success 'a gone device loses its pin and no live index is reused' '
	add_pair xdpa 30000 xdpb 30001 &&
	add_pair xdpc 30010 xdpd 30011 &&
	load "$NAME" &&
	[ -e "$B/$NAME/link_0" ] && [ -e "$B/$NAME/link_1" ] &&
	ip link del xdpa &&
	"$SHIRUDO_BIN" status --check &&
	"$SHIRUDO_BIN" init &&
	add_pair xdpe 30020 xdpf 30021 &&
	reconcile &&
	[ ! -e "$B/$NAME/link_0" ] &&
	[ -e "$B/$NAME/link_1" ] && [ -e "$B/$NAME/link_2" ] &&
	[ "$("$H" query xdpc)" -gt 0 ] &&
	[ "$("$H" query xdpe)" -gt 0 ]
'

test_xdp_success 'a pass after unload leaves nothing behind' '
	add_pair xdpa 30000 xdpb 30001 &&
	load "$NAME" &&
	unload "$NAME" &&
	reconcile &&
	[ ! -e "$B/$NAME" ] &&
	[ "$("$H" query xdpa)" = 0 ]
'

test_xdp_success 'a veth end moved away keeps its link and the host end attaches' '
	add_pair xdpa 30000 xdpb 30001 &&
	load "$NAME" &&
	[ "$("$H" query xdpa)" -gt 0 ] && [ "$("$H" query xdpb)" = 0 ] &&
	ip netns add xdp-test-a &&
	ip link set xdpa netns xdp-test-a &&
	reconcile &&
	[ "$(ip netns exec xdp-test-a "$H" query xdpa)" -gt 0 ] &&
	[ "$("$H" query xdpb)" -gt 0 ]
'

test_xdp_success 'a driver refusing one device warns, spares the others and shows in status' '
	add_pair xdpa 30000 xdpb 30001 &&
	load "$NAME" &&
	ip link add xdpc index 30010 numrxqueues 1 type veth \
		peer name xdpd index 30011 numtxqueues 2 &&
	ip link set xdpc up && ip link set xdpd up &&
	add_pair xdpe 30020 xdpf 30021 &&
	out=$(reconcile 2>&1) &&
	[ "$("$H" query xdpc)" = 0 ] &&
	[ "$("$H" query xdpe)" -gt 0 ] &&
	printf "%s\n" "$out" | grep -q "attach xdpc" &&
	"$SHIRUDO_BIN" status | grep -q "XdpCovered *WARN .*$NAME on xdpc (no native XDP)"
'

test_xdp_success 'an unload racing a pass is not tampering' '
	add_pair xdpa 30000 xdpb 30001 &&
	(
		i=0
		while [ "$i" -lt 30 ]; do
			load "$NAME" >/dev/null 2>&1
			unload "$NAME" >/dev/null 2>&1
			i=$((i + 1))
		done
	) &
	churn=$!
	bad=0
	while kill -0 "$churn" 2>/dev/null; do
		report=$("$SHIRUDO_BIN" upatch reconcile --report=- 2>/dev/null) || bad=1
		case $report in *tampered*) bad=1 ;; esac
	done
	wait "$churn"
	[ "$bad" = 0 ]
'

test_done
