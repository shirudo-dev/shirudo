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
VM_PATCH=shirudo-test-xdp-vm
[ -x "$H" ] || test_skip_all "XDP helper unavailable"
command -v ip >/dev/null 2>&1 || test_skip_all "ip unavailable"
for name in "$NAME" "$CONFLICT" "$VM_PATCH"; do
	[ -s "$FIXTURES/$name.upatch" ] || test_skip_all "XDP fixture unavailable"
done

load() {
	"$SHIRUDO_BIN" upatch load "$FIXTURES/$1.upatch" --no-precheck
}

unload() {
	"$SHIRUDO_BIN" upatch unload "$FIXTURES/$1.unload.upatch" --no-precheck
}

objget_counter() {
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
print(json.load(sys.stdin)["tamper_attempts"]["counters"]["ObjGet"])
'
}

cleanup() {
	for name in "$NAME" "$CONFLICT" "$VM_PATCH"; do
		unload "$name" >/dev/null 2>&1 || true
	done
	for dev in xdph0 xdph1 xdpa xdpc xdpbr; do
		ip link del "$dev" >/dev/null 2>&1 || true
	done
	for ns in xdp-test-a xdp-test-b; do
		ip netns del "$ns" >/dev/null 2>&1 || true
	done
}
trap cleanup EXIT

test_xdp_success() {
	cleanup
	test_expect_success "$@"
	cleanup
}

test_xdp_success 'a device without native XDP alone is no attachable target' '
	ip link add xdpbr type bridge && ip link set xdpbr up &&
	status=0 &&
	report=$("$SHIRUDO_BIN" upatch load "$FIXTURES/$NAME.upatch" \
		--no-precheck --report=- 2>/dev/null) || status=$?
	[ "$status" = 1 ] &&
	[ "$(printf "%s\n" "$report" | report_field category)" = attach_target_missing ] &&
	[ ! -e "$B/$NAME" ]
'

test_xdp_success 'one endpoint of a host veth pair receives native XDP' '
	ip link add xdph0 index 30001 type veth peer name xdph1 index 30000 &&
	ip link set xdph0 up && ip link set xdph1 up &&
	load "$NAME" &&
	[ "$("$H" query xdph1)" -gt 0 ] &&
	[ "$("$H" query xdph0)" = 0 ] &&
	[ -e "$B/$NAME/link_0" ] && [ ! -e "$B/$NAME/link_1" ] &&
	before=$(wc -l </var/lib/shirudo/eventlog) &&
	"$SHIRUDO_BIN" init &&
	[ "$(wc -l </var/lib/shirudo/eventlog)" = "$before" ] &&
	[ "$("$H" query xdph1)" -gt 0 ] &&
	unload "$NAME" &&
	[ "$("$H" query xdph1)" = 0 ] &&
	ip link del xdph0
'

test_xdp_success 'a device without native XDP is skipped beside supported ones' '
	ip link add xdph0 index 30000 type veth peer name xdph1 index 30001 &&
	ip link set xdph0 up && ip link set xdph1 up &&
	ip link add xdpbr type bridge && ip link set xdpbr up &&
	load "$NAME" &&
	[ "$("$H" query xdph0)" -gt 0 ] && [ "$("$H" query xdpbr)" = 0 ] &&
	unload "$NAME"
'

test_xdp_success 'the VM class selects the guest adapter' '
	adapter=$(ip -o route show default | awk "{print \$5; exit}") &&
	[ -n "$adapter" ] && load "$VM_PATCH" &&
	[ "$("$H" query "$adapter")" -gt 0 ] &&
	unload "$VM_PATCH" && [ "$("$H" query "$adapter")" = 0 ]
'

test_xdp_success 'both host endpoints of separate cross-namespace pairs attach' '
	ip netns add xdp-test-a && ip netns add xdp-test-b &&
	ip link add xdpa type veth peer name xdpa-peer netns xdp-test-a &&
	ip link add xdpc type veth peer name xdpc-peer netns xdp-test-b &&
	ip link set xdpa up && ip link set xdpc up &&
	ip -n xdp-test-a link set xdpa-peer up &&
	ip -n xdp-test-b link set xdpc-peer up &&
	ip -n xdp-test-a link add internal0 type veth peer name internal1 &&
	ip -n xdp-test-a link set internal0 up &&
	ip -n xdp-test-a link set internal1 up &&
	load "$NAME" &&
	[ "$("$H" query xdpa)" -gt 0 ] && [ "$("$H" query xdpc)" -gt 0 ] &&
	[ -e "$B/$NAME/link_0" ] && [ -e "$B/$NAME/link_1" ] &&
	[ ! -e "$B/$NAME/link_2" ] &&
	[ "$(ip netns exec xdp-test-a "$H" query internal0)" = 0 ] &&
	[ "$(ip netns exec xdp-test-a "$H" query internal1)" = 0 ] &&
	before=$(objget_counter) && "$H" denied xdpa &&
	[ "$(objget_counter)" -gt "$before" ] &&
	unload "$NAME" &&
	[ "$("$H" query xdpa)" = 0 ] && [ "$("$H" query xdpc)" = 0 ] &&
	ip link del xdpa && ip link del xdpc &&
	ip netns del xdp-test-a && ip netns del xdp-test-b
'

test_xdp_success 'a later occupied device rolls back earlier successful links' '
	ip link add xdph0 index 31000 type veth peer name xdph1 index 31001 &&
	ip link set xdph0 up && ip link set xdph1 up &&
	load "$CONFLICT" &&
	ip link add xdpa index 30000 type veth peer name xdpc index 30001 &&
	ip link set xdpa up && ip link set xdpc up &&
	! load "$NAME" &&
	[ ! -e "$B/$NAME" ] &&
	[ "$("$H" query xdpa)" = 0 ] &&
	[ "$("$H" query xdph0)" -gt 0 ] &&
	unload "$CONFLICT"
'

test_done
