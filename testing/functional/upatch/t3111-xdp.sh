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
	if [ -n "${adapter_mtu:-}" ]; then
		ip link set "$adapter" mtu "$adapter_mtu" >/dev/null 2>&1 || true
		adapter_mtu=
	fi
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

test_xdp_success 'a device without native XDP alone loads and waits for a device' '
	ip link add xdpbr type bridge && ip link set xdpbr up &&
	load "$NAME" &&
	[ -e "$B/$NAME/xdp_prog_0" ] && [ ! -e "$B/$NAME/link_0" ] &&
	"$SHIRUDO_BIN" status | grep -q "waiting for a device" &&
	before=$(wc -l </var/lib/shirudo/eventlog) &&
	"$SHIRUDO_BIN" init &&
	[ "$(wc -l </var/lib/shirudo/eventlog)" = "$before" ] &&
	unload "$NAME" &&
	[ ! -e "$B/$NAME" ]
'

test_xdp_success 'one endpoint of a host veth pair receives native XDP' '
	ip link add xdph0 index 30001 type veth peer name xdph1 index 30000 &&
	ip link set xdph0 up && ip link set xdph1 up &&
	load "$NAME" &&
	[ "$("$H" query xdph1)" -gt 0 ] &&
	[ "$("$H" query xdph0)" = 0 ] &&
	[ -e "$B/$NAME/link_0" ] && [ ! -e "$B/$NAME/link_1" ] &&
	[ -e "$B/$NAME/xdp_prog_0" ] &&
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
	"$SHIRUDO_BIN" status | grep -q "XdpCovered *WARN .*$NAME on xdpbr (no native XDP)" &&
	unload "$NAME"
'

test_xdp_success 'the VM class selects the guest adapter' '
	adapter=$(ip -o route show default | awk "{print \$5; exit}") &&
	[ -n "$adapter" ] && load "$VM_PATCH" &&
	[ "$("$H" query "$adapter")" -gt 0 ] &&
	unload "$VM_PATCH" && [ "$("$H" query "$adapter")" = 0 ]
'

test_xdp_success 'virtio_net attaches above the single-buffer MTU' '
	adapter=$(ip -o route show default | awk "{print \$5; exit}") &&
	[ -n "$adapter" ] &&
	[ "$(basename "$(readlink "/sys/class/net/$adapter/device/driver")")" = virtio_net ] &&
	adapter_mtu=$(cat "/sys/class/net/$adapter/mtu") &&
	ip link set "$adapter" mtu 9000 &&
	load "$VM_PATCH" &&
	[ "$("$H" query "$adapter")" -gt 0 ] &&
	unload "$VM_PATCH" &&
	ip link set "$adapter" mtu "$adapter_mtu" &&
	adapter_mtu=
'

test_xdp_success 'veth attaches above the single-buffer MTU' '
	ip link add xdpa index 30000 type veth peer name xdpc index 30001 &&
	ip link set xdpc mtu 9000 &&
	ip link set xdpa up && ip link set xdpc up &&
	load "$NAME" &&
	[ "$("$H" query xdpa)" -gt 0 ] &&
	unload "$NAME"
'

test_xdp_success 'a driver refusing the program fails the load as xdp_driver_refused' '
	ip link add xdpa index 30000 numrxqueues 1 type veth \
		peer name xdpc index 30001 numtxqueues 2 &&
	ip link set xdpa up && ip link set xdpc up &&
	category=$("$SHIRUDO_BIN" upatch load "$FIXTURES/$NAME.upatch" \
		--no-precheck --report=- 2>/dev/null | report_field category) &&
	[ "$category" = xdp_driver_refused ] &&
	[ ! -e "$B/$NAME" ] &&
	[ "$("$H" query xdpa)" = 0 ]
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
	category=$("$SHIRUDO_BIN" upatch load "$FIXTURES/$NAME.upatch" \
		--no-precheck --report=- 2>/dev/null | report_field category) &&
	[ "$category" = xdp_device_occupied ] &&
	[ ! -e "$B/$NAME" ] &&
	[ "$("$H" query xdpa)" = 0 ] &&
	[ "$("$H" query xdph0)" -gt 0 ] &&
	unload "$CONFLICT"
'

test_done
