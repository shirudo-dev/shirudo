#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./test-lib.sh

SHB="$(pwd)/../tools/shirudo-build/shirudo-build"
CHECK=helper/test-upatch-prog-metadata
[ -x "$SHB" ] || test_skip_all "shirudo-build not built"
[ -x "$CHECK" ] || test_skip_all "metadata helper not built"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

openssl req -x509 -newkey ML-DSA-87 -nodes -keyout "$WORK/k.pem" \
	-outform DER -out "$WORK/c.der" -days 1 -subj /CN=t3012 \
	>/dev/null 2>&1 || test_skip_all "OpenSSL ML-DSA unavailable"

build_xdp() {
	cat >"$WORK/xdp.bpf.c" <<-EOF
	// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
	#include "vmlinux.h"
	#include <bpf/bpf_helpers.h>
	char _license[] SEC("license") = "Dual BSD/GPL";
	SEC("$1")
	int pass(struct xdp_md *ctx) { return XDP_PASS; }
	EOF
	(cd .. && "$SHB" "$WORK/xdp.bpf.c" -o "$WORK/xdp.upatch" \
		--name xdp --emit-artifacts --vmlinux vendor/linux/vmlinux.h \
		--key "$WORK/k.pem" --cert "$WORK/c.der") >"$WORK/log" 2>&1
}

build_pair() {
	cat >"$WORK/pair.bpf.c" <<-EOF
	// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
	#include "vmlinux.h"
	#include <bpf/bpf_helpers.h>
	char _license[] SEC("license") = "Dual BSD/GPL";
	SEC("$1")
	int first(struct xdp_md *ctx) { return XDP_PASS; }
	SEC("$2")
	int second(struct xdp_md *ctx) { return XDP_PASS; }
	EOF
	(cd .. && "$SHB" "$WORK/pair.bpf.c" -o "$WORK/pair.upatch" \
		--name pair --emit-artifacts --vmlinux vendor/linux/vmlinux.h \
		--key "$WORK/k.pem" --cert "$WORK/c.der") >"$WORK/log" 2>&1
}

check_masks() {
	for mask in $(seq 1 31); do
		if [ $((mask & 4)) -ne 0 ]; then
			! build_xdp "xdp/$mask" || return 1
			continue
		fi
		build_xdp "xdp/$mask" &&
		"$CHECK" "$WORK/xdp.upatch" xdp "$mask" || return 1
	done
}

check_rejections() {
	for section in xdp xdp/ xdp/0 xdp/32 xdp/0x1 xdp/+1 xdp/eth0 \
		xdp/18446744073709551616 xdp.frags xdp/devmap xdp/cpumap; do
		if build_xdp "$section"; then
			return 1
		fi
	done
}

test_expect_success 'every class mask survives signing and parsing, and bit 4 fails' '
	check_masks
'

test_expect_success 'an object input retains the signed XDP selection' '
	build_xdp xdp/27 &&
	(cd .. && "$SHB" "$WORK/xdp.o" -o "$WORK/object.upatch" \
		--name xdp --key "$WORK/k.pem" --cert "$WORK/c.der") &&
	"$CHECK" "$WORK/object.upatch" xdp 27
'

test_expect_success 'missing, malformed and unsupported masks and variants fail' '
	check_rejections
'

test_expect_success 'programs of one upatch with disjoint classes build' '
	build_pair xdp/1 xdp/2
'

test_expect_success 'programs of one upatch sharing a class are refused' '
	! build_pair xdp/3 xdp/2 &&
	grep -q "selects a device class another XDP program" "$WORK/log"
'

test_done
