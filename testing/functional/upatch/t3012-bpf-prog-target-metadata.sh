#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3012 -- a program attaching to a program of another upatch records that
# upatch, its payload and the program in the signed metadata.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

SHB=../tools/shirudo-build/shirudo-build
CHECK=helper/test-upatch-prog-metadata

command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built (make shirudo-build)"
[ -x "$CHECK" ] || test_skip_all "metadata helper not built"
[ -e ../vendor/linux/vmlinux.h ] || test_skip_all "no vendor/linux/vmlinux.h (build the tree)"
[ -e ../vendor/libbpf/bpf/bpf_helpers.h ] || test_skip_all "no vendored bpf headers"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

openssl req -x509 -newkey ML-DSA-87 -nodes -keyout "$WORK/k.pem" \
	-outform DER -out "$WORK/c.der" -days 1 -subj "/CN=t3012" \
	>/dev/null 2>&1 || test_skip_all "openssl ML-DSA keygen failed (needs OpenSSL >= 3.5)"

case "$SHB" in
/*) B="$SHB" ;;
*)  B="$(pwd)/$SHB" ;;
esac

build() {
	( cd .. && "$B" "$@" --vmlinux vendor/linux/vmlinux.h \
		--key "$WORK/k.pem" --cert "$WORK/c.der" )
}

cat > "$WORK/missing.bpf.c" <<'EOF'
// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/no_such_program")
int BPF_PROG(missing)
{
	return 0;
}
EOF

test_expect_success 'the target is built with its object' '
	build testing/fixtures/basic.bpf.c -o "$WORK/target.upatch" \
		--name t3012-target --emit-artifacts >/dev/null 2>&1 &&
	[ -s "$WORK/target.o" ]
'

test_expect_success 'the fentry program records the target upatch and program' '
	build testing/fixtures/bpf-prog-fentry.bpf.c -o "$WORK/fentry.upatch" \
		--name t3012-fentry --attach-upatch "$WORK/target.upatch" \
		--attach-object "$WORK/target.o" >/dev/null 2>&1 &&
	"$CHECK" "$WORK/fentry.upatch" bpf-prog "$WORK/target.upatch" \
		shirudo_test_basic 0
'

test_expect_success 'a target object is required with a target upatch' '
	! build testing/fixtures/bpf-prog-fentry.bpf.c -o "$WORK/no-object.upatch" \
		--name t3012-no-object --attach-upatch "$WORK/target.upatch" \
		>"$WORK/no-object.log" 2>&1 &&
	grep -q "go together" "$WORK/no-object.log"
'

test_expect_success 'a function the target does not have is refused' '
	! build "$WORK/missing.bpf.c" -o "$WORK/missing.upatch" \
		--name t3012-missing --attach-upatch "$WORK/target.upatch" \
		--attach-object "$WORK/target.o" >"$WORK/missing.log" 2>&1 &&
	grep -q "no program attaches" "$WORK/missing.log"
'

test_done
