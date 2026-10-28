#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0009 -- uprobe.multi SEC metadata resolves a standard libbpf glob to
# sorted ELF file offsets and records the target's GNU build ID.

cd "$(dirname "$0")/.."
. ./test-lib.sh

SHB=../tools/shirudo-build/shirudo-build
CHECK=helper/test-upatch-prog-metadata

command -v cc >/dev/null 2>&1 || test_skip_all "no C compiler"
command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built (make shirudo-build)"
[ -x "$CHECK" ] || test_skip_all "metadata helper not built"
[ -e ../vendor/linux/vmlinux.h ] || test_skip_all "no vendor/linux/vmlinux.h (build the tree)"
[ -e ../vendor/libbpf/bpf/bpf_helpers.h ] || test_skip_all "no vendored bpf headers"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/target.c" <<'EOF'
__attribute__((noinline, used)) int fooFunc(int value) { return value + 1; }
__attribute__((noinline, used)) int barFunc(int value) { return value + 2; }
__attribute__((noinline, used)) int notTarget(int value) { return value + 3; }
int main(void) { return fooFunc(1) + barFunc(2) + notTarget(3); }
EOF

cc -O0 -g -Wl,--build-id=sha1 -o "$WORK/target" "$WORK/target.c" ||
	test_skip_all "could not build GNU-build-ID target ELF"

# shirudo signs with ML-DSA-87 only (needs OpenSSL >= 3.5 to mint it).
openssl req -x509 -newkey ML-DSA-87 -nodes -keyout "$WORK/k.pem" \
	-outform DER -out "$WORK/c.der" -days 1 -subj "/CN=t0009" \
	>/dev/null 2>&1 || test_skip_all "openssl ML-DSA keygen failed (needs OpenSSL >= 3.5)"

case "$SHB" in
/*) B="$SHB" ;;
*)  B="$(pwd)/$SHB" ;;
esac

write_probe() {
	pattern=$1
	cat > "$WORK/probe.bpf.c" <<EOF
// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe.multi/$WORK/target:$pattern")
int probe(struct pt_regs *ctx)
{
	return 0;
}
EOF
}

test_expect_success 'one * glob assigns the program to fooFunc and barFunc' '
	write_probe "*Func" &&
	( cd .. && "$B" "$WORK/probe.bpf.c" \
		-o "$WORK/uprobe.upatch" --vmlinux vendor/linux/vmlinux.h \
		--name uprobe-multi-test --key "$WORK/k.pem" \
		--cert "$WORK/c.der" ) >/dev/null 2>&1 &&
	"$CHECK" "$WORK/uprobe.upatch" uprobe-multi \
		"$WORK/target" "*Func" 2
'

test_expect_success 'a zero-match function glob is rejected at build time' '
	write_probe "doesNotExist*" &&
	! ( cd .. && "$B" "$WORK/probe.bpf.c" \
		-o "$WORK/no-match.upatch" --vmlinux vendor/linux/vmlinux.h \
		--name uprobe-no-match --key "$WORK/k.pem" \
		--cert "$WORK/c.der" ) >"$WORK/no-match.log" 2>&1 &&
	grep -q "matched no functions" "$WORK/no-match.log"
'

test_expect_success 'comma alternation is rejected with an actionable error' '
	write_probe "fooFunc,barFunc" &&
	! ( cd .. && "$B" "$WORK/probe.bpf.c" \
		-o "$WORK/alternation.upatch" --vmlinux vendor/linux/vmlinux.h \
		--name uprobe-alternation --key "$WORK/k.pem" \
		--cert "$WORK/c.der" ) >"$WORK/alternation.log" 2>&1 &&
	grep -q "alternation are unsupported" "$WORK/alternation.log"
'

test_done
