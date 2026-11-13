#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3007 -- uprobe, uretprobe, uprobe.multi and uretprobe.multi SEC
# metadata, sleepable forms included, resolves a function, a function and
# offset, a raw file offset or a standard libbpf glob to ELF file offsets
# and records the target's GNU build ID.

cd "$(dirname "$0")/../.."
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
	-outform DER -out "$WORK/c.der" -days 1 -subj "/CN=t3006" \
	>/dev/null 2>&1 || test_skip_all "openssl ML-DSA keygen failed (needs OpenSSL >= 3.5)"

case "$SHB" in
/*) B="$SHB" ;;
*)  B="$(pwd)/$SHB" ;;
esac

write_probe() {
	pattern=$1
	sec=${2:-uprobe.multi/$WORK/target:$pattern}
	cat > "$WORK/probe.bpf.c" <<EOF
// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("$sec")
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

test_expect_success 'a uretprobe.multi glob records the return kind' '
	write_probe "*Func" "uretprobe.multi/$WORK/target:*Func" &&
	( cd .. && "$B" "$WORK/probe.bpf.c" \
		-o "$WORK/uretprobe.upatch" --vmlinux vendor/linux/vmlinux.h \
		--name uretprobe-multi-test --key "$WORK/k.pem" \
		--cert "$WORK/c.der" ) >/dev/null 2>&1 &&
	"$CHECK" "$WORK/uretprobe.upatch" uretprobe-multi \
		"$WORK/target" "*Func" 2
'

refused() {
	write_probe "" "$1" &&
	! ( cd .. && "$B" "$WORK/probe.bpf.c" \
		-o "$WORK/refused.upatch" --vmlinux vendor/linux/vmlinux.h \
		--name uprobe-refused --key "$WORK/k.pem" \
		--cert "$WORK/c.der" ) >"$WORK/refused.log" 2>&1 &&
	grep -q "unsupported uprobe section" "$WORK/refused.log"
}

test_expect_success 'a uprobe without a binary is refused' '
	refused "uprobe"
'

# build_probe <name> <section>: build the probe into $WORK/<name>.upatch.
build_probe() {
	write_probe "" "$2" &&
	( cd .. && "$B" "$WORK/probe.bpf.c" \
		-o "$WORK/$1.upatch" --vmlinux vendor/linux/vmlinux.h \
		--name "$1" --key "$WORK/k.pem" \
		--cert "$WORK/c.der" ) >"$WORK/$1.log" 2>&1
}

# check_probe <name> <mode> <target> <entry offset> <file offset>
check_probe() {
	"$CHECK" "$WORK/$1.upatch" "$2" "$WORK/target" "$3" "$4" >"$WORK/$1.out" &&
	[ "$(head -n 1 "$WORK/$1.out")" = "$5" ]
}

test_expect_success 'a uprobe on a function records its one file offset' '
	build_probe uprobe-func "uprobe/$WORK/target:fooFunc" &&
	"$CHECK" "$WORK/uprobe-func.upatch" uprobe "$WORK/target" fooFunc 0 \
		>"$WORK/uprobe-func.out" &&
	base=$(head -n 1 "$WORK/uprobe-func.out") &&
	[ "$base" -gt 0 ] &&
	echo "$base" >"$WORK/base"
'

base=$(cat "$WORK/base" 2>/dev/null || echo 0)

test_expect_success 'a uprobe at function+offset adds the offset' '
	build_probe uprobe-off "uprobe/$WORK/target:fooFunc+4" &&
	check_probe uprobe-off uprobe fooFunc 4 $((base + 4))
'

test_expect_success 'a uprobe at a raw file offset records it as given' '
	raw=$(printf "0x%x" "$base") &&
	build_probe uprobe-raw "uprobe/$WORK/target:$raw" &&
	check_probe uprobe-raw uprobe "$raw" 0 "$base"
'

test_expect_success 'a uretprobe on a function records the return kind' '
	build_probe uretprobe-func "uretprobe/$WORK/target:fooFunc" &&
	check_probe uretprobe-func uretprobe fooFunc 0 "$base"
'

test_expect_success 'the sleepable uprobe.s and uretprobe.s take the same kinds' '
	build_probe uprobe-s "uprobe.s/$WORK/target:fooFunc" &&
	check_probe uprobe-s uprobe fooFunc 0 "$base" &&
	build_probe uretprobe-s "uretprobe.s/$WORK/target:fooFunc" &&
	check_probe uretprobe-s uretprobe fooFunc 0 "$base"
'

test_expect_success 'a uretprobe offset is refused' '
	! build_probe uretprobe-off "uretprobe/$WORK/target:fooFunc+4" &&
	grep -q "uretprobe offsets are unsupported" "$WORK/uretprobe-off.log"
'

test_expect_success 'a uprobe on a missing function is refused' '
	! build_probe uprobe-missing "uprobe/$WORK/target:noSuchFunc" &&
	grep -q "not found in" "$WORK/uprobe-missing.log"
'

test_expect_success 'a uprobe offset past the end of the file is refused' '
	! build_probe uprobe-past "uprobe/$WORK/target:0x10000000" &&
	grep -q "lies outside" "$WORK/uprobe-past.log"
'

test_expect_success 'a uprobe on a relative path is refused' '
	! build_probe uprobe-relative "uprobe/target:fooFunc" &&
	grep -q "invalid uprobe section" "$WORK/uprobe-relative.log"
'

test_expect_success 'a sleepable uprobe.multi.s glob records the entry kind' '
	write_probe "*Func" "uprobe.multi.s/$WORK/target:*Func" &&
	( cd .. && "$B" "$WORK/probe.bpf.c" \
		-o "$WORK/uprobe-s.upatch" --vmlinux vendor/linux/vmlinux.h \
		--name uprobe-multi-s-test --key "$WORK/k.pem" \
		--cert "$WORK/c.der" ) >/dev/null 2>&1 &&
	"$CHECK" "$WORK/uprobe-s.upatch" uprobe-multi \
		"$WORK/target" "*Func" 2
'

test_expect_success 'a sleepable uretprobe.multi.s glob records the return kind' '
	write_probe "*Func" "uretprobe.multi.s/$WORK/target:*Func" &&
	( cd .. && "$B" "$WORK/probe.bpf.c" \
		-o "$WORK/uretprobe-s.upatch" --vmlinux vendor/linux/vmlinux.h \
		--name uretprobe-multi-s-test --key "$WORK/k.pem" \
		--cert "$WORK/c.der" ) >/dev/null 2>&1 &&
	"$CHECK" "$WORK/uretprobe-s.upatch" uretprobe-multi \
		"$WORK/target" "*Func" 2
'

test_expect_success 'a sleepable uprobe.session.s is refused' '
	refused "uprobe.session.s/$WORK/target:*Func"
'

test_done
