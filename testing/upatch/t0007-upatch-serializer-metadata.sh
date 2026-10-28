#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0007 -- serializer upatches use the UPGM metadata format and bind
# each serializer program to its target map. Builds the arena-tree
# example, signs it with throwaway keys, and checks the container
# offline. Full load/read is covered by integration environments with
# BPF_MAP_TYPE_ARENA support.

cd "$(dirname "$0")/.."
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

# shirudo signs with ML-DSA-87 only (needs OpenSSL >= 3.5 to mint it).
openssl req -x509 -newkey ML-DSA-87 -nodes -keyout "$WORK/k.pem" \
	-outform DER -out "$WORK/c.der" -days 1 -subj "/CN=t0007" \
	>/dev/null 2>&1 || test_skip_all "openssl ML-DSA keygen failed (needs OpenSSL >= 3.5)"

case "$SHB" in
/*) B="$SHB" ;;
*)  B="$(pwd)/$SHB" ;;
esac

( cd .. && "$B" testing/fixtures/arena-tree-serializer.bpf.c \
	-o "$WORK/arena-tree-serializer.upatch" \
	--vmlinux vendor/linux/vmlinux.h --name arena-tree-serializer \
	--key "$WORK/k.pem" --cert "$WORK/c.der" ) >/dev/null 2>&1 ||
	test_skip_all "arena serializer build failed (kernel/toolchain lacks arena support?)"

test_expect_success 'arena serializer upatch carries UPGM serializer metadata' '
	"$CHECK" "$WORK/arena-tree-serializer.upatch"
'

cat >"$WORK/no-output.bpf.c" <<'EOF'
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "shirudo_serializer.h"
char _license[] SEC("license") = "Dual BSD/GPL";
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} target SEC(".maps");
SEC("syscall")
int shirudo_serialize__target(struct shirudo_serialize_ctx *ctx)
{
	return 0;
}
EOF
cat >"$WORK/missing-target.bpf.c" <<'EOF'
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "shirudo_serializer.h"
char _license[] SEC("license") = "Dual BSD/GPL";
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, struct shirudo_serial_chunk);
} shirudo_ser SEC(".maps");
SEC("syscall")
int shirudo_serialize__absent(struct shirudo_serialize_ctx *ctx)
{
	return 0;
}
EOF
cat >"$WORK/reserved-target.bpf.c" <<'EOF'
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "shirudo_serializer.h"
char _license[] SEC("license") = "Dual BSD/GPL";
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, struct shirudo_serial_chunk);
} shirudo_ser SEC(".maps");
SEC("syscall")
int shirudo_serialize__shirudo_ser(struct shirudo_serialize_ctx *ctx)
{
	return 0;
}
EOF
expect_build_error() {
	source=$1
	message=$2
	if (cd .. && "$B" "$WORK/$source" -o "$WORK/bad.upatch" \
		--vmlinux vendor/linux/vmlinux.h --name invalid-serializer \
		--key "$WORK/k.pem" --cert "$WORK/c.der") \
		>"$WORK/build.log" 2>&1; then return 1; fi
	grep -Fq "$message" "$WORK/build.log"
}
test_expect_success 'builder rejects serializers without output map' '
	expect_build_error no-output.bpf.c "requires shirudo_ser output map"
'
test_expect_success 'builder rejects serializer with missing target map' '
	expect_build_error missing-target.bpf.c "targets missing map"
'
test_expect_success 'builder rejects serializer targeting reserved output map' '
	expect_build_error reserved-target.bpf.c "cannot target reserved map"
'
test_expect_success 'builder rejects duplicate serializer targets' '
	if ! command -v llvm-objcopy >/dev/null 2>&1; then exit 0; fi
	(cd .. &&
		clang -target bpf -O2 -g -I vendor/linux -I vendor/libbpf \
			-I bpf/lib -c testing/fixtures/arena-tree-serializer.bpf.c \
			-o "$WORK/arena-tree-serializer.o" &&
		llvm-objcopy --redefine-sym \
			shirudo_serialize__tree_error=shirudo_serialize__tree_arena \
			"$WORK/arena-tree-serializer.o" "$WORK/duplicate-serializer.o" &&
		if "$B" "$WORK/duplicate-serializer.o" -o "$WORK/duplicate.upatch" \
			--vmlinux vendor/linux/vmlinux.h --name duplicate-serializer \
			--key "$WORK/k.pem" --cert "$WORK/c.der" \
			>"$WORK/duplicate.log" 2>&1; then false; fi) &&
	grep -Fq "duplicate serializer for map" "$WORK/duplicate.log"
'
test_done
