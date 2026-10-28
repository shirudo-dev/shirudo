#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0012 -- netfilter upatches carry explicit IPv6 pre-routing metadata.

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
	-outform DER -out "$WORK/c.der" -days 1 -subj "/CN=t0012" \
	>/dev/null 2>&1 || test_skip_all "openssl ML-DSA keygen failed (needs OpenSSL >= 3.5)"

case "$SHB" in
/*) B="$SHB" ;;
*)  B="$(pwd)/$SHB" ;;
esac

cat > "$WORK/netfilter.bpf.c" <<'EOF'
// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define NF_ACCEPT 1

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("netfilter")
int nf_accept(struct bpf_nf_ctx *ctx)
{
	return NF_ACCEPT;
}
EOF

( cd .. && "$B" "$WORK/netfilter.bpf.c" \
	-o "$WORK/netfilter.upatch" \
	--vmlinux vendor/linux/vmlinux.h --name netfilter \
	--key "$WORK/k.pem" --cert "$WORK/c.der" ) >/dev/null 2>&1 ||
	test_skip_all "netfilter build failed"

test_expect_success 'netfilter records IPv6 pre-routing attach metadata' '
	"$CHECK" "$WORK/netfilter.upatch" netfilter-ipv6-pre-routing
'

test_done
