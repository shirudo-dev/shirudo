#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0009 -- cgroup_skb upatches carry explicit attach metadata.

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
	-outform DER -out "$WORK/c.der" -days 1 -subj "/CN=t0009" \
	>/dev/null 2>&1 || test_skip_all "openssl ML-DSA keygen failed (needs OpenSSL >= 3.5)"

case "$SHB" in
/*) B="$SHB" ;;
*)  B="$(pwd)/$SHB" ;;
esac

cat > "$WORK/cgroup-ingress.bpf.c" <<'EOF'
// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("cgroup_skb/ingress")
int ingress(struct __sk_buff *skb)
{
	return 1;
}
EOF

cat > "$WORK/cgroup-egress.bpf.c" <<'EOF'
// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("cgroup_skb/egress")
int egress(struct __sk_buff *skb)
{
	return 1;
}
EOF

( cd .. && "$B" "$WORK/cgroup-ingress.bpf.c" \
	-o "$WORK/cgroup-ingress.upatch" \
	--vmlinux vendor/linux/vmlinux.h --name cgroup-ingress \
	--key "$WORK/k.pem" --cert "$WORK/c.der" ) >/dev/null 2>&1 ||
	test_skip_all "cgroup_skb ingress build failed"

( cd .. && "$B" "$WORK/cgroup-egress.bpf.c" \
	-o "$WORK/cgroup-egress.upatch" \
	--vmlinux vendor/linux/vmlinux.h --name cgroup-egress \
	--key "$WORK/k.pem" --cert "$WORK/c.der" ) >/dev/null 2>&1 ||
	test_skip_all "cgroup_skb egress build failed"

test_expect_success 'cgroup_skb/ingress records ingress attach metadata' '
	"$CHECK" "$WORK/cgroup-ingress.upatch" cgroup-ingress
'

test_expect_success 'cgroup_skb/egress records egress attach metadata' '
	"$CHECK" "$WORK/cgroup-egress.upatch" cgroup-egress
'

test_done
