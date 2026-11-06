#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3010 -- unsupported network attach kinds are rejected with shirudo-specific
# diagnostics.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

SHB=../tools/shirudo-build/shirudo-build

command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built (make shirudo-build)"
[ -e ../vendor/linux/vmlinux.h ] || test_skip_all "no vendor/linux/vmlinux.h (build the tree)"
[ -e ../vendor/libbpf/bpf/bpf_helpers.h ] || test_skip_all "no vendored bpf headers"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# shirudo signs with ML-DSA-87 only (needs OpenSSL >= 3.5 to mint it).
openssl req -x509 -newkey ML-DSA-87 -nodes -keyout "$WORK/k.pem" \
	-outform DER -out "$WORK/c.der" -days 1 -subj "/CN=t3010" \
	>/dev/null 2>&1 || test_skip_all "openssl ML-DSA keygen failed (needs OpenSSL >= 3.5)"

case "$SHB" in
/*) B="$SHB" ;;
*)  B="$(pwd)/$SHB" ;;
esac

cat > "$WORK/sk-skb.bpf.c" <<'EOF'
// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("sk_skb/stream_verdict")
int verdict(struct __sk_buff *skb)
{
	return 1;
}
EOF

cat > "$WORK/socket-filter.bpf.c" <<'EOF'
// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("socket")
int filter(struct __sk_buff *skb)
{
	return 0;
}
EOF

cat > "$WORK/cgroup-skb-generic.bpf.c" <<'EOF'
// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("cgroup/skb")
int generic(struct __sk_buff *skb)
{
	return 1;
}
EOF

cat > "$WORK/xdp.bpf.c" <<'EOF'
// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	return XDP_PASS;
}
EOF

test_expect_success 'sk_skb sections are rejected for now' '
	! ( cd .. && "$B" "$WORK/sk-skb.bpf.c" \
		-o "$WORK/sk-skb.upatch" \
		--vmlinux vendor/linux/vmlinux.h --name sk-skb \
		--key "$WORK/k.pem" --cert "$WORK/c.der" ) \
		>"$WORK/sk-skb.out" 2>&1 &&
	grep -q "unsupported sk_skb section" "$WORK/sk-skb.out"
'

test_expect_success 'socket filter sections are rejected for lifecycle reasons' '
	! ( cd .. && "$B" "$WORK/socket-filter.bpf.c" \
		-o "$WORK/socket-filter.upatch" \
		--vmlinux vendor/linux/vmlinux.h --name socket-filter \
		--key "$WORK/k.pem" --cert "$WORK/c.der" ) \
		>"$WORK/socket-filter.out" 2>&1 &&
	grep -q "pinnable bpf_link lifecycle" "$WORK/socket-filter.out"
'

test_expect_success 'generic cgroup skb sections require ingress or egress' '
	! ( cd .. && "$B" "$WORK/cgroup-skb-generic.bpf.c" \
		-o "$WORK/cgroup-skb-generic.upatch" \
		--vmlinux vendor/linux/vmlinux.h --name cgroup-skb-generic \
		--key "$WORK/k.pem" --cert "$WORK/c.der" ) \
		>"$WORK/cgroup-skb-generic.out" 2>&1 &&
	grep -q "use cgroup_skb/ingress or cgroup_skb/egress" \
		"$WORK/cgroup-skb-generic.out"
'

test_expect_success 'XDP without an explicit signed device class mask is rejected' '
	! ( cd .. && "$B" "$WORK/xdp.bpf.c" \
		-o "$WORK/xdp.upatch" \
		--vmlinux vendor/linux/vmlinux.h --name xdp \
		--key "$WORK/k.pem" --cert "$WORK/c.der" ) \
		>"$WORK/xdp.out" 2>&1 &&
	grep -q "unsupported section .xdp." "$WORK/xdp.out" &&
	! test -e "$WORK/xdp.upatch"
'

test_done
