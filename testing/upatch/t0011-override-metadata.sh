#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0011 -- override-capable kprobe/fmod_ret upatches carry attach metadata
# that lets the target create the right link type.

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
	-outform DER -out "$WORK/c.der" -days 1 -subj "/CN=t0011" \
	>/dev/null 2>&1 || test_skip_all "openssl ML-DSA keygen failed (needs OpenSSL >= 3.5)"

case "$SHB" in
/*) B="$SHB" ;;
*)  B="$(pwd)/$SHB" ;;
esac

cat > "$WORK/kprobe-override.bpf.c" <<'EOF'
// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/bpf_modify_return_test")
int reject_with_kprobe(struct pt_regs *ctx)
{
	bpf_override_return(ctx, -22);
	return 0;
}
EOF

cat > "$WORK/fmod-ret.bpf.c" <<'EOF'
// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("fmod_ret/bpf_modify_return_test")
int BPF_PROG(reject_with_fmod_ret, int a, int *b, int ret)
{
	return a < 0 ? -22 : ret;
}
EOF

( cd .. && "$B" "$WORK/kprobe-override.bpf.c" \
	-o "$WORK/kprobe-override.upatch" \
	--vmlinux vendor/linux/vmlinux.h --name kprobe-override \
	--key "$WORK/k.pem" --cert "$WORK/c.der" ) >/dev/null 2>&1 ||
	test_skip_all "kprobe override build failed"

( cd .. && "$B" "$WORK/fmod-ret.bpf.c" \
	-o "$WORK/fmod-ret.upatch" \
	--vmlinux vendor/linux/vmlinux.h --name fmod-ret \
	--key "$WORK/k.pem" --cert "$WORK/c.der" ) >/dev/null 2>&1 ||
	test_skip_all "fmod_ret build failed"

test_expect_success 'kprobe override records kprobe target metadata' '
	"$CHECK" "$WORK/kprobe-override.upatch" kprobe-override
'

test_expect_success 'fmod_ret records BPF_MODIFY_RETURN metadata' '
	"$CHECK" "$WORK/fmod-ret.upatch" fmod-ret
'

test_done
