#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./test-lib.sh

SHB=../tools/shirudo-build/shirudo-build
CHECK=helper/test-upatch-prog-metadata

[ -x "$SHB" ] || test_skip_all "shirudo-build not built"
[ -x "$CHECK" ] || test_skip_all "metadata helper not built"
command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

openssl req -x509 -newkey ML-DSA-87 -nodes -keyout "$WORK/key.pem" \
	-outform DER -out "$WORK/cert.der" -days 1 -subj /CN=loader-attach \
	>/dev/null 2>&1 || test_skip_all "openssl lacks ML-DSA-87"

test_expect_success 'the builder signs a loader-link role for tracing programs' '
	"$SHB" fixtures/basic.bpf.c -o "$WORK/basic.upatch" \
		--extra-cflags "-I../vendor/libbpf -I../bpf/lib" \
		--vmlinux ../vendor/linux/vmlinux.h --name loader-basic \
		--key "$WORK/key.pem" --cert "$WORK/cert.der" &&
	"$CHECK" "$WORK/basic.upatch" loader-link
'

test_expect_success 'mixed objects retain loader links, serializers and userspace attachment' '
	"$SHB" fixtures/loader-mixed.bpf.c -o "$WORK/mixed.upatch" \
		--extra-cflags "-I../vendor/libbpf -I../bpf/lib" \
		--vmlinux ../vendor/linux/vmlinux.h --name loader-mixed \
		--key "$WORK/key.pem" --cert "$WORK/cert.der" &&
	"$CHECK" "$WORK/mixed.upatch" loader-mixed
'

test_done
