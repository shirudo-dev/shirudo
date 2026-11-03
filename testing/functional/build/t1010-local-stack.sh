#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./test-lib.sh
command -v openssl >/dev/null 2>&1 || test_skip_all 'no openssl'
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export TEST_VM_STACK_DIR="$WORK/public" TEST_VM_STACK_PRIVATE_DIR="$WORK/private"

cat >"$WORK/inspect.sh" <<'EOF'
set -eu
[ "$TEST_VM_LOCAL_STACK" = 1 ]
[ "$TEST_VM_MAP_EXPORT_ENDPOINT" = https://10.0.2.2:14319 ]
[ "$TEST_VM_MAP_EXPORT_INSECURE" = false ]
[ "$TEST_VM_OCI_CA" = "$TEST_VM_MAP_EXPORT_CA" ]
[ -s "$TEST_VM_OCI_CA" ]
EOF

test_expect_success 'a VM can prepare trust and endpoints before services exist' '
	vm/stack.sh vm sh "$WORK/inspect.sh" &&
	test ! -e "$TEST_VM_STACK_DIR/server.key" &&
	test ! -e "$TEST_VM_STACK_DIR/ca.key"
'

test_expect_success 'preparing services later preserves the VM trust anchor' '
	cp "$TEST_VM_STACK_DIR/ca.pem" "$WORK/original.pem" &&
	vm/stack.sh prepare &&
	cmp "$TEST_VM_STACK_DIR/ca.pem" "$WORK/original.pem"
'

test_done
