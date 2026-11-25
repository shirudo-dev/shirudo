#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./test-lib.sh

SHIRUDO=${SHIRUDO:-../shirudo}

command -v python3 >/dev/null 2>&1 || test_skip_all 'python3 unavailable'
command -v openssl >/dev/null 2>&1 || test_skip_all 'openssl unavailable'

if unshare --mount --propagation private true 2>/dev/null; then
	test_expect_success 'bpm installs keys and repository certificates in private directories' '
		python3 helper/test-bpm-key.py "$SHIRUDO" --isolated-keys
	'
else
	echo "# private mount namespace unavailable, skipping key installation cases"
	test_expect_success 'bpm keys fingerprint certificates, packages, and OCI references' '
		python3 helper/test-bpm-key.py "$SHIRUDO"
	'
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Without the namespace above, as CI runs, these still cover both
# refusals: they come before any write, so the host's own keys stay
# untouched, and the message shows it was the algorithm, not a write
# without permission, that failed.
test_expect_success 'bpm key add refuses a certificate that is not ML-DSA-87' '
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-keyout "$WORK/ec.key" -outform DER -out "$WORK/ec.der" \
		-days 1 -subj "/CN=t7003" >/dev/null 2>&1 &&
	! "$SHIRUDO" bpm key add "$WORK/ec.der" >"$WORK/add.out" 2>&1 &&
	grep -q "ec.der is EC; shirudo accepts only ML-DSA-87" "$WORK/add.out"
'

test_expect_success 'bpm config register add refuses a certificate that is not ML-DSA-87' '
	rc=0 &&
	"$SHIRUDO" bpm config register add src oci://registry.example \
		--cert "$WORK/ec.der" >"$WORK/register.out" 2>&1 || rc=$? &&
	[ "$rc" -eq 2 ] &&
	grep -q "ec.der is EC; shirudo accepts only ML-DSA-87" \
		"$WORK/register.out"
'

test_done
