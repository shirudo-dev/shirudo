#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# jobs/sbom-scan over the file:// store test/sbom-store, with
# test/stub-trivy.sh as the matcher. Every state of an image comes out
# of it: ok with findings and without, missing, hash_mismatch,
# parse_error for an SBOM that is not CycloneDX, one that is not JSON,
# an image.json that is not JSON and one that names another version,
# and unsupported_format. Two images share an SBOM, whose findings are
# loaded once. Objects out of the layout, an image whose
# matcher fails and one whose report is refused are left out with a
# message and status 1, and the rest is loaded. A second run scans the
# first image again, with a cache directory for the matcher.

set -eu

test=$(cd "$(dirname "$0")" && pwd)
job=$test/../jobs/sbom-scan
root=a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c
unset SBOM_STORE TRIVY TRIVY_CACHE_DIR S3_CLIENT

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export STUB_TRIVY_LOG="$work/trivy.log"

status=0
STUB_TRIVY_FAIL=67b15da716e8b47de1b70e10b04e6629f0582be47137b363211ec699d42ea537 \
	"$job" --store "file://$test/sbom-store" --trivy "$test/stub-trivy.sh" 2>&1 ||
	status=$?
printf 'first run: status %d\n' "$status"
cat "$STUB_TRIVY_LOG"

mkdir -p "$work/store/fleet-os/2026.11.1"
cp -R "$test/sbom-store/fleet-os/2026.11.1/$root" "$work/store/fleet-os/2026.11.1/"
: >"$STUB_TRIVY_LOG"
TRIVY=$test/stub-trivy.sh SBOM_STORE=file://$work/store \
	"$job" --cache-dir /var/cache/trivy-test 2>&1
echo 'second run: status 0'
cat "$STUB_TRIVY_LOG"
