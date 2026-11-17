#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# jobs/sbom-scan with the real Trivy as the matcher, on the first image
# of test/sbom-store. Its findings depend on the advisory database, so
# the test asserts what does not: the image is loaded ok, with the
# database's version, and no finding is of a kernel package. It needs
# trivy on the host and SBOM_TRIVY_CACHE, a Trivy cache directory that
# holds a pinned database, which the job never updates; without either
# it is skipped, as it is in CI, which caches no database.

set -eu

test=$(cd "$(dirname "$0")" && pwd)
job=$test/../jobs/sbom-scan
root=a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c
unset SBOM_STORE TRIVY TRIVY_CACHE_DIR S3_CLIENT

if ! command -v trivy >/dev/null 2>&1; then
	echo 'needs trivy on the host'
	exit 77
fi
if [ -z "${SBOM_TRIVY_CACHE:-}" ] || [ ! -d "$SBOM_TRIVY_CACHE/db" ]; then
	echo 'needs SBOM_TRIVY_CACHE, a Trivy cache with a pinned database; CI caches none'
	exit 77
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/store/fleet-os/2026.11.1"
cp -R "$test/sbom-store/fleet-os/2026.11.1/$root" "$work/store/fleet-os/2026.11.1/"

"$job" --store "file://$work/store" --cache-dir "$SBOM_TRIVY_CACHE" >"$work/out" 2>&1 || {
	cat "$work/out"
	exit 1
}
echo 'scanned with trivy'
