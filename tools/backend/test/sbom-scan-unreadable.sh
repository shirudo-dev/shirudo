#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# jobs/sbom-scan over local stores it cannot enumerate. A store whose
# directory cannot be listed loads nothing and fails, as a missing store
# does, while a readable empty store succeeds. root ignores the directory
# mode, so the test skips itself when the store stays readable.

set -eu

test=$(cd "$(dirname "$0")" && pwd)
job=$test/../jobs/sbom-scan
unset SBOM_STORE TRIVY TRIVY_CACHE_DIR S3_CLIENT

work=$(mktemp -d)
trap 'chmod 700 "$work/store" 2>/dev/null || :; rm -rf "$work"' EXIT

scan()
{
	status=0
	output=$("$job" --store "file://$work/$1" 2>&1) || status=$?
	[ -z "$output" ] || printf '%s\n' "$output" | sed "s#$work/store#<store>#g"
	printf '%s: status %d\n' "$2" "$status"
}

mkdir "$work/store"
chmod 000 "$work/store"
if ls "$work/store" >/dev/null 2>&1; then
	echo 'the store stays readable; run as a non-root user to test the unreadable store'
	exit 77
fi
chmod 700 "$work/store"

scan store readable-empty

chmod 000 "$work/store"
scan store unreadable
chmod 700 "$work/store"

rmdir "$work/store"
scan store missing
