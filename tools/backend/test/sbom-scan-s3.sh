#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# jobs/sbom-scan over an s3:// store, with test/stub-aws.sh in place of
# the AWS command line: the job copies the objects it reads and scans
# them as it does a file:// store. Then what it refuses, each with a
# message and without loading anything: a copy that fails, a store of
# another kind or none, a file:// directory that is not there and a
# matcher that cannot say its version.

set -eu

test=$(cd "$(dirname "$0")" && pwd)
job=$test/../jobs/sbom-scan
root=a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c
unset SBOM_STORE TRIVY TRIVY_CACHE_DIR S3_CLIENT

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
images=$work/s3/fleet-images/sboms/fleet-os
mkdir -p "$images/2026.11.1" "$images/2026.11.6"
cp -R "$test/sbom-store/fleet-os/2026.11.1/$root" "$images/2026.11.1/"
cp -R "$test/sbom-store/fleet-os/2026.11.6/-" "$images/2026.11.6/"
echo 'not read' >"$images/2026.11.6/-/build.log"

export STUB_S3_ROOT="$work/s3" S3_CLIENT="$test/stub-aws.sh"
"$job" --store s3://fleet-images/sboms --trivy "$test/stub-trivy.sh" 2>&1

rows()
{
	# shellcheck disable=SC2086 # a command with its options, to be split
	printf 'rows: %s\n' "$($CLICKHOUSE_CLIENT --query \
		'SELECT count() FROM shirudo.sbom_images' </dev/null)"
}

# refused <what> <expected status> <command>...
refused()
{
	what=$1
	expected=$2
	shift 2
	status=0
	"$@" 2>&1 || status=$?
	printf '%s: status %d\n' "$what" "$status"
	[ "$status" -eq "$expected" ]
}

rows
refused 'copy fails' 1 env STUB_S3_STATUS=1 "$job" \
	--store s3://fleet-images/sboms --trivy "$test/stub-trivy.sh"
refused 'https store' 1 "$job" --store https://registry.example.com/sboms \
	--trivy "$test/stub-trivy.sh"
refused 'empty s3 store' 1 "$job" --store s3:// --trivy "$test/stub-trivy.sh"
refused 'no store' 2 "$job" --trivy "$test/stub-trivy.sh"
refused 'no directory' 1 "$job" --store file://no-such-store \
	--trivy "$test/stub-trivy.sh"
refused 'no version' 1 "$job" --store "file://$work/s3/fleet-images/sboms" --trivy false
rows
