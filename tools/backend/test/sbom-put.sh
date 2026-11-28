#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# jobs/sbom-put into a file:// store and an s3:// one, with
# test/stub-aws.sh in place of the AWS command line and
# test/stub-trivy.sh as the matcher of --scan. An image is stored, its
# files are those sbom-scan reads, and --scan loads it; storing it again
# with the same SBOM changes nothing, with another is refused, also when
# a put running meanwhile has placed its SBOM but not yet image.json.
# Then what it refuses before writing anything: a key out of the layout,
# a root that is not a root, a time out of form, an SBOM that is not
# CycloneDX and one that is not there, a store that is not one and wrong
# usage.

set -eu

test=$(cd "$(dirname "$0")" && pwd)
job=$test/../jobs/sbom-put
root=a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c
sbom=$test/sbom-store/fleet-os/2026.11.1/$root/sbom.cdx.json
other=$test/sbom-store/fleet-os/2026.11.6/-/sbom.cdx.json
unset SBOM_STORE TRIVY_CACHE_DIR S3_CLIENT
export TRIVY="$test/stub-trivy.sh"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/store"

# run <what> <command>...: run a command, then name its status.
run()
{
	what=$1
	shift
	status=0
	"$@" 2>&1 || status=$?
	printf '%s: status %d\n' "$what" "$status"
}

run 'put and scan' "$job" --store "file://$work/store" --image-id fleet-os \
	--image-version 2026.11.1 --image-root "$root" \
	--built-at 2026-11-02T08:00:00Z --scan "$sbom"
(cd "$work/store" && find . -type f | sort)
cat "$work/store/fleet-os/2026.11.1/$root/image.json"
cmp "$sbom" "$work/store/fleet-os/2026.11.1/$root/sbom.cdx.json" && echo 'the SBOM is the bytes given'

run 'same again' "$job" --store "file://$work/store" --image-id fleet-os \
	--image-version 2026.11.1 --image-root "$root" "$sbom"
run 'another sbom' "$job" --store "file://$work/store" --image-id fleet-os \
	--image-version 2026.11.1 --image-root "$root" "$other"

SBOM_STORE=file://$work/store run 'no root, default time' "$job" \
	--image-id fleet-os --image-version 2026.11.6 "$other"
sed 's/"built_at":"[0-9]\{4\}-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z"/"built_at":"<now>"/' \
	"$work/store/fleet-os/2026.11.6/-/image.json"

# Another put that placed its SBOM first and has not yet placed image.json.
raced=$work/store/fleet-os/2026.11.7/-
mkdir -p "$raced"
cp "$other" "$raced/sbom.cdx.json"
run 'raced, another sbom' "$job" --store "file://$work/store" \
	--image-id fleet-os --image-version 2026.11.7 "$sbom"
cmp "$other" "$raced/sbom.cdx.json" && echo 'the SBOM placed first is kept'
run 'raced, same sbom' "$job" --store "file://$work/store" \
	--image-id fleet-os --image-version 2026.11.7 --built-at 2026-11-03T08:00:00Z "$other"

mkdir -p "$work/s3/fleet-images"
export STUB_S3_ROOT="$work/s3"
S3_CLIENT=$test/stub-aws.sh run 's3 put' "$job" --store s3://fleet-images/sboms \
	--image-id fleet-os --image-version 2026.11.1 --image-root "$root" \
	--built-at 2026-11-02T08:00:00Z "$sbom"
(cd "$work/s3" && find . -type f | sort)
S3_CLIENT=$test/stub-aws.sh run 's3 same again' "$job" --store s3://fleet-images/sboms \
	--image-id fleet-os --image-version 2026.11.1 --image-root "$root" "$sbom"
S3_CLIENT=$test/stub-aws.sh run 's3 another sbom' "$job" --store s3://fleet-images/sboms \
	--image-id fleet-os --image-version 2026.11.1 --image-root "$root" "$other"
S3_CLIENT=$test/stub-aws.sh STUB_S3_STATUS=1 run 's3 fails' "$job" \
	--store s3://fleet-images/sboms --image-id fleet-os --image-version 2026.11.2 "$sbom"

put()
{
	"$job" --store "file://$work/store" "$@"
}
printf '{"bomFormat":"SPDX"}\n' >"$work/spdx.json"
run 'dot id' put --image-id .fleet --image-version 1 "$sbom"
run 'slash version' put --image-id fleet-os --image-version a/b "$sbom"
run 'short root' put --image-id fleet-os --image-version 1 --image-root abc "$sbom"
run 'bad time' put --image-id fleet-os --image-version 1 --built-at 2026-11-02 "$sbom"
run 'not cyclonedx' put --image-id fleet-os --image-version 1 "$work/spdx.json"
(cd "$work" && run 'no sbom' put --image-id fleet-os --image-version 1 none.json)
run 'https store' "$job" --store https://example.com/sboms --image-id fleet-os \
	--image-version 1 "$sbom"
run 'no store directory' "$job" --store file://no-such-store --image-id fleet-os \
	--image-version 1 "$sbom"
run 'no image id' put --image-version 1 "$sbom"
run 'two sboms' put --image-id fleet-os --image-version 1 "$sbom" "$sbom"
(cd "$work/store" && find . -type f | sort)
(cd "$work/store" && find . -name '.put.*')
