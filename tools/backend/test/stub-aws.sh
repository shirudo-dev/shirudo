#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# test/stub-aws.sh -- stand in for `aws s3 cp` in the tests of
# jobs/sbom-scan and jobs/sbom-put. The object s3://<bucket>/<key> is the
# file STUB_S3_ROOT/<bucket>/<key>. It names its arguments on standard
# error, a local path as <directory> or <file> since the job makes it,
# and exits with STUB_S3_STATUS, 0 by default. With --recursive it copies
# the files under the source whose names the --include patterns end in,
# and nothing when there is no such prefix, as AWS does; without, it
# copies one local file to an object.

set -eu

[ "${1:-} ${2:-}" = 's3 cp' ] || {
	echo "stub-aws: only s3 cp, not $*" >&2
	exit 2
}
said='s3 cp'
shift 2
recursive=0
source=
destination=
names=
while [ $# -gt 0 ]; do
	case "$1" in
	s3://*)
		if [ -z "$source" ] && [ "$recursive" -eq 1 ]; then
			source=$STUB_S3_ROOT/${1#s3://}
		else
			destination=$STUB_S3_ROOT/${1#s3://}
		fi
		said="$said $1" ;;
	--recursive)
		recursive=1
		said="$said $1" ;;
	--include)
		names="$names ${2##*/}"
		said="$said $1 $2"
		shift ;;
	--exclude)
		said="$said $1 $2"
		shift ;;
	-*)
		said="$said $1" ;;
	*)
		if [ "$recursive" -eq 1 ]; then
			destination=$1
			said="$said <directory>"
		else
			source=$1
			said="$said <file>"
		fi ;;
	esac
	shift
done
printf 'stub-aws: %s\n' "$said" >&2
[ "${STUB_S3_STATUS:-0}" -eq 0 ] || exit "$STUB_S3_STATUS"

if [ "$recursive" -eq 0 ]; then
	mkdir -p "${destination%/*}"
	cp "$source" "$destination"
	exit 0
fi
[ -d "$source" ] || exit 0
cd "$source"
for name in $names; do
	find . -type f -name "$name" | while read -r file; do
		mkdir -p "$destination/${file%/*}"
		cp "$file" "$destination/$file"
	done
done
