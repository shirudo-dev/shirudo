#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# test/stub-aws.sh -- stand in for `aws s3 cp --recursive` in the tests
# of jobs/sbom-scan. The object s3://<bucket>/<key> is the file
# STUB_S3_ROOT/<bucket>/<key>. It names its arguments on standard error,
# the destination as <directory> since the job makes it, copies the
# files whose names the --include patterns end in and exits with
# STUB_S3_STATUS, 0 by default.

set -eu

[ "${1:-} ${2:-} ${3:-}" = 's3 cp --recursive' ] || {
	echo "stub-aws: only s3 cp --recursive, not $*" >&2
	exit 2
}
said='s3 cp --recursive'
shift 3
source=
destination=
names=
while [ $# -gt 0 ]; do
	case "$1" in
	s3://*)
		source=$STUB_S3_ROOT/${1#s3://}
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
		destination=$1
		said="$said <directory>" ;;
	esac
	shift
done
printf 'stub-aws: %s\n' "$said" >&2
[ "${STUB_S3_STATUS:-0}" -eq 0 ] || exit "$STUB_S3_STATUS"

cd "$source"
for name in $names; do
	find . -type f -name "$name" | while read -r file; do
		mkdir -p "$destination/${file%/*}"
		cp "$file" "$destination/$file"
	done
done
