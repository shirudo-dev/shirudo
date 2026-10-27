#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0056 -- a path the caller names for shirudo to write is opened as
# output root may ask for: never through a symbolic link, never a
# directory or device, and never a sealed inode (the label needs root,
# so that case is the target suite's t1141). Driven through the report a
# failed load writes and the JSON a map listing appends.

cd "$(dirname "$0")"
. ./test-lib.sh

S=../shirudo

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
printf 'keep\n' >"$WORK/target"
ln -s "$WORK/target" "$WORK/link"
mkdir "$WORK/dir"

test_expect_success 'a report is not written through a symbolic link' '
	! $S upatch load "$WORK/missing.upatch" --no-precheck \
		--report="$WORK/link" >/dev/null 2>"$WORK/err" &&
	grep -q "report: open .*symbolic links" "$WORK/err" &&
	[ "$(cat "$WORK/target")" = keep ]
'

test_expect_success 'a report is not written over a directory' '
	! $S upatch load "$WORK/missing.upatch" --no-precheck \
		--report="$WORK/dir" >/dev/null 2>"$WORK/err" &&
	grep -q "^report: open" "$WORK/err" &&
	[ -d "$WORK/dir" ]
'

test_expect_success 'a report is written to a plain path' '
	! $S upatch load "$WORK/missing.upatch" --no-precheck \
		--report="$WORK/report.json" >/dev/null 2>&1 &&
	grep -q "\"category\":\"parser_rejected\"" "$WORK/report.json"
'

test_expect_success 'a map listing is not appended through a symbolic link' '
	! $S upatch map --json="$WORK/link" >/dev/null 2>"$WORK/err" &&
	[ "$(cat "$WORK/target")" = keep ]
'

test_done
