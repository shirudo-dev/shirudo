#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# A stored `bpm tree show --walk` output of a tree in three segments,
# test/tree-show-walk.json, loads every segment. A walk read while the
# tree had two loads those, a later walk adds only the third, a walk
# read again adds nothing, and a walk after one that stopped before its
# last insert completes it. The stub of `bpm tree show` is given
# --walk.

set -eu

test=$(cd "$(dirname "$0")" && pwd)
job=$test/../jobs/tree-ingest
show=$test/tree-show-walk.json

query()
{
	# shellcheck disable=SC2086 # a command with its options, to be split
	$CLICKHOUSE_CLIENT --query "$1"
}

rows()
{
	query "SELECT (SELECT count() FROM shirudo.tree_pubs FINAL),
		      (SELECT count() FROM shirudo.tree_ops FINAL),
		      (SELECT count() FROM shirudo.upatch_fixes FINAL)"
}

head -n 2 "$show" | "$job" --input - 2>&1
rows
first=$(query 'SELECT groupArray(published_at) FROM
	(SELECT published_at FROM shirudo.tree_pubs FINAL ORDER BY generation)')

sleep 0.1
STUB_SHOW_OUTPUT=$show "$job" --shirudo "$test/stub-shirudo.sh" \
	--cert /certs/operator.pem \
	oci://registry.example.com/shirudo/fleet-segments 2>&1
rows
[ "$(query 'SELECT groupArray(published_at) FROM
	(SELECT published_at FROM shirudo.tree_pubs FINAL
	 WHERE generation < 5 ORDER BY generation)')" = "$first" ]
echo 'published_at of the first two segments kept'

"$job" --input "$show" 2>&1
rows

query 'TRUNCATE TABLE shirudo.tree_pubs'
"$job" --input "$show" 2>&1
rows
