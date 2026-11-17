#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# The stored `bpm tree show` output for the generation 3 publication of
# shirudo's testing/fixtures/keepalive/tree-1.1.0.json loads once: a
# second run inserts nothing and leaves published_at alone, and a run
# after one that stopped before its last insert completes it.

set -eu

test=$(cd "$(dirname "$0")" && pwd)
job=$test/../jobs/tree-ingest
show=$test/tree-show-1.1.0.json

query()
{
	# shellcheck disable=SC2086 # a command with its options, to be split
	$CLICKHOUSE_CLIENT --query "$1"
}

rows()
{
	query "SELECT (SELECT count() FROM shirudo.tree_pubs),
		      (SELECT count() FROM shirudo.tree_ops),
		      (SELECT count() FROM shirudo.upatch_fixes)"
}

"$job" --input "$show"
echo 'rows inserted, before any merge:'
rows
first=$(query 'SELECT published_at FROM shirudo.tree_pubs FINAL')

sleep 0.1
"$job" --input - <"$show"
rows
[ "$(query 'SELECT published_at FROM shirudo.tree_pubs FINAL')" = "$first" ]
echo 'published_at kept'

query 'TRUNCATE TABLE shirudo.tree_pubs'
"$job" --input "$show"
