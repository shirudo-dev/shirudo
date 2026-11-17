#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# sql/apply-retention.sh refuses a retention it cannot apply safely and
# then changes neither table, not even the one whose own value was good:
# 0 for shirudo.keepalive, and less than a day for shirudo.boot_first,
# whose current baselines are written again only once an hour. A day is
# applied.

set -eu

test=$(cd "$(dirname "$0")" && pwd)

query()
{
	# shellcheck disable=SC2086 # a command with its options, to be split
	$CLICKHOUSE_CLIENT --query "$1" </dev/null
}

try()
{
	query "INSERT INTO shirudo.settings
		(stale_seconds, stuck_seconds, window, keepalive_retention_seconds,
		 boot_first_retention_seconds)
		VALUES (180, 3600, 512, $1, $2)"
	status=0
	# shellcheck disable=SC2086
	"$test/../sql/apply-retention.sh" $CLICKHOUSE_CLIENT 2>&1 || status=$?
	printf 'keepalive %s, boot_first %s: status %d\n' "$1" "$2" "$status"
	query "SELECT name, extract(engine_full, 'TTL .*\\\\)') FROM system.tables
		WHERE database = 'shirudo' AND name IN ('boot_first', 'keepalive')
		ORDER BY name"
}

try 7200 3600
try 0 5184000
try 7200 86400
