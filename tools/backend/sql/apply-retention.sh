#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# sql/apply-retention.sh -- give shirudo.keepalive and shirudo.boot_first
# the retention that shirudo.settings names. A ClickHouse TTL cannot read
# a table, so run this after loading the schema and after every change
# of keepalive_retention_seconds or boot_first_retention_seconds.
#
#   sql/apply-retention.sh [<client command>...]
#
# The arguments are the command that reaches the server, by default
# clickhouse-client; --query '<SQL>' is appended to it. A value that is
# refused changes neither table.

set -eu

# shirudo.boot_first_keep_mv writes the baseline of a node's current boot
# again once an hour. A retention near that hour could remove one between
# two refreshes, so a day is the least the script applies.
BOOT_FIRST_MINIMUM=86400

[ $# -gt 0 ] || set -- clickhouse-client

setting()
{
	name=$1
	shift
	"$@" --query "SELECT $name FROM shirudo.settings FINAL" </dev/null
}

refuse()
{
	printf 'apply-retention.sh: %s is "%s", need a number of seconds %s\n' \
		"$1" "$2" "$3" >&2
	exit 1
}

keepalive=$(setting keepalive_retention_seconds "$@")
boot_first=$(setting boot_first_retention_seconds "$@")

case "$keepalive" in
''|0|*[!0-9]*)
	refuse keepalive_retention_seconds "$keepalive" 'above 0' ;;
esac
case "$boot_first" in
''|*[!0-9]*)
	refuse boot_first_retention_seconds "$boot_first" \
		"of at least $BOOT_FIRST_MINIMUM" ;;
esac
[ "$boot_first" -ge "$BOOT_FIRST_MINIMUM" ] ||
	refuse boot_first_retention_seconds "$boot_first" \
		"of at least $BOOT_FIRST_MINIMUM"

"$@" --query "ALTER TABLE shirudo.keepalive
	MODIFY TTL toDateTime(received) + INTERVAL $keepalive SECOND" </dev/null
"$@" --query "ALTER TABLE shirudo.boot_first
	MODIFY TTL last_used + INTERVAL $boot_first SECOND" </dev/null
