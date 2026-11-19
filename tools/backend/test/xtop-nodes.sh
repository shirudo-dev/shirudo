#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# The query the nodes view of tools/xtop sends, over the nodes of
# xtop-nodes.setup.sql, with the names and types of its columns, which the
# view reads by name. The times and the age in the line of check 2 change
# from run to run and are left out.

query=$(dirname "$0")/../../xtop/sql/nodes.sql

{
	printf '%s\n' "SELECT * EXCEPT (log, last_seen_ms, updated_ms),"
	printf '%s\n' "    arrayMap(line -> replaceRegexpOne(line, 'last record -?[0-9]+ s ago', 'last record N s ago'), log) AS log,"
	printf '%s\n' "    last_seen_ms > 0 AS seen, updated_ms > 0 AS updated"
	printf '%s\n' "FROM ("
	sed '/^--/d' "$query"
	printf '%s\n' ") ORDER BY node_id FORMAT TSVWithNamesAndTypes"
} | $CLICKHOUSE_CLIENT
