#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# The query the shields view of tools/xtop sends, over the rows of
# xtop-nodes.setup.sql, with the names and types of its columns, which
# the view reads by name. The publication time changes from run to run
# and is left out.

query=$(dirname "$0")/../../xtop/sql/shields.sql

{
	printf '%s\n' "SELECT * EXCEPT (published_ms), published_ms > 0 AS published"
	printf '%s\n' "FROM ("
	sed '/^--/d' "$query"
	printf '%s\n' ") ORDER BY tree_id, id FORMAT TSVWithNamesAndTypes"
} | $CLICKHOUSE_CLIENT
