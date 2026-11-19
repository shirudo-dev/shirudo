#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# The two queries the SBOM view of tools/xtop sends, over the rows of
# xtop-nodes.setup.sql, with the names and types of their columns, which
# the view reads by name: the findings with the nodes they affect, and
# the images. The time of the scan changes from run to run and is left
# out.

xtop=$(dirname "$0")/../../xtop/sql

# query <file> <outer select>: run a query of the view inside a select
# that leaves out what changes.
query()
{
	{
		printf '%s\n' "$2 FROM ("
		sed '/^--/d' "$xtop/$1"
		printf '%s\n' ") FORMAT TSVWithNamesAndTypes"
	} | $CLICKHOUSE_CLIENT
}

query sbom.sql 'SELECT *'
query sbom-images.sql 'SELECT * EXCEPT (scanned_ms), scanned_ms > 0 AS scanned'
