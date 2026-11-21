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

# query <file> <outer select> [<order>]: run a query of the view inside a
# select that leaves out what changes.
query()
{
	{
		printf '%s\n' "$2 FROM ("
		sed '/^--/d' "$xtop/$1"
		printf '%s\n' ") ${3:-} FORMAT TSVWithNamesAndTypes"
	} | $CLICKHOUSE_CLIENT
}

query sbom.sql 'SELECT *'
query sbom-images.sql 'SELECT * EXCEPT (scanned_ms), scanned_ms > 0 AS scanned'

# A node on a build of that image whose root the store does not have is
# counted on a no_sbom row of its own, not on the stored build's.
$CLICKHOUSE_CLIENT --query "INSERT INTO shirudo.checked
	(host_name, body, ok, ak_name, ak_public, reset_count, clock)
	SELECT 'edge-03', replaceOne(body,
		'a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c',
		'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),
		1, '000b0f', 'QUtG', 1, 1000
	FROM shirudo.keepalive FINAL WHERE ak_name = '000b23602ab98bfb'"
query sbom-images.sql 'SELECT image_id, image_version, image_root, state, nodes' \
	'ORDER BY image_root'
