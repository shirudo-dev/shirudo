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

# A node that reports no root is counted once, on the newest build of its
# id and version that has an SBOM, as node_vulns binds it: not on the
# older build as well, nor on a newer one whose SBOM is missing.
$CLICKHOUSE_CLIENT --query "INSERT INTO shirudo.sbom_images
	(image_id, image_version, image_root, sbom_sha256, state, built_at,
	 db_version, scanned_at)
	SELECT 'fleet-os', '2026.11.1', repeat(root, 64),
		if(state = 'ok', repeat(root, 64), ''), state, built_at, '2', now()
	FROM values('root String, state String, built_at DateTime',
		('c', 'ok', '2026-11-03 08:00:00'),
		('d', 'missing', '2026-11-04 08:00:00'))"
query sbom-images.sql 'SELECT image_id, image_version, image_root, state, nodes' \
	'ORDER BY image_root'

# A build stored without a root is that node's own, before a newer one.
$CLICKHOUSE_CLIENT --query "INSERT INTO shirudo.sbom_images
	(image_id, image_version, image_root, sbom_sha256, state, built_at,
	 db_version, scanned_at)
	SELECT 'fleet-os', '2026.11.1', '', repeat('e', 64), 'ok',
		'2026-11-01 08:00:00', '2', now()"
query sbom-images.sql 'SELECT image_id, image_version, image_root, state, nodes' \
	'ORDER BY image_root'
