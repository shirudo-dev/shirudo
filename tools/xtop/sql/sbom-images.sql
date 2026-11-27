-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- One row per image for the SBOM view of tools/xtop: the newest scan of
-- every image in sbom_images, its findings and the nodes that run it,
-- and, as no_sbom, every image a node runs that sbom_images does not
-- have. A node that reports no image root runs one build of its id and
-- version, the one node_vulns binds it to; one that reports a
-- root sbom_images has not for that id and version runs a build of its
-- own, a no_sbom row with that root, so that every node is counted on
-- one row. Times are epoch milliseconds; a no_sbom row has 0 for them.

WITH
running AS
(
    SELECT
        assumeNotNull(l.image_id) AS image_id,
        ifNull(l.image_version, '') AS image_version,
        ifNull(l.image_root, '') AS image_root,
        l.ak_name AS ak_name
    FROM shirudo.latest AS l
    WHERE l.image_id IS NOT NULL
),
findings AS
(
    SELECT
        sbom_sha256,
        scanned_at,
        uniq(vuln_id) AS vulns,
        uniqIf(vuln_id, severity = 'CRITICAL') AS critical,
        uniqIf(vuln_id, severity = 'HIGH') AS high
    FROM shirudo.sbom_vulns
    GROUP BY sbom_sha256, scanned_at
),
images AS
(
    SELECT image_id, image_version, image_root, state, sbom_format, sbom_sha256, built_at,
           scanned_at, db_version
    FROM shirudo.sbom_images FINAL
),
bound AS
(
    -- The order is that of img in node_vulns_mv, so that a node that
    -- reports no root is counted on the build its findings come from.
    SELECT i.image_id AS image_id, i.image_version AS image_version, i.image_root AS image_root,
           r.ak_name AS ak_name
    FROM images AS i
    INNER JOIN running AS r ON r.image_id = i.image_id AND r.image_version = i.image_version
    WHERE r.image_root = i.image_root OR r.image_root = ''
    ORDER BY r.ak_name, i.image_root = r.image_root DESC,
             i.state = 'ok' AND i.sbom_sha256 != '' DESC, i.built_at DESC, i.image_root
    LIMIT 1 BY r.ak_name
),
nodes AS
(
    SELECT image_id, image_version, image_root, uniq(ak_name) AS nodes
    FROM bound
    GROUP BY image_id, image_version, image_root
)
SELECT *
FROM
(
SELECT
    i.image_id AS image_id,
    i.image_version AS image_version,
    i.image_root AS image_root,
    toString(i.state) AS state,
    i.sbom_format AS sbom_format,
    i.sbom_sha256 AS sbom_sha256,
    toInt64(toUnixTimestamp(i.built_at)) * 1000 AS built_ms,
    toInt64(toUnixTimestamp(i.scanned_at)) * 1000 AS scanned_ms,
    i.db_version AS db_version,
    ifNull(i.scanned_at < now() - toIntervalSecond((SELECT any(sbom_stale_seconds) FROM shirudo.settings FINAL)), false)
        AS stale,
    f.vulns AS vulns,
    f.critical AS critical,
    f.high AS high,
    n.nodes AS nodes
FROM images AS i
LEFT JOIN findings AS f ON f.sbom_sha256 = i.sbom_sha256 AND f.scanned_at = i.scanned_at
LEFT JOIN nodes AS n
    ON n.image_id = i.image_id AND n.image_version = i.image_version AND n.image_root = i.image_root
UNION ALL
SELECT
    r.image_id,
    r.image_version,
    r.image_root,
    'no_sbom',
    '',
    '',
    toInt64(0),
    toInt64(0),
    '',
    false,
    toUInt64(0),
    toUInt64(0),
    toUInt64(0),
    uniq(r.ak_name)
FROM running AS r
WHERE (r.image_id, r.image_version, r.image_root) NOT IN (SELECT image_id, image_version, image_root FROM images)
      AND (r.image_root != ''
           OR (r.image_id, r.image_version) NOT IN (SELECT image_id, image_version FROM images))
GROUP BY r.image_id, r.image_version, r.image_root
)
ORDER BY image_id, image_version, image_root
