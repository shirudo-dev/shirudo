-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- One row per upatch of every tree for the shields view of tools/xtop:
-- its newest operation, the advisories the newest add of it fixes with
-- their severity and package, the images that carry them, and how the
-- nodes following the tree came out of the newest operation, from their
-- history in node_ops. A node whose record has not reached that
-- operation is pending. Times are epoch milliseconds.

WITH
shields AS
(
    SELECT
        tree_id,
        id,
        max(o.seq) AS newest_seq,
        argMax(o.op, o.seq) AS newest_op,
        maxIf(o.seq, o.op = 'add') AS add_seq,
        count() AS ops,
        argMax(o.manifest_digest, o.seq) AS newest_manifest,
        argMax(o.repository, o.seq) AS newest_repository,
        argMax(o.selector, o.seq) AS newest_selector
    FROM shirudo.tree_ops AS o FINAL
    GROUP BY tree_id, id
),
published AS
(
    SELECT s.tree_id AS tree_id, s.id AS id, min(p.published_at) AS published_at
    FROM shields AS s
    INNER JOIN shirudo.tree_pubs AS p FINAL ON p.tree_id = s.tree_id
    WHERE p.head_seq >= s.newest_seq
    GROUP BY tree_id, id
),
fixes AS
(
    SELECT DISTINCT s.tree_id AS tree_id, s.id AS id, f.advisory AS advisory
    FROM shields AS s
    INNER JOIN shirudo.upatch_fixes AS f FINAL
        ON f.tree_id = s.tree_id AND f.id = s.id AND f.seq = s.add_seq
),
known AS
(
    SELECT vuln_id, any(severity) AS severity, 'linux' AS package, 'kernel' AS source
    FROM shirudo.kernel_vulns FINAL
    GROUP BY vuln_id
    UNION ALL
    SELECT vuln_id, any(severity) AS severity, any(package) AS package, 'sbom' AS source
    FROM shirudo.sbom_vulns
    GROUP BY vuln_id
),
exposure AS
(
    SELECT
        upatch_id,
        vuln_id,
        uniqIf(ak_name, exposure = 'shielded') AS shielded,
        uniqIf(ak_name, exposure NOT IN ('shielded', 'none', 'unknown')) AS exposed,
        arraySort(groupUniqArrayIf(concat(image_id, ' ', image_version), image_id != '')) AS images
    FROM shirudo.node_vulns
    WHERE vuln_id != ''
    GROUP BY upatch_id, vuln_id
),
advisories AS
(
    SELECT
        fx.tree_id AS tree_id,
        fx.id AS id,
        arraySort(groupArray(tuple(fx.advisory, ifNull(k.severity, ''), ifNull(k.package, ''),
                                   ifNull(k.source, ''), e.shielded, e.exposed))) AS advisories,
        arraySort(arrayDistinct(arrayFlatten(groupArray(e.images)))) AS images
    FROM fixes AS fx
    LEFT JOIN known AS k ON k.vuln_id = fx.advisory
    LEFT JOIN exposure AS e ON e.upatch_id = fx.id AND e.vuln_id = fx.advisory
    GROUP BY tree_id, id
),
history AS
(
    SELECT ak_name, tree_id, seq, code
    FROM shirudo.node_ops FINAL
),
rollout AS
(
    SELECT
        s.tree_id AS tree_id,
        s.id AS id,
        uniq(l.ak_name) AS nodes,
        uniqIf(l.ak_name, h.code = 1) AS applied,
        uniqIf(l.ak_name, h.code = 2) AS not_selected,
        uniqIf(l.ak_name, h.code = 3) AS no_target,
        uniqIf(l.ak_name, ifNull(l.last_seq, 0) < s.newest_seq) AS pending
    FROM shields AS s
    INNER JOIN (SELECT ak_name, assumeNotNull(tree_id) AS tree_id, last_seq
                FROM shirudo.latest WHERE tree_id IS NOT NULL) AS l ON l.tree_id = s.tree_id
    LEFT JOIN history AS h ON h.ak_name = l.ak_name AND h.tree_id = s.tree_id AND h.seq = s.newest_seq
    GROUP BY tree_id, id
)
SELECT
    s.tree_id AS tree_id,
    s.id AS id,
    s.newest_seq AS seq,
    toString(s.newest_op) AS op,
    s.add_seq AS add_seq,
    s.ops AS ops,
    s.newest_manifest AS manifest_digest,
    s.newest_repository AS repository,
    s.newest_selector AS selector,
    toUnixTimestamp64Milli(p.published_at) AS published_ms,
    a.advisories AS advisories,
    a.images AS images,
    r.nodes AS nodes,
    r.applied AS applied,
    r.not_selected AS not_selected,
    r.no_target AS no_target,
    r.pending AS pending
FROM shields AS s
LEFT JOIN published AS p ON p.tree_id = s.tree_id AND p.id = s.id
LEFT JOIN advisories AS a ON a.tree_id = s.tree_id AND a.id = s.id
LEFT JOIN rollout AS r ON r.tree_id = s.tree_id AND r.id = s.id
ORDER BY tree_id, id
