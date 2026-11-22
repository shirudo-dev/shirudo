-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- One row per shield of shirudo.shield_catalog for the shields view of
-- tools/xtop, at the version put last: the reference and manifest digest
-- bpm tree append takes it by, its selector, the advisories it fixes with
-- their severity and the nodes they leave exposed, and the trees whose
-- newest operation of it is an add. Times are epoch milliseconds.

WITH
newest AS
(
    SELECT
        id,
        argMax(reference, put_at) AS reference,
        argMax(package, put_at) AS package,
        argMax(version, put_at) AS version,
        argMax(manifest_digest, put_at) AS manifest_digest,
        argMax(fixes, put_at) AS fixes,
        argMax(selector, put_at) AS selector,
        argMax(description, put_at) AS description,
        max(put_at) AS last_put,
        count() AS versions
    FROM shirudo.shield_catalog FINAL
    GROUP BY id
),
in_trees AS
(
    SELECT id, arraySort(groupArray(tree_id)) AS trees
    FROM
    (
        SELECT tree_id, id, argMax(op, seq) AS newest_op
        FROM shirudo.tree_ops FINAL
        GROUP BY tree_id, id
    )
    WHERE newest_op = 'add'
    GROUP BY id
),
known AS
(
    -- An advisory both tables know is the kernel's.
    SELECT vuln_id, argMin(severity, rank) AS severity, argMin(package, rank) AS package,
           argMin(source, rank) AS source
    FROM
    (
        SELECT vuln_id, any(severity) AS severity, 'linux' AS package, 'kernel' AS source, 0 AS rank
        FROM shirudo.kernel_vulns FINAL
        GROUP BY vuln_id
        UNION ALL
        SELECT vuln_id, any(severity) AS severity, any(package) AS package, 'sbom' AS source, 1 AS rank
        FROM shirudo.sbom_vulns
        GROUP BY vuln_id
    )
    GROUP BY vuln_id
),
exposure AS
(
    SELECT vuln_id, uniqIf(ak_name, exposure NOT IN ('shielded', 'none', 'unknown')) AS exposed
    FROM shirudo.node_vulns
    WHERE vuln_id != ''
    GROUP BY vuln_id
),
fixes AS
(
    SELECT id, advisory FROM newest ARRAY JOIN fixes AS advisory
),
advisories AS
(
    SELECT
        fx.id AS id,
        arraySort(groupArray(tuple(fx.advisory, ifNull(k.severity, ''), ifNull(k.package, ''),
                                   ifNull(k.source, ''), ifNull(e.exposed, 0)))) AS advisories
    FROM fixes AS fx
    LEFT JOIN known AS k ON k.vuln_id = fx.advisory
    LEFT JOIN exposure AS e ON e.vuln_id = fx.advisory
    GROUP BY id
)
SELECT
    n.id AS id,
    n.package AS package,
    n.version AS version,
    n.reference AS reference,
    n.manifest_digest AS manifest_digest,
    n.selector AS selector,
    n.description AS description,
    toUnixTimestamp64Milli(n.last_put) AS put_ms,
    n.versions AS versions,
    a.advisories AS advisories,
    t.trees AS trees
FROM newest AS n
LEFT JOIN advisories AS a ON a.id = n.id
LEFT JOIN in_trees AS t ON t.id = n.id
ORDER BY id
