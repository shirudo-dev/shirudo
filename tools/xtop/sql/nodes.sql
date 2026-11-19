-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- One row per node for the nodes view of tools/xtop: the outcome of the
-- checks from node_status, what the newest record says it runs from
-- latest, the labels the operator gave it from node_labels, and per node
-- the counts of node_vulns. Times are epoch milliseconds, so that no
-- client reads them in the server's time zone.

WITH vulns AS
(
    SELECT
        ak_name,
        uniqIf(upatch_id, exposure = 'shielded') AS shields_applied,
        uniqIf(upatch_id, exposure = 'shield_pending') AS shields_pending,
        uniqIf(upatch_id, exposure IN ('shield_module_absent', 'shield_excludes_node', 'shield_withdrawn')) AS shields_idle,
        uniqIf(vuln_id, exposure IN ('exposed_no_shield', 'shield_module_absent', 'shield_excludes_node', 'shield_withdrawn')) AS exposed,
        countIf(exposure = 'unknown') AS unknown
    FROM shirudo.node_vulns
    GROUP BY ak_name
)
SELECT
    s.node_id AS node_id,
    s.ak_name AS ak_name,
    s.host_name AS host_name,
    toString(s.status) AS status,
    toString(s.trust) AS trust,
    s.failed_check AS failed_check,
    s.log AS log,
    toUnixTimestamp64Milli(s.last_seen) AS last_seen_ms,
    toInt64(toUnixTimestamp(s.updated_at)) * 1000 AS updated_ms,
    s.generation AS generation,
    s.last_seq AS last_seq,
    s.head_seq AS head_seq,
    s.loaded AS loaded,
    l.kernel_release AS kernel_release,
    l.version_id AS version_id,
    l.image_id AS image_id,
    l.image_version AS image_version,
    v.shields_applied AS shields_applied,
    v.shields_pending AS shields_pending,
    v.shields_idle AS shields_idle,
    v.exposed AS exposed,
    v.unknown AS unknown,
    lb.labels AS labels,
    ifNull(lb.by, 'none') AS labels_by
FROM shirudo.node_status AS s
LEFT JOIN shirudo.latest AS l ON l.ak_name = s.ak_name
LEFT JOIN vulns AS v ON v.ak_name = s.ak_name
LEFT JOIN shirudo.node_labels AS lb ON lb.ak_name = s.ak_name
ORDER BY node_id, ak_name
