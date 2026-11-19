-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- One row per finding, an advisory in a package, over the nodes it
-- affects in node_vulns, for the SBOM view of tools/xtop: how many of
-- them the upatch linked to it shields, and every affected node with its
-- exposure. total is the number of nodes in node_status.

SELECT
    v.vuln_id AS vuln_id,
    v.package AS package,
    any(v.severity) AS severity,
    toString(any(v.source)) AS source,
    any(v.fixed) AS fixed,
    arraySort(groupUniqArray(v.installed)) AS installed,
    uniq(v.ak_name) AS affected,
    ifNull((SELECT uniq(ak_name) FROM shirudo.node_status), 0) AS total,
    anyIf(v.upatch_id, v.upatch_id != '') AS upatch_id,
    uniqIf(v.ak_name, v.exposure = 'shielded') AS shielded,
    uniqIf(v.ak_name, v.exposure = 'shield_pending') AS pending,
    uniqIf(v.ak_name, v.exposure IN ('shield_module_absent', 'shield_excludes_node')) AS idle,
    uniqIf(v.ak_name, v.exposure = 'shield_withdrawn') AS withdrawn,
    uniqIf(v.ak_name, v.exposure = 'exposed_no_shield') AS unshielded,
    max(v.sbom_stale) AS stale,
    arraySort(groupArray(tuple(v.node_id, v.ak_name, toString(v.exposure), v.image_id, v.image_version,
                               v.installed, toString(v.binding), toString(v.status)))) AS nodes
FROM shirudo.node_vulns AS v
WHERE v.vuln_id != ''
GROUP BY v.vuln_id, v.package
ORDER BY vuln_id, package
