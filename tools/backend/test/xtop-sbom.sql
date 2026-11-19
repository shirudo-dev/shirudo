-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- Every finding of node_vulns is a row of the SBOM view; xtop-sbom.sh
-- prints the rows.

SELECT 'findings', uniqExact(vuln_id, package) FROM shirudo.node_vulns WHERE vuln_id != '';
