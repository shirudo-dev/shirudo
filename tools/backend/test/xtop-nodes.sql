-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- Every node of node_status is a row of the nodes view; xtop-nodes.sh
-- prints the rows.

SELECT 'nodes', count() FROM shirudo.node_status;
