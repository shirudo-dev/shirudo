-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- What jobs/tree-ingest loaded in test/tree-ingest-variants.sh: every
-- publication and operation, a selector as compact JSON that still
-- reads as JSON, and fixes only where the list was well formed.

SELECT 'tree_pubs';
SELECT tree_id, generation, parent_manifest_digest, head_seq
FROM shirudo.tree_pubs FINAL ORDER BY tree_id;

SELECT 'tree_ops';
SELECT tree_id, count(), groupArray(seq) FROM
(
    SELECT tree_id, seq FROM shirudo.tree_ops FINAL ORDER BY tree_id, seq
)
GROUP BY tree_id ORDER BY tree_id;
SELECT selector, JSONExtract(selector, 'labels', 'site', 'Array(String)')
FROM shirudo.tree_ops FINAL WHERE tree_id = 'first.tree';

SELECT 'upatch_fixes';
SELECT * FROM shirudo.upatch_fixes FINAL ORDER BY tree_id, seq, advisory;
