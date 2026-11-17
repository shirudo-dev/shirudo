-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- What jobs/tree-ingest loaded in test/tree-ingest-walk.sh: a row in
-- tree_pubs per segment, each naming its base, the sealed segment before
-- it and the history root there, which is 64 zeros for the first and
-- shirudo's history_root over the operation digests after seq 2 and 4
-- for the others; all five operations; and their fixes.

SELECT 'tree_pubs';
SELECT tree_id, generation, manifest_digest, parent_manifest_digest,
       segment_base_seq, head_seq, segment_manifest_digest, history_root
FROM shirudo.tree_pubs FINAL ORDER BY tree_id, generation;

SELECT 'tree_ops';
SELECT tree_id, seq, op, id, manifest_digest, operation_digest
FROM shirudo.tree_ops FINAL ORDER BY tree_id, seq;

SELECT 'upatch_fixes';
SELECT * FROM shirudo.upatch_fixes FINAL ORDER BY tree_id, seq, advisory;

-- The segments join up: each one's base is the head of the one before,
-- and names its manifest.
SELECT 'chain';
SELECT s.generation, p.generation
FROM shirudo.tree_pubs AS s FINAL
INNER JOIN shirudo.tree_pubs AS p FINAL
    ON p.tree_id = s.tree_id AND p.manifest_digest = s.segment_manifest_digest
WHERE s.segment_base_seq = p.head_seq
ORDER BY s.generation;
