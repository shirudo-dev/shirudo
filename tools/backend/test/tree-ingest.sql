-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- What jobs/tree-ingest loaded in test/tree-ingest.sh: the publication,
-- its three operations with the digests of shirudo's example, stored
-- without "sha256:", and the advisory of operations 1 and 3. A tree that
-- was never sealed is one segment: base 0, no segment before it and a
-- history root of 64 zeros.

SELECT 'tree_pubs';
SELECT tree_id, generation, manifest_digest, parent_manifest_digest, head_seq,
       segment_base_seq, segment_manifest_digest, history_root,
       published_at BETWEEN now64(3) - INTERVAL 1 HOUR AND now64(3)
FROM shirudo.tree_pubs FINAL;

SELECT 'tree_ops';
SELECT * FROM shirudo.tree_ops FINAL ORDER BY tree_id, seq;

SELECT 'upatch_fixes';
SELECT * FROM shirudo.upatch_fixes FINAL ORDER BY tree_id, seq, advisory;
