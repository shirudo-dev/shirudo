-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- After test/tree-ingest-refused.sh only the one publication that
-- `bpm tree show`, here its stub, printed is loaded, and the first two
-- segments of the walk, loaded before the walk that was refused.

SELECT tree_id, generation, manifest_digest, head_seq FROM shirudo.tree_pubs FINAL
ORDER BY tree_id, generation;
SELECT (SELECT count() FROM shirudo.tree_ops FINAL),
       (SELECT count() FROM shirudo.upatch_fixes FINAL);
