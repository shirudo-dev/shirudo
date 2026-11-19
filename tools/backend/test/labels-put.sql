-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- The labels of each node after test/labels-put.sh, the union of its
-- sets. edge-01 has its key's set, which the second put gave it, its
-- node_id's, and its config image's, whose role=lab loses to the key's
-- role=edge: a conflict. edge-02, whose node_id set the second put
-- cleared, and lab-01, which has no set of its own, have their config
-- image's. core-01 has its key's set from the first put, which the second
-- left alone. The refused files loaded nothing.

SELECT node_id, ak_name, labels, sources, conflicts FROM shirudo.node_labels ORDER BY node_id;
SELECT node_id, ak_name, key, value, by, given FROM shirudo.label_conflicts ORDER BY node_id, key;
SELECT 'items', count() FROM shirudo.node_label_items;
SELECT 'sets', count() FROM shirudo.label_sets;
