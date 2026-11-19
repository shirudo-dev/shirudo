-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- The labels of each node after test/labels-put.sh: edge-01 by its key,
-- which the second put gave it over its node_id's set; edge-02, whose
-- node_id set the second put cleared, and lab-01, which has no set of its
-- own, by the config image they booted; core-01 by its key from the first
-- put, which the second left alone. The refused files loaded nothing.

SELECT node_id, ak_name, labels, by FROM shirudo.node_labels ORDER BY node_id;
SELECT 'sets', count() FROM shirudo.label_sets;
