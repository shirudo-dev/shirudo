-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- The keys after test/enroll-put.sh. The key the backend had seen as
-- host-a is enrolled and named edge-01, the builder's name; the one it
-- had not seen is enrolled and named core-01, the operator's rename. The
-- refused file, which named a third key, loaded nothing, and neither did
-- --check.

SELECT right(ak_name, 4), argMinMerge(node_id), max(trust), min(first_seen) FROM shirudo.nodes
GROUP BY ak_name ORDER BY ak_name;
SELECT right(ak_name, 4), right(ek_name, 4), node_id, source FROM shirudo.enrollments FINAL ORDER BY ak_name;
