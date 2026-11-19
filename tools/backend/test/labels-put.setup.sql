-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- Three keys the backend knows, named edge-01, edge-02 and core-01.

INSERT INTO shirudo.nodes (ak_name, node_id)
SELECT record.1, argMinState(record.2, toDateTime64(0, 3))
FROM (SELECT arrayJoin([('000b01', 'edge-01'), ('000b02', 'edge-02'), ('000b03', 'core-01')]) AS record)
GROUP BY record.1;
