-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- Four keys the backend knows, named edge-01, edge-02, core-01 and
-- lab-01. The newest records of the two edge nodes and lab-01 name one
-- config image, that of core-01 another.

INSERT INTO shirudo.nodes (ak_name, node_id)
SELECT record.1, argMinState(record.2, toDateTime64(0, 3))
FROM (SELECT arrayJoin([('000b01', 'edge-01'), ('000b02', 'edge-02'), ('000b03', 'core-01'),
                        ('000b04', 'lab-01')]) AS record)
GROUP BY record.1;

INSERT INTO shirudo.keepalive_latest (ak_name, order_key, config_root) VALUES
('000b01', 1, repeat('c1', 32)),
('000b02', 1, repeat('c1', 32)),
('000b03', 1, repeat('c2', 32)),
('000b04', 1, repeat('c1', 32));
