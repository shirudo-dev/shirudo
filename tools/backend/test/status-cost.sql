-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- The refresh of node_status reads the newest record of each node and the
-- first of each boot, never the records themselves: of the tables the
-- last refresh read, as system.query_log has them, none is
-- shirudo.keepalive. The table that takes the result has a name of its
-- own for every refresh and is left out. Both that refresh and the one
-- of node_ops read how far each node's history reaches through the
-- projection of node_ops, one row per node, and not its whole history,
-- of which they read only the rows the windows overlap
-- (history_conflicts); the history is refreshed twice, so that the
-- second refresh finds a part to read.

-- The publication of testing/fixtures/keepalive/tree-1.1.0.json, as the
-- ingest job loads it: generation 3 with its three operations.
INSERT INTO shirudo.tree_pubs (tree_id, generation, manifest_digest, parent_manifest_digest, head_seq, published_at) VALUES
('fleet-base', 3, '1f327364233e3f2dcebcd13c0af8d84f886201531b135294bd7356a2f7ed680b', '4ee49208ad87695d862c8cc976d1c910170a3de611cfcee2ce181efd8e0a2942', 3, now64(3) - INTERVAL 10 MINUTE);
INSERT INTO shirudo.tree_ops (tree_id, seq, op, id, selector, repository, manifest_digest, layer_digest, payload_sha256, operation_digest) VALUES
('fleet-base', 1, 'add', 'xfs-fix', '{"labels":{"role":["edge"]}}', 'oci://registry.example.com/shirudo/fleet-base', '98f2c22f02ed3106f44cefae608868f529a38fada82d52a263f230cbda076144', '9ecc7c28f423abab4de35c3dbcb2af66dd44df59c0dcd52f465f7bc6338772e6', '59f8ad56dfc63ce2b91d4b2edd89218694bee7287eaafe06a8624869210cf885', '13b248d4a85d91150717e3e96dc9c2d7a8a43633e3b58f8f6168d408aed26c43'),
('fleet-base', 2, 'delete', 'xfs-fix', '{"labels":{"role":["edge"]}}', 'oci://registry.example.com/shirudo/fleet-base', '4d4f3bf9f68bf0dcbd06bffe4aa9eaf83444430e60936b9b2d11ec6229130a1b', 'e80b73d1bf9f8b4d50e5037f317e68bc4c8b15532187b1a3d73b5152a1596c55', 'f6a8fbb53b29691f47d8e9059a3796ecce2a48e693ec444da690209edef000f1', '5ce215313f29f87bfb87aa0cc65c237bf21bdc7702606e9cc29be187f950074b'),
('fleet-base', 3, 'add', 'xfs-fix', '{"labels":{"role":["edge"]}}', 'oci://registry.example.com/shirudo/fleet-base', 'b25c835b353ba101d51c4473d602764c2f8746a6e60342bcf49d510a868cb62a', '653919e8cd88d08fc0d7d3bee8ac27323fadac7ec0a8b8eb6e9dc5a68c36bc97', '82db4a710ddb53f6e3e245e01001242cfb2d628e542e9ffefbb343b01c48a7bf', 'bd98b27dd5cfc9deeb0e4f49a7d4bd0f991762ec784be9ea838a59966d9dd0dc');
INSERT INTO shirudo.expected_builds (version_id, note) VALUES
('d6d918ad22ff597579e6678bef75adca84d30f9661e0b7bbdbf534eebc138c1f', 'shirudo 2026.11');

-- The bodies of testing/fixtures/keepalive/, byte for byte.
CREATE TEMPORARY TABLE fixture (name String, body String);
INSERT INTO fixture VALUES
('node-a-1.1.0', '{"schema":"shirudo.keepalive/1","boot_id":"168d20a1-5011-4e1b-9924-d8b73c85aa4e","version_id":"d6d918ad22ff597579e6678bef75adca84d30f9661e0b7bbdbf534eebc138c1f","config_root":"1d8465c5b17838303fee92b3905420d294d2c22c576a0bdef0f69f190ed22807","kernel_release":"7.4.2","image_id":"fleet-os","image_version":"2026.11.1","image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c","verdict":"ok","cond":5461,"flags":0,"tamper":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"tree_id":"fleet-base","generation":3,"base_seq":0,"last_seq":3,"base_root":"0000000000000000000000000000000000000000000000000000000000000000","projection_root":"154522480ff8884daa95589e80f26f20248bbf9c192dfbb3cee04e03b4f136a1","mask":"VA==","set_sha256":"74e5bd2c665109f6d8f926af5476c266ad70ab07293ff13b1a13d0b89aa5c1bf","count":1,"not_ok":0}');

INSERT INTO shirudo.checked (host_name, body, ok, ak_name, ak_public, reset_count, clock)
SELECT node.1, arrayFold((body, change) -> replaceOne(body, change.1, change.2), node.3, f.body),
       1, concat('000b', node.1), 'QUtB', 1, 1000
FROM
(
    SELECT arrayJoin([
        ('edge-01', 'node-a-1.1.0', [('"flags":0', '"flags":0')])
    ]) AS node
) AS n
INNER JOIN fixture AS f ON f.name = node.2;
SYSTEM REFRESH VIEW shirudo.node_ops_mv;
SYSTEM WAIT VIEW shirudo.node_ops_mv;
SYSTEM REFRESH VIEW shirudo.node_ops_mv;
SYSTEM WAIT VIEW shirudo.node_ops_mv;
SYSTEM REFRESH VIEW shirudo.node_status_mv;
SYSTEM WAIT VIEW shirudo.node_status_mv;

SYSTEM FLUSH LOGS;

SELECT arrayJoin(arraySort(arrayFilter(name -> name NOT LIKE '%.tmp.%', tables))) AS read
FROM system.query_log
WHERE type = 'QueryFinish' AND query_kind = 'Insert' AND has(tables, 'shirudo.node_status_mv')
ORDER BY event_time_microseconds DESC
LIMIT 1 BY read
LIMIT 20;

SELECT 'reads shirudo.keepalive', has(tables, 'shirudo.keepalive'), read_rows > 0
FROM system.query_log
WHERE type = 'QueryFinish' AND query_kind = 'Insert' AND has(tables, 'shirudo.node_status_mv')
ORDER BY event_time_microseconds DESC
LIMIT 1;

SELECT view, has(projections, 'shirudo.node_ops.reach')
FROM system.query_log
ARRAY JOIN ['shirudo.node_ops_mv', 'shirudo.node_status_mv'] AS view
WHERE type = 'QueryFinish' AND query_kind = 'Insert' AND has(tables, view)
ORDER BY view, event_time_microseconds DESC
LIMIT 1 BY view;
