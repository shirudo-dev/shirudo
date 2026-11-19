-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- The nodes of vulns-fixtures.sql, node A shielded, node B left out by
-- the selector and node C with no image, and two more for the states the
-- nodes view of tools/xtop tells apart: node D sends node A's record with
-- a verdict that is not ok, so check 3 fails it, and node E sent node
-- B's record an hour ago and turns stale. Generation 4 of the tree adds
-- ssl-fix for the openssl finding at operation 4, which no node has
-- reached yet: a rollout under way, for the shields view. The test
-- xtop-shields reads the same rows.

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
('node-a-1.1.0', '{"schema":"shirudo.keepalive/1","boot_id":"168d20a1-5011-4e1b-9924-d8b73c85aa4e","version_id":"d6d918ad22ff597579e6678bef75adca84d30f9661e0b7bbdbf534eebc138c1f","config_root":"1d8465c5b17838303fee92b3905420d294d2c22c576a0bdef0f69f190ed22807","kernel_release":"7.4.2","image_id":"fleet-os","image_version":"2026.11.1","image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c","verdict":"ok","cond":5461,"flags":0,"tamper":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"tree_id":"fleet-base","generation":3,"base_seq":0,"last_seq":3,"base_root":"0000000000000000000000000000000000000000000000000000000000000000","projection_root":"154522480ff8884daa95589e80f26f20248bbf9c192dfbb3cee04e03b4f136a1","mask":"VA==","set_sha256":"74e5bd2c665109f6d8f926af5476c266ad70ab07293ff13b1a13d0b89aa5c1bf","count":1,"not_ok":0}'),
('node-b-1.1.0', '{"schema":"shirudo.keepalive/1","boot_id":"9a6f14ea-0cc2-45e1-8e23-7b887120cf54","version_id":"d6d918ad22ff597579e6678bef75adca84d30f9661e0b7bbdbf534eebc138c1f","config_root":"ff2cbeff5d0e9c41a7b36f28d14ce09b73a5182e6fc40d97b5e2a1683c0f7ff8","kernel_release":"7.4.2","image_id":"fleet-os","image_version":"2026.11.1","image_root":null,"verdict":"ok","cond":5461,"flags":0,"tamper":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"tree_id":"fleet-base","generation":3,"base_seq":0,"last_seq":3,"base_root":"0000000000000000000000000000000000000000000000000000000000000000","projection_root":"0000000000000000000000000000000000000000000000000000000000000000","mask":"qA==","set_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","count":0,"not_ok":0}');


-- What the tree ingest job takes from the fixes of operations 1 and 3.
INSERT INTO shirudo.upatch_fixes (tree_id, seq, id, advisory, source) VALUES
('fleet-base', 1, 'xfs-fix', 'EXAMPLE-0101', 'fixes'),
('fleet-base', 3, 'xfs-fix', 'EXAMPLE-0101', 'fixes');

-- What the sbom-scan job writes for the image and its one finding, in
-- place of a scan, and the kernel advisory.
CREATE TEMPORARY TABLE scan AS SELECT now() - INTERVAL 1 HOUR AS at;
INSERT INTO shirudo.sbom_images (image_id, image_version, image_root, sbom_format, sbom_sha256, state, built_at, db_version, scanned_at)
SELECT 'fleet-os', '2026.11.1', 'a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c', 'cyclonedx-json',
       '5b0e2c8a4f6d1e3b7a9c0d2e4f6a8b1c3d5e7f9a0b2c4d6e8f1a3b5c7d9e91d4', 'ok', '2026-11-02 08:00:00', '2', at
FROM scan;
INSERT INTO shirudo.sbom_vulns (sbom_sha256, vuln_id, package, installed, fixed, severity, scanned_at)
SELECT '5b0e2c8a4f6d1e3b7a9c0d2e4f6a8b1c3d5e7f9a0b2c4d6e8f1a3b5c7d9e91d4', 'EXAMPLE-0202', 'openssl', '3.5.1-1', '3.5.1-2', 'HIGH', at
FROM scan;
INSERT INTO shirudo.kernel_vulns (vuln_id, introduced, fixed, severity) VALUES
('EXAMPLE-0101', [7, 0], [7, 4, 5], 'CRITICAL');

INSERT INTO shirudo.checked (host_name, body, ok, ak_name, ak_public, reset_count, clock)
SELECT 'edge-01', body, 1, '000b23602ab98bfb', 'QUtB', 7, 86523114 FROM fixture WHERE name = 'node-a-1.1.0';
INSERT INTO shirudo.checked (host_name, body, ok, ak_name, ak_public, reset_count, clock)
SELECT 'core-01', body, 1, '000b9d72e08380a1', 'QUtC', 4, 91200408 FROM fixture WHERE name = 'node-b-1.1.0';
INSERT INTO shirudo.checked (host_name, body, ok, ak_name, ak_public, reset_count, clock)
SELECT 'lab-01', replaceOne(replaceOne(replaceOne(body, '"tree_id":"fleet-base","generation":3,"base_seq":0,"last_seq":3,"base_root":"0000000000000000000000000000000000000000000000000000000000000000","projection_root":"0000000000000000000000000000000000000000000000000000000000000000","mask":"qA=="', '"tree_id":null,"generation":null,"base_seq":null,"last_seq":null,"base_root":null,"projection_root":null,"mask":null'),
       '"kernel_release":"7.4.2","image_id":"fleet-os","image_version":"2026.11.1"', '"kernel_release":"7.5.1","image_id":null,"image_version":null'),
       '9a6f14ea-0cc2-45e1-8e23-7b887120cf54', '5c1d7e2f-3a4b-4c5d-8e6f-7a8b9c0d1e2f'),
       1, '000b0c', 'QUtD', 1, 1000 FROM fixture WHERE name = 'node-b-1.1.0';

INSERT INTO shirudo.checked (host_name, body, ok, ak_name, ak_public, reset_count, clock)
SELECT 'edge-02', replaceOne(body, '"verdict":"ok"', '"verdict":"degraded"'), 1, '000b0d', 'QUtE', 2, 2000
FROM fixture WHERE name = 'node-a-1.1.0';
INSERT INTO shirudo.checked (received, host_name, body, ok, ak_name, ak_public, reset_count, clock)
SELECT now64(3) - INTERVAL 1 HOUR, 'core-02', body, 1, '000b0e', 'QUtF', 3, 3000
FROM fixture WHERE name = 'node-b-1.1.0';

-- Generation 4: operation 4 adds ssl-fix for the openssl finding. Its
-- digests are made up; no node reaches it.
INSERT INTO shirudo.tree_pubs (tree_id, generation, manifest_digest, parent_manifest_digest, head_seq, published_at) VALUES
('fleet-base', 4, '7d1e0f2a9b8c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e', '1f327364233e3f2dcebcd13c0af8d84f886201531b135294bd7356a2f7ed680b', 4, now64(3) - INTERVAL 1 MINUTE);
INSERT INTO shirudo.tree_ops (tree_id, seq, op, id, selector, repository, manifest_digest, layer_digest, payload_sha256, operation_digest) VALUES
('fleet-base', 4, 'add', 'ssl-fix', '{}', 'oci://registry.example.com/shirudo/fleet-base', 'c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00', 'c0ffee01c0ffee01c0ffee01c0ffee01c0ffee01c0ffee01c0ffee01c0ffee01', 'c0ffee02c0ffee02c0ffee02c0ffee02c0ffee02c0ffee02c0ffee02c0ffee02', 'c0ffee03c0ffee03c0ffee03c0ffee03c0ffee03c0ffee03c0ffee03c0ffee03');
INSERT INTO shirudo.upatch_fixes (tree_id, seq, id, advisory, source) VALUES
('fleet-base', 4, 'ssl-fix', 'EXAMPLE-0202', 'fixes');

-- The operator's labels, as the page has them.
INSERT INTO shirudo.nodes (ak_name, node_id)
SELECT record.1, argMinState(record.2, toDateTime64(0, 3))
FROM (SELECT arrayJoin([('000b23602ab98bfb', 'node-a'), ('000b9d72e08380a1', 'node-b'), ('000b0c', 'node-c'), ('000b0d', 'node-d'), ('000b0e', 'node-e')]) AS record)
GROUP BY record.1;

SYSTEM REFRESH VIEW shirudo.node_ops_mv;
SYSTEM WAIT VIEW shirudo.node_ops_mv;
SYSTEM REFRESH VIEW shirudo.node_status_mv;
SYSTEM WAIT VIEW shirudo.node_status_mv;
SYSTEM REFRESH VIEW shirudo.node_vulns_mv;
SYSTEM WAIT VIEW shirudo.node_vulns_mv;
