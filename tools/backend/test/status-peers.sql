-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- Check 7 groups the nodes at the same point of the same tree with the
-- same config and kernel, and fails the one whose path up to last_seq is
-- not the group's most common: of three edge nodes, the one that passed
-- every operation over. A node alone in its group has no peers and
-- passes. Peers that have seen different heads have masks of different
-- lengths for the same path, and are not outliers for that.

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

INSERT INTO shirudo.checked (host_name, body, ok, ak_name, ak_public, reset_count, clock)
SELECT node.1, arrayFold((body, change) -> replaceOne(body, change.1, change.2), node.3, f.body),
       1, concat('000b', node.1), 'QUtB', 1, 1000
FROM
(
    SELECT arrayJoin([
        ('edge-01', 'node-a-1.1.0', [('"flags":0', '"flags":0')]),
        ('edge-02', 'node-a-1.1.0', [('"flags":0', '"flags":0')]),
        ('edge-03', 'node-a-1.1.0', [('"mask":"VA=="', '"mask":"VAA="')]),
        ('edge-04', 'node-b-1.1.0', [('"config_root":"ff2cbeff5d0e9c41a7b36f28d14ce09b73a5182e6fc40d97b5e2a1683c0f7ff8"', '"config_root":"1d8465c5b17838303fee92b3905420d294d2c22c576a0bdef0f69f190ed22807"')]),
        ('core-01', 'node-b-1.1.0', [('"flags":0', '"flags":0')]),
        ('edge-on-another-kernel', 'node-a-1.1.0', [('"kernel_release":"7.4.2"', '"kernel_release":"7.4.3"')])
    ]) AS node
) AS n
INNER JOIN fixture AS f ON f.name = node.2;
SYSTEM REFRESH VIEW shirudo.node_status_mv;
SYSTEM WAIT VIEW shirudo.node_status_mv;
SELECT node_id, host_name, status, trust, failed_check, generation, last_seq, head_seq, loaded
FROM shirudo.node_status ORDER BY node_id;
SELECT node_id, replaceRegexpOne(line, 'last record -?[0-9]+ s ago', 'last record N s ago')
FROM shirudo.node_status ARRAY JOIN log AS line
WHERE line LIKE '7 %'
ORDER BY node_id, line;
