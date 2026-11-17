-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- A tree of eight operations, published two at a time, with keepalives
-- whose window is the last two operations, as a node built with a
-- window of 2 sends them: base_seq is the head of the publication before.
-- node_ops records what each node did at every operation as its records
-- arrive, and node_sets what that leaves loaded. Once a window starts past
-- seq 0, check 4 holds base_root against the root stored at base_seq and
-- check 6 takes the upatches applied below the window from node_sets.
-- edge-liar reports a base_root that hides what it applied before its
-- window, and a mask, root and set that agree with that story: only
-- the history shows it, and check 7 compares base_root with its peers'.
-- The contradiction marks the node, and the mark keeps check 4 failing
-- and the history from growing after its window has moved past what the
-- backend stored, until an operator deletes it. edge-swap sends a wider
-- window that starts at the right base_root but calls an operation the
-- history has as applied one whose attach module was not loaded: the
-- roots agree, the code at that seq does not.

INSERT INTO shirudo.tree_pubs (tree_id, generation, manifest_digest, parent_manifest_digest, head_seq, published_at) VALUES
('fleet-long', 1, '1111111111111111111111111111111111111111111111111111111111111111', '', 2, now64(3) - INTERVAL 40 MINUTE),
('fleet-long', 2, '2222222222222222222222222222222222222222222222222222222222222222', '1111111111111111111111111111111111111111111111111111111111111111', 4, now64(3) - INTERVAL 30 MINUTE),
('fleet-long', 3, '3333333333333333333333333333333333333333333333333333333333333333', '2222222222222222222222222222222222222222222222222222222222222222', 6, now64(3) - INTERVAL 20 MINUTE),
('fleet-long', 4, '4444444444444444444444444444444444444444444444444444444444444444', '3333333333333333333333333333333333333333333333333333333333333333', 8, now64(3) - INTERVAL 10 MINUTE);
-- Operations 1 to 3 are those of
-- testing/fixtures/keepalive/tree-1.1.0.json; the digests of the others
-- are made up.
INSERT INTO shirudo.tree_ops (tree_id, seq, op, id, selector, repository, manifest_digest, layer_digest, payload_sha256, operation_digest) VALUES
('fleet-long', 1, 'add', 'xfs-fix', '{"labels":{"role":["edge"]}}', 'oci://registry.example.com/shirudo/fleet-long', '98f2c22f02ed3106f44cefae608868f529a38fada82d52a263f230cbda076144', '9ecc7c28f423abab4de35c3dbcb2af66dd44df59c0dcd52f465f7bc6338772e6', '59f8ad56dfc63ce2b91d4b2edd89218694bee7287eaafe06a8624869210cf885', '13b248d4a85d91150717e3e96dc9c2d7a8a43633e3b58f8f6168d408aed26c43'),
('fleet-long', 2, 'delete', 'xfs-fix', '{"labels":{"role":["edge"]}}', 'oci://registry.example.com/shirudo/fleet-long', '4d4f3bf9f68bf0dcbd06bffe4aa9eaf83444430e60936b9b2d11ec6229130a1b', 'e80b73d1bf9f8b4d50e5037f317e68bc4c8b15532187b1a3d73b5152a1596c55', 'f6a8fbb53b29691f47d8e9059a3796ecce2a48e693ec444da690209edef000f1', '5ce215313f29f87bfb87aa0cc65c237bf21bdc7702606e9cc29be187f950074b'),
('fleet-long', 3, 'add', 'xfs-fix', '{"labels":{"role":["edge"]}}', 'oci://registry.example.com/shirudo/fleet-long', 'b25c835b353ba101d51c4473d602764c2f8746a6e60342bcf49d510a868cb62a', '653919e8cd88d08fc0d7d3bee8ac27323fadac7ec0a8b8eb6e9dc5a68c36bc97', '82db4a710ddb53f6e3e245e01001242cfb2d628e542e9ffefbb343b01c48a7bf', 'bd98b27dd5cfc9deeb0e4f49a7d4bd0f991762ec784be9ea838a59966d9dd0dc'),
('fleet-long', 4, 'add', 'net-guard', '{"labels":{"role":["edge"]}}', 'oci://registry.example.com/shirudo/fleet-long', '4444444444444444444444444444444444444444444444444444444444444404', '4444444444444444444444444444444444444444444444444444444444444414', 'c1a4ce09e5b1fb14befa6c31b1686c93d65751a5f7882a70ba74ae53eff1c445', 'b5a7fd0926194d53c3c38d9a9f33191d22dbcf421eabb6a095af1b0dda854017'),
('fleet-long', 5, 'add', 'log-tap', '{"labels":{"role":["core"]}}', 'oci://registry.example.com/shirudo/fleet-long', '5555555555555555555555555555555555555555555555555555555555555505', '5555555555555555555555555555555555555555555555555555555555555515', '1c838773b1a663e05f30a70eb492a091cf7edf9e8636c0467bf4c75bc6492b60', '7e7d4e53558bdf3a32dad9b9cb76617d8c4d72df92da85bae8b80ea39dbc8de3'),
('fleet-long', 6, 'add', 'net-guard', '{"labels":{"role":["edge"]}}', 'oci://registry.example.com/shirudo/fleet-long', '6666666666666666666666666666666666666666666666666666666666666606', '6666666666666666666666666666666666666666666666666666666666666616', '04327d1d09b5fd365976ae08b7868ce475c7e05ea06e7953298dc49f0b49a73e', '9482a7501c078b476df790ad7f3d293fc33c8fac98656b942fa9c04066fe6701'),
('fleet-long', 7, 'delete', 'log-tap', '{"labels":{"role":["core"]}}', 'oci://registry.example.com/shirudo/fleet-long', '7777777777777777777777777777777777777777777777777777777777777707', '7777777777777777777777777777777777777777777777777777777777777717', '8b0e09319c7612405a657c8adb8ddae1094224cfe816b63ee7713f982014736b', '48c8470b6db1077529650c52be2eada465d1ec6795565532a79aa0432e268152'),
('fleet-long', 8, 'delete', 'net-guard', '{"labels":{"role":["edge"]}}', 'oci://registry.example.com/shirudo/fleet-long', '8888888888888888888888888888888888888888888888888888888888888808', '8888888888888888888888888888888888888888888888888888888888888818', '45517a96247744dacfcb009e9b9a1393feb7593641b463b8bb60a8bec3a545b2', 'a7e69500fd7613e54bcbd7dccffe0d8a081145e93a59f2230114d08b9c8a81cd');
INSERT INTO shirudo.expected_builds (version_id, note) VALUES
('d6d918ad22ff597579e6678bef75adca84d30f9661e0b7bbdbf534eebc138c1f', 'shirudo 2026.11');

-- The bodies of node A and node B of testing/fixtures/keepalive/ with
-- the tree keys left for each record to fill in.
CREATE TEMPORARY TABLE fixture (name String, body String);
INSERT INTO fixture VALUES
('a', '{"schema":"shirudo.keepalive/1","boot_id":"168d20a1-5011-4e1b-9924-d8b73c85aa4e","version_id":"d6d918ad22ff597579e6678bef75adca84d30f9661e0b7bbdbf534eebc138c1f","config_root":"1d8465c5b17838303fee92b3905420d294d2c22c576a0bdef0f69f190ed22807","kernel_release":"7.4.2","image_id":"fleet-os","image_version":"2026.11.1","image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c","verdict":"ok","cond":5461,"flags":0,"tamper":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],@TREE@,"not_ok":0}'),
('b', '{"schema":"shirudo.keepalive/1","boot_id":"9a6f14ea-0cc2-45e1-8e23-7b887120cf54","version_id":"d6d918ad22ff597579e6678bef75adca84d30f9661e0b7bbdbf534eebc138c1f","config_root":"ff2cbeff5d0e9c41a7b36f28d14ce09b73a5182e6fc40d97b5e2a1683c0f7ff8","kernel_release":"7.4.2","image_id":"fleet-os","image_version":"2026.11.1","image_root":null,"verdict":"ok","cond":5461,"flags":0,"tamper":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],@TREE@,"not_ok":0}');

-- edge-swap is an edge node of its own configuration, so that it has no
-- peers.
INSERT INTO fixture
SELECT 'c', replaceOne(body, '1d8465c5b17838303fee92b3905420d294d2c22c576a0bdef0f69f190ed22807',
                       'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc')
FROM fixture WHERE name = 'a';

-- The tree keys of each record: an edge node applies every edge
-- operation and passes the core ones over, a core node the other way
-- round. Generation g has its head at 2g and the window starts at 2g - 2.
CREATE TEMPORARY TABLE tree_keys (path String, generation UInt64, base_root String, projection_root String, mask String, set_sha256 String, count UInt64);
INSERT INTO tree_keys VALUES
('edge', 1, '0000000000000000000000000000000000000000000000000000000000000000', 'a042a582b3a3d8c1b633b8ed0356e0b52f1f5aa25af85b06cc3f481562dcda93', 'UA==', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0),
('edge', 2, 'a042a582b3a3d8c1b633b8ed0356e0b52f1f5aa25af85b06cc3f481562dcda93', '61fc83b3a0ac0db078d815d7a1d5656d1c1b86969c33b2502a9d4553a475f75f', 'UA==', '55fe60cc8e2f809e798c3f733a1186a1a4a5d3c23bafce8278d9f6613fd24f20', 2),
('edge', 3, '61fc83b3a0ac0db078d815d7a1d5656d1c1b86969c33b2502a9d4553a475f75f', 'c7a9860aeaaa41c9b5960ea49d36bf8493829fe711d6ee041615a59e3e4a160b', 'kA==', '39cfdd2bbb3ee01e93c5f663d4f5b416ed5eac60af43d1a88d075b4d352fd352', 2),
('edge', 4, 'c7a9860aeaaa41c9b5960ea49d36bf8493829fe711d6ee041615a59e3e4a160b', '7abe8b4e5b09b24d541e029f0c21b7fddc42088b538544b28874d20820edfcd4', 'kA==', '74e5bd2c665109f6d8f926af5476c266ad70ab07293ff13b1a13d0b89aa5c1bf', 1),
('core', 1, '0000000000000000000000000000000000000000000000000000000000000000', '0000000000000000000000000000000000000000000000000000000000000000', 'oA==', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0),
('core', 2, '0000000000000000000000000000000000000000000000000000000000000000', '0000000000000000000000000000000000000000000000000000000000000000', 'oA==', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0),
('core', 3, '0000000000000000000000000000000000000000000000000000000000000000', '7eb926ee3992a1b56d01db3f58713440ca1c7378b02a9c6354e59d2e32cd577f', 'YA==', '885e4806c48d2d850267ee7f714abd8da2bd679483f6d60323fe8499fe8af7f9', 1),
('core', 4, '7eb926ee3992a1b56d01db3f58713440ca1c7378b02a9c6354e59d2e32cd577f', '2b11a79d680e7ebfe4ac646730b29f6247080ecd765d2b1d83538f21f011030a', 'YA==', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0),
-- An edge node at generation 3 that says it applied nothing before seq 4.
('liar', 3, '0000000000000000000000000000000000000000000000000000000000000000', '78b6a625584ca000a0b7821895cb9441563e4d00f4ec0193ee1395976e16593e', 'kA==', 'fee50b592ea40c6ae2f6ecf6bed6fa2781e1a791e1b9b7a443f2f7f38c6ee650', 1),
-- An edge node at generation 4 with a window from seq 4 that marks seq 6
-- 3 instead of 1.
('swap', 4, '61fc83b3a0ac0db078d815d7a1d5656d1c1b86969c33b2502a9d4553a475f75f', '7abe8b4e5b09b24d541e029f0c21b7fddc42088b538544b28874d20820edfcd4', 'uQ==', '74e5bd2c665109f6d8f926af5476c266ad70ab07293ff13b1a13d0b89aa5c1bf', 1);

-- The records of each round: in round g every node sends its record of
-- generation g, or the one its line names, with its window from
-- 2g - 2 but for edge-swap's at generation 4.
CREATE TEMPORARY TABLE records (round UInt64, host String, body String);
INSERT INTO records
SELECT r.4, r.1,
       replaceOne(f.body, '@TREE@',
                  format('"tree_id":"fleet-long","generation":{},"base_seq":{},"last_seq":{},"base_root":"{}","projection_root":"{}","mask":"{}","set_sha256":"{}","count":{}',
                         toString(t.generation), toString(if(t.path = 'swap', 4, 2 * t.generation - 2)), toString(2 * t.generation),
                         t.base_root, t.projection_root, t.mask, t.set_sha256, toString(t.count)))
FROM (SELECT arrayJoin(arrayFlatten(arrayMap(g -> [
          ('edge-01', 'a', 'edge', g), ('edge-02', 'a', 'edge', g),
          ('edge-liar', 'a', if(g = 3, 'liar', 'edge'), g), ('edge-swap', 'c', if(g = 4, 'swap', 'edge'), g),
          ('core-01', 'b', 'core', g)], range(1, 5)))) AS r) AS x
INNER JOIN fixture AS f ON f.name = r.2
INNER JOIN tree_keys AS t ON t.path = r.3 AND t.generation = r.4;

-- Round 1: windows from seq 0, held against the tree alone.
INSERT INTO shirudo.checked (host_name, body, ok, ak_name, ak_public, reset_count, clock)
SELECT host, body, 1, concat('000b', host), 'QUtB', 1, 1000 * round FROM records WHERE round = 1;
SYSTEM REFRESH VIEW shirudo.node_ops_mv;
SYSTEM WAIT VIEW shirudo.node_ops_mv;
SYSTEM REFRESH VIEW shirudo.node_status_mv;
SYSTEM WAIT VIEW shirudo.node_status_mv;
SELECT 'round 1';
SELECT node_id, status, failed_check, log[4], log[6], log[7] FROM shirudo.node_status ORDER BY node_id;

-- Round 2: base_seq 2, which the history of round 1 reaches.
INSERT INTO shirudo.checked (host_name, body, ok, ak_name, ak_public, reset_count, clock)
SELECT host, body, 1, concat('000b', host), 'QUtB', 1, 1000 * round FROM records WHERE round = 2;
SYSTEM REFRESH VIEW shirudo.node_status_mv;
SYSTEM WAIT VIEW shirudo.node_status_mv;
SYSTEM REFRESH VIEW shirudo.node_ops_mv;
SYSTEM WAIT VIEW shirudo.node_ops_mv;
SELECT 'round 2';
SELECT node_id, status, failed_check, log[4], log[6], log[7] FROM shirudo.node_status ORDER BY node_id;

-- Round 3: edge-liar gives another base_root than its history has, and
-- is marked for it.
INSERT INTO shirudo.checked (host_name, body, ok, ak_name, ak_public, reset_count, clock)
SELECT host, body, 1, concat('000b', host), 'QUtB', 1, 1000 * round FROM records WHERE round = 3;
SYSTEM REFRESH VIEW shirudo.node_ops_mv;
SYSTEM WAIT VIEW shirudo.node_ops_mv;
SYSTEM REFRESH VIEW shirudo.history_contradictions_mv;
SYSTEM WAIT VIEW shirudo.history_contradictions_mv;
SYSTEM REFRESH VIEW shirudo.node_status_mv;
SYSTEM WAIT VIEW shirudo.node_status_mv;
SELECT 'round 3';
SELECT node_id, status, failed_check, log[4], log[6], log[7] FROM shirudo.node_status ORDER BY node_id;

-- Round 4: the window of an edge node no longer holds xfs-fix, which
-- the set still has. edge-liar's window starts past its history, which
-- would be a gap, but its mark stays. edge-swap contradicts its history
-- inside the window, though base_root, the roots and the set agree.
INSERT INTO shirudo.checked (host_name, body, ok, ak_name, ak_public, reset_count, clock)
SELECT host, body, 1, concat('000b', host), 'QUtB', 1, 1000 * round FROM records WHERE round = 4;
SYSTEM REFRESH VIEW shirudo.node_ops_mv;
SYSTEM WAIT VIEW shirudo.node_ops_mv;
SYSTEM REFRESH VIEW shirudo.history_contradictions_mv;
SYSTEM WAIT VIEW shirudo.history_contradictions_mv;
SYSTEM REFRESH VIEW shirudo.node_status_mv;
SYSTEM WAIT VIEW shirudo.node_status_mv;
SELECT 'round 4';
SELECT node_id, status, failed_check, log[4], log[6], log[7] FROM shirudo.node_status ORDER BY node_id;
SELECT 'marks';
SELECT n.node_id, m.tree_id, m.seq, m.reason
FROM shirudo.history_contradictions AS m
INNER JOIN shirudo.node_status AS n ON n.ak_name = m.ak_name
ORDER BY n.node_id;

-- An operator clears both marks, as the backend documentation says.
-- edge-liar's next refresh starts a gap and it passes; edge-swap's
-- record still contradicts its history and marks it again.
DELETE FROM shirudo.history_contradictions WHERE ak_name = '000bedge-liar';
DELETE FROM shirudo.history_contradictions WHERE ak_name = '000bedge-swap';
SYSTEM REFRESH VIEW shirudo.node_ops_mv;
SYSTEM WAIT VIEW shirudo.node_ops_mv;
SYSTEM REFRESH VIEW shirudo.history_contradictions_mv;
SYSTEM WAIT VIEW shirudo.history_contradictions_mv;
SYSTEM REFRESH VIEW shirudo.node_status_mv;
SYSTEM WAIT VIEW shirudo.node_status_mv;
SELECT 'cleared';
SELECT node_id, status, failed_check, log[4], log[6], log[7] FROM shirudo.node_status
WHERE node_id IN ('edge-liar', 'edge-swap') ORDER BY node_id;
SELECT 'marks';
SELECT n.node_id, m.tree_id, m.seq, m.reason
FROM shirudo.history_contradictions AS m
INNER JOIN shirudo.node_status AS n ON n.ak_name = m.ak_name
ORDER BY n.node_id;

-- What the backend stored: edge-liar's history stops where its story
-- changed and starts again with a gap once its mark is cleared;
-- edge-swap's stops at seq 6, since its records no longer extend it.
SELECT 'history';
SELECT n.node_id, h.seq, h.code, substring(lower(hex(h.root)), 1, 8)
FROM shirudo.node_ops AS h FINAL
INNER JOIN shirudo.node_status AS n ON n.ak_name = h.ak_name
ORDER BY n.node_id, h.seq;
SELECT n.node_id, s.id, s.last_seq, s.last_op, substring(s.last_payload, 1, 8)
FROM shirudo.node_sets AS s FINAL
INNER JOIN shirudo.node_status AS n ON n.ak_name = s.ak_name
ORDER BY n.node_id, s.id;

-- A refresh that finds nothing new adds nothing.
SYSTEM REFRESH VIEW shirudo.node_ops_mv;
SYSTEM WAIT VIEW shirudo.node_ops_mv;
SELECT 'rows', count() FROM shirudo.node_ops;
