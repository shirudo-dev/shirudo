-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- node_vulns case by case; a node is named for what it shows.
--
-- binding: a root other than the SBOM's is root_mismatch and keeps its
-- rows; an image whose state is not ok, or that has no row, is no_sbom,
-- which keeps the kernel rows and is unknown without any. Of two builds
-- of one version a node gets its own root's, else the newest one's.
-- A package of the kernel and the findings of an older scan are left
-- out, and an image without findings gives none.
--
-- kernel: a release at the fixed one, or one that starts with no number,
-- has no kernel finding.
--
-- shield: a row says what the node has applied, applied_seq and
-- applied_op, and what its tree ends with, next_seq and next_op. On
-- fleet-old, an add of old-fix and its delete, a node at 0 is
-- shield_withdrawn with nothing applied, a node at 1 is shielded with the
-- delete coming, and a node at 2 has applied the delete. On fleet-base,
-- xfs-fix added at 1, deleted at 2 and added again at 3, a node at 0 is
-- shield_pending, a node at 1 has what its mask says of the first add,
-- shielded, module absent or excluded, with the new add coming, a node at
-- 2 is shield_withdrawn with it coming, and a node at 3 has what its mask
-- says of the new add, where both pairs are equal. A node without a mask,
-- or with one that ends before the add it has applied, is unknown there,
-- and still pending or withdrawn where no mask is needed to say so.
--
-- links: EXAMPLE-0303 is linked by hand to the add at 3 only, so that
-- for a node at 1 or 2 the shield is still to come, whatever it has
-- loaded; EXAMPLE-0606 to the add at 1 only, which shields a node at 1,
-- is withdrawn at 2 and no longer counts once the node has applied the
-- add at 3, nor for a node at 0, whose tree ends with an add that is not
-- linked. A manual row gives shield_link manual and loses to a fixes row
-- for the same operation. Of two upatches linked to one advisory the
-- better outcome counts, and an add that is still published, even one
-- whose selector left the node out, counts before a withdrawn upatch.
-- An advisory no upatch is linked to, and any advisory for a node that
-- follows no tree, is exposed_no_shield with no upatch, seq 0, no
-- operation and shield_link none.
--
-- next_shields: a node at 1 on fleet-base is shielded against 0101 and
-- 0606 with the add at 3 coming, which carries 0101 and drops 0606, so
-- 0101 reads true and 0606 false.
--
-- Last, the nodes that are shielded now and about to lose it, and those
-- shielded now with an add coming, with whether it keeps the shield.

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


INSERT INTO shirudo.tree_pubs (tree_id, generation, manifest_digest, parent_manifest_digest, head_seq) VALUES
('fleet-old', 2, 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', 2),
('fleet-two', 2, 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', '0000000000000000000000000000000000000000000000000000000000000000', 2),
('fleet-mix', 3, '9999999999999999999999999999999999999999999999999999999999999999', '8888888888888888888888888888888888888888888888888888888888888888', 3);
INSERT INTO shirudo.tree_ops (tree_id, seq, op, id, selector, repository, manifest_digest, layer_digest, payload_sha256, operation_digest) VALUES
('fleet-old', 1, 'add', 'old-fix', '{"labels":{"role":["edge"]}}', 'oci://registry.example.com/shirudo/fleet-old', '1111111111111111111111111111111111111111111111111111111111111111', '5555555555555555555555555555555555555555555555555555555555555555', '9999999999999999999999999999999999999999999999999999999999999999', 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'),
('fleet-old', 2, 'delete', 'old-fix', '{"labels":{"role":["edge"]}}', 'oci://registry.example.com/shirudo/fleet-old', '2222222222222222222222222222222222222222222222222222222222222222', '6666666666666666666666666666666666666666666666666666666666666666', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'),
('fleet-two', 1, 'add', 'fix-a', '{"labels":{"role":["edge"]}}', 'oci://registry.example.com/shirudo/fleet-two', '1111111111111111111111111111111111111111111111111111111111111111', '5555555555555555555555555555555555555555555555555555555555555555', '9999999999999999999999999999999999999999999999999999999999999999', 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'),
('fleet-two', 2, 'add', 'fix-b', '{"labels":{"role":["edge"]}}', 'oci://registry.example.com/shirudo/fleet-two', '2222222222222222222222222222222222222222222222222222222222222222', '6666666666666666666666666666666666666666666666666666666666666666', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'),
('fleet-mix', 1, 'add', 'fix-a', '{"labels":{"role":["edge"]}}', 'oci://registry.example.com/shirudo/fleet-mix', '2222222222222222222222222222222222222222222222222222222222222222', '6666666666666666666666666666666666666666666666666666666666666666', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'),
('fleet-mix', 2, 'add', 'fix-b', '{"labels":{"role":["edge"]}}', 'oci://registry.example.com/shirudo/fleet-mix', '2222222222222222222222222222222222222222222222222222222222222222', '6666666666666666666666666666666666666666666666666666666666666666', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'),
('fleet-mix', 3, 'delete', 'fix-a', '{"labels":{"role":["edge"]}}', 'oci://registry.example.com/shirudo/fleet-mix', '2222222222222222222222222222222222222222222222222222222222222222', '6666666666666666666666666666666666666666666666666666666666666666', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd');

INSERT INTO shirudo.upatch_fixes (tree_id, seq, id, advisory, source) VALUES
('fleet-base', 1, 'xfs-fix', 'EXAMPLE-0101', 'fixes'),
('fleet-base', 3, 'xfs-fix', 'EXAMPLE-0101', 'fixes'),
('fleet-base', 3, 'xfs-fix', 'EXAMPLE-0101', 'manual'),
('fleet-base', 3, 'xfs-fix', 'EXAMPLE-0303', 'manual'),
('fleet-base', 1, 'xfs-fix', 'EXAMPLE-0606', 'manual'),
('fleet-old', 1, 'old-fix', 'EXAMPLE-0101', 'fixes'),
('fleet-two', 1, 'fix-a', 'EXAMPLE-0101', 'fixes'),
('fleet-two', 2, 'fix-b', 'EXAMPLE-0101', 'fixes'),
('fleet-mix', 1, 'fix-a', 'EXAMPLE-0101', 'fixes'),
('fleet-mix', 2, 'fix-b', 'EXAMPLE-0101', 'fixes');

-- 0101 as on the page; 0303 and 0606 have no fixed release yet; 0404 was
-- fixed before 7.4.2.
INSERT INTO shirudo.kernel_vulns (vuln_id, introduced, fixed, severity) VALUES
('EXAMPLE-0101', [7, 0], [7, 4, 5], 'CRITICAL'),
('EXAMPLE-0303', [7, 4], [], 'MEDIUM'),
('EXAMPLE-0404', [7, 0], [7, 2], 'HIGH'),
('EXAMPLE-0606', [7, 0], [], 'LOW');

CREATE TEMPORARY TABLE scan AS SELECT now() - INTERVAL 1 HOUR AS at;
INSERT INTO shirudo.sbom_images (image_id, image_version, image_root, sbom_format, sbom_sha256, state, built_at, db_version, scanned_at)
SELECT 'fleet-os', '2026.11.1', 'a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c', 'cyclonedx-json', '5b0e2c8a4f6d1e3b7a9c0d2e4f6a8b1c3d5e7f9a0b2c4d6e8f1a3b5c7d9e91d4', 'ok', '2026-11-02 08:00:00', '2', at FROM scan UNION ALL
SELECT 'fleet-os', '2026.11.2', '2222222222222222222222222222222222222222222222222222222222222222', 'cyclonedx-json', '', 'missing', '2026-11-03 08:00:00', '2', at FROM scan UNION ALL
SELECT 'fleet-os', '2026.11.3', 'a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c', 'cyclonedx-json', '', 'hash_mismatch', '2026-11-04 08:00:00', '2', at FROM scan UNION ALL
SELECT 'fleet-os', '2026.11.4', 'a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c', 'cyclonedx-json', '', 'parse_error', '2026-11-05 08:00:00', '2', at FROM scan UNION ALL
SELECT 'fleet-os', '2026.11.5', 'a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c', 'spdx-json', '', 'unsupported_format', '2026-11-06 08:00:00', '2', at FROM scan UNION ALL
SELECT 'fleet-os', '2026.11.6', '6666666666666666666666666666666666666666666666666666666666666666', 'cyclonedx-json', '6666666666666666666666666666666666666666666666666666666666666666', 'ok', '2026-11-07 08:00:00', '2', at FROM scan UNION ALL
SELECT 'fleet-os', '2026.11.7', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'cyclonedx-json', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'ok', '2026-11-08 08:00:00', '2', at FROM scan UNION ALL
SELECT 'fleet-os', '2026.11.7', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'cyclonedx-json', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'ok', '2026-11-09 08:00:00', '2', at FROM scan;
INSERT INTO shirudo.sbom_vulns (sbom_sha256, vuln_id, package, installed, fixed, severity, scanned_at)
SELECT '5b0e2c8a4f6d1e3b7a9c0d2e4f6a8b1c3d5e7f9a0b2c4d6e8f1a3b5c7d9e91d4', 'EXAMPLE-0202', 'openssl', '3.5.1-1', '3.5.1-2', 'HIGH', at FROM scan UNION ALL
SELECT '5b0e2c8a4f6d1e3b7a9c0d2e4f6a8b1c3d5e7f9a0b2c4d6e8f1a3b5c7d9e91d4', 'EXAMPLE-0101', 'linux-image-7.4.2', '7.4.2-1', '7.4.5-1', 'CRITICAL', at FROM scan UNION ALL
SELECT '5b0e2c8a4f6d1e3b7a9c0d2e4f6a8b1c3d5e7f9a0b2c4d6e8f1a3b5c7d9e91d4', 'EXAMPLE-0101', 'kernel-core', '7.4.2-1', '7.4.5-1', 'CRITICAL', at FROM scan UNION ALL
SELECT '5b0e2c8a4f6d1e3b7a9c0d2e4f6a8b1c3d5e7f9a0b2c4d6e8f1a3b5c7d9e91d4', 'EXAMPLE-0909', 'zlib', '1.3-1', '1.3-2', 'LOW', at - INTERVAL 1 DAY FROM scan UNION ALL
SELECT 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'EXAMPLE-0707', 'curl', '8.1-1', '', 'MEDIUM', at FROM scan UNION ALL
SELECT 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'EXAMPLE-0808', 'curl', '8.1-2', '', 'MEDIUM', at FROM scan;

INSERT INTO shirudo.checked (host_name, body, ok, ak_name, ak_public, reset_count, clock)
SELECT node.1, arrayFold((body, change) -> replaceOne(body, change.1, change.2), node.2, f.body),
       1, concat('000b', node.1), 'QUtB', 1, 1000
FROM
(
    SELECT arrayJoin([
        ('binding-root-mismatch', [('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"1111111111111111111111111111111111111111111111111111111111111111"')]),
        ('binding-no-sbom-missing', [('"image_version":"2026.11.1"', '"image_version":"2026.11.2"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"2222222222222222222222222222222222222222222222222222222222222222"')]),
        ('binding-no-sbom-hash', [('"image_version":"2026.11.1"', '"image_version":"2026.11.3"'), ('"kernel_release":"7.4.2"', '"kernel_release":"6.18.9"')]),
        ('binding-no-sbom-parse', [('"image_version":"2026.11.1"', '"image_version":"2026.11.4"'), ('"kernel_release":"7.4.2"', '"kernel_release":"6.18.9"')]),
        ('binding-no-sbom-format', [('"image_version":"2026.11.1"', '"image_version":"2026.11.5"'), ('"kernel_release":"7.4.2"', '"kernel_release":"6.18.9"')]),
        ('binding-no-sbom-no-row', [('"image_version":"2026.11.1"', '"image_version":"2026.12.0"'), ('"kernel_release":"7.4.2"', '"kernel_release":"6.18.9"')]),
        ('binding-clean', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"6666666666666666666666666666666666666666666666666666666666666666"'), ('"kernel_release":"7.4.2"', '"kernel_release":"6.18.9"')]),
        ('build-own-root', [('"image_version":"2026.11.1"', '"image_version":"2026.11.7"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'), ('"kernel_release":"7.4.2"', '"kernel_release":"6.18.9"')]),
        ('build-other-root', [('"image_version":"2026.11.1"', '"image_version":"2026.11.7"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"'), ('"kernel_release":"7.4.2"', '"kernel_release":"6.18.9"')]),
        ('build-no-root', [('"image_version":"2026.11.1"', '"image_version":"2026.11.7"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":null'), ('"kernel_release":"7.4.2"', '"kernel_release":"6.18.9"')]),
        ('kernel-fixed', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"6666666666666666666666666666666666666666666666666666666666666666"'), ('"kernel_release":"7.4.2"', '"kernel_release":"7.4.5"')]),
        ('kernel-unreadable', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"6666666666666666666666666666666666666666666666666666666666666666"'), ('"kernel_release":"7.4.2"', '"kernel_release":"next-20261111"')]),
        ('old-at-0', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"6666666666666666666666666666666666666666666666666666666666666666"'), ('"tree_id":"fleet-base"', '"tree_id":"fleet-old"'), ('"last_seq":3', '"last_seq":0'), ('"mask":"VA=="', '"mask":"AA=="')]),
        ('old-at-1', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"6666666666666666666666666666666666666666666666666666666666666666"'), ('"tree_id":"fleet-base"', '"tree_id":"fleet-old"'), ('"last_seq":3', '"last_seq":1'), ('"mask":"VA=="', '"mask":"QA=="')]),
        ('old-at-2', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"6666666666666666666666666666666666666666666666666666666666666666"'), ('"tree_id":"fleet-base"', '"tree_id":"fleet-old"'), ('"last_seq":3', '"last_seq":2'), ('"mask":"VA=="', '"mask":"UA=="')]),
        ('base-at-0', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"6666666666666666666666666666666666666666666666666666666666666666"'), ('"last_seq":3', '"last_seq":0'), ('"mask":"VA=="', '"mask":"AA=="')]),
        ('base-at-1', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"6666666666666666666666666666666666666666666666666666666666666666"'), ('"last_seq":3', '"last_seq":1'), ('"mask":"VA=="', '"mask":"QA=="')]),
        ('base-at-1-module-absent', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"6666666666666666666666666666666666666666666666666666666666666666"'), ('"last_seq":3', '"last_seq":1'), ('"mask":"VA=="', '"mask":"wA=="')]),
        ('base-at-1-excluded', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"6666666666666666666666666666666666666666666666666666666666666666"'), ('"last_seq":3', '"last_seq":1'), ('"mask":"VA=="', '"mask":"gA=="')]),
        ('base-at-2', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"6666666666666666666666666666666666666666666666666666666666666666"'), ('"last_seq":3', '"last_seq":2'), ('"mask":"VA=="', '"mask":"UA=="')]),
        ('base-at-3', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"6666666666666666666666666666666666666666666666666666666666666666"'), ('"flags":0', '"flags":0')]),
        ('base-at-3-module-absent', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"6666666666666666666666666666666666666666666666666666666666666666"'), ('"mask":"VA=="', '"mask":"XA=="')]),
        ('no-mask-at-0', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"6666666666666666666666666666666666666666666666666666666666666666"'), ('"last_seq":3', '"last_seq":0'), ('"mask":"VA=="', '"mask":null')]),
        ('no-mask-at-2', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"6666666666666666666666666666666666666666666666666666666666666666"'), ('"last_seq":3', '"last_seq":2'), ('"mask":"VA=="', '"mask":null')]),
        ('no-mask-at-3', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"6666666666666666666666666666666666666666666666666666666666666666"'), ('"mask":"VA=="', '"mask":null')]),
        ('mask-too-short-at-3', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"6666666666666666666666666666666666666666666666666666666666666666"'), ('"mask":"VA=="', '"mask":""')]),
        ('shield-best-of-two', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"6666666666666666666666666666666666666666666666666666666666666666"'), ('"tree_id":"fleet-base"', '"tree_id":"fleet-two"'), ('"last_seq":3', '"last_seq":2'), ('"mask":"VA=="', '"mask":"kA=="')]),
        ('shield-live-before-withdrawn', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"6666666666666666666666666666666666666666666666666666666666666666"'), ('"tree_id":"fleet-base"', '"tree_id":"fleet-mix"'), ('"mask":"VA=="', '"mask":"ZA=="')]),
        ('shield-no-tree', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"6666666666666666666666666666666666666666666666666666666666666666"'), ('"tree_id":"fleet-base","generation":3,"base_seq":0,"last_seq":3', '"tree_id":null,"generation":null,"base_seq":null,"last_seq":null'), ('"mask":"VA=="', '"mask":null')])
    ]) AS node
) AS n, fixture AS f;

SYSTEM REFRESH VIEW shirudo.node_status_mv;
SYSTEM WAIT VIEW shirudo.node_status_mv;
SYSTEM REFRESH VIEW shirudo.node_vulns_mv;
SYSTEM WAIT VIEW shirudo.node_vulns_mv;

SELECT node_id, binding, source, vuln_id, package, installed, fixed, exposure, upatch_id, applied_seq, applied_op,
       next_seq, next_op, next_shields, shield_link
FROM shirudo.node_vulns ORDER BY node_id, vuln_id, package;

SELECT 'nodes', uniq(ak_name), (SELECT count() FROM shirudo.node_status) FROM shirudo.node_vulns;

SELECT 'shielded now, delete coming';
SELECT node_id, vuln_id, upatch_id, applied_seq, next_seq
FROM shirudo.node_vulns
WHERE exposure = 'shielded' AND next_seq > applied_seq AND next_op = 'delete'
ORDER BY node_id, vuln_id;

SELECT 'shielded now, add coming';
SELECT node_id, vuln_id, upatch_id, applied_seq, next_seq, next_shields
FROM shirudo.node_vulns
WHERE exposure = 'shielded' AND next_seq > applied_seq AND next_op = 'add'
ORDER BY node_id, vuln_id;
