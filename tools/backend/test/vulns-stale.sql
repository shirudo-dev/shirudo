-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- An image whose newest scan is older than sbom_stale_seconds of
-- shirudo.settings, two days by default, reads stale in node_vulns while
-- sbom_vulns still has its findings, and never clean: its findings stay,
-- with sbom_stale true on every row of its nodes, kernel rows included,
-- and a node without findings is unknown rather than none, also when
-- the findings have expired, as those of a scan eight days old have. A
-- scan an hour old is fresh, and an image whose state is not ok is
-- no_sbom and never stale. Lowering the setting to half an hour makes
-- the scans of an hour ago stale at the next refresh. The query a UI runs
-- for the stale images counts the nodes on each.

-- What the sbom-scan job writes, in place of a scan: 2026.11.1 three
-- days ago with one finding, 2026.11.6 eight days ago with none left,
-- 2026.11.2 and 2026.11.3 an hour ago, with one finding and with none,
-- and 2026.11.4 three days ago without its SBOM.
CREATE TEMPORARY TABLE scan AS SELECT now() AS at;
INSERT INTO shirudo.sbom_images (image_id, image_version, image_root, sbom_format, sbom_sha256, state, built_at, db_version, scanned_at)
SELECT 'fleet-os', '2026.11.1', 'a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c', 'cyclonedx-json', '1111111111111111111111111111111111111111111111111111111111111111', 'ok', '2026-11-02 08:00:00', '2', at - INTERVAL 3 DAY FROM scan UNION ALL
SELECT 'fleet-os', '2026.11.6', '', 'cyclonedx-json', 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', 'ok', '2026-11-07 08:00:00', '2', at - INTERVAL 8 DAY FROM scan UNION ALL
SELECT 'fleet-os', '2026.11.2', '2222222222222222222222222222222222222222222222222222222222222222', 'cyclonedx-json', 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', 'ok', '2026-11-03 08:00:00', '2', at - INTERVAL 1 HOUR FROM scan UNION ALL
SELECT 'fleet-os', '2026.11.3', '3333333333333333333333333333333333333333333333333333333333333333', 'cyclonedx-json', 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', 'ok', '2026-11-04 08:00:00', '2', at - INTERVAL 1 HOUR FROM scan UNION ALL
SELECT 'fleet-os', '2026.11.4', '4444444444444444444444444444444444444444444444444444444444444444', 'cyclonedx-json', '', 'missing', '2026-11-05 08:00:00', '', at - INTERVAL 3 DAY FROM scan;
INSERT INTO shirudo.sbom_vulns (sbom_sha256, vuln_id, package, installed, fixed, severity, scanned_at)
SELECT '1111111111111111111111111111111111111111111111111111111111111111', 'EXAMPLE-0202', 'openssl', '3.5.1-1', '3.5.1-2', 'HIGH', at - INTERVAL 3 DAY FROM scan UNION ALL
SELECT 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', 'EXAMPLE-0707', 'curl', '8.1-1', '', 'MEDIUM', at - INTERVAL 1 HOUR FROM scan;
INSERT INTO shirudo.kernel_vulns (vuln_id, introduced, fixed, severity) VALUES
('EXAMPLE-0101', [7, 0], [7, 4, 5], 'CRITICAL');

-- The body of testing/fixtures/keepalive/node-a-1.1.0.json, byte for byte.
CREATE TEMPORARY TABLE fixture (name String, body String);
INSERT INTO fixture VALUES
('node-a-1.1.0', '{"schema":"shirudo.keepalive/1","boot_id":"168d20a1-5011-4e1b-9924-d8b73c85aa4e","version_id":"d6d918ad22ff597579e6678bef75adca84d30f9661e0b7bbdbf534eebc138c1f","config_root":"1d8465c5b17838303fee92b3905420d294d2c22c576a0bdef0f69f190ed22807","kernel_release":"7.4.2","image_id":"fleet-os","image_version":"2026.11.1","image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c","verdict":"ok","cond":5461,"flags":0,"tamper":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"tree_id":"fleet-base","generation":3,"base_seq":0,"last_seq":3,"base_root":"0000000000000000000000000000000000000000000000000000000000000000","projection_root":"154522480ff8884daa95589e80f26f20248bbf9c192dfbb3cee04e03b4f136a1","mask":"VA==","set_sha256":"74e5bd2c665109f6d8f926af5476c266ad70ab07293ff13b1a13d0b89aa5c1bf","count":1,"not_ok":0}');

-- A node per case, named for it, on kernel 6.18.9, which no advisory
-- covers, unless the case is a kernel finding.
INSERT INTO shirudo.checked (host_name, body, ok, ak_name, ak_public, reset_count, clock)
SELECT node.1, arrayFold((body, change) -> replaceOne(body, change.1, change.2), node.2, f.body),
       1, concat('000b', node.1), 'QUtB', 1, 1000
FROM
(
    SELECT arrayJoin([
        ('stale-findings', [('"kernel_release":"7.4.2"', '"kernel_release":"6.18.9"')]),
        ('stale-expired', [('"kernel_release":"7.4.2"', '"kernel_release":"6.18.9"'), ('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":null')]),
        ('stale-kernel', [('"image_version":"2026.11.1"', '"image_version":"2026.11.6"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":null')]),
        ('fresh-findings', [('"kernel_release":"7.4.2"', '"kernel_release":"6.18.9"'), ('"image_version":"2026.11.1"', '"image_version":"2026.11.2"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"2222222222222222222222222222222222222222222222222222222222222222"')]),
        ('fresh-clean', [('"kernel_release":"7.4.2"', '"kernel_release":"6.18.9"'), ('"image_version":"2026.11.1"', '"image_version":"2026.11.3"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"3333333333333333333333333333333333333333333333333333333333333333"')]),
        ('no-sbom', [('"kernel_release":"7.4.2"', '"kernel_release":"6.18.9"'), ('"image_version":"2026.11.1"', '"image_version":"2026.11.4"'), ('"image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c"', '"image_root":"4444444444444444444444444444444444444444444444444444444444444444"')])
    ]) AS node
) AS n, fixture AS f;

SYSTEM REFRESH VIEW shirudo.node_status_mv;
SYSTEM WAIT VIEW shirudo.node_status_mv;
SYSTEM REFRESH VIEW shirudo.node_vulns_mv;
SYSTEM WAIT VIEW shirudo.node_vulns_mv;

SELECT node_id, image_version, binding, sbom_stale, source, vuln_id, package, exposure
FROM shirudo.node_vulns ORDER BY node_id, vuln_id, package;

SELECT 'stale images';
SELECT image_id, image_version, uniq(ak_name) AS nodes
FROM shirudo.node_vulns
WHERE sbom_stale
GROUP BY image_id, image_version
ORDER BY image_id, image_version;

INSERT INTO shirudo.settings (stale_seconds, stuck_seconds, window, keepalive_retention_seconds,
                              boot_first_retention_seconds, sbom_stale_seconds)
VALUES (180, 3600, 512, 3600, 2592000, 1800);
SYSTEM REFRESH VIEW shirudo.node_vulns_mv;
SYSTEM WAIT VIEW shirudo.node_vulns_mv;

SELECT 'sbom_stale_seconds 1800';
SELECT node_id, image_version, binding, sbom_stale, source, vuln_id, package, exposure
FROM shirudo.node_vulns ORDER BY node_id, vuln_id, package;
