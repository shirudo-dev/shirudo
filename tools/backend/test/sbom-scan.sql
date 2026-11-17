-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- What jobs/sbom-scan loaded in test/sbom-scan.sh: a row for every image
-- it could read, with the state of its SBOM, and the findings of the two
-- scans of fleet-os 2026.11.1 without the kernel packages and with one
-- finding the report gave twice once; 2026.11.13, built from the same
-- SBOM, adds none. The image's row has the time of
-- the second scan, which is later than the first, and node A, which
-- booted the image's root, reads that scan's findings alone.

SELECT 'sbom_images';
SELECT image_id, image_version, image_root, sbom_format, sbom_sha256, state, toString(built_at, 'UTC'), db_version
FROM shirudo.sbom_images FINAL
ORDER BY image_id, image_version, image_root;

SELECT 'scanned again', groupArray(image_version)
FROM
(
    SELECT image_version FROM shirudo.sbom_images FINAL
    WHERE scanned_at = (SELECT max(scanned_at) FROM shirudo.sbom_images)
    ORDER BY image_version
);
SELECT 'scans', uniqExact(scanned_at) FROM shirudo.sbom_images;

SELECT 'sbom_vulns';
SELECT sbom_sha256, vuln_id, package, installed, fixed, severity,
       scanned_at = (SELECT scanned_at FROM shirudo.sbom_images FINAL WHERE image_version = '2026.11.1') AS newest
FROM shirudo.sbom_vulns
ORDER BY newest, vuln_id, package;

INSERT INTO shirudo.checked (host_name, body, ok, ak_name, ak_public, reset_count, clock) VALUES
('edge-01', '{"schema":"shirudo.keepalive/1","boot_id":"168d20a1-5011-4e1b-9924-d8b73c85aa4e","version_id":"d6d918ad22ff597579e6678bef75adca84d30f9661e0b7bbdbf534eebc138c1f","config_root":"1d8465c5b17838303fee92b3905420d294d2c22c576a0bdef0f69f190ed22807","kernel_release":"7.4.2","image_id":"fleet-os","image_version":"2026.11.1","image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c","verdict":"ok","cond":5461,"flags":0,"tamper":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"tree_id":"fleet-base","generation":3,"base_seq":0,"last_seq":3,"base_root":"0000000000000000000000000000000000000000000000000000000000000000","projection_root":"154522480ff8884daa95589e80f26f20248bbf9c192dfbb3cee04e03b4f136a1","mask":"VA==","set_sha256":"74e5bd2c665109f6d8f926af5476c266ad70ab07293ff13b1a13d0b89aa5c1bf","count":1,"not_ok":0}',
 1, '000b23602ab98bfb', 'QUtB', 7, 86523114);

SYSTEM REFRESH VIEW shirudo.node_status_mv;
SYSTEM WAIT VIEW shirudo.node_status_mv;
SYSTEM REFRESH VIEW shirudo.node_vulns_mv;
SYSTEM WAIT VIEW shirudo.node_vulns_mv;

SELECT 'node_vulns';
SELECT node_id, image_version, binding, sbom_stale, source, vuln_id, package, installed, fixed, severity, exposure
FROM shirudo.node_vulns
ORDER BY node_id, vuln_id, package;
