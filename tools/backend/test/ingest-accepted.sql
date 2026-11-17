-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- A record inserted into shirudo.checked as the checker passed it lands
-- in keepalive, nodes, keepalive_latest and boot_first, with every field
-- of the body in a column, and boot_first keeps the tamper total of each
-- boot's first record. The first body is that of a node on a tree,
-- the second that of a node that follows none.

-- The records below carry fixed times, long past the retention of
-- shirudo.keepalive.
SYSTEM STOP TTL MERGES shirudo.keepalive;

INSERT INTO shirudo.checked (received, time, host_name, quote, body, ok, ak_name, ak_public, reset_count, clock) VALUES
('2026-11-11 10:00:00', '2026-11-11 09:59:59', 'edge-01', 'q1', '{"schema":"shirudo.keepalive/1","boot_id":"168d20a1-5011-4e1b-9924-d8b73c85aa4e","version_id":"d6d918ad22ff597579e6678bef75adca84d30f9661e0b7bbdbf534eebc138c1f","config_root":"1d8465c5b17838303fee92b3905420d294d2c22c576a0bdef0f69f190ed22807","kernel_release":"7.4.2","image_id":"fleet-os","image_version":"2026.11.1","image_root":"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c","verdict":"ok","cond":5461,"flags":0,"tamper":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7],"tree_id":"fleet-base","generation":3,"base_seq":0,"last_seq":3,"base_root":"0000000000000000000000000000000000000000000000000000000000000000","projection_root":"154522480ff8884daa95589e80f26f20248bbf9c192dfbb3cee04e03b4f136a1","mask":"VA==","set_sha256":"74e5bd2c665109f6d8f926af5476c266ad70ab07293ff13b1a13d0b89aa5c1bf","count":1,"not_ok":0}', 1, '000baa', 'QUtB', 7, 60000),
('2026-11-11 10:00:01', '2026-11-11 10:00:00', 'core-01', 'q2', '{"schema":"shirudo.keepalive/1","boot_id":"9a6f14ea-0cc2-45e1-8e23-7b887120cf54","version_id":"d6d918ad22ff597579e6678bef75adca84d30f9661e0b7bbdbf534eebc138c1f","config_root":null,"kernel_release":"7.4.2","image_id":null,"image_version":null,"image_root":null,"verdict":"init-pending","cond":5465,"flags":8,"tamper":null,"tree_id":null,"generation":null,"base_seq":null,"last_seq":null,"base_root":null,"projection_root":null,"mask":null,"set_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","count":0,"not_ok":0,"later_key":1}', 1, '000bbb', 'QUtC', 2, 500);

SELECT 'keepalive';
SELECT * EXCEPT (body) FROM shirudo.keepalive FINAL ORDER BY ak_name FORMAT Vertical;
SELECT ak_name, lower(hex(SHA256(body))) FROM shirudo.keepalive FINAL ORDER BY ak_name;

SELECT 'nodes';
SELECT ak_name, max(ak_public), argMinMerge(node_id), min(first_seen), max(trust)
FROM shirudo.nodes GROUP BY ak_name ORDER BY ak_name;

SELECT 'keepalive_latest';
SELECT ak_name, order_key, reset_count, clock, host_name, verdict, last_seq, mask, count
FROM shirudo.keepalive_latest FINAL ORDER BY ak_name;

SELECT 'boot_first';
SELECT ak_name, boot_id, min(first_order_key), argMinMerge(tamper_first)
FROM shirudo.boot_first GROUP BY ak_name, boot_id ORDER BY ak_name, boot_id;

-- The same node again: a newer record under another host name, the
-- newer record a second time, then an older record of the same boot and
-- one of an earlier boot, both arriving late.
INSERT INTO shirudo.checked (received, host_name, body, ok, ak_name, ak_public, reset_count, clock) VALUES
('2026-11-11 10:01:00', 'renamed', '{"schema":"shirudo.keepalive/1","boot_id":"168d20a1-5011-4e1b-9924-d8b73c85aa4e","verdict":"degraded","last_seq":3,"count":1}', 1, '000baa', 'QUtB', 7, 120000);
INSERT INTO shirudo.checked (received, host_name, body, ok, ak_name, ak_public, reset_count, clock) VALUES
('2026-11-11 10:01:05', 'renamed', '{"schema":"shirudo.keepalive/1","boot_id":"168d20a1-5011-4e1b-9924-d8b73c85aa4e","verdict":"degraded","last_seq":3,"count":1}', 1, '000baa', 'QUtB', 7, 120000);
INSERT INTO shirudo.checked (received, host_name, body, ok, ak_name, ak_public, reset_count, clock) VALUES
('2026-11-11 10:02:00', 'edge-01', '{"schema":"shirudo.keepalive/1","boot_id":"168d20a1-5011-4e1b-9924-d8b73c85aa4e","verdict":"reboot-pending","tamper":[1,0,2],"last_seq":2,"count":1}', 1, '000baa', 'QUtB', 7, 30000);
INSERT INTO shirudo.checked (received, host_name, body, ok, ak_name, ak_public, reset_count, clock) VALUES
('2026-11-11 10:03:00', 'edge-01', '{"schema":"shirudo.keepalive/1","boot_id":"00000000-0000-4000-8000-000000000006","verdict":"ok","last_seq":1,"count":1}', 1, '000baa', 'QUtB', 6, 900000);

SELECT 'a record sent twice is one row';
SELECT reset_count, clock, verdict FROM shirudo.keepalive FINAL WHERE ak_name = '000baa' ORDER BY reset_count, clock;

SELECT 'the newest record by the quote stays latest';
SELECT ak_name, order_key, reset_count, clock, host_name, verdict, last_seq
FROM shirudo.keepalive_latest FINAL ORDER BY ak_name;

SELECT 'a node keeps its first name and its trust';
SELECT ak_name, argMinMerge(node_id), min(first_seen), max(trust)
FROM shirudo.nodes GROUP BY ak_name ORDER BY ak_name;

SELECT 'each boot keeps its first record';
SELECT ak_name, boot_id, min(first_order_key), argMinMerge(tamper_first)
FROM shirudo.boot_first GROUP BY ak_name, boot_id ORDER BY ak_name, min(first_order_key);

SELECT 'nothing was rejected';
SELECT count() FROM shirudo.rejected;

SELECT 'a relabelled node keeps everything but its name';
INSERT INTO shirudo.nodes (ak_name, node_id)
SELECT '000bbb', argMinState('rack-7', toDateTime64(0, 3));
SELECT ak_name, max(ak_public), argMinMerge(node_id), min(first_seen), max(trust)
FROM shirudo.nodes GROUP BY ak_name ORDER BY ak_name;
