-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- sql/apply-retention.sh gives shirudo.keepalive and shirudo.boot_first
-- the retention of shirudo.settings, which test/retention.setup.sql set
-- to two minutes and to sixty days before the runner applied it. A
-- record older than two minutes leaves keepalive and stays where the
-- checks read: keepalive_latest and boot_first.

SELECT keepalive_retention_seconds, boot_first_retention_seconds FROM shirudo.settings FINAL;
SELECT name, extract(engine_full, 'TTL .*\\)') FROM system.tables
WHERE database = 'shirudo' AND name IN ('boot_first', 'keepalive')
ORDER BY name;

INSERT INTO shirudo.checked (received, host_name, body, ok, ak_name, ak_public, reset_count, clock)
SELECT now64(3) - record.1, 'edge-01',
       concat('{"schema":"shirudo.keepalive/1","boot_id":"', record.2, '","tamper":[', toString(record.4), ']}'),
       1, '000baa', 'QUtB', record.3, 1000
FROM
(
    SELECT arrayJoin([
        (600, '00000000-0000-4000-8000-000000000001', 1, 5),
        (10, '00000000-0000-4000-8000-000000000002', 2, 0)
    ]) AS record
);
OPTIMIZE TABLE shirudo.keepalive FINAL;

SELECT 'keepalive';
SELECT reset_count, boot_id FROM shirudo.keepalive FINAL ORDER BY reset_count;
SELECT 'keepalive_latest';
SELECT reset_count, boot_id FROM shirudo.keepalive_latest FINAL ORDER BY reset_count;
SELECT 'boot_first';
SELECT boot_id, argMinMerge(tamper_first) FROM shirudo.boot_first GROUP BY ak_name, boot_id ORDER BY boot_id;
