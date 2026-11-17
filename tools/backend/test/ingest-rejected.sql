-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- A record the checker refused, one of an unknown schema and one whose
-- counters order_key cannot hold land in shirudo.rejected with their
-- reason, and nowhere else. The largest counters that fit are accepted.

-- The records below carry fixed times, long past the retention of
-- shirudo.keepalive.
SYSTEM STOP TTL MERGES shirudo.keepalive;

INSERT INTO shirudo.checked (received, host_name, quote, body, ok, reason, ak_name, ak_public, reset_count, clock) VALUES
('2026-11-11 10:00:00', 'n1', 'q1', '{"schema":"shirudo.keepalive/1"}', 0, 'bad_signature', '', '', 0, 0),
('2026-11-11 10:00:01', 'n2', 'q2', '{"schema":"shirudo.keepalive/1"}', 0, 'body_mismatch', '', '', 0, 0),
('2026-11-11 10:00:02', 'n3', 'q3', '{"schema":"shirudo.keepalive/1"}', 0, 'malformed', '', '', 0, 0),
('2026-11-11 10:00:03', 'n4', 'q4', '{"schema":"shirudo.keepalive/1"}', 0, '', '', '', 0, 0),
('2026-11-11 10:00:04', 'n5', 'q5', '{"schema":"shirudo.keepalive/2"}', 1, '', '000b05', 'QQ==', 1, 1),
('2026-11-11 10:00:05', 'n6', 'q6', 'not json', 1, '', '000b06', 'QQ==', 1, 1),
('2026-11-11 10:00:06', 'n7', 'q7', '{"schema":"shirudo.keepalive/1"}', 1, '', '000b07', 'QQ==', 16777216, 1),
('2026-11-11 10:00:07', 'n8', 'q8', '{"schema":"shirudo.keepalive/1"}', 1, '', '000b08', 'QQ==', 1, 1099511627776),
('2026-11-11 10:00:08', 'n9', 'q9', '{"schema":"shirudo.keepalive/1"}', 1, '', '000b09', 'QQ==', 16777215, 1099511627775);

SELECT 'rejected';
SELECT received, reason, host_name, ak_name, reset_count, clock, quote, body
FROM shirudo.rejected ORDER BY received;

SELECT 'accepted';
SELECT ak_name, reset_count, clock FROM shirudo.keepalive FINAL;
SELECT ak_name, order_key FROM shirudo.keepalive_latest FINAL;
SELECT ak_name FROM shirudo.nodes FINAL;
SELECT ak_name, first_order_key FROM shirudo.boot_first FINAL;
