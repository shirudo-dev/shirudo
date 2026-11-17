-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- A keepalive written to otel.otel_logs as the collector writes it goes
-- through tpm_quote_check once and on to keepalive or rejected. The
-- quotes are in the form test/stub-quote-check.sh reads, hence the name:
-- test/run.sh skips a test named *-stub when it installs a real checker.

INSERT INTO otel.otel_logs (Timestamp, SeverityText, SeverityNumber, ServiceName, Body, ResourceAttributes, ScopeName, LogAttributes, EventName)
WITH
    '{"schema":"shirudo.keepalive/1","boot_id":"168d20a1-5011-4e1b-9924-d8b73c85aa4e","verdict":"ok","count":1}' AS body,
    lower(hex(SHA256(body))) AS digest
SELECT '2026-11-11 10:00:00', 'INFO', 9, 'shirudo', record.3,
       map('service.name', 'shirudo', 'host.name', record.1), 'shirudo.keepalive',
       if(record.4 = '', map(), map('shirudo.quote', record.4)), record.2
FROM
(
    SELECT arrayJoin([
        ('good', 'shirudo.keepalive', body, concat('attest=7/60000/', digest, ';sig=good;ak=QUtB')),
        ('altered', 'shirudo.keepalive', replaceOne(body, '"count":1', '"count":2'), concat('attest=7/60001/', digest, ';sig=good;ak=QUtB')),
        ('forged', 'shirudo.keepalive', body, concat('attest=7/60002/', digest, ';sig=AAAA;ak=QUtB')),
        ('reordered', 'shirudo.keepalive', body, concat('sig=good;attest=7/60003/', digest, ';ak=QUtB')),
        ('spaced', 'shirudo.keepalive', body, concat('attest=7/60004/', digest, '; sig=good;ak=QUtB')),
        ('unquoted', 'shirudo.keepalive', body, ''),
        ('wrapped', 'shirudo.keepalive', body, concat('attest=16777216/5/', digest, ';sig=good;ak=QUtB')),
        ('snapshot', 'shirudo.bpf.map.snapshot', body, concat('attest=7/60005/', digest, ';sig=good;ak=QUtB'))
    ]) AS record
);

SELECT 'keepalive';
SELECT host_name, time, ak_name, reset_count, clock, boot_id, verdict, count,
       quote LIKE concat('attest=7/60000/', lower(hex(SHA256(body))), ';%')
FROM shirudo.keepalive FINAL;

SELECT 'nodes';
SELECT ak_name, max(ak_public), argMinMerge(node_id), max(trust)
FROM shirudo.nodes GROUP BY ak_name;

SELECT 'rejected';
SELECT host_name, reason, ak_name, reset_count, clock FROM shirudo.rejected ORDER BY host_name;
