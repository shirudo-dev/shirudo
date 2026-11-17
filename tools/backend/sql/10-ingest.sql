-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- Ingest: a keepalive enters at otel.otel_logs, is checked once by
-- tpm_quote_check on its way into shirudo.checked and from there lands
-- either in shirudo.keepalive or in shirudo.rejected. Neither otel_logs
-- nor checked stores a row; both only feed the views behind them.

-- The columns the collector's ClickHouse exporter inserts.
CREATE TABLE IF NOT EXISTS otel.otel_logs
(
    Timestamp DateTime64(9),
    TraceId String,
    SpanId String,
    TraceFlags UInt8,
    SeverityText LowCardinality(String),
    SeverityNumber UInt8,
    ServiceName LowCardinality(String),
    Body String,
    ResourceSchemaUrl LowCardinality(String),
    ResourceAttributes Map(LowCardinality(String), String),
    ScopeSchemaUrl LowCardinality(String),
    ScopeName String,
    ScopeVersion LowCardinality(String),
    ScopeAttributes Map(LowCardinality(String), String),
    LogAttributes Map(LowCardinality(String), String),
    EventName String
)
ENGINE = Null;

-- One row per keepalive, accepted or not. A writer gives the columns up
-- to clock; the others are read from the body, so that a test which
-- inserts here gets the same rows as a record that came through
-- checked_mv. reject is empty for an accepted record and otherwise the
-- reason it lands in shirudo.rejected under.
CREATE TABLE IF NOT EXISTS shirudo.checked
(
    received DateTime64(3) DEFAULT now64(3),
    time DateTime64(9),
    host_name String,
    quote String,
    body String,
    ok UInt8,
    reason LowCardinality(String),
    ak_name String,
    ak_public String,
    reset_count UInt64,
    clock UInt64,

    schema String DEFAULT JSONExtractString(body, 'schema'),
    boot_id String DEFAULT JSONExtractString(body, 'boot_id'),
    version_id String DEFAULT JSONExtractString(body, 'version_id'),
    config_root Nullable(String) DEFAULT JSONExtract(body, 'config_root', 'Nullable(String)'),
    kernel_release String DEFAULT JSONExtractString(body, 'kernel_release'),
    image_id Nullable(String) DEFAULT JSONExtract(body, 'image_id', 'Nullable(String)'),
    image_version Nullable(String) DEFAULT JSONExtract(body, 'image_version', 'Nullable(String)'),
    image_root Nullable(String) DEFAULT JSONExtract(body, 'image_root', 'Nullable(String)'),
    verdict LowCardinality(String) DEFAULT JSONExtractString(body, 'verdict'),
    cond UInt64 DEFAULT JSONExtractUInt(body, 'cond'),
    flags UInt64 DEFAULT JSONExtractUInt(body, 'flags'),
    tamper Array(UInt64) DEFAULT JSONExtract(body, 'tamper', 'Array(UInt64)'),
    tree_id Nullable(String) DEFAULT JSONExtract(body, 'tree_id', 'Nullable(String)'),
    generation Nullable(UInt64) DEFAULT JSONExtract(body, 'generation', 'Nullable(UInt64)'),
    base_seq Nullable(UInt64) DEFAULT JSONExtract(body, 'base_seq', 'Nullable(UInt64)'),
    last_seq Nullable(UInt64) DEFAULT JSONExtract(body, 'last_seq', 'Nullable(UInt64)'),
    base_root Nullable(String) DEFAULT JSONExtract(body, 'base_root', 'Nullable(String)'),
    projection_root Nullable(String) DEFAULT JSONExtract(body, 'projection_root', 'Nullable(String)'),
    mask Nullable(String) DEFAULT JSONExtract(body, 'mask', 'Nullable(String)'),
    set_sha256 String DEFAULT JSONExtractString(body, 'set_sha256'),
    count UInt64 DEFAULT JSONExtractUInt(body, 'count'),
    not_ok UInt64 DEFAULT JSONExtractUInt(body, 'not_ok'),

    -- keepalive_latest orders by this, which leaves 24 bits for
    -- reset_count and 40 for clock: a record beyond either is refused.
    order_key UInt64 DEFAULT bitOr(bitShiftLeft(reset_count, 40), clock),
    reject LowCardinality(String) DEFAULT multiIf(
        ok != 1, if(reason = '', 'malformed', reason),
        schema != 'shirudo.keepalive/1' AND NOT startsWith(schema, 'shirudo.keepalive/1.'), 'schema',
        reset_count >= 16777216 OR clock >= 1099511627776, 'clock_range',
        '')
)
ENGINE = Null;

-- tpm_quote_check answers with one JSON line per record, which the
-- outer query takes apart. The subquery keeps it at one call per record.
CREATE MATERIALIZED VIEW IF NOT EXISTS shirudo.checked_mv TO shirudo.checked AS
SELECT
    time,
    host_name,
    quote,
    body,
    JSONExtractUInt(answer, 'ok') = 1 AS ok,
    JSONExtractString(answer, 'reason') AS reason,
    JSONExtractString(answer, 'ak_name') AS ak_name,
    JSONExtractString(answer, 'ak_public') AS ak_public,
    JSONExtractUInt(answer, 'reset_count') AS reset_count,
    JSONExtractUInt(answer, 'clock') AS clock
FROM
(
    SELECT
        Timestamp AS time,
        ResourceAttributes['host.name'] AS host_name,
        LogAttributes['shirudo.quote'] AS quote,
        Body AS body,
        extractGroups(quote, '^attest=([A-Za-z0-9+/=]+);sig=([A-Za-z0-9+/=]+);ak=([A-Za-z0-9+/=]+)$') AS field,
        tpm_quote_check(field[1], field[2], field[3], lower(hex(SHA256(body)))) AS answer
    FROM otel.otel_logs
    WHERE EventName = 'shirudo.keepalive'
);

-- Every accepted record, kept for audit: no check reads this table. A
-- record sent twice has the same key and collapses into one row. The TTL
-- here is the default of shirudo.settings; sql/apply-retention.sh sets
-- the one the settings name, since a TTL cannot read a table.
CREATE TABLE IF NOT EXISTS shirudo.keepalive
(
    received DateTime64(3),
    time DateTime64(9),
    host_name String,
    quote String CODEC(ZSTD(1)),
    body String CODEC(ZSTD(1)),
    ak_name String,
    reset_count UInt32,
    clock UInt64,
    schema LowCardinality(String),
    boot_id String,
    version_id String,
    config_root Nullable(String),
    kernel_release LowCardinality(String),
    image_id Nullable(String),
    image_version Nullable(String),
    image_root Nullable(String),
    verdict LowCardinality(String),
    cond UInt64,
    flags UInt64,
    tamper Array(UInt64),
    tree_id Nullable(String),
    generation Nullable(UInt64),
    base_seq Nullable(UInt64),
    last_seq Nullable(UInt64),
    base_root Nullable(String),
    projection_root Nullable(String),
    mask Nullable(String),
    set_sha256 String,
    count UInt64,
    not_ok UInt64
)
ENGINE = ReplacingMergeTree
ORDER BY (ak_name, reset_count, clock)
TTL toDateTime(received) + INTERVAL 3600 SECOND;

CREATE MATERIALIZED VIEW IF NOT EXISTS shirudo.keepalive_mv TO shirudo.keepalive AS
SELECT * EXCEPT (ok, reason, ak_public, order_key, reject)
FROM shirudo.checked
WHERE reject = '';

-- What was refused and why: bad_signature, body_mismatch and malformed
-- from the checker, schema for a body of an unknown major version and
-- clock_range for counters order_key cannot hold.
CREATE TABLE IF NOT EXISTS shirudo.rejected
(
    received DateTime64(3),
    reason LowCardinality(String),
    host_name String,
    ak_name String,
    reset_count UInt64,
    clock UInt64,
    quote String CODEC(ZSTD(1)),
    body String CODEC(ZSTD(1))
)
ENGINE = MergeTree
ORDER BY received
TTL toDateTime(received) + INTERVAL 7 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS shirudo.rejected_mv TO shirudo.rejected AS
SELECT
    received,
    reject AS reason,
    host_name,
    ak_name,
    reset_count,
    clock,
    quote,
    body
FROM shirudo.checked
WHERE reject != '';
