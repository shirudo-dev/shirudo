-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- The tables that keep the checks from reading shirudo.keepalive: the
-- newest record of every node and the first record of every boot, both
-- kept up to date as records arrive.

-- The record with the highest order_key of each node, which is its
-- newest by the TPM's own counters. A record that arrives late does not
-- replace a newer one. The newest record sent again does replace itself,
-- received included, which is why no check reads received here for the
-- age of a record: boot_first has when it came first.
CREATE TABLE IF NOT EXISTS shirudo.keepalive_latest
(
    ak_name String,
    order_key UInt64,
    received DateTime64(3),
    time DateTime64(9),
    host_name String,
    body String CODEC(ZSTD(1)),
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
ENGINE = ReplacingMergeTree(order_key)
ORDER BY ak_name;

CREATE MATERIALIZED VIEW IF NOT EXISTS shirudo.keepalive_latest_mv TO shirudo.keepalive_latest AS
SELECT * EXCEPT (ok, reason, ak_public, quote, reject)
FROM shirudo.checked
WHERE reject = '';

-- What check 3 compares a record with: the total of the tamper counters
-- in the boot's first record, by order_key, that could read them. They
-- start at zero with every boot and must not rise within one. A record
-- whose tamper is null has no total and does not set the baseline; it
-- reads as an empty array here.
--
-- newest_received is when the boot's newest record, by order_key, was
-- received first. Check 2 reads its age and not the age of the row in
-- keepalive_latest, which a record sent again replaces with the time of
-- the copy: whoever holds a node's last record could keep a node that
-- sends no more from turning stale.
--
-- last_used is when a record of the boot was last received, or when
-- boot_first_keep_mv last found the boot to be its node's current one,
-- and a row leaves that long after it as the TTL says. The TTL here is
-- the default of shirudo.settings; sql/apply-retention.sh sets the one
-- the settings name.
CREATE TABLE IF NOT EXISTS shirudo.boot_first
(
    ak_name String,
    boot_id String,
    first_order_key SimpleAggregateFunction(min, UInt64),
    tamper_first AggregateFunction(argMin, UInt64, UInt64),
    newest_received AggregateFunction(argMax, DateTime64(3), Tuple(UInt64, Int64)),
    last_used SimpleAggregateFunction(max, DateTime)
)
ENGINE = AggregatingMergeTree
ORDER BY (ak_name, boot_id)
TTL last_used + INTERVAL 2592000 SECOND;

CREATE MATERIALIZED VIEW IF NOT EXISTS shirudo.boot_first_mv TO shirudo.boot_first AS
SELECT
    ak_name,
    boot_id,
    min(order_key) AS first_order_key,
    argMinStateIf(arraySum(tamper), order_key, notEmpty(tamper)) AS tamper_first,
    argMaxState(received, (order_key, -toUnixTimestamp64Milli(received))) AS newest_received,
    max(toDateTime(received)) AS last_used
FROM shirudo.checked
WHERE reject = ''
GROUP BY ak_name, boot_id;

-- A TTL removes a row from the part it is in, whatever newer parts say
-- of the same boot, and the row that holds a boot's baseline is its
-- oldest: left alone, the baseline of a boot that runs longer than the
-- retention would move to a later record and hide a rise before it. So
-- once an hour the baseline of every node's current boot, the boot of
-- its newest record, is written again with the time of the refresh. That
-- boot's baseline never leaves, whether the node still sends or not; the
-- rows of the boots before it do.
CREATE MATERIALIZED VIEW IF NOT EXISTS shirudo.boot_first_keep_mv
REFRESH EVERY 1 HOUR APPEND TO shirudo.boot_first AS
SELECT
    b.ak_name AS ak_name,
    b.boot_id AS boot_id,
    min(b.first_order_key) AS first_order_key,
    argMinMergeState(b.tamper_first) AS tamper_first,
    argMaxMergeState(b.newest_received) AS newest_received,
    now() AS last_used
FROM shirudo.boot_first AS b
INNER JOIN shirudo.keepalive_latest AS k FINAL ON k.ak_name = b.ak_name AND k.boot_id = b.boot_id
GROUP BY b.ak_name, b.boot_id;
