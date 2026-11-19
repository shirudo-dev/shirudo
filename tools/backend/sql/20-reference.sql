-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- Reference: what the checks compare a keepalive with. nodes fills
-- itself from the accepted records; the operator and the ingest job
-- write the others.

-- One row per attestation key. node_id is the host name the key first
-- claimed; to relabel a node, insert argMinState('<name>',
-- toDateTime64(0, 3)) for its ak_name, which is why a row that leaves
-- ak_public and first_seen out must not change them. trust only ever
-- rises: a keepalive never sets it, so a node stays untrusted until the
-- operator inserts enrolled for its ak_name, once credential activation
-- or a builder's records have shown that the key lives in a TPM. The
-- row may come before the node's first record.
CREATE TABLE IF NOT EXISTS shirudo.nodes
(
    ak_name String,
    ak_public SimpleAggregateFunction(max, String),
    node_id AggregateFunction(argMin, String, DateTime64(3)),
    first_seen SimpleAggregateFunction(min, Nullable(DateTime64(3))),
    trust SimpleAggregateFunction(max, Enum8('untrusted' = 0, 'enrolled' = 1)) DEFAULT 'untrusted'
)
ENGINE = AggregatingMergeTree
ORDER BY ak_name;

CREATE MATERIALIZED VIEW IF NOT EXISTS shirudo.nodes_mv TO shirudo.nodes AS
SELECT
    ak_name,
    max(ak_public) AS ak_public,
    argMinState(host_name, received) AS node_id,
    min(received) AS first_seen
FROM shirudo.checked
WHERE reject = ''
GROUP BY ak_name;

-- The builds a node may run, by the version_id of its keepalive.
CREATE TABLE IF NOT EXISTS shirudo.expected_builds
(
    version_id String,
    note String,
    added DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree
ORDER BY version_id;

-- One row per publication of a tree. Digests are 64 lowercase hex digits
-- without "sha256:", as in the keepalive body. published_at is when the
-- ingest job first loaded the publication, which is all the backend
-- knows: the publication document carries no time. A publication is a
-- segment of its tree, holding the operations past segment_base_seq;
-- segment_manifest_digest names the sealed segment before it, empty for
-- the first, and history_root is the tree's history root at
-- segment_base_seq, 64 zeros for the first.
CREATE TABLE IF NOT EXISTS shirudo.tree_pubs
(
    tree_id String,
    generation UInt64,
    manifest_digest String,
    parent_manifest_digest String,
    head_seq UInt64,
    segment_base_seq UInt64 DEFAULT 0,
    segment_manifest_digest String DEFAULT '',
    history_root String DEFAULT repeat('0', 64),
    published_at DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree
ORDER BY (tree_id, generation);

-- One row per operation of a tree. An operation never changes once
-- published, so loading a publication again replaces rows with equal ones.
-- selector is the operation's selector as JSON text, copied and never
-- evaluated: what an operation did on a node is read from the node's mask.
CREATE TABLE IF NOT EXISTS shirudo.tree_ops
(
    tree_id String,
    seq UInt64,
    op Enum8('add' = 1, 'delete' = 2),
    id String,
    selector String,
    repository String,
    manifest_digest String,
    layer_digest String,
    payload_sha256 String,
    operation_digest String
)
ENGINE = ReplacingMergeTree
ORDER BY (tree_id, seq);

-- Which advisory an operation's upatch shields against. source is fixes
-- for a row the ingest job took from the operation's fixes key and
-- manual for one an operator added.
CREATE TABLE IF NOT EXISTS shirudo.upatch_fixes
(
    tree_id String,
    seq UInt64,
    id String,
    advisory String,
    source Enum8('fixes' = 1, 'manual' = 2)
)
ENGINE = ReplacingMergeTree
ORDER BY (tree_id, seq, advisory, source);

-- The labels the operator gives a node, out of band: what jobs/labels-put
-- loads, not what the node's own node.labels holds, which only its tree
-- sync reads. One row per set, by node_id or by ak_name; a newer put of
-- the same name replaces it, and an empty map clears it. Read it with
-- FINAL, or through shirudo.node_labels.
CREATE TABLE IF NOT EXISTS shirudo.label_sets
(
    by Enum8('node_id' = 1, 'ak_name' = 2),
    node String,
    labels Map(String, String),
    put_at DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(put_at)
ORDER BY (by, node);

-- The thresholds of the checks, the retention of shirudo.keepalive and
-- shirudo.boot_first and the age at which an SBOM's scan is stale, in one
-- row. Read it with FINAL; to change a value, insert the whole row again
-- with id 1. The two retention values take effect when
-- sql/apply-retention.sh runs, the others at the next refresh. A scan
-- older than sbom_stale_seconds marks the rows of its image's nodes in
-- node_vulns; keep it below the 7 days after which shirudo.sbom_vulns
-- drops the findings, so that an image reads stale before it reads clean.
-- stale_seconds is 10 minutes: a keepalive cannot run while a tree sync
-- holds the target's config operation lock, so a node that syncs sends
-- nothing for as long as the sync runs. The node status page of the
-- backend documentation says why.
CREATE TABLE IF NOT EXISTS shirudo.settings
(
    id UInt8 DEFAULT 1,
    stale_seconds UInt32,
    stuck_seconds UInt32,
    window UInt32,
    keepalive_retention_seconds UInt32 DEFAULT 3600,
    boot_first_retention_seconds UInt32 DEFAULT 2592000,
    sbom_stale_seconds UInt32 DEFAULT 172800,
    updated DateTime64(3) DEFAULT now64(3),
    CONSTRAINT one_row CHECK id = 1
)
ENGINE = ReplacingMergeTree(updated)
ORDER BY id;

INSERT INTO shirudo.settings (stale_seconds, stuck_seconds, window, keepalive_retention_seconds,
                              boot_first_retention_seconds, sbom_stale_seconds)
SELECT 600, 3600, 512, 3600, 2592000, 172800
WHERE (SELECT count() FROM shirudo.settings) = 0;
