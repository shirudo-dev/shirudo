-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- Status: the checks over the newest record of every node, run once a
-- minute for all nodes and kept in shirudo.node_status, which is what a
-- UI reads, with the history of every node that the checks read below
-- the window a record covers. Nothing here reads shirudo.keepalive.

-- The outcome pair of the i-th operation of a mask's window, i from 0:
-- 1 applied, 2 selector did not match, 3 attach module not loaded and
-- 0 not reached. A function has no database, so the name is global. A
-- mask that is not base64, or too short for i, reads as 0: a record is
-- signed by a key anyone can make, and one bad mask must not stop the
-- refresh for every node.
CREATE OR REPLACE FUNCTION mask_code AS (mask, i) ->
    bitAnd(bitShiftRight(reinterpretAsUInt8(substring(tryBase64Decode(mask), intDiv(i, 4) + 1, 1)),
                         6 - 2 * (i % 4)), 3);

-- The newest record of every node with the node's label and trust.
CREATE VIEW IF NOT EXISTS shirudo.latest AS
SELECT n.node_id AS node_id, n.trust AS trust, k.*
FROM shirudo.keepalive_latest AS k FINAL
INNER JOIN
(
    SELECT ak_name, argMinMerge(node_id) AS node_id, max(trust) AS trust
    FROM shirudo.nodes
    GROUP BY ak_name
) AS n ON n.ak_name = k.ak_name;

-- Every label of every node, one row per set it comes from: the set put
-- under the node's ak_name, the one under its node_id, and the one under
-- the config_root of its newest record. rank orders them by how specific
-- the name is, the ak_name highest.
CREATE VIEW IF NOT EXISTS shirudo.node_label_items AS
WITH
sets AS
(
    SELECT toString(by) AS by, node, CAST(labels, 'Array(Tuple(String, String))') AS items
    FROM shirudo.label_sets FINAL
),
named AS
(
    SELECT n.ak_name AS ak_name, n.node_id AS node_id, ifNull(r.config_root, '') AS config_root
    FROM
    (
        SELECT ak_name, argMinMerge(node_id) AS node_id
        FROM shirudo.nodes
        GROUP BY ak_name
    ) AS n
    LEFT JOIN
    (
        SELECT k.ak_name AS ak_name, k.config_root AS config_root
        FROM shirudo.keepalive_latest AS k FINAL
    ) AS r ON r.ak_name = n.ak_name
),
found AS
(
    SELECT n.ak_name AS ak_name, n.node_id AS node_id, s.by AS by, s.items AS items
    FROM named AS n
    INNER JOIN (SELECT * FROM sets WHERE by = 'ak_name') AS s ON s.node = n.ak_name
    UNION ALL
    SELECT n.ak_name, n.node_id, s.by, s.items
    FROM named AS n
    INNER JOIN (SELECT * FROM sets WHERE by = 'node_id') AS s ON s.node = n.node_id
    UNION ALL
    SELECT n.ak_name, n.node_id, s.by, s.items
    FROM named AS n
    INNER JOIN (SELECT * FROM sets WHERE by = 'config_root') AS s ON s.node = n.config_root
    WHERE n.config_root != ''
)
SELECT
    f.ak_name AS ak_name,
    f.node_id AS node_id,
    f.by AS by,
    multiIf(f.by = 'ak_name', 3, f.by = 'node_id', 2, 1) AS rank,
    item.1 AS key,
    item.2 AS value
FROM found AS f
ARRAY JOIN f.items AS item;

-- The labels of every node: the union of its sets, where a key two sets
-- give takes the value of the more specific name. sources says, per key,
-- which name its value came from, and conflicts how many keys the sets
-- gave different values; label_conflicts has them.
CREATE VIEW IF NOT EXISTS shirudo.node_labels AS
WITH
won AS
(
    SELECT
        i.ak_name AS ak_name,
        i.key AS key,
        argMax(i.value, i.rank) AS value,
        argMax(i.by, i.rank) AS by,
        uniqExact(i.value) > 1 AS conflict
    FROM shirudo.node_label_items AS i
    GROUP BY i.ak_name, i.key
),
sorted AS
(
    SELECT
        w.ak_name AS ak_name,
        arraySort(groupArray(tuple(w.key, w.value, w.by))) AS items,
        countIf(w.conflict) AS conflicts
    FROM won AS w
    GROUP BY w.ak_name
),
merged AS
(
    SELECT
        ak_name,
        mapFromArrays(arrayMap(x -> x.1, items), arrayMap(x -> x.2, items)) AS labels,
        mapFromArrays(arrayMap(x -> x.1, items), arrayMap(x -> x.3, items)) AS sources,
        conflicts
    FROM sorted
)
SELECT
    n.ak_name AS ak_name,
    n.node_id AS node_id,
    m.labels AS labels,
    m.sources AS sources,
    m.conflicts AS conflicts
FROM
(
    SELECT ak_name, argMinMerge(node_id) AS node_id
    FROM shirudo.nodes
    GROUP BY ak_name
) AS n
LEFT JOIN merged AS m ON m.ak_name = n.ak_name;

-- The keys whose sets give a node different values: the value that won,
-- the name it came from, and every value with the name that gave it.
CREATE VIEW IF NOT EXISTS shirudo.label_conflicts AS
SELECT
    i.ak_name AS ak_name,
    any(i.node_id) AS node_id,
    i.key AS key,
    argMax(i.value, i.rank) AS value,
    argMax(i.by, i.rank) AS by,
    arraySort(x -> -x.1, groupArray(tuple(i.rank, i.by, i.value))) AS given
FROM shirudo.node_label_items AS i
GROUP BY i.ak_name, i.key
HAVING uniqExact(i.value) > 1;

-- History: what each node did at every operation of its tree that the
-- backend has seen it reach, so that checks 4 and 6 and node_vulns can
-- look below the window of the last 512 operations a keepalive covers.
-- One row per node, tree and seq: code is the outcome pair of the mask,
-- 1 to 3, and root the node's projection_root after that seq. A row of
-- code 0 is a gap: it stands at the base_seq of a record whose window
-- starts past the history stored for the node, holds the base_root that
-- record gave, and nothing below it is known. Rows are never removed;
-- the node status page of the backend documentation says why and what
-- that costs.
--
-- The projection keeps, per node and tree, how far the history reaches,
-- the root there and the seq of its first gap, so that a refresh reads
-- one row per node and not the node's whole history. A ReplacingMergeTree
-- keeps a projection only when told to rebuild it after a merge.
CREATE TABLE IF NOT EXISTS shirudo.node_ops
(
    ak_name String,
    tree_id String,
    seq UInt64,
    code UInt8,
    root FixedString(32),
    PROJECTION reach
    (
        SELECT ak_name, tree_id, max(seq), argMax(root, seq), minIf(seq, code = 0)
        GROUP BY ak_name, tree_id
    )
)
ENGINE = ReplacingMergeTree
ORDER BY (ak_name, tree_id, seq)
SETTINGS deduplicate_merge_projection_mode = 'rebuild';

-- The newest operation of every upatch that each node applied, from the
-- rows of node_ops with code 1: what the node's history leaves loaded.
CREATE TABLE IF NOT EXISTS shirudo.node_sets
(
    ak_name String,
    tree_id String,
    id String,
    last_seq UInt64,
    last_op Enum8('add' = 1, 'delete' = 2),
    last_payload String
)
ENGINE = ReplacingMergeTree(last_seq)
ORDER BY (ak_name, tree_id, id);

CREATE MATERIALIZED VIEW IF NOT EXISTS shirudo.node_sets_mv TO shirudo.node_sets AS
SELECT h.ak_name AS ak_name, h.tree_id AS tree_id, o.id AS id, h.seq AS last_seq,
       o.op AS last_op, o.payload_sha256 AS last_payload
FROM shirudo.node_ops AS h
INNER JOIN shirudo.tree_ops AS o FINAL ON o.tree_id = h.tree_id AND o.seq = h.seq
WHERE h.code = 1;

-- The marks of nodes whose record contradicted their history, one row
-- per node and tree, set by node_ops_mv when it finds the contradiction:
-- the seq it found first and whether that was the base or an operation
-- of the window. A mark fails check 4 for the node, whatever tree and
-- boot its newest record has, and stops its history from growing, until
-- an operator deletes it; the node status page of the backend
-- documentation says how and why.
CREATE TABLE IF NOT EXISTS shirudo.history_contradictions
(
    ak_name String,
    tree_id String,
    seq UInt64,
    reason Enum8('base' = 1, 'window' = 2),
    marked_at DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY (ak_name, tree_id);

-- Where the newest record of a node contradicts the history stored for
-- it: one row per node whose base_root differs from the root stored at
-- base_seq (reason base), or whose code or folded root differs from the
-- stored row at an operation of its window that the history reaches
-- (reason window), with the first such seq. A gap row holds a root but
-- no code, so only its root is compared. The roots are folded from
-- base_root once per distinct path, as far as tree_ops has every
-- operation, and only the rows of node_ops the windows overlap are read.
CREATE VIEW IF NOT EXISTS shirudo.history_conflicts AS
WITH
    reach AS
    (
        SELECT ak_name, tree_id, max(seq) AS stored_max
        FROM shirudo.node_ops
        GROUP BY ak_name, tree_id
    ),
    node AS
    (
        SELECT k.ak_name AS ak_name,
               ifNull(k.tree_id, '') AS p_tree,
               ifNull(k.base_seq, 0) AS p_base,
               ifNull(k.mask, '') AS p_mask,
               ifNull(k.base_root, '') AS p_root,
               least(ifNull(k.last_seq, 0), r.stored_max) AS p_upto
        FROM shirudo.keepalive_latest AS k FINAL
        INNER JOIN reach AS r ON r.ak_name = k.ak_name AND r.tree_id = ifNull(k.tree_id, '')
        WHERE k.tree_id IS NOT NULL AND k.mask IS NOT NULL AND k.base_seq IS NOT NULL
              AND k.last_seq IS NOT NULL AND k.last_seq >= k.base_seq
              AND match(p_root, '^[0-9a-f]{64}$') AND r.stored_max >= p_base
    ),
    stored AS
    (
        SELECT ak_name, tree_id, seq, any(code) AS code, any(root) AS root
        FROM shirudo.node_ops
        WHERE (ak_name, tree_id, seq) IN (SELECT ak_name, p_tree, arrayJoin(range(p_base, p_upto + 1)) FROM node)
        GROUP BY ak_name, tree_id, seq
    ),
    folded AS
    (
        SELECT p.p_tree AS p_tree, p.p_base AS p_base, p.p_upto AS p_upto,
               p.p_root AS p_root, p.p_mask AS p_mask,
               arraySort(groupArray((o.seq, mask_code(p.p_mask, o.seq - p.p_base - 1),
                                     unhex(o.operation_digest)))) AS steps,
               arrayFold((acc, x) -> arrayPushBack(acc, if(has([1, 3], x.2),
                                                           SHA256(concat(acc[-1], x.3)), acc[-1])),
                         steps, [toFixedString(unhex(any(p.p_root)), 32)]) AS roots
        FROM (SELECT DISTINCT p_tree, p_base, p_upto, p_root, p_mask FROM node) AS p
        INNER JOIN shirudo.tree_ops AS o FINAL ON o.tree_id = p.p_tree
        WHERE o.seq > p.p_base AND o.seq <= p.p_upto
        GROUP BY p.p_tree, p.p_base, p.p_upto, p.p_root, p.p_mask
    ),
    -- What each record says: its base_root at base_seq, and the code and
    -- root after every operation of its window up to the first one
    -- missing from tree_ops.
    claims AS
    (
        SELECT ak_name, p_tree AS tree_id, p_base AS seq, 'base' AS kind, toUInt8(0) AS code,
               toFixedString(unhex(p_root), 32) AS root
        FROM node
        WHERE p_base > 0
        UNION ALL
        SELECT n.ak_name, n.p_tree, step.1, 'window', step.2, step.3
        FROM node AS n
        INNER JOIN folded AS f ON f.p_tree = n.p_tree AND f.p_base = n.p_base AND f.p_upto = n.p_upto
                                  AND f.p_root = n.p_root AND f.p_mask = n.p_mask
        ARRAY JOIN arrayFilter((x, i) -> x.1 = f.p_base + i,
                               arrayMap((x, r) -> (x.1, x.2, r), f.steps, arrayPopFront(f.roots)),
                               arrayEnumerate(f.steps)) AS step
    )
SELECT c.ak_name AS ak_name, c.tree_id AS tree_id,
       min((c.kind, c.seq)).1 AS reason, min((c.kind, c.seq)).2 AS seq
FROM claims AS c
INNER JOIN stored AS s ON s.ak_name = c.ak_name AND s.tree_id = c.tree_id AND s.seq = c.seq
WHERE s.root != c.root OR (c.kind = 'window' AND s.code != 0 AND s.code != c.code)
GROUP BY c.ak_name, c.tree_id;

-- Once a minute, the rows that each node's newest record adds past the
-- history stored for it. They continue the history from its last row
-- when the record's window starts at or below that row, and otherwise
-- start with a gap at the record's base_seq: the backend has not heard
-- from the node since before its window, or never, and what the node did
-- in between is lost. The roots are folded from the stored root, or from
-- base_root after a gap. The rows are added only when every operation is
-- in tree_ops, none up to last_seq is unreached and the fold ends at the
-- record's projection_root: a record that does not extend the history
-- consistently adds nothing. Nor does a record that contradicts the
-- history, or any record of a marked node: what such a node says is not
-- kept. The fold runs once per distinct path and start, not per node.
CREATE MATERIALIZED VIEW IF NOT EXISTS shirudo.node_ops_mv
REFRESH EVERY 1 MINUTE APPEND TO shirudo.node_ops AS
WITH
    reach AS
    (
        SELECT ak_name, tree_id, max(seq) AS stored_max, argMax(root, seq) AS stored_root
        FROM shirudo.node_ops
        GROUP BY ak_name, tree_id
    ),
    node AS
    (
        SELECT k.ak_name AS ak_name,
               ifNull(k.tree_id, '') AS p_tree,
               ifNull(k.base_seq, 0) AS p_base,
               ifNull(k.last_seq, 0) AS p_last,
               ifNull(k.mask, '') AS p_mask,
               ifNull(k.base_root, '') AS p_root,
               ifNull(k.projection_root, '') AS p_end,
               r.ak_name = '' AS unknown,
               if(unknown, 0, r.stored_max) AS stored_max,
               stored_max < p_base AS gap,
               if(gap, p_base, stored_max) AS p_start,
               toFixedString(if(gap, unhex(p_root), if(unknown, repeat('\0', 32), r.stored_root)), 32)
                   AS start_root
        FROM shirudo.keepalive_latest AS k FINAL
        LEFT JOIN reach AS r ON r.ak_name = k.ak_name AND r.tree_id = ifNull(k.tree_id, '')
        WHERE k.tree_id IS NOT NULL AND k.mask IS NOT NULL AND k.base_seq IS NOT NULL
              AND k.last_seq IS NOT NULL AND match(p_root, '^[0-9a-f]{64}$')
              AND match(p_end, '^[0-9a-f]{64}$') AND p_last > p_start
    ),
    folded AS
    (
        SELECT p.p_tree AS p_tree, p.p_base AS p_base, p.p_last AS p_last, p.p_mask AS p_mask,
               p.p_end AS p_end, p.gap AS gap, p.p_start AS p_start, p.start_root AS start_root,
               arraySort(groupArray((o.seq, mask_code(p.p_mask, o.seq - p.p_base - 1),
                                     unhex(o.operation_digest)))) AS steps,
               arrayFold((acc, x) -> arrayPushBack(acc, if(has([1, 3], x.2),
                                                           SHA256(concat(acc[-1], x.3)), acc[-1])),
                         steps, [any(p.start_root)]) AS roots
        FROM (SELECT DISTINCT p_tree, p_base, p_last, p_mask, p_end, gap, p_start, start_root FROM node) AS p
        INNER JOIN shirudo.tree_ops AS o FINAL ON o.tree_id = p.p_tree
        WHERE o.seq > p.p_start AND o.seq <= p.p_last
        GROUP BY p.p_tree, p.p_base, p.p_last, p.p_mask, p.p_end, p.gap, p.p_start, p.start_root
        HAVING length(steps) = p_last - p_start AND arrayAll(x -> x.2 != 0, steps)
               AND lower(hex(roots[-1])) = p_end
    )
SELECT n.ak_name AS ak_name, n.p_tree AS tree_id, row.1 AS seq, row.2 AS code, row.3 AS root
FROM node AS n
INNER JOIN folded AS f
    ON f.p_tree = n.p_tree AND f.p_base = n.p_base AND f.p_last = n.p_last AND f.p_mask = n.p_mask
       AND f.p_end = n.p_end AND f.gap = n.gap AND f.p_start = n.p_start AND f.start_root = n.start_root
ARRAY JOIN arrayConcat(if(f.gap, [(f.p_base, toUInt8(0), f.start_root)], []),
                       arrayMap((x, r) -> (x.1, x.2, r), f.steps, arrayPopFront(f.roots))) AS row
WHERE n.ak_name NOT IN (SELECT ak_name FROM shirudo.history_contradictions)
      AND (n.ak_name, n.p_tree) NOT IN (SELECT ak_name, tree_id FROM shirudo.history_conflicts);

-- Once a minute, a mark for every node whose newest record contradicts
-- its history and that has none for the tree yet.
CREATE MATERIALIZED VIEW IF NOT EXISTS shirudo.history_contradictions_mv
REFRESH EVERY 1 MINUTE APPEND TO shirudo.history_contradictions AS
SELECT ak_name, tree_id, seq, reason
FROM shirudo.history_conflicts
WHERE (ak_name, tree_id) NOT IN (SELECT ak_name, tree_id FROM shirudo.history_contradictions);

-- One row per node. status is stale when the newest record is older than
-- stale_seconds, whatever it says, else unhealthy when one of checks 3
-- to 7 fails and healthy otherwise. failed_check is the first check that
-- fails, 2 for stale and 0 for none, and log has one line per check, 1
-- to 7. trust is not part of status. head_seq is the head of the newest
-- publication known for the node's tree.
CREATE TABLE IF NOT EXISTS shirudo.node_status
(
    node_id String,
    ak_name String,
    host_name String,
    status Enum8('healthy' = 1, 'unhealthy' = 2, 'stale' = 3),
    trust Enum8('untrusted' = 0, 'enrolled' = 1),
    failed_check UInt8,
    log Array(String),
    last_seen DateTime64(3),
    generation Nullable(UInt64),
    last_seq Nullable(UInt64),
    head_seq Nullable(UInt64),
    loaded UInt64,
    set_sha256 String,
    updated_at DateTime
)
ENGINE = MergeTree
ORDER BY (node_id, ak_name);

-- Each refresh replaces the rows of node_status in one step.
--
-- Checks 4 to 7 are only evaluated for a node whose record can be held
-- against the tree; skip names why another is not, and such a node
-- passes them: it follows no tree, its record has no mask (its outcomes
-- file is damaged, which flags bit 2 says and check 3 fails), or it
-- names a generation the ingest job has not loaded yet, so that
-- tree_ops may end before the record does.
--
-- The root and the set a mask leads to depend on the tree and the mask,
-- not on the node, so both are folded once per distinct path and joined
-- back to the nodes on it.
--
-- A record whose window starts past seq 0 is also held against the
-- node's history in node_ops: its base_root against the root stored at
-- base_seq (check 4), and its set against what node_sets leaves loaded
-- there, under what the window changes (check 6). Where the backend has
-- not seen the node reach base_seq, without a gap since, the line says
-- so and the check does not fail on that account. Every record, from
-- seq 0 or not, is also held against the rows its window overlaps
-- (history_conflicts), and a node that has a mark fails check 4 whether
-- its record can be held against the tree or not.
CREATE MATERIALIZED VIEW IF NOT EXISTS shirudo.node_status_mv
REFRESH EVERY 1 MINUTE TO shirudo.node_status AS
WITH
    (SELECT stale_seconds FROM shirudo.settings FINAL) AS stale_after,
    (SELECT stuck_seconds FROM shirudo.settings FINAL) AS stuck_after,
    head AS
    (
        SELECT tree_id,
               max(generation) AS newest,
               argMax(head_seq, generation) AS head_seq
        FROM shirudo.tree_pubs FINAL
        GROUP BY tree_id
    ),
    node AS
    (
        SELECT l.*,
               h.newest AS newest,
               h.head_seq AS head,
               multiIf(l.tree_id IS NULL, 'no tree',
                       l.mask IS NULL, 'no mask',
                       h.newest = 0 OR ifNull(l.generation, 0) > h.newest, 'publication unknown',
                       '') AS skip,
               ifNull(l.tree_id, '') AS p_tree,
               ifNull(l.base_seq, 0) AS p_base,
               ifNull(l.last_seq, 0) AS p_last,
               ifNull(l.base_root, '') AS p_root,
               ifNull(l.mask, '') AS p_mask,
               ifNull(l.config_root, '') AS p_config,
               l.base_seq IS NOT NULL AND l.last_seq IS NOT NULL AND p_last >= p_base
                   AND match(p_root, '^[0-9a-f]{64}$')
                   AND match(ifNull(l.projection_root, ''), '^[0-9a-f]{64}$') AS well_formed,
               -- The pairs up to last_seq: what peers at the same point
               -- of a tree have in common, whatever head each has seen.
               if(p_last > p_base,
                  substring(tryBase64Decode(p_mask), 1, intDiv(p_last - p_base + 3, 4)), '') AS walked
        FROM shirudo.latest AS l
        LEFT JOIN head AS h ON h.tree_id = l.tree_id
    ),
    -- When the publication a node has not finished was loaded: the
    -- earliest one whose head is beyond the node's last_seq. The stuck
    -- clock of check 5 starts there and not at the newest publication,
    -- which an operator who publishes often would keep moving.
    unfinished AS
    (
        SELECT n.p_tree AS p_tree, n.p_last AS p_last, min(t.published_at) AS behind_since
        FROM (SELECT DISTINCT p_tree, p_last FROM node WHERE skip = '') AS n
        INNER JOIN shirudo.tree_pubs AS t FINAL ON t.tree_id = n.p_tree
        WHERE t.head_seq > n.p_last
        GROUP BY n.p_tree, n.p_last
    ),
    paths AS
    (
        SELECT DISTINCT p_tree, p_base, p_last, p_root, p_mask
        FROM node
        WHERE skip = '' AND well_formed
    ),
    -- How far each node's stored history reaches and the seq of its first
    -- gap, 0 when it has none: rows are only ever added past the last, so
    -- the history up to a seq is whole when it reaches that seq and has no
    -- gap at or below it.
    reach AS
    (
        SELECT ak_name, tree_id, max(seq) AS stored_max, minIf(seq, code = 0) AS first_gap
        FROM shirudo.node_ops
        GROUP BY ak_name, tree_id
    ),
    -- The stored row at the base_seq of each record whose window starts
    -- past seq 0.
    based AS
    (
        SELECT ak_name, tree_id, seq, any(code) AS code, lower(hex(any(root))) AS root
        FROM shirudo.node_ops
        WHERE (ak_name, tree_id, seq) IN (SELECT ak_name, p_tree, p_base FROM node WHERE skip = '' AND p_base > 0)
        GROUP BY ak_name, tree_id, seq
    ),
    ops AS
    (
        SELECT p.p_tree AS p_tree, p.p_base AS p_base, p.p_last AS p_last,
               p.p_root AS p_root, p.p_mask AS p_mask,
               o.seq AS seq, o.id AS id, o.op AS op,
               o.payload_sha256 AS payload_sha256, o.operation_digest AS operation_digest,
               mask_code(p.p_mask, o.seq - p.p_base - 1) AS code
        FROM paths AS p
        INNER JOIN shirudo.tree_ops AS o FINAL ON o.tree_id = p.p_tree
        WHERE o.seq > p.p_base AND o.seq <= p.p_last
    ),
    chain AS
    (
        SELECT p_tree, p_base, p_last, p_root, p_mask,
               count() AS ops,
               countIf(code = 0) AS unreached,
               lower(hex(arrayFold((acc, digest) -> SHA256(concat(acc, unhex(digest))),
                                   arrayMap(x -> x.2, arraySort(groupArrayIf((seq, operation_digest), code IN (1, 3)))),
                                   toFixedString(unhex(any(p_root)), 32)))) AS root
        FROM ops
        GROUP BY p_tree, p_base, p_last, p_root, p_mask
    ),
    applied AS
    (
        SELECT p_tree, p_base, p_last, p_root, p_mask, id,
               max(seq) AS last_seq,
               argMax(op, seq) AS last_op,
               argMax(payload_sha256, seq) AS last_payload
        FROM ops
        WHERE code = 1
        GROUP BY p_tree, p_base, p_last, p_root, p_mask, id
    ),
    sets AS
    (
        SELECT p_tree, p_base, p_last, p_root, p_mask,
               lower(hex(SHA256(arrayStringConcat(arrayMap(x -> x.2, arraySort(
                   groupArrayIf((id, concat(last_payload, ' ', id, '\n')), last_op = 'add'))))))) AS expected_set
        FROM applied
        GROUP BY p_tree, p_base, p_last, p_root, p_mask
    ),
    -- The set of a node whose window starts past seq 0: per upatch the
    -- newest operation it applied, from the window where the window has
    -- one and else from node_sets at or below base_seq. node_sets keeps
    -- only an upatch's newest operation, which may be in the window; the
    -- window then has it too.
    long_sets AS
    (
        SELECT ak_name,
               lower(hex(SHA256(arrayStringConcat(arrayMap(x -> x.2, arraySort(
                   groupArrayIf((id, concat(payload, ' ', id, '\n')), op = 'add'))))))) AS expected_set
        FROM
        (
            SELECT ak_name, id, argMax(last_op, last_seq) AS op, argMax(last_payload, last_seq) AS payload
            FROM
            (
                SELECT k.ak_name AS ak_name, a.id AS id, a.last_seq AS last_seq,
                       toString(a.last_op) AS last_op, a.last_payload AS last_payload
                FROM node AS k
                INNER JOIN applied AS a ON a.p_tree = k.p_tree AND a.p_base = k.p_base AND a.p_last = k.p_last
                                           AND a.p_root = k.p_root AND a.p_mask = k.p_mask
                WHERE k.skip = '' AND k.p_base > 0
                UNION ALL
                SELECT k.ak_name, s.id, s.last_seq, toString(s.last_op), s.last_payload
                FROM node AS k
                INNER JOIN
                (
                    SELECT *
                    FROM shirudo.node_sets FINAL
                    WHERE (ak_name, tree_id) IN (SELECT ak_name, p_tree FROM node WHERE skip = '' AND p_base > 0)
                ) AS s ON s.ak_name = k.ak_name AND s.tree_id = k.p_tree
                WHERE k.skip = '' AND k.p_base > 0 AND s.last_seq <= k.p_base
            )
            GROUP BY ak_name, id
        )
        GROUP BY ak_name
    ),
    peers AS
    (
        SELECT ak_name, n, same,
               max(same) OVER (PARTITION BY p_tree, p_base, p_last, p_config, kernel_release) AS most
        FROM
        (
            SELECT ak_name, p_tree, p_base, p_last, p_config, kernel_release,
                   count() OVER (PARTITION BY p_tree, p_base, p_last, p_config, kernel_release) AS n,
                   count() OVER (PARTITION BY p_tree, p_base, p_last, p_config, kernel_release, p_root, walked)
                       AS same
            FROM node
            WHERE skip = ''
        )
    ),
    boot AS
    (
        SELECT ak_name, boot_id, argMinMerge(tamper_first) AS tamper_first
        FROM shirudo.boot_first
        GROUP BY ak_name, boot_id
    ),
    conflicts AS
    (
        SELECT ak_name, tree_id, reason, seq
        FROM shirudo.history_conflicts
    ),
    marks AS
    (
        SELECT ak_name, argMin(seq, marked_at) AS seq
        FROM shirudo.history_contradictions
        GROUP BY ak_name
    ),
    refused AS
    (
        SELECT ak_name, count() AS rejected
        FROM shirudo.rejected
        WHERE received >= now() - INTERVAL 1 HOUR
        GROUP BY ak_name
    ),
    result AS
    (
        SELECT k.node_id AS node_id, k.ak_name AS ak_name, k.host_name AS host_name, k.trust AS trust,
               k.received AS received, k.generation AS generation, k.last_seq AS last_seq,
               k.count AS count, k.set_sha256 AS set_sha256, k.verdict AS verdict, k.cond AS cond,
               k.flags AS flags, k.version_id AS version_id, k.projection_root AS projection_root,
               k.skip AS skip, k.newest AS newest, k.head AS head, k.p_last AS p_last,
               p.n AS n,
               r.rejected AS rejected,
               dateDiff('second', k.received, now64(3)) AS age_s,
               age_s > stale_after AS stale,
               -- A record that could not read its counters has no total
               -- to compare; flags bit 3 says so and fails the check.
               if(empty(k.tamper), 0,
                  toInt64(arraySum(k.tamper)) - toInt64(b.tamper_first)) AS tamper_rise,
               k.version_id IN (SELECT version_id FROM shirudo.expected_builds) AS build_ok,
               -- The seven condition pairs this schema knows, all OK,
               -- and flags bits 0 to 3; bits 4 and 5 say busy, not broken.
               k.verdict = 'ok' AND bitAnd(k.cond, 0x3FFF) = 0x1555 AND bitAnd(k.flags, 15) = 0
                   AND tamper_rise = 0 AND build_ok AS ok3,
               -- A gap row holds the base_root of the record that found
               -- the gap, which nothing verified: the same value again
               -- is no more verified, another one is a changed story.
               multiIf(k.skip != '' OR k.p_base = 0, '',
                       bs.ak_name = '' OR (bs.code = 0 AND bs.root = k.p_root), 'gap',
                       bs.root = k.p_root, '',
                       'differs') AS base_state,
               multiIf(base_state = 'differs' OR cf.reason = 'base', 'base differs from history',
                       cf.reason = 'window', concat('window differs from history at seq ', toString(cf.seq)),
                       mk.ak_name != '', concat('marked: contradicted history at seq ', toString(mk.seq)),
                       base_state = 'gap', 'base unverified (gap)',
                       '') AS history_state,
               (k.skip != '' OR (k.well_formed AND c.ops = k.p_last - k.p_base AND c.unreached = 0
                   AND if(c.ops = 0, k.p_root, c.root) = k.projection_root AND base_state != 'differs'))
                   AND cf.ak_name = '' AND mk.ak_name = '' AS ok4,
               k.p_base > 0 AND NOT (h.stored_max >= k.p_base AND (h.first_gap = 0 OR h.first_gap > k.p_base))
                   AS set_gap,
               if(k.p_base > 0, ls.expected_set, s.expected_set) AS expected_set,
               k.p_last >= k.head AS at_head,
               k.skip != '' OR at_head
                   OR dateDiff('second', u.behind_since, now64(3)) <= stuck_after AS ok5,
               -- An operation in flight has a seq above last_seq, so a
               -- pending one at the head is a contradiction.
               multiIf(k.skip != '', '',
                       bitTest(k.flags, 4) AND at_head, 'FAIL sync in progress at head',
                       bitTest(k.flags, 4), 'sync in progress',
                       bitTest(k.flags, 5), 'snapshot unsettled',
                       set_gap, 'set unverified (gap)',
                       if(expected_set = '', lower(hex(SHA256(''))), expected_set) = k.set_sha256, 'pass',
                       'FAIL drift') AS set_state,
               NOT startsWith(set_state, 'FAIL') AS ok6,
               k.skip != '' OR p.n = 1 OR p.same = p.most AS ok7
        FROM node AS k
        LEFT JOIN boot AS b ON b.ak_name = k.ak_name AND b.boot_id = k.boot_id
        LEFT JOIN refused AS r ON r.ak_name = k.ak_name
        LEFT JOIN peers AS p ON p.ak_name = k.ak_name
        LEFT JOIN unfinished AS u ON u.p_tree = k.p_tree AND u.p_last = k.p_last
        LEFT JOIN chain AS c ON c.p_tree = k.p_tree AND c.p_base = k.p_base AND c.p_last = k.p_last
                                AND c.p_root = k.p_root AND c.p_mask = k.p_mask
        LEFT JOIN sets AS s ON s.p_tree = k.p_tree AND s.p_base = k.p_base AND s.p_last = k.p_last
                               AND s.p_root = k.p_root AND s.p_mask = k.p_mask
        LEFT JOIN reach AS h ON h.ak_name = k.ak_name AND h.tree_id = k.p_tree
        LEFT JOIN based AS bs ON bs.ak_name = k.ak_name AND bs.tree_id = k.p_tree AND bs.seq = k.p_base
        LEFT JOIN long_sets AS ls ON ls.ak_name = k.ak_name
        LEFT JOIN conflicts AS cf ON cf.ak_name = k.ak_name AND cf.tree_id = k.p_tree
        LEFT JOIN marks AS mk ON mk.ak_name = k.ak_name
    )
SELECT
    node_id,
    ak_name,
    host_name,
    multiIf(stale, 'stale', ok3 AND ok4 AND ok5 AND ok6 AND ok7, 'healthy', 'unhealthy') AS status,
    trust,
    multiIf(stale, 2, NOT ok3, 3, NOT ok4, 4, NOT ok5, 5, NOT ok6, 6, NOT ok7, 7, 0) AS failed_check,
    [
        concat('1 signed: pass, ', toString(trust), ', ', toString(rejected), ' rejected in the last hour'),
        concat('2 fresh: ', if(stale, 'FAIL', 'pass'), ', last record ', toString(age_s), ' s ago'),
        concat('3 reported: ', if(ok3, 'pass', 'FAIL'), ', verdict ', verdict, ', cond 0x', hex(cond),
               ', flags ', toString(flags), ', tamper ', if(tamper_rise < 0, '', '+'), toString(tamper_rise),
               ', build ', substring(version_id, 1, 8), if(build_ok, '', ' (not expected)')),
        concat('4 chain: ', if(skip != '' AND history_state = '', skip,
               concat(if(ok4, 'pass', 'FAIL'),
                      if(skip != '', concat(', ', skip),
                         concat(', root ', substring(ifNull(projection_root, ''), 1, 8))),
                      if(history_state = '', '', concat(', ', history_state))))),
        concat('5 head: ', if(skip != '', skip,
               concat(multiIf(at_head, 'pass', ok5, 'behind', 'FAIL stuck'), ', seq ', toString(p_last),
                      ' of ', toString(head), ', generation ', toString(ifNull(generation, 0))))),
        concat('6 set: ', if(skip != '', skip, concat(set_state, ', ', toString(count), ' loaded'))),
        concat('7 peers: ', if(skip != '', skip,
               concat(multiIf(n = 1, 'no peers', ok7, 'pass', 'FAIL outlier'), ', ', toString(n), ' in group')))
    ] AS log,
    received AS last_seen,
    generation,
    last_seq,
    if(newest = 0, NULL, head) AS head_seq,
    count AS loaded,
    set_sha256,
    now() AS updated_at
FROM result;
