-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- Exposure: which nodes run a vulnerable package or kernel, and whether
-- an upatch of their tree shields them. Packages come from the SBOM of
-- the image a node says it booted, the kernel from the release it
-- reports, the shield from its mask and its history in node_ops.
-- shirudo.node_vulns is what a UI reads; the tables before it are its
-- inputs.

-- One row per image the SBOM store holds, written by jobs/sbom-scan.
-- image_root is empty for an image built without verity and sbom_sha256
-- is empty unless state is ok. sbom_format is the value of image.json,
-- cyclonedx-json when it names none. Only an image whose state is ok has
-- findings in sbom_vulns.
CREATE TABLE IF NOT EXISTS shirudo.sbom_images
(
    image_id String,
    image_version String,
    image_root String,
    sbom_format LowCardinality(String) DEFAULT 'cyclonedx-json',
    sbom_sha256 String,
    state Enum8('ok' = 1, 'missing' = 2, 'hash_mismatch' = 3, 'parse_error' = 4,
                'unsupported_format' = 5),
    built_at DateTime,
    db_version String,
    scanned_at DateTime
)
ENGINE = ReplacingMergeTree(scanned_at)
ORDER BY (image_id, image_version, image_root);

-- The findings of every scan of an SBOM. scanned_at is that of the scan,
-- as sbom_images has it: the findings of an image are the rows of its
-- newest scan, and those of older scans leave with the TTL. fixed is
-- empty while no fixed version exists.
CREATE TABLE IF NOT EXISTS shirudo.sbom_vulns
(
    sbom_sha256 String,
    vuln_id String,
    package String,
    installed String,
    fixed String,
    severity LowCardinality(String),
    scanned_at DateTime
)
ENGINE = MergeTree
ORDER BY (sbom_sha256, vuln_id, package)
TTL scanned_at + INTERVAL 7 DAY;

-- Kernel advisories, one row per affected range of releases: from
-- introduced, inclusive, to fixed, exclusive, each a release as kver()
-- gives it. An empty fixed is a range without an end.
CREATE TABLE IF NOT EXISTS shirudo.kernel_vulns
(
    vuln_id String,
    introduced Array(UInt32),
    fixed Array(UInt32),
    severity LowCardinality(String)
)
ENGINE = ReplacingMergeTree
ORDER BY (vuln_id, introduced);

-- The numbers a kernel release starts with: '7.4.2-shirudo' is
-- [7, 4, 2]. Arrays compare element by element and a prefix sorts before
-- what extends it, so [7, 4, 2] is at least [7, 0] and below [7, 4, 5].
-- A release that starts with no number is []: a record is signed by a
-- key anyone can make, and one bad kernel_release must not stop the
-- refresh for every node. A number UInt32 cannot hold reads as 0. A
-- function has no database, so the name is global.
CREATE OR REPLACE FUNCTION kver AS (r) ->
    arrayMap(x -> toUInt32OrZero(x), extractAll(extract(r, '^[0-9]+(?:[.][0-9]+)*'), '[0-9]+'));

-- One row per node and finding, and one row with an empty vuln_id for a
-- node with none, so that a node without findings differs from a node
-- that is not there. binding says how far the SBOM can be trusted to
-- describe the node, sbom_stale that the newest scan of that SBOM is
-- older than sbom_stale_seconds of shirudo.settings, and exposure what
-- stands between the node and the vulnerability now. upatch_id names the
-- upatch that is read from; applied_seq and applied_op are its newest
-- operation the node has applied, 0 and empty when it has applied none,
-- and next_seq and next_op its newest operation in the tree, equal to
-- those two when nothing is coming, so that next_seq above applied_seq
-- says something is.
-- next_shields says whether that newest operation is an add linked to the
-- advisory, false when it is a delete or an add that drops the link.
-- shield_link is where the link to the advisory comes from. All of them
-- are empty, 0, false and none when no upatch is linked. The exposure
-- values are in the order they are ranked in, best first. status and
-- trust are the node's in node_status.
CREATE TABLE IF NOT EXISTS shirudo.node_vulns
(
    node_id String,
    ak_name String,
    host_name String,
    status Enum8('healthy' = 1, 'unhealthy' = 2, 'stale' = 3),
    trust Enum8('untrusted' = 0),
    image_id String,
    image_version String,
    binding Enum8('verified' = 1, 'declared' = 2, 'root_mismatch' = 3, 'no_sbom' = 4, 'no_image' = 5),
    sbom_stale Bool,
    source Enum8('sbom' = 1, 'kernel' = 2, 'none' = 3),
    vuln_id String,
    severity LowCardinality(String),
    package String,
    installed String,
    fixed String,
    exposure Enum8('shielded' = 1, 'shield_pending' = 2, 'shield_module_absent' = 3,
                   'shield_excludes_node' = 4, 'shield_withdrawn' = 5, 'exposed_no_shield' = 6,
                   'none' = 7, 'unknown' = 8),
    upatch_id String,
    applied_seq UInt64,
    applied_op Enum8('' = 0, 'add' = 1, 'delete' = 2),
    next_seq UInt64,
    next_op Enum8('' = 0, 'add' = 1, 'delete' = 2),
    next_shields Bool,
    shield_link Enum8('none' = 0, 'fixes' = 1, 'manual' = 2),
    updated_at DateTime
)
ENGINE = MergeTree
ORDER BY (node_id, ak_name, vuln_id, package);

-- Each refresh replaces the rows of node_vulns in one step. Five minutes
-- are enough: an SBOM's findings change once a day at most, and
-- node_status follows the tree every minute.
--
-- The work is per image, per kernel release and per path through a tree,
-- not per node: the kernel advisories are matched once for each distinct
-- kernel_release, and the newest operation of every upatch is found once
-- for each distinct tree_id, base_seq, last_seq and mask, then joined to
-- the nodes. Only what an operation below the window did is per node: the
-- mask does not cover it, so it is read from the node's history in
-- node_ops, one row per node and linked upatch.
--
-- A stale scan keeps its findings, which are still the newest known, and
-- marks them sbom_stale. It never makes a node read clean: the row of a
-- node without findings is unknown then, as for a node without an SBOM,
-- since the findings may have expired with sbom_vulns' TTL.
--
-- A row says where the node is, not where the tree is. For an upatch
-- linked to the advisory, the node has applied the operations up to its
-- last_seq. When the newest of them is an add, the mask says what it
-- did there, or the node's history when the add is below the window:
-- shielded, shield_module_absent or shield_excludes_node, and unknown
-- when neither says, because the record has no mask or marks the
-- operation as not reached, or the backend never saw the node reach it. When it is a delete, the shield is
-- withdrawn. When the node has applied none, nothing is loaded:
-- shield_pending when the tree's newest operation is an add, and
-- shield_withdrawn when it is a delete, which the node will reach
-- without ever having had the shield.
--
-- An upatch counts for an advisory when upatch_fixes links the newest
-- add the node has applied or the newest add of the tree. Only the
-- first says what is loaded: when just the coming add is linked, what
-- the node has applied is no shield against this advisory and the row
-- reads as if it had applied none. shield_link is the applied add's
-- link when there is one, else the coming add's.
--
-- Of several upatches linked to one advisory the best outcome counts, in
-- the order of the exposure values, and of two links to the same
-- operation the signed one, fixes, before manual.
CREATE MATERIALIZED VIEW IF NOT EXISTS shirudo.node_vulns_mv
REFRESH EVERY 5 MINUTE TO shirudo.node_vulns AS
WITH
    (SELECT sbom_stale_seconds FROM shirudo.settings FINAL) AS sbom_stale_after,
    node AS
    (
        SELECT ak_name, kernel_release,
               ifNull(image_id, '') AS image_id,
               ifNull(image_version, '') AS image_version,
               ifNull(image_root, '') AS image_root,
               ifNull(tree_id, '') AS p_tree,
               ifNull(base_seq, 0) AS p_base,
               ifNull(last_seq, 0) AS p_last,
               ifNull(mask, '') AS p_mask
        FROM shirudo.latest
    ),
    -- The SBOM of each node's image: the one with the node's own root
    -- when there is one, else the newest build of that id and version.
    img AS
    (
        SELECT n.ak_name AS ak_name, i.sbom_sha256 AS sbom_sha256, i.scanned_at AS scanned_at,
               multiIf(n.image_id = '', 'no_image',
                       i.image_id = '' OR i.state != 'ok' OR i.sbom_sha256 = '', 'no_sbom',
                       n.image_root != '' AND n.image_root = i.image_root, 'verified',
                       n.image_root != '' AND i.image_root != '', 'root_mismatch',
                       'declared') AS binding,
               binding IN ('verified', 'declared', 'root_mismatch')
                   AND dateDiff('second', i.scanned_at, now()) > sbom_stale_after AS sbom_stale
        FROM node AS n
        LEFT JOIN shirudo.sbom_images AS i FINAL
            ON i.image_id = n.image_id AND i.image_version = n.image_version
        ORDER BY n.ak_name, i.image_root = n.image_root DESC, i.built_at DESC, i.image_root
        LIMIT 1 BY n.ak_name
    ),
    kmatch AS
    (
        SELECT r.kernel_release AS kernel_release, k.vuln_id AS vuln_id, k.severity AS severity,
               arrayStringConcat(arrayMap(x -> toString(x), k.fixed), '.') AS fixed
        FROM (SELECT DISTINCT kernel_release, kver(kernel_release) AS release FROM node) AS r
        CROSS JOIN shirudo.kernel_vulns AS k FINAL
        WHERE notEmpty(r.release) AND r.release >= k.introduced
              AND (empty(k.fixed) OR r.release < k.fixed)
        ORDER BY r.kernel_release, k.vuln_id, k.introduced
        LIMIT 1 BY r.kernel_release, k.vuln_id
    ),
    -- The SBOM describes the kernel installed in the image, and the node
    -- may run another: kernel findings come from kernel_vulns alone.
    found AS
    (
        SELECT g.ak_name AS ak_name, 'sbom' AS source, v.vuln_id AS vuln_id, v.severity AS severity,
               v.package AS package, v.installed AS installed, v.fixed AS fixed
        FROM img AS g
        INNER JOIN shirudo.sbom_vulns AS v
            ON v.sbom_sha256 = g.sbom_sha256 AND v.scanned_at = g.scanned_at
        WHERE g.binding IN ('verified', 'declared', 'root_mismatch')
              AND NOT match(v.package, '^(linux-image-|kernel$|kernel-core$)')
        UNION ALL
        SELECT n.ak_name, 'kernel', m.vuln_id, m.severity, 'linux', n.kernel_release, m.fixed
        FROM node AS n
        INNER JOIN kmatch AS m ON m.kernel_release = n.kernel_release
    ),
    paths AS
    (
        SELECT DISTINCT p_tree, p_base, p_last, p_mask
        FROM node
        WHERE p_tree != ''
    ),
    -- code is what the node did at applied_seq when the mask covers it,
    -- and 255 when the operation is below the window and the node's
    -- history has to say.
    upatch AS
    (
        SELECT p.p_tree AS p_tree, p.p_base AS p_base, p.p_last AS p_last, p.p_mask AS p_mask,
               o.id AS upatch_id,
               max(o.seq) AS next_seq,
               argMax(toString(o.op), o.seq) AS next_op,
               maxIf(o.seq, o.op = 'add') AS next_add,
               maxIf(o.seq, o.seq <= p.p_last) AS applied_seq,
               argMaxIf(toString(o.op), o.seq, o.seq <= p.p_last) AS applied_op,
               maxIf(o.seq, o.op = 'add' AND o.seq <= p.p_last) AS applied_add,
               if(applied_seq > p.p_base OR applied_seq = 0,
                  argMaxIf(mask_code(p.p_mask, o.seq - p.p_base - 1), o.seq,
                           o.seq > p.p_base AND o.seq <= p.p_last),
                  255) AS code
        FROM paths AS p
        INNER JOIN shirudo.tree_ops AS o FINAL ON o.tree_id = p.p_tree
        GROUP BY p.p_tree, p.p_base, p.p_last, p.p_mask, o.id
    ),
    linked AS
    (
        SELECT u.p_tree AS p_tree, u.p_base AS p_base, u.p_last AS p_last, u.p_mask AS p_mask,
               u.upatch_id AS upatch_id, f.advisory AS vuln_id,
               any(u.next_seq) AS next_seq, any(u.next_op) AS next_op,
               any(u.applied_seq) AS applied_seq, any(u.applied_op) AS applied_op,
               minIf(toInt8(f.source), f.seq = u.applied_add) AS applied_link,
               minIf(toInt8(f.source), f.seq = u.next_add) AS next_link,
               if(applied_link != 0, applied_link, next_link) AS link,
               next_op = 'add' AND next_link != 0 AS next_shields,
               any(u.code) AS code
        FROM upatch AS u
        INNER JOIN shirudo.upatch_fixes AS f FINAL ON f.tree_id = u.p_tree
        WHERE f.seq = u.applied_add OR f.seq = u.next_add
        GROUP BY u.p_tree, u.p_base, u.p_last, u.p_mask, u.upatch_id, f.advisory
    ),
    -- Per node, the links of its path, with the code of an operation
    -- below the window taken from the node's history: 0, and so unknown,
    -- when the backend never saw the node reach it.
    reached AS
    (
        SELECT n.ak_name AS ak_name, l.vuln_id AS vuln_id, l.upatch_id AS upatch_id,
               l.applied_seq AS applied_seq, l.applied_op AS applied_op,
               l.next_seq AS next_seq, l.next_op AS next_op, l.link AS link, l.next_shields AS next_shields,
               if(l.code = 255, h.code, l.code) AS code,
               multiIf(l.applied_link != 0 AND l.applied_op = 'add',
                       transform(code, [1, 2, 3],
                                 ['shielded', 'shield_excludes_node', 'shield_module_absent'], 'unknown'),
                       l.applied_link != 0, 'shield_withdrawn',
                       l.next_op = 'add', 'shield_pending',
                       'shield_withdrawn') AS exposure
        FROM node AS n
        INNER JOIN linked AS l ON l.p_tree = n.p_tree AND l.p_base = n.p_base AND l.p_last = n.p_last
                                  AND l.p_mask = n.p_mask
        LEFT JOIN
        (
            SELECT ak_name, tree_id, seq, any(code) AS code
            FROM shirudo.node_ops
            WHERE (ak_name, tree_id, seq) IN
                  (SELECT n.ak_name, n.p_tree, l.applied_seq
                   FROM node AS n
                   INNER JOIN linked AS l ON l.p_tree = n.p_tree AND l.p_base = n.p_base
                                             AND l.p_last = n.p_last AND l.p_mask = n.p_mask
                   WHERE l.code = 255)
            GROUP BY ak_name, tree_id, seq
        ) AS h ON h.ak_name = n.ak_name AND h.tree_id = n.p_tree AND h.seq = l.applied_seq
    ),
    shield AS
    (
        SELECT ak_name, vuln_id,
               argMin((exposure, upatch_id, applied_seq, applied_op, next_seq, next_op,
                       if(link = 1, 'fixes', 'manual'), next_shields),
                      (indexOf(['shielded', 'shield_pending', 'shield_module_absent',
                                'shield_excludes_node', 'shield_withdrawn', 'unknown'], exposure),
                       link, upatch_id)) AS best
        FROM reached
        GROUP BY ak_name, vuln_id
    )
SELECT
    s.node_id AS node_id,
    s.ak_name AS ak_name,
    s.host_name AS host_name,
    s.status AS status,
    s.trust AS trust,
    n.image_id AS image_id,
    n.image_version AS image_version,
    g.binding AS binding,
    g.sbom_stale AS sbom_stale,
    if(v.vuln_id = '', 'none', v.source) AS source,
    v.vuln_id AS vuln_id,
    v.severity AS severity,
    v.package AS package,
    v.installed AS installed,
    v.fixed AS fixed,
    multiIf(v.vuln_id = '' AND (g.binding IN ('no_image', 'no_sbom') OR g.sbom_stale), 'unknown',
            v.vuln_id = '', 'none',
            h.best.1 = '', 'exposed_no_shield',
            h.best.1) AS exposure,
    h.best.2 AS upatch_id,
    h.best.3 AS applied_seq,
    h.best.4 AS applied_op,
    h.best.5 AS next_seq,
    h.best.6 AS next_op,
    if(h.best.1 = '', 'none', h.best.7) AS shield_link,
    h.best.1 != '' AND h.best.8 AS next_shields,
    now() AS updated_at
FROM shirudo.node_status AS s
INNER JOIN node AS n ON n.ak_name = s.ak_name
INNER JOIN img AS g ON g.ak_name = s.ak_name
LEFT JOIN found AS v ON v.ak_name = s.ak_name
LEFT JOIN shield AS h ON h.ak_name = s.ak_name AND h.vuln_id = v.vuln_id;
