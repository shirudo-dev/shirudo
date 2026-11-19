..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

Reference
=========

What the checks compare a record against, and what the operator says of a
node. nodes fills itself from accepted records; tree-ingest loads the tree
tables; labels-put loads label_sets; enroll-put loads enrollments and
raises trust in nodes; the operator writes builds, manual fixes and
settings.

Schema: :src:`tools/backend/sql/20-reference.sql`

Views, functions and jobs
-------------------------

``shirudo.nodes_mv``
   materialized view, on insert.

   checked → nodes for accepted rows, grouped by ak_name.

``jobs/tree-ingest``
   external job.

   Runs shirudo bpm tree show --walk and loads every verified segment not
   yet loaded into tree_pubs, tree_ops and upatch_fixes (source fixes). All
   or nothing on a conflict.

``jobs/labels-put``
   external job.

   Checks a file of label sets and loads it into label_sets in one insert,
   all or nothing, each row with one put_at later than any before.

``jobs/enroll-put``
   external job.

   Checks a builder's file of key bindings against enrollments, raises
   each key's trust in nodes to enrolled and names its node there, then
   records the new bindings in enrollments. A key is bound once.

shirudo.nodes
-------------

.. clickhouse-table:: shirudo.nodes
   :kind: ref
   :written-by: the operator, to relabel a node
   :row-size: ~0.5 KB (estimate: ak_public dominates).
   :scale: Every key ever seen. No TTL: a reprovisioned TPM adds a row and the
      old one stays.
   :reference: 10,000 rows ≈ 5 MB
   :bytes: 5e+06

   One row per attestation key: its public area, a human label, when it was
   first seen and its trust level.

   - Read through aggregates: argMinMerge(node_id), max(ak_public),
     min(first_seen), max(trust), GROUP BY ak_name.
   - To relabel, insert argMinState('<name>', toDateTime64(0, 3)) for the
     ak_name. Epoch 0 wins argMin. Leave ak_public and first_seen out so
     they don't change.
   - trust only ever rises. The operator inserts (ak_name, 'enrolled') once
     credential activation or a builder's records show the key is a TPM's,
     before or after the node's first record; jobs/enroll-put does it from
     a builder's records, with the node_id it gave at
     toDateTime64(0.001, 3), which a rename at epoch 0 still beats. It is shown but never part
     of status.

   :ak_name: Node identity.
   :ak_public: Public area of the key.
   :node_id: Label: the host name the key claimed first, unless relabeled.
   :first_seen: First accepted record.
   :trust: untrusted by default, enrolled once the operator records the key.

shirudo.expected_builds
-----------------------

.. clickhouse-table:: shirudo.expected_builds
   :kind: ref
   :written-by: the operator, or tools/put-shirudo-build
   :row-size: ~100 B (estimate).
   :scale: Builds you allow.
   :reference: tens of rows, negligible
   :bytes: 1000

   The builds a node is allowed to run, by version_id. A node whose
   version_id is missing fails check 3 with (not expected).

   :version_id: Build identifier of the shirudo binary, as in the keepalive body.
   :note: Free text for the operator.
   :added: Defaults to now().

shirudo.tree_pubs
-----------------

.. clickhouse-table:: shirudo.tree_pubs
   :kind: ref
   :written-by: :src:`tools/backend/jobs/tree-ingest`, from the verified output of ``shirudo bpm
      tree show --walk``: the newest publication and every sealed segment
      before it, back to seq 0
   :row-size: ~450 B (estimate: six 64-hex digests and roots).
   :scale: Publications (segments) per tree. Not per node.
   :reference: hundreds of rows, negligible
   :bytes: 100000

   One row per publication of a upatch tree. A publication is a segment of
   the tree holding the operations past segment_base_seq. Gives each tree's
   head for check 5 and the time a node's stuck clock starts.

   - published_at is when ingest loaded the row, not when the operator
     published. Ingest lag delays the stuck clock by the same amount.
   - Digests are 64 lowercase hex digits without a sha256: prefix.
   - The job holds every segment against what is loaded before inserting
     anything. One generation already loaded under a different manifest
     digest refuses the whole run, and nothing loads.

   :tree_id: Tree name.
   :generation: Publication number within the tree.
   :manifest_digest: OCI manifest of this publication.
   :parent_manifest_digest: Previous publication's manifest; empty for the first.
   :head_seq: Seq of the last operation in this publication.
   :segment_base_seq: The segment holds the operations after this seq. 0 for the first
      segment.
   :segment_manifest_digest: The sealed segment before this one; empty for the first.
   :history_root: The tree's history root at segment_base_seq; 64 zeros for the first
      segment.
   :published_at: Load time, default now64(3).

shirudo.tree_ops
----------------

.. clickhouse-table:: shirudo.tree_ops
   :kind: ref
   :written-by: :src:`tools/backend/jobs/tree-ingest`, from every segment of the tree
   :row-size: ~350 B (estimate: four 64-hex digests, selector JSON).
   :scale: Operations across all trees. Not per node.
   :reference: 65,000 rows ≈ 23 MB
   :bytes: 2.3e+07

   One row per operation of a tree. Operations never change once published,
   so reloading a publication replaces rows with identical ones.

   - selector is stored as JSON text and never evaluated. Whether it matched
     is read from the node's mask, where code 2 means it did not.

   :tree_id: Tree name.
   :seq: Position in the tree, from 1.
   :op: Load or remove a upatch.
   :id: Upatch id the operation acts on.
   :selector: Which nodes it targets, as JSON. Read with JSONExtract for display.
   :repository: OCI repository of the payload.
   :manifest_digest: Payload manifest.
   :layer_digest: Payload layer.
   :payload_sha256: Hash of the payload. Feeds the set hash in check 6.
   :operation_digest: Hash of the operation. Folded into the chain root in check 4.

shirudo.upatch_fixes
--------------------

.. clickhouse-table:: shirudo.upatch_fixes
   :kind: ref
   :written-by: :src:`tools/backend/jobs/tree-ingest` (source ``fixes``, from the operation's fixes
      key); the operator (source ``manual``)
   :row-size: ~60 B (estimate).
   :scale: Advisory links across all operations.
   :reference: negligible
   :bytes: 100000

   Which advisory an operation's upatch shields against. This is what turns
   a vulnerability into shielded, pending or withdrawn in node_vulns.

   - When both exist for the same operation, fixes (signed in the
     publication) ranks above manual.

   :tree_id: Tree name.
   :seq: The add operation that carries the shield.
   :id: Upatch id.
   :advisory: Vulnerability id, matching sbom_vulns / kernel_vulns vuln_id.
   :source: Where the link came from.

shirudo.settings
----------------

.. clickhouse-table:: shirudo.settings
   :kind: ref
   :written-by: the operator; seeded once by :src:`tools/backend/sql/20-reference.sql` if empty
   :queried-by: :src:`tools/backend/sql/apply-retention.sh`
   :row-size: ~50 B.
   :scale: Always one row (more until a merge).
   :reference: negligible
   :bytes: 50

   Thresholds and retention, in exactly one row. Read with FINAL. To change
   a value, insert the whole row again with id 1.

   - Retention values take effect when apply-retention.sh runs (it ALTERs
     the TTL of keepalive and boot_first). The rest apply at the next
     refresh.
   - Keep sbom_stale_seconds below 7 days, the sbom_vulns TTL, so an image
     reads stale before its findings expire and it reads clean.

   :id: Always 1.
   :stale_seconds: 600. A node with no record for this long is stale (check 2). Ten
      minutes because a tree sync holds the lock that keepalive needs.
   :stuck_seconds: 3600. How long a node may stay behind its tree's head (check 5).
   :window: 512. Operations a keepalive's mask covers.
   :keepalive_retention_seconds: 3600. TTL of shirudo.keepalive.
   :boot_first_retention_seconds: 2592000 (30 days). TTL of shirudo.boot_first.
   :sbom_stale_seconds: 172800 (2 days). Age after which a scan marks node_vulns rows
      sbom_stale.
   :updated: Version column: the newest row wins.

shirudo.label_sets
------------------

.. clickhouse-table:: shirudo.label_sets
   :kind: ref
   :written-by: jobs/labels-put
   :row-size: ~200 B (estimate: a few short labels).
   :scale: Every node and key ever labeled, each put once more until a merge.
   :reference: 10,000 rows ≈ 2 MB
   :bytes: 2e+06

   The labels the operator gives a node out of band, one set per node_id,
   ak_name or config_root. Not what the node's node.labels holds: tree
   sync matches selectors against that file, and nothing here reaches the
   node; a set by config_root is the one place they can agree.

   - Read with FINAL, or through node_labels: the newest put of a name
     replaces the set.
   - An empty map clears the set. A node's labels are the union of its
     sets in node_labels; label_conflicts lists the keys they disagree on.

   :by: Whether node names a node_id, an ak_name, or the config_root of the nodes that booted that config image.
   :node: The node_id, ak_name or config_root.
   :labels: The whole set, key to value.
   :put_at: When labels-put loaded it; the version ReplacingMergeTree keeps the newest of.

shirudo.enrollments
-------------------

.. clickhouse-table:: shirudo.enrollments
   :kind: ref
   :written-by: jobs/enroll-put
   :row-size: ~250 B (estimate: two TPM names, a node_id and a source).
   :scale: Every key a builder enrolled. No TTL.
   :reference: 10,000 rows ≈ 2.5 MB
   :bytes: 2.5e+06

   The attestation keys a builder created in a TPM, as it recorded them:
   what enrolled each key, where nodes only keeps that it is.

   - Read with FINAL. A key's binding is written once; enroll-put refuses
     another.
   - The row may come before the node's first record.

   :ak_name: The attestation key's name.
   :ek_name: The endorsement key's name the builder saw beside it, empty when it gave none. Nothing checks against it; attest verify --ek-name does.
   :node_id: The name the builder gave the node, empty when it gave none.
   :source: The builder, as the file named it.
   :put_at: When enroll-put loaded it.
