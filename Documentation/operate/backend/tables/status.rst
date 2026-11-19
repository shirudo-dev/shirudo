..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

Status
======

Once a minute: extend each node's operation history, mark nodes whose
records contradict it, then run checks 1–7 for every node and replace
node_status in one step. Nothing here reads shirudo.keepalive.

Schema: :src:`tools/backend/sql/40-status.sql`

Views, functions and jobs
-------------------------

``mask_code(mask, i)``
   SQL function (global).

   Outcome pair of the i-th operation of a mask's window: 1, 2, 3, or 0 for
   not reached. Bad base64 or a short mask reads as 0, so one forged record
   can't break the refresh.

``shirudo.latest``
   view.

   keepalive_latest FINAL joined to nodes: the newest record of every node
   with node_id and trust.

``shirudo.node_labels``
   view.

   label_sets FINAL joined to nodes: per key, the labels put under its
   ak_name, else those put under its node_id, else none, and by, which of
   the three it is. An empty set counts as none.

``shirudo.history_conflicts``
   view.

   Nodes whose newest record contradicts their stored history: base_root
   against the root at base_seq, and every code and folded root of the
   window against the stored rows it overlaps. Gives the first differing seq
   and reason base or window.

``shirudo.node_ops_mv``
   refreshable MV, every 1 minute, APPEND.

   Appends to node_ops what each node's newest record adds past its stored
   history, folding roots once per distinct path. Skips nodes in
   history_conflicts or history_contradictions.

``shirudo.history_contradictions_mv``
   refreshable MV, every 1 minute, APPEND.

   Adds a mark to history_contradictions for each node and tree in
   history_conflicts that has none yet.

``shirudo.node_sets_mv``
   materialized view, on insert.

   node_ops (code 1) joined to tree_ops → node_sets.

``shirudo.node_status_mv``
   refreshable MV, every 1 minute.

   Runs checks 1–7 for all nodes and replaces node_status.

shirudo.node_ops
----------------

.. clickhouse-table:: shirudo.node_ops
   :kind: derived
   :ttl: None: rows are never removed (README.md, History, explains the cost)
   :row-size: ~34 B (README), mostly the 32-byte root, which does not compress.
   :scale: Nodes × operations each node reaches, every outcome counted, including
      selector misses. No TTL. Grows with publishing, not with keepalive
      rate.
   :reference: 650M rows ≈ 22 GB (README)
   :bytes: 2.2e+10

   Each node's history: what it did at every tree operation the backend has
   seen it reach. Lets checks 4 and 6 and node_vulns look below the
   512-operation window a keepalive covers.

   - code 0 is a gap: the node's record started past the stored history, so
     nothing below that seq is known. The gap row holds the unverified
     base_root of that record.
   - Rows are only appended when every operation is in tree_ops, none up to
     last_seq is unreached, and the fold ends at the record's
     projection_root. An inconsistent record adds nothing.
   - A record that contradicts the stored rows (history_conflicts) adds
     nothing, and neither does any record of a node marked in
     history_contradictions, gap rows included.
   - Projection reach keeps max(seq), argMax(root, seq) and the first gap
     per (ak_name, tree_id), so a refresh reads one row per node.
     deduplicate_merge_projection_mode = 'rebuild' is required for a
     ReplacingMergeTree to keep it.

   :ak_name: Node.
   :tree_id: Tree.
   :seq: Operation.
   :code: 1 applied, 2 selector did not match, 3 attach module not loaded, 0
      gap.
   :root: The node's projection root after this seq (raw SHA-256 bytes).

shirudo.node_sets
-----------------

.. clickhouse-table:: shirudo.node_sets
   :kind: derived
   :ttl: None
   :row-size: ~70 B (README).
   :scale: Nodes × upatches each node ever applied. No TTL.
   :reference: 1,000 upatches each: 10M rows ≈ 700 MB
   :bytes: 7e+08

   Per node, the newest operation of every upatch it applied, from node_ops
   rows with code 1. This is what the node's history leaves loaded, used by
   check 6 when a window starts past seq 0.

   :ak_name: Node.
   :tree_id: Tree.
   :id: Upatch.
   :last_seq: Newest applied operation for that upatch.
   :last_op: Whether it was loaded or removed.
   :last_payload: payload_sha256 of that operation.

shirudo.history_contradictions
------------------------------

.. clickhouse-table:: shirudo.history_contradictions
   :kind: derived
   :ttl: None: cleared only by an operator's ``DELETE``
   :row-size: ~80 B (estimate).
   :scale: Marked nodes × trees. Grows only when nodes lie; cleared by the
      operator.
   :reference: negligible
   :bytes: 1000

   Marks on nodes whose record once contradicted their stored history, one
   row per node and tree. A mark fails check 4 and stops the node's history
   from growing until an operator deletes it.

   - The mark is stricter than the record that set it. It holds whatever
     tree the node's newest record follows and whatever boot it comes from,
     and it fails check 4 even when check 4 would otherwise skip the node
     (no tree, no mask, publication unknown).
   - Neither a reboot nor a gap clears it, so a node that lied once cannot
     launder the lie by staying silent until its window moves past the
     history.
   - Clear it after looking at the node, for example with shirudo attest:
     DELETE FROM shirudo.history_contradictions WHERE ak_name = '<ak_name>'.

   :ak_name: Node.
   :tree_id: Tree whose history it contradicted.
   :seq: First seq where it differed. Shown in check 4 as 'marked: contradicted
      history at seq <seq>'.
   :reason: base: base_root differs from the stored root at base_seq. window: a
      code or folded root inside the window differs from a stored row.
   :marked_at: When the mark was set; default now().

shirudo.node_status
-------------------

.. clickhouse-table:: shirudo.node_status
   :kind: ui
   :queried-by: the UI
   :row-size: ~0.7 KB (estimate: seven log lines dominate).
   :scale: Nodes. The whole table is rewritten every minute.
   :reference: 10,000 rows ≈ 7 MB, rewritten every minute
   :bytes: 7e+06

   One row per node with the outcome of all seven checks. This is what a UI
   reads, as often as it likes.

   - Checks: 1 signed, 2 fresh, 3 reported, 4 chain, 5 head, 6 set, 7 peers.
     Each only means something if the ones before it passed.
   - Checks 4–7 pass with a reason when the node cannot be held against a
     tree: no tree, no mask, or publication unknown (ingest is behind).
   - A node behind the head is healthy until stuck_seconds after the
     earliest publication it has not finished was loaded; line 5 reads
     behind.
   - Check 4 also fails when the record contradicts the stored history
     ('base differs from history', 'window differs from history at seq N')
     or the node carries a mark ('marked: contradicted history at seq N'). A
     mark fails it even for a node check 4 would otherwise skip.

   :node_id: Label from nodes.
   :ak_name: Identity.
   :host_name: Host name the newest record claimed.
   :status: stale wins over everything; unhealthy if any of checks 3–7 fails.
   :trust: From nodes. Never part of status.
   :failed_check: First failing check: 2 for stale, 3–7 for unhealthy, 0 for healthy.
   :log: Seven lines, one per check, e.g. '5 head: pass, seq 3 of 3, generation
      3'.
   :last_seen: received of the newest record.
   :generation: From the newest record. NULL with no tree.
   :last_seq: From the newest record.
   :head_seq: Head of the newest loaded publication of the node's tree.
   :loaded: count from the record.
   :set_sha256: From the record.
   :updated_at: When the row was computed.
