..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

Latest state
============

Small tables kept current on every insert so the checks never scan the audit
store: each node's newest record, and each boot's first tamper total and when its
newest record came first.

Schema: :src:`tools/backend/sql/30-latest.sql`

Views, functions and jobs
-------------------------

``shirudo.keepalive_latest_mv``
   materialized view, on insert.

   checked → keepalive_latest for accepted rows.

``shirudo.boot_first_mv``
   materialized view, on insert.

   checked → boot_first, aggregating per (ak_name, boot_id).

``shirudo.boot_first_keep_mv``
   refreshable MV, every 1 hour, APPEND.

   Rewrites the baseline of every node's current boot with last_used =
   now(), so the TTL only removes boots a node has left.

shirudo.keepalive_latest
------------------------

.. clickhouse-table:: shirudo.keepalive_latest
   :kind: store
   :row-size: ~1.5 KB per node (estimate: body plus its parsed columns; one row per
      node, so little cross-row compression).
   :scale: Nodes after a merge. Before one, up to one row per record received
      since the last merge.
   :reference: ≈ 15 MB
   :bytes: 1.5e+07

   The newest record of each node by the TPM's own counters. A late
   record never replaces a newer one; the newest one received again
   replaces itself, with the time of the copy.

   - Read with FINAL.
   - Same columns as keepalive, minus quote, plus order_key.

   :ak_name: Node identity; the sort key.
   :order_key: reset_count << 40 \| clock. Highest wins.
   :received: When the backend received the record, or a copy of it. Retention
      counts from it. Freshness (check 2) does not: it reads newest_received
      of boot_first.
   :time: The OTLP Timestamp the target put on the log record. Not trusted for
      ordering.
   :host_name: host.name resource attribute: what the node claims to be called. Not
      an identity.
   :body: The newest record's signed body.
   :reset_count: TPM reset counter of the newest record.
   :clock: TPM clock of the newest record.
   :schema: Body schema. Must be shirudo.keepalive/1 or 1.x, else the record is
      rejected as schema.
   :boot_id: Identifies the boot that sent the record. Tamper baselines in
      boot_first are per boot.
   :version_id: Build identifier of the shirudo binary: SHA-256 over its git commit
      (with -dirty), config.mk and Makefile.shirudo. Printed by shirudo
      version --version-id. Check 3 requires it to be in expected_builds.
   :config_root: Digest of the node's configuration. One of the keys that groups peers
      for check 7.
   :kernel_release: Running kernel, e.g. 7.4.2. Groups peers (check 7) and is matched
      against kernel_vulns via kver().
   :image_id: OS image the node says it booted. Joins to sbom_images.
   :image_version: Version of that image.
   :image_root: Verity root of the image. When it matches the SBOM's root the binding
      is verified.
   :verdict: The node's own overall verdict. Check 3 requires ok.
   :cond: Condition pairs, two bits each. Check 3 requires the low seven pairs
      to read 0x1555 (all OK).
   :flags: Bits 0–3 are faults and fail check 3 (bit 2: outcomes file damaged,
      bit 3: tamper counters unreadable). Bit 4: sync in progress. Bit 5:
      snapshot unsettled.
   :tamper: Tamper counters. Their sum must not rise within a boot (check 3).
      Empty when unreadable.
   :tree_id: The upatch tree the node follows. NULL means no tree, and checks 4–7
      are skipped.
   :generation: Publication generation of the tree the node has seen.
   :base_seq: The record's window starts after this operation seq (exclusive).
   :last_seq: Last operation the node has applied (inclusive end of the window).
   :base_root: Hash-chain root at base_seq, 64 hex digits.
   :projection_root: Hash-chain root after last_seq. Check 4 refolds the tree to reproduce
      it.
   :mask: Base64, two bits per operation in the window: 1 applied, 2 selector
      did not match, 3 attach module not loaded, 0 not reached. Decoded by
      mask_code().
   :set_sha256: Hash of the upatch set the node has loaded. Check 6 recomputes it.
   :count: Number of upatches loaded. Shown as loaded in node_status.
   :not_ok: Reported by the node and stored. No check reads it.

shirudo.boot_first
------------------

.. clickhouse-table:: shirudo.boot_first
   :kind: store
   :ttl: The default of ``boot_first_retention_seconds`` in :table:`settings`,
      set by :src:`tools/backend/sql/apply-retention.sh`
   :row-size: ~150 B (estimate).
   :scale: Nodes × boots with a record in the last 30 days, plus each node's
      current boot, which is kept indefinitely.
   :reference: ~3 boots each: 30k rows ≈ 5 MB
   :bytes: 5e+06

   Per node and boot, the tamper total of the first record that could read
   the counters. Check 3 fails if the current total is higher.

   - A record with empty tamper does not set the baseline (argMinStateIf …
     notEmpty(tamper)).
   - A TTL drops a row from its part regardless of newer parts. Without the
     hourly rewrite, a boot longer than the retention would lose its oldest
     row and its baseline would move later, hiding a rise.
     docs/boot-baselines.md explains it.

   :ak_name: Node.
   :boot_id: Boot.
   :first_order_key: order_key of the boot's first record.
   :tamper_first: arraySum(tamper) at the lowest order_key with readable counters. Read
      with argMinMerge.
   :newest_received: When the boot's record with the highest order_key was first
      received. Check 2 reads the age of a node's newest record here, so that a
      copy of it sent again does not make it fresh. Read with argMaxMerge.
   :last_used: Last record received for the boot, or last time the hourly job found
      it to be the node's current boot.
