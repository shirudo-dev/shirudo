..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

Ingest
======

The collector writes into otel.otel_logs. checked_mv verifies each record's
TPM quote once, and the result is routed either to the audit store or to the
reject log. Neither otel_logs nor checked keeps a row.

Schema: :src:`tools/backend/sql/10-ingest.sql`

Views, functions and jobs
-------------------------

``shirudo.checked_mv``
   materialized view, on insert.

   Splits the quote with a regex, calls tpm_quote_check(attest, sig, ak,
   sha256(body)) once per record and writes the parsed JSON answer to
   checked.

``shirudo.keepalive_mv``
   materialized view, on insert.

   checked → keepalive for accepted rows.

``shirudo.rejected_mv``
   materialized view, on insert.

   checked → rejected for refused rows, with reject as reason.

``tpm_quote_check()``
   executable_pool UDF, clickhouse/tpm_quote_check_function.xml.

   Runs shirudo-quote-check (pool of 4). Returns one JSON line: ok, reason,
   ak_name, ak_public, reset_count, clock.

otel.otel_logs
--------------

.. clickhouse-table:: otel.otel_logs
   :kind: null
   :written-by: otelcol-contrib, configured by :src:`tools/backend/otelcol.yaml`
   :row-size: 0 B stored. About 2 KB per record on the wire (body ~0.9 KB plus
      quote).
   :scale: Nodes × 1 record per minute, passing through: 10,000 nodes ≈ 170
      inserts/s.
   :reference: 0 B
   :bytes: 0

   Landing table for the OpenTelemetry Collector's ClickHouse exporter. It
   holds nothing; it exists so the exporter has a target and checked_mv has
   a source.

   - The columns match what the exporter inserts. Only Timestamp,
     ResourceAttributes['host.name'], LogAttributes['shirudo.quote'], Body
     and EventName are used.
   - Log records with any other event name are dropped.

   :Timestamp: Becomes checked.time.
   :TraceId, SpanId, TraceFlags: OTLP trace context. Unused.
   :SeverityText, SeverityNumber: Unused.
   :ServiceName: Unused.
   :Body: The keepalive body: a compact JSON string that the quote signs.
   :ResourceSchemaUrl, ScopeSchemaUrl, ScopeName, ScopeVersion: Unused.
   :ResourceAttributes: host.name is taken from here.
   :ScopeAttributes: Unused.
   :LogAttributes: shirudo.quote: attest=…;sig=…;ak=… (base64 TPM structures).
   :EventName: Must be shirudo.keepalive.

shirudo.checked
---------------

.. clickhouse-table:: shirudo.checked
   :kind: null
   :written-by: tests, which insert here directly
   :row-size: 0 B stored.
   :scale: Same rate as otel_logs. Each row costs one tpm_quote_check call (pool
      of 4 processes).
   :reference: 0 B
   :bytes: 0

   One row per keepalive, accepted or not, with the checker's answer and
   every body field split into its own column. The body fields and
   order_key/reject are DEFAULT expressions, so a test can insert just the
   first eleven columns and get the same row a real record would.

   - order_key = reset_count << 40 \| clock. That leaves 24 bits for
     reset_count and 40 for clock; a record outside that range is rejected
     as clock_range.
   - reject is computed in order: checker failure (bad_signature,
     body_mismatch, malformed), then schema, then clock_range. Empty means
     accepted.

   :received: When the backend received the record. Freshness (check 2) and
      retention count from it.
   :time: The OTLP Timestamp the target put on the log record. Not trusted for
      ordering.
   :host_name: host.name resource attribute: what the node claims to be called. Not
      an identity.
   :quote: The shirudo.quote attribute as sent.
   :body: The JSON body as sent.
   :ok: 1 when tpm_quote_check accepted the quote.
   :reason: The checker's reason on failure.
   :ak_name: Attestation key name, from the checker.
   :ak_public: Public area of the attestation key, from the checker. Goes only to
      nodes.
   :reset_count: TPM reset counter from the quote.
   :clock: TPM clock from the quote.
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
   :order_key: reset_count << 40 \| clock. The TPM's own ordering, never a wall
      clock.
   :reject: Empty if accepted, else malformed, bad_signature, body_mismatch,
      schema or clock_range.

shirudo.keepalive
-----------------

.. clickhouse-table:: shirudo.keepalive
   :kind: store
   :queried-by: audit and ad-hoc queries only
   :ttl: The default of ``keepalive_retention_seconds`` in :table:`settings`;
      :src:`tools/backend/sql/apply-retention.sh` rewrites it from the setting
   :row-size: ~200 B per record compressed (README).
   :scale: Nodes × 1,440 records per day × retention. 30 days of retention is
      432M rows ≈ 86 GB.
   :reference: 600k rows ≈ 120 MB at the default 1 hour
   :bytes: 1.2e+08

   Every accepted record with its quote and body, kept for audit. No check
   reads this table.

   - A record sent twice has the same key and collapses into one row on
     merge.
   - quote and body are ZSTD-compressed.

   :received: When the backend received the record. Freshness (check 2) and
      retention count from it.
   :time: The OTLP Timestamp the target put on the log record. Not trusted for
      ordering.
   :host_name: host.name resource attribute: what the node claims to be called. Not
      an identity.
   :quote: The signed quote, ZSTD(1).
   :body: The signed body, ZSTD(1).
   :ak_name: Name of the TPM attestation key. This is the node's identity
      everywhere in the schema.
   :reset_count: TPM reset counter from the quote. First half of the ordering.
   :clock: TPM clock from the quote. Second half of the ordering.
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

shirudo.rejected
----------------

.. clickhouse-table:: shirudo.rejected
   :kind: store
   :row-size: ~1 KB (estimate: raw quote and body, sorted by time so little
      cross-row compression).
   :scale: Refused records × 7 days. Near zero normally; one bad node at 1 per
      minute adds ~10,000 rows a week.
   :reference: ≈ 10 MB per misbehaving node
   :bytes: 1e+07

   Every refused record and why. Check 1 counts a node's rejections in the
   last hour.

   :received: When it arrived.
   :reason: malformed: quote missing or unparseable. bad_signature: does not
      verify or wrong signer. body_mismatch: quote is over a different body.
      schema: unknown major version. clock_range: counters too large for
      order_key.
   :host_name: Claimed host name.
   :ak_name: Key name, when the checker got far enough to read one.
   :reset_count: From the quote, if parsed.
   :clock: From the quote, if parsed.
   :quote: As sent, ZSTD(1).
   :body: As sent, ZSTD(1).
