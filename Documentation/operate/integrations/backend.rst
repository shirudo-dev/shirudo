..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: Operators, SecOps

Backend
=======

The other pages of this section store what targets send and alert on
it. The backend goes further: it checks every keepalive's TPM quote and
compares what each target reports with the upatch tree it follows. It
lives in :src:`tools/backend/`: an OpenTelemetry Collector
configuration, a ClickHouse schema, the jobs that load trees and SBOMs,
and their tests. It also serves as the end-to-end tester of shirudo
itself, at the scale of many nodes and many upatches.

This is a do-it-yourself example, not an integration shirudo
maintains. shirudo holds no fleet state: a target only sends its
keepalive to the collector it is configured with, and nothing on the
target depends on the backend. Start from it and adapt retention,
access control and sizing to your deployment.

What it does
------------

- An OpenTelemetry Collector configuration that writes every keepalive
  to ClickHouse, where a materialized view checks its quote with
  ``shirudo-quote-check``, installed as the ClickHouse function
  ``tpm_quote_check``, and keeps the record or the reason it was
  refused. A node is known by the name of its attestation key, never by
  the host name it claims, and its records are ordered by the quote's
  clock.
- A tree ingest job that loads every publication of an upatch tree
  through ``shirudo bpm tree show``, which verifies it as a target does,
  and the ``fixes`` its operations carry.
- A table, ``node_status``, refreshed every minute, that says for every
  node whether it is healthy, unhealthy or stale, with one line per
  check: the record is fresh, the target reports no problem, its mask
  and roots match the tree, it is at the head of the tree or still
  within the time a rollout may take, the upatches it has loaded are
  those the tree leaves, and its outcomes are the most common among
  nodes in the same place in the tree.
- A table, ``node_vulns``, refreshed every five minutes, that says
  which advisories affect each node's image and kernel and whether a
  published upatch shields it.

``shirudo-quote-check`` and ``shirudo bpm tree show`` come with the
operator package, :doc:`/reference/cli/quote-check` and
:doc:`/reference/cli/bpm` describe them. A pass of the quote check says
that the body is what one key signed, not that the key lives in a
genuine TPM, so every node reads ``untrusted``, nor that the body is
true: root on a target can have its TPM quote a body of its own, so
``healthy`` is the target's own account until ``shirudo attest verify``
confirms it (R17 of :doc:`/security/threat-model`).

A silent node
-------------

A node turns stale when its newest keepalive is older than the
backend's ``stale_seconds``, 10 minutes by default. A keepalive cannot
run while a ``bpm tree sync`` holds the config operation lock, so a sync
of several minutes leaves a gap of that length, as
:doc:`/operate/run/telemetry` explains; the alerts for a silent target on
the other pages of this section use the same 10 minutes. Tune the value
to the longest sync your fleet runs.

The end-to-end test ``t9107`` runs the backend against the example
keepalives of :src:`testing/fixtures/keepalive/` and their recorded
quotes, through its collector, its quote check and its tree ingest job.

What a keepalive is
-------------------

Once a minute ``shirudo status --otel`` sends one OTLP log record with
the event name ``shirudo.keepalive``. Its body is a compact JSON object,
sent as a string, and its only attribute, ``shirudo.quote``, is a TPM
quote over the SHA-256 of that string:

.. code-block:: none

   attest=<base64 TPMS_ATTEST>;sig=<base64 TPMT_SIGNATURE>;ak=<base64 TPMT_PUBLIC>

A node is known by the name of its attestation key, ``ak_name``, never
by the host name it claims, and its records are ordered by the quote's
``reset_count`` and ``clock``, never by a wall clock.

How a record flows
------------------

The collector writes every record into a table that stores nothing,
and a materialized view checks its quote on the way in:

.. code-block:: none

   target --OTLP/HTTPS--> otelcol-contrib --> otel.otel_logs (Null)
                                                 | checked_mv, one tpm_quote_check call per record
                                                 v
                                           shirudo.checked (Null)
                 accepted                        |                 refused
      +------------+---------------+-------------+                    |
      v            v               v             v                    v
   keepalive     nodes     keepalive_latest   boot_first          rejected

Neither ``otel.otel_logs`` nor ``shirudo.checked`` stores anything. A
record is stored once it is checked, in ``shirudo.keepalive``, or with
the reason it was refused, in ``shirudo.rejected``. Log records of any
other event name are dropped.

Once a minute ``shirudo.node_ops_mv`` adds to ``shirudo.node_ops`` what
each node's newest record says it did at operations the backend had not
seen it reach, ``shirudo.history_contradictions_mv`` marks each node
whose newest record contradicts that history, and
``shirudo.node_status_mv`` runs the checks over ``keepalive_latest``,
``boot_first`` and that history for every node and replaces the rows of
``shirudo.node_status``, which is what a UI reads
(:doc:`backend/status`). Every five minutes ``shirudo.node_vulns_mv``
does the same for ``shirudo.node_vulns`` (:doc:`backend/exposure`).

Files
-----

.. list-table::
   :header-rows: 1

   * - Path
     - Purpose
   * - :src:`tools/backend/otelcol.yaml`
     - Collector configuration: OTLP over HTTPS in, ``otel.otel_logs``
       out.
   * - :src:`tools/backend/clickhouse/tpm_quote_check_function.xml`
     - Declares the ``tpm_quote_check`` function over the
       ``shirudo-quote-check`` program.
   * - :src:`tools/backend/sql/`
     - The schema, loaded in the order of the file names, and
       ``apply-retention.sh``, which sets how long ``shirudo.keepalive``
       keeps a record and ``shirudo.boot_first`` a boot.
   * - :src:`tools/backend/jobs/tree-ingest`
     - Loads every segment of an upatch tree into the reference tables.
   * - :src:`tools/backend/jobs/sbom-scan`
     - Scans the SBOM of every image in the SBOM store and loads the
       outcome into ``sbom_images`` and ``sbom_vulns``.
   * - :src:`tools/backend/test/`
     - The SQL tests and their runner, ``test/run.sh``
       (:ref:`testing-backend`).

.. toctree::
   :titlesonly:

   backend/set-up
   backend/status
   backend/exposure
   backend/tree-ingest
   backend/sbom-scan
   backend/maintain
   backend/boot-baselines
   backend/tables/index
