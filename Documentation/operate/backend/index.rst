..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: Operators, SecOps

Backend
=======

The pages of :doc:`/operate/integrations/index` provides export targets
shirudo can use and alert on. This describes a reference backend: it checks
every keepalive's TPM quote and compares what each target reports with the
upatch tree it follows. It lives in :src:`tools/backend/`: an OpenTelemetry Collector
configuration, a ClickHouse schema, the jobs that load trees and SBOMs,
and their tests. It also provides the end-to-end tester of shirudo itself,
at the scale of many nodes and many upatches. This allows us to validate the
event structure and workflows at scale with a viable backend.

A Shirudo target only sends its keepalive to the collector it is configured
with, and nothing on the target depends on the backend. However, it does
enable testing many nodes and validate resource requirements. Start from it
and adapt retention, access control, sizing and features for your deployment.

What it does
------------

- An OpenTelemetry Collector configuration that writes every keepalive
  to ClickHouse, where a materialized view checks its quote with
  ``shirudo-quote-check``, installed as the ClickHouse function
  ``tpm_quote_check``, and keeps the record or the reason it was
  refused. A node is known by the name of its attestation key, never by
  the host name it claims, and its records are ordered by the quote's
  clock.
- A tree ingest job that loads every publication of a upatch tree
  through ``shirudo bpm tree show``, which verifies it as a target does,
  and the ``fixes`` its operations carry.
- A table, ``node_status``, refreshed every minute, that says for every
  node whether it is healthy, unhealthy or stale, with one line per
  check: the record is fresh, the target reports no problem, its mask
  and roots match the tree, it is at the head of the tree or still
  within the time a rollout may take, the upatches it has loaded are
  from the published tree, and its outcomes match the nodes expected
  results.
- A table, ``node_vulns``, refreshed every five minutes, that says
  which advisories affect each node's image and kernel and whether a
  published upatch shields it. Which can be used to match vulnerabilities
  to nodes using a standard SBOM.

``shirudo-quote-check`` and ``shirudo bpm tree show`` come with the
operator package, :doc:`/reference/cli/quote-check` and
:doc:`/reference/cli/bpm` describe them. A pass of the quote check says
that the body is what one key signed, not that the key lives in a
genuine TPM, so every node reads ``untrusted`` until you enroll its key
(:doc:`maintain`) and insert ``enrolled`` for its ``ak_name``
into ``shirudo.nodes``. Neither says that the body is true: root on a
target can have its TPM quote a body of its own, so
``healthy`` is the target's own account until ``shirudo attest verify``
confirms it (R17 of :doc:`/security/threat-model`).

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
     - Loads every segment of a upatch tree into the reference tables.
   * - :src:`tools/backend/jobs/sbom-scan`
     - Scans the SBOM of every image in the SBOM store and loads the
       outcome into ``sbom_images`` and ``sbom_vulns``.
   * - :src:`tools/backend/test/`
     - The SQL tests and their runner, ``test/run.sh``
       (:ref:`testing-backend`).
   * - :src:`tools/xtop/`
     - A terminal view of the nodes, over ``node_status``,
       ``latest`` and ``node_vulns``, and of the upatches of the trees
       and their rollout (:doc:`xtop`).

.. toctree::
   :titlesonly:

   overview
   set-up
   status
   exposure
   tree-ingest
   sbom-scan
   maintain
   boot-baselines
   xtop
   tables/index
