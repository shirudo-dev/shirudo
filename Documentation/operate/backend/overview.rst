..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

Overview
========

How the tables connect and what they cost.

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

How a keepalive moves through the schema
----------------------------------------

A keepalive sent from Shirudo enters the backend at :table:`otel.otel_logs`, is checked once on its way
into :table:`checked`, and from there fans out on insert to
:table:`keepalive`, :table:`rejected`, :table:`nodes`,
:table:`keepalive_latest` and :table:`boot_first`. Refreshed views then
build :table:`node_ops`, :table:`history_contradictions` and
:table:`node_status` every minute and :table:`node_vulns` every five.
Each box links to its table.

.. clickhouse-flow::
   :alt: Data flow from otel_logs through checked into keepalive,
      rejected, nodes, keepalive_latest and boot_first, then into
      node_ops, node_sets, history_contradictions, node_status and
      node_vulns

   box  otel     10  30 140 otel.otel_logs | otel_logs
   box  checked 240  30 130 checked
   box  rej     240 130 130 rejected
   box  ka      420  10 150 keepalive
   box  nodes   420  70 150 nodes
   box  latest  420 130 150 keepalive_latest
   box  boot    420 190 150 boot_first
   box  tree     10 250 150 tree_pubs tree_ops
   box  ops     420 270 150 node_ops
   box  sets    420 330 150 node_sets
   box  status  640 160 150 node_status
   box  contra  610 240 180 history_contradictions
   box  sbom    640 330 150 sbom_images sbom_vulns kernel_vulns | sbom_* / kernel_vulns
   box  vulns   840 250 150 node_vulns
   edge otel    r checked l quote check
   edge checked b rej     t refused
   edge checked r ka      l
   edge checked r nodes   l
   edge checked r latest  l accepted
   edge checked r boot    l
   edge latest  b ops     t
   edge tree    r ops     l 1 min
   edge ops     b sets    t
   edge latest  r status  l 1 min
   edge boot    r status  l
   edge ops     r status  l
   edge rej     r status  l
   edge sets    r status  l
   edge ops     r contra  l
   edge contra  t status  b
   edge status  r vulns   l 5 min
   edge sbom    r vulns   l

Where the bytes go
------------------

At a reference fleet of 10,000 nodes sending one keepalive a minute,
following one tree of 65,000 operations, with 50 SBOMs of 500 findings
each. :table:`keepalive` is counted at its default retention of one
hour; it grows by about 2.9 GB a day of retention at this fleet.

.. clickhouse-sizes::

.. admonition:: TODO

   :table:`node_ops` grows unbounded with the number of tree operations.
   The figure above is for 65,000.
