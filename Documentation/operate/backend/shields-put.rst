..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators

List the shields available to append
====================================

The backend learns which upatches a tree carries from the tree itself
(:doc:`tree-ingest`), but not which shields you have published and could
append. :src:`tools/backend/jobs/shields-put` loads them into
``shirudo.shield_catalog`` (:doc:`tables/reference`), where
:doc:`xtop` lists them as available, with the advisories they fix and the
nodes those leave exposed. It is POSIX shell around
``clickhouse-client``, with :src:`tools/backend/jobs/shields-rows.py` to
read the file, so the host that runs it needs ``python3`` and
``clickhouse-client``.

1. Push the shields and write their catalog with
   :src:`tools/put-shields` (:doc:`/upatches/publish/publishing`):

   .. code-block:: console

      operator$ tools/put-shields --version 1.0.0 --keys-dir <keys-dir> \
          --catalog shields.json oci://<registry>/<namespace>

   The catalog has one entry per ``[upatches.tree]`` entry of a pushed
   package:

   .. code-block:: json

      {"shields": [
        {"id": "cve-2026-63984-rpl-detector",
         "package": "cve-2026-63984-rpl-detector", "version": "1.0.0",
         "reference": "oci://registry.example.com/shields/cve-2026-63984-rpl-detector:1.0.0",
         "manifest_digest": "sha256:65fc…",
         "fixes": ["CVE-2026-63984"],
         "selector": {"architecture": ["x86_64"], "kernel_release_prefix": ["7.2"]},
         "description": "Counts RPL source routing headers whose n + 1 exceeds 127, CVE-2026-63984"}
      ]}

2. Check it, which loads nothing:

   .. code-block:: console

      $ jobs/shields-put --check shields.json

3. Load it:

   .. code-block:: console

      $ jobs/shields-put shields.json
      shields-put: oci://registry.example.com/shields/cve-2026-63984-rpl-detector:1.0.0 cve-2026-63984-rpl-detector (CVE-2026-63984)
      shields-put: loaded shields: 1

``-`` in place of the file reads standard input.

What a put does
---------------

A shield is named by its reference and its ``id``. A put of the same pair
replaces its row, and every other row stays, so each version you push is
kept: xtop shows the newest put of each ``id``, and how many versions it
has. The file is loaded in one insert, whole or not at all.

The job refuses a file, and loads nothing, when it is not the form
above, or when a value is one ``bpm build`` or ``bpm push`` would not
have made: an ``id`` that is not an upatch name, a package name or
version out of their rules (:doc:`/reference/formats/bpm-formats`), a
digest that is not ``sha256:`` and 64 lowercase hex digits, a reference
that is not ``oci://<registry>/<repository>:<version>`` of that package
and version, more than 16 advisories or one out of the ``fixes`` rule
(:doc:`/reference/formats/beefile`), a selector that is not an object, a
description of more than 1024 bytes or with a control character, or one
shield twice.

The catalog is what you say you pushed. The job does not read the
registry: ``bpm tree append`` verifies the package by its digest when you
append it, and the target verifies every upatch it loads.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - Every shield is loaded, or checked with ``--check``.
   * - 1
     - The file is refused or cannot be read, or the load fails.
       Nothing is loaded.
   * - 2
     - Wrong usage.

``CLICKHOUSE_CLIENT`` names the client and its options, split at spaces,
``clickhouse-client`` by default, which reads ``CLICKHOUSE_HOST``,
``CLICKHOUSE_USER`` and ``CLICKHOUSE_PASSWORD`` itself.
