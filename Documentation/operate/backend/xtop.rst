..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators, SecOps

Watch nodes, shields and SBOMs with xtop
========================================

:src:`tools/xtop/` is a terminal view of the backend. It reads the
backend's ClickHouse over its HTTP interface, one query per view: Nodes
sends :src:`tools/xtop/sql/nodes.sql`, over ``shirudo.node_status``,
``shirudo.latest`` and ``shirudo.node_vulns``, and shows one row per
node, or one per image; Shields sends :src:`tools/xtop/sql/shields.sql`,
over the tree tables, ``shirudo.node_ops`` and ``shirudo.node_vulns``,
and shows one row per upatch; SBOM sends :src:`tools/xtop/sql/sbom.sql`,
over ``shirudo.node_vulns``, and shows one row per finding, or, with
:src:`tools/xtop/sql/sbom-images.sql` over ``shirudo.sbom_images``, one
per image. It only reads: every query is sent with ``readonly=1``. It is a `Bun <https://bun.sh>`_ program built on
Ink and React, and runs on an operator's host, never on a target.

Build and run
-------------

1. Install Bun 1.4.4 or later.
2. Build the executable, which embeds the query:

   .. code-block:: console

      $ make -C tools/xtop

3. Point it at the HTTP interface, port 8123 unless the server is set up
   otherwise, and run it:

   .. code-block:: console

      $ CLICKHOUSE_URL=https://clickhouse.example.com:8443/ CLICKHOUSE_USER=xtop \
        CLICKHOUSE_PASSWORD=... tools/xtop/dist/xtop

``bun run src/index.tsx`` in :src:`tools/xtop/` runs it without
building. Against the local development stack, whose ClickHouse holds
the backend once ``make quote-check`` has built the checker, the URL is
``http://127.0.0.1:18124/``, which ``make xtop`` from the checkout root
sets (:ref:`local-dev-stack`). A user that can only ``SELECT`` from the ``shirudo`` database
is enough.

.. list-table::
   :header-rows: 1

   * - Variable
     - Value
   * - ``CLICKHOUSE_URL``
     - The HTTP interface, ``http`` or ``https``. Default
       ``http://127.0.0.1:8123/``. A URL that carries a user or a
       password is refused, so that they never show in the process list.
   * - ``CLICKHOUSE_USER``, ``CLICKHOUSE_PASSWORD``
     - The ClickHouse user and its password, sent in the
       ``X-ClickHouse-User`` and ``X-ClickHouse-Key`` headers. Without
       them the server's default user answers.

A view queries when it opens, every minute after that, as often as
``node_status_mv`` recomputes its table, and when you press ``r``. A
query that fails leaves the rows of the last one in place and says why
at the start of the summary line.

Read the nodes
--------------

``STATUS`` and ``TRUST`` are the columns of ``node_status`` that
:doc:`status` describes, shown side by side as that page asks: a healthy
node is one whose records match its tree, an enrolled one is one whose
key the operator has recorded as a TPM's.

.. list-table::
   :header-rows: 1

   * - Column
     - Value
   * - ``STATUS``
     - ``unhealthy``, ``stale`` or ``healthy``, worst first.
   * - ``TRUST``
     - ``untrusted`` or ``enrolled``.
   * - ``NODE``
     - ``node_id``.
   * - ``LABELS``
     - The labels from ``shirudo.node_labels``, as ``key=value`` in key
       order: what :doc:`labels-put` loaded, not the node's own
       ``node.labels``; ``—`` when none was put. ``!N`` before them
       counts the keys whose sets disagree, from
       ``shirudo.label_conflicts``.
   * - ``CHECK``
     - The first check that failed, as its line names it, for example
       ``3 reported``; ``—`` when all passed.
   * - ``IMAGE``, ``KERNEL``, ``BUILD``
     - ``image_id`` and ``image_version``, ``kernel_release`` and the
       first eight digits of ``version_id`` from the node's newest
       record. ``—`` for a node that reports no image.
   * - ``TREE``
     - ``✓ #<head>`` at the head of its tree, ``#<last>/#<head>``
       behind it, ``no tree`` when it follows none.
   * - ``SHIELDS``
     - From ``node_vulns``, counted by upatch: ``✓`` loaded and
       shielding (``shielded``), ``…`` coming (``shield_pending``),
       ``✗`` published but doing nothing on the node
       (``shield_module_absent``, ``shield_excludes_node``,
       ``shield_withdrawn``).
   * - ``EXPOSED``
     - From ``node_vulns``, the advisories no loaded upatch shields: those
       ``exposed_no_shield`` and those of the ``✗`` shields. A ``?``
       before it says the node has a finding ``unknown``, see
       :doc:`exposure`.
   * - ``SEEN``
     - How long ago the newest record was received.

The summary line gives the health of the nodes shown: the percent of
them ``healthy``, so 100% when every node is healthy and 0% when none
is. A stale node counts against it like an unhealthy one.

Enter on a node shows its host name, key, the builder that enrolled the
key, when, and the endorsement key's name it gave, from
``shirudo.enrollments`` (:doc:`enroll-put`), or ``by hand`` for a key
enrolled without one, labels with the name each was
put under, ``ak_name``, ``node_id`` or ``config_root``, a line per
conflict with the values it overrode, what its record says it runs, and
the seven lines of its ``log``, a failed one in red; Esc returns. ``/``
searches the node, host and key names, status, trust, image, kernel,
build, the line of the failed check and each label as ``key=value``, so
``role=edge`` finds the nodes of that role, and ``label conflict`` finds
the nodes with one.

``t`` switches to one row per image id and version, with the ``role``
labels of its members beside it, ``?`` for a member without one. A
group's status is its worst member's, its health the percent of its
members ``healthy``, its kernel ``mixed`` when its members differ, its
tree the member furthest behind, its shields the sums over its members,
and its exposure that of its most exposed member. Enter on an image
shows its nodes.

Detector hits are not shown: the collector of
:src:`tools/backend/otelcol.yaml` takes in no map snapshot metrics.

Read the shields
----------------

Shields has one row per upatch of every tree the tree ingest job loaded
(:doc:`tree-ingest`), from its newest operation in ``shirudo.tree_ops``.

.. list-table::
   :header-rows: 1

   * - Column
     - Value
   * - ``STATUS``
     - ``pending`` while a node following the tree has not reached the
       newest operation, ``deployed`` once every one has, ``withdrawn``
       when that operation is a ``delete``.
   * - ``SHIELD``
     - The upatch id and the first eight digits of the manifest digest
       of its newest operation.
   * - ``SEVERITY``
     - The worst severity of the advisories in ``upatch_fixes`` for its
       newest ``add``, as ``kernel_vulns`` or ``sbom_vulns`` give it;
       ``—`` when neither knows them.
   * - ``TARGET``
     - What those advisories are in: ``kernel``, or the packages of an
       image's SBOM.
   * - ``IMAGES``
     - The first image, as id and version, of a node an advisory affects
       in ``node_vulns``, and ``+N`` for the others.
   * - ``ROLLOUT``
     - From the history of each node following the tree in ``node_ops``:
       the nodes that applied the newest operation over those it can
       apply on, all but the nodes its selector left out; ``…`` the nodes
       that have not reached it, ``✗`` those it reached whose module is
       not loaded.
   * - ``TREE``
     - The ``seq`` of the newest operation.

Enter on a shield shows its tree, its newest operation and how many it
has, when the backend loaded that operation's publication, the
repository, manifest digest and selector, the rollout in full, the
images, and per advisory its severity and how many affected nodes the
upatch shields. ``/`` searches the id, tree, status, severity, digest,
repository, advisories, packages and images.

The rollout counts the nodes whose newest record names the tree; a node
that moved to another tree leaves it. Detector hits are not shown,
because the backend takes in no metrics.

Read the SBOM findings
----------------------

SBOM has one row per finding, an advisory in a package, that
``node_vulns`` has on any node: from the SBOM of a node's image, as
:doc:`sbom-scan` matched it, or from ``kernel_vulns`` by the node's
kernel release (:doc:`exposure`).

.. list-table::
   :header-rows: 1

   * - Column
     - Value
   * - ``SEVERITY``, ``VULNERABILITY``
     - The advisory and its severity.
   * - ``PACKAGE``
     - ``kernel``, or the package of the SBOM, and the versions the
       nodes have installed.
   * - ``FIXED IN``
     - The first version without it; ``none yet`` when there is none.
   * - ``NODES``
     - The nodes it affects, of all the nodes in ``node_status``.
   * - ``SHIELD``
     - The upatch linked to the advisory, ``—`` when none is.
   * - ``STATUS``
     - ``no shield`` when no upatch is linked; ``shielded`` when it
       shields every affected node; ``pending`` while it is still
       coming to one; ``partial`` when it leaves some out, because the
       selector does, the module it attaches to is not loaded or it was
       withdrawn. The nodes it shields of those affected follow.

The summary line says when the findings come from a scan older than
``sbom_stale_seconds``. Enter on a finding shows its package, source and
shield, and every node it affects with its exposure, image, installed
version, the binding of its image to an SBOM and its status.

``t`` switches to the images: every image of ``sbom_images`` at its
newest scan, with its state (:doc:`sbom-scan`), ``stale`` when that scan
is older than ``sbom_stale_seconds``, the nodes that run it, its
findings with how many are critical and high, how long ago it was
scanned and the version of the matcher's database. An image a node runs
that has no SBOM in the store reads ``no_sbom``: store one with
:doc:`sbom-put`. Enter on an image shows its findings.
