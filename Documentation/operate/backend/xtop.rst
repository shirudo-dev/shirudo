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
and shows one row per upatch, or, with
:src:`tools/xtop/sql/shields-available.sql` over
``shirudo.shield_catalog``, one per shield available to append; SBOM sends :src:`tools/xtop/sql/sbom.sql`,
over ``shirudo.node_vulns``, and shows one row per finding, or, with
:src:`tools/xtop/sql/sbom-images.sql` over ``shirudo.sbom_images``, one
per image. Every query is sent with ``readonly=1``, or without it to a user whose profile is read-only at another level and may not set it, and it changes nothing unless it is given the operator's keys to create a tree with. It is a `Bun <https://bun.sh>`_ program built on
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

``/`` searches a table; each view below says which fields. The search is
terms separated by blanks, all of which a row must meet. A term is a
regular expression, of JavaScript's syntax and ignoring case, that one of
the fields must match; after a leading ``!``, none may. A term that is
no regular expression is matched as text, and the search line says so.
In SBOM, ``!^linux`` leaves out the findings of the packages whose names
start with ``linux``, and ``high !^linux`` keeps the high ones of the
rest. Enter keeps the search, Esc clears it.

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
       behind it, ``#<last>`` when the head of its tree is not known,
       ``no tree`` when it follows none.
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
tree the member furthest behind, or one whose head is not known when
none is behind, its shields the sums over its members, and its exposure
that of its most exposed member. Enter on an image shows its nodes.

Detector hits are not shown: the collector of
:src:`tools/backend/otelcol.yaml` takes in no map snapshot metrics.

Read the shields
----------------

Shields has two tabs: ``in trees``, the upatches the trees carry, and
``available``, the shields published to a registry that a tree can take.
``t`` switches between them, as does ``k`` past the header to the tabs,
``h`` or ``l`` and Enter. The tab stays chosen while xtop runs.

In trees
~~~~~~~~

``in trees`` has one row per upatch of every tree the tree ingest job
loaded (:doc:`tree-ingest`), from its newest operation in
``shirudo.tree_ops``.

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

``c`` creates a tree. Type the tree's repository, a path under the
registry of the shields such as ``shirudo/fleet-base``, and Enter; then
``j`` and ``k`` move over the available shields and Space picks one, in
the order the tree is to take them. ``n`` returns to the repository, Esc
to the table. Below the shields are the commands that create it: one
``bpm tree append`` per shield picked and the :doc:`tree-ingest` that
loads the tree into the backend. The tree's id is the last name of the
repository:

.. code-block:: none

   $ shirudo bpm tree append oci://<registry>/<namespace>/<package>:<version> --package-digest sha256:<digest> oci://<registry>/shirudo/fleet-base --tree-id fleet-base --keys-dir <keys>
   $ tools/backend/jobs/tree-ingest --cert <keys>/cert.der oci://<registry>/shirudo/fleet-base

Without ``XTOP_KEYS_DIR`` xtop only shows them, with the keys directory
left to fill in, and stays a program that reads. With it, ``x`` runs
them in order, without a shell and with xtop's environment, which is
where ``bpm tree append`` and ``tree-ingest`` take their registry's CA
and their ClickHouse client from. Each command shows ``✓`` and its last
line, or ``✗`` and what it printed, and a failure stops the ones after
it; ``x`` again runs from the command that failed. Once all have
succeeded xtop returns to the table, which then lists the tree. xtop then signs with
the operator's key: set the variable only on the operator's host.

.. list-table::
   :header-rows: 1

   * - Variable
     - Value
   * - ``XTOP_KEYS_DIR``
     - The operator's keys directory, with ``signing_key.pem`` and
       ``cert.der``. Unset, xtop runs nothing.
   * - ``SHIRUDO``
     - The ``shirudo`` to run. Default ``shirudo``.
   * - ``XTOP_TREE_INGEST``
     - The tree ingest job. Default ``tools/backend/jobs/tree-ingest``,
       from the directory xtop runs in.

``make xtop`` sets all three, and the stack's CA and ClickHouse client,
once ``make vm`` has made a bundle with operator keys.

Available
~~~~~~~~~

``available`` has one row per shield of ``shirudo.shield_catalog``, at
the version put last, which :src:`tools/put-shields` writes and
:src:`tools/backend/jobs/shields-put` loads. It lists the shields
before any tree takes them, so that you can choose which to append.

.. list-table::
   :header-rows: 1

   * - Column
     - Value
   * - ``SEVERITY``
     - The worst severity of the advisories in the shield's ``fixes``,
       as ``kernel_vulns`` or ``sbom_vulns`` give it; ``—`` when neither
       knows them.
   * - ``SHIELD``
     - The id of its ``[upatches.tree]`` entry, which a tree operation
       takes.
   * - ``FIXES``
     - The first advisory it fixes, and ``+N`` for the others.
   * - ``TARGET``
     - What those advisories are in: ``kernel``, or the packages of an
       image's SBOM.
   * - ``EXPOSED``
     - The most nodes one of those advisories leaves exposed in
       ``node_vulns`` now, whatever shields them later. A node exposed
       to two of them counts once.
   * - ``VERSION``
     - The version of its package put last.
   * - ``IN TREES``
     - The trees whose newest operation of the shield is an ``add``;
       ``—`` when no tree carries it.
   * - ``PUT``
     - How long ago that version was put.

The table sorts by severity, then by the nodes exposed and the id. Enter
on a shield shows its description, its package and version, the
reference and manifest digest ``bpm tree append`` takes it by, its
selector, when it was put and how many versions were, the trees that
carry it, each advisory with its severity and the nodes it exposes, and
the command that appends it, with the tree left to fill in:

.. code-block:: none

   shirudo bpm tree append oci://<registry>/<namespace>/<package>:<version> --package-digest sha256:<digest> oci://<registry>/<tree> --tree-id <tree-id>

``/`` searches the id, package, version, reference, selector,
description, advisories, severities, packages and trees. With no row in
``shirudo.shield_catalog`` the tab says to run ``make shields`` on the
local stack (:ref:`local-dev-stack`), or :src:`tools/put-shields` with
``--catalog`` and then ``shields-put``.

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
version, the binding of its image to an SBOM and its status. ``/``
searches the advisory, package, severity, source, shield, status, the
installed versions, and the names and images of the nodes it affects.

``t`` switches to the images: every image of ``sbom_images`` at its
newest scan, with its state (:doc:`sbom-scan`), ``stale`` when that scan
is older than ``sbom_stale_seconds``, the nodes that run it, its
findings with how many are critical and high, how long ago it was
scanned and the version of the matcher's database. An image a node runs
that has no SBOM in the store reads ``no_sbom``: store one with
:doc:`sbom-put`. So does a build a node runs whose root the store does
not have for that id and version, on a row of its own with that root:
``node_vulns`` binds such a node ``root_mismatch``. Enter on an image
shows its findings.
