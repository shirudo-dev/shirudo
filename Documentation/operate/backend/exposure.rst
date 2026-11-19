..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators, SecOps

Exposure
========

Which nodes run a vulnerable package or kernel, and whether a upatch
shields them. A node carries no scanner and sends no package list: its
keepalive names the image it booted (``image_id``, ``image_version``,
``image_root``) and the kernel it runs (``kernel_release``), and the
backend knows the rest. In :src:`tools/backend/sql/50-vulns.sql`:

.. list-table::
   :header-rows: 1

   * - Object
     - Engine
     - Holds
   * - ``shirudo.sbom_images``
     - ReplacingMergeTree by ``scanned_at``, ``ORDER BY (image_id, image_version, image_root)``
     - One row per image whose SBOM the scan job found, with the ``state`` of its last scan.
   * - ``shirudo.sbom_vulns``
     - MergeTree, ``ORDER BY (sbom_sha256, vuln_id, package)``, 7-day TTL
     - The findings of every scan of an SBOM.
   * - ``shirudo.kernel_vulns``
     - ReplacingMergeTree, ``ORDER BY (vuln_id, introduced)``
     - Kernel advisories, one row per affected range of releases.
   * - ``kver(release)``
     - function
     - The numbers a kernel release starts with, as an array.
   * - ``shirudo.node_vulns``
     - MergeTree, ``ORDER BY (node_id, ak_name, vuln_id, package)``
     - One row per node and finding: what a UI reads.
   * - ``shirudo.node_vulns_mv``
     - refreshable materialized view, every five minutes
     - Computes the rows for all nodes and replaces those of ``node_vulns`` in one step.

``shirudo.upatch_fixes``, which links an operation's upatch to the
advisories it shields against, is among the reference tables
(:doc:`tables/reference`).

Inputs
------

:src:`tools/backend/jobs/sbom-scan` writes ``sbom_images`` and
``sbom_vulns`` from the SBOM store, see :doc:`sbom-scan`, which an image
pipeline fills itself or with :doc:`sbom-put`. Nothing in the backend fills
``kernel_vulns``: the operator writes it.

``shirudo.sbom_images``:

.. list-table::
   :header-rows: 1

   * - Column
     - Value
   * - ``image_id``, ``image_version``
     - The image, as its build and the keepalive name it.
   * - ``image_root``
     - Its dm-verity root, 64 hex digits; empty for an image built without verity. A rebuild that keeps the version has another root and is another row.
   * - ``sbom_format``
     - The format the image's ``image.json`` names, ``cyclonedx-json`` when it names none.
   * - ``sbom_sha256``
     - The SHA-256 of the SBOM, which ``sbom_vulns`` is keyed by; empty unless ``state`` is ``ok``.
   * - ``state``
     - ``ok``, or why there are no findings: ``missing``, ``hash_mismatch``, ``parse_error``, ``unsupported_format``.
   * - ``built_at``, ``db_version``, ``scanned_at``
     - When the image was built, and the advisory database and time of the last scan. ``db_version`` is empty unless ``state`` is ``ok``.

``shirudo.sbom_vulns`` has ``sbom_sha256``, ``vuln_id``, ``package``,
``installed``, ``fixed`` (empty while no fixed version exists),
``severity`` and the ``scanned_at`` of the scan the row is from. The
findings of an image are the rows with the ``scanned_at`` its
``sbom_images`` row has, so a new scan replaces the old one's findings
by writing its own, and the TTL removes what no row points to any more.

A scan older than ``sbom_stale_seconds`` of ``shirudo.settings``, two
days by default, is stale: the rows of the nodes on that image say so in
``sbom_stale``, see below. Its findings are still shown, since they are
the newest known, and a node without findings reads ``unknown``, not
``none``, so an image whose scans stopped never reads as clean, also
once the TTL has removed its findings after seven days. Keep the setting
below seven days (604800) and scan more often than it allows; the job
below runs daily.

``shirudo.kernel_vulns`` has ``vuln_id``, ``introduced`` and ``fixed``
as arrays of numbers and ``severity``. A kernel is affected from
``introduced``, inclusive, to ``fixed``, exclusive; an empty ``fixed``
is a range without an end, and an advisory with several ranges has
several rows:

.. code-block:: sql

   INSERT INTO shirudo.kernel_vulns (vuln_id, introduced, fixed, severity) VALUES
   ('EXAMPLE-0101', [7, 0], [7, 4, 5], 'HIGH');

``kver()`` turns the ``kernel_release`` of a keepalive into such an
array: ``kver('7.4.2-shirudo')`` is ``[7, 4, 2]``. Arrays compare
element by element and a prefix sorts before what extends it, so ``[7,
4, 2]`` is at least ``[7, 0]`` and below ``[7, 4, 5]``, and ``[7, 5,
0]`` is not below ``[7, 5]``. A release that starts with no number gives
``[]`` and matches no range; a number of more than 32 bits reads as 0.
The match is on the upstream numbers alone: a distribution kernel that
carries a fix under an older number reads as affected.

Packages of the kernel in an SBOM (``linux-image-*``, ``kernel``,
``kernel-core``) are left out: the SBOM shows the kernel installed in
the image, and the node may run another.

To link a upatch to an advisory by hand, for one published without
``fixes``, add a row with source ``manual`` for the upatch's newest
``add``:

.. code-block:: sql

   INSERT INTO shirudo.upatch_fixes (tree_id, seq, id, advisory, source)
   VALUES ('fleet-base', 3, 'xfs-fix', 'EXAMPLE-0303', 'manual');

A link belongs to an operation, not to a upatch's name: a later ``add``
of the same upatch shields against what its own rows say.

node_vulns
----------

.. list-table::
   :header-rows: 1

   * - Column
     - Value
   * - ``node_id``, ``ak_name``, ``host_name``, ``status``, ``trust``
     - The node, as ``node_status`` has it. A stale node keeps its last known rows, with ``stale`` beside them.
   * - ``image_id``, ``image_version``
     - The image the node's newest record names; empty when it names none.
   * - ``binding``
     - How far the SBOM can be trusted to describe the node, see below.
   * - ``sbom_stale``
     - True when ``binding`` is ``verified``, ``declared`` or ``root_mismatch`` and the newest scan of that SBOM is more than ``sbom_stale_seconds`` old. The same on every row of the node, kernel rows included; false when there is no SBOM to scan.
   * - ``source``
     - ``sbom``, ``kernel``, or ``none`` on the one row of a node without findings.
   * - ``vuln_id``, ``severity``, ``package``, ``installed``, ``fixed``
     - The finding. For a kernel finding ``package`` is ``linux``, ``installed`` the node's ``kernel_release`` and ``fixed`` the end of the range. All empty on the row of a node without findings.
   * - ``exposure``
     - What stands between the node and the vulnerability, see below.
   * - ``upatch_id``
     - The upatch ``exposure`` is read from; empty when no upatch is linked to the advisory.
   * - ``applied_seq``, ``applied_op``
     - Where the node is: the ``seq`` of the newest operation of that upatch the node has applied, which is one at or below its ``last_seq``, and whether it is an ``add`` or a ``delete``. 0 and empty when the node has applied none.
   * - ``next_seq``, ``next_op``
     - Where the tree is: the newest operation of that upatch in the node's tree. When the node is up to date they equal ``applied_seq`` and ``applied_op``; something is coming when ``next_seq`` is above ``applied_seq``.
   * - ``next_shields``
     - Whether the operation ``next_seq`` names is an ``add`` linked to the advisory in ``upatch_fixes``: false when it is a ``delete`` or an ``add`` that drops the link, and false when no upatch is linked. A ``shielded`` row with ``next_shields`` false loses its shield when the node reaches ``next_seq``.
   * - ``shield_link``
     - Where the link to the advisory comes from: ``fixes``, signed by the operator in the publication, ``manual``, a row somebody added here, or ``none``.
   * - ``updated_at``
     - When the row was computed.

A node with nothing found still has one row, so that "clean" differs
from "no data".

``binding``:

.. list-table::
   :header-rows: 1

   * - Value
     - When
   * - ``verified``
     - The node's ``image_root`` equals the SBOM's: the SBOM describes what booted.
   * - ``declared``
     - Matched on ``image_id`` and ``image_version`` only, because the node or the image has no root. Root on the node can edit ``os-release``.
   * - ``root_mismatch``
     - Same id and version, another root: a rebuild that kept its version, or a modified image. The rows are those of the newest build; flag them.
   * - ``no_sbom``
     - The node names an image that has no row in ``sbom_images``, or one whose ``state`` is not ``ok``. Kernel rows still appear.
   * - ``no_image``
     - The node reports no image. Kernel rows still appear.

When several builds share an id and a version, a node gets the one with
its own root, else the newest by ``built_at``.

``exposure`` says what stands between the node and the vulnerability
now. It is read from the newest operation the node has applied of a
upatch linked to the advisory in ``upatch_fixes``, and from the node's
mask, or from its history in ``node_ops`` when that operation is below
the record's window, so that a shield older than the window keeps its
state; what the tree holds beyond the node's ``last_seq`` is in
``next_seq`` and ``next_op``, not here. For each upatch linked to the
advisory, four things decide the value, in the order of the table: the
add the link names, the newest operation of the upatch the node has
applied, what the node did at that add, as its mask or its history
says, and the newest operation of the upatch in the tree.

.. list-table::
   :header-rows: 1
   :widths: 17 15 17 11 18 22

   * - Link on
     - Node applied last
     - Outcome at that add
     - Tree's newest
     - ``exposure``
     - What to do
   * - The add the node applied
     - That ``add``
     - Applied
     - Any
     - ``shielded``
     - Nothing: the upatch is loaded.
   * - The add the node applied
     - That ``add``
     - Attach module not loaded
     - Any
     - ``shield_module_absent``
     - The shield does nothing here until the module it attaches to is
       loaded.
   * - The add the node applied
     - That ``add``
     - Selector did not match
     - Any
     - ``shield_excludes_node``
     - Check the selector: either the node is not affected in a way a
       version cannot show, or the selector is too narrow.
   * - The add the node applied
     - That ``add``
     - Not known: no mask, one that does not cover the add, or an add
       below the window the history has no row for
     - Any
     - ``unknown``
     - Repair the node; such a record fails the status checks, see
       :doc:`status`.
   * - The add the node applied
     - A later ``delete``
     - Not read
     - Any
     - ``shield_withdrawn``
     - Find out why the upatch was deleted and whether its successor is
       on the way, which ``next_op`` ``add`` says.
   * - The tree's newest add only
     - Nothing, or an operation after an add the link does not name
     - Not read
     - ``add``
     - ``shield_pending``
     - Wait for the rollout, unless check 5 calls the node stuck.
   * - The tree's newest add only
     - Nothing, or an operation after an add the link does not name
     - Not read
     - ``delete``
     - ``shield_withdrawn``
     - As above: the node reaches the ``delete`` without ever having had
       the shield.
   * - No upatch, or the node follows no tree
     - Not read
     - Not read
     - Not read
     - ``exposed_no_shield``
     - No known shield: none was published, or none is linked to the
       advisory. A node with the right upatch loaded reads so too when
       nothing links that upatch to the advisory.

``exposed_no_shield`` leaves ``upatch_id`` empty, the two ``seq`` 0, the
two operations empty, ``next_shields`` false and ``shield_link``
``none``. A row without a finding reads ``none``, or ``unknown`` when the
node has no usable SBOM, see ``binding``, or one whose scan is stale,
and no kernel finding.

Of several upatches linked to one advisory the best outcome counts, in
the order ``shielded``, ``shield_pending``, ``shield_module_absent``,
``shield_excludes_node``, ``shield_withdrawn`` and ``unknown``, which is
also the order of the enum; of a ``fixes`` and a ``manual`` link to the
same operation the ``fixes`` one is shown. Sorting the findings by
``exposure`` descending, as the fleet query below does, puts ``unknown``
first, then ``exposed_no_shield`` and ``shield_withdrawn``, ahead of
every outcome of a published shield.

A row does not run ahead of its node. A node that has applied the
``add`` of a upatch whose ``delete`` is published stays ``shielded``
until it applies the ``delete``, with ``next_op`` ``delete`` saying that
it will; a node with an older build loaded is ``shielded`` by that build
while the newer ``add`` is still coming. When that newer ``add`` no
longer carries the advisory, the row reads ``shielded`` with
``next_shields`` false, and turns ``exposed_no_shield`` once the node
applies it.

Which upatches count: one whose newest ``add`` the node has applied, or
whose newest ``add`` in the tree, is linked to the advisory. Only the
first says what is loaded. When just the coming ``add`` is linked, a
newer build that shields against more than the one before, what the node
has applied is no shield against this advisory: the row is
``shield_pending``, or ``shield_withdrawn`` when the tree ends with a
``delete``, while ``applied_seq`` still names what the node applied.
``shield_link`` is the link of the applied ``add`` when it has one, else
of the coming one. A link on an ``add`` the node has left behind does
not count.

The two nodes of the example in :src:`testing/fixtures/keepalive/`, both
on image ``fleet-os`` 2026.11.1 and kernel 7.4.2, and a third installed
by hand, with :src:`tools/backend/test/vulns-fixtures.sql` showing the
same:

.. code-block:: none

   node_id  binding   source  vuln_id       package  installed  fixed    exposure              upatch_id  applied_seq  applied_op  next_seq  next_op
   node-a   verified  kernel  EXAMPLE-0101  linux    7.4.2      7.4.5    shielded              xfs-fix              3  add                3  add
   node-a   verified  sbom    EXAMPLE-0202  openssl  3.5.1-1    3.5.1-2  exposed_no_shield                          0                     0
   node-b   declared  kernel  EXAMPLE-0101  linux    7.4.2      7.4.5    shield_excludes_node  xfs-fix              3  add                3  add
   node-b   declared  sbom    EXAMPLE-0202  openssl  3.5.1-1    3.5.1-2  exposed_no_shield                          0                     0
   node-c   no_image  none                                               unknown                                    0                     0

Node B is the pairing the table is for: it runs the vulnerable kernel, a
shield exists, and the selector that keeps it to edge nodes leaves B
out.

What the refresh costs: it matches the kernel advisories once for each
distinct ``kernel_release`` and reads the operations once for each
distinct ``tree_id``, ``base_seq``, ``last_seq`` and ``mask``, then
joins both to the nodes. For a linked upatch whose newest applied
operation is below the window it reads one row of ``node_ops`` per node.
Like the status refresh it never reads ``shirudo.keepalive``. It takes
``status`` and ``trust`` from ``node_status`` as that table is, so a
node appears here after its first status refresh. To run it at once:

.. code-block:: sql

   SYSTEM REFRESH VIEW shirudo.node_vulns_mv;
   SYSTEM WAIT VIEW shirudo.node_vulns_mv;

What a UI runs
--------------

All from the one table. Nodes are counted by ``ak_name``, since two keys
can claim one ``node_id``.

The fleet, worst first:

.. code-block:: sql

   SELECT vuln_id, severity, exposure, uniq(ak_name) AS nodes
   FROM shirudo.node_vulns
   WHERE vuln_id != ''
   GROUP BY ALL
   ORDER BY severity = 'CRITICAL' DESC, severity = 'HIGH' DESC, exposure DESC, nodes DESC;

One node:

.. code-block:: sql

   SELECT vuln_id, severity, package, installed, fixed, exposure, upatch_id, binding, status
   FROM shirudo.node_vulns
   WHERE node_id = 'node-b';

Shields whose selector leaves nodes out:

.. code-block:: sql

   SELECT upatch_id, vuln_id, groupArray(node_id) AS left_out
   FROM shirudo.node_vulns
   WHERE exposure = 'shield_excludes_node'
   GROUP BY upatch_id, vuln_id;

Coverage, how much is known:

.. code-block:: sql

   SELECT binding, uniq(ak_name) AS nodes
   FROM shirudo.node_vulns
   GROUP BY binding;

Images whose newest scan is stale, and how many nodes run them:

.. code-block:: sql

   SELECT image_id, image_version, uniq(ak_name) AS nodes
   FROM shirudo.node_vulns
   WHERE sbom_stale
   GROUP BY image_id, image_version;

Nodes that are shielded now and about to lose it, because the delete of
their shield is published and they have not applied it yet:

.. code-block:: sql

   SELECT node_id, vuln_id, upatch_id, applied_seq, next_seq
   FROM shirudo.node_vulns
   WHERE exposure = 'shielded' AND next_seq > applied_seq AND next_op = 'delete';
