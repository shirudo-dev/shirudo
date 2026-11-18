..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: upatch authors, operators

.. _upatch-tree-format:

upatch tree
===========

A upatch tree is a signed, append-only list of ``add`` and ``delete``
operations in one OCI repository, ``oci://<registry>/<repository>``. The
operator publishes it with ``bpm tree append``, one operation per
``[upatches.tree]`` entry of a package. Every node reads it with ``bpm
tree sync``, walks it in order and applies the operations whose selector
matches. The ``mask`` and ``projection_root`` of the keepalive
(:ref:`keepalive-body-format`) are a node's account of that walk.

CBMC proves the target's readers of the tree publication's selectors and
operations, and the checks that keep a publication from taking a node
back, within the bounds :doc:`/contribute/testing/proof-coverage` lists.
Lean 4 proves that across any history of syncs, stops and reboots a
node's generation, cursor and tree eventlog never go back and each
operation is applied at most once; CBMC shows that ``bpm tree sync``
makes exactly the model's writes.

Overview
--------

A tree lives in its own repository of a registry namespace, beside the
packages and the index of :doc:`bpm-formats`, as Figure 1 shows. Each
publication is one segment of operations, a signed document behind a
manifest. The tag ``<reference>`` names the current segment, and each
segment names the sealed one before it by digest. Each operation pins
the artifact manifest of its ``.upatch`` by digest. The sections below
define the objects and keys: `Registry objects`_, `Publication
document`_, `Operation`_ and `Selector`_.

.. figure:: /images/reference-tree-registry.svg
   :alt: One registry namespace holds a package repository with its
         package manifest and certificate referrer, the bpm-index
         repository whose signed index document pins the package
         manifest and archive by digest, and the tree repository. In the
         tree, the segments tagged segment-1 with seq 1 to 64 and
         segment-2 with seq 65 to 128 and the current one tagged stable
         with seq 129 to 150 each hold a signed document and its
         signature, and each names the one before it by
         base.segment_manifest_digest. The operations pin artifact
         manifests tagged upatch-id-payload16. Superseded generations
         are untagged and may be collected. A node at seq 70 walks back
         from stable to segment-2 by digest and then applies seq 71 to
         128 and 129 to 150, oldest first.

   Figure 1. A tree and its namespace in the registry, with a node at
   seq 70 that is behind.

Digests in the tree carry a ``sha256:`` prefix, as OCI does; the
keepalive leaves it out.

What is signed
--------------

.. list-table::
   :header-rows: 1
   :widths: 24 40 36

   * - Object
     - Protection
     - Checked by
   * - Publication document
     - Detached CMS signature over the exact document bytes.
     - ``bpm tree sync``, against the active config's non-revoked BPF
       signer set.
   * - Artifact manifest and ``.upatch`` layer
     - Not signed. Each signed operation pins them by
       ``manifest_digest``, ``layer_digest`` and ``payload_sha256``.
     - ``bpm tree sync``.
   * - ``.upatch`` file
     - CMS signature, ML-DSA-87, over ``loader_insns || data``.
     - The kernel, at every load and unload.

The detached signature uses the CMS profile of
:doc:`bpm-formats`: DER ``SignedData``, no encapsulated content, no
certificates, ML-DSA-87, signer named by subject key identifier, checked
without a validity-time check against any active, enrolled BPF signer.

Names
-----

.. list-table::
   :header-rows: 1
   :widths: 24 30 46

   * - Name
     - Source
     - Rule
   * - ``tree_id``
     - ``--tree-id``, else the package name of the first append
     - A package name (:doc:`bpm-formats`). Fixed for the life of the
       tree. Distinct from the operation ``id``.
   * - Operation ``id``
     - Beefile ``[upatches.tree] id``
     - Must equal the upatch name of the artifact it publishes, so the
       source file's basename. ``bpm tree append`` and ``bpm tree sync``
       both refuse a mismatch.

Registry objects
----------------

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Object
     - Content
   * - Publication manifest
     - At ``<repository>:<reference>``, ``stable`` unless
       ``--reference`` names another tag. OCI image manifest,
       ``schemaVersion`` 2, ``artifactType``
       ``application/vnd.shirudo.upatch.tree.v1``, the empty config, and
       exactly one document layer and one signature layer, in that order.
       Its bytes are exactly those ``bpm tree append`` writes: compact
       JSON with the keys ``schemaVersion``, ``mediaType``,
       ``artifactType``, ``config`` and ``layers`` in this order, and each
       descriptor's ``mediaType``, ``digest`` and ``size``. A target and
       ``bpm tree append`` refuse a manifest in any other form, so that the
       manifest digest a target records and a successor names as its
       parent or segment follows from the two signed layers.
   * - Sealed segment
     - A publication manifest that a later segment names in
       ``base.segment_manifest_digest``, unchanged since it was the
       current one. Tagged ``segment-<k>``, ``k`` counting the sealed
       segments from 1, only so that registry garbage collection keeps
       it; targets fetch it by digest and never read the tag.
   * - Document layer
     - The publication document, media type
       ``application/vnd.shirudo.upatch.tree.v1+json``.
   * - Signature layer
     - Detached CMS signature over the document layer's bytes, media type
       ``application/vnd.shirudo.upatch.tree.signature.v1``.
   * - Artifact manifest
     - One per operation, tagged ``upatch-<id>-<payload16>``, where
       ``<payload16>`` is the first 16 hex digits of the artifact's
       ``payload_sha256``. ``artifactType`` and layer media type
       ``application/vnd.shirudo.upatch.v1``, the empty config, one layer
       holding the ``.upatch`` file, annotation
       ``org.opencontainers.image.title`` ``<id>.upatch``. An ``add``
       publishes the load artifact, a ``delete`` the unload directive.
   * - Superseded generation
     - A publication manifest that ``<reference>`` named before an
       append that did not seal it. Untagged once the reference moves. A
       target never fetches it, so registry garbage collection may
       remove it.

``bpm tree append`` adds to the current segment or seals it and starts
the next, as Figure 2 shows; :doc:`/reference/cli/bpm` gives the rule.

.. figure:: /images/reference-tree-append.svg
   :alt: Two cases of appending three operations. When the segment
         tagged stable, seq 129 to 150, has room, the new generation
         tagged stable holds seq 129 to 153, names the old generation,
         now untagged, as its parent and keeps segment-2 as its base.
         When the segment holds seq 129 to 192 and is full, its
         manifest is tagged segment-3 unchanged, and the new generation
         tagged stable holds only seq 193 to 195 and names segment-3 as
         both its base and its parent.

   Figure 2. What an append of three operations does to a segment with
   room and to a full one.

Publication document
--------------------

One JSON object per generation. Every append signs a new document that
holds the segment's operations so far.

.. code-block:: text

   {"schema": 1,
    "tree_id": "<tree-id>",
    "generation": <n>,
    "parent_manifest_digest": "sha256:<hex>",
    "base": {"seq": <b>,
             "segment_manifest_digest": "sha256:<hex>",
             "history_root": "<hex>"},
    "operations": [<operation>, ...],
    "head": {"seq": <n>}}

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Key
     - Value
   * - ``schema``
     - ``1``. Required.
   * - ``tree_id``
     - A package name. Required.
   * - ``generation``
     - Required. 1 for the first publication, one more for each append.
       From 0 to 2\ :sup:`63` - 2.
   * - ``parent_manifest_digest``
     - Digest of the publication manifest this one replaces. Absent in
       the first publication.
   * - ``base.seq``
     - Required. 0 for the first segment of the tree, otherwise the
       ``head.seq`` of the sealed segment before it.
   * - ``base.segment_manifest_digest``
     - Required when ``base.seq`` is above 0 and refused at 0. Digest of
       the sealed publication manifest of the segment before this one.
   * - ``base.history_root``
     - Required when ``base.seq`` is above 0 and refused at 0. 64 hex
       digits: the ``history_root`` every node's ``outcomes`` record
       holds at ``base.seq``, see `Node records`_.
   * - ``operations``
     - Required. At most 512. Each ``seq`` is one more than the previous
       one, and the first is ``base.seq + 1``. At least one when
       ``base.seq`` is above 0.
   * - ``head.seq``
     - Required. The ``seq`` of the last operation, or ``base.seq`` when
       there is none. Below 2\ :sup:`63` - 1.

Unknown keys are ignored.

Operation
---------

One step of the tree: load or unload one upatch on the nodes its
selector matches. There is no replace: a new build of a loaded upatch is
a ``delete`` of the old one followed by an ``add`` of the new, since a
node cannot load a second upatch under a name already loaded.

.. code-block:: text

   {"seq": <n>, "op": "add", "id": "<upatch-name>",
    "selector": {...},
    "artifact": {"repository": "oci://<registry>/<repository>",
                 "manifest_digest": "sha256:<hex>",
                 "layer_digest": "sha256:<hex>",
                 "payload_sha256": "sha256:<hex>"},
    "fixes": ["<advisory-id>", ...],
    "operation_digest": "sha256:<hex>"}

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Key
     - Value
   * - ``seq``
     - Positive sequence number.
   * - ``op``
     - ``add`` or ``delete``.
   * - ``id``
     - The upatch name of the artifact. Must be a valid upatch name.
   * - ``selector``
     - Which nodes apply the operation, see `Selector`_. ``bpm tree
       append`` always writes it. Absent or ``{}``, it matches every node.
   * - ``artifact.repository``
     - ``oci://<registry>/<repository>`` the artifact manifest lives in.
   * - ``artifact.manifest_digest``
     - Digest of the artifact manifest.
   * - ``artifact.layer_digest``
     - Digest of the ``.upatch`` layer.
   * - ``artifact.payload_sha256``
     - ``sha256:`` and the artifact's header ``payload_sha256``.
   * - ``fixes``
     - Optional, on an ``add`` only: the IDs of the advisories the upatch
       fixes, 1 to 16 strings of 1 to 255 bytes of letters, digits,
       ``.``, ``_``, ``:`` and ``-``, each once, in byte order. A
       convention of the keepalive backend, not of shirudo: the CMS
       signature covers it, the operation digest does not, and the target
       never reads, checks or measures it, so a malformed one never makes
       a node refuse the publication. ``bpm tree append`` writes it after
       ``artifact`` from the Beefile's ``fixes``
       (:doc:`/reference/formats/beefile`), leaves it out when the list is
       empty, carries every earlier operation's list into the next
       generation unchanged, and refuses to append to a publication whose
       list breaks these rules.
   * - ``operation_digest``
     - ``sha256:`` and the SHA-256 of the canonical operation, see
       `Operation digest`_.

Selector
--------

Every key present must match. A list matches when one value matches.
Lists hold at least one value, and an option or label appears once in
``kconfig`` and ``kernel_config`` together or in ``labels``: the node
refuses a publication otherwise.

.. list-table::
   :header-rows: 1
   :widths: 26 30 44

   * - Key
     - Type
     - Matches when
   * - ``architecture``
     - list of strings
     - One value equals ``uname`` machine, for example ``x86_64``.
   * - ``kernel_release_prefix``
     - list of strings
     - The kernel release starts with the value, followed by the end, a
       ``.`` or a ``-``.
   * - ``kernel_build_id``
     - list of strings
     - One value equals the kernel's GNU build ID from
       ``/sys/kernel/notes``, lowercase hex. A kernel without one never
       matches.
   * - ``kconfig``
     - object of lists
     - For each option, its value in ``/proc/config.gz``, else
       ``/boot/config-<release>``, is in the list. ``# CONFIG_<x> is not
       set`` reads as ``n``. ``kernel_config`` is accepted as an alias when
       parsing.
   * - ``labels``
     - object of lists
     - For each key, the node label's value is in the list. Node labels
       come from ``etc/shirudo/node.labels`` in the config image. A node
       without labels never matches.

Lists hold 1 to 16 strings of fewer than 256 bytes. ``kconfig`` and
``labels`` hold at most 64 keys each.

Operation digest
----------------

``operation_digest`` is the SHA-256 of the compact JSON of the operation
without ``operation_digest`` and ``fixes``, in this form:

- Keys in the order ``seq``, ``op``, ``id``, ``selector``, ``artifact``.
- ``selector`` keys in byte order: ``architecture``, ``kconfig``,
  ``kernel_build_id``, ``kernel_release_prefix``, ``labels``. Empty lists
  are left out. ``kconfig`` and ``labels`` keys in byte order.
- List values in the published order. ``bpm tree append`` sorts them in
  byte order before it publishes.
- ``artifact`` keys in the order ``repository``, ``manifest_digest``,
  ``layer_digest``, ``payload_sha256``.

The target recomputes the digest from the parsed operation and refuses the
publication when one differs. The digest of each applied operation enters
the measurement register as a ``tree_op`` event, see
:doc:`/reference/eventlog`.

From the Beefile
----------------

Operations come from a package's Beefile. Each ``[[upatches]]`` entry
with a ``[upatches.tree]`` table becomes one operation when ``bpm tree
append`` publishes the package: an ``add`` by default, a ``delete`` with
``--op delete``. :doc:`beefile` gives the keys; the selector tables
become ``selector``, with each list sorted in byte order.

.. code-block:: toml

   [[upatches]]
   source = "xfs-fix.bpf.c"

   [upatches.tree]
   id = "xfs-fix"

   [upatches.tree.selector]
   kernel_release_prefix = ["7.4"]

   [upatches.tree.selector.kconfig]
   CONFIG_XFS_FS = ["y", "m"]          # published as ["m", "y"]

publishes an operation with this selector:

.. code-block:: json

   {"kconfig": {"CONFIG_XFS_FS": ["m", "y"]}, "kernel_release_prefix": ["7.4"]}

Target acceptance
-----------------

``bpm tree sync`` applies a publication only when all of these hold:

#. The manifest has one document layer and one signature layer, each
   matching its descriptor's digest and size.
#. The signature verifies against the active config's non-revoked BPF
   signer set.
#. The document parses with the rules above, ``tree_id`` is a package
   name, and every operation has a valid ``id``, ``op`` and digests and a
   correct ``operation_digest``.
#. ``tree_id`` equals the one the node recorded.
#. A publication other than the recorded one has a higher
   ``generation``. A direct successor that names a
   ``parent_manifest_digest`` names the recorded manifest.
#. ``head.seq`` is not below the node's last applied ``seq``.
#. When ``base.seq`` lies past the node's last applied ``seq``, 0 for a
   node without a state, the node walks back to it through the sealed
   segments, see `Walk`_.
#. Base check: the ``history_root`` of the node's ``outcomes`` at
   ``base.seq``, 32 zero bytes at 0, equals ``base.history_root``.
#. Prefix check: the publication's operation digests, folded from
   ``base.history_root`` up to the node's last applied ``seq``, give the
   node's ``history_root`` there. This applies to every publication, so
   a registry that serves operations other than the ones a node already
   processed, inside a segment or at its base, is refused with
   ``EKEYREJECTED``.

The node then records the publication, see `Node records`_, and processes
the operations after its last applied ``seq``.

For each new operation whose selector matches, the target then fetches the
artifact manifest by ``manifest_digest``, takes the layer with
``layer_digest`` and media type ``application/vnd.shirudo.upatch.v1``,
checks its digest and size, and refuses the ``.upatch`` unless its header
``payload_sha256`` equals ``artifact.payload_sha256``, its ``name`` equals
``id`` and it is an unload directive exactly when ``op`` is ``delete``.

Walk
----

A node behind the segment that ``<reference>`` names walks back to the
segment its last applied ``seq`` lies in and then applies the segments
forwards, as Figure 1 shows. It keeps the manifest digest, ``base.seq``,
``head.seq`` and ``generation`` of each segment, not the documents.

#. While the oldest segment so far starts past the node's last applied
   ``seq``, the node refuses the sync when the distance between the two
   exceeds the walk limit (``E2BIG``), see `Limits`_, then fetches
   ``manifests/<base.segment_manifest_digest>``. The sealed segment must
   pass checks 1 to 3 above, hash to that digest, have the same
   ``tree_id``, end at its successor's ``base.seq`` and have a lower
   ``generation`` (``ERANGE``). A segment the registry does not serve
   refuses the sync; the node never skips ahead.
#. Oldest first, the node fetches each sealed segment again by its
   digest and checks it as before, then runs checks 4 to 9 and applies
   it as above. The segment ``<reference>`` names, which the walk holds,
   comes last.

An operation left in progress is completed against the oldest segment of
the walk alone: the node records a segment before it processes it, so the
operation lies in the segment its state names. ``state.json`` moves at
each applied operation and at each segment recorded, so a walk that stops
resumes with a shorter one. A reboot never walks: ``init`` reads
``state.json`` alone.

Outcomes
--------

A node records one outcome for every operation it processes, in its
``outcomes`` record (`Node records`_). The keepalive reports the same
outcome as the operation's two bits of ``mask``.

.. list-table::
   :header-rows: 1
   :widths: 10 10 44 18 18

   * - ``outcomes``
     - ``mask``
     - Operation
     - Loads or unloads
     - Into the chain and register
   * - 1
     - ``01``
     - The selector matched and the operation was applied.
     - yes
     - yes
   * - 2
     - ``10``
     - The selector did not match: passed over for good.
     - no
     - no
   * - 3
     - ``11``
     - The selector matched, but an ``add``'s attach target was missing
       (``attach_target_missing``): measured, not loaded, with
       ``status/<id>``.
     - no
     - yes
   * - none
     - ``00``
     - Not reached yet: past ``last_seq``.
     - no
     - no

For outcomes 1 and 3, ``projection_root`` becomes the SHA-256 of the
previous root followed by the raw ``operation_digest``, starting from 32
zero bytes, and the operation enters the measurement register as a
``tree_op`` event.

Node records
------------

The target keeps these under ``/var/lib/shirudo/bpm/upatch-tree/``. They are
not published. Each JSON object carries ``schema`` (1).

``state.json``
~~~~~~~~~~~~~~

The publication the node last accepted and how far it got.

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Key
     - Value
   * - ``tree_id``, ``generation``, ``manifest_digest``
     - Of the publication the node last accepted.
   * - ``head_seq``, ``segment_base_seq``
     - The publication's ``head.seq`` and ``base.seq``.
   * - ``last_seq``
     - The last operation processed, applied or passed over because its
       selector does not match.
   * - ``projection_root``, ``projection_root_tpm``
     - The node's projection root, see ``tree-eventlog``.

A sync records a publication, each segment of a walk in turn, once it
passes the checks above and an interrupted operation is completed, and
before it processes the first new operation of it. A sync that stops
among them leaves ``last_seq`` from ``segment_base_seq`` to ``head_seq``,
and the node refuses an older generation from then on. A state without
one of ``tree_id``, ``last_seq``, the two roots, ``head_seq`` and
``segment_base_seq`` is refused.

``tree-eventlog``
~~~~~~~~~~~~~~~~~

One JSON object per line and applied operation, with ``seq``, ``digest``
(the ``operation_digest``) and ``projection_root``. ``projection_root``
is the SHA-256 of the previous root followed by the raw operation
digest, starting from 32 zero bytes. A last line without its newline is
an append that did not finish: the replay skips it and the next append
drops it.

``outcomes``
~~~~~~~~~~~~

One JSON object per line and processed operation, in order from ``seq``
1. Nothing rebuilds or prunes the file: the keepalive reads its last 512
operations from it whatever segments held them
(:doc:`/reference/cli/status`).

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Key
     - Value
   * - ``seq``
     - The operation.
   * - ``outcome``
     - 1 applied, 2 selector did not match, 3 an ``add`` measured but
       not loaded because of ``attach_target_missing``.
   * - ``projection_root``
     - The node's projection root after the operation, which an
       unmatched one leaves where it was.
   * - ``history_root``
     - The SHA-256 of ``shirudo-tree-history``, a NUL byte, the previous
       history root and the raw operation digest, starting from 32 zero
       bytes. It counts every operation, whatever its outcome, so it is
       the same on every node at the same ``seq``.

A line at or below ``last_seq`` is never rewritten. A sync refuses a
state with ``last_seq`` above 0 whose ``outcomes`` is missing
(``ENOENT``), or has a gap or a malformed line or ends before
``last_seq`` (``EBADMSG``).

``pending.json``
~~~~~~~~~~~~~~~~

``seq``, ``id`` and ``operation_digest`` of the operation in progress,
present only while one is.

Other files
~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - File
     - Content
   * - ``artifacts/<hex>.upatch``
     - Fetched artifacts, named by their layer digest.
   * - ``status/<id>``
     - ``skipped: module not loaded`` for an ``add`` whose attach target
       was missing.

Order of the writes
~~~~~~~~~~~~~~~~~~~

The order in which a sync writes is what makes it safe to stop at any
point. An operation whose selector does not match gets its ``outcomes``
line, outcome 2, and moves ``last_seq``. One that matches is applied in
this order:

#. ``pending.json`` is written.
#. The artifact is fetched and checked, then loaded for an ``add`` or
   unloaded for a ``delete``.
#. The measurement register is extended.
#. The ``tree-eventlog`` line is appended.
#. The ``outcomes`` line is appended and synced to disk.
#. ``state.json`` moves to the operation.
#. ``status/<id>`` is written for an ``add`` whose module is not loaded,
   and removed otherwise.
#. ``pending.json`` is removed.

The next sync does this with what a stopped one left:

- It drops ``outcomes`` lines past ``last_seq`` and a last line without
  its newline before it appends.
- With a ``pending.json``, it completes the operation, without applying
  it again when the tree eventlog or this boot's eventlog already
  records it, and applies it again otherwise. An ``add`` applied again
  whose upatch the stopped sync already loaded with its payload counts
  as installed.
- Completing it writes the ``outcomes`` lines the stopped sync did not
  commit: outcome 2 for each operation between ``last_seq`` and the
  pending one, which that sync passed over, then the pending
  operation's, 3 when it is an ``add`` whose upatch is not loaded, with
  its ``status/<id>``, and 1 otherwise.

:doc:`/reference/files` lists every file shirudo keeps.

.. _upatch-tree-limits:

Limits
------

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - Item
     - Limit
   * - Operations per publication
     - 512
   * - Values per selector list
     - 16, of fewer than 256 bytes
   * - ``kconfig`` and ``labels`` keys
     - 64 each
   * - Walk of a node that has processed an operation,
       ``TREE_MAX_WALK_OPS``
     - 65,536 operations from its last applied ``seq``
   * - Walk of a node that has processed none, ``TREE_MAX_JOIN_OPS``
     - 1,048,576 operations from ``seq`` 0
   * - JSON document
     - 8 MiB
   * - Detached signature
     - 64 KiB (writer)

A walk past its limit refuses the sync with ``E2BIG`` before it fetches a
sealed segment, see `Walk`_. The bound is on the distance from the node's
last applied ``seq``, not on the size of the tree. A node that has
applied nothing holds no upatch of the tree yet and is joining, so it
gets the higher limit; a running node walks holding the bpm lock, which
stops its keepalive, and gets the lower one. A higher limit only allows
more verified fetches and never makes a node accept what it would
otherwise refuse. Join time grows linearly with the tree: each segment
of a walk costs two fetches of its manifest, document and signature and
two signature checks, so a node that joins at the limit with the default
64 operations per segment walks 16,384 segments, about 100,000 registry
requests, besides fetching, loading and measuring each operation its
selectors match. Both limits are compile-time defines, settled for now
and to be revisited by experiment on live clusters; a node further
behind than its limit is refused every sync of the tree.

Example
-------

Generation 3 of a tree ``fleet-base``: three packages published, then
``kernel-obs`` replaced by a new build, a ``delete`` of the old one and
an ``add`` of the new. ``artifact`` objects and digests are left out.

.. code-block:: text

   {"schema": 1, "tree_id": "fleet-base", "generation": 3,
    "parent_manifest_digest": "sha256:<hex>",
    "base": {"seq": 0},
    "operations": [
     {"seq": 1, "op": "add", "id": "kernel-obs", "selector": {}, ...},
     {"seq": 2, "op": "add", "id": "net-guard",
      "selector": {"architecture": ["x86_64"], "labels": {"role": ["edge"]}}, ...},
     {"seq": 3, "op": "add", "id": "xfs-fix",
      "selector": {"kconfig": {"CONFIG_XFS_FS": ["m", "y"]},
                   "kernel_release_prefix": ["7.4"]}, ...},
     {"seq": 4, "op": "delete", "id": "kernel-obs", "selector": {}, ...},
     {"seq": 5, "op": "add", "id": "kernel-obs", "selector": {}, ...}],
    "head": {"seq": 5}}

How three nodes walk it, with the outcome of each operation as its
``mask`` bits:

.. list-table::
   :header-rows: 1
   :widths: 22 26 26 26

   * - Operation
     - Node A: ``x86_64``, 7.4.2, ``role=edge``, XFS ``m``, ``xfs``
       loaded
     - Node B: ``aarch64``, 7.3.9, ``role=core``, XFS ``y``
     - Node C: ``x86_64``, 7.4.2, ``role=core``, XFS ``m``, ``xfs`` not
       loaded
   * - 1 ``add kernel-obs``
     - ``01``
     - ``01``
     - ``01``
   * - 2 ``add net-guard``
     - ``01``
     - ``10``, architecture
     - ``10``, label
   * - 3 ``add xfs-fix``
     - ``01``
     - ``10``, release
     - ``11``, module not loaded
   * - 4 ``delete kernel-obs``
     - ``01``
     - ``01``
     - ``01``
   * - 5 ``add kernel-obs``
     - ``01``
     - ``01``
     - ``01``
   * - Loaded
     - ``kernel-obs`` (new), ``net-guard``, ``xfs-fix``
     - ``kernel-obs`` (new)
     - ``kernel-obs`` (new)
   * - Chained
     - 1 to 5
     - 1, 4, 5
     - 1, 3, 4, 5
   * - ``mask``
     - ``"VUA="``
     - ``"aUA="``
     - ``"bUA="``

Each node's keepalive reports ``last_seq`` 5, its ``mask`` and its
``projection_root``, folded from the digests of the operations it
chained.

Related
-------

- :doc:`beefile` for the ``[upatches.tree]`` keys
- :doc:`bpm-formats` for packages and the repository index
- :doc:`keepalive` for what a node reports of its walk
- :doc:`/upatches/publish/publishing`
- :doc:`/reference/cli/bpm` for ``bpm tree append``, ``sync`` and ``show``
- :doc:`/reference/configuration` for the tree settings
