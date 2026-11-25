..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators, SecOps

Node status
===========

Once a minute the backend decides, for every node, whether it is
healthy, from the node's newest record, its history and the tree it
follows. The objects that do it are in :src:`tools/backend/sql/40-status.sql`, and
:doc:`tables/status` gives their columns and cost:

.. list-table::
   :header-rows: 1

   * - Object
     - Kind
     - Holds
   * - ``mask_code(mask, i)``
     - function
     - The outcome pair of the operation at index ``i``, from 0, of a mask's window: 1 applied, 2 selector did not match, 3 attach module not loaded, 0 not reached. ClickHouse functions have no database, so the name is global. A mask that is not base64, or too short, reads as 0.
   * - ``shirudo.latest``
     - view
     - The newest record of every node, from ``keepalive_latest``, with the node's ``node_id`` and ``trust``.
   * - ``shirudo.node_label_items``
     - view
     - Every label of every node, one row per set it comes from, see :doc:`labels-put`.
   * - ``shirudo.node_labels``
     - view
     - The labels of every node: the union of its sets, the most specific name's value where they disagree.
   * - ``shirudo.label_conflicts``
     - view
     - Per node, each key its sets give different values, and those values.
   * - ``shirudo.node_ops``
     - ReplacingMergeTree, ``ORDER BY (ak_name, tree_id, seq)``, no TTL
     - The history of every node: what it did at each operation of its tree the backend has seen it reach, see `History`_.
   * - ``shirudo.node_ops_mv``
     - refreshable materialized view, every minute, appending
     - Adds the operations each node's newest record reaches past its stored history, unless the record contradicts that history or the node is marked.
   * - ``shirudo.history_conflicts``
     - view
     - Per node whose newest record contradicts its stored history, whether at ``base_seq`` (``base``) or inside the window (``window``), and the first ``seq`` where it does, see `History`_.
   * - ``shirudo.history_contradictions``
     - MergeTree, ``ORDER BY (ak_name, tree_id)``, no TTL
     - The marks: one row per node and tree whose record once contradicted its history, with ``seq``, ``reason`` and ``marked_at``. Only an operator removes one.
   * - ``shirudo.history_contradictions_mv``
     - refreshable materialized view, every minute, appending
     - Marks every node in ``history_conflicts`` that has no mark for that tree yet.
   * - ``shirudo.node_sets``
     - ReplacingMergeTree by ``last_seq``, ``ORDER BY (ak_name, tree_id, id)``, no TTL
     - Per node, the newest operation of every upatch it applied, from ``node_ops``.
   * - ``shirudo.node_sets_mv``
     - materialized view
     - Writes a row of ``node_sets`` for every row of ``node_ops`` with code 1.
   * - ``shirudo.node_status``
     - MergeTree, ``ORDER BY (node_id, ak_name)``
     - One row per node: the outcome of the checks.
   * - ``shirudo.node_status_mv``
     - refreshable materialized view, every minute
     - Runs the checks for all nodes and replaces the rows of ``node_status`` in one step.

A UI reads ``node_status`` as often as it likes, as :doc:`xtop` does:

.. code-block:: sql

   SELECT node_id, host_name, status, trust, failed_check, log, last_seen, updated_at
   FROM shirudo.node_status
   ORDER BY status = 'healthy', node_id;

.. list-table::
   :header-rows: 1

   * - Column
     - Value
   * - ``node_id``, ``ak_name``, ``host_name``
     - The node's label, its key and the host name its newest record claimed.
   * - ``status``
     - ``stale``, ``unhealthy`` or ``healthy``, see below.
   * - ``trust``
     - The node's ``trust`` from ``shirudo.nodes``: ``untrusted``, or ``enrolled`` once the operator has recorded its key as a TPM's (:doc:`maintain`). A node's own ``trust`` never decides its ``status``: a healthy node is one whose records are consistent and match the tree, an enrolled one is one whose key is known to live in a TPM. Show both. Check 7 reads it only to choose whom a node is compared with.
   * - ``failed_check``
     - The first check that failed: 2 for ``stale``, 3 to 7 for ``unhealthy``, 0 for ``healthy``.
   * - ``log``
     - Seven lines, one per check in order.
   * - ``last_seen``
     - When the newest record was first received.
   * - ``generation``, ``last_seq``
     - From the newest record; ``NULL`` for a node that follows no tree.
   * - ``head_seq``
     - The head of the newest publication loaded for the node's tree, ``NULL`` when there is none or when the node names a later generation, whose head is in a publication yet to be loaded.
   * - ``loaded``, ``set_sha256``
     - ``count`` and ``set_sha256`` of the newest record.
   * - ``updated_at``
     - When the row was computed.

Checks
------

``status`` is:

- ``stale`` when the newest record was first received more than
  ``stale_seconds`` ago, 10 minutes by default. It wins over everything
  else, because the other lines then describe old data; the ``log`` still
  shows what that record said. A node whose records are all refused gets
  no new record and turns stale.

  A record received again counts from when it came first. Its quote
  still checks, so whoever holds a node's last record, a collector or a
  reader of ``shirudo.keepalive``, can send it again, but a node that
  sends nothing new turns stale all the same: only a quote with a later
  ``clock`` or ``reset_count`` is news, and only the node's TPM signs
  one. ``shirudo.boot_first`` keeps that first time for the newest
  record of each boot.

  A node sends a record a minute, but not while it syncs its tree:
  every shirudo command on a target holds the config operation lock for
  its whole run, and ``bpm tree sync`` holds it until its last operation
  is applied. A keepalive that cannot take the lock within 30 seconds
  sends nothing, so a sync that runs for minutes leaves a gap of that
  length. The default allows for syncs of a few minutes; it is a first
  guess, to be tuned against the sync durations seen on real clusters.
- ``unhealthy`` when the record is fresh and one of checks 3 to 7 fails.
- ``healthy`` otherwise. A node behind the head of its tree is healthy
  until ``stuck_seconds`` have passed since the oldest publication it has
  not finished was loaded: that is a rollout, and line 5 says ``behind``.

The checks, in order. Each only means something if those before it
passed. Checks 3 to 6 have a section each below.

.. list-table::
   :header-rows: 1

   * - #
     - Line starts
     - Passes when
     - Fails as
   * - 1
     - ``1 signed:``
     - Always, here: a record whose quote fails never becomes a node's newest. The line gives the node's trust and how many records under its key were refused in the last hour.
     - Never fails
   * - 2
     - ``2 fresh:``
     - The newest record, by the quote's ``reset_count`` and ``clock``, was first received at most ``stale_seconds`` ago.
     - ``FAIL``
   * - 3
     - ``3 reported:``
     - The record reports a healthy target of an expected build, see `Check 3`_.
     - ``FAIL``
   * - 4
     - ``4 chain:``
     - The mask folds to ``projection_root`` and agrees with the node's history, see `Check 4`_.
     - ``FAIL``
   * - 5
     - ``5 head:``
     - The node is at the head of its tree, or ``behind`` it for at most ``stuck_seconds``, see `Check 5`_.
     - ``FAIL stuck``
   * - 6
     - ``6 set:``
     - The loaded set is the one the mask leads to, see `Check 6`_.
     - ``FAIL drift``
   * - 7
     - ``7 peers:``
     - The node's ``base_root`` and its mask up to ``last_seq`` are the most common pair among the nodes with the same ``tree_id``, ``base_seq``, ``last_seq``, ``config_root`` and ``kernel_release``, or one of several equally common ones. An enrolled node is compared with the enrolled nodes of that group only, an untrusted one with all of them. Alone in its group it has ``no peers``.
     - ``FAIL outlier``

An outlier is a reason to attest a node, not an alarm by itself: a node
whose labels changed partway through a tree differs from its peers for
a good reason.

Whoever can post to the collector can make keys, as many as it takes to
be the most common pair of a group. Untrusted keys therefore have no
say about an enrolled node: they can neither make it an outlier nor
hide one among them. Among untrusted nodes they can do both, so enroll
the nodes whose check 7 you rely on (:doc:`maintain`). The line's count
is that of the nodes the node was compared with, itself included.

Three kinds of node are not held against the tree. Checks 4 to 7 pass
for them and their lines say why:

.. list-table::
   :header-rows: 1

   * - Line reads
     - When
   * - ``no tree``
     - The record's ``tree_id`` is ``null``: the node follows no tree. Checks 1 to 3 still run.
   * - ``no mask``
     - The node follows a tree but its record has no ``mask``: its record of outcomes is damaged. The node says so in ``flags`` bit 2, so check 3 fails.
   * - ``publication unknown``
     - The record names a generation newer than the newest in ``tree_pubs`` for its tree, or a tree with no publication there: the ingest job is behind, and ``tree_ops`` may end before the record does. A record naming an older generation that was never loaded is checked as usual, since operations never change and no check looks a generation up.

The two nodes of the example in :src:`testing/fixtures/keepalive/`, after release 1.1.0 of the upatch
their tree carries, with :src:`tools/backend/test/status-fixtures.sql` showing the same:

.. code-block:: none

   node_id:      edge-01
   status:       healthy
   trust:        untrusted
   failed_check: 0
   log:          1 signed: pass, untrusted, 0 rejected in the last hour
                 2 fresh: pass, last record 21 s ago
                 3 reported: pass, verdict ok, cond 0x1555, flags 0, tamper +0, build d6d918ad
                 4 chain: pass, root 15452248
                 5 head: pass, seq 3 of 3, generation 3
                 6 set: pass, 1 loaded
                 7 peers: no peers, 1 in group

   node_id:      core-01
   status:       healthy
   trust:        untrusted
   failed_check: 0
   log:          1 signed: pass, untrusted, 0 rejected in the last hour
                 2 fresh: pass, last record 21 s ago
                 3 reported: pass, verdict ok, cond 0x1555, flags 0, tamper +0, build d6d918ad
                 4 chain: pass, root 00000000
                 5 head: pass, seq 3 of 3, generation 3
                 6 set: pass, 0 loaded
                 7 peers: no peers, 1 in group

Check 3
~~~~~~~

Check 3 passes when all of these hold:

- ``verdict`` is ``ok``;
- each of the seven condition pairs of ``cond`` is OK, ``0x1555``; pairs
  above the seventh are not read;
- bits 0 to 3 of ``flags`` are clear;
- the total of ``tamper`` is what it was in the first record of this
  boot that could read the counters;
- ``version_id`` is in ``shirudo.expected_builds``.

It fails as ``FAIL``, with every item on the line; an unexpected build
is marked ``(not expected)``. Bits 4 and 5 of ``flags`` say a node is
busy, not broken, and do not fail it, see `Check 6`_.

The baseline of check 3 is a boot's first readable total. A record
whose ``tamper`` is ``null`` could not read the counters: it says so in
``flags`` bit 3 and fails the check for that, its line reads ``tamper +0``,
and it neither sets the baseline nor is compared with it. The next
record that reads them is held against the first one that did, so a
boot that begins with an unreadable record does not fail later for
counters it had from the start.

Check 4
~~~~~~~

Check 4 folds the published operation digests that the mask marks 1 or
3, from ``base_root``, each step SHA-256 of the previous root and the
digest. It passes when all of these hold:

- the fold gives ``projection_root``;
- no operation up to ``last_seq`` is marked 0;
- every operation from ``base_seq + 1`` to ``last_seq`` is in
  ``tree_ops``;
- ``base_seq``, ``last_seq``, ``base_root`` and ``projection_root`` are
  present and well formed;
- when ``base_seq`` is 0, ``base_root`` is the zero root every tree
  starts from: the history is folded from it, so a window that starts
  anywhere else at seq 0 would pass with nothing stored for it;
- when ``base_seq`` is above 0, ``base_root`` is the root the node's
  history has at ``base_seq``, see `Gaps`_;
- at every operation of the window the history reaches, the code and the
  root folded from ``base_root`` are the stored ones, see
  `Contradictions`_;
- the node has no mark.

Where the history has no row at ``base_seq``, or only the gap row with
the same root, the line adds ``base unverified (gap)`` and the check
does not fail on that account. When the history is why it fails, the
line adds ``base differs from history``, ``window differs from history
at seq <seq>`` or ``marked: contradicted history at seq <seq>``. A
marked node fails even when its record cannot be held against the tree.

Check 5
~~~~~~~

Check 5 passes when ``last_seq`` is at the head of the newest
publication of the tree, or when the oldest publication the node has
not finished was loaded at most ``stuck_seconds`` ago, and the line then
reads ``behind``. It fails as ``FAIL stuck``.

The stuck clock of check 5 belongs to the node, not to the tree. It
starts at the ``published_at`` of the earliest-loaded publication of the
node's tree whose ``head_seq`` is beyond the node's ``last_seq``, so a
publication that follows does not start it again: an operator who
publishes more often than ``stuck_seconds`` still sees a node that never
moves, ``stuck_seconds`` after the first publication it failed to finish.
A node that moves, but never as far as the head, starts a new clock
with every publication it finishes. :src:`tools/backend/test/status-stuck.sql` shows both.

Check 6
~~~~~~~

Check 6 folds the operations the mask marks 1 into the set they leave
loaded, an ``add`` loading its payload under its ``id`` and a ``delete``
removing it, and hashes one line ``<payload_sha256> <id>`` per upatch,
sorted by ``id``. When ``base_seq`` is above 0 the fold starts from what
the node's history leaves loaded at ``base_seq``, from ``node_sets``. The
line reads the first of these that applies:

.. list-table::
   :header-rows: 1

   * - Line reads
     - When
     - Check 6
   * - ``FAIL sync in progress at head``
     - ``flags`` bit 4, a tree operation in flight, on a node at the head.
     - Fails
   * - ``sync in progress``
     - ``flags`` bit 4.
     - Passes, the set not compared
   * - ``snapshot unsettled``
     - ``flags`` bit 5.
     - Passes, the set not compared
   * - ``set unverified (gap)``
     - ``base_seq`` is above 0 and the history does not reach it without a gap.
     - Passes, the set not compared
   * - ``pass``
     - The hash is ``set_sha256``.
     - Passes
   * - ``FAIL drift``
     - Otherwise.
     - Fails

The check is exact. A node sends a record of one point in time or flags
it, and neither flag hides a node for long. An operation in flight has a
``seq`` above ``last_seq``, so bit 4 on a node at the head is a
contradiction; a node that stays behind the head fails check 5 as stuck,
with or without the bits. A gap is what the backend cannot know: what
the node applied in it would be in its set.

What the checks cost
~~~~~~~~~~~~~~~~~~~~

Checks 4 and 6 depend on the tree and the mask, not on the node, so the
refresh folds each distinct path, the combination of ``tree_id``,
``base_seq``, ``last_seq``, ``base_root`` and
``mask``, once and joins the result to the nodes on it. It reads
``keepalive_latest`` and ``boot_first``, one row per node and per boot,
and never ``shirudo.keepalive``. Of the history it reads, per node, the
projection that says how far it reaches, the rows of ``node_ops`` from
``base_seq`` to where the window or the history ends, whichever comes
first, at most 513 per node, and, for a node whose window starts past
seq 0, its rows of ``node_sets``, one per upatch it ever applied. The
rows of the window are read through ``history_conflicts``, which
``node_ops_mv`` and ``history_contradictions_mv`` read too, so each refresh
reads them once per node. :src:`tools/backend/test/status-cost.sql` asserts what the
refresh reads.

History
-------

A keepalive's ``mask`` covers a window of the last 512 operations of the
node's tree, from ``base_seq + 1``, and ``base_root`` is the node's root
before it. Below the window a record says nothing, so the backend keeps
what each node's records said while it could: ``shirudo.node_ops`` has a
row for every node, tree and operation the backend has seen the node
reach, and ``shirudo.node_sets`` what that leaves loaded. Check 4 holds
every record against them, check 6 a record whose ``base_seq`` is above
0, and ``node_vulns`` a upatch whose newest operation is below the
window.

``shirudo.node_ops``:

.. list-table::
   :header-rows: 1

   * - Column
     - Value
   * - ``ak_name``, ``tree_id``, ``seq``
     - The node, its tree and the operation.
   * - ``code``
     - What the node did there, as its mask said: 1 applied, 2 selector did not match, 3 attach module not loaded. 0 marks a gap, see below.
   * - ``root``
     - The node's ``projection_root`` after ``seq``, 32 bytes: ``hex(root)`` gives the form of a keepalive.

``shirudo.node_sets`` has, per node, tree and upatch ``id``, the newest
operation the node applied: ``last_seq``, ``last_op`` (``add`` or ``delete``)
and the ``last_payload`` of that operation.

Once a minute the backend holds each node's newest record against its
stored history, ``node_ops_mv`` to add rows and
``history_contradictions_mv`` to mark the node. Figure 1 shows the three
outcomes: the record extends the history, its window starts past it and
leaves a gap, or it contradicts it.

.. figure:: /images/operate-backend-history.svg
   :alt: Three rows on one seq axis from 0 to 700, each with a node's
         stored history above the window of its newest record, from
         base_seq 188 to 700. Extends: the history ends at 600, the
         window is compared with it from 188 to 600, and rows 601 to 700
         are added. Gap: the history ends at 100, 101 to 187 are
         unknown, a gap row of code 0 holds the record's base_root at
         188, and rows 189 to 700 are added. Contradiction: the code or
         root differs from the stored row at 412, nothing is added and
         the node is marked.

   Figure 1. What a node's newest record does to its stored history, for
   a tree whose head is 700 and a window of the last 512 operations.

A record extends the history by the operations it reaches past the
last stored row, up to ``last_seq``, with their codes from the mask and
their roots folded from the last stored root. They are added only when
every one of them is in ``tree_ops``, none is marked 0 and the fold ends
at the record's ``projection_root``: a record that does not extend the
history consistently adds nothing, nor does one that contradicts it,
see `Contradictions`_, or any record of a marked node. The rows of an
operation never change once added.
``node_sets_mv`` follows every row with code 1. The fold runs once per
distinct path and starting point, not per node.

Gaps
~~~~

A record whose window starts past the stored history, because the node
is new to the backend or was not heard from while its tree moved on by
more than the window, leaves a gap: the operations in between are in no
record the node will send. The history starts again at the record's
``base_seq`` with a gap row, code 0, which holds the record's
``base_root``, as the middle row of Figure 1 shows. Rows are only ever
added past the last one, so the history up to a ``seq`` is whole when it
reaches that ``seq`` and has no gap at or below it. For a record whose
``base_seq`` is above 0:

- check 4 reads ``base unverified (gap)`` where the history has no row
  at ``base_seq`` or only the gap row, which nothing verified, with the
  same root; another root, a gap row's included, fails as ``base differs
  from history``, see `Check 4`_;
- check 6 reads ``set unverified (gap)`` where the history does not
  reach ``base_seq`` whole, see `Check 6`_; otherwise the expected set is
  that of ``node_sets`` at or below ``base_seq``, with the operations the
  window marks 1 on top;
- ``node_vulns`` reads an operation below the window from the history,
  and is ``unknown`` when the history has no row for it, see :doc:`exposure`.

:src:`tools/backend/test/history-base.sql` shows nodes followed from seq 0 through four
windows, :src:`tools/backend/test/history-gap.sql` nodes first seen, or seen again, past
their history, and :src:`tools/backend/test/vulns-history.sql` a shield older than the
window.

The order of the refreshes does not matter: check 6 reads the history
at or below ``base_seq``, which an earlier record put there, and check 4
also the rows of the window, which match the record they were folded
from. Check 4 and ``node_ops_mv`` find a contradiction from
``history_conflicts`` themselves and do not wait for the mark.

A keepalive reports a node's outcomes for the last 512
operations of its tree only (U20 of :doc:`/security/threat-model`). A node first
heard from after its tree has grown past that window never tells the
backend which earlier operations it applied. Check 4 anchors its
history at that first record's ``base_root`` and verifies the records
after it; comparing it with its peers (check 7) works from the start;
but check 6 stays ``set unverified (gap)`` for as long as the node
follows that tree, and ``node_vulns`` is ``unknown`` for shields added
before the window. Every node that joins a tree of more than 512
operations is in that case, and so is one that the backend did not
hear from while its tree moved on by more than 512 operations. Attest such a node with ``shirudo attest`` when its
loaded set matters.

Contradictions
~~~~~~~~~~~~~~

A record that does not extend a node's history adds no rows. Two rules
decide when it fails:

1. Where a record's window overlaps the node's stored history, it has
   to match the stored rows at every seq they share, as the top row of
   Figure 1 compares them: ``base_root`` the root at ``base_seq``, and up
   to the lower of ``last_seq`` and the end of the history the mask's
   code and the folded root the stored ones. A gap row has no code, so
   only its root is compared. This holds for a window from seq 0 too. A
   mismatch fails check 4 as ``base differs from history`` or ``window
   differs from history at seq <seq>``, naming the first seq that
   differs. The code is compared because the roots alone would miss an
   operation the node calls applied (1) in one record and attach module
   not loaded (3) in another: both chain the operation.
   ``shirudo.history_conflicts`` finds these records.
2. A node whose record once contradicted its history keeps failing
   until an operator clears its mark, so that a later gap cannot
   launder it: without the mark, a node whose window has moved past its
   stored history would start a gap like one not heard from, and pass.
   Once a minute ``history_contradictions_mv`` adds a row to
   ``shirudo.history_contradictions`` for every node and tree in
   ``history_conflicts`` that has none. While a node has a mark, check 4
   fails as ``marked: contradicted history at seq <seq>``, unless its
   record contradicts its history now, which the line names instead,
   and ``node_ops_mv`` adds nothing to its history, gap rows included.

The mark is stricter than the record that set it in three ways: it
holds for the node whatever tree its newest record follows and whatever
boot it comes from, and it fails check 4 even for a node whose record
check 4 otherwise skips (``no tree``, ``no mask``, ``publication unknown``).
A new boot does not clear it, since a node that lies once can reboot,
and nor does a gap.

Clear a mark once the node has been looked at, for example attested
with ``shirudo attest``:

.. code-block:: sql

   DELETE FROM shirudo.history_contradictions WHERE ak_name = '<ak_name>';

Its history then grows again from where it stopped. A record that
still contradicts it is marked again at the next refresh; one whose
window has moved past it starts a gap, as for a node not heard from.
To hold the node's next records against nothing it said before, delete
its history with the mark, as for a node that is gone, see :doc:`maintain`.
:src:`tools/backend/test/history-base.sql` shows both rules with ``edge-liar``, which lies
about its base, and ``edge-swap``, which lies inside its window. Watch
for gaps on nodes the backend heard from all along.

Size
~~~~

``node_ops`` gains a row per node for every
operation the node processes, whatever its outcome, about 34 bytes on
disk, mostly the root: a publication of one operation to 10,000 nodes
adds 10,000 rows, and 10,000 nodes that each go through a tree of
65,000 operations hold about 650 million rows, some 22 GB. ``node_sets``
holds a row per node and upatch the node ever applied, about 70 bytes.
Neither has a TTL, and nothing removes their rows but the operator:
trimming them would reopen the gaps they close, turning the base of
check 4, the set of check 6 and older shields in ``node_vulns`` back into
``gap`` and ``unknown``. A refresh reads one row of the projection per node
to find where its history ends, and the rows it needs at ``base_seq``,
not the whole table.

No retention is chosen for ``node_ops`` and ``node_sets``. It needs
measurements on real clusters, together with ``stale_seconds``, which
decides how long a node may be silent, and the two grow as above.

``window`` of ``shirudo.settings`` is not read: a node chooses its window
and says where it starts in ``base_seq``, and the checks read what the
record has.
