..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators

Maintain the backend
====================

Run the statements with ``clickhouse-client``, and the scripts from
:src:`tools/backend/`.

See a node now
--------------

The refresh runs every minute. To run it at once:

.. code-block:: sql

   SYSTEM REFRESH VIEW shirudo.node_status_mv;
   SYSTEM WAIT VIEW shirudo.node_status_mv;

Allow a build
-------------

Check 3 fails a node whose ``version_id`` is not listed:

.. code-block:: sql

   INSERT INTO shirudo.expected_builds (version_id, note) VALUES ('<version_id>', 'shirudo 2026.11');

Enroll a node
-------------

Every node starts ``untrusted``: a keepalive proves that one key signed
each record, not what hardware holds the key. Once you know the key
lives in a TPM, from credential activation (``shirudo attest verify
--expect-credential`` passed) or from the records of the builder that
created the TPM's keys, raise it:

.. code-block:: sql

   INSERT INTO shirudo.nodes (ak_name, trust) VALUES ('<ak_name>', 'enrolled');

A builder's records go in with :doc:`enroll-put`, which does the same for
each key, names its node and keeps the binding. The row may come before the node's first record, as it does when a
builder hands you the name before the node boots. It changes nothing
but ``trust``, and no row lowers it again: a key that is no longer
trusted, such as one whose TPM was replaced, shows up under a new
``ak_name``, which starts ``untrusted``. ``enrolled`` says who signed,
not that what they signed is true: a node's root can have its TPM quote
a body of its own, so only ``shirudo attest verify`` confirms its
state.

Rename a node
-------------

``node_id`` is the first host name a key claimed. To set another, insert
one that sorts before it:

.. code-block:: sql

   INSERT INTO shirudo.nodes (ak_name, node_id)
   SELECT '<ak_name>', argMinState('<name>', toDateTime64(0, 3));

Change a threshold
------------------

``stale_seconds``, ``stuck_seconds`` and ``sbom_stale_seconds`` are read
at every refresh; tune ``stale_seconds`` to the longest tree sync your
nodes run, ``stuck_seconds`` to the size of the fleet and to how long a
rollout takes, and the third to how often
:src:`tools/backend/jobs/sbom-scan` runs. Insert the whole row again and
read the table with ``FINAL``:

.. code-block:: sql

   INSERT INTO shirudo.settings (stale_seconds, stuck_seconds, window, keepalive_retention_seconds,
                                 boot_first_retention_seconds, sbom_stale_seconds)
   VALUES (600, 3600, 512, 3600, 2592000, 172800);

A column the statement leaves out goes back to its default.

Reset a node after ``TPM2_Clear``
---------------------------------

Clearing a TPM restarts its ``reset_count`` and ``clock`` under the same
attestation key, so the node's new records sort before its old ones and
never become its latest. Delete the node's rows afterwards:

.. code-block:: sql

   DELETE FROM shirudo.keepalive WHERE ak_name = '<ak_name>';
   DELETE FROM shirudo.keepalive_latest WHERE ak_name = '<ak_name>';
   DELETE FROM shirudo.boot_first WHERE ak_name = '<ak_name>';

The node's history in ``node_ops`` and ``node_sets`` stays, and so does
a mark in ``history_contradictions``: the node and its tree state are
the same, only the TPM's counters restarted.

The same statements remove a node that is gone for good, whose newest
record and current baseline otherwise stay; remove its history with
them:

.. code-block:: sql

   DELETE FROM shirudo.node_ops WHERE ak_name = '<ak_name>';
   DELETE FROM shirudo.node_sets WHERE ak_name = '<ak_name>';
   DELETE FROM shirudo.history_contradictions WHERE ak_name = '<ak_name>';

The node's row leaves ``node_status`` at the next refresh and comes back
with its next record.

Set the retention
-----------------

``shirudo.rejected`` keeps a row for seven days. ``shirudo.keepalive``
keeps a record for ``keepalive_retention_seconds`` of
``shirudo.settings`` after it was received, one hour by default. Nothing
reads those records but an audit: the newest record of every node stays
in ``keepalive_latest`` and the baseline of its boot in ``boot_first``,
whatever this retention. A ClickHouse TTL cannot read a table, so a
setting takes effect when the script applies it. To keep thirty days, at
about 200 bytes a record:

.. code-block:: sql

   INSERT INTO shirudo.settings (stale_seconds, stuck_seconds, window, keepalive_retention_seconds,
                                 boot_first_retention_seconds, sbom_stale_seconds)
   VALUES (600, 3600, 512, 2592000, 2592000, 172800);

.. code-block:: console

   $ sql/apply-retention.sh

The script refuses 0. ClickHouse then rewrites the table's parts in the
background, dropping what is older.

Clear a contradiction mark
--------------------------

A node whose record contradicted its history fails check 4 until its row
in ``shirudo.history_contradictions`` is deleted (:doc:`status`):

.. code-block:: sql

   DELETE FROM shirudo.history_contradictions WHERE ak_name = '<ak_name>';

History retention
-----------------

``shirudo.node_ops`` and ``shirudo.node_sets`` keep every row.
:doc:`status` says why, how fast they grow and why no retention is chosen.

Boot baseline retention
-----------------------

``shirudo.boot_first`` gains a row per node per boot. It keeps one for
``boot_first_retention_seconds`` after the boot was last used, thirty
days by default, and the same script applies a change. A boot is used
when one of its records arrives and, once an hour, when
``shirudo.boot_first_keep_mv`` finds it to be the boot of its node's
newest record. The baseline of a node's current boot therefore never
expires, however long the boot runs and whether the node still sends or
not; what the setting decides is how long the rows of the boots before
it stay, which no check reads. The script refuses less than a day
(86400), so that an hourly refresh that runs late cannot let a current
baseline go. The margin matters for one case: after the server was down,
or the view stopped, for longer than the retention, a baseline can
expire before the next refresh. Check 3 then compares with what is left:
the boot's oldest remaining record, or zero when no row is left, so that
counters above zero fail rather than become the baseline.
:src:`tools/backend/test/retention-boot.sql` shows a boot forty days old
and a lost baseline. :doc:`boot-baselines` gives the reasoning and a
reboot step by step.
