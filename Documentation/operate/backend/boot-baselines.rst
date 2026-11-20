..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: Operators

Boot baselines and their retention
==================================

Check 3 asks whether a node's tamper counters have risen since it
booted. The answer needs the counters' total at the start of the boot,
and ``shirudo.boot_first`` holds it. This page says how a row gets
there, when it leaves, and why the table needs a view that writes rows
again. The commands are in :doc:`maintain`.

What the table holds
--------------------

One row per attestation key and ``boot_id``:

.. list-table::
   :header-rows: 1

   * - Column
     - Holds
   * - ``tamper_first``
     - The total of the tamper counters in the boot's first record that could read them. This is the baseline.
   * - ``first_order_key``
     - The order key of the boot's first record.
   * - ``last_used``
     - When the boot was last used: see below. The TTL counts from it.

A record that could not read its counters arrives with an empty
``tamper`` array. It neither sets the baseline nor is compared with it;
the first readable total of the boot becomes the baseline.

How a row is written and read
-----------------------------

- ``shirudo.boot_first_mv`` writes a row for every accepted record as it
  is ingested, keyed by the record's ``ak_name`` and ``boot_id``. The table
  is an AggregatingMergeTree: the rows of one boot merge into one, which
  keeps the total of the earliest record. The same row keeps when the
  boot's newest record was first received, which check 2 reads for the
  record's age (:doc:`status`).
- The refresh of ``node_status`` joins a node's newest record to the row
  with the same ``ak_name`` and ``boot_id``, and check 3 compares the
  record's total with that baseline. A rise fails the check.

The backend receives no event for a reboot. It learns of one when a
record arrives with a ``boot_id`` it has not seen for that key.

Why a TTL alone is not enough
-----------------------------

The table gains a row per node per boot, so rows have to leave. A TTL on
the time the boot started would remove the baseline of a boot that is
still running:

1. Day 0: a node boots with a total of 3. The baseline is 3.
2. Day 30, with thirty days of retention: the TTL removes that row. The
   node is still up.
3. Day 35: the total rises to 5, a rise of 2 that check 3 must fail.
4. The oldest row the table still has for the boot is now a later one,
   so the baseline reads 5, and the check reports ``tamper +0``.

A retention shorter than a node's uptime would therefore hide a rise on
the nodes that have run longest.

Counting the TTL from the newest record of the boot does not help.
ClickHouse keeps the rows of one boot in separate parts until it merges
them, and a TTL removes a row from the part it is in, whatever newer
parts hold for the same key. The part with the day 0 row still carries a
day 0 time and still loses it. This was observed on the pinned server: a
background merge dropped the oldest row and the baseline of a boot that
was still sending moved from 3 to 5.

The keep view
-------------

``shirudo.boot_first_keep_mv`` runs once an hour. For every node it
takes the boot of the node's newest record in ``keepalive_latest``, the
node's current boot, and writes that boot's merged baseline again as a
new row with ``last_used`` set to the time of the run. It never changes
a baseline; it only gives the current one a fresh time.

``last_used`` is thus the later of two times: when a record of the boot
last arrived, and when the keep view last found the boot to be its
node's current one. The TTL removes a row
``boot_first_retention_seconds`` after it.

What follows:

- The baseline of a node's current boot never expires, however long the
  boot runs.
- The setting decides how long the rows of earlier boots stay after a
  reboot. No check reads those rows.

A reboot, step by step
----------------------

1. The node sends records with ``boot_id`` X. The table has a row for X
   with baseline 3, and the keep view writes it again every hour.
2. The node reboots. The backend sees nothing.
3. The first record after the reboot carries ``boot_id`` Y.
   ``boot_first_mv`` writes a row for Y at ingest, with that record's
   total as the baseline.
4. From that record on check 3 compares with the baseline of Y. The row
   for X is not read again.
5. At its next run the keep view finds Y to be the node's current boot,
   writes the row for Y again and leaves the row for X alone.
6. ``last_used`` of X no longer moves, and the TTL removes the row when
   the retention has passed.

The setting
-----------

``boot_first_retention_seconds`` in ``shirudo.settings``, 2592000
(thirty days) by default. A ClickHouse TTL cannot read a table, so
:src:`tools/backend/sql/apply-retention.sh` applies a change, as it does
for ``keepalive_retention_seconds``. The script refuses less than a day
(86400), so that an hourly run that is late cannot let a current
baseline go, and it checks both values before it changes either table.

Cases to know
-------------

- A node that stops sending. Its newest record still names its last
  boot, so the keep view keeps that boot's row for good. A node that is
  gone leaves one row in ``boot_first`` and one in ``keepalive_latest``
  until an operator deletes them; :doc:`maintain` gives the statements.
- The server down, or the view stopped, for longer than the
  retention. A current baseline can expire before the next run. Check
  3 then compares with what is left: the boot's oldest remaining row,
  or zero when none is left, so that counters above zero fail rather
  than become the baseline. The thirty-day default is the margin for
  this case.
- After ``TPM2_Clear``. The node's new records sort before its old
  ones. Delete the node's rows as :doc:`maintain` says.

:src:`tools/backend/test/retention-boot.sql` pins a boot forty days old
that keeps its baseline, a node that went silent, an earlier boot whose
row is gone and a lost baseline.
:src:`tools/backend/test/retention-refused.sh` pins the values the
script refuses.

Why not one row per node
------------------------

One row per node, replaced when the node reboots, would bound the table
by the number of nodes and need neither a TTL nor a setting nor the keep
view. To replace a row the backend has to know which of two boots is the
newer, and ``boot_id`` is a random value with no order: the row would have
to be ordered by the TPM's ``reset_count``. That is only right when every
new ``boot_id`` comes with a higher ``reset_count``. Where a node could
start a new boot without a TPM reset, the earlier baseline would stay
while the counters start again from zero, and a rise would go unseen
until it passed the old total. Keying by ``boot_id`` assumes nothing about
``reset_count``, at the cost of the keep view.
