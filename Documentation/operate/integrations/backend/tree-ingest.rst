..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators

Load a tree's publications
==========================

The checks compare what a node reports with the tree it follows, so the
backend needs every operation of that tree. A long tree is a chain of
signed segments: the publication its tag names holds only the operations
after its ``base.seq``, and names the sealed segment before it by manifest
digest. :src:`tools/backend/jobs/tree-ingest` loads them all. It is POSIX shell around
``clickhouse-client`` and ``shirudo bpm tree show --walk``, with
:src:`tools/backend/jobs/tree-rows.py` to parse the JSON, so the host that runs it needs
``python3``, ``clickhouse-client`` and, to fetch a publication, ``shirudo``
from the operator package.

.. code-block:: console

   $ jobs/tree-ingest --cert /etc/shirudo/operator.pem oci://registry.example.com/shirudo/fleet-base
   $ shirudo bpm tree show oci://registry.example.com/shirudo/fleet-base --cert /etc/shirudo/operator.pem --walk >show.json
   $ jobs/tree-ingest --input show.json

The first form runs ``shirudo bpm tree show oci://<repository>
[--reference <ref>] --cert <file> --walk`` itself; the second reads a
stored output of that command, from standard input with ``--input -``.

What it reads
-------------

One JSON object per segment, oldest first, from the segment whose
``base.seq`` is 0 to the publication the tag names, each
``{"manifest_digest":"sha256:<hex>","document":<publication document>}``
followed by a newline, as ``bpm tree show --walk`` prints them once it
has fetched every segment and verified its signature against the
certificate. A document may span lines, so the job reads a stream of
JSON values, not lines. A tree that was never sealed is one segment, so
the output of ``bpm tree show`` without ``--walk`` for it is read the
same way.

The job verifies nothing itself and trusts its input for that reason:
feed it only what ``bpm tree show`` printed, and keep a stored output
where nobody else can write. It checks only that the segments join up:
the first has ``base.seq`` 0 and neither
``base.segment_manifest_digest`` nor ``base.history_root``; every later
one has both, at least one operation, the same ``tree_id``, a
``base.seq`` equal to the ``head.seq`` of the one before, a
``segment_manifest_digest`` naming the manifest of the one before and a
higher ``generation``; and every operation's ``seq`` is above its
segment's ``base.seq`` and at most its ``head.seq``. Input of another
shape, or a walk that does not join up, is refused with a message and
exit status 1, and nothing is inserted.

What it writes
--------------

.. list-table::
   :header-rows: 1

   * - Table
     - Rows
   * - ``shirudo.tree_pubs``
     - One per segment: ``tree_id``, ``generation``, ``manifest_digest``, ``parent_manifest_digest`` (empty for a first publication), ``head_seq``, ``segment_base_seq`` (its ``base.seq``), ``segment_manifest_digest`` (empty for the first segment) and ``history_root``, the tree's history root at ``segment_base_seq`` as the document carries it, 64 zeros for the first segment.
   * - ``shirudo.tree_ops``
     - One per operation: ``seq``, ``op``, ``id``, the ``selector``, and the artifact's ``repository``, ``manifest_digest``, ``layer_digest`` and ``payload_sha256`` with the ``operation_digest``.
   * - ``shirudo.upatch_fixes``
     - One per advisory ID in an operation's ``fixes``, with ``source`` ``fixes``.

Digests are stored as 64 hex digits, without ``sha256:``. A selector is
stored as compact JSON text with its keys in the document's order, and
is not interpreted: read a key with ``JSONExtract``. ``published_at`` is
when the job loaded the publication, not when the operator published it,
because the document carries no time: run the job soon after a
publication, since the time a node is given to catch up counts from
there.

``fixes`` is a convention between the operator and this backend, which
shirudo's nodes ignore. An operation whose ``fixes`` is not an array of
strings is loaded without fixes and named on standard error; the rest of
the publication loads.

Running it again
----------------

A segment is loaded once. The job first looks up the generations of the
tree in ``tree_pubs`` and skips every segment that is there with the
same manifest digest, so a sealed segment is loaded by the first run
that sees it, a later run adds only the segments that are new, and
``published_at`` of a loaded one stays. It inserts the operations and
fixes of the new segments before their own rows: a run that stops
halfway leaves those segments out of ``tree_pubs``, and the next run
inserts them again, which ReplacingMergeTree collapses into the same
rows. A segment whose generation is loaded under another manifest digest
is refused with status 1 and none of the walk is loaded, since two
publications cannot share a generation; look at the registry before
deleting the row. The job only adds: an advisory that a later
publication no longer names stays in ``upatch_fixes``.

Connection
----------

The job runs ``clickhouse-client``, which takes the server from
``CLICKHOUSE_HOST``, ``CLICKHOUSE_USER`` and ``CLICKHOUSE_PASSWORD``.
For anything else, ``CLICKHOUSE_CLIENT`` names the command with its
options, split at spaces, for example ``clickhouse-client --secure
--port 9440`` or ``docker exec -i clickhouse clickhouse-client``. The
job's user needs ``SELECT`` on ``shirudo.tree_pubs`` and ``INSERT`` on
the three tables. ``SHIRUDO``, ``TREE_REPOSITORY``, ``TREE_REFERENCE``
and ``TREE_CERT`` stand in for ``--shirudo``, the repository,
``--reference`` and ``--cert``.

When to run it
--------------

That is yours to choose; the job is one shot and keeps no state of its
own, so both of these work, also together:

- *On a timer.* Run it every minute or so for each tree, from cron or a
  systemd timer. A run that finds nothing new costs one fetch and one
  query. For example, with the environment above in
  ``/etc/shirudo-backend/fleet-base.env``:

  .. code-block:: ini

     # tree-ingest@.service
     [Service]
     Type=oneshot
     EnvironmentFile=/etc/shirudo-backend/%i.env
     ExecStart=/opt/shirudo-backend/jobs/tree-ingest

     # tree-ingest@.timer
     [Timer]
     OnCalendar=minutely
     [Install]
     WantedBy=timers.target

- *On a registry webhook.* Have the registry's push notification for the
  tree's repository start the same command, through whatever receives
  your webhooks. The job takes nothing from the notification: it
  fetches the publication and has it verified like any other run, so a
  forged notification loads nothing that is not signed.

A timer reads the newest publication and the sealed segments behind it,
so a generation published and replaced within its segment between two
runs is never loaded. Nothing is lost with it: the segments together
carry every operation of the tree, and no check looks a generation up.
The time a node is given to catch up then counts from the first
publication beyond it that was loaded. Each run fetches every segment
back to ``base.seq`` 0, one registry request per segment, and parses all
of them, also those loaded already; on a long tree, run it from a
webhook or a slower timer.
