..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators

Label the nodes
===============

A tree selector picks nodes by their labels (:doc:`/operate/run/deliver-packages`),
but a node's keepalive does not carry them, so the backend cannot show
which nodes a selector reaches. :src:`tools/backend/jobs/labels-put` gives
the backend the labels out of band: the operator, or the pipeline that
builds the config images, loads the same labels it writes into each
node's ``etc/shirudo/node.labels``. It is POSIX shell around
``clickhouse-client``, with :src:`tools/backend/jobs/labels-rows.py` to
read the file, so the host that runs it needs ``python3`` and
``clickhouse-client``.

The backend's labels are what the operator says, not what the node
matches: tree sync on the node reads its own ``node.labels``, and nothing
the job loads reaches a node. Load them from the same source as the
config images, after each change, or the two drift apart.

1. Write the sets, one per node, each named by its ``node_id`` or by its
   ``ak_name``:

   .. code-block:: json

      {"nodes": [
        {"node_id": "edge-01", "labels": {"role": "edge", "site": "fra"}},
        {"node_id": "edge-02", "labels": {"role": "edge", "site": "ams"}},
        {"ak_name": "000b9d72e08380a1", "labels": {"role": "core"}}
      ]}

2. Check it, which loads nothing:

   .. code-block:: console

      $ jobs/labels-put --check labels.json

3. Load it:

   .. code-block:: console

      $ jobs/labels-put labels.json
      labels-put: node_id edge-01: 2 labels
      labels-put: node_id edge-02: 2 labels
      labels-put: ak_name 000b9d72e08380a1: 1 label
      labels-put: loaded sets: 3

``-`` in place of the file reads standard input.

What a set does
---------------

A set replaces the whole set stored under its name: a label it leaves out
is gone. An empty set, ``"labels": {}``, clears it. A node the file does
not name keeps its labels. The file is loaded in one insert, whole or
not at all.

A node gets the set put under its ``ak_name``, else the one put under its
``node_id``, else none, as the view ``shirudo.node_labels`` reads them
(:doc:`tables/status`). Name a node by its ``node_id``, the name
:doc:`maintain` gives it, so that the labels stay with it when it gets a
new key; name it by its ``ak_name`` to give one key labels of its own. A
name no node has yet keeps its set until one has it.

What it refuses
---------------

A label is one ``node.labels`` could hold, so that a set copied from that
file loads as it is and a selector's key and value can match it. The job
refuses the whole file, with status 1 and a message naming the set, when:

- it is not UTF-8 JSON, or not an object whose one key is ``nodes``, an
  array; or an object has a key twice;
- a set is not an object with ``labels`` and exactly one of ``node_id``,
  1 to 255 characters with no control character, and ``ak_name``, 1 to
  255 lowercase hex digits; or has another key;
- two sets name the same ``node_id`` or ``ak_name``;
- ``labels`` is not an object of strings, or holds more than 64 labels;
- a key is empty, has ``=``, starts with ``#``, or a key or value has a
  blank at either end, a control character, or more than 255 bytes.

Exit status
-----------

0 when every set is loaded, or checked with ``--check``; 1 when the file
is refused or the load fails, with nothing loaded; 2 for wrong usage.

Connection
----------

As :src:`tools/backend/jobs/tree-ingest`, the job runs
``clickhouse-client`` or the command ``CLICKHOUSE_CLIENT`` names. Its user
needs ``SELECT`` and ``INSERT`` on ``shirudo.label_sets``.
