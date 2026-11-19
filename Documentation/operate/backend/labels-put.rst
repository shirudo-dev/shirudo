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

1. Write the sets, each named by a node's ``node_id`` or ``ak_name``, or
   by the ``config_root`` of a config image, for every node that booted
   it:

   .. code-block:: json

      {"nodes": [
        {"config_root": "6d5ed552f448a1c07e3b9d24f5a86c1e0b7d93f2c4e5a6b7180c9d2e3f4a5b6c",
         "labels": {"role": "edge"}},
        {"node_id": "edge-01", "labels": {"role": "edge", "site": "fra"}},
        {"ak_name": "000b9d72e08380a1", "labels": {"role": "core"}}
      ]}

2. Check it, which loads nothing:

   .. code-block:: console

      $ jobs/labels-put --check labels.json

3. Load it:

   .. code-block:: console

      $ jobs/labels-put labels.json
      labels-put: config_root 6d5ed552f448a1c07e3b9d24f5a86c1e0b7d93f2c4e5a6b7180c9d2e3f4a5b6c: 1 label
      labels-put: node_id edge-01: 2 labels
      labels-put: ak_name 000b9d72e08380a1: 1 label
      labels-put: loaded sets: 3

``-`` in place of the file reads standard input.

What a set does
---------------

A set replaces the whole set stored under its name: a label it leaves out
is gone. An empty set, ``"labels": {}``, clears it. A node the file does
not name keeps its labels. The file is loaded in one insert, whole or
not at all.

A node's labels are the union of the sets put under its ``ak_name``, its
``node_id`` and the ``config_root`` its newest keepalive reports, as the
view ``shirudo.node_labels`` reads them (:doc:`tables/status`). Where two
of them give one key different values, the node takes the value of the
more specific name, ``ak_name`` over ``node_id`` over ``config_root``,
and the key is a conflict:

.. code-block:: none

   config_root  role=lab   image=base
   node_id      role=edge             site=fra
   labels       role=edge  image=base site=fra    conflict: role

The view ``shirudo.label_conflicts`` has one row per node and key in
conflict, with the value the node took, the name it came from and every
value given; query it to report them. After every load the job names each
one on standard error, whether or not the file caused it:

.. code-block:: none

   labels-put: conflict: edge-01 (000b23602ab98bfb): role=edge from node_id over lab from config_root

A conflict is not an error of the load: the sets stay loaded, and the
status is 0. Resolve it by changing one of the sets.

Name the sets by ``config_root`` where you can. A config image holds
``etc/shirudo/node.labels``, so the pipeline that builds the image can
load the same labels under its root, and they are then the ones the
node's tree sync matches for as long as the node runs that image. A node
that boots another image takes that image's set, or none. Name a node by
its ``node_id``, the name :doc:`maintain` gives it, to add labels its
image does not have, and so that they stay with it when it gets a new
key; name it by its ``ak_name`` to give one key labels of its own. A name
no node has yet keeps its set until one has it.

What it refuses
---------------

A label is one ``node.labels`` could hold, so that a set copied from that
file loads as it is and a selector's key and value can match it. The job
refuses the whole file, with status 1 and a message naming the set, when:

- it is not UTF-8 JSON, or not an object whose one key is ``nodes``, an
  array; or an object has a key twice;
- a set is not an object with ``labels`` and exactly one of ``node_id``,
  1 to 255 characters with no control character, ``ak_name``, 1 to 255
  lowercase hex digits, and ``config_root``, 64 lowercase hex digits; or
  has another key;
- two sets name the same ``node_id``, ``ak_name`` or ``config_root``;
- ``labels`` is not an object of strings, or holds more than 64 labels;
- a key is empty, has ``=``, starts with ``#``, or a key or value has a
  blank at either end, a control character, or more than 255 bytes.

Exit status
-----------

0 when every set is loaded, conflicts or not, or checked with
``--check``; 1 when the file is refused or the load fails, with nothing
loaded, or the conflicts cannot be read after the load; 2 for wrong
usage.

Connection
----------

As :src:`tools/backend/jobs/tree-ingest`, the job runs
``clickhouse-client`` or the command ``CLICKHOUSE_CLIENT`` names. Its user
needs ``SELECT`` and ``INSERT`` on ``shirudo.label_sets`` and ``SELECT``
on the views ``shirudo.label_conflicts`` reads.
