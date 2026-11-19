..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators

Enroll keys from a builder
==========================

A node reads ``untrusted`` until the backend knows its attestation key
lives in a TPM. When a builder you trust created the key, as
:doc:`/operate/run/attest` describes under "Enroll from a builder's
records", :src:`tools/backend/jobs/enroll-put` loads the builder's
records into the backend: it raises each key's ``trust`` in
``shirudo.nodes`` to ``enrolled``, names its node, and keeps the binding
in ``shirudo.enrollments``. It is POSIX shell around
``clickhouse-client``, with :src:`tools/backend/jobs/enroll-rows.py` to
read the file, so the host that runs it needs ``python3`` and
``clickhouse-client``.

Run it before or after the node's first keepalive; the binding waits for
the key. Take the names from the builder, never from the node.

1. Write the bindings, one per key the builder created:

   .. code-block:: json

      {"source": "vm-host-1", "nodes": [
        {"ak_name": "000b5df9f114316811380fc4fcba38a6d03d306cb68efed75bc004f1bf8de9f75e78",
         "ek_name": "000b8c1f6e0d2a9b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4cd",
         "node_id": "edge-01"},
        {"ak_name": "000b0e4c7a2b9d1f3e5a7c9b1d3f5e7a9c1b3d5f7e9a1c3b5d7f9e1a3c5b7d9f1e3a"}
      ]}

   ``source`` names the builder, as you want to find it again: a host, a
   pipeline, a batch.

2. Check it against the bindings already loaded, which loads nothing:

   .. code-block:: console

      $ jobs/enroll-put --check bindings.json

3. Load it:

   .. code-block:: console

      $ jobs/enroll-put bindings.json
      enroll-put: 000b5df9…9f75e78 (ek_name 000b8c1f…a3b4cd, node_id edge-01): enrolled
      enroll-put: 000b0e4c…5b7d9f1e3a (ek_name none, node_id none): enrolled
      enroll-put: loaded bindings: 2

   The job prints each name whole; they are shortened here.

``-`` in place of the file reads standard input.

What a binding does
-------------------

A key is enrolled for good: ``trust`` only rises, and a key that is no
longer trusted, such as one whose TPM was replaced, comes back under a
new ``ak_name``, which starts ``untrusted``. ``enrolled`` says who
signed the records, not that what they say is true: only
``shirudo attest verify`` confirms a node's state.

A key is bound once. The same binding loaded again, from a builder that
sends its whole inventory each time, changes nothing and prints
``already enrolled``. A binding that gives an enrolled key another
``ek_name`` or ``node_id`` refuses the whole file: the builder saw one
TPM create the key, and a second answer means one of the two records is
wrong.

The ``node_id`` names the node in ``shirudo.nodes`` in place of the host
name its first record claimed, and is the name ``labels-put`` and xtop
use. A rename (:doc:`maintain`) still wins over it. Without one the node
keeps the host name. The ``ek_name`` is kept for the inventory that
``shirudo attest verify --ek-name`` reads; the backend checks nothing
against it.

What it refuses
---------------

The job refuses the whole file, with status 1 and a message naming the
binding, when:

- it is not UTF-8 JSON, or not an object whose keys are ``source``, 1
  to 255 characters with no control character, and ``nodes``, an array;
  or an object has a key twice;
- a binding is not an object with ``ak_name`` and, optionally,
  ``ek_name`` and ``node_id``; or has another key;
- an ``ak_name`` or ``ek_name`` is not a TPM name, ``000b`` and 64
  lowercase hex digits, or a ``node_id`` is not 1 to 255 characters with
  no control character;
- two bindings name the same ``ak_name``;
- a binding differs from the one loaded for its key.

Exit status
-----------

0 when every binding is loaded, or checked with ``--check``; 1 when the
file is refused or the load fails; 2 for wrong usage. The job raises
``trust`` before it records the bindings, so a load that fails between
the two is finished by running it again.

Connection
----------

As :src:`tools/backend/jobs/tree-ingest`, the job runs
``clickhouse-client`` or the command ``CLICKHOUSE_CLIENT`` names. Its user
needs ``SELECT`` and ``INSERT`` on ``shirudo.enrollments`` and ``INSERT``
on ``shirudo.nodes``.
