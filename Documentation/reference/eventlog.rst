..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators, security reviewers

Eventlog events
===============

The eventlog records every extension of the measurement register, one
JSON object per line. A replay of this boot's records reproduces the
register value. :doc:`/internals/measurement-register` explains the
register. This page gives the files, the record format, the event kinds
and their digests, the replay rule and the limits.

Files
-----

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Path
     - Contents
   * - ``/var/lib/shirudo/eventlog``
     - The eventlog. Mode ``0600``. It inherits the seal label of
       ``/var/lib/shirudo``, so only tasks with shirudo's runtime
       authority may open it for writing, rename, unlink or change it.
       shirudo appends to it and never rotates or truncates it.
   * - ``/run/shirudo/eventlog.pending``
     - The ``init`` record that ``shirudo init`` writes while it runs
       from the initrd. Readers treat it as the end of the eventlog
       until it is adopted.
   * - ``/var/lib/shirudo/eventlog.lock``
     - Lock file. upatch loads and unloads, key revocations and tree
       operations hold it from the register extend to the matching
       append, so the register and the log advance in the same order.
       Adopting the pending record also takes it.

``SHIRUDO_EVENTLOG_PATH`` and ``SHIRUDO_EVENTLOG_PENDING_PATH`` override
the two paths for host tests. A target running from a runtime image
refuses both, see :doc:`/reference/environment`.

The upatch tree keeps its own projection log in
``/var/lib/shirudo/bpm/upatch-tree/tree-eventlog``, described in
:doc:`formats/upatch-tree`. Config image activations extend the config PCR
instead of the register and keep their records under
``/var/lib/shirudo/config-update``, see :doc:`/internals/config-images`.
Neither is part of the eventlog.

Record format
-------------

- One compact JSON object per line, terminated by ``\n``. A record is
  not in the log until its ``\n`` is: a last line without one is an
  append that did not finish, killed or cut short by a crash.
- A command appends a record only after the register extend succeeded,
  writes it and its ``\n`` in one ``write``, then calls ``fsync``. An
  append that fails part-way is truncated back to the previous size, and
  the next append first drops a last line that did not finish, with a
  warning in the journal.
- Digests are SHA-256, written as 64 lowercase hex digits.

Every record carries these fields:

.. list-table::
   :header-rows: 1
   :widths: 22 14 64

   * - Field
     - Type
     - Value
   * - ``schema``
     - integer
     - ``1``
   * - ``ts``
     - string
     - Time of the append, ISO 8601 UTC, for example
       ``2026-10-29T16:21:19Z``.
   * - ``nv_index``
     - string
     - The register's NV index, ``0x01818E00``.
   * - ``alg``
     - string
     - ``sha256``
   * - ``digest``
     - string
     - The event, 64 hex digits: the value extended into the register.
   * - ``type``
     - string
     - ``init``, ``upatch_load``, ``upatch_unload``, ``key_revoke`` or
       ``tree_op``.
   * - ``boot_id``
     - string
     - ``/proc/sys/kernel/random/boot_id`` at the append.

Event kinds
-----------

.. list-table::
   :header-rows: 1
   :widths: 18 40 42

   * - ``type``
     - Written by
     - Additional fields
   * - ``init``
     - ``shirudo init``, once per TPM reset, after boot restore. A
       re-run of ``init`` in the same boot writes nothing.
     - See `Fields of an init record`_.
   * - ``upatch_load``
     - ``shirudo upatch load``, after the load, before it reports
       success.
     - ``upatch``: object with ``name`` and ``payload_sha256``.
   * - ``upatch_unload``
     - ``shirudo upatch unload``, before the detach. A live config
       activation that revokes a key writes one per loaded upatch the
       key signed.
     - ``upatch``: object with ``name`` and ``payload_sha256``.
       ``reason``: ``key_revoke`` for an unload caused by a key
       revocation, absent otherwise.
   * - ``key_revoke``
     - ``shirudo image update``, when the activated config revokes a
       certificate that is in the ``.bpf`` keyring. A revocation
       applied at boot is covered by the ``init`` event instead.
     - ``key``: object with ``fingerprint`` (SHA-256 of the public key)
       and ``cert_sha256`` (SHA-256 of the certificate DER).
   * - ``tree_op``
     - ``shirudo bpm tree sync``, once per applied tree operation.
     - ``tree``: object with ``seq`` (integer), ``op`` (``add`` or
       ``delete``), ``id`` (the upatch name) and ``operation_digest``
       (``sha256:<hex>``). ``chain``: the register value after the
       event.

Fields of an init record
~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 24 14 62

   * - Field
     - Type
     - Value
   * - ``tpm_reset_count``
     - integer
     - The TPM's reset count when the register was bound.
   * - ``cert_sha256``
     - string
     - Digest of the enrolled certificate set: the SHA-256 of the
       certificate DER when one certificate is enrolled, else the
       SHA-256 of the concatenated DER digests sorted bytewise.
   * - ``certs``
     - array of string
     - SHA-256 of each enrolled certificate's DER.
   * - ``set_digest``
     - string
     - SHA-256 of the restored set listing (see `Event digests`_).
   * - ``tree_root``
     - string
     - The upatch tree's ``projection_root`` at boot, or 64 zeros
       without tree state.
   * - ``set``
     - array of object
     - The upatches boot restore applied or found loaded, each with
       ``name`` and ``payload_sha256``.
   * - ``pcr``
     - integer
     - ``9``, the PCR that anchors the register.
   * - ``pcr_before``
     - string
     - PCR 9 before the binding.
   * - ``phase_pcr``
     - integer
     - ``11``, the boot phase PCR.
   * - ``phase_before``
     - string
     - PCR 11 at the binding.
   * - ``bound_in``
     - string
     - ``initrd`` when ``init`` ran from the initrd, ``root`` otherwise.
   * - ``nv_name``
     - string
     - The register's TPM name after its first write, 68 hex digits
       (``000b`` and a SHA-256).
   * - ``nv_writer_public``
     - string
     - The NV writer key's RSA modulus, 384 bytes big-endian, 768 hex
       digits. The exponent is 65537 and not stored.
   * - ``anchor``
     - string
     - ``nvpcr-init:shirudo:0x1818e00:<nv_name>``
   * - ``anchor_digest``
     - string
     - SHA-256 of the ``anchor`` string, extended into PCR 9.
   * - ``chain``
     - string
     - The register value after the event.

Event digests
-------------

Each digest is a SHA-256 over a tag, its terminating NUL byte and the
event's fields. Hex fields enter the hash as their 32 decoded bytes.
``attest verify`` recomputes every non-``init`` digest from the
record's own fields and fails a record whose digest does not derive
from them. Its report names a record by what the digest covers: the
upatch name, the tree ``seq`` and ``operation_digest``, or the
certificate's ``cert_sha256``. A tree operation's ``op`` and ``id`` and
a key's ``fingerprint`` are not shown, as verify cannot tie them to the
digest. Evidence with a record ``type`` other than lowercase letters and
``_``, or an upatch record without a valid upatch name, is no evidence
document.

.. list-table::
   :header-rows: 1
   :widths: 18 82

   * - ``type``
     - ``digest``
   * - ``init``
     - ``SHA256("shirudo-init\0" || cert_sha256 || set_digest ||
       tree_root)``
   * - ``upatch_load``
     - ``SHA256("shirudo-upatch\0" || payload_sha256 || name)``
   * - ``upatch_unload``
     - ``SHA256("shirudo-unload\0" || payload_sha256 || name)``
   * - ``key_revoke``
     - ``SHA256("shirudo-key-revoke\0" || cert_sha256)``
   * - ``tree_op``
     - ``SHA256("shirudo-tree\0" || seq || operation_digest)``

- ``name`` is the upatch name's bytes without a terminating NUL, at most
  256 bytes.
- ``seq`` is the tree sequence number as an 8-byte big-endian integer.
- ``set_digest`` is the SHA-256 of one line ``<payload_sha256> <name>\n``
  per member of ``set``, sorted by name, concatenated. An empty set
  gives the SHA-256 of the empty string,
  ``e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855``.
- The register starts at 32 zero bytes after every TPM reset. Each
  event sets it to ``SHA256(register || digest)``, the TPM's NV extend.

Replay
------

``shirudo status``, ``shirudo attest`` and the measuring commands select
this boot's records the same way:

- They read ``/var/lib/shirudo/eventlog`` followed by
  ``/run/shirudo/eventlog.pending``.
- They parse every line. One line that is not valid JSON fails the
  replay, whatever boot it belongs to, and so does a NUL anywhere in
  either file, which would end the walk early. A last line without
  ``\n`` is skipped, as it is no record yet. The register then runs
  ahead of the log, as after an append that failed.
- They skip lines without a ``boot_id`` or with another boot's
  ``boot_id``.
- They start at this boot's first ``init`` record. Every ``init``
  record restarts the fold at 32 zero bytes, so the replay covers the
  last ``init`` record and the records after it.
- A boot without an ``init`` record has no replay.

The upatches this boot measured are folded from the records the register
vouches for, which the undo pass of ``upatch load`` and ``upatch
unload``, ``upatch reconcile`` and the ``UpatchesMeasured`` condition of
``status`` read. A boot ID read by path is root's to replace in a mount
namespace of its own, so they select the boot by the TPM instead:

- They start at the last ``init`` record whose ``nv_name`` is the name
  of the live index and whose ``tpm_reset_count`` is the TPM's reset
  count, both read over the session ``init`` pinned.
- They derive each record's digest from its fields, as the extend that
  wrote it computed it (see `Event digests`_), and refuse a record whose
  ``digest`` differs and a type no writer uses.
- They fold the records from zero and refuse unless the result is the
  value the TPM reports for the register.

A refusal is ``tampered`` for a load or an unload and an ``ALERT`` of
``UpatchesMeasured`` in ``status``. An ``init`` record starts the set
over with its ``set``, and an ``upatch_load`` or ``upatch_unload``
record adds or removes its upatch.
Only an ``init`` record's ``set`` counts. Lean 4 proves the fold holds an
upatch exactly when the last record that bears on it, an ``init`` record
or a load or unload of it, leaves it loaded: its load, or an ``init``
record whose ``set`` lists it, with that payload.

``status`` compares the replay with the live register (condition
``ChainIntact``, field ``tpm.chain_matches_eventlog`` in
:doc:`formats/status-json`). It also reports a mismatch when the register's
name differs from the recorded ``nv_name``, when the recorded PCR values
and writer key do not give that name, and when two ``init`` records
name the same TPM reset count. ``shirudo attest`` puts the selected
records, verbatim, in the evidence's ``eventlog`` array, see
:doc:`/operate/run/attest`.

Pending record
--------------

``shirudo init`` run from the initrd writes its ``init`` record to
``/run/shirudo/eventlog.pending``. ``/run`` survives the switch to the
root file system. The ``init`` run of ``shirudo.service`` on the root
file system adopts it: it appends each pending line that this boot's
part of the eventlog does not already hold, then removes the pending
file. Any other append adopts a pending record first. Every reader
takes the pending record only from a ``/run/shirudo`` that carries the
seal label, and only when the file carries it too: a ``/run`` of root's
making, in a mount namespace of its own, cannot carry it.

Size limits
-----------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Limit
     - Behavior
   * - ``eventlog.max_bytes``
     - Signed config setting, default ``0`` (unlimited), see
       :doc:`configuration`. ``init``, ``upatch load`` and
       ``upatch unload`` refuse before they change anything when the
       eventlog size plus 4096 bytes exceeds it. ``upatch load`` and
       ``upatch unload`` report category ``eventlog_full`` (``ENOSPC``,
       phase ``pre_flight``). ``init`` fails without binding the
       register. ``tree_op``, ``key_revoke`` and revocation ``upatch_unload``
       records are appended without this check.
   * - Reader cap, 8 MiB
     - Readers load at most 8388608 bytes: the eventlog alone, and the
       eventlog and the pending record together. Above that the replay
       fails. ``status`` then reports ``ChainIntact`` ``ALERT`` and the
       verdict ``tampered``, ``upatch load`` and ``upatch unload`` fail
       with ``tpm_error``, and ``init`` refuses to bind the register.

The eventlog grows across boots and shirudo never shortens it. Keep
``eventlog.max_bytes`` at or below 8388608 so that a refusal with
``eventlog_full`` comes before the reader cap.

Example
-------

``shirudo status --include-eventlog`` on a test target after one boot,
one load and one unload prints the eventlog as a table (excerpt):

.. code-block:: text

   Eventlog:
     TIME                 TYPE          DIGEST        DETAIL
     2026-10-29T16:17:38Z init          cb206abf8e51  set_digest=e3b0c44298fc..
     2026-10-29T16:21:19Z upatch_load   d979b373d4e5  shirudo-test-basic payload=8aee7072a1a1..
     2026-10-29T16:21:20Z upatch_unload 26dae981e9bb  shirudo-test-basic payload=8aee7072a1a1..

The ``upatch_load`` record of that eventlog, one line:

.. code-block:: json

   {"schema":1,"ts":"2026-10-29T16:21:19Z","nv_index":"0x01818E00","alg":"sha256","digest":"d979b373d4e5c59775c06c3bee5fd868d9d033db5403b290b61b512d4a293597","type":"upatch_load","boot_id":"743acb26-a7ee-405d-b45a-600484470644","upatch":{"name":"shirudo-test-basic","payload_sha256":"8aee7072a1a15e4dddc93ad6b253a0e2e70ad6cdf767442aa8a1c1997bc3069f"}}

Its ``init`` record, indented here, with the 768 hex digits of
``nv_writer_public`` shortened:

.. code-block:: json

   {
     "schema": 1,
     "ts": "2026-10-29T16:17:38Z",
     "nv_index": "0x01818E00",
     "alg": "sha256",
     "digest": "cb206abf8e514bc714fc69f372d464d2c7512f1489431aed2319551c5ed34b9a",
     "type": "init",
     "boot_id": "743acb26-a7ee-405d-b45a-600484470644",
     "tpm_reset_count": 1,
     "cert_sha256": "51a99fe89f5069a4d67131da3e1556dedbac7b2a1ec6702c51ca170c45d01d65",
     "certs": [
       "3702e8ffe817ade6151eea338194649cc3a5be1e0b940e462a1a75e52f7095d0",
       "d95db97ff4658b96b8b538afef41a25ca9f7a2c4d0abffdb26cbac7b0ba294b9"
     ],
     "set_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
     "tree_root": "0000000000000000000000000000000000000000000000000000000000000000",
     "set": [],
     "pcr": 9,
     "pcr_before": "0000000000000000000000000000000000000000000000000000000000000000",
     "phase_pcr": 11,
     "phase_before": "0000000000000000000000000000000000000000000000000000000000000000",
     "bound_in": "initrd",
     "nv_name": "000be3a552e2219550d2597ab96f3fffdeec0d01ce27cde858e0858ab0cdaba6c045",
     "nv_writer_public": "b4d7434fadbc7cb1a0d6...e07197",
     "anchor": "nvpcr-init:shirudo:0x1818e00:000be3a552e2219550d2597ab96f3fffdeec0d01ce27cde858e0858ab0cdaba6c045",
     "anchor_digest": "6912e5d20117d2eb4d2e55429bf666b1bb24ea2cd3882468411b1192f3940d50",
     "chain": "d1bdb80f7c0cfc1560f0a5a0b974d282bfd05fc95852b7649d59a054b450aa51"
   }

The test VM boots without a measured UKI, so PCR 9 and PCR 11 were zero
when ``init`` bound the register. Folding the three digests from 32
zero bytes gives
``e57e1428ab398e758b63f8eda52bac87b5d85c1368c2d8d786ed446448e46239``,
the register value ``status`` showed after the unload.

Related
-------

- :doc:`/internals/measurement-register`
- :doc:`/operate/run/attest`
- :doc:`formats/status-json`
- :doc:`/reference/cli/status`
