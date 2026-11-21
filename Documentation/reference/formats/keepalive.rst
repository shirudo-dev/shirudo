..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

Keepalive
=========

The keepalive is the status record a target's TPM quotes and sends to
its collector: one OTLP log record that ``shirudo status --otel`` sends
when ``shirudo-keepalive.timer`` runs it. The transport, the endpoint
and the resource it shares with the map documents are in :doc:`otlp`.

.. _keepalive-format:

Log record
----------

One log record in ``resourceLogs[0].scopeLogs[0].logRecords``:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Field
     - Value
   * - ``timeUnixNano``, ``observedTimeUnixNano``
     - Wall clock when shirudo builds the document, nanoseconds since
       the epoch, decimal string.
   * - ``severityNumber``, ``severityText``
     - ``9`` ``INFO`` for ``ok``. ``13`` ``WARN`` for ``degraded``,
       ``init-pending`` and ``reboot-pending``. ``17`` ``ERROR`` for
       every other verdict, ``tampered`` and ``lsm-off`` included.
   * - ``eventName``
     - ``shirudo.keepalive``
   * - ``body``
     - ``{"stringValue": <body>}``: the keepalive body
       (:ref:`keepalive-body-format`) as one string, never a
       ``kvlistValue``. A collector
       may re-encode a structure, and the quote covers these exact
       bytes.
   * - Attribute ``shirudo.quote``
     - The one attribute, a string: the TPM quote of the body, below.

``timeUnixNano`` and the resource attributes are for display only. They
identify nothing and order nothing; the quote does both.

``shirudo.quote`` has three fields in this order, separated by ``;``
with no blanks, each in standard base64 with padding:

.. code-block:: none

   attest=<TPMS_ATTEST>;sig=<TPMT_SIGNATURE>;ak=<TPMT_PUBLIC>

.. list-table::
   :header-rows: 1
   :widths: 14 86

   * - Field
     - Value
   * - ``attest``
     - The ``TPMS_ATTEST`` the TPM signed, without the ``TPM2B`` size: a
       ``TPM2_Quote`` whose qualifying data is the SHA-256 of the body
       bytes and whose PCR selection is one SHA-256 bank with no PCR set.
       Its clock information, ``resetCount`` and ``clock``, orders the
       keepalives of one node.
   * - ``sig``
     - The marshalled ``TPMT_SIGNATURE`` over ``attest``: ECDSA with
       SHA-256.
   * - ``ak``
     - The marshalled ``TPMT_PUBLIC`` of the attestation key, without
       the ``TPM2B`` size: the fixed-template P-256 ECDSA primary under
       the endorsement hierarchy that :doc:`/reference/cli/attest` uses.
       ``000b`` and the SHA-256 of these bytes is the key's name, which
       identifies the node. The quote's signer is the key's qualified
       name under the endorsement hierarchy.

:doc:`/reference/cli/quote-check` checks a quote against its body without
a TPM. An attestation quote always selects a PCR, so it cannot pass as
a keepalive quote. A quote that checks proves that the body is
unchanged since the key signed it, not that the key lives in a TPM.

When no TPM answers or the quote fails, ``status --otel`` sends nothing.
A body that JSON cannot carry unchanged, one with a NUL byte or
malformed UTF-8, is not sent either; the body ``status`` builds is never
one.

The keepalive uses ``map_export.otel_endpoint``,
``map_export.tenant_id``, ``map_export.otel_insecure``,
``map_export.otel_retries`` and ``map_export.otlp_max_bytes``.
``status --otel`` exits ``1`` when the export fails and ``2`` when the
``map_export.*`` settings are invalid.

.. _keepalive-body-format:

Keepalive body
--------------

The body is the record the quote covers, the bytes that ``status
--keepalive`` prints. It is one compact JSON object in UTF-8: no blank
or newline between tokens, no trailing newline, at most 4095 bytes. Its
23 keys are always present and come in the order of the tables below,
which group them as identity, health, upatch tree and loaded set; a key
that does not apply is ``null``, never left out. A hash is 64 lowercase
hex digits. An integer is a JSON number with no sign, fraction or
exponent.

.. code-block:: none

   Identity      schema boot_id version_id config_root kernel_release
                 image_id image_version image_root
   Health        verdict cond flags tamper integrity
   Upatch tree   tree_id generation base_seq last_seq base_root
                 projection_root mask
   Loaded set    set_sha256 count not_ok

A collector reads a condition, a tamper counter and an integrity counter
by its place. A new one is added after the last, never put between two.

Identity
~~~~~~~~

Which boot, build, configuration, kernel and image the record speaks
for. Nothing in the body names the host: the attestation key of the
quote identifies the node.

.. list-table::
   :header-rows: 1
   :widths: 18 16 66

   * - Key
     - Type
     - Value
   * - ``schema``
     - string
     - ``shirudo.keepalive/1``.
   * - ``boot_id``
     - string
     - The kernel's ``/proc/sys/kernel/random/boot_id``, a UUID.
   * - ``version_id``
     - hash
     - The binary's ``SHIRUDO_VERSION_ID``, as ``shirudo version
       --version-id`` prints it (:doc:`/reference/versions`).
   * - ``config_root``
     - hash or ``null``
     - The dm-verity root of the selected signed config image. ``null``
       unless that config is active.
   * - ``kernel_release``
     - string
     - The kernel release, as ``uname -r`` prints it.
   * - ``image_id``
     - string or ``null``
     - ``IMAGE_ID`` of ``/etc/os-release``, else of
       ``/usr/lib/os-release``. ``null`` when neither has it.
   * - ``image_version``
     - string or ``null``
     - ``IMAGE_VERSION`` of the same file. ``null`` when it has none.
   * - ``image_root``
     - hash or ``null``
     - ``roothash=`` of the kernel command line, else ``usrhash=``,
       lowercased. ``null`` when neither is there or the one taken is
       not 64 hex digits.

Health
~~~~~~

What the node reports about itself, as ``shirudo status`` evaluates it.
The detail strings of the conditions stay in ``status --json``; the body
carries only the outcomes.

.. list-table::
   :header-rows: 1
   :widths: 18 16 66

   * - Key
     - Type
     - Value
   * - ``verdict``
     - string
     - The verdict of :doc:`/reference/cli/status`: ``tampered``,
       ``lsm-off``, ``init-pending``, ``reboot-pending``, ``degraded``
       or ``ok``.
   * - ``cond``
     - integer
     - The seven conditions, two bits each, 0 to 16383.
   * - ``flags``
     - integer
     - Bits that qualify what the body reports.
   * - ``tamper``
     - array of integers or ``null``
     - Every counter of :doc:`/security/tamper-counters`, zeros
       included, in the order of that page. ``null`` with
       ``tamper_unavailable``.
   * - ``integrity``
     - array of integers or ``null``
     - Every counter of :doc:`/security/integrity-counters` the same
       way. ``null`` with ``integrity_unavailable``.

``cond`` holds two bits per condition, condition *i* at bits ``2i`` and
``2i+1``:

.. list-table::
   :header-rows: 1
   :widths: 10 30 60

   * - *i*
     - Condition
     - Bits
   * - 0
     - ``LsmAttached``
     - 0 and 1
   * - 1
     - ``KeyringSealed``
     - 2 and 3
   * - 2
     - ``ChainIntact``
     - 4 and 5
   * - 3
     - ``UpatchesMeasured``
     - 6 and 7
   * - 4
     - ``TpmMeasured``
     - 8 and 9
   * - 5
     - ``ConfigActive``
     - 10 and 11
   * - 6
     - ``XdpCovered``
     - 12 and 13

Each pair is ``00`` not evaluated, ``01`` ``OK``, ``10`` ``WARN`` or
``11`` ``ALERT``. All seven ``OK`` is ``5461``.

The bits of ``flags``:

.. list-table::
   :header-rows: 1
   :widths: 8 24 68

   * - Bit
     - Name
     - Set when
   * - 0
     - ``register_rebound``
     - The register was bound more than once for this TPM reset.
   * - 1
     - ``bound_late``
     - This boot's ``init`` record says the register was bound from the
       root file system, not from the initrd.
   * - 2
     - ``tree_log_mismatch``
     - The tree eventlog does not replay to the ``projection_root`` of
       ``state.json``, or the outcomes record lacks a line the window
       needs; ``base_root`` and ``mask`` are then ``null``.
   * - 3
     - ``tamper_unavailable``
     - The tamper counters cannot be read; ``tamper`` is ``null``.
   * - 4
     - ``tree_op_pending``
     - A tree operation was left in flight: ``pending.json`` existed
       before or after the read, after a sync stopped mid-operation.
   * - 5
     - ``snapshot_unsettled``
     - ``state.json`` kept changing while the body was read, which the
       config operation lock leaves to a writer outside it.
   * - 6
     - ``integrity_unavailable``
     - The integrity counters cannot be read; ``integrity`` is ``null``.

Upatch tree
~~~~~~~~~~~

Where the node is in the upatch tree it follows and what it did at each
operation of a window of the last 512. All seven keys are ``null`` when
the node follows no tree or its tree state cannot be read. The window
and the outcomes come from the outcomes record of
:doc:`/reference/formats/upatch-tree`, which keeps every operation the
node processed, those of sealed segments included.

.. list-table::
   :header-rows: 1
   :widths: 18 16 66

   * - Key
     - Type
     - Value
   * - ``tree_id``
     - string or ``null``
     - The ``tree_id`` of the upatch tree the node follows
       (:ref:`upatch-tree-format`).
   * - ``generation``
     - integer or ``null``
     - The ``generation`` of the publication the node recorded.
   * - ``base_seq``
     - integer or ``null``
     - The sequence number the window starts after: the head of the
       recorded publication less 512, or 0 for a tree of 512 operations
       or fewer.
   * - ``last_seq``
     - integer or ``null``
     - The last operation the node processed.
   * - ``base_root``
     - hash or ``null``
     - The node's projection root after ``base_seq``, 64 zeros at 0.
       ``null`` with ``tree_log_mismatch``.
   * - ``projection_root``
     - hash or ``null``
     - The node's projection root after ``last_seq``, as ``state.json``
       records it.
   * - ``mask``
     - string or ``null``
     - The outcome of every operation of the window. ``""`` for a
       window of no operation, ``null`` with ``tree_log_mismatch``.

``mask`` is standard base64 with padding of two bits per operation, from
``base_seq + 1`` to the head of the recorded publication: ``01``
applied, ``10`` passed over, ``11`` module absent, ``00`` not reached,
which every operation past ``last_seq`` is. The first operation takes
the two highest bits of the first byte, the next the two below them,
and the last byte is padded with ``00``. A full window of 512 operations
is 128 bytes, 172 characters.

Loaded set
~~~~~~~~~~

What is loaded now, as one hash and two counts, the same size for one
upatch or a thousand.

.. list-table::
   :header-rows: 1
   :widths: 18 16 66

   * - Key
     - Type
     - Value
   * - ``set_sha256``
     - hash
     - SHA-256 over a ``<payload_sha256> <name>`` line for every loaded
       upatch, sorted by name: the ``set_digest`` form of the ``init``
       event (:doc:`/reference/eventlog`), without the ``java`` prefix
       that event gives a Java upatch, as a tree operation names no
       payload type. Upatches loaded outside the tree are included.
   * - ``count``
     - integer
     - The upatches loaded.
   * - ``not_ok``
     - integer
     - The loaded upatches the tree holds a status file for.

Example
~~~~~~~

The body of a target with verdict ``ok`` that follows no tree:

.. code-block:: json

   {"schema":"shirudo.keepalive/1","boot_id":"82639935-1127-4dab-91b5-f818eabc7f13","version_id":"d0d7aa800303439023907d1979d917d46a21bec21f816689c138728a28e84af9","config_root":"6d5ed552f448a1c07e3b9d24f5a86c1e0b7d93f2c4e5a6b7180c9d2e3f4a5b6c","kernel_release":"7.3.0-bpf-next+","image_id":null,"image_version":null,"image_root":null,"verdict":"ok","cond":5461,"flags":0,"tamper":[15,0,0,0,0,1,0,0,0,0,0,8,0,0,0,0,0,1,0,0,1,0,0,0,0,0,7,0,0,2,0,0,0,0,0,0,0,0,0,0,0,0,0],"integrity":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"tree_id":null,"generation":null,"base_seq":null,"last_seq":null,"base_root":null,"projection_root":null,"mask":null,"set_sha256":"5f0c2e8b7a1d4c3f9e6b2a0d8c7f1e3b5a9d4c2e6f8b0a1d3c5e7f9b2d4a6c8e","count":1,"not_ok":0}

Keepalive document
------------------

The keepalive of a target with verdict ``ok``, as the code builds it.
Angle brackets mark values that vary, and the body string is shortened
to its first keys:

.. code-block:: json

   {
     "resourceLogs": [
       {
         "resource": {
           "attributes": [
             {"key": "service.name", "value": {"stringValue": "shirudo"}},
             {"key": "service.version", "value": {"stringValue": "<version>"}},
             {"key": "host.name", "value": {"stringValue": "<host>"}}
           ]
         },
         "scopeLogs": [
           {
             "scope": {"name": "shirudo.keepalive", "version": "<version>"},
             "logRecords": [
               {
                 "timeUnixNano": "<ns>",
                 "observedTimeUnixNano": "<ns>",
                 "severityNumber": 9,
                 "severityText": "INFO",
                 "eventName": "shirudo.keepalive",
                 "body": {
                   "stringValue": "{\"schema\":\"shirudo.keepalive/1\",\"boot_id\":\"<boot-id>\",\"version_id\":\"<version-id>\",...}"
                 },
                 "attributes": [
                   {"key": "shirudo.quote", "value": {"stringValue": "attest=<base64>;sig=<base64>;ak=<base64>"}}
                 ]
               }
             ]
           }
         ]
       }
     ]
   }

Related
-------

- :doc:`otlp`
- :doc:`/reference/cli/status`
- :doc:`/reference/cli/quote-check`
- :doc:`/operate/run/telemetry`
- :doc:`/operate/backend/index`
