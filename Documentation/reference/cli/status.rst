..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

shirudo status
==============

Report the local readiness and state of this host, and optionally send the
keepalive, the status record the TPM quotes, as an OTLP log, or print
its body.

Runs on: any host, and on a target as root with the runtime binary. It is the
only command that runs while a config activation is pending or cannot be
verified. Requires: nothing. It runs before ``init`` too. Changes measured
state: no.

Usage
-----

.. code-block:: none

   shirudo status [--json | --otel | --keepalive] [--check]
                  [--show-full] [--include-system] [--include-eventlog]

Description
-----------

``status`` reads the state of the host without changing it and prints a
report. The roles come from what is present:

- target: the certificate (:doc:`init` lists its path), the pinned LSM
  link ``/run/shirudo/bpffs/lsm_link`` or the ``.bpf`` keyring that
  ``init`` froze
- operator: ``/var/lib/shirudo/keys/signing_key.pem``

The report shows seven conditions, each ``OK``, ``WARN`` or ``ALERT``:
``LsmAttached``, ``KeyringSealed``, ``ChainIntact``,
``UpatchesMeasured``, ``TpmMeasured``, ``ConfigActive`` and
``XdpCovered``. The verdict is the first that applies of ``tampered``,
``lsm-off``, ``init-pending``, ``reboot-pending``, ``degraded`` and
``ok``, and its reason the first cause that applies:
:ref:`status-json-verdicts` lists them with the condition each raises.

The human report follows the verdict with the conditions, the tamper
and integrity counters that moved this boot and the loaded upatches. Three sections
are folded unless ``--show-full`` asks for them: the ``.bpf`` and
``.dm-verity`` keyrings with the certificates each should hold and the
key that holds each one, the TPM measurement state and the assets under
``/var/lib/shirudo``. On a target the keyrings unfold when
``KeyringSealed`` is not ``OK``, and the TPM measurement when
``ChainIntact`` or ``TpmMeasured`` is not. The last line names the
sections that stayed folded. :doc:`/operate/run/read-status` explains
each field and :doc:`/reference/formats/status-json` the JSON document.

With ``--otel``, ``status`` sends the keepalive, only when an endpoint
is configured: ``map_export.otel_endpoint``, else
``OTEL_EXPORTER_OTLP_LOGS_ENDPOINT``, else
``OTEL_EXPORTER_OTLP_ENDPOINT``. It builds the keepalive body described
below, has the TPM's attestation key quote the SHA-256 of the body, and
sends one OTLP log record named ``shirudo.keepalive`` with the body as a
string and the quote as its one attribute, ``shirudo.quote``
(:doc:`/reference/formats/keepalive`). The attestation key is the one
:doc:`attest` uses, created for the quote and flushed after it. When no
TPM answers or the quote fails, ``status`` sends nothing, says why on
standard error and exits 1: a keepalive without a quote is worth nothing
to the backend. Without an endpoint it sends nothing, quotes nothing and
says nothing, except while a config activation is pending or
unverifiable, when it prints a warning. ``--otel`` alone prints nothing
on standard output. Add ``--json`` to print the JSON report too; it is
the full document, not the keepalive body, and ``--include-system`` and
``--include-eventlog`` change only it.

With ``--keepalive``, ``status`` prints the keepalive body, the compact
status record a node's TPM quotes, as one line on standard output. It
neither quotes nor sends it and needs no TPM, so an operator can see
what a node reports. Its keys, their order and their encoding are in
:ref:`keepalive-body-format`.

``status`` holds the config operation lock for its whole run, as every
target command does, a ``bpm tree sync`` included. It therefore never
reads a tree a sync is changing: while one runs, ``status`` waits up to
30 seconds for the lock and then fails, and no body is printed or
sent. A sync writes ``pending.json`` before it loads or unloads anything
and removes it only after ``state.json`` has the new ``last_seq``, so
``tree_op_pending`` says a sync stopped in the middle of an operation
and the next sync completes it. ``status`` still reads ``state.json``,
looks for ``pending.json``, reads the outcomes up to that ``last_seq``
and the loaded upatches, then looks for ``pending.json`` and reads
``state.json`` again, and starts over when the second ``state.json``
differs from the first, three times in all, printing the last read with
``snapshot_unsettled`` set; under the lock that happens only if
something writes the tree without it. With both flags clear the tree
keys and the loaded set describe one point. The two flags say the node
is busy, not that it is unhealthy.

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 26 14 12 48

   * - Option
     - Argument
     - Default
     - Description
   * - ``--json``
     - none
     - off
     - Print the report as one JSON document.
   * - ``--otel``
     - none
     - off
     - Quote the keepalive body with the TPM and send it as an OTLP log
       record.
   * - ``--keepalive``
     - none
     - off
     - Print the keepalive body without quoting or sending it. Not with
       ``--json`` or ``--otel``.
   * - ``--include-system``
     - none
     - off
     - Add the system section: operating system, kernel release, version
       and build ID, architecture, CPUs, memory, disk, uptime, machine ID
       and boot ID. The JSON ``system`` object carries the host name too.
   * - ``--include-eventlog``
     - none
     - off
     - Add the eventlog records, all boots.
   * - ``--check``
     - none
     - off
     - Exit 1 when the verdict is ``tampered``.
   * - ``--show-full``
     - none
     - off
     - Print the folded sections, the keyrings, the TPM measurement and
       the assets, whatever their conditions say, and turn on
       ``--include-system`` and ``--include-eventlog``.

Exit status
-----------

``status`` exits with 0 whatever the verdict, ``tampered`` included,
unless ``--check`` is given, which exits 1 for ``tampered``. Monitoring
reads ``.status`` and the conditions from the JSON document.

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - The report was produced.
   * - 1
     - With ``--check``: the verdict is ``tampered``. With ``--otel``:
       the configuration cannot be loaded, the body cannot be built, no
       TPM answered, the quote failed or the OTLP request failed.
       With ``--json``: the document does not fit the output buffer.
       With ``--keepalive``: the body cannot be built. Also an allocation
       failure.
   * - 2
     - A usage error: an unknown option, an option given twice or an
       argument, ``--keepalive`` with ``--json`` or ``--otel``. Or, with
       ``--otel``, an invalid ``map_export`` configuration.

Files and environment
---------------------

- Reads ``/run/shirudo/bpffs`` (pins, identity, tamper and integrity
  counters), the
  ``.bpf`` and ``.dm-verity`` keyrings, the TPM register,
  ``/var/lib/shirudo/eventlog``, ``/var/lib/shirudo/keys``, the config
  certificate the runtime image's bootstrap names and the config
  activation records
- With ``--keepalive`` or ``--otel``: ``state.json``, ``pending.json``, ``outcomes``,
  ``tree-eventlog`` and ``status/`` under
  ``/var/lib/shirudo/bpm/upatch-tree``, ``/etc/os-release`` (else
  ``/usr/lib/os-release``), ``/proc/cmdline`` and
  ``/proc/sys/kernel/random/boot_id``
- With ``--otel``: the TPM, ``map_export.*`` and the
  ``OTEL_EXPORTER_OTLP_*`` variables (see :doc:`/reference/environment`).
  ``shirudo-keepalive.service`` reads them from
  ``/etc/shirudo/map-export.env``

Examples
--------

Show the state of a target:

.. code-block:: console

   target# shirudo status
   Host:                  docs
   Roles:                 target
   Status:                ok
   Version ID:            d0d7aa800303439023907d1979d917d46a21bec21f816689c138728a28e84af9

   Conditions:
     TYPE               STATUS  DETAIL
     LsmAttached        OK      lsm/bpf link present and pinned
     KeyringSealed      OK      bpf serial 272801410, dm-verity serial 799624487, pins match
     ChainIntact        OK      live register equals the eventlog replay
     UpatchesMeasured   OK      every pinned or archived upatch is in this boot's records
     TpmMeasured        OK      NV index 0x01818E00 readable
     ConfigActive       OK      config 6d5ed552f448.. is active
     XdpCovered         OK      every device an XDP upatch selects runs it

   Tamper attempts (this boot):
     LoadNotLoader            15  program load that is not a signed loader
     MapCreate                 1  map creation by another executable
     BpfCommand                8  detach, update, delete or unclassified bpf() command
     BpffsUmount               1  unmount of the private bpffs
     SealWrite                 1  write open of a sealed file
     SealEntry                 2  entry into a sealed directory, or a sealed inode linked

   Integrity attempts (this boot):
     none

   Loaded upatches (1):
     NAME                      LOCATION                       MAPS  MISSED  STATUS                        AGE
     shirudo-test-basic        fentry/do_nanosleep               0       0  success                       1s

   Folded: keyrings, TPM measurement, assets (--show-full)

Show the folded sections too. ``--show-full`` adds the eventlog and the
system as well:

.. code-block:: console

   target# shirudo status --show-full
   Host:                  docs
   Roles:                 target
   Status:                ok
   Version ID:            d0d7aa800303439023907d1979d917d46a21bec21f816689c138728a28e84af9

   Conditions:
     TYPE               STATUS  DETAIL
     LsmAttached        OK      lsm/bpf link present and pinned
     KeyringSealed      OK      bpf serial 272801410, dm-verity serial 799624487, pins match
     ChainIntact        OK      live register equals the eventlog replay
     UpatchesMeasured   OK      every pinned or archived upatch is in this boot's records
     TpmMeasured        OK      NV index 0x01818E00 readable
     ConfigActive       OK      config 6d5ed552f448.. is active
     XdpCovered         OK      every device an XDP upatch selects runs it

   Tamper attempts (this boot):
     LoadNotLoader            15  program load that is not a signed loader
     MapCreate                 1  map creation by another executable
     BpfCommand                8  detach, update, delete or unclassified bpf() command
     BpffsUmount               1  unmount of the private bpffs
     SealWrite                 1  write open of a sealed file
     SealEntry                 2  entry into a sealed directory, or a sealed inode linked

   Integrity attempts (this boot):
     none

   Loaded upatches (1):
     NAME                      LOCATION                       MAPS  MISSED  STATUS                        AGE
     shirudo-test-basic        fentry/do_nanosleep               0       0  success                       1s

   Keyring (.bpf):
     Serial:                272801410
     Frozen serial:         272801410  (matches)
     Certificates:          2 trusted, 0 revoked, 0 unvouched, 2 in the bpf keyring
       a8be2bb837b0f052f7652f9edf446594a5465eed614d939964ddfcc96e61ba7f
         CN=shirudo, ML-DSA-87, issued 2026-11-03
         key 465853497  shirudo: 30dee65057025367c4c384928bcf1e4cd8fe0265  (frozen)
       6bd6b1a28b631295a013102d358d371d52ab1c894587aedceaf02e472c88f858  (primary)
         CN=shirudo, ML-DSA-87, issued 2026-11-03
         key 91435879  shirudo: 7fa1d435249690766f8b1397122775d26f1ed92e  (frozen)

   Keyring (.dm-verity):
     Serial:                799624487
     Frozen serial:         799624487  (matches)
     Certificates:          1 trusted, 1 in the dm-verity keyring
       6bd6b1a28b631295a013102d358d371d52ab1c894587aedceaf02e472c88f858  (config)
         CN=shirudo, ML-DSA-87, issued 2026-11-03
         key 403194297  shirudo: 7fa1d435249690766f8b1397122775d26f1ed92e  (frozen)

   TPM measurement:
     TPM:                   reachable (device:/dev/tpmrm0)
     NV index:              0x01818E00 (anchored in PCR 9)
     Chain:                 7f63313a31ac8ddd3a6a16fce2038322c9c782d5787155d2dc18dfa582dff548
     Register name:         000b21eb0d45ac9ee1bb0a87dbb069120e3b8cb251b3d40cc2a86a307ab73f728789
     Anchored:              yes, name on record
     PCR before init:       0000000000000000000000000000000000000000000000000000000000000000
     Phase at init:         0000000000000000000000000000000000000000000000000000000000000000 (PCR 11)
     Bound in:              initrd
     Chain vs eventlog:     matches
     Eventlog:              /var/lib/shirudo/eventlog  (2 entries, 2324 bytes)

   Eventlog:
     TIME                 TYPE          DIGEST        DETAIL
     2026-11-03T14:53:17Z init          377ce174fb1f  set_digest=e3b0c44298fc..
     2026-11-03T14:54:33Z upatch_load   d979b373d4e5  shirudo-test-basic payload=8aee7072a1a1..

   Assets (/var/lib/shirudo):
     keys/cert.der          present
     keys/signing_key.pem   absent
     eventlog               present (2324 bytes)
     upatches/              1 archived
     bpffs/                 mounted

   System:
     OS:                    Ubuntu 26.04.1 LTS
     Kernel:                7.3.0-bpf-next+
     Kernel version:        #1 SMP PREEMPT Tue Nov  3 13:54:40 UTC 2026
     Kernel build ID:       132d1451aab18a693c59d5b9519d25a06f2236bf
     Architecture:          x86_64
     CPUs:                  4
     Memory:                314M/3.85G
     Disk:                  1.99G/6.61G
     Uptime:                0d 0h 1m
     Machine ID:            6bae4cfbc0ed04ed63cc4cf8cb0a1b6c
     Boot ID:               82639935-1127-4dab-91b5-f818eabc7f13

Read the verdict in a script:

.. code-block:: console

   target# shirudo status --json | jq -r .status
   ok

Print the keepalive body of the same target, which follows no tree:

.. code-block:: console

   target# shirudo status --keepalive
   {"schema":"shirudo.keepalive/1","boot_id":"82639935-1127-4dab-91b5-f818eabc7f13","version_id":"d0d7aa800303439023907d1979d917d46a21bec21f816689c138728a28e84af9","config_root":"6d5ed552f448a1c07e3b9d24f5a86c1e0b7d93f2c4e5a6b7180c9d2e3f4a5b6c","kernel_release":"7.3.0-bpf-next+","image_id":null,"image_version":null,"image_root":null,"verdict":"ok","cond":5461,"flags":0,"tamper":[15,0,0,0,0,1,0,0,0,0,0,8,0,0,0,0,0,1,0,0,1,0,0,0,0,0,7,0,0,2,0,0,0,0,0,0,0,0,0,0,0,0],"integrity":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"tree_id":null,"generation":null,"base_seq":null,"last_seq":null,"base_root":null,"projection_root":null,"mask":null,"set_sha256":"5f0c2e8b7a1d4c3f9e6b2a0d8c7f1e3b5a9d4c2e6f8b0a1d3c5e7f9b2d4a6c8e","count":1,"not_ok":0}

Add this boot's eventlog to the report:

.. code-block:: console

   target# shirudo status --include-eventlog

The eventlog section of that report:

.. code-block:: none

   Eventlog:
     TIME                 TYPE          DIGEST        DETAIL
     2026-11-03T14:53:17Z init          377ce174fb1f  set_digest=e3b0c44298fc..
     2026-11-03T14:54:33Z upatch_load   d979b373d4e5  shirudo-test-basic payload=8aee7072a1a1..
     2026-11-03T14:54:35Z upatch_unload 26dae981e9bb  shirudo-test-basic payload=8aee7072a1a1..

Related
-------

- :doc:`/operate/run/read-status`
- :doc:`/reference/formats/status-json`
- :doc:`/security/tamper-counters`
- :doc:`/operate/troubleshoot/incident-tampered`
- :doc:`/operate/run/telemetry`
