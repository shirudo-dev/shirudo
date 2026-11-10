..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

shirudo status
==============

Report the local readiness and state of this host, and optionally send the
report as an OTLP keepalive.

Runs on: any host, and on a target as root with the runtime binary. It is the
only command that runs while a config activation is pending or cannot be
verified. Requires: nothing. It runs before ``init`` too. Changes measured
state: no.

Usage
-----

.. code-block:: none

   shirudo status [--json | --otel] [--check] [--show-full]
                  [--include-system] [--include-eventlog]

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
``XdpCovered``. The verdict is the first of these that applies:

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Verdict
     - Applies when
   * - ``tampered``
     - The live register differs from the eventlog replay, the ``.bpf``
       or ``.dm-verity`` keyring is not the one ``init`` froze or is
       gone, a keyring holds a link ``init`` did not freeze, the config
       key is gone from ``.dm-verity``, a upatch is pinned or archived
       without a record of this boot, or the selected config cannot be verified
       against its records.
   * - ``lsm-off``
     - The LSM link is not pinned.
   * - ``init-pending``
     - ``init`` has not frozen a ``.bpf`` keyring this boot.
   * - ``reboot-pending``
     - A config activation is pending until the next reboot.
   * - ``degraded``
     - No TPM answered, no register is bound this boot, or a device an
       XDP upatch selects does not run it.
   * - ``ok``
     - None of the above.

The human report follows the verdict with the conditions, the tamper
counters that moved this boot and the loaded upatches. Three sections
are folded unless ``--show-full`` asks for them: the ``.bpf`` and
``.dm-verity`` keyrings with the certificates each should hold and the
key that holds each one, the TPM measurement state and the assets under
``/var/lib/shirudo``. On a target the keyrings unfold when
``KeyringSealed`` is not ``OK``, and the TPM measurement when
``ChainIntact`` or ``TpmMeasured`` is not. The last line names the
sections that stayed folded. :doc:`/operate/run/read-status` explains
each field and :doc:`/reference/formats/status-json` the JSON document.

With ``--otel``, ``status`` builds the JSON report and sends it as one
OTLP log record named ``shirudo.keepalive``, only when an endpoint is
configured: ``map_export.otel_endpoint``, else
``OTEL_EXPORTER_OTLP_LOGS_ENDPOINT``, else
``OTEL_EXPORTER_OTLP_ENDPOINT``. Without an endpoint it sends nothing and
says nothing, except while a config activation is pending or unverifiable,
when it prints a warning. ``--otel`` alone prints nothing on standard
output. Add ``--json`` to print the document too.

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
     - Send the JSON report as an OTLP keepalive log record.
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
       the configuration cannot be loaded or the OTLP request failed.
       With ``--json``: the document does not fit the output buffer.
       Also an allocation failure.
   * - 2
     - An unknown option, or with ``--otel`` an invalid ``map_export``
       configuration.

Files and environment
---------------------

- Reads ``/run/shirudo/bpffs`` (pins, identity, tamper counters), the
  ``.bpf`` and ``.dm-verity`` keyrings, the TPM register,
  ``/var/lib/shirudo/eventlog``, ``/var/lib/shirudo/keys``, the config
  certificate the runtime image's bootstrap names and the config
  activation records
- With ``--otel``: ``map_export.*`` and the ``OTEL_EXPORTER_OTLP_*``
  variables (see :doc:`/reference/environment`).
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
     SealPtrace                7  ptrace of a shirudo task
     SealEntry                 2  entry into a sealed directory, or a sealed inode linked

   Loaded upatches (1):
     NAME                      LOCATION                       MAPS  STATUS                        AGE
     shirudo-test-basic        fentry/do_nanosleep               0  success                       1s

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
     SealPtrace                7  ptrace of a shirudo task
     SealEntry                 2  entry into a sealed directory, or a sealed inode linked

   Loaded upatches (1):
     NAME                      LOCATION                       MAPS  STATUS                        AGE
     shirudo-test-basic        fentry/do_nanosleep               0  success                       1s

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
     incoming/              empty
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
