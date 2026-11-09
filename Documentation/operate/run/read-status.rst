..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators, SecOps

Read shirudo status
===================

``shirudo status`` is the target's own report on its enforcement, its
``.bpf`` keyring, its measurement register and its signed config. It is
the first command to run on a target that misbehaves, and the keepalive
timer sends the same data to your collector. It is the target's account
of itself: anyone with root on the target can lie to a reader of this
report, so it proves nothing to a third party. TPM-signed evidence does,
see :doc:`/operate/run/attest`.

This page walks through a healthy report section by section, then
explains every verdict and what to do about it.

Before you begin
----------------

- You need root on the target.
- On the target, ``shirudo`` means the binary on the runtime image,
  ``/run/shirudo/runtime/usr/bin/shirudo``. Any other copy is refused.
  :ref:`runtime-invocation` shows how to set this up.

Print the report
----------------

1. Print the human report:

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

2. The report folds the sections whose condition is ``OK``: the
   keyrings, the TPM measurement and the assets. To print them all, and
   the system and eventlog sections with them:

   .. code-block:: console

      target# shirudo status --show-full

:doc:`/reference/cli/status` lists the options, ``--include-system`` and
``--include-eventlog`` among them.

Read the report
---------------

This is the full report of a healthy production target with one upatch
loaded, captured from the test VM with ``--show-full``. Without the
option the report ends after the loaded upatches and names the folded
sections, the keyrings, the TPM measurement and the assets, on its last
line; a section unfolds on its own when its condition is not ``OK``.

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

The sections below explain each part.

Header
~~~~~~

``Host``
    The host name.

``Roles``
    ``target`` when the primary certificate, the ``lsm/bpf`` pin or the
    keyring is present, ``operator`` when
    ``/var/lib/shirudo/keys/signing_key.pem`` exists, both as
    ``target, operator``, or ``none``. A production target shows
    ``target`` alone. A private signing key on a target breaks the
    operator and target split: remove it and treat the key as exposed,
    see :doc:`/operate/maintain/keys`.

``Status``
    The verdict, followed by the reason in parentheses when it is not
    ``ok``. :ref:`status-verdicts` explains each verdict.

``Version ID``
    The identifier of the shirudo build that runs. Compare it with the
    build you deployed, see :doc:`/operate/maintain/upgrade`.

Conditions
~~~~~~~~~~

Six conditions, each ``OK``, ``WARN`` or ``ALERT`` with a detail. The
verdict is derived from them.

.. list-table::
   :header-rows: 1
   :widths: 18 82

   * - Condition
     - What it checks, and the details other than ``OK``
   * - ``LsmAttached``
     - The ``lsm/bpf`` link is pinned. ``ALERT`` ``lsm/bpf link absent,
       enforcement off`` means enforcement did not come up this boot.
   * - ``KeyringSealed``
     - The live ``.bpf`` and ``.dm-verity`` keyrings are the ones
       ``init`` sealed and recorded in the frozen identity map, they
       hold no link ``init`` did not freeze, and ``.dm-verity`` still
       holds the config key. ``WARN`` ``.bpf keyring absent before
       init`` before ``init``. ``ALERT`` after it names the keyring
       and what changed: a swapped or missing keyring, links ``init``
       did not freeze, or the missing config key.
   * - ``ChainIntact``
     - The live register is the NV index ``init`` bound this boot, was
       bound once, and equals this boot's eventlog records replayed.
       ``ALERT`` ``live register differs from the eventlog replay``. ``WARN``
       ``no register bound this boot (init incomplete)`` or ``no TPM
       answered, no register to replay``.
   * - ``UpatchesMeasured``
     - Every upatch pinned in the private bpffs or archived under
       ``/var/lib/shirudo/upatches`` is in this boot's records: loaded
       with the payload its pin or archive records and not unloaded
       since. ``ALERT`` ``<n> pinned or archived without a record of
       this boot: <names>`` is what a load stopped between its pins and
       its extend leaves, or an archive root brought back after its
       unload, which the next ``upatch load`` or ``upatch unload``
       undoes before it acts. ``ALERT`` ``<n> XDP archives differ from
       the loaded payload: <names>``: the sealed archive of a loaded XDP
       upatch has changed, or is gone, so ``upatch reconcile`` refuses to
       run and new devices stay uncovered. Handle it as an incident:
       :doc:`/operate/troubleshoot/incident-tampered`. ``WARN`` ``no
       record of this boot to check the pins against`` before ``init``, or
       ``pins not checked against the records: <error>``.
   * - ``TpmMeasured``
     - The NV index is defined, written and readable. ``WARN`` ``NV
       index 0x01818E00 not bound this boot`` or ``no TPM answered``.
   * - ``ConfigActive``
     - The config PCR, the activation records and the mounted config
       image agree. ``WARN`` ``the activation of config <root>.. is
       pending until the next reboot``. ``ALERT`` with one of three
       details, see :ref:`status-verdicts`.

Tamper attempts
~~~~~~~~~~~~~~~

The counters of attempts this boot, one per guard point, each refused
there except ``SealSignal``, which is let through and counted, with the
counters that are not zero listed by name, count and meaning. ``none``
means every counter is zero. ``none recorded before init`` means
``init`` did not get as far as pinning the counters, and ``unavailable:
<error>`` that they could not be read.
:ref:`status-tamper-counters` explains how to read them.

Keyrings
~~~~~~~~

Two sections, ``Keyring (.bpf)`` for the keys that verify signed
loaders and ``Keyring (.dm-verity)`` for the key that verifies config
roots, read the same way.

``Serial``
    The serial of the kernel's keyring.

``Frozen serial``
    The serial ``init`` recorded when it sealed the keyring, followed by
    ``(matches)``, ``(swapped)`` or ``(gone)``.

``Certificates``
    The certificates the keyring should hold, and how many keys it
    holds. For ``.bpf`` this is the trusted set: the runtime image's
    primary certificate and the vouched certificates of the active
    signed config, less its revocations; ``unvouched`` counts
    certificates in the config without a valid vouch, which are
    therefore not members. :doc:`/operate/maintain/keys` explains the set. For
    ``.dm-verity`` it is the config certificate the runtime image names,
    marked ``(config)``.

    Each certificate follows with its public key fingerprint, the
    runtime image's ``.bpf`` certificate marked ``(primary)``, and two
    lines below it. The first gives the subject, the key algorithm and
    the date the certificate was issued, the start of its validity
    period. The end of that period is not shown: neither the kernel nor
    shirudo compares it with the clock, and a certificate stays trusted
    until a signed config revokes it. The second is the key that holds
    the certificate in the keyring, by serial and the kernel's
    description, ``(frozen)`` when ``init`` recorded it. ``not in the
    keyring (enrolled at the next boot)`` marks a ``.bpf`` certificate a
    config update added after the boot; ``not in the keyring (MISSING)``
    under ``.dm-verity`` means the config key is gone.

``Other links``
    Shown only when the keyring holds a link that is no certificate's
    key. Each line names the kind of link, ``key`` for a public key or
    the kernel's type such as ``keyring``, its serial and description,
    and ``(not frozen)`` when ``init`` did not record it. The kernel
    trusts every key such a link reaches, so ``KeyringSealed`` is
    ``ALERT`` and the verdict ``tampered``.

Loaded upatches
~~~~~~~~~~~~~~~

One row per upatch pinned in the private bpffs: its name, the attach
location resolved from kernel BTF, its number of maps, ``success`` and
the time since it was loaded. ``Loaded upatches (0):`` followed by
``none`` means nothing is loaded.

TPM measurement
~~~~~~~~~~~~~~~

``TPM``
    Whether a TPM answered, and the TCTI that reached it.

``NV index``
    The measurement register, ``0x01818E00``, and the PCR its name is
    anchored in.

``Chain``
    The register's value. It moves with every measured load, unload,
    revocation and tree operation.

``Register name``
    The TPM name of the NV index, which binds its attributes and policy.

``Anchored``
    ``yes, name on record`` when the index is the one ``init`` bound and
    recorded. ``no, the index is not the one init bound`` otherwise.

``PCR before init`` and ``Phase at init``
    The values of PCR 9 and PCR 11 that ``init`` bound the register to.
    A verifier pins them with ``--expect-bind-pcr``, see
    :doc:`/operate/run/attest`. In the capture above both are zero because
    the test VM boots its kernel and initrd directly, without a measured
    UKI. On a production target booted from a measured UKI, PCR 11 holds
    the ``enter-initrd`` phase measurement. ``init`` warns in the journal
    when it finds PCR 11 unmeasured.

``Bound in``
    ``initrd`` or ``root file system``. A production target shows
    ``initrd``. ``root file system`` means the first ``init`` of this
    boot ran after the initrd.

``Init records``
    Printed only when the register was bound more than once for this TPM
    reset: ``<n> for this TPM reset, rebound after init``.

``Chain vs eventlog``
    ``matches``, ``mismatch`` or ``not evaluated`` when there is no
    register to compare.

``Eventlog``
    The path of the eventlog, its number of entries over all boots and
    its size.

Assets
~~~~~~

``keys/cert.der``
    Whether the primary certificate is present. On a production target
    this is the runtime image's ``keys/cert.der``.

``keys/signing_key.pem``
    ``absent`` on every target. ``present`` means a private signing key
    is on the target.

``eventlog``
    Whether ``/var/lib/shirudo/eventlog`` exists, and its size.

``upatches/``
    The number of archived upatches that ``init`` restores at the next
    boot.

``incoming/`` and ``bpffs/``
    The staging directory for loads in progress and whether the private
    bpffs is mounted.

Eventlog
~~~~~~~~

With ``--include-eventlog`` the report adds an ``Eventlog`` section with
every record of the eventlog, of all boots, after the loaded upatches,
or between the ``TPM measurement`` and ``Assets`` sections when those
are printed. This target recorded its boot, then one load and one
unload:

.. code-block:: console

   target# shirudo status --include-eventlog
   ...
   Eventlog:
     TIME                 TYPE          DIGEST        DETAIL
     2026-11-03T14:53:17Z init          377ce174fb1f  set_digest=e3b0c44298fc..
     2026-11-03T14:54:33Z upatch_load   d979b373d4e5  shirudo-test-basic payload=8aee7072a1a1..
     2026-11-03T14:54:35Z upatch_unload 26dae981e9bb  shirudo-test-basic payload=8aee7072a1a1..
   ...

The ``init`` record comes from the initrd run. Every later record is a
state change that extended the register. :doc:`/reference/formats/eventlog`
describes the records.

.. _status-verdicts:

Act on the verdict
------------------

``status`` derives one verdict from the conditions, in this order of
precedence: ``tampered``, ``lsm-off``, ``init-pending``,
``reboot-pending``, ``degraded``, ``ok``. The first that applies wins.

.. list-table::
   :header-rows: 1
   :widths: 18 42 40

   * - Verdict
     - Meaning
     - What to do
   * - ``ok``
     - Enforcement is up, the keyring is the sealed one, the register
       replays from the eventlog and the config is active.
     - Nothing. Verify with the TPM regularly, see
       :doc:`/operate/run/attest`.
   * - ``degraded``
     - Enforcement is up, but this report has no register to check.
     - Read the ``Chain`` line. See :ref:`status-degraded`.
   * - ``reboot-pending``
     - A config activation is pending until the next reboot. Every
       command except ``status`` and ``image status`` refuses until
       then.
     - Reboot when it suits you. See :ref:`status-reboot-pending`.
   * - ``init-pending``
     - The ``lsm/bpf`` link is pinned but no keyring was recorded:
       ``init`` did not finish.
     - Read the journal of ``shirudo-initrd.service``, see
       :doc:`/operate/deploy/initialize`.
   * - ``lsm-off``
     - The ``lsm/bpf`` link is not pinned. Enforcement is off and the
       target is unprotected.
     - See :ref:`status-lsm-off`.
   * - ``tampered``
     - The register, the keyring or the config is not what ``init``
       recorded.
     - Handle it as an incident. See :ref:`status-tampered`.

.. _status-tampered:

``tampered``
~~~~~~~~~~~~

A ``tampered`` verdict has one of five reasons. Each shows as an
``ALERT`` condition. The lines below are what ``status`` prints in each
state, cut to the verdict and the condition that raised it. ``<pinned>``,
``<live>`` and ``<root>`` stand for the values of your target.

The register does not replay from the eventlog:

.. code-block:: text

   Status:                tampered  (live register differs from the eventlog replay)
   ...
     ChainIntact        ALERT   live register differs from the eventlog replay

Something extended or replaced the register without a matching eventlog
record, the eventlog of this boot was altered or hidden, or the index is
not the one ``init`` bound. The ``TPM measurement`` section shows which
lines disagree.

A upatch is pinned or archived without a record:

.. code-block:: text

   Status:                tampered  (a upatch is pinned or archived without a record of this boot)
   ...
     UpatchesMeasured   ALERT   1 pinned or archived without a record of this boot: <name>

A load was stopped between its pins and its extend, so the upatch runs
while the register does not cover it, an unload was stopped after its
extend, or an archive came back after its unload, which ``init`` would
not restore. The next ``upatch load`` or ``upatch unload``, and every
``bpm`` command that loads or unloads, undoes those pins and archives
before it acts and records the undo in the journal. What stopped the
load, or who brought the archive back, is the question for the
incident.

The live keyring is not the one ``init`` sealed:

.. code-block:: text

   Status:                tampered  (keyring serial swap detected)
   ...
     KeyringSealed      ALERT   pinned serial <pinned>, live serial <live>: swapped

The keyring ``init`` sealed is gone:

.. code-block:: text

   Status:                tampered  (the keyring init froze is gone)
   ...
     KeyringSealed      ALERT   pinned serial <pinned>, the .bpf keyring is gone

The same for ``.dm-verity`` reads ``dm-verity keyring serial swap
detected`` or ``the dm-verity keyring init froze is gone``.

A keyring holds a link ``init`` did not freeze, which the kernel trusts
for signatures from then on:

.. code-block:: text

   Status:                tampered  (a keyring holds a link init did not freeze)
   ...
     KeyringSealed      ALERT   the dm-verity keyring holds 1 link init did not freeze

The keyring section lists that link under ``Other links`` with
``(not frozen)``. If instead the config key is gone from
``.dm-verity``, the reason is ``the config key init froze is gone``.

The config cannot be verified against its records:

.. code-block:: text

   Status:                tampered  (the selected config cannot be verified against its records)
   ...
     ConfigActive       ALERT   the config PCR, activation records and mounted config disagree

The detail of ``ConfigActive`` names the cause:

- ``the config PCR, activation records and mounted config disagree``: the config PCR does not hold the value the activation
  records predict. Something extended the PCR after this boot's config
  measurement. Software that measures into the same PCR causes this
  too, see :doc:`/operate/plan/hardening` for the PCR choice.
- ``the config activation record does not belong to this TPM boot``: the TPM was reset since the config was measured, for
  example by a resume from hibernation.
- ``the mounted config does not match the selected root``: the
  config image mounted at ``/run/shirudo/config`` is not the one the
  records select.

In each of the config states every command except ``status`` and
``image status`` refuses with ``shirudo: image state:`` and the error,
see :doc:`/operate/troubleshoot/troubleshooting`.

For every reason, do not retry anything and do not reboot first: the
journal and the state of this boot are the evidence. Follow
:doc:`/operate/troubleshoot/incident-tampered`.

.. _status-lsm-off:

``lsm-off``
~~~~~~~~~~~

.. code-block:: text

   Status:                lsm-off  (LSM not attached, enforcement off)
   ...
     LsmAttached        ALERT   lsm/bpf link absent, enforcement off

Enforcement is not up. Root can load BPF, and the seal on shirudo's
state is not enforced. A failure of ``init`` in the initrd does not stop
the boot, so a target whose ``shirudo-initrd.service`` failed comes up
in this state. So does a target booted without the shirudo initrd.

1. Read the journal of the initrd run:

   .. code-block:: console

      target# journalctl -b -u shirudo-initrd.service

2. Fix the cause that :doc:`/operate/deploy/initialize` lists for the failed
   step.

3. Reboot.

.. _status-reboot-pending:

``reboot-pending``
~~~~~~~~~~~~~~~~~~

.. code-block:: text

   Status:                reboot-pending  (a config activation is pending until the next reboot)
   ...
     ConfigActive       WARN    the activation of config <root>.. is pending until the next reboot

A config activation was recorded as pending and did not complete. This
happens when ``shirudo image update`` is interrupted after it saved the
pending selection, and when ``init`` fails after it recorded this boot's
config measurement, while restoring the archived upatches or binding the
register. In the second case ``ChainIntact`` and ``TpmMeasured`` also
show ``WARN``. Every command except ``status`` and ``image status``
refuses with ``shirudo: image state: Operation now in progress`` until
the next boot.
A re-run of ``init`` refuses too. shirudo never reboots the target on
its own.

1. Read the journal to learn which step failed:

   .. code-block:: console

      target# journalctl -b -t shirudo

2. Reboot. The next boot verifies the pending config and records a fresh
   measurement for it.

3. Check the verdict again. A ``reboot-pending`` verdict after the next
   boot, with ``boot-restore`` errors in the journal, means an archived
   upatch fails to load at every boot. :doc:`/operate/maintain/backup-recovery`
   describes what works in that case.

.. _status-degraded:

``degraded``
~~~~~~~~~~~~

.. code-block:: text

   Status:                degraded  (no register bound this boot)
   ...
     ChainIntact        WARN    no register bound this boot (init incomplete)
     UpatchesMeasured   WARN    no record of this boot to check the pins against
     TpmMeasured        WARN    NV index 0x01818E00 not bound this boot

Enforcement is up, but the TPM holds no written measurement register, or
``status`` could not read it. The ``Chain`` line of the ``TPM
measurement`` section, which unfolds in this state, tells the two
apart: ``unavailable, register not bound this boot`` or ``unavailable,
TPM error: <error>``.

A failure of ``init`` while binding the register leaves the config
activation pending, which shows as ``reboot-pending``. A ``degraded``
verdict whose ``Chain`` line says ``unavailable, register not bound this
boot`` therefore means the register was bound and then disappeared. Undefining
the index takes TPM owner authorization, which root has on a TPM whose
owner authorization is empty. Collect the evidence as for ``tampered``,
see :doc:`/operate/troubleshoot/incident-tampered`, then reboot.

The reason ``no TPM answered`` means the TPM stopped answering while
``status`` ran. On a production target every command first checks that
the TPM is the one ``init`` bound, so a TPM that does not answer at all
makes ``status`` itself fail with ``shirudo: image state:``.

.. _status-tamper-counters:

Read the tamper counters
------------------------

Each counter counts the attempts at one guard point this boot, refused
there except ``SealSignal``. A refusal worked, so a counter alone does
not change any condition or the verdict. It tells you that something on
the host tried. A ``SealSignal`` tells you that a shirudo command was
signalled from outside; a load stopped that way shows under
``UpatchesMeasured`` until the next upatch command undoes it.

These four attempts, made as root without shirudo's runtime authority,
were each refused:

.. code-block:: console

   # cat /run/shirudo/bpffs/tamper
   cat: /run/shirudo/bpffs/tamper: Permission denied
   # rm /run/shirudo/bpffs/identity
   rm: cannot remove '/run/shirudo/bpffs/identity': Operation not permitted
   # umount /run/shirudo/bpffs
   umount: /run/shirudo/bpffs: must be superuser to unmount.
   # echo x >> /var/lib/shirudo/eventlog
   sh: 4: cannot create /var/lib/shirudo/eventlog: Permission denied

``umount`` prints ``must be superuser to unmount`` for the ``EPERM`` the
LSM returns. The report afterwards lists one more count under
``ObjGet``, ``PinUnlink``, ``BpffsUmount`` and ``SealWrite``:

.. code-block:: console

   target# shirudo status
   ...
   Tamper attempts (this boot):
     LoadNotLoader            39  program load that is not a signed loader
     MapCreate                 1  map creation by another executable
     BpfCommand               16  detach, update, delete or unclassified bpf() command
     PinUnlink                 1  unlink of a pin in the private bpffs
     BpffsUmount               1  unmount of the private bpffs
     SealWrite                 1  write open of a sealed file
     SealPtrace               12  ptrace of a shirudo task
     ObjGet                    1  pin, map or link opened by another executable
   ...

Read the counters with these rules:

- Learn the baseline of your hosts. Software other than shirudo that
  uses BPF or inspects processes is refused too. A freshly booted test
  VM shows counts for ``LoadNotLoader``, ``MapCreate``, ``BpfCommand``
  and ``SealPtrace`` before any upatch is loaded.
- Alert on a counter that moves beyond the baseline, and on any count of
  a counter that stays at zero on your hosts.
- Find the actor in the journal and on the host. The counter does not
  record who tried.
- A zero count does not prove that nothing tried. Some refusals have no
  counter, among them those of the runtime and config image mounts and
  of device-mapper control commands.

:doc:`/security/tamper-counters` lists every counter and the guard point
that raises it.

Monitor with ``status --json``
------------------------------

``status --json`` prints the same data as one JSON document. The
keepalive timer sends it to your collector, see
:doc:`/operate/run/telemetry`.

.. warning::

   ``shirudo status`` exits 0 whatever the verdict, ``tampered``
   included, unless you pass ``--check``, which exits 1 on ``tampered``
   and 0 on every other verdict. It exits 1 also when it cannot load its
   configuration, runs out of memory or fails to send a keepalive, and 2
   on a usage error or an invalid ``map_export`` setting. Alert on the
   ``status`` field of the JSON document, not on the exit code.

Read the verdict:

.. code-block:: console

   target# shirudo status --json | jq -r .status
   ok

The fields that matter for monitoring:

.. list-table::
   :header-rows: 1
   :widths: 38 62

   * - Field
     - Alert when
   * - ``status``
     - It is not ``ok``.
   * - ``conditions[].status``
     - Any condition is ``ALERT``.
   * - ``tamper_attempts.total``
     - It rises beyond your baseline. It is ``null`` before ``init``.
   * - ``config.activation_pending``
     - It is ``true``.
   * - ``config.error``
     - It is not ``null``. It carries the error of an unverifiable
       config: ``Structure needs cleaning``, ``Stale file handle`` or
       ``Key was rejected by service``.
   * - ``keyring_serial_matches``
     - It is ``false``.
   * - ``bpf_keyring.serial_matches`` and
       ``dm_verity_keyring.serial_matches``
     - Either is ``false``.
   * - ``other_links[].frozen`` in either keyring
     - Any is ``false``.
   * - ``tpm.register_bound`` and ``tpm.register_anchored``
     - Either is ``false``.
   * - ``tpm.chain_matches_eventlog``
     - It is ``false``.
   * - ``tpm.register_rebound``
     - It is ``true``.
   * - ``tpm.bound_in``
     - It is not ``initrd``.
   * - ``signing_key_present``
     - It is ``true`` on a target.
   * - ``version_id``
     - It differs from the build you deployed.
   * - ``upatch_tree.eventlog_matches_state``
     - It is ``false``.

``upatches_loaded`` lists each loaded upatch with its
``payload_sha256``, which you can compare with the artifacts you
shipped. :doc:`/reference/formats/status-json` describes every field.

Alert separately when ``status`` does not run at all. A target that
refuses every command, ``status`` included, prints ``shirudo: image
state:`` with an error and exits 1, and a target whose keepalive stops
arriving may be in that state.

Check a copy outside the runtime image
--------------------------------------

Only the runtime image's binary has runtime authority. Any other copy of
the binary is refused before it reads anything:

.. code-block:: console

   target# /usr/local/bin/shirudo status
   shirudo: image state: Permission denied

It exits 1. The refusal also shows as one more ``ObjGet`` count, because
the copy tried to open the identity pin. A monitoring agent that reports
this error is running the wrong binary, see :ref:`runtime-invocation`.

Verify
------

Confirm that your monitoring reads the verdict from the JSON document:
on a healthy target, ``shirudo status --json | jq -r .status`` prints
``ok`` and your alert stays quiet.

Next steps
----------

- :doc:`/operate/run/attest` to have the TPM confirm what the report says
- :doc:`/operate/troubleshoot/incident-tampered` for a ``tampered`` verdict
- :doc:`/operate/troubleshoot/troubleshooting` for refused commands and failure
  categories
- :doc:`/operate/run/telemetry` to send the report to a collector
- :doc:`/reference/cli/status` for every option
