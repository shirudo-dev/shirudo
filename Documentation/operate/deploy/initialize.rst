..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators

Initialize a target
===================

``shirudo init`` brings enforcement up on every boot. It runs twice: once
from the initrd, where it does the work, and once from the root file
system, where it checks that work and records it. You do not run it by
hand. This page tells you what each run does, how to check that it
worked, and what to do when it did not.

Before you begin
----------------

- A target set up as described in :doc:`/operate/deploy/boot-integration`.
- A root shell on the target. On the target, ``shirudo`` means the
  runtime image's binary, ``/run/shirudo/runtime/usr/bin/shirudo``. See
  :ref:`runtime-invocation`.

What init does
--------------

.. list-table::
   :header-rows: 1
   :widths: 16 22 62

   * - Run
     - Unit and binary
     - What it does
   * - Initrd
     - ``shirudo-initrd.service``, with the binary in the initrd that the
       UKI authenticates
     - Steps 1 to 14 of Figure 1. It binds ``/sysroot/var/lib/shirudo``
       writable at ``/var/lib/shirudo``, checks the runtime image against
       ``runtime.root_hash``, mounts it at ``/run/shirudo/runtime`` and the
       config image at ``/run/shirudo/config``, and writes its init record
       to ``/run/shirudo/eventlog.pending``.
   * - Root file system
     - ``shirudo.service``, running the runtime image's binary directly
       (or through its drop-in for a dynamically linked binary)
     - Checks that the keyring and the runtime image are the ones the
       initrd recorded, appends the pending init record to
       ``/var/lib/shirudo/eventlog``, and checks the LSM link, the config
       activation and the register. Adds no register event.

Figure 1 shows the steps of both runs in order, and the three bands that
`When init fails`_ sorts a failed initrd run into. The mounts under
``/run/shirudo`` survive the switch to the root file system.
:doc:`/internals/boot-flow` explains each step.

.. figure:: /images/operate-init-timeline.svg
   :alt: The initrd run in 14 steps: pre-flight and binding the state,
         the bpffs, the runtime image and .dm-verity, the config, .bpf,
         labels and eventlog, the LSM programs; then the runtime mount
         and a second check of the config; then the config BOOT event,
         revocations and the config mount, the upatch restore, the
         register and completing the activation. A failure before the
         LSM programs attach leaves lsm-off, one before the BOOT event
         image state errors, one after it reboot-pending. After
         switch-root the root run only checks and adds no register event.

   Figure 1. The steps of init in the initrd and on the root file system,
   and what a failure of the initrd run leaves in each band.

Check that init worked
----------------------

1. Read the status report:

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

   ``Status: ok`` and every condition ``OK`` mean that enforcement is
   attached, the ``.bpf`` keyring is the one init sealed, the register
   matches the eventlog, every pinned upatch is measured, the config is
   active and every device an XDP upatch selects runs it.

2. Read where the register was bound:

   .. code-block:: console

      target# shirudo status --show-full
      ...
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
      ...

   The report folds the TPM measurement section while ``ChainIntact``
   and ``TpmMeasured`` are ``OK``, and ``--show-full`` prints it.
   ``Bound in: initrd`` says that the initrd run bound the register.

   ``PCR before init`` and ``Phase at init`` are PCR 9 and PCR 11 as init
   found them. The output comes from the test VM, which boots the kernel
   and initrd without a UKI, so both are zero. A target that boots a
   measured UKI shows its own values, and a verifier pins them as
   :doc:`/operate/run/attest` describes.

3. Check the fields a script reads:

   .. code-block:: console

      target# shirudo status --json

   .. list-table::
      :header-rows: 1
      :widths: 40 60

      * - Field
        - Value after a good boot
      * - ``status``
        - ``"ok"``
      * - ``keyring_mode``
        - ``"bpf"``
      * - ``tpm.bound_in``
        - ``"initrd"``
      * - ``tpm.chain_matches_eventlog``
        - ``true``
      * - ``tpm.register_rebound``
        - ``false``
      * - ``config.activation_pending``
        - ``false``

   :doc:`/reference/formats/status-json` describes every field.

4. Check that the root run adopted the initrd's record:

   .. code-block:: console

      target# ls /run/shirudo/eventlog.pending

   The file must not exist. When it remains, ``shirudo.service`` did not
   run or failed, and its journal says why.

5. Read both runs in the journal:

   .. code-block:: console

      target# journalctl -b -u shirudo-initrd.service -u shirudo.service

   A complete initrd run logs
   ``tpm: register bound in the initrd and extended (index 0x01818E00,
   PCR 9 anchored, <n> upatches in set)`` and
   ``init: complete (LSM active, writable state sealed)``. The root run
   logs ``tpm: register already bound this boot; chain unchanged (index
   0x01818E00)`` and the same last line.

To see which prerequisites init checks first, run the pre-flight alone.
It changes no persistent or enforcement state:

.. code-block:: console

   target# shirudo init --check-only
   Pre-flight checks:
     OK    root
     OK    bpf_lsm_active
     OK    bpffs_supported
     OK    signed_loader_kernel_abi
     OK    kernel_lsm_hooks
     OK    module_signatures
     OK    cert_on_disk
     OK    cert_algorithm
     OK    cert_kernel_support
     OK    kernel_keyring
     OK    embedded_loader
     OK    tpm2_reachable: TCTI from the config: device:/dev/tpmrm0
   12 of 12 passed

:doc:`/reference/cli/init` describes each check.

When init fails
---------------

A failed initrd run does not stop the boot. ``shirudo-initrd.service`` is
only wanted by ``initrd.target``, and nothing acts on its failure. The
host boots, and what it runs depends on the band of Figure 1 where init
stopped.
When the initrd lacks the shirudo module or its certificate, init does
not run at all and nothing reports an error.
``shirudo-gen-initrd --check`` detects such an initrd before you boot it.

.. list-table::
   :header-rows: 1
   :widths: 24 38 38

   * - Where init stopped
     - What you see
     - What to do
   * - Before the LSM programs attach, steps 1 to 7: the pre-flight,
       the image settings, the bpffs, verifying the images and enrolling
       the keys, sealing state or loading enforcement.
     - The host runs without enforcement. ``shirudo.service`` is
       skipped, because the runtime image is not mounted. The keepalive
       service cannot start without the runtime binary, so the keepalive
       stops. ``status`` from any copy of the binary reports ``lsm-off``.
     - Read the initrd journal, fix the cause and reboot.
   * - After the LSM programs attach and before the config BOOT event,
       steps 8 and 9: mounting the runtime image, or checking the
       activation record and verifying the config again.
     - Enforcement is on. Depending on the step, the runtime binary is
       missing, commands fail with ``shirudo: image state: <error>``, or
       ``status`` reports a config condition that does not belong to
       this boot.
     - Keep the journal, fix the cause and reboot. When the journal does
       not explain the state, follow
       :doc:`/operate/troubleshoot/incident-tampered`.
   * - From the config BOOT event on, steps 10 to 14: extending the
       config PCR, applying the revocations, restoring upatches, binding
       the register or completing the activation.
     - Enforcement is on and the config activation stays pending.
       ``status`` reports ``reboot-pending``, and until step 13 binds the
       register ``ChainIntact`` and ``TpmMeasured`` warn that none is
       bound. Commands other than ``status`` and ``image status`` fail
       with ``shirudo: image state: Operation now in progress``,
       attestation included.
     - Fix the cause and reboot. A reboot without a fix fails at the
       same step.

Do not run ``shirudo init`` again in the same boot. After a failure past
the config BOOT event, init refuses with
``image: activation is pending; further changes are blocked`` and
``init: loading authenticated boot settings failed: Operation now in
progress``. Only a reboot clears the pending activation. A re-run after a
successful init changes nothing.

Do not run init from the root file system to make up for a failed initrd
run either. Workloads have already run without enforcement by then, and
the register would record a binding from the root file system, which a
verifier that pins PCR 11 rejects. Reboot instead.

Failures to restore upatches
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Init restores the archived upatches in name order and stops at the first
one that fails, with ``boot-restore: failed to apply <file>`` and
``init: boot-restore failed; further changes and attestation remain
blocked``. The upatches it loaded before that one stay loaded, and no
register measures them. The archive is sealed, so the next boot tries
the same upatch again. The usual cause is a kernel on which the upatch
no longer loads, or a device that an XDP upatch selects whose driver
refuses it. :ref:`boot-restore-lockout` describes the way out.

Init stops the same way, with ``boot-restore: cannot read the pins of
<name>`` and the error, when it cannot read the pin directory of an
archived upatch to tell whether it is loaded already. It does not
restore that upatch.

Register binding failures
~~~~~~~~~~~~~~~~~~~~~~~~~

When init cannot bind the register, it logs
``init: incomplete: LSM active and upatches loaded, but the TPM register
did not advance`` after one of these lines:

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - Message
     - Cause and action
   * - ``tpm: not usable; shirudo requires a TPM 2.0 (tpm_error)``
     - No usable TPM answered on ``/dev/tpmrm0``. Check the TPM driver in the
       initrd and the firmware's TPM setting.
   * - ``tpm: register 0x01818E00 cannot be bound (tpm_error); ...``
     - The TPM refused the authorization, usually because the owner
       hierarchy has a password that shirudo does not have. Set
       ``tpm.owner_auth`` in both bootstrap files as
       :doc:`/operate/deploy/boot-integration` describes. The environment
       variable that the message names is refused on a target.
   * - ``tpm: register extend failed, the chain did not advance while
       the LSM is active (tpm_error); the operator must reconcile``
     - The register could not be defined or extended. Read the journal
       for the TPM error before it.
   * - ``tpm: the register this boot recorded is gone or replaced;
       refusing to bind another before the next TPM reset (tampered)``
     - Something removed or replaced the register after init bound it
       this boot. Handle it as an incident:
       :doc:`/operate/troubleshoot/incident-tampered`.

The threat model lists the boot paths that leave a target unprotected and
what detects them: :doc:`/security/threat-model`.

Next steps
----------

- :doc:`/operate/run/read-status` for every section and verdict of the
  status report
- :doc:`/operate/troubleshoot/troubleshooting` for refusals after init
- :doc:`/operate/run/attest` to prove the boot to a remote verifier
