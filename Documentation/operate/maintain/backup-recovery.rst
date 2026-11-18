..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators

Back up, recover and decommission a target
==========================================

shirudo refuses to paper over a state it cannot vouch for, so several
failures have one way out: a reboot. One has no way out in place. This
page lists what to back up, how to get a target out of each state that
blocks it, and how to take a target out of service.

Every procedure here works with shirudo as it is. Where no recovery
exists, the page says so.

Before you begin
----------------

- Root on the target. On the target, ``shirudo`` stands for the runtime
  image's binary, ``/run/shirudo/runtime/usr/bin/shirudo``
  (:ref:`runtime-invocation`).
- For a decommission, the operator host that builds and signs the
  target's UKI.

What to back up
---------------

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Item
     - Why it matters
   * - ``/var/lib/shirudo/eventlog``
     - The target's measurement history across boots. Nothing else holds
       it, so it is evidence you cannot recreate.
   * - ``/var/lib/shirudo/config-update/``
     - The config activation journal: each activation with its TPM reset
       and restart counts. Evidence, tied to this target's TPM.
   * - ``/var/lib/shirudo/images/``
     - The runtime image and every config bundle the target has
       activated, named by root hash. The operator holds the originals.
   * - ``/var/lib/shirudo/upatches/`` and ``/var/lib/shirudo/bpm/``
     - The upatch archive that ``init`` restores at boot, the installed
       packages and the tree state. The registry holds the packages.
   * - ``/etc/shirudo/``
     - Host files: ``bpm/environment``, ``map-export.env``, and
       ``shirudo.conf`` when the dracut module takes the initrd's
       bootstrap file from there.
   * - ``/etc/systemd/system/shirudo*.d/``
     - The runtime drop-ins of the shirudo units.
   * - On the operator host
     - The signing keys (:doc:`/operate/maintain/keys`), the image source
       directories and bootstrap files, the UKI build inputs, and each target's
       attestation key name, endorsement key pin and expected values
       (:doc:`/operate/run/attest`).

Back up a target
~~~~~~~~~~~~~~~~

The seal stops writes to ``/var/lib/shirudo`` but not reads, so root can
copy the state while enforcement is up.

#. Archive the state and the host configuration:

   .. code-block:: console

      target# tar --create --gzip --file=<archive> /var/lib/shirudo \
          /etc/shirudo /etc/systemd/system

   ``<archive>`` is a path outside ``/var/lib/shirudo``, for example
   ``/root/shirudo-state.tar.gz``.

#. Save the journal of shirudo's messages:

   .. code-block:: console

      target# journalctl -t shirudo -o export > <journal-file>

#. Copy both files off the target.

Restore
~~~~~~~

shirudo has no restore command, and while enforcement is up the seal
refuses root's writes into ``/var/lib/shirudo``. You cannot restore files
into a running target. Rebuild a lost target instead:

#. Provision it again (:doc:`/operate/deploy/boot-integration`,
   :doc:`/operate/deploy/initialize`).
#. Install its packages from the registry
   (:doc:`/operate/run/deliver-packages`).
#. Keep the old eventlog, journal and activation journal with your
   records as the history of the old installation.

Do not copy an eventlog, an activation journal or the tree state
``/var/lib/shirudo/bpm/upatch-tree/`` onto another target. The tree
state records how far its own target got in the tree, and another
target would skip every operation up to that point.

Plan for eventlog growth
------------------------

The eventlog grows by one record for each boot, upatch load and unload,
key revocation and tree operation. shirudo never rotates or truncates
it, has no command to, and the seal stops root from doing it. In the
test VM, the init record of a target with two certificates takes about
2 KB and a load adds a few hundred bytes:

.. code-block:: console

   target# shirudo status --show-full
   ...
     Eventlog:              /var/lib/shirudo/eventlog  (2 entries, 2324 bytes)
   ...

Every command that reads the eventlog reads all of it, plus the pending
record of the initrd, and refuses when the two exceed 8 MiB (8388608
bytes). ``eventlog.max_bytes`` in the signed config sets a lower cap: at
the cap, ``upatch load`` and ``upatch unload``, and the package and tree
commands built on them, refuse with ``eventlog_full``.
``init`` checks the same cap and the same read limit before it binds the
register, so a target whose eventlog reaches either one fails ``init`` at
every boot (:ref:`backup-recovery-init-failed`). At about 2 KB per boot,
that takes a few thousand boots with no other events, and fewer with
loads and tree operations.

Watch ``assets.eventlog_bytes`` in ``shirudo status --json`` or the
keepalive (:doc:`/operate/run/telemetry`), and decommission and reprovision a
target well before it reaches the limit.

Nothing removes old bundles from ``/var/lib/shirudo/images`` either.
Each config you activate stays there under its root hash, so size config
images with the ``--size`` option of ``shirudo-gen-image``.

Recover a target
----------------

Find the state from what the target shows, then follow its section.

.. list-table::
   :header-rows: 1
   :widths: 44 30 26

   * - What you see
     - State
     - Way out
   * - ``reboot-pending``, ``Pending: yes`` from ``image status``, and
       ``shirudo: image state: Operation now in progress`` from other
       commands
     - `A config activation is pending`_
     - Reboot.
   * - The same, with ``init: boot-restore failed`` or ``init:
       incomplete`` in the journal of this boot
     - :ref:`backup-recovery-init-failed`
     - Fix the cause and reboot.
   * - ``boot-restore: failed to apply <file>`` at every boot
     - :ref:`boot-restore-lockout`
     - Boot the previous kernel, remove the upatch, boot the new one. If
       no kernel loads it, decommission.
   * - ``tampered`` with ``the config activation record does not belong
       to this TPM boot``, and ``shirudo: image state: Stale file
       handle``
     - `TPM reset or restarted without a reboot`_
     - Reboot if you know the TPM was reset; otherwise handle an
       incident first.

A config activation is pending
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Symptoms:

- ``shirudo status`` reports ``reboot-pending`` with the reason ``a
  config activation is pending until the next reboot``.
- ``shirudo image status`` prints ``Pending: yes`` and exits 1.
- Every other command prints ``shirudo: image state: Operation now in
  progress`` and exits 1.

Cause: ``shirudo image update`` stopped after it saved the pending
selection, or ``init`` failed after it recorded this boot's activation
(:ref:`backup-recovery-init-failed`).

#. Read why in the journal:

   .. code-block:: console

      target# journalctl -b -t shirudo

#. Reboot when it suits you. shirudo never reboots a node itself, and
   the node keeps running in this state with enforcement up.

#. Check after the reboot that ``shirudo status`` reports ``ok`` and
   ``shirudo image status`` prints ``Pending: no`` and
   ``Consistent: yes``.

At the next boot, ``init`` verifies the pending selection, records a
fresh boot activation and completes. There is no command that clears a
pending activation in the same boot, and the seal stops you from
removing the journal.

.. _backup-recovery-init-failed:

init failed after it recorded the boot's activation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``init`` records the boot's config activation before it restores the
archived upatches and binds the TPM register. A failure in either step
leaves the activation pending. The journal shows one of:

.. code-block:: text

   init: boot-restore failed; further changes and attestation remain blocked
   init: incomplete: LSM active and upatches loaded, but the TPM register did not advance

In this state the LSM is attached and enforcement is up. The upatches
restored before the failure stay loaded, the register is not bound, and
``shirudo status`` reports ``reboot-pending`` with the ``ChainIntact``
detail ``no register bound this boot (init incomplete)``. Every command
that reads target state is refused, except ``status`` and ``image``.

A second ``init`` in the same boot does not help. It stops with:

.. code-block:: text

   image: activation is pending; further changes are blocked
   init: loading authenticated boot settings failed: Operation now in progress

#. Find the step that failed in the journal of both runs:

   .. code-block:: console

      target# journalctl -b -u shirudo-initrd.service -u shirudo.service

#. Fix the cause. A cause in the boot inputs needs new boot inputs
   (:doc:`/operate/deploy/boot-integration`). An archived upatch that fails to
   load needs the next procedure.

#. Reboot.

.. _boot-restore-lockout:

An archived upatch no longer loads at boot
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Symptoms:

- The journal shows ``boot-restore: failed to apply <file>`` before the
  ``init`` lines above.
- ``shirudo status`` reports ``reboot-pending``, and commands other than
  ``status`` and ``image status`` fail with ``shirudo: image state:
  Operation now in progress``.

Cause: ``init`` restores the archive in name order and stops at the
first upatch that fails, without unloading what it already loaded. The
usual cause is a new kernel on which the upatch fails with
``verifier_rejected``, ``attach_target_missing`` or
``kernel_abi_unsupported``. For an XDP upatch, a line ``XDP: attach
<device>`` before it names a device whose driver refused the program: a
NIC added since the load, or a setting that survived the reboot, in the
NIC's firmware or the hypervisor, such as LRO, header-data split or a
device without multi-buffer XDP.

``init`` restores the same archive at every boot, so a reboot fails the
same way. These do not work:

- A second ``init``: it refuses the pending activation.
- ``shirudo bpm uninstall`` and ``shirudo upatch unload``: every command
  that reads target state is refused, except ``status`` and ``image``.
- Deleting the file from ``/var/lib/shirudo/upatches``: the seal refuses
  it.

For an XDP device, undo the setting or remove the device, and reboot. A
device that cannot take XDP needs a upatch signed with a class mask
that leaves it out. Otherwise remove the upatch from a boot on which it
loads:

#. Before you reboot, read the name of the failed upatch:

   .. code-block:: console

      target# journalctl -b -u shirudo-initrd.service

   The line is ``boot-restore: failed to apply <file>``.

#. Boot a kernel on which the upatch loads, usually the previous one,
   from its UKI in the boot menu. Its runtime image must still be where
   its UKI bootstrap file names it, in ``/var/lib/shirudo/images``.

#. Check that ``shirudo status`` reports ``ok``.

#. Remove the upatch. Uninstall its package with
   ``shirudo bpm uninstall <package>``, unload it with its unload
   directive (:doc:`/reference/cli/upatch-unload`), or, for a upatch
   from the tree, publish a ``delete`` operation and let the tree sync
   apply it.

#. Boot the new kernel's UKI and check init as described in
   :doc:`/operate/deploy/initialize`.

If no kernel loads the upatch, shirudo offers no recovery in place.
Decommission the target and provision it again. To avoid the state,
make sure every archived upatch loads on a new kernel before you reboot
into it (:doc:`/operate/maintain/upgrade`).

TPM reset or restarted without a reboot
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The activation journal records the TPM's reset and restart counts. When
either changes while the system runs, as on a resume from hibernation:

- Every command that reads target state, except ``status`` and
  ``image``, prints ``shirudo: image state: Stale file handle`` and
  exits 1. ``init``, ``genkey``, ``build``, ``help`` and ``version``
  skip that check.
- ``shirudo status`` reports ``tampered`` with the reason ``the selected
  config cannot be verified against its records``, and ``ConfigActive``
  reads ``the config activation record does not belong to this TPM boot``.
- The register can be gone, which ``ChainIntact`` reports as a warning.

If you know the TPM was reset, reboot. Do not run ``init`` again: after a
TPM reset it binds the register from the root file system, which a
verifier that pins PCR 11 rejects, and after a restart alone it refuses
to bind and leaves a config activation pending. If you do not know why
the counts changed, handle the target as in
:doc:`/operate/troubleshoot/incident-tampered` before you reboot.
:doc:`/operate/plan/hardening` covers turning hibernation off.

Decommission a target
---------------------

Enforcement cannot be switched off while the target runs: the LSM links
are held by pins in the private bpffs that only shirudo could remove,
and shirudo has no command that removes them. Taking a target out of
service is a reboot into a boot path without shirudo.

#. Optional: uninstall every package, so the eventlog records each
   unload:

   .. code-block:: console

      target# shirudo bpm uninstall <package>

#. Save the eventlog and the journal as the target's last record, as in
   the backup procedure above.

#. Stop and disable the timers:

   .. code-block:: console

      target# systemctl disable --now shirudo-keepalive.timer \
          shirudo-map-export.timer shirudo-bpm-repo-update.timer \
          shirudo-bpm-tree-sync.timer

#. Disable the root service:

   .. code-block:: console

      target# systemctl disable shirudo.service

#. Remove the runtime drop-ins you installed (:ref:`unit-drop-ins`) and
   reload systemd:

   .. code-block:: console

      target# systemctl daemon-reload

#. Remove the target package, which removes the binary, the units and
   the dracut module:

   .. code-block:: console

      target# apt remove shirudo-target

   On RPM-based systems, run ``dnf remove shirudo-target``.

#. On the operator host, build and sign a UKI whose initrd does not
   contain the shirudo dracut module and whose kernel command line
   carries neither ``bpf.keyring_unsealed=1`` nor
   ``dm_verity.keyring_unsealed=1``, and make it the target's default
   boot entry. Without the module, ``shirudo-initrd.service`` does not
   run. Without the parameters, the kernel seals the ``.bpf`` and
   ``.dm-verity`` keyrings empty at boot. Regenerating the initrd on the
   target alone changes nothing a UKI boots. If the shirudo installer
   added the parameters, it wrote them through ``grubby``, to
   ``/etc/default/grub.d/shirudo.cfg`` or to ``/etc/kernel/cmdline``;
   remove them there too.

#. Reboot the target.

#. Check that the kernel left the ``.bpf`` keyring sealed:

   .. code-block:: console

      target# cat /sys/module/bpf/parameters/keyring_unsealed

   The file reads ``N``. ``/run/shirudo`` does not exist.

#. Remove the state. The seal stopped root from doing this before the
   reboot:

   .. code-block:: console

      target# rm -rf /var/lib/shirudo /etc/shirudo

#. On the operator host, retire the target: remove its attestation key
   name, endorsement key pin and expected values from your verifier's
   records, so that no evidence from it passes verification again.

The register's NV index ``0x01818E00`` stays defined in the TPM. If the
TPM goes to another use, remove the index with the owner hierarchy's
authorization, for example with ``tpm2_nvundefine 0x01818E00`` from
tpm2-tools.

Next steps
----------

- :doc:`/operate/troubleshoot/troubleshooting` for messages by symptom
- :doc:`/operate/troubleshoot/incident-tampered` when ``status`` reports
  ``tampered``
- :doc:`/operate/maintain/upgrade` to change the kernel without stranding a
  upatch
- :doc:`/reference/files` for every file shirudo keeps
