..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: Kernel developers, security reviewers

Boot from initrd to root
========================

``shirudo init`` runs twice on every boot: once in the initrd, where it
brings enforcement up, and once in the root file system, where it checks
what the first run left and adopts its record. This page follows both
runs step by step, says what crosses the switch to the root file system,
and what happens when a run fails.

Why the initrd
--------------

Enforcement protects nothing that happened before it attached. Every
process that runs before ``init`` could load BPF, hold a descriptor or
change state, and the evidence would not show it. The initrd is the
earliest point at which a systemd service can reach the state on the root
file system, and on a measured UKI boot the initrd is measured with the
UKI.

The register needs the initrd too. Its first write is possible only
while PCRs 9 and 11 hold the values ``init`` reads, and systemd extends
PCR 11 with ``leave-initrd`` before the switch to the root file system.
A binding made in the initrd is therefore one that nothing later can
repeat. :doc:`measurement-register` explains the policy.

Initrd run
----------

The dracut module ``90shirudo`` puts the binary, its bootstrap
``/etc/shirudo/shirudo.conf``, a copy of the certificates for the
pre-flight and ``shirudo-initrd.service`` into the initrd. The unit runs
after ``initrd-root-fs.target``, ``tpm2.target``,
``systemd-pcrphase-initrd.service`` and
``systemd-tpm2-setup-early.service``, and before ``initrd.target`` and
the switch to the root file system. It needs
``/sysroot/var/lib/shirudo``, remounts ``/sysroot`` read-write, and runs
``shirudo init`` with ``KeyringMode=inherit``.

``init`` then runs these steps. ``cmd_init()`` and ``run_init()`` in
:src:`builtin-init.c` are the reference.

#. Read the bootstrap settings from the initrd's
   ``/etc/shirudo/shirudo.conf``. ``runtime.image`` and
   ``runtime.root_hash`` must be present; the UKI authenticates both.
#. Run the pre-flight: root, the BPF LSM active, bpffs, the signed
   loader ABI, the certificates readable, ML-DSA-87 and accepted by the
   kernel, the BPF keyring present, the embedded objects present, the
   TPM reachable. A failed check ends ``init``.
#. Check that ``/`` is an initramfs and bind
   ``/sysroot/var/lib/shirudo`` recursively at ``/var/lib/shirudo``. The
   bind must be writable, because config selection is recorded there
   before the config PCR is extended.
#. Create ``/run/shirudo``, mount a private tmpfs there when it is still
   part of ``/run``, label it, and mount the private bpffs at
   ``/run/shirudo/bpffs`` with ``mode=0700,nosuid,nodev,noexec``.
#. Map the runtime image with dm-verity, check its root hash against
   ``runtime.root_hash``, read the whole mapping, mount it and read the
   runtime's bootstrap settings: ``config.image``,
   ``config.verification_key`` and ``config.pcr``.
#. Enroll every config verification certificate in ``.dm-verity``
   and seal it. The keyring must hold exactly the configured set, whose
   serials are frozen and protected by the key permission hook.
#. Open the TPM and the activation journal under
   ``/var/lib/shirudo/config-update``, and select the config: the one
   the activation record names, or ``config.image`` on a first boot.
   On a later TPM boot, an eligible ``next-boot`` record selects its
   candidate instead. Verify its signature against the runtime's config
   certificates, map it through the kernel's signature check, read it
   completely and validate its contents.
#. Build the BPF trust set from the runtime's ``keys/cert.der`` and the
   config's vouched certificates, less its revocations, with the
   runtime certificate always included. Enroll the set in the ``.bpf``
   keyring, seal it, and check that it holds exactly that set.
#. Unmount the runtime and the candidate config and remove their
   mappings.
#. Label the state tree on the first boot.
#. Load and attach the enforcement objects, in the order
   :doc:`enforcement` gives.
#. Walk the state tree again, which fills the directory marks of the
   seal.
#. Map and mount the runtime image again, this time under the guards, so that
   the device record makes its executables eligible for runtime
   authority. It is mounted at ``/run/shirudo/runtime`` with
   ``ro,nodev,nosuid``.
#. Activate the selected config as a boot event: record the selection as
   pending, extend the config PCR, read the PCR back, append the event to
   the config log, apply the config's revocations and mount it at
   ``/run/shirudo/config`` with ``ro,nodev,nosuid,noexec``.
#. Restore the archived upatches from ``/var/lib/shirudo/upatches`` in
   sorted order through the signed loader path. An entry without the
   seal label, one that is not a valid artifact, or one whose load the
   eventlog does not record as still loaded, is ignored. The
   first failure stops the restore; upatches restored before it stay
   loaded.
#. Bind the measurement register, extend it with one ``init`` event that
   covers the trust set, the restored set and the tree root, extend
   PCR 9 with the anchor, and write the record to
   ``/run/shirudo/eventlog.pending``.
#. Mark the config selection complete and remove its next-boot record,
   if one was staged.
#. Detach the ``/var/lib/shirudo`` bind.

The keyrings are sealed before any guard attaches, by the initrd's
binary, which the boot chain measured. The runtime image that later
commands run from is mounted under the guards.

What crosses the switch to the root file system
-----------------------------------------------

systemd moves ``/run`` with its mounts into the root file system. The
private tmpfs at ``/run/shirudo`` goes with it, and with that tmpfs:

- the private bpffs, whose pins keep every enforcement link and every
  restored upatch attached, and which holds the identity map, the task
  and device maps and the tamper counters;
- the runtime image at ``/run/shirudo/runtime`` and the config image at
  ``/run/shirudo/config``;
- ``eventlog.pending``, the record of the initrd run.

The sealed keyrings, the device records and the TPM state are kernel and
TPM state and do not depend on the switch. The bind of
``/var/lib/shirudo`` does not cross; the root file system has the same
directory at that path.

Root file system run
--------------------

``shirudo.service`` runs in the root file system before
``sysinit.target``, after ``local-fs.target``,
``systemd-tpm2-setup-early.service`` and
``systemd-pcrnvdone.service``, and only when ``/run/shirudo/runtime`` is
a mount point. The drop-in that ``shirudo-gen-runtime --unit-output``
writes replaces its ``ExecStart`` with the binary on the runtime image,
so this ``init`` earns runtime authority by its exec.

This run reads the runtime root hash from the frozen identity map rather
than from a file, checks that every pinned enforcement link is an LSM
link to the expected kernel function on the expected maps, and checks
that the runtime mount is the recorded runtime device. Then:

- the private bpffs is already mounted, and the ``.bpf`` keyring serial
  and the runtime root equal the frozen record;
- the state tree must already carry its label, and ``init`` labels
  nothing;
- the pending record is appended to ``/var/lib/shirudo/eventlog`` under
  the eventlog lock, and ``eventlog.pending`` is removed;
- the enforcement links are found pinned, and nothing attaches;
- the config record is checked: same TPM boot, not pending, and the
  config log replays to the live config PCR;
- every archived upatch must already be loaded with the archived
  payload; one that is not is refused as ``tampered``;
- the register is found written under the recorded name, and no event
  is added.

The root run therefore adds nothing to the register. The ``init`` event
from the initrd stays the only one for the boot until an operator
changes the loaded set.

When init fails
---------------

A failed ``init`` does not stop the boot. ``initrd.target`` only wants
``shirudo-initrd.service``, the unit has no failure action, and shirudo
never halts or reboots a node. What the target runs afterwards depends on
where ``init`` stopped:

- Before the enforcement objects attach (settings, pre-flight, images,
  keyrings): nothing is attached. A failure inside the attach sequence
  unpins what was attached, with the same result. The runtime image is
  not mounted, so ``shirudo.service`` is skipped, and the target runs
  without enforcement.
- After attaching, before the runtime image is mounted again: the guards
  are in place, ``shirudo.service`` is skipped, and commands that need
  the runtime image fail.
- After the config boot event (a restore failure, a register that cannot
  be bound): the guards are in place and the config selection stays
  pending. ``shirudo.service`` refuses with the activation pending, and
  every target command except ``shirudo status`` and ``shirudo image
  status`` refuses until a reboot.

``shirudo status`` and attestation are how such a target shows. Without
a complete initrd ``init`` the register is not bound in the initrd, and a
verifier that requires an initrd binding rejects the target's evidence.

Hibernation and TPM resets
--------------------------

shirudo does not refuse hibernation. The register and the config record
are tied to the TPM's reset and restart counts. When the TPM is reset or
restarted without a reboot, which a resume from hibernation can do, the
register is cleared and one of the counts changes while the kernel's
boot ID stays. Register extensions then fail with ``tpm_error``, and every
target command except ``shirudo status`` and ``shirudo image status``
refuses because the config record belongs to another TPM boot. Nothing
re-runs ``init`` automatically. After a TPM reset, whose count the
``init`` record no longer matches, a manual ``shirudo init`` records a
new config boot event and binds the register again, from the root file
system and with the PCR values of that moment; a verifier that requires
an initrd binding rejects that evidence. After a TPM restart the reset
count still matches the record, and ``init`` refuses to bind the cleared
register again (``tampered``) before the next reboot, which leaves the
config selection it recorded pending.

Kexec
-----

``lsm/kernel_load_data`` and ``lsm/kernel_read_file`` refuse every kexec
kernel image and initramfs to every caller, through ``kexec_load(2)`` and
``kexec_file_load(2)``, crash kernels included, once ``init`` has
attached them (``Kexec``). A kexec would hand the machine to a kernel of
the caller's choosing with the TPM as it is, so the evidence of this boot
would vouch for what runs after it. A crash kernel that kdump needs must
be loaded before ``init`` runs, or it is refused.

Related
-------

- :doc:`/concepts/background/initrd-dracut` and
  :doc:`/concepts/background/boot` for the boot chain
- :doc:`/operate/deploy/boot-integration` for setting up the initrd and the
  UKI
- :doc:`config-images` for the images and the activation journal
- :doc:`/security/threat-model` for what a failed or skipped ``init``
  means for the trust model
