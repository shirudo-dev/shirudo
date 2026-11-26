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
   loader ABI and LSM hooks, module signatures in a kernel that loads
   modules, the certificates readable, ML-DSA-87 and accepted by the
   kernel, the BPF keyring present, the embedded objects present, the
   TPM reachable. A failed check ends ``init``.
#. Check that ``/`` is an initramfs and bind
   ``/sysroot/var/lib/shirudo`` recursively at ``/var/lib/shirudo``. The
   bind must be writable, because config selection is recorded there
   before the config PCR is extended.
#. Create ``/run/shirudo``, mount a private tmpfs there when it is still
   part of ``/run``, label it, and mount the private bpffs at
   ``/run/shirudo/bpffs`` with ``mode=0700,nosuid,nodev,noexec``.
#. Create ``/run/shirudo-java`` with mode ``0755`` and label it, or check
   that the one there is root's and labeled: boot restore writes the
   jars of the Java upatches there, where every JVM can read them.
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
#. Label the state tree on the first boot, and mark the directories
   above it up to the root of its file system.
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

Figure 1 groups the steps in their phases, marks where the keyrings
are sealed, the guards attached and the register anchored, and shows
what crosses the switch and what the run in the root file system does.
The keyrings are sealed before any guard attaches, by the initrd's
binary, which the boot chain measured. The runtime image that later
commands run from is mounted under the guards.

.. figure:: /images/internals-init-run.svg
   :alt: The 18 steps of init in the initrd as a row of cells in four
         phases: settings and mounts (1 to 4), images and keyrings (5 to
         9), guards and the runtime image under them (10 to 13), and the
         config boot event, the restore and the register (14 to 17),
         then step 18. Markers show the keyrings sealed after step 8,
         the guards attached after step 11 and the PCR 9 anchor after
         step 16. Brackets below show what a stop leaves: in steps 1 to
         11 nothing attached and shirudo.service skipped; in 12 and 13
         guards on, no runtime image and the service skipped; in step
         14 before the selection is pending, the service runs init
         again; from there to step 17 the selection stays pending until
         a reboot. Below the switch to the root file system, the private
         bpffs, the image mounts and eventlog.pending cross with
         /run/shirudo, and shirudo.service checks what the initrd run
         left and adds no register event.

   Figure 1. The two runs of ``init``. The numbers are the steps above.

What crosses the switch to the root file system
-----------------------------------------------

systemd moves ``/run`` with its mounts into the root file system, and
with it the private tmpfs at ``/run/shirudo`` and what Figure 1 lists
under it: the private bpffs, whose pins keep every enforcement link and
every restored upatch attached, the image mounts and ``eventlog.pending``.
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
a mount point. Its ``ExecStart`` invokes
``/run/shirudo/runtime/usr/bin/shirudo`` directly (or through the
drop-in that ``shirudo-gen-runtime`` writes for a dynamically linked
binary), so this ``init`` earns runtime authority by its exec.

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
where ``init`` stopped, the brackets of Figure 1:

- Up to the attach: nothing is attached, since a failure inside the
  attach sequence unpins what was attached, and ``shirudo.service``,
  which runs only when ``/run/shirudo/runtime`` is a mount point, is
  skipped. The target runs without enforcement.
- Before the runtime image is mounted again: the guards are in place,
  ``shirudo.service`` is skipped, and commands that need the runtime
  image fail.
- Before the config selection is recorded pending, which happens partway
  through the config boot event: ``shirudo.service`` runs ``init``
  again, which starts the boot event, the restore and the binding over
  from the root file system.
- Once the selection is pending: it stays pending. ``shirudo.service``
  refuses with the activation pending, and every target command except
  ``shirudo status`` and ``shirudo image status`` refuses until a
  reboot.

``shirudo status`` and attestation are how such a target shows. Without
a complete initrd ``init`` the register is not bound in the initrd, and a
verifier that requires an initrd binding rejects the target's evidence.

Hibernation and TPM resets
--------------------------

shirudo refuses hibernation from ``init`` on (A9 in
:doc:`/security/threat-model`). The register and the config record
are tied to the TPM's reset count: a TPM boot ends only when it changes.
When the TPM is reset or restarted without a reboot, which a resume from
hibernation can do, the register is cleared while the kernel's boot ID
stays, and register extensions fail with ``tpm_error``. Nothing re-runs
``init`` automatically.

- After a TPM reset the config record belongs to another TPM boot, and
  every target command except ``shirudo status`` and ``shirudo image
  status`` refuses. A manual ``shirudo init`` records a new config boot
  event and binds the register again, from the root file system and
  with the PCR values of that moment; a verifier that requires an initrd
  binding rejects that evidence. ``TPM2_Clear`` sets the reset count
  back to zero and counts as such a reset.
- After a TPM restart the TPM boot goes on, but the restart cleared the
  config PCR, so commands refuse with ``EUCLEAN``. ``init`` records no
  boot event in the same TPM boot and refuses to bind the cleared
  register again (``tampered``), so the target stays so, and a pending
  activation stays pending, until the next reboot.
- A resume from suspend to RAM keeps the PCRs, the register and the TPM
  boot: commands run as before, and a pending activation stays pending
  until the next reboot. A command the suspend interrupts refuses, as
  its read back finds the restart count moved.

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
