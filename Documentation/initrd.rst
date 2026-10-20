..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Bringing shirudo up from the initrd
===================================

The production configuration of a target brings enforcement up before
the root file system runs anything: ``shirudo init`` runs inside the
initrd.  This document describes what that run does, what the root
file system's run finishes afterwards, what an initrd needs to contain
and how the pieces survive the switch from one to the other.  The
``threat-model`` document says why it matters; ``tpm`` describes the
register the initrd binds.

1) Two runs of init
-------------------

``shirudo init`` is one command that runs twice per boot in production:

The initrd run
    Starts from ``shirudo-initrd.service`` after the root file system is
    mounted at ``/sysroot`` and after ``systemd-pcrphase-initrd.service``
    has measured ``enter-initrd`` into PCR 11, and finishes before the
    switch to the root file system.  It enrols the initrd's own copy of
    the certificate, ``/etc/shirudo/keys/cert.der``, in the kernel's bpf
    keyring and seals it, which needs the kernel booted with
    ``bpf.keyring_unsealed=1``; mounts the private bpffs at
    ``/run/shirudo/bpffs`` and attaches the enforcement programs with
    their pins in it; re-applies the upatches archived under
    ``/sysroot/var/lib/shirudo/upatches``; binds the measurement
    register under PCRs 9 and 11 and extends it by the init event; and
    writes the ``init`` record to ``/run/shirudo/eventlog.pending``.

The root file system's run
    Starts from ``shirudo.service`` inside the sysinit phase.  It finds
    the keyring sealed around the certificate, the LSM attached, the
    upatches loaded and the register bound, and does what the initrd
    could not do on a root file system that was still read-only: it
    labels the state tree and the binary with the sealing xattr and
    appends the pending record to ``/var/lib/shirudo/eventlog``, exactly
    once.  Then it stops.  ``status`` reports ``mode: production`` and
    ``bound_in: initrd``.

Without an initrd that runs the first half, the root file system's run
does everything itself.  The kernel sealed the bpf keyring empty at
boot, so the certificate is staged in a ``shirudo`` keyring under the
user keyring until the next reboot, and the register binds after
``leave-initrd`` moved PCR 11.  That is the staging configuration:
``status`` says ``mode: staging`` and ``bound_in: root``, the keepalive
condition warns, and a verifier can refuse the evidence with
``--require-initrd`` or by pinning PCR 11.

2) What survives the switch to the root file system
---------------------------------------------------

systemd's switch-root carries ``/dev``, ``/sys``, ``/proc`` and ``/run``
from the initrd into the root file system and lazily detaches every
other mount of the initrd.  A BPF link stays attached only while
something holds it, and in an agentless design the only holders are
the pins in the bpffs; a bpffs mounted anywhere the switch detaches
dies with the old root and takes enforcement with it.  That is why the
private bpffs lives at ``/run/shirudo/bpffs``: a mount under ``/run``
is carried across, is never shadowed by a later mount of ``/var``, and
needs nothing from the root file system.

The kernel keyring is kernel state and survives by itself; so do the
TPM's NV index and PCRs.  The init record cannot be written to the
root's eventlog while the root is read-only, so it waits under ``/run``
in the same tmpfs, in ``/run/shirudo``, which ``init`` labels with the
sealing xattr so that the record is sealed from the instant it is
created, and the eventlog readers treat it as part of this boot's log
until the root file system's run appends it and removes the file.

The bpffs guards admit the executable recorded at init.  From the
initrd the running binary is the initrd's copy, which is gone after
the switch; the identity that lasts is the root's binary at the same
path, ``/sysroot`` plus the path the initrd ran shirudo from, and the
initrd's copy is recorded beside it for the rest of that one run.  The
root file system therefore needs shirudo installed at the path the
initrd runs it from, which the dracut module guarantees by copying the
installed binary.

3) What the initrd needs
------------------------

* The target binary at its installed path.  It is fully static PIE,
  including the C library, and needs no ELF interpreter or shared
  libraries to start.
* ``/etc/shirudo/keys/cert.der``, a copy of ``/var/lib/shirudo/keys/cert.der``,
  and ``/etc/shirudo/keys/trusted/`` with the further certificates and
  their vouches.  These copies are measured with the initrd, so a
  verifier that pins PCR 11 knows which certificates were enrolled.
  ``init`` warns when the root's set differs, which means an initrd
  that was not regenerated after a certificate was added or revoked;
  the initrd's copies are the anchor either way, less the certificates
  the root's ``keys/revoked`` names, which ``init`` reads through its
  bind.
* ``/etc/shirudo/shirudo.conf`` when the TPM has an owner password
  (``tpm.owner_auth``).
* ``shirudo-initrd.service``, enabled in ``initrd.target``.
* A TPM 2.0 reachable as ``/dev/tpmrm0``: the TPM driver and the
  device node.  dracut's ``tpm2-tss`` module provides both.
* ``systemd-pcrphase-initrd.service``, so that PCR 11 holds the
  ``enter-initrd`` value when the register binds and moves at
  ``leave-initrd``.  dracut's ``systemd-pcrextend`` module (called
  ``systemd-pcrphase`` before dracut 103) provides it.  systemd runs
  the unit only for a measured UKI boot (``ConditionSecurity=
  measured-uki``); a kernel and initrd loaded by grub or passed to QEMU
  directly leave PCR 11 at its boot value, ``init`` warns that no phase
  was measured, and the binding then has the PCR 9 anchor but not the
  PCR 11 distinction between an initrd and a later binding.  The
  production configuration is therefore a UKI boot; the rest of the
  design holds without it.
* The root file system mounted at ``/sysroot`` with
  ``/var/lib/shirudo`` on it.  When ``/var`` is a separate file system
  it must be mounted in the initrd (``x-initrd.mount`` in fstab), or
  the initrd run refuses with a message that says so and the root's
  run falls back to the staging configuration.
* The kernel booted with ``bpf.keyring_unsealed=1``.  The parameter is
  read-only after boot, so the only way to open the keyring is the
  measured command line.

The ``tools/gen-initrd`` directory holds the dracut module that
installs all of this, a generator that drives dracut and verifies the
result, and the installer; the ``getting-started`` document shows how
they are used.  Non-systemd initrds (initramfs-tools, busybox) are
not supported: without the phase measurements an initrd binding is no
stronger than a late one.

4) Building the initrd
----------------------

``tools/gen-initrd`` holds three pieces; the target package installs
the first two.

The dracut module
    ``module-setup.sh``, installed as
    ``/usr/lib/dracut/modules.d/90shirudo``, copies the installed
    binary at its own path, the certificate as ``/etc/shirudo/keys/cert.der``
    with the trusted set and its vouches beside it,
    ``shirudo.conf`` when there is one and ``shirudo-initrd.service``,
    enables the unit in ``initrd.target`` and depends on dracut's
    ``tpm2-tss`` and ``systemd-pcrphase`` modules.  It includes itself
    whenever a certificate is installed, so once shirudo is set up
    every initrd dracut builds, for a kernel update or by hand, carries
    it.  A ``dracut.conf(5)`` file can point it at other files
    (``shirudo_binary``, ``shirudo_binary_path``, ``shirudo_cert``,
    ``shirudo_trusted_dir``, ``shirudo_conf``, ``shirudo_unit``), which
    is how the test VM
    builds an initrd from a bundle.

The generator
    ``shirudo-gen-initrd`` drives dracut for one kernel and checks the
    result::

        sudo shirudo-gen-initrd                    # the running kernel
        sudo shirudo-gen-initrd --kver 7.4.0 --output /boot/initrd.img-7.4.0
        shirudo-gen-initrd --check /boot/initrd.img-7.4.0
        shirudo-gen-initrd --print-cmdline         # bpf.keyring_unsealed=1

    Run from a checkout it installs the module into dracut's directory
    first.  ``--binary``, ``--binary-path``, ``--cert`` and ``--unit``
    build from files other than the installed ones; everything after
    ``--`` goes to dracut.  The check reads the initrd with
    ``lsinitrd`` and refuses one that lacks the binary, the
    certificate, the unit, its enablement or the phase measurement.

The installer
    ``install.sh`` does the whole setup of a target in one go, as
    ``curl ... | bash -s -- <options>``: it fetches the release package
    for the host's package format and architecture from the GitHub
    release assets, verifying ``SHA256SUMS`` when the release publishes
    one, installs it, places the certificate given with ``--cert`` (a
    file or a URL), adds ``bpf.keyring_unsealed=1`` to the boot
    command line through ``grubby``, ``update-grub`` or
    ``/etc/kernel/cmdline`` and the loader entries, and rebuilds the
    initrd of the running kernel through the generator.  ``--now``
    starts enforcement right away, staged until the reboot; ``--dry-run``
    prints the plan; ``--package`` installs a local package instead of
    downloading one.  On a system that builds its initrd with
    initramfs-tools the installer stops before the initrd unless told
    ``--switch-to-dracut``, because an initrd without systemd has no
    phase measurements for the binding to lean on.

Unified kernel images take the command line from their ``.cmdline``
section and the initrd from their build; on such systems the module
does its work when ``kernel-install`` or ``ukify`` runs dracut, and the
parameter goes into ``/etc/kernel/cmdline`` before the image is
rebuilt.

5) Checking a target
--------------------

On the target::

    shirudo status --json | python3 -c \
        'import json,sys; d=json.load(sys.stdin); print(d["mode"], d["bound_in"])'

prints ``production initrd`` when both runs did their part.  The
eventlog's ``init`` record carries ``bound_in: initrd`` and the PCR 11
value the register was bound under; ``shirudo attest verify
--require-initrd --expect-bind-pcr=11=<enter-initrd value>`` checks
both against the evidence, with the value computed from the UKI or
initrd by ``systemd-measure`` or ``systemd-pcrlock``.  No pending
record remains under ``/run/shirudo`` once the root's run has adopted
it; a target where it lingers is one whose ``shirudo.service`` has not
run.

The test VM exercises the whole path: ``make -C testing test-tgt TEST_VM_INITRD=1``
builds an initrd from the bundle with the generator, boots the guest
from it and runs the target suite, where ``t1122`` checks the
configuration above and the rest of the suite runs against enforcement
the initrd brought up.  It needs dracut and root on the host.
``make -C testing test-installer`` goes one step further and runs
``testing/t1300-installer-e2e.sh``: a stock cloud image booted in QEMU
with a vTPM gets the bpf-next kernel packages, reboots into them, runs
``install.sh`` with a local target package and certificate, reboots
again and must come up in the production configuration, with ``t1122``
passing on the installed system.
