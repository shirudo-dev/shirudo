..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Operating a target
==================

This guide is for whoever runs targets: what to watch, what the
conditions and the categories mean, how to upgrade shirudo and the
kernel underneath it, how to take a target out of service, what to back
up, and how to recover from the states shirudo refuses to paper over.
The `getting-started <getting-started.rst>`__ document brings a target
up; the `initrd <initrd.rst>`__ document describes the production
configuration; this one is about the time after that.

For the opt-in image mode, see `config-images <config-images.rst>`__
and section 8 below. The ordinary installation's paths and executable-upgrade
procedure remain as documented here.

1) The moving parts
-------------------

A target runs no daemon.  Everything is a one-shot command started by
systemd:

.. list-table::
   :header-rows: 1
   :widths: 36 64

   * - Unit
     - Runs
   * - ``shirudo-initrd.service``
     - ``shirudo init`` in the initrd, once per boot; enrols the
       certificate, attaches the LSM, restores the archived upatches,
       binds the register.  Only present in an initrd the dracut
       module built.
   * - ``shirudo.service``
     - ``shirudo init`` from the root file system, before
       ``sysinit.target``: finishes the initrd run (labels, eventlog
       record) or does everything itself in the staging configuration.
   * - ``shirudo-keepalive.timer``
     - ``shirudo status --otel --include-system`` every 5 seconds: the
       conditions below and the system facts as an OTLP keepalive.
   * - ``shirudo-map-export.timer``
     - ``shirudo upatch map --all`` every 5 seconds, with the export
       destination from ``map-export.env``: decoded map snapshots as
       OTLP logs and metrics.
   * - ``shirudo-bpm-repo-update.timer``
     - ``shirudo bpm repo update`` at boot: refreshes the signed
       repository indexes.
   * - ``shirudo-bpm-tree-sync.timer``
     - ``shirudo bpm tree sync`` every 60 seconds when
       ``/etc/shirudo/bpm/upatch-tree.conf`` exists.

The keepalive and map-export units read ``/etc/shirudo/map-export.env``
and the ``map_export.*`` keys of ``/etc/shirudo/shirudo.conf``; the
`telemetry <telemetry.rst>`__ document covers what they send and how
to receive it.  ``shirudo config`` prints every effective setting with
a comment.

State lives in two places.  ``/var/lib/shirudo`` is persistent:
``keys/`` (the primary certificate, the trusted set with its vouches,
the revoked certificates), ``eventlog``, the ``upatches/`` archive
``init`` restores at boot, ``bpm/`` (indexes, cached packages, tree
state) and ``locks/``. The seal protects labelled files against the
operations listed in the `threat model <threat-model.rst>`__. New inodes
inherit the label during creation when their parent has a cached seal
mark; Shirudo's writers hold the parent directory open while creating.
This does not exclude every foreign directory entry or revoke existing
writable references.
``/run/shirudo`` is per boot: the private bpffs with the
LSM pins, the frozen identity map and the pending init record between
the initrd run and the root's.

2) Watching a target
--------------------

``shirudo status`` is the local view and ``shirudo status --json`` the
machine-readable one.  The fields that matter day to day:

``mode``
    ``production`` (certificate in the kernel's bpf keyring, enforcement
    up), ``staging`` (enforcement up, certificate in the user keyring
    until the next reboot) or ``inactive`` (``init`` has not run).

``tpm.reachable``
    Whether a TPM answered on the TCTI, which the human report names on
    its ``TPM:`` line.

``tpm.bound_in``
    ``initrd`` or ``root``: where the register was bound.  Production
    means ``initrd``.

Conditions
    Four, each ``OK``, ``WARN`` or ``ALERT`` with a detail:

    .. list-table::
       :header-rows: 1
       :widths: 22 78

       * - Condition
         - Meaning when not ``OK``
       * - ``LsmAttached``
         - ``ALERT``: the ``lsm/bpf`` link is not pinned; enforcement
           is off and the target has not been initialised this boot.
       * - ``KeyringSealed``
         - ``WARN`` while staging or before ``init``; ``ALERT`` when
           the live keyring is not the one ``init`` froze into the
           identity map or is gone (every load refuses ``tampered``).
           The detail names the kind of keyring, ``bpf`` or ``user``.
       * - ``ChainIntact``
         - ``ALERT`` when replaying this boot's eventlog does not
           reproduce the live register: something extended it that
           shirudo did not record.
       * - ``TpmMeasured``
         - ``WARN`` when no register is bound this boot
           (``degraded``) or no TPM answers; the detail says which.

``keyring_serial`` and ``keyring_serial_pinned``
    The live keyring and the one frozen at ``init``; they match on a
    healthy target.

``certs``, ``certs_enrolled``, ``certs_unvouched``, ``certs_revoked``
    The trusted set on disk (each member's digest, fingerprint and
    whether it is the primary), how many keys the bpf keyring holds
    right now, how many files under ``keys/trusted`` lack a valid
    vouch and are therefore not members, and how many certificates are
    revoked.  The set and the keyring part when a certificate was added
    since the boot (the keyring learns of it at the next boot) or
    revoked (the keyring lost it at once); the `key-lifecycle
    <key-lifecycle.rst>`__ guide covers both.

``register_rebound``, ``init_records``
    Two init records for one TPM reset means the register was bound
    again, which only a TPM reset should allow.

``tamper_attempts``
    What the named guard points refused this boot: ``total`` and one counter
    per point of refusal under ``counters`` (``LoadNotLoader``,
    ``LoadUnsigned``, ``LoadUnverified``, ``LoadKeyringKind``,
    ``LoadKeyring``, ``MapFdWrite``, ``PinRename``,
    ``BpffsUmountAbove``, ``SealWrite``, ``SealPtrace`` and the rest,
    named in ``util/tamper.c`` like the condition types), or
    ``null`` before ``init`` has run.  The human report lists the
    counters that are not zero with what each means under ``Tamper
    attempts``.  A count is an attempt that was refused, so the
    conditions stay ``OK``; it is the operator's cue to look at the
    journal and the host. Image-only device, parent-mount and process
    refusals are not counted; zero does not mean no attempts occurred.

The same conditions leave the target every five seconds as the OTLP
keepalive, so a collector sees a target go ``WARN`` or ``ERROR``, or go
silent, without anyone logging in.

Logs go to the journal under the ``shirudo`` identifier::

    journalctl -t shirudo
    journalctl -b -u shirudo-initrd.service -u shirudo.service

Four events are logged at audit priority and are worth forwarding:
``genkey`` creating signing material (operator), ``upatch load`` with
the upatch name, the keyring used and the program count, ``upatch
load`` or ``unload`` measured with the register value afterwards, and
an ``upatch unload`` that found nothing to unload.  Every refusal is
logged at error priority with its category.

The target's own account proves nothing to anyone else.  The operator's
health check is ``shirudo attest`` on the target and ``shirudo attest
verify`` on the operator against the value ``shirudo attest predict``
computes from what was installed, with a fresh nonce each time; the
`tpm <tpm.rst>`__ document describes the loop and what each refusal
means.

3) Upgrading shirudo
--------------------

The bpffs guards admit the executable whose inode ``init`` recorded at
boot.  A package upgrade replaces the binary with a new inode, so until
the next boot the new binary can run read-only commands but cannot
load, unload or set the payload xattr on a pin: those report
``tampered`` or a permission error from the LSM.  An upgrade is
therefore::

    sudo apt install ./shirudo-target_<version>_amd64.deb   # or dnf, or the tarball
    sudo shirudo-gen-initrd
    sudo reboot

The second step matters: the initrd carries its own copy of the binary,
and ``init`` warns at boot when the root's binary differs from it.
Kernel package updates rebuild the initrd through dracut's hooks, so
the module's copy follows the binary installed at that time; a shirudo
upgrade alone does not trigger a rebuild.  The pending eventlog record
and the seal label are the same across versions, so an upgrade needs no
state conversion.  When shirudo is installed on a target for the first
time, the package enables ``shirudo.service`` for the next boot and
nothing more; ``systemctl start shirudo.service`` brings enforcement up
immediately, in the staging configuration until the reboot.

4) Kernel updates
-----------------

A new kernel package makes dracut build an initrd for it, and the
shirudo module includes itself whenever a certificate is installed, so
the production configuration carries over without action.  The kernel
parameter ``bpf.keyring_unsealed=1`` lives in the boot loader's
configuration, which the installer wrote once.

The upatches do not carry over by themselves.  ``init`` restores the
archived set on every boot, and a upatch built for another kernel
generation fails its load with ``btf_mismatch`` or
``verifier_rejected``; boot-restore is all or nothing, so one such
upatch leaves the target with the LSM up, nothing loaded and no
register bound (``TpmMeasured`` warns, ``status`` says
``degraded``).  Before rebooting into a new kernel generation,
either uninstall the packages that do not cover it or make sure the
tree the node follows has selectors that do: an operation whose
``kernel_release_prefix`` or ``kernel_build_id`` no longer matches is
not applied again, but a upatch the node already loaded stays archived
until a ``delete`` removes it.  The `upatch <upatch.rst>`__ guide
covers selectors.  After the reboot, ``shirudo init`` reports the
upatch that failed; remove it (``bpm uninstall``, or the tree's
``delete``) and re-run ``init``, which then binds the register.

5) Taking a target out of service
---------------------------------

Enforcement cannot be switched off at runtime, by design: the LSM
links are held by pins that nothing but shirudo can remove and that
shirudo has no command to remove.  Decommissioning is therefore a
reboot with shirudo gone from the boot path::

    sudo shirudo bpm uninstall <package>        # every installed package
    sudo systemctl disable --now shirudo-keepalive.timer \
        shirudo-map-export.timer shirudo-bpm-repo-update.timer \
        shirudo-bpm-tree-sync.timer
    sudo systemctl disable shirudo.service
    sudo apt remove shirudo-target               # or dnf; removes the dracut module
    sudo rm /etc/default/grub.d/shirudo.cfg && sudo update-grub   # or the equivalent
    sudo dracut --force
    sudo reboot
    sudo rm -rf /var/lib/shirudo /etc/shirudo

The package's removal scripts disable the units; the initrd must be
rebuilt without the module so that ``shirudo-initrd.service`` does not
run, and the kernel parameter should go so that the bpf keyring is
sealed empty again at boot.  The state directory can only be removed
after the reboot: while the seal is attached, its labels stop root
from deleting it.  An unload before the reboot is optional but
measured, which keeps the last evidence of the node complete.

6) Backup and restore
---------------------

Back up ``/var/lib/shirudo`` and ``/etc/shirudo``:

* ``keys/`` is replaceable from the operator: the primary, the
  trusted set with its vouches and the revoked certificates.  The
  signing keys are never on a target.
* ``eventlog`` is the node's measurement history across boots, append
  only.  Evidence and verification work per boot, so losing it costs
  the history, not the security of the running boot; keep it where
  audit records go.
* ``upatches/`` and ``bpm/`` are what ``init`` restores at boot and
  what the tree sync continues from.  They are also recoverable from
  the registry by reinstalling.
* ``/etc/shirudo`` holds the configuration, the repository
  registrations and their certificates, the tree configuration and the
  node labels.

Restoring onto a reinstalled target is a matter of putting the files
back before ``shirudo init`` runs; the labels are reapplied by ``init``.
Restoring an ``eventlog`` whose last boot is not this one is harmless:
readers work from this boot's ``init`` record on.  Restoring tree
state from another node is not: the sequence it continues from belongs
to that node.

The eventlog grows by one line per init, load, unload and tree
operation and is never rotated by shirudo.  ``eventlog.max_bytes`` in
``shirudo.conf`` caps it (``0``, the default, is unlimited); at the
cap every state-changing operation refuses ``eventlog_full`` before it
does anything, so the register and the log never diverge.  Because the
file is sealed, nothing but shirudo can truncate or rotate it while
enforcement is up, and shirudo has no command to; archive it at
reinstall time, and size the cap to the lifetime of the installation.

7) Recovering
-------------

``tampered``
    The register, the keyring or the pins are not what the operation
    expected.  Nothing was changed.  It is also what a legitimate
    concurrent operator produces, so refresh the state (``shirudo
    status``, the eventlog, the journal) before deciding; never retry
    the same input blind.  A register the eventlog cannot explain or a
    keyring that is not the frozen one is an incident; a reboot
    restores a clean boot and the evidence of the bad one is in the
    eventlog, the journal and whatever the TPM certified before.

``degraded`` and ``TpmMeasured`` warning
    ``init`` attached the LSM but did not bind the register: a
    boot-restore failure (section 4) or a TPM that could not be
    reached, which the ``TpmMeasured`` detail tells apart.  The journal of ``shirudo-initrd.service`` or
    ``shirudo.service`` names the step.  Fix the cause and re-run
    ``shirudo init``; it is idempotent and completes what it can.

The register is gone before the next reboot
    A process with the owner authorisation undefined the NV index, or
    the TPM was reset without a reboot (hibernation does that).  Every
    extension fails ``tpm_error`` and ``init`` refuses to bind again
    before the next TPM reset, except in the hibernation case, which
    the reset count on the record lets ``init`` tell apart.  Reboot,
    and read the eventlog of the boot it happened in.

``KeyringSealed`` warns ``staging``
    The kernel sealed the bpf keyring empty at boot, so ``init`` staged
    the certificate in the user keyring.  The kernel parameter is
    missing, the initrd has no shirudo in it, or ``shirudo-initrd.service``
    failed; ``journalctl -b -u shirudo-initrd.service`` and the
    `initrd <initrd.rst>`__ document say what to check.  Enforcement
    is up either way.

The initrd copy differs
    ``init`` warns when the root's binary or trusted set differs from
    the initrd's: the initrd was not rebuilt after an upgrade, a
    ``keys add`` or a ``keys revoke``.  Run ``shirudo-gen-initrd`` and
    reboot at the next opportunity.

``certs_unvouched`` is not zero
    A file under ``keys/trusted`` has no vouch that verifies under a
    member, so it is not enrolled: something other than ``shirudo keys
    add`` put it there, or the key that vouched for it was revoked.
    Remove it, or re-vouch it from an operator holding a remaining key
    and run ``keys add`` again.

A key is compromised
    ``shirudo keys revoke <fingerprint>`` on every target the key is
    enrolled on, then ``shirudo-gen-initrd``; the `key-lifecycle
    <key-lifecycle.rst>`__ guide gives the order and what the command
    does to the archive.  A target that cannot be reached keeps
    trusting the key until it is; the evidence of the ones that have
    revoked carries the ``key_revoke`` event.

A pending record lingers
    ``/run/shirudo/eventlog.pending`` is the initrd run's record until
    the root's ``init`` appends it.  One that remains after boot means
    ``shirudo.service`` did not run or could not append; its journal
    says why.  Loads still work meanwhile, since the readers treat the
    pending record as part of this boot's log.

``shirudo init --check-only`` runs the pre-flight without touching
anything and is the first thing to run on a target that misbehaves.

8) Categories and exit status
-----------------------------

Every ``upatch load`` and ``unload`` ends in one category, in the
report (``--report``) and in the journal.  The commands exit ``0`` on
success, ``1`` on any refusal or failure and ``2`` on a usage error;
``shirudo init`` exits ``1`` when the pre-flight fails or a step does.

.. list-table::
   :header-rows: 1
   :widths: 26 44 30

   * - Category
     - Meaning
     - Action
   * - ``ok``
     - The operation completed and was measured.
     - None.
   * - ``init_prereqs_missing``
     - A pre-flight check failed; the message names each.
     - ``shirudo init --check-only``; fix what it lists.
   * - ``kernel_abi_unsupported``
     - The kernel lacks the signed-loader ABI.
     - A current upstream kernel.
   * - ``keyring_missing``
     - No trust anchor is frozen this boot: ``init`` has not run.
     - ``shirudo init``.
   * - ``tampered``
     - The register, the keyring or a pin disagrees with what the
       operation expected (section 7).
     - Inspect before acting.
   * - ``version_mismatch``
     - ``--expect-version-id`` named another build.
     - Match operator and target builds.
   * - ``eventlog_full``
     - The eventlog cap would be exceeded.
     - Raise ``eventlog.max_bytes``.
   * - ``parser_rejected``
     - The file is not a valid upatch, or its name is unsafe.
     - Rebuild it.
   * - ``signature_rejected``
     - The kernel rejected the loader's signature.
     - The artifact was signed with another key, or altered.
   * - ``signature_unsupported``
     - The kernel cannot verify ML-DSA.
     - ``CONFIG_CRYPTO_MLDSA`` and ``CONFIG_CRYPTO_SHA512``.
   * - ``lsm_denied``
     - The LSM denied the load (``EACCES``), or the kernel refused the
       keyring (``EPERM``).
     - The load named a keyring other than the anchor.
   * - ``verifier_rejected``
     - The verifier rejected the payload; the log is in the report.
     - Rebuild against the target kernel's BTF.
   * - ``btf_mismatch``
     - A CO-RE relocation found no match.
     - Regenerate ``vmlinux.h`` from the target kernel.
   * - ``payload_mismatch``
     - The unload directive's expected payload is not the pin's.
     - Build the directive for the loaded artifact.
   * - ``already_unloaded``
     - Nothing to unload.
     - None.
   * - ``detach_failed``
     - The link could not be detached.
     - Inspect the journal; the pin is intact.
   * - ``tpm_error``
     - The register could not be extended or bound.
     - ``/dev/tpmrm0``, ``tpm.tcti``, ``tpm.owner_auth``; section 7.
   * - ``unknown``
     - An error without a closer category; errno is in the report.
     - Read the report.

8) Operating image mode
-----------------------

Use ``shirudo image status`` to inspect the active config root hash, PCR,
TPM reset and restart counts, event sequence and pending state. Ordinary target commands
hold the config operation lock and use one held config directory for the
operation. They refuse a pending activation or PCR/history inconsistency;
attestation follows the same rule.

Activate a complete locally staged bundle or pull it by HTTPS prefix::

    shirudo image update /path/to/new-config
    shirudo image update https://config.example/shirudo/config

A successful command means required key and mount effects completed.
Validation failures before the pending selection is saved leave the current
config usable. Once activation is pending, interruption or an ambiguous TPM
response blocks further mutations and config attestation. The node keeps
running; Shirudo never initiates a reboot and has no same-boot recovery
command. The operator chooses when to reboot. Trusted startup then verifies
the pending selection and records a fresh BOOT event before completing
initialization. Do not remove pending records or rewrite the eventlog to
make a failure disappear.

Additional BPF keys and revocations arrive through signed config images;
local ``keys add``, ``bpm key add`` and ``keys revoke`` commands are refused.
Repository registration changes also require a signed config: ``bpm config
register add``, ``remove`` and ``rm`` do not mutate image-mode trust inputs.
Package installation and upgrades, tree sync, export and attestation remain
available using the active authenticated configuration. New BPF signing keys
require boot-time enrollment and a reboot; live activation cannot add them
to the sealed keyring. Config updates using the existing signing-key set and
the signed upatch flow remain live. Runtime executable updates are
intentionally disruptive: replace the runtime image and authenticated boot
hash, regenerate the UKI and reboot. Replacing the config verification
certificate uses that same reboot procedure.

New signer enrollment has a provisioning limitation: the CLI does not queue
an otherwise refused candidate for reboot. An existing activation record
selects its cached bundle before the bootstrap ``config.image`` default.
Changing only the default does not select a new signer set. Plan the
boot-time provisioning separately; do not erase the journal to force the
selection. First-boot provisioning and live updates with already enrolled
signers are the workflows exercised by the image fixture suite.

Back up the image bundles under ``/var/lib/shirudo/images`` together with
``/var/lib/shirudo/config-update``, normal installed state and eventlogs.
The activation journal includes TPM reset identity and expected PCR values;
a journal from another target or an inconsistent partial restore must not be
accepted as the current boot. The selected cached config is verified and
receives a fresh BOOT event after reset. Retain operator source directories
and signing keys separately from target backups.

A valid old config remains acceptable in this implementation. Check the intended
root hash when operating a deployment; do not infer rollback prevention or
proof of activation against direct TPM writers from the measurement alone.
