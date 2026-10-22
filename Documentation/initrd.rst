..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Bringing shirudo up from the initrd
===================================

Every target starts enforcement from an authenticated systemd initrd before
untrusted workloads. The initrd verifies a runtime image and a separate signed
config image. The host root filesystem stays in place; there is no root pivot.
See `config-images <config-images.rst>`__ for the image contents and generation
commands, `architecture <architecture.rst>`__ for the LSM flow and
`tpm <tpm.rst>`__ for measurement and attestation.

1) What boot needs
-------------------

* An authenticated UKI containing the bootstrap binary and configuration.
  ``runtime.image`` names the cached runtime bundle and ``runtime.root_hash``
  gives its exact expected SHA-256 root. Missing image settings are an error.
* The runtime image contains Shirudo, its ELF interpreter and libraries,
  initial BPF certificate, config-verification certificate and bootstrap TPM
  settings. The initial config bundle is signed by an accepted config key.
* Boot parameters ``bpf.keyring_unsealed=1 dm_verity.keyring_unsealed=1``.
  The initrd enrolls the trust anchors and seals both kernel keyrings. There
  is no fallback to a user keyring when the BPF ring is sealed empty.
* A TPM 2.0, the required BPF and dm-verity kernel interfaces, and a reserved
  static SHA-256 PCR for config measurements. See
  `requirements <requirements.rst>`__ for the exact kernel requirements,
  including disabled 32-bit compatibility.
* ``/sysroot/var/lib/shirudo`` mounted writable before Shirudo starts. If
  state is on a separate filesystem, mount it in the initrd too. Config
  selections and cached bundles must be durable before PCR extension.
* ``systemd-pcrphase-initrd.service`` and its ``enter-initrd`` measurement
  before Shirudo binds its upatch register. A direct QEMU kernel/initrd boot
  tests the handoff but does not establish a measured UKI or the PCR 11 phase
  distinction. Non-systemd initrds are unsupported.

2) The initrd run
-----------------

``shirudo-initrd.service`` runs after the root filesystem is available at
``/sysroot`` and before switch-root. Shirudo binds writable state at
``/var/lib/shirudo``, verifies the images and determines the boot signer set.
The initial BPF certificate comes from the runtime; additional certificates
need valid vouches from the selected config. Config revocations exclude keys
from enrollment. The config verification certificate is enrolled in
``.dm-verity`` and the BPF trust set in ``.bpf``; both keyrings are sealed.

Initialization labels writable state, loads the two embedded bootstrap BPF
objects and freezes their shared state before attaching admission gates.
The authenticated bootstrap task has temporary authority to finish startup.
It mounts the runtime under the device and mount guards, measures config,
applies revocations before restoring signed upatches, and binds the upatch
measurement register. Runtime and config files receive no seal xattrs;
writable state keeps them. All BPF upatches still require signed loaders.

The mounts live below ``/run/shirudo`` so systemd carries them through
switch-root: ``runtime`` is ``ro,nodev,nosuid``, ``config`` is
``ro,nodev,nosuid,noexec``, and ``bpffs`` holds the links and maps. Kernel
keyrings and TPM state survive independently. The initrd eventlog record
waits in ``/run/shirudo/eventlog.pending`` for the root service to adopt.

3) The root service
--------------------

Generate a systemd drop-in with ``shirudo-gen-runtime --unit-output`` and
install it at ``/etc/systemd/system/shirudo.service.d/verity.conf``. It invokes
the runtime's ELF interpreter with its host cache disabled and library paths
inside the image, then starts the runtime binary. The loader and executable
both come from the verified runtime, not from the host root filesystem.

The service re-runs ``init``, checks the existing guards and measurements,
and adopts the initrd eventlog record without another extension. Successful
exec from the runtime grants the task mark needed for these operations.
There are no lasting executable inode identities or root-only bootstrap
fallback. Do not apply caller-controlled seccomp to this invocation.

4) Building the initrd
----------------------

The target package installs ``tools/gen-initrd/module-setup.sh`` as dracut
module ``90shirudo`` and installs ``shirudo-gen-initrd``. The module includes
the bootstrap binary, a preflight certificate copy, authenticated
``/etc/shirudo/shirudo.conf``, the enabled initrd service, TPM support and the
image drivers. Actual BPF enrollment uses the verified image's trust set.

After building and provisioning the images, generate an initrd with::

    sudo shirudo-gen-initrd --bootstrap-conf bootstrap.conf \
        --kver <kernel-release> --output /boot/initrd-shirudo.img
    shirudo-gen-initrd --check /boot/initrd-shirudo.img
    shirudo-gen-initrd --print-cmdline

``--binary`` and ``--binary-path`` select the authenticated bootstrap copy;
``--cert``, ``--trusted-dir`` and ``--unit`` select preflight material and the
service. Arguments after ``--`` go to dracut. The archive check requires the
binary, bootstrap config, certificate, service, enablement and phase unit.
A dracut configuration can provide the same inputs through ``shirudo_binary``,
``shirudo_binary_path``, ``shirudo_cert``, ``shirudo_trusted_dir``,
``shirudo_conf`` and ``shirudo_unit``.

Build and authenticate the UKI with this initrd and both enrollment boot
parameters. Do not start an unprotected target from the host filesystem and
expect image setup to repair earlier writable references. The package
installer can install files and prepare dracut; it does not provision the
images or authorize their runtime hash, and its old ``--now`` mode is removed.

5) Checks, updates and recovery
-------------------------------

Using the configured runtime invocation, check::

    shirudo status --json
    shirudo image status

The status must report ``mode: production``, ``keyring_mode: bpf`` and
``tpm.bound_in: initrd``. The config status must be consistent with no pending
activation, and the upatch register must match this boot's eventlog.
Attestation verification should require the approved UKI measurements,
``--require-initrd`` and the expected config root and PCR.

Live config updates activate another signed immutable image. BPF upatches
continue to use their signed-loader path. A new runtime, config verification
key or BPF signer requires the appropriate authenticated boot rollout and
reboot. The existing activation record takes precedence over the initial
``config.image`` default; the CLI has no separate next-boot selection command.

If activation is interrupted after pending state is recorded, further changes
and config attestation refuse. The node continues running and Shirudo never
reboots automatically. The operator chooses when to reboot; trusted startup
re-verifies the selected image, records a fresh BOOT event and finishes init.
It does not retry the previous boot's PCR extension.

The standard disposable VM run is ``sudo make -C testing test-tgt``. It
exercises this initrd handoff, signed config and upatch updates, task and
writable-state protection, TPM checks and interrupted activation.
