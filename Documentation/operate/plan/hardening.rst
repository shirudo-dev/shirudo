..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators, SecOps

Hardening checklist
===================

shirudo keeps root from loading BPF, changing its state and extending
its register. It relies on the kernel and the boot chain for the rest:
root with a way to write kernel memory, replace the kernel or talk to the
TPM directly goes around every check shirudo makes. This checklist lists
what a production target needs beyond :doc:`/operate/plan/system-requirements`,
and says for each item whether shirudo checks it.

The ``Checked`` column reads:

- ``init fails``: init refuses to bring enforcement up without it
- ``warns``: init logs a warning and continues
- ``enforced``: shirudo's LSM programs enforce it themselves
- ``no``: nothing in shirudo checks it. Only your build, your boot chain
  or attestation catch a target without it

:doc:`/security/threat-model` explains the threats behind each item.

Kernel configuration
--------------------

.. list-table::
   :header-rows: 1
   :widths: 30 52 18

   * - Item
     - Why
     - Checked
   * - Lockdown in integrity mode: optional
     - shirudo's ``bpf2`` object refuses, from ``init`` on, what
       integrity mode refuses: unsigned modules, ``/dev/mem``, MSRs,
       I/O ports, PCI resources, debugfs writes, ACPI table overrides
       and hibernation, and ``/proc/kcore`` with them, which the mode
       leaves readable. The kernel's lockdown LSM, where it runs, refuses
       first and covers the boot before ``init``; module signatures and
       the resume device need the rows below either way. Do not use
       confidentiality mode: it withholds ``bpf_probe_read_kernel()``
       from BPF programs, which shirudo's own programs need, so they
       would not load.
     - no
   * - Module signatures: ``CONFIG_MODULE_SIG``, with every module the
       target loads signed by a key the kernel trusts
     - Without it the kernel loads a module without asking lockdown, and
       the module runs in the kernel with no BPF involved. With it,
       ``bpf2`` refuses an unsigned module from ``init`` on where the
       kernel does not refuse it first (``CONFIG_MODULE_SIG_FORCE`` or
       ``module.sig_enforce=1``).
     - partly: from ``init`` on, an unsigned module is refused and
       counted as ``ModuleSignature``
   * - ``CONFIG_STRICT_DEVMEM`` and ``CONFIG_IO_STRICT_DEVMEM``, or no
       ``/dev/mem`` at all
     - Limits ``/dev/mem`` before ``init``, after which ``bpf2`` refuses
       it.
     - no
   * - ``CONFIG_BLK_DEV_WRITE_MOUNTED=n``
     - The seal acts on file operations. Root writing to the block
       device under ``/var/lib/shirudo`` changes sealed state without
       any of them. With the option off, the kernel refuses writes to a
       mounted block device.
     - no
   * - No resume device: no ``resume=`` on the command line, an empty
       ``CONFIG_PM_STD_PARTITION`` and none named in the initrd, or no
       hibernation (``CONFIG_HIBERNATION=n``, ``nohibernate`` or
       ``lockdown=integrity``)
     - Resuming from a hibernation image replaces kernel memory with
       what the image holds, and the initrd resumes before ``init``,
       from an image root can write to swap.
     - partly: from ``init`` on, hibernating is refused, and so is a
       write of the ``HibernateLocation`` EFI variable through which
       systemd's initrd finds an image the UKI does not name, counted
       as ``HibernateLocation``
   * - Kexec
     - A kexec boots a kernel and initrd of root's choosing while the
       TPM keeps this boot's register and PCRs.
     - enforced: no task loads a kexec image or initramfs, counted as
       ``Kexec``
   * - 64-bit userspace only: ``CONFIG_COMPAT=n``, and on x86-64
       ``CONFIG_IA32_EMULATION=n`` and ``CONFIG_X86_X32_ABI=n``
     - shirudo's LSM programs are written for 64-bit callers.
     - no
   * - ``CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG=y``
     - The kernel checks the config image's signature only with this
       option.
     - init fails: the config image cannot be mapped
   * - ``CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG_SECONDARY_KEYRING=n`` and
       ``CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG_PLATFORM_KEYRING=n``
     - The kernel tries the built-in trusted keys, the secondary keyring
       and the platform keyring before ``.dm-verity``. Every key in them
       can sign a config the target activates: the platform keyring holds
       firmware keys, and the secondary keyring takes further keys at
       runtime when a trusted key signed them. The built-in keys always
       count, including the module signing key of the kernel build, so
       keep that key in the same custody as the config key.
     - no
   * - The ``tpm_command`` LSM hook carried by the shirudo kernel build
     - The hook lets shirudo refuse extensions of its register by
       other processes.
     - init fails: ``lsm/tpm_command`` cannot attach
   * - ``CONFIG_I2C_CHARDEV=n`` and ``CONFIG_SPI_SPIDEV=n``, or neither
       reaching the TPM's bus
     - The ``tpm_command`` hook sees only commands written through the
       kernel's TPM driver. Root with ``i2c-dev`` or ``spidev`` access to
       the TPM's bus sends commands past it.
     - no
   * - An IOMMU confining device DMA
     - A device that root can program, or one plugged in, can otherwise
       write kernel memory by DMA.
     - no

Kernel command line
-------------------

.. list-table::
   :header-rows: 1
   :widths: 30 52 18

   * - Item
     - Why
     - Checked
   * - ``bpf.keyring_unsealed=1``
     - Without it, the kernel seals ``.bpf`` empty at boot and init cannot
       enroll the BPF signers.
     - init fails
   * - ``dm_verity.keyring_unsealed=1``
     - Without it, the kernel seals ``.dm-verity`` empty at boot and init
       cannot enroll the config certificate.
     - init fails
   * - ``bpf`` in the LSM list
     - The LSM programs attach only when the BPF LSM is active.
     - init fails: pre-flight ``bpf_lsm_active``
   * - An authenticated command line, in the signed UKI, that the boot
       loader cannot replace
     - Root who can change the command line can drop the parameters
       above, or mask the initrd unit with
       ``rd.systemd.mask=shirudo-initrd.service``, and boot the target
       without enforcement.
     - no

Boot chain
----------

.. list-table::
   :header-rows: 1
   :widths: 30 52 18

   * - Item
     - Why
     - Checked
   * - A signed UKI that carries the shirudo initrd, booted with Secure
       Boot and measured boot
     - The UKI authenticates the initrd, its bootstrap file and the
       runtime image's root hash.
     - no
   * - The ``enter-initrd`` phase measured into PCR 11 before init
     - The PCR 11 value is how a verifier tells a binding made in the
       initrd from a later one. systemd measures the phase only for a
       UKI booted through its stub.
     - warns: ``tpm: PCR 11 holds no phase measurement``
   * - No unit seals ``.bpf`` or ``.dm-verity`` before
       ``shirudo-initrd.service``, for example systemd's
       ``systemd-keyring-setup``, which systemd 263 adds
     - Init must install the keyrings' restriction itself.
     - init fails: the keyring carries a restriction init did not
       install
   * - Monitoring for a target that boots without enforcement
     - A failed or skipped ``shirudo-initrd.service`` does not stop the
       boot. The target comes up with the verdict ``lsm-off`` and no
       register.
     - no: ``shirudo status`` and attestation show it
   * - Only shirudo's own executables on the runtime image
     - Every executable on the runtime image runs with shirudo's
       authority. Never add a shell, a debugger or an interpreter with
       ``--extra-binary``.
     - no

TPM
---

.. list-table::
   :header-rows: 1
   :widths: 30 52 18

   * - Item
     - Why
     - Checked
   * - A config PCR that nothing extends after the initrd: not IMA's PCR,
       10 by default, and not PCR 15, which systemd extends with the
       machine ID, file systems and encrypted volumes
     - Any extension of the config PCR after init blocks every command
       but ``status`` and ``image status`` until the next reboot, and
       ``status`` reports ``tampered``.
     - partly: init refuses PCRs 9, 11 and above 15, and ``status``
       detects a later extension
   * - A ``device:`` TCTI
     - A software TPM or another TCTI is for development.
     - init fails: an active target refuses any other TCTI
   * - Custody of the TPM owner password, when the TPM has one
     - The password is in the UKI's initrd and readable by root in the
       runtime image.
     - no
   * - Protection of the TPM device node
     - shirudo opens the TPM by its device path and does not
       authenticate the answers to its own commands. Evidence that
       :doc:`/operate/run/attest` verifies is signed by the TPM's attestation
       key and does not depend on that path.
     - no

Host files
----------

.. list-table::
   :header-rows: 1
   :widths: 30 52 18

   * - Item
     - Why
     - Checked
   * - ``/etc/shirudo/map-export.env`` and
       ``/etc/shirudo/bpm/environment`` empty, or owned by root with mode
       ``0600`` and reviewed
     - The timer services read them, and they are host files outside the
       signed config. Their variables reach processes with shirudo's
       authority: ``BPM_OCI_SCHEME=http`` switches registry traffic to
       cleartext, ``BPM_OCI_CA_FILE`` adds a trusted CA, and the
       ``OTEL_EXPORTER_OTLP_*`` variables name an export destination when
       the config names none. Signatures still protect what a target
       installs.
     - partly: the overrides ``SHIRUDO_KEYS_DIR``, ``SHIRUDO_TPM_TCTI``,
       ``SHIRUDO_TPM_OWNER_AUTH``, ``SHIRUDO_EVENTLOG_PATH``,
       ``SHIRUDO_EVENTLOG_PENDING_PATH``, ``SHIRUDO_INITRD_RELEASE`` and
       ``SHIRUDO_SYSROOT`` are refused
   * - ``/etc/shirudo/init.env`` absent
     - ``shirudo.service`` reads it unless the drop-in from
       ``shirudo-gen-runtime`` clears it, as
       :ref:`unit-drop-ins` installs.
     - no

Related
-------

- :doc:`/operate/plan/system-requirements` for what shirudo needs to run
- :doc:`/operate/deploy/boot-integration` for the UKI, the command line and the
  config PCR
- :doc:`/operate/run/attest` for the checks that catch a target booted
  without these items
- :doc:`/security/threat-model` for the threats and residual risks
