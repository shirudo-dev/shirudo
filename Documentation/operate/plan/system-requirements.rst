..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

System requirements
===================

What the target, the operator host and the host that builds the target
binary need. A missing requirement fails the build, ``shirudo init`` or
the load. shirudo has no compatibility mode and no fallback for an older
kernel.

Architectures
-------------

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Architecture
     - Notes
   * - x86-64
     - Target and operator. The test VM runs on x86-64 hosts. Targets
       need upstream commit ``31ac959c915c`` (see below).
   * - arm64
     - Target and operator. The test VM runs on arm64 hosts.
   * - riscv64
     - Target and operator. The build applies the hardening flags that
       exist for riscv64. No test VM runs on riscv64.

All three are little-endian, the byte order of the ``.upatch`` container.

:doc:`/contribute/arch-support` compares how far each architecture is
tested and what the kernel supports on it.

Target kernel
-------------

The target runs a bpf-next kernel with the signed-loader ABI. A release
number does not identify such a kernel: development trees report the
release they follow (the test kernel reports ``7.4.0-rc1-bpf-next+``), and
the ABI and the patches below decide whether shirudo works on it.

Kernel source
~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Component
     - Requirement
   * - bpf-next
     - The signed-loader ABI: ``bpf_map.sha``, ``bpf_map.excl_prog_sha``,
       ``bpf_prog_aux.sig`` with ``keyring_serial``, ``keyring_type``
       and ``verdict``, the ``.bpf`` keyring reachable as
       ``KEY_SPEC_BPF_KEYRING`` with the ``bpf.keyring_unsealed``
       parameter, and the kfuncs ``bpf_inode_init_xattr`` and
       ``bpf_real_data_inode``. The test suite runs bpf-next commit
       ``57fae4059380``.
   * - Upstream commit ``1041fca2ee8a``
     - ``keys: add KEY_SPEC_DM_VERITY_KEYRING``. ``shirudo init``
       enrolls and seals the config certificate in the ``.dm-verity``
       keyring through ``KEY_SPEC_DM_VERITY_KEYRING``. Apply it to a
       bpf-next tree that predates it.
   * - Upstream commit ``31ac959c915c``
     - ``x86/ftrace: Mark jmp mode by clearing bit 63 of trampoline
       address``, x86-64 only, in bpf-next and in the bpf fixes tree for
       7.4. Without it, detaching one BPF program from a hook that others
       share can crash tasks that run the hook during the update, on
       kernels where an ftrace callback starts at an odd address (seen
       with gcc 13 and ``CONFIG_CC_OPTIMIZE_FOR_SIZE=y``). Unloading an
       upatch detaches its programs from hooks that other programs
       share. Apply it to an x86-64 tree that predates it.
   * - :src:`kernel/0001-tpm-Let-LSMs-inspect-userspace-commands.patch`
     - Adds the ``tpm_command`` LSM hook. ``shirudo init`` attaches
       ``lsm/tpm_command`` to refuse an untrusted ``TPM2_NV_Extend`` of
       its register and fails without the hook.
   * - :src:`kernel/0002-bpf-Read-security.bpf-xattrs-for-LSM-programs-without-the-caller-s-permission.patch`
     - Lets an LSM program read a ``security.bpf.`` xattr without the
       calling task's read permission on the inode, as the in-kernel
       LSMs read their labels. Without it the seal takes a label its
       caller may not read for a missing one unless the inode carries a
       mark, which root can arrange with an idmapped mount or an ACL.
   * - :src:`kernel/0003-bpf-Let-sleepable-LSM-programs-attach-to-the-remaining-inode-hooks.patch`
     - Lets a sleepable LSM program attach to ``inode_mkdir``,
       ``inode_link``, ``inode_set_acl``, ``inode_remove_acl``,
       ``inode_file_setattr`` and ``inode_copy_up``. The seal reads
       labels in those hooks and ``shirudo init`` fails to attach them
       without it.
   * - :src:`kernel/0004-bpf-Treat-dentry-d_parent-as-a-trusted-pointer.patch`
     - Lets an LSM program pass ``dentry->d_parent`` to the xattr kfunc.
       The seal reads the label of the directory a new entry goes into
       from it; without the patch the verifier refuses the seal's entry
       hooks.

:doc:`/internals/kernel-patches` gives the upstream status of the
carried patches.

Identify the kernel
~~~~~~~~~~~~~~~~~~~

- Record the source commit and the patches applied when you build the
  kernel. ``make -C testing kernel`` writes them as ``commit=``,
  ``upstream_commit=`` and ``patches_applied=`` to a
  ``<name>-kernel-build`` file beside the kernel packages, for bpf-next
  ``bpf-next-kernel-build``.
- ``shirudo init --check-only`` checks the ABI of the running kernel
  from its BTF (``signed_loader_kernel_abi``). A load on a kernel
  without it fails with ``kernel_abi_unsupported``.
- The test harness builds bpf-next by default. It also builds release
  tags and refuses any tag older than v7.4. It applies the patches in
  :src:`kernel/` to either. A release kernel still needs ``kernel/0001``.

Kernel configuration
~~~~~~~~~~~~~~~~~~~~

shirudo needs every option below. The test kernel's configuration is the
slim configuration in :src:`testing/vm/build-kernel.sh`, which also enables
options that only the tests use.

.. list-table::
   :header-rows: 1
   :widths: 38 62

   * - Option
     - Reason
   * - ``CONFIG_BPF_SYSCALL``
     - The ``bpf()`` system call, the BPF file system that holds
       shirudo's pins, and the ``.bpf`` keyring. Pre-flight check
       ``bpffs_supported``.
   * - ``CONFIG_BPF_JIT``
     - BPF trampolines, through which the LSM programs and ``fentry``,
       ``fexit``, ``fmod_ret`` and ``lsm`` upatches attach, exist only
       with the JIT. ``CONFIG_BPF_LSM`` depends on it.
   * - ``CONFIG_BPF_LSM``, ``CONFIG_SECURITY``, ``bpf`` in
       ``CONFIG_LSM``
     - Every admission gate, guard and the seal are BPF LSM programs.
       Without ``bpf`` in ``CONFIG_LSM``, add it with ``lsm=`` on the
       command line. Pre-flight check ``bpf_lsm_active``.
   * - ``CONFIG_BPF_EVENTS``, with ``CONFIG_PERF_EVENTS`` and
       ``CONFIG_KPROBE_EVENTS`` or ``CONFIG_UPROBE_EVENTS``
     - ``CONFIG_BPF_LSM`` depends on ``CONFIG_BPF_EVENTS``, which
       depends on these.
   * - ``CONFIG_SECURITYFS``
     - ``/sys/kernel/security/lsm``, which ``bpf_lsm_active`` reads.
   * - ``CONFIG_FUNCTION_TRACER``, ``CONFIG_DYNAMIC_FTRACE``,
       ``CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS``
     - The kernel installs a trampoline on an ftrace-managed function as
       an ftrace direct call and refuses the attach without direct-call
       support.
   * - ``CONFIG_DEBUG_INFO_BTF``
     - ``/sys/kernel/btf/vmlinux``: the ABI check, CO-RE relocation in
       every signed loader, and attaching LSM programs by BTF id.
   * - ``CONFIG_KEYS``
     - The ``.bpf`` and ``.dm-verity`` keyrings. Pre-flight check
       ``kernel_keyring``.
   * - ``CONFIG_ASYMMETRIC_KEY_TYPE``,
       ``CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE``,
       ``CONFIG_X509_CERTIFICATE_PARSER``
     - ``add_key(2)`` of the signing and config certificates as
       ``asymmetric`` keys. Pre-flight check ``cert_kernel_support``.
   * - ``CONFIG_PKCS7_MESSAGE_PARSER``,
       ``CONFIG_SYSTEM_DATA_VERIFICATION``
     - Verification of the detached PKCS#7 signature of a loader at
       ``BPF_PROG_LOAD`` and of a config image's root hash by dm-verity.
   * - ``CONFIG_CRYPTO_MLDSA``
     - ML-DSA-87 certificates and signatures, the only kind shirudo
       produces. Without it ``add_key(2)`` fails with ``ENOENT`` or
       ``ENOPKG`` and ``cert_kernel_support`` fails.
   * - ``CONFIG_CRYPTO_SHA512``
     - The signed-attributes digest that OpenSSL 3.x adds to an ML-DSA
       signature. ``CONFIG_CRYPTO_MLDSA`` does not select it.
   * - ``CONFIG_CRYPTO_SHA256``
     - The ``sha256`` hash trees of the runtime and config images.
   * - ``CONFIG_TCG_TPM`` and a TPM driver (``CONFIG_TCG_TIS``,
       ``CONFIG_TCG_CRB`` or the platform's)
     - ``/dev/tpmrm0``. Pre-flight check ``tpm2_reachable``.
   * - ``CONFIG_BLK_DEV_DM``, ``CONFIG_DM_VERITY``
     - The runtime and config images are mapped as dm-verity devices:
       verity format 1, SHA-256, 4096-byte blocks.
   * - ``CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG``
     - The kernel verifies the signed root hash of a config image. The
       ``.dm-verity`` keyring exists only with this option.
   * - ``CONFIG_BLK_DEV_LOOP``
     - The image files are attached to loop devices.
   * - ``CONFIG_EXT4_FS``
     - The images are ext4 file systems, mounted read-only.
   * - Security extended attributes on the file system of
       ``/var/lib/shirudo`` (``CONFIG_EXT4_FS_SECURITY`` on ext4)
     - The seal labels writable state with ``security.bpf.shirudo``,
       on new inodes while the kernel creates them.
   * - ``CONFIG_TMPFS``, ``CONFIG_TMPFS_XATTR``
     - ``/run/shirudo`` carries the same label.

The dm-verity root-hash check also accepts a config signed by a key in
the kernel's built-in trusted keyring, and in the secondary or platform
keyring when ``CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG_SECONDARY_KEYRING`` or
``CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG_PLATFORM_KEYRING`` is set.
:doc:`/operate/plan/hardening` lists what that means for who can sign a
config, and the options the trust model assumes beyond this table:
lockdown, module signature enforcement, ``CONFIG_COMPAT`` and others.

Kernel command line
~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 38 62

   * - Parameter
     - Reason
   * - ``bpf.keyring_unsealed=1``
     - The kernel leaves the ``.bpf`` keyring unsealed at boot, so that
       ``shirudo init`` in the initrd enrolls the trusted certificates
       and seals it. Without it the kernel seals the keyring empty and
       ``init`` fails: ``bpf keyring serial=<n> was sealed empty at boot;
       boot with bpf.keyring_unsealed=1``.
   * - ``dm_verity.keyring_unsealed=1``
     - The same for the ``.dm-verity`` keyring and the config
       certificate. Without it ``init`` fails with ``initrd boot keys:
       dm-verity keyring sealed empty at boot; boot with
       dm_verity.keyring_unsealed=1``.
   * - ``lsm=<list>`` including ``bpf``
     - Only when ``CONFIG_LSM`` does not list ``bpf``.

``shirudo-gen-initrd --print-cmdline`` prints the two keyring parameters.
In production the command line is part of the signed unified kernel
image. See :doc:`/operate/deploy/boot-integration`.

Attach points for upatches
~~~~~~~~~~~~~~~~~~~~~~~~~~

shirudo runs without these options. They decide where the upatches a
fleet runs can attach. ``fentry``, ``fexit``, ``lsm`` and ``tp_btf``
upatches need nothing beyond the table above. An upatch whose attach
point is missing fails to load.

.. list-table::
   :header-rows: 1
   :widths: 38 62

   * - Option
     - Enables
   * - ``CONFIG_KPROBES``, ``CONFIG_KPROBE_EVENTS``
     - ``kprobe`` and ``kretprobe`` upatches.
   * - ``CONFIG_FUNCTION_ERROR_INJECTION``
     - ``fmod_ret`` on kernel functions outside the ``security_*`` hooks
       that are marked for error injection.
   * - ``CONFIG_BPF_KPROBE_OVERRIDE``
     - ``bpf_override_return()`` from a ``kprobe`` upatch.
   * - ``CONFIG_UPROBE_EVENTS``
     - ``uprobe``, ``uretprobe``, ``uprobe.multi`` and
       ``uretprobe.multi`` upatches.
   * - ``CONFIG_CGROUP_BPF``
     - ``cgroup_skb`` upatches.
   * - ``CONFIG_NETFILTER``, ``CONFIG_NETFILTER_BPF_LINK``
     - ``netfilter`` upatches.

:doc:`/upatches/write/attach-kinds` describes each attach kind.

TPM
---

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Requirement
     - Reason
   * - TPM 2.0 through the kernel resource manager, ``/dev/tpmrm0``
     - The measurement register and the attestation key. There is no
       mode without a TPM. An authenticated-image target accepts only a
       ``device:`` TCTI, so that ``lsm/tpm_command`` sees every command.
       The static target binary contains only the device TCTI.
   * - SHA-256 PCR bank
     - shirudo reads PCRs 9 and 11 and the config PCR in the SHA-256
       bank and extends PCR 9 and the config PCR there.
   * - RSA-3072 primary keys with RSASSA and SHA-256 in the owner
       hierarchy
     - The key that authorizes writes to the register through
       ``TPM2_PolicySigned``.
   * - ECC NIST P-256 primary keys with ECDSA and SHA-256 in the
       endorsement hierarchy
     - The attestation key that ``shirudo attest`` signs evidence with.
   * - An endorsement key in the RSA-2048 or ECC P-256 template
     - Credential activation for ``shirudo attest --challenge``.
   * - NV index ``0x01818E00`` free
     - shirudo defines its register there. The index clears at TPM reset.
   * - Endorsement hierarchy without an authorization value
     - shirudo creates the attestation and endorsement keys with an
       empty authorization.
   * - Owner hierarchy authorization, if set, in ``tpm.owner_auth``
     - shirudo defines the NV index and the writer key under the owner
       hierarchy. See :doc:`/reference/formats/configuration`.

Target userspace
----------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Requirement
     - Reason
   * - systemd 256 or newer
     - ``shirudo-initrd.service`` orders itself after ``tpm2.target``,
       which systemd 256 introduced. With an older systemd, ``init`` can
       run before the TPM is available.
   * - A systemd initrd built by dracut, with the ``systemd``,
       ``systemd-initrd`` and ``systemd-pcrextend`` modules
       (``systemd-pcrphase`` in older dracut)
     - The dracut module ``90shirudo`` installs and enables
       ``shirudo-initrd.service``. ``shirudo-gen-initrd`` refuses an
       initrd without ``systemd-pcrphase-initrd.service``.
   * - A unified kernel image booted through ``systemd-stub``
     - ``systemd-pcrphase-initrd.service`` measures ``enter-initrd`` into
       PCR 11 only under ``systemd-stub``. The register's write policy
       binds PCRs 9 and 11 while the initrd runs.
   * - ``/var/lib/shirudo`` writable and mounted under ``/sysroot``
       while the initrd runs
     - ``shirudo-initrd.service`` has
       ``RequiresMountsFor=/sysroot/var/lib/shirudo``. Its file system
       needs security extended attributes.
   * - No other task adds keys to or restricts the ``.bpf`` and
       ``.dm-verity`` keyrings before ``shirudo-initrd.service``
     - ``init`` refuses a keyring that holds keys other than its own or
       carries a restriction it did not install.
   * - Root
     - Run shirudo as root on a target. ``shirudo init`` refuses a
       non-zero effective UID (pre-flight check ``root``).
   * - ``CAP_IPC_LOCK`` or an ``RLIMIT_MEMLOCK`` large enough for the
       process
     - ``shirudo`` locks all its memory with ``mlockall(2)`` before it
       dispatches a command and exits with ``hardening: cannot lock
       process memory`` when that fails. The shipped units set
       ``LimitMEMLOCK=infinity``.

The target needs no external tools: it maps and verifies the images
through kernel interfaces.

Pre-flight checks
-----------------

``shirudo init`` runs these checks first and stops when one fails.
``shirudo init --check-only`` runs only them. See
:doc:`/reference/cli/init`.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Check
     - Passes when
   * - ``root``
     - The effective UID is 0.
   * - ``bpf_lsm_active``
     - ``/sys/kernel/security/lsm`` lists ``bpf``.
   * - ``bpffs_supported``
     - ``/proc/filesystems`` lists ``bpf``.
   * - ``signed_loader_kernel_abi``
     - The kernel BTF has the fields of the signed-loader ABI with the
       expected types.
   * - ``cert_on_disk``
     - The primary certificate exists, is a regular file and is not
       empty.
   * - ``cert_algorithm``
     - Every trusted certificate is ML-DSA-87.
   * - ``cert_kernel_support``
     - The kernel accepts every trusted certificate as an
       ``asymmetric`` key, probed in the thread keyring.
   * - ``kernel_keyring``
     - ``keyctl(2)`` resolves the user keyring and the ``.bpf`` keyring.
   * - ``embedded_loader``
     - The binary carries its two embedded BPF objects.
   * - ``tpm2_reachable``
     - ``/dev/tpmrm0`` is readable and writable, or ``tpm.tcti`` names a
       TCTI.

Run the checks as root on a target:

.. code-block:: console

   target# shirudo init --check-only
   Pre-flight checks:
     OK    root
     OK    bpf_lsm_active
     OK    bpffs_supported
     OK    signed_loader_kernel_abi
     OK    cert_on_disk
     OK    cert_algorithm
     OK    cert_kernel_support
     OK    kernel_keyring
     OK    embedded_loader
     OK    tpm2_reachable: TCTI from the config: device:/dev/tpmrm0
   10 of 10 passed

A failed check prints ``FAIL`` and its reason, and the command exits 1
after ``init: pre-flight failed, <failed> of <total> checks``.

Network
-------

Every HTTPS connection to a registry, an OTLP collector or an S3
endpoint uses TLS 1.3 with the hybrid key exchange ``X25519MLKEM768`` or
``SecP256r1MLKEM768``. A server that offers neither fails the handshake,
unless its exact host name is listed in ``tls.classical_hosts``. Then
shirudo also offers ``X25519`` and ``secp256r1`` and logs a warning when
the handshake uses one of them.

Operator host
-------------

The operator host never loads BPF and never uses a TPM or the kernel
keyrings. Any Linux kernel on which the tools below run serves.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Requirement
     - Reason
   * - OpenSSL 3.5 or newer: ``libcrypto``, ``libssl`` and the
       ``openssl`` command with ML-DSA
     - ML-DSA-87 signing and hybrid ML-KEM TLS. The build refuses older
       versions.
   * - ``libcurl`` 7.75 or newer, ``tss2-esys`` 4.0 or newer,
       ``tss2-tctildr``, ``libelf``, ``zlib``, LuaJIT with GC64
     - Linked by the ``shirudo`` binary, which is the same program on
       both roles. LuaJIT GC64 is required on the supported 64-bit
       architectures.
   * - ``clang`` and LLVM 23 with the BPF target
     - ``shirudo build`` runs ``/usr/bin/clang``, and the helper of the
       Debian package ``/usr/lib/llvm-23/bin/clang``. It does not search
       ``PATH``; ``make SHIRUDO_CLANG_PATH=<path>`` builds a helper that
       runs another. It compiles for BPF instruction set v4.
   * - The target kernel's ``vmlinux.h``
     - The one kernel-derived input of a build. ``shirudo build`` takes
       ``--vmlinux``, else ``./vmlinux.h``, else
       ``./vendor/linux/vmlinux.h``, else ``<sharedir>/shirudo/vmlinux.h``
       of the installation. See :doc:`/reference/cli/build`.
   * - ``veritysetup`` (``cryptsetup-bin`` or ``cryptsetup``),
       ``mkfs.ext4`` (``e2fsprogs``), Bash and GNU coreutils
     - Building runtime and config images, and ``shirudo image verify``.
   * - ``llvm-strip`` (LLVM), ``readelf`` (binutils) and ``ldd``
     - ``shirudo-gen-runtime`` strips the target binary it puts on the
       runtime image and resolves the libraries of a dynamic one.
   * - ``CAP_IPC_LOCK`` or an ``RLIMIT_MEMLOCK`` large enough for the
       process
     - ``shirudo`` and ``shirudo-build`` lock all their memory before
       they dispatch a command.

The operator package depends on clang 23, as ``clang-23`` in the Debian
package and ``clang >= 23`` in the RPM, and on ``llvm`` and the
``veritysetup`` package. Debian unstable, Fedora 45 and apt.llvm.org
ship clang 23. On Debian testing or Ubuntu 24.04, add Debian unstable or
apt.llvm.org as a package source before you install the package. A
build from source runs ``/usr/bin/clang``, so point that at clang 23.
The operator and target packages conflict, so one host cannot install
both.

Build host for the target binary
--------------------------------

``make target`` builds a static PIE binary with no interpreter, no
shared-library dependencies and no library search path. It runs ``make
target-deps`` first.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Requirement
     - Reason
   * - Network access to the OpenSSL and curl release downloads and to
       the tpm2-tss Git repository
     - ``make target-deps`` builds OpenSSL 3.5.9, libcurl 8.18.0 and
       tpm2-tss 4.2.0 from source as static archives. Set
       ``TARGET_DEPS_PREBUILT=1`` and ``SHIRUDO_TARGET_PKG_CONFIG_PATH``
       to use prebuilt ones.
   * - autoconf, automake, libtool and autoconf-archive
     - tpm2-tss's ``bootstrap`` script.
   * - Static ``libelf.a``, ``libz.a``, ``libzstd.a`` and
       ``libluajit-5.1.a`` with GC64
     - Taken from the first of ``/usr/lib/<multiarch>``, ``/usr/lib64``
       and ``/usr/lib`` that holds ``libelf.a``.
       ``TARGET_SYSTEM_LIBDIR=`` names another directory.
   * - Static glibc, ``libm``, startup objects and compiler runtime with
       static PIE support (``libc6-dev`` on Debian, ``glibc-static`` on
       Fedora)
     - The static PIE link. They come from the compiler's sysroot.
   * - ``clang`` 23 with the BPF target
     - The BPF objects embedded in the binary.
   * - BTF of a kernel with the signed-loader ABI
     - The embedded BPF objects read ``prog->aux->sig`` and do not
       compile against an older ``vmlinux.h``. The build uses
       ``BPF_VMLINUX_BTF=<file>``, or ``BPF_VMLINUX_H=<file>``, else
       ``artifacts/bpf-next-kernel-debs/vmlinux.btf`` when present, else
       ``/sys/kernel/btf/vmlinux``.
   * - ``readelf`` (binutils)
     - The build checks that the result is a static PIE.

The operator binary links the host's shared libraries. Build it on the
distribution it is installed on.

Related
-------

- :doc:`/operate/deploy/deployment-checklist`
- :doc:`/operate/plan/hardening`
- :doc:`/operate/deploy/boot-integration`
- :doc:`/internals/kernel-interfaces`
- :doc:`/start/install`
