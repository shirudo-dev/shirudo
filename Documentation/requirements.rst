..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

System requirements
===================

This is the single list of what a host needs before shirudo is built,
installed or initialised on it.  The operator and target roles have
different needs; a development host that plays both needs the union.
shirudo requires Linux v7.4 or newer and a current toolchain and has
no fallback paths for older ones, so a missing item here fails loudly at
build or pre-flight time rather than degrading silently.


1) Target kernel
----------------

The target runs Linux v7.4 or newer.  That release is the base
minimum: it carries the signed BPF loader support shirudo builds on,
and shirudo tracks current upstream from there.  The ``shirudo init``
pre-flight checks that the running kernel has that support
(``signed_loader_kernel_abi``) and refuses otherwise; a load on an
older kernel reports ``kernel_abi_unsupported``.

The table below is what shirudo itself needs; without any of it,
``shirudo init`` does not complete. The test VM kernel uses the slim
configuration embedded in ``contrib/build-kernel-package.sh``. It also
builds the networking modules used by the VM test setup: veth, bridge,
802.1Q, and the netfilter flow table. It also enables IPv6 for the kernel-obs
fixture.

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Option
     - Why shirudo needs it
   * - ``CONFIG_BPF``, ``CONFIG_BPF_SYSCALL``, ``CONFIG_BPF_JIT``
     - The ``bpf()`` syscall, the JIT and bpffs, for the loaders, the
       enforcement programs and the private pin mount.
   * - ``CONFIG_BPF_LSM``, ``CONFIG_BPF_EVENTS``, ``CONFIG_SECURITY``,
       ``bpf`` in ``CONFIG_LSM`` (or ``lsm=`` on the kernel command line)
     - The ``lsm/bpf`` and ``lsm/bpf_prog_load`` gates, the bpffs and
       mount guards, and the filesystem seal are all BPF LSM programs.
       ``CONFIG_BPF_EVENTS`` is listed because ``CONFIG_BPF_LSM``
       depends on it, not for tracing.
   * - ``CONFIG_FUNCTION_TRACER``,
       ``CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS``
     - Base, not an attach-point option: shirudo's own enforcement
       programs attach through BPF trampolines, and a trampoline is
       installed at the function entry that function tracing
       reserves, through an ftrace direct call.  Without function
       tracing there is no entry to patch; with tracing but without
       direct calls the kernel refuses every trampoline attach with
       ``ENOTSUPP``.  Either way ``shirudo init`` cannot attach its
       enforcement.  The same trampolines later carry ``fentry``,
       ``fexit``, ``fmod_ret`` and ``lsm`` upatches at no extra cost.
   * - ``CONFIG_SECURITYFS``
     - ``/sys/kernel/security/lsm``, which the pre-flight reads to
       confirm the BPF LSM is active (``bpf_lsm_active``).
   * - ``CONFIG_DEBUG_INFO_BTF``
     - CO-RE relocation of every shipped and user-built BPF program,
       ``vmlinux.h`` generation, and the ABI check above.
   * - ``CONFIG_KEYS``, ``CONFIG_ASYMMETRIC_KEY_TYPE``,
       ``CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE``
     - The kernel's bpf keyring (``KEY_SPEC_BPF_KEYRING``), which
       holds the operator certificate once ``init`` has enrolled it
       and sealed it.  The kernel is booted with
       ``bpf.keyring_unsealed=1`` so that the keyring takes the
       certificate from the initrd; booted without, it is sealed
       empty and a ``shirudo`` keyring under the user keyring stages
       the certificate until the next reboot.
   * - ``CONFIG_X509_CERTIFICATE_PARSER``,
       ``CONFIG_PKCS7_MESSAGE_PARSER``,
       ``CONFIG_SYSTEM_DATA_VERIFICATION``
     - Parsing ``cert.der`` at ``add_key(2)`` and verifying the
       detached CMS signature at ``BPF_PROG_LOAD``.  The last one is
       usually pulled in by module signing or IMA; set it explicitly
       on a kernel that has neither.
   * - ``CONFIG_CRYPTO_MLDSA``
     - Verification of ML-DSA-87 (FIPS 204) signatures and
       certificates, the only kind shirudo produces.  Without it the
       kernel rejects the certificate at ``add_key(2)``; ``shirudo
       init`` reports the ``cert_kernel_support`` pre-flight failure
       and a load reports ``signature_unsupported``.
   * - ``CONFIG_CRYPTO_SHA512``
     - The signed-attributes digest OpenSSL 3.x emits next to an
       ML-DSA signature; ``CONFIG_CRYPTO_MLDSA`` does not select it.
   * - ``CONFIG_CRYPTO_SHA256``
     - ``excl_prog_hash``, ``payload_sha256``, the measurement register
       and the eventlog digests.
   * - ``CONFIG_TCG_TPM`` plus a TPM driver (``CONFIG_TCG_TIS``,
       ``CONFIG_TCG_CRB``, or the platform's virtual TPM)
     - The measurement register and the attestation key.  A TPM 2.0 is
       mandatory; there is no unmeasured mode.  ``contrib/swtpm.sh``
       provides a software TPM for machines without one.
   * - ``CONFIG_EXT4_FS_SECURITY`` (when ``/var/lib/shirudo`` is on ext4)
     - Allows ``init`` to store the ``security.bpf.shirudo`` label used by
       the filesystem seal.  Other filesystems hosting this state must
       support security xattrs.

``CONFIG_PKCS7_WAIVE_AUTHATTRS_REJECTION_FOR_MLDSA`` is not required: it
only relaxes module-signature checks, and BPF signature verification
accepts the signed-attributes form.

Attach points for upatches
~~~~~~~~~~~~~~~~~~~~~~~~~~

Everything from here on is optional.  shirudo itself runs without any
of it; these options only decide where the upatches an operator ships
can attach.  ``fentry``, ``fexit``, ``lsm`` and ``tp_btf`` upatches
attach through the trampolines and BTF the base table already
requires for shirudo itself, and
``fmod_ret`` works on the ``security_*`` hooks without anything more.
Enable the rest for the kinds of upatch a fleet will run.  An upatch
that needs a missing one fails at load with the kernel's error in the
report; it never attaches somewhere else.

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Option
     - What it enables
   * - ``CONFIG_KPROBES``, ``CONFIG_KPROBE_EVENTS``
     - ``kprobe`` and ``kretprobe`` upatches on arbitrary kernel
       functions.
   * - ``CONFIG_FUNCTION_ERROR_INJECTION``,
       ``CONFIG_BPF_KPROBE_OVERRIDE``
     - ``fmod_ret`` on functions outside the ``security_*`` hooks
       (those marked ``ALLOW_ERROR_INJECTION``) and
       ``bpf_override_return()`` from a kprobe: the two ways a shield
       rejects a call before the function body runs.
   * - ``CONFIG_UPROBE_EVENTS`` (selects ``CONFIG_UPROBES``)
     - ``uprobe.multi`` upatches against userspace binaries.
   * - ``CONFIG_CGROUP_BPF``
     - ``cgroup_skb`` upatches on the cgroup v2 root.
   * - ``CONFIG_NETFILTER``, ``CONFIG_NETFILTER_BPF_LINK``
     - ``netfilter`` upatches at IPv6 pre-routing.


2) Operator kernel
------------------

The operator kernel needs nothing from the tables above.  Building and
signing never touch ``bpf()``: ``shirudo build`` compiles with clang,
runs libbpf's gen_loader, which records map creation, program loads,
CO-RE relocations and attach targets for the signed loader to perform
on the target kernel, and signs the result with libcrypto.  No BPF
program is loaded on the operator, the operator kernel's BTF is not
consulted, and no capability is needed.  ``shirudo bpm build``, ``push``
and ``tree append`` wrap that path and talk to a registry.  Any Linux
kernel that a current clang and OpenSSL 3.5 run on will do.

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Operator activity
     - Kernel requirement
   * - Build and sign upatches; build and publish packages and trees
       (``shirudo build``, ``shirudo bpm build``, ``push``,
       ``tree append``)
     - None.  No BPF is loaded and no kernel BTF is read; the target
       kernel's ``vmlinux.h`` is the only kernel-derived input, see
       below.
   * - Inspect artifacts and packages offline (``shirudo upatch info``,
       ``shirudo bpm info``)
     - None.
   * - Craft and test mitigations: reproduce the bug, load the shield,
       run the reproducer against it
     - A kernel that mimics the target: the fleet's release,
       configuration and BTF, meeting the base and attach-point tables
       of the target kernel, preferably in a VM.
   * - Operator and target on one node (local development)
     - The full target table; the node is a target.

``vmlinux.h`` is the one input the build takes from a kernel.  By
default the tree generates it from the build host's own BTF
(``/sys/kernel/btf/vmlinux``) with ``tools/gen-vmlinux-h``.  When the
fleet runs another kernel, generate it from that kernel's BTF
(``tools/gen-vmlinux-h <vmlinux or BTF file> > vmlinux.h``) and either
build the tree with ``BPF_VMLINUX_H=<path>`` or pass ``--vmlinux
<path>`` to ``shirudo build``.  CO-RE makes the artifact portable
across builds of the same kernel generation, not across kernels that
renamed a field.

Mimic the target to craft mitigations.  Building is where the operator
kernel's requirements end; crafting a mitigation is not.  The agentic
loop the architecture describes (ingest the fix, reproduce it, derive a
shield, load it, run the reproducer against it) needs a kernel that
behaves like the fleet's: the same release and configuration, the same
BTF, the attach points the shield will use.  Run that loop in a VM
booting the target kernel rather than on the operator host.  ``make -C testing
kernel KERNEL_TAG=<tag> KERNEL_CONFIG=<the fleet's .config>`` builds
such a kernel with its BTF, ``make -C testing vm KERNEL=<version>`` boots a
supported selection with a software TPM and a prepared shirudo, and
``make -C testing test-tgt`` runs the target suite in it; any VM of the operator's
own serves the same purpose.  A mitigation that loads and passes its
reproducer on a kernel unlike the fleet's proves nothing about the
fleet.

The test VM runs under KVM and so has the architecture of its host,
x86-64 or arm64; the kernel image is ``bzImage`` or ``Image`` to match.
On a Fedora or RHEL host the scripts print RPM package names for a
missing tool and build the kernel as an RPM.  Where ``cloud-localds`` is
not packaged, ``xorriso`` or ``genisoimage`` builds the cloud-init seed
instead, and ``TEST_VM_QEMU`` names the emulator on a host that has no
``qemu-system-<arch>`` binary, such as ``/usr/libexec/qemu-kvm``.  The
runtime image installs its packages through the caller's ``http_proxy``
or ``TEST_VM_APT_PROXY``; a proxy that only the host's ``/etc/hosts``
names must be given by address, as in ``http://[2001:db8::1]:8080``,
since the libguestfs appliance resolves names through DNS alone.


3) Cryptography
---------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Use
     - Algorithm
   * - Signing key and certificate
     - ML-DSA-87 (FIPS 204, NIST category 5) and nothing else:
       ``shirudo genkey`` has no algorithm option, the builder refuses
       a classical key, the target pre-flight refuses a classical
       certificate.  The smaller ML-DSA parameter sets are not offered:
       a fleet-wide trust anchor gets the largest margin for about
       2 KiB more per signature.  The certificate is self-signed with
       the same key.
   * - ``.upatch`` loader signature
     - Detached CMS over ``loader_insns || data``.  With OpenSSL 3.x the
       SignerInfo carries signed attributes and a SHA-512 message
       digest; OpenSSL 4 signs the content directly.  The kernel
       verifies both forms; see `upatch-spec <upatch-spec.rst>`__.
   * - BPM index and upatch-tree signatures
     - Detached CMS in the same form, produced by ``shirudo-build`` on
       behalf of ``shirudo bpm push`` and ``shirudo bpm tree append``,
       verified on the target with libcrypto against the registered
       certificate.
   * - Payload, program and register digests
     - SHA-256: ``payload_sha256``, ``excl_prog_hash``, the measurement
       register, its policy and the eventlog.
   * - TPM attestation
     - ECDSA P-256 (the attestation key); TPMs sign with nothing
       post-quantum today, so the evidence is classical.
   * - TLS (registries, OTLP and S3 export)
     - TLS 1.3 only with hybrid ML-KEM key exchange only
       (X25519MLKEM768, SecP256r1MLKEM768), on every libcurl client in
       both profiles.  A server that offers only classical groups is
       refused; there is no fallback.  Server certificates are whatever
       the registry or collector presents.


4) Operator host
----------------

* A C toolchain (``cc``, ``make``, ``pkg-config``).
* Current upstream ``clang`` and ``llvm`` with the BPF target, for
  ``shirudo build`` and the embedded enforcement programs.
* OpenSSL 3.5 or newer: ``libcrypto`` and ``libssl`` development files
  and the ``openssl`` command.  3.5 is the first release with ML-DSA;
  the build probe refuses older versions.
* ``libelf``, ``zlib``, ``libcurl`` 7.75 or newer, ``libluajit-5.1``
  and tpm2-tss (``tss2-esys`` 4.0 or newer, ``tss2-tctildr``)
  development files.
* No kernel tree: libbpf, its BPF-side headers and the BPF UAPI headers
  are vendored under ``vendor/libbpf``, and ``vmlinux.h`` is generated
  by the in-tree ``tools/gen-vmlinux-h`` into ``vendor/linux/`` (never
  committed), so neither a submodule nor bpftool is needed.  ``make
  bpf-deps`` refreshes the vendored copy from a kernel tree on
  demand.
* Nothing else: packages, indexes and trees are built and published
  through the same ``shirudo-build`` helper.

The operator never needs a TPM, the kernel keyring or ``CAP_BPF``; only
the private key under ``/var/lib/shirudo/keys/``.


5) Target host
--------------

* The kernel configuration above, booted with the BPF LSM enabled.
* Root (``CAP_SYS_ADMIN``, ``CAP_BPF``) for ``shirudo init`` and every
  state-changing command.
* The target binary from ``make target`` links OpenSSL, libcurl,
  tpm2-tss with its device TCTI, libbpf, libelf, zlib, zstd and
  LuaJIT statically and needs only the C library at runtime, so it
  runs on a distribution whose own OpenSSL predates ML-DSA and reaches
  the TPM from an initrd that holds no tpm2-tss shared objects.
* A TPM 2.0 exposed as ``/dev/tpmrm0`` (discrete, firmware or cloud
  vTPM), or a software TPM reachable through ``tpm.tcti``.  TPM 1.2 is
  refused; there is no opt-out.
* ``systemd`` for the boot units and the timers, and a systemd-based
  initrd (dracut) for the production configuration, with
  ``systemd-pcrphase-initrd.service``, which measures ``enter-initrd``
  and ``leave-initrd`` into PCR 11: the register's binding closes when
  the second one lands, so without the phase measurements an initrd
  binding is no stronger than a late one.  The ``initrd`` document
  lists what the initrd must contain.
* x86-64, arm64 or riscv64.

Operator and target may be on different architectures; the artifact
format is little-endian and the signature is architecture-neutral.


6) Build host for the target binary
-----------------------------------

``make target`` runs ``make target-deps`` first, which builds OpenSSL,
an OpenSSL-backed libcurl and tpm2-tss from source and stages them as
static archives.  The build host then needs static ``libelf``,
``zlib``, ``zstd`` and ``libluajit-5.1`` archives;
``SHIRUDO_TARGET_STATIC_LIBDIR`` names their directory when it is not
the system one.  The operator package, by contrast, links the host's
shared libraries and must be built on the distribution it is installed
on.
