..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: shirudo contributors

Test coverage
=============

This page lists what the tests under :src:`testing/` cover, by family, by
area and by threat, and what no test covers. A test is named by its
number here, and by its file name without ``.sh`` in the family
tables. :doc:`/contribute/testing/testing` explains the families, the numbering
and how to run them.

Families
--------

Operator tests (``t?0??``) run on the build host. Target tests
(``t?1??``) run as root in a VM the family boots, against a target
initialized from the initrd with the dm-verity runtime image and a
signed config image.

``ci-checks`` (0)
~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 36 64

   * - Test
     - Covers
   * - ``t0001-check-dco``
     - ``check-dco.sh``: subject, body and sign-off, the identities it
       rejects, the author the sign-off must match, merge commits
   * - ``t0002-check-spdx``
     - ``check-spdx.sh``: tag form by file type, the two expressions,
       the dual license of BPF sources and package files, vendored
       licenses, the upstream tag of a carried file, and the tree itself
   * - ``t0003-check-style``
     - ``check-style.sh``: checkpatch at 100 columns, the block-comment
       opener, the subject length, the integer, parser, copy and
       format rules
   * - ``t0004-ci-commit-range``
     - ``ci-commit-range.sh``: the ranges for a pull request, a push and
       a force push
   * - ``t0005-gen-sbom``
     - ``gen-sbom.sh``: the SPDX documents of a target and an operator
       package, and the archives it refuses to leave out
   * - ``t0006-check-coccinelle``
     - ``check-coccinelle.sh``: a match that fails the check with its
       file, line and rule, the vendored sources left out, a rule named
       alone, the rewrite of ``-D patch``, a case for each rule taken
       from CERT C, a case for each BPF hazard rule beside the safe
       form it leaves alone, and the tree itself
   * - ``t0007-check-operator-linkage``
     - ``check-operator-linkage.sh``: the libraries an operator binary
       may link and its own interpreter, another loader, a library
       outside the list or named like one on it, and the operator
       binaries when built

``build`` (1)
~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 36 64

   * - Test
     - Covers
   * - ``t1001-build-dispatch``
     - Helper resolution: ``SHIRUDO_BUILD``, ``PATH`` and a missing
       helper
   * - ``t1002-command-surface``
     - Removed fleet-management commands are absent and rejected
   * - ``t1003-static-target``
     - The target binary is a static PIE with OpenSSL 3.5 or newer and
       no shared TLS closure, fits the default runtime image, and the
       operator binary is dynamic. Runs only where ``make target`` has
       built ``shirudo-target``
   * - ``t1004-target-system-libdir``
     - Where ``make target-deps`` finds the system static archives
   * - ``t1005-binrpm-pkg``
     - rpm packages: metadata, file lists, requirements and scriptlets;
       the clang 23 requirement of both operator packages and the clang
       path of the Debian one
   * - ``t1006-gen-initrd-cli``
     - Initrd generator and installer options, the installer's
       ``--dry-run`` plan
   * - ``t1007-test-vm-cli``
     - Test VM scripts: kernel selection, host dependencies, arm64
       boot settings, the bundle stamp
   * - ``t1008-kernel-ami-config``
     - The slim kernel configuration for NitroTPM CRB, EC2, EFI and SSM
   * - ``t1009-upatch-isa``
     - The upatch build compiles for BPF instruction set v4, and a
       ``-mcpu`` in ``--extra-cflags`` replaces it; a dense ``switch``
       compiles to branches, not a table in ``.rodata``
   * - ``t1010-test-filter``
     - Script regex matching through ``-t`` and ``TEST_FILTER``, command-line
       precedence, empty and invalid patterns, ordering and failure status

``signing`` (2)
~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 36 64

   * - Test
     - Covers
   * - ``t2001-genkey``
     - ML-DSA-87 only, certificate key identifiers, ``--force``
   * - ``t2002-mldsa-sign``
     - The CMS form the kernel verifies, refusal of RSA and ML-DSA-65
       keys, a one-bit change in the signed bytes
   * - ``t2003-keys-set``
     - The trusted set and its digest, revoked certificates left out,
       ``attest predict`` agreement
   * - ``t2004-keys-vouch``
     - ``keys vouch``, and ``keys add`` admitting only vouched
       certificates
   * - ``t2005-keys-signer``
     - Signer identification for a revocation purge, prediction of a
       revoke event
   * - ``t2101-keys``
     - Two enrolled certificates, both keyrings as ``keys`` lists them,
       a upatch signed by the second loads
   * - ``t2102-keys-add``
     - Live ``keys add`` is refused under a signed config
   * - ``t2103-keys-revoke``
     - Live ``keys revoke`` is refused under a signed config

``upatch`` (3)
~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 36 64

   * - Test
     - Covers
   * - ``t3001-upatch-parse``
     - Malformed ``.upatch`` containers are refused, files over 16 MiB
       without mapping them
   * - ``t3002-upatch-decoders``
     - Decoder metadata, Lua sandbox limits, refusal of bytecode
   * - ``t3003-upatch-map-types``
     - Map type labels, arena maps only through a serializer
   * - ``t3004-upatch-serializer-metadata``
     - Serializer metadata and the builder's refusals
   * - ``t3005-upatch-serializer-pages``
     - Paged serializer JSON and ``upatch map`` output
   * - ``t3006-cgroup-skb-metadata``
     - ``cgroup_skb`` ingress and egress attach metadata
   * - ``t3007-uprobe-multi-metadata``
     - ``uprobe.multi`` globs to file offsets and the target's build ID
   * - ``t3008-override-metadata``
     - kprobe override and ``fmod_ret`` attach metadata
   * - ``t3009-netfilter-metadata``
     - netfilter attach metadata
   * - ``t3010-unsupported-network-sections``
     - Attach kinds the builder refuses
   * - ``t3011-string-bounds``
     - Names and the tree repository are refused rather than cut
   * - ``t3101-target-fixtures``
     - Prebuilt fixtures load and unload, foreign and own-keyring
       fixtures are refused, a map fixture exports
   * - ``t3102-upatch-arena-serializer``
     - Arena serializer pagination on a target
   * - ``t3103-version-gate``
     - ``--expect-version-id`` refuses ``version_mismatch``
   * - ``t3104-payload-mismatch``
     - An unload with the wrong payload refuses ``payload_mismatch``
   * - ``t3105-load-unload``
     - Load, the payload xattr on the pin, unload
   * - ``t3106-upatch-get``
     - ``upatch get`` source lines and JSON
   * - ``t3107-uprobe-multi``
     - A live ``uprobe.multi`` load, refusal after a build ID change
   * - ``t3108-status-many``
     - ``status --json`` with eighty loaded upatches lists all of them
   * - ``t3109-policy-labels``
     - A loaded upatch labels executable and ordinary files, ORing
       multiple policy bits with a preexisting xattr; its signed policy
       section binds verdict programs to shared task and socket policy
       maps
   * - ``t3110-double-load``
     - A second load of a loaded upatch is refused as ``already_loaded``

``tpm`` (4)
~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 36 64

   * - Test
     - Covers
   * - ``t4001-tpm-wire``
     - Policy digests, names and attestation structures against values
       computed independently
   * - ``t4002-eventlog-pending``
     - The initrd's pending record and its adoption
   * - ``t4003-register``
     - Register lifecycle before ``init``, binding, ``attest``,
       ``verify``, ``predict`` and ``challenge``, a TPM reset. Runs in
       the register VM
   * - ``t4004-config-attest``
     - Config activation in the evidence and its verification. Runs in
       the register VM
   * - ``t4101-initrd``
     - The production configuration: ``init`` from the initrd, adoption,
       PCR 11 after the binding, pins under ``/run``
   * - ``t4102-tpm-chain``
     - Replay, measured load and unload, evidence from the VM's TPM,
       challenges with ECC and RSA endorsement keys
   * - ``t4103-nv-writer``
     - The ``tpm_command`` guard: root without authority cannot extend
       the register, through inherited and nonblocking descriptors
       too

``image`` (5)
~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 36 64

   * - Test
     - Covers
   * - ``t5001-config-image``
     - Image builder and ``veritysetup`` format, superblock and size
       checks, the ML-DSA-87 root signature, runtime acceptance by the
       exact root, the generator scripts
   * - ``t5002-image-config``
     - Settings a config may set, symbolic links and special files
   * - ``t5003-image-keys``
     - Signer set and revocation records in a config
   * - ``t5004-image-cli``
     - Local key and repository changes refused, ``config`` output,
       repository certificates inside the image, tree trust
   * - ``t5005-image-cleanup``
     - Candidate removal and its ``EBUSY`` retries
   * - ``t5006-image-bootstrap``
     - Bootstrap settings in the initrd
   * - ``t5007-config-update``
     - Activation events, the pending latch, interruption, locks,
       symbolic links in state
   * - ``t5008-text-lines``
     - Long lines and NUL bytes in settings files
   * - ``t5101-verity-boot-signers``
     - The ``.dm-verity`` keyring, boot enrollment of a vouched signer
   * - ``t5102-verity-config``
     - Config classification, corruption, live activation from A to B
   * - ``t5103-verity-cli``
     - Key and repository changes require a signed config
   * - ``t5104-verity-revocation``
     - Signed revocation unlinks the signer and purges its upatch
   * - ``t5105-verity-interruption``
     - An interruption after measurement blocks changes and attestation

``tamperproof`` (6)
~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 36 64

   * - Test
     - Covers
   * - ``t6001-seal-create``
     - The creation helpers label what they create under a labeled
       directory
   * - ``t6002-seal-seccomp``
     - The seal builds with either seccomp layout in ``vmlinux.h``
   * - ``t6003-tamper-points``
     - Every tamper counter has a name and a meaning
   * - ``t6004-conditions``
     - Status conditions: both keyrings, register, pins, config
       activation
   * - ``t6005-mode-objects``
     - The embedded admission and seal objects include image
       enforcement
   * - ``t6006-harden``
     - Memory locking at startup, failing closed
   * - ``t6007-output-paths``
     - Output paths: no symbolic links, directories or devices
   * - ``t6101-mode-objects``
     - Device, memory and config-root guards are pinned
   * - ``t6102-siggate``
     - A foreign-signed upatch is refused
   * - ``t6103-lsm-deny``
     - An unsigned userspace ``BPF_PROG_LOAD`` is denied
   * - ``t6104-prog-load-keyring-gate``
     - A valid signature against a keyring of the caller's is denied
   * - ``t6105-mount-lockdown``
     - Unmount, lazy unmount, remount and mount over the bpffs
   * - ``t6106-pin-rename``
     - Renames in the bpffs
   * - ``t6107-bpf-cmd-deny``
     - ``bpf()`` commands left to shirudo or denied, opening pins,
       maps and links
   * - ``t6108-tamper-counters``
     - Counters move with refusals and root cannot reset them
   * - ``t6109-map-lockdown``
     - Map descriptors, pin reads and serializer test runs
   * - ``t6110-pr-set-mm-identity``
     - ``PR_SET_MM`` executable changes
   * - ``t6111-seal-scratch``
     - The seal against root, including policy xattr add, update and
       removal, root at a file system uid that cannot read the label,
       directly and through an idmapped mount, chattr and rmdir
   * - ``t6112-key-permission``
     - The ``.bpf`` and ``.dm-verity`` keyrings cannot be changed
   * - ``t6113-verity-authority``
     - Task authority on exec, fork and failed exec
   * - ``t6114-output-paths``
     - Output paths aimed at sealed state
   * - ``t6115-archive-restore``
     - Artifacts brought into the archive, a hidden state directory,
       ``/etc/initrd-release``
   * - ``t6116-attach-scope``
     - ``attach_scope_mismatch`` in a foreign network or cgroup
       namespace, and through a substituted PMU
   * - ``t6117-signed-metadata``
     - Edited attach metadata, name, map count and unload target
   * - ``t6118-foreign-entries``
     - Entries root brings into sealed directories
   * - ``t6119-perf-attach``
     - ``PERF_EVENT_IOC_SET_BPF``
   * - ``t6120-umount-above``
     - Unmounts above the bpffs, by subtree and by propagation
   * - ``t6121-bpffs-entries``
     - Directories, symbolic links and hard links in the bpffs
   * - ``t6122-persist-undo``
     - A load whose archive copy fails is undone
   * - ``t6123-foreign-state-root``
     - An unlabeled state root bound over the path
   * - ``t6124-overlay-copy-up``
     - An overlay over the state root
   * - ``t6125-tpm-identity``
     - A substituted TPM device is refused by its attestation key name
   * - ``t6126-kexec``
     - ``kexec_load`` and ``kexec_file_load``
   * - ``t6127-proc-substitution``
     - Config read through a substituted ``/proc``
   * - ``t6128-register-lock``
     - The lock that keeps register and eventlog in step
   * - ``t6129-keyring-seal``
     - The exact keyring check at ``init``
   * - ``t6130-verity-devices``
     - Image mount flags, device-mapper table changes, mount changes
   * - ``t6131-verity-process``
     - ``ptrace`` and memory writes to an image-authorized task
   * - ``t6132-verity-hidden``
     - A hidden bpffs cannot make shirudo fall back to host settings
   * - ``t6133-seal-init-xattr``
     - Labels at inode creation
   * - ``t6134-seal-task``
     - ``ptrace`` and perf events on a running shirudo
   * - ``t6135-task-descriptors``
     - Descriptors through ``/proc`` and ``pidfd_getfd``
   * - ``t6136-secure-exec``
     - Secure-exec mode, no program interpreter, and the library
       variables a target refuses
   * - ``t6137-traced-exec``
     - A traced task cannot exec shirudo
   * - ``t6138-upatch-integrity``
     - A mutated loader, the payload binding, links by pin or id
   * - ``t6139-serializer-runs``
     - Repeated peeks and concurrent drains
   * - ``t6140-status-keyrings``
     - Status reports both keyrings with each certificate's frozen key
   * - ``t6141-policy-inheritance``
     - Task policy accumulates across parent exec, child exec and
       interpreter handlers
   * - ``t6142-policy-socket-inheritance``
     - Task policy is inherited by a listener and its accepted socket
   * - ``t6143-unmeasured-load``
     - A load stopped before its extend is counted, reported by status
       and undone by the next upatch command
   * - ``t6144-returned-archive``
     - The archive directory with its mark evicted takes nothing and
       lets no labeled archive out; an archive without a record of its
       load is reported, not restored by init and removed by the next
       upatch command

``bpm`` (7)
~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 36 64

   * - Test
     - Covers
   * - ``t7001-bpm-cli``
     - Subcommands, reference validation before network access, source
       and tree configuration lines
   * - ``t7002-bpm-info``
     - READMEs of local and OCI packages, archive integrity
   * - ``t7003-bpm-key``
     - ``bpm key`` from files and OCI references, ``bpm pull``, which
       replaces no file, not even after a failed digest, and names none
       after a layer title that is not a package name
   * - ``t7004-bpm-repo-update``
     - The repository update unit and timer and their package
       scriptlets, as text
   * - ``t7005-bpm-publish``
     - ``bpm build``, ``bpm push`` with a signed index, ``bpm tree
       append``
   * - ``t7006-policy-labels``
     - Beefile policy declarations are serialized into the signed
       upatch section
   * - ``t7101-bpm-tree``
     - Tree sync with a selector
   * - ``t7102-bpm-tree-sequential``
     - Re-sync and the next generation
   * - ``t7103-bpm-tree-delete``
     - A delete operation and adding the upatch back
   * - ``t7104-bpm-tree-kconfig``
     - A kconfig selector the target cannot read stops the sync where it
       is; the operation applies once the config reads

``otel`` (8)
~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 36 64

   * - Test
     - Covers
   * - ``t8001-otel-map``
     - OTLP mapping, retries, S3 uploads, tenant IDs, the insecure
       override
   * - ``t8002-map-export-config``
     - Map export settings
   * - ``t8003-systemd-map-export``
     - Exporter units and timers and their package scriptlets, as text
   * - ``t8004-status-otel``
     - The keepalive log record
   * - ``t8005-tls-policy``
     - TLS 1.3 with ``X25519MLKEM768`` only
   * - ``t8006-otel-transport``
     - OTLP environment variables, headers and limits
   * - ``t8101-map-export-all``
     - ``upatch map --all`` and JSON lines
   * - ``t8102-otel-backend``
     - The map-export service and timer with decoders
   * - ``t8103-otel-serialized-metric``
     - Serializer metrics, peek and drain
   * - ``t8104-export-config``
     - Precedence of config, environment and command line, a failed
       export
   * - ``t8105-export-tls``
     - CA and client certificate selection, the S3 CA

``end2end`` (9)
~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 36 64

   * - Test
     - Covers
   * - ``t9001-dns-observability-matrix``
     - The DNS packet builders the matrix test uses
   * - ``t9101-kernel-obs``
     - ``kernel-obs`` with eight serializers, records from real events,
       draining exports and matching OTLP and ClickHouse snapshots
   * - ``t9102-kernel-obs-net``
     - Socket families and matching OTLP and ClickHouse snapshots
   * - ``t9103-kernel-obs-priv``
     - Privilege and executable-mapping records in maps, OTLP and ClickHouse
   * - ``t9104-kernel-obs-dns-matrix``
     - DNS over loopback in maps, OTLP and ClickHouse
   * - ``t9105-delivery``
     - Registry, tree sync, load, export and attestation end to end
   * - ``t9106-policy-exec-graph``
     - A signed SHPL section labels five executables; its BPF policy
       allows unlabeled tasks to exec unlabeled files and 0x1, allows
       0x1 to exec 0x2, and denies 0x1 and socket policy B from execing
       unlabeled files; socket-storage bits allow 127.0.0.1 for policy A
       and deny it for B; final evidence includes the loaded policy upatch
   * - ``t9107-ksock-dummy``
     - A signed syscall program creates and connects a kernel UDP socket,
       sends a fixed datagram to the VM host and releases it; signed
       unload removes its pin. The host receiver checks the exact payload
       and fails the end-to-end run if no valid datagram arrives

Unit suites and fuzz targets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The unit suites in :src:`testing/unit/` cover eight of the modules in
:src:`util/`: ``chain``, ``hex``, ``json``, ``kernel_abi``,
``kernel_build_id``, ``kernel_release``, ``string`` and ``upatch``, and
``overflow`` the arithmetic of :src:`include/shirudo/overflow.h`. The
other modules are reached through the test helpers, the fuzz targets and
the binaries the functional tests run.

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Fuzz target
     - Input
   * - ``attest``
     - Evidence as ``attest verify`` reads it, and challenges
   * - ``beefile``
     - A Beefile
   * - ``bpm-index``
     - A repository index
   * - ``bpm-package``
     - A ``.bee`` package as ``bpm install`` unpacks it
   * - ``bpm-tar``
     - The Beefile inside a package archive
   * - ``cms``
     - Certificates and detached CMS signatures
   * - ``config``
     - ``shirudo.conf``, registry sources and ``upatch-tree.conf``
   * - ``decoder``
     - Map data a Lua decoder reads
   * - ``elf``
     - The build ID of a uprobe target binary
   * - ``eventlog``
     - The eventlog and its replay
   * - ``json``
     - The JSON parser
   * - ``kconfig``
     - A kernel configuration and ``node.labels``
   * - ``kernel``
     - The kernel's ELF notes
   * - ``oci-http``
     - Registry and token server responses
   * - ``oci-manifest``
     - An OCI manifest
   * - ``oci-ref``
     - ``oci://`` references
   * - ``otel``
     - OTLP collector responses and ``OTEL_EXPORTER_OTLP_HEADERS``
   * - ``prog-metadata``
     - A load upatch's program metadata
   * - ``registry-auth``
     - The container auth file
   * - ``serializer``
     - Serializer output pages
   * - ``tpm-wire``
     - TPM structures in evidence
   * - ``tree``
     - An upatch tree publication
   * - ``tree-state``
     - The tree's ``state.json`` and eventlog
   * - ``upatch``
     - A ``.upatch`` container and its decoder table

Coverage by area
----------------

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Area
     - Tests
   * - Signed loading
     - ``t2002``, ``t2101``, ``t3101``, ``t3105``, ``t6102``,
       ``t6117``, ``t6138``. Fuzz: ``cms``, ``upatch``,
       ``prog-metadata``
   * - Admission
     - ``t6005``, ``t6101``, ``t6102``, ``t6103``, ``t6104``,
       ``t6107``, ``t6113``
   * - BPF command policy
     - ``t6107``, ``t6108``, ``t6109``, ``t6110``, ``t6119``,
       ``t6138``. Root without runtime authority cannot open shirudo's
       maps, links or pins by pin, id or file: ``t6107``, ``t6108``,
       ``t6109``, ``t6138``
   * - Maps, links and serializers
     - ``t3003``, ``t3004``, ``t3005``, ``t3102``, ``t6109``,
       ``t6138``, ``t6139``, ``t8101``, ``t8103``
   * - Load and unload
     - ``t3101``, ``t3103``, ``t3104``, ``t3105``, ``t4102``,
       ``t6116``, ``t6122``, ``t6128``. Unit: ``kernel_abi``
   * - Attach kinds
     - Offline metadata: ``t3006``, ``t3007``, ``t3008``, ``t3009``,
       ``t3010``. Loaded on a target: fentry (fixtures), ``lsm``
       (``t9101``), ``cgroup_skb`` and netfilter (``t6116``),
       ``uprobe.multi`` (``t3107``)
   * - bpffs pins and mounts
     - ``t4101``, ``t6105``, ``t6106``, ``t6108``, ``t6120``,
       ``t6121``
   * - Seal
     - ``t6001``, ``t6002``, ``t6007``, ``t6111``, ``t6114``,
       ``t6115``, ``t6118``, ``t6123``, ``t6124``, ``t6133``,
       ``t6144``
   * - Task authority
     - ``t6006``, ``t6110``, ``t6113``, ``t6131``, ``t6132``,
       ``t6134``, ``t6135``, ``t6136``, ``t6137``
   * - Keyrings
     - ``t2101``, ``t2102``, ``t2103``, ``t5101``, ``t5104``,
       ``t6004``, ``t6104``, ``t6112``, ``t6129``, ``t6140``
   * - Signing keys and the trusted set
     - ``t2001``, ``t2002``, ``t2003``, ``t2004``, ``t2005``,
       ``t5003``
   * - TPM register
     - ``t4001``, ``t4003``, ``t4101``, ``t4102``, ``t4103``,
       ``t6125``, ``t6128``, ``t6143``, ``t6144``. Unit: ``chain``
   * - Attestation
     - ``t2003``, ``t2005``, ``t4003``, ``t4004``, ``t4102``,
       ``t9105``. Fuzz: ``attest``, ``tpm-wire``
   * - Eventlog
     - ``t4002``, ``t4102``, ``t5007``, ``t6114``, ``t6128``. Fuzz:
       ``eventlog``
   * - Boot and initrd
     - ``t1006``, ``t4002``, ``t4101``, ``t5006``, ``t6115``,
       ``t6126``
   * - Config images
     - ``t4004``, ``t5001`` to ``t5008``, ``t5101`` to ``t5105``,
       ``t6112``, ``t6127``, ``t6130``, ``t6132``. Fuzz: ``config``
   * - Packages and repositories
     - ``t7001``, ``t7002``, ``t7003``, ``t7004``, ``t7005``,
       ``t7006``. Fuzz:
       ``beefile``, ``bpm-index``, ``bpm-package``, ``bpm-tar``,
       ``oci-http``, ``oci-manifest``, ``oci-ref``, ``registry-auth``
   * - upatch tree
     - ``t3011``, ``t5004``, ``t7005``, ``t7101``, ``t7102``,
       ``t7103``, ``t7104``, ``t9105``. Fuzz: ``tree``, ``tree-state``,
       ``kconfig``. Unit: ``kernel_build_id``, ``kernel_release``
   * - Policy labels
     - upatch labels and Beefile serialization: ``t3109``, ``t7006``.
       Unauthorized policy-xattr changes: ``t6111``. Task and socket
       inheritance: ``t6141``, ``t6142``
   * - Telemetry
     - ``t6139``, ``t8001`` to ``t8006``, ``t8101`` to ``t8105``,
       ``t9101`` to ``t9105``. Fuzz: ``otel``, ``serializer``
   * - Decoders
     - ``t3002``, ``t8102``, ``t9101``. Fuzz: ``decoder``
   * - Tamper counters
     - ``t6003``, ``t6108``, ``t6115``, ``t6118``, ``t6119``,
       ``t6120``, ``t6121``, ``t6124``, ``t6126``, ``t6135``,
       ``t6137``
   * - CLI
     - ``t1001``, ``t1002``, ``t2001``, ``t3005``, ``t3106``,
       ``t3108``, ``t5004``, ``t5103``, ``t6007``, ``t6114``,
       ``t7001``, ``t8001``
   * - Build and packaging
     - ``t0005``, ``t0007``, ``t1003``, ``t1004``, ``t1005``,
       ``t1008``, ``t7004``, ``t8003``
   * - CI scripts
     - ``t0001`` to ``t0007``
   * - Parsers
     - ``t3001``, ``t3011``, ``t5002``, ``t5006``, ``t5008``. Unit:
       ``hex``, ``json``, ``string``. Every fuzz target

Coverage by threat
------------------

The threats are those of :doc:`/security/threat-model`.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Threat
     - Tests
   * - T1 Loading unsigned BPF
     - ``t2002``, ``t3101``, ``t6102``, ``t6103``, ``t6104``,
       ``t6107``, ``t6108``, ``t6138``
   * - T2 Detaching or replacing enforcement
     - ``t6101``, ``t6105``, ``t6106``, ``t6107``, ``t6108``,
       ``t6109``, ``t6116``, ``t6119``, ``t6120``, ``t6121``,
       ``t6138``
   * - T3 Tampering with shirudo's files and process
     - ``t6001``, ``t6006``, ``t6007``, ``t6110``, ``t6111``,
       ``t6112``, ``t6114``, ``t6115``, ``t6118``, ``t6123``,
       ``t6124``, ``t6127``, ``t6129``, ``t6133``, ``t6134``,
       ``t6135``, ``t6136``, ``t6137``
   * - T4 Substituting artifacts
     - ``t3001``, ``t3011``, ``t3104``, ``t3105``, ``t6117``,
       ``t6138``
   * - T5 Silent state change
     - ``t2005``, ``t4002``, ``t4003``, ``t4102``, ``t4103``,
       ``t5007``, ``t6115``, ``t6122``, ``t6125``, ``t6128``
   * - T6 The boot window
     - ``t1006``, ``t4101``, ``t6115``, ``t6126``
   * - T7 The delivery path
     - ``t7002``, ``t7003``, ``t7005``, ``t7101``, ``t7102``,
       ``t7103``, ``t7104``, ``t8005``, ``t9105``
   * - T8 Quantum-capable adversaries
     - ``t2001``, ``t2002``, ``t5001``, ``t8005``
   * - T9 A target lying about its state
     - ``t4001``, ``t4003``, ``t4004``, ``t4102``, ``t9105``
   * - T10 An attempt that leaves no trace
     - ``t6003``, ``t6108``, ``t6118``, ``t6119``, ``t6120``,
       ``t6121``, ``t6124``, ``t6126``, ``t6135``, ``t6137``
   * - T11 Image-mode config and executable substitution
     - ``t5001``, ``t5002``, ``t5003``, ``t5006``, ``t5008``,
       ``t5101``, ``t5102``, ``t5103``, ``t5104``, ``t6112``,
       ``t6113``, ``t6127``, ``t6130``, ``t6131``, ``t6132``
   * - T12 Interrupted image activation
     - ``t4004``, ``t5007``, ``t5105``, ``t6004``

Coverage of tamper counters
---------------------------

``t6003`` checks that every counter has a name and a meaning, and
``t6108`` that ``status --json`` reports the counters as numbers. These
tests assert that a refusal moves its counter:

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Counter
     - Test
   * - ``LoadNotLoader``, ``ProgAttach``, ``ObjPin``, ``ObjGet``,
       ``BpfCommand``, ``PinUnlink``, ``PinRename``, ``BpffsUmount``
     - ``t6108``
   * - ``BpffsUmountAbove``
     - ``t6120``
   * - ``PinEntry``
     - ``t6121``
   * - ``PerfAttach``
     - ``t6119``
   * - ``SealEntry``
     - ``t6115``, ``t6118``, ``t6144``
   * - ``SealCopyUp``
     - ``t6124``
   * - ``SealPtrace``
     - ``t6135``
   * - ``SealSignal``
     - ``t6143``
   * - ``ExecTraced``
     - ``t6137``
   * - ``Kexec``
     - ``t6126``

Not covered
-----------

These are verified absences: no test under :src:`testing/` exercises them.

Attacks
~~~~~~~

Most of these attacks are open threats in
:doc:`/security/threat-model`:

- ``attest verify`` run without ``--ak-name`` or without any
  expectation of the state.
- An environment that steers an authorized shirudo process, such as
  ``BPM_OCI_SCHEME``, ``BPM_OCI_CA_FILE``, proxy variables,
  ``SSLKEYLOGFILE`` or ``TSS2_LOGFILE``. ``t6136`` covers the dynamic
  loader's variables only.
- A repository index or tree publication signed with a classical
  algorithm.
- Removing an empty sealed directory, ``chattr`` on sealed files, POSIX
  ACLs on them, and a hard link of a labeled inode into an unsealed
  directory. ``t6118`` covers hard links into sealed directories only.
- An eventlog larger than the size the readers accept.
- A fake TPM transport that replays the attestation key name ``init``
  recorded. ``t6125`` covers a device with another name.
- Making ``init`` read another boot ID, or miss this boot's init
  record by other means than the unlabeled state directory ``t6115``
  covers, so that it binds the register again.
- A target without kernel lockdown. The test kernel enables no
  lockdown.
- A failure of ``shirudo-initrd.service`` that lets the boot continue
  without enforcement, and a first ``init`` outside the initrd.
- Another LSM denying the read of a seal label. The test kernel runs
  with ``CONFIG_LSM="bpf"`` alone.
- ``bpm config update --base-package`` running commands from a package
  fetched from a registry.
- A boot restore that fails part way.
- Loading an older artifact signed by the same key, and an unload
  directive signed by another trusted key than the load.
- Stopping a running shirudo with ``SIGSTOP``, ``mount_setattr(2)``,
  hibernation and ``/dev/snapshot``, ``/dev/mem``, and TPM access over
  ``i2c-dev`` or ``spidev``.

Tests that assert behavior the threat model lists as a threat to
resolve. They change when that threat is resolved:

- ``t5102`` asserts that a config root signed under a kernel built-in
  certificate is accepted.
- ``t2003`` and ``t5003`` assert that a revoked signer's earlier
  vouches stay valid.
- ``t5004`` asserts that tree publications verify against the runtime
  trust anchor.
- ``t7003`` adds a certificate from an OCI reference without a
  fingerprint to compare it with.

Commands and procedures
~~~~~~~~~~~~~~~~~~~~~~~

- ``bpm repo update``, ``bpm install``, ``bpm upgrade`` and ``bpm
  uninstall`` against a repository on a target. ``t7004`` reads the
  unit files, ``t7001`` checks argument validation and the
  ``bpm-index`` fuzz target the index parser.
- ``bpm config update``.
- ``upatch load`` or ``upatch unload`` refusing ``tampered`` for a
  stale ``--expect-chain``. Only ``attest verify`` is tested with that
  option.
- ``status --include-eventlog`` and ``--show-full``.
- ``upatch rewrite-rodata`` in ``shirudo-build``, which
  ``kernel-obs`` uses to rewrite its watch lists.
- The ``kernel-cve`` package. Its Beefile is a seed of the ``beefile``
  fuzz target only.
- The recovery, upgrade and decommissioning procedures of
  :doc:`/operate/maintain/backup-recovery` and :doc:`/operate/maintain/upgrade`.
- Exit statuses. ``t8001``, ``t4003`` and ``t4102`` check a few, but no
  test checks the exit status of every command. No test names the
  failure categories ``already_unloaded``, ``attach_target_missing``,
  ``detach_failed``, ``eventlog_full``, ``kernel_abi_unsupported``,
  ``lsm_denied``, ``signature_unsupported`` or ``verifier_rejected``.
- Completion against the parsers. :src:`completion/shirudo.bash` keeps its
  option lists by hand, and no test compares them with the options the
  commands accept.

Units and boot
~~~~~~~~~~~~~~

- The units on the root file system as installed. The test VM replaces
  the ``ExecStart`` of each of them with the runtime command before the
  tests run, so no test runs one as installed. ``shirudo.service``,
  ``shirudo-keepalive.service`` and ``shirudo-bpm-repo-update.service``
  are never started. ``t8102``, ``t8103``, ``t8104`` and ``t9105``
  start the map-export and tree-sync services with the replaced
  command. ``shirudo-initrd.service`` runs from its template in the
  initrd of every target VM.
- A reboot. No test reboots a guest. Restore at boot and the completion
  of a pending activation run as repeated ``init`` runs and through
  helpers (``t5007``), and ``t4003`` resets a simulated TPM.

Tamper counters
~~~~~~~~~~~~~~~

No test asserts that a refusal moves ``LoadUnsigned``,
``LoadUnverified``, ``LoadKeyringKind``, ``LoadKeyring``, ``MapCreate``,
``MapWrite``, ``MapFdWrite``, ``ProgRun``, ``ExeIdentity``,
``KeyringWrite``, ``PinXattr``, ``BpffsMount``, ``SealWrite``,
``SealUnlink``, ``SealRename``, ``SealSetattr``, ``SealXattr``,
``SealLabel``, ``SealPerf`` or ``TpmExtend``. The refusals behind
several of them are tested, the counter is not.

Attach kinds
~~~~~~~~~~~~

- ``fexit``, ``tp_btf`` and ``kretprobe`` have no test, offline or on a
  target.
- ``fmod_ret`` and kprobe override are checked offline only
  (``t3008``).
- kprobe loads run only on a kernel with a kprobe PMU. The test kernel
  has none, so ``t6116`` leaves out its kprobe case.

Platforms
~~~~~~~~~

- Real TPMs. Every TPM test uses ``swtpm`` in the VM or the libtpms
  simulator helper. ``t1008`` checks only the kernel configuration for
  NitroTPM.
- Architectures. CI builds and runs the unit tests on arm64 and on
  riscv64, under QEMU user emulation, with the BPF objects built from
  the BTF of the x86-64 bpf-next kernel. Every other tier runs on
  x86-64 only. The test VM boots arm64 too, and ``t1007`` checks its
  arm64 settings without booting. riscv64 has no test VM.
- Kernels. CI boots bpf-next only. ``KERNEL=`` boots a release kernel
  by hand.

Parsers and units
~~~~~~~~~~~~~~~~~

- The dm-verity superblock check in :src:`util/config_image.c` has no
  fuzz target. ``t5001`` covers truncation and unsupported fields.
- 54 of the 62 modules in :src:`util/` have no unit suite of their own.

Related
-------

- :doc:`/contribute/testing/testing` to run the tests and write one
- :doc:`/security/threat-model` for the threats and residual risks
- :doc:`/security/tamper-counters` for what each counter means
