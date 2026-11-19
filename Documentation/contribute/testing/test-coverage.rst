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
and how to run them. What the proofs cover, for every input within their
bounds rather than for the inputs a test picks, is on
:doc:`proof-coverage`.

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
       format rules, and a fetch of ``checkpatch.pl`` that asks a host
       which does not answer only once
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
       form it leaves alone, a dead store beside the reads
       ``dead_store`` leaves alone, a count by hand in a macro and an
       ``ARRAY_SIZE()`` of a file's own for ``array_size``, which
       rewrites the one and leaves the other, a file a rule gives up on
       at its time limit named rather than failed, and the tree itself
   * - ``t0007-check-operator-linkage``
     - ``check-operator-linkage.sh``: the libraries an operator binary
       may link and its own interpreter, another loader, a library
       outside the list or named like one on it, and the operator
       binaries when built
   * - ``t0008-check-docs``
     - ``check-docs.sh``: the whole of each field of a threat's fact
       box, a hook by its section, each tamper and integrity counter's
       entry on its page, the source files a proof reads or the proof
       coverage page lists as read by none, a figure against its TikZ
       source and one without a source, and the tree itself
   * - ``t0009-check-unused``
     - ``check-unused.sh``: an extern function nothing calls, with its
       type on its line or the one above, a header's declaration that is
       no call, the calls that count and the definitions it leaves
       alone, and the tree itself

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
     - Test VM scripts: kernel artifact selection, host dependencies, arm64
       boot settings, the bundle stamp, the build container, serve mode,
       node mode only for a core or edge node of the end-to-end tier,
       whose vTPM keys the builder helper creates before boot, the
       operator VM's role and its signing key
   * - ``t1009-upatch-isa``
     - The upatch build compiles for BPF instruction set v4, and a
       ``-mcpu`` in ``--extra-cflags`` replaces it; a dense ``switch``
       compiles to branches, not a table in ``.rodata``
   * - ``t1010-test-filter``
     - Script regex matching through ``-t`` and ``TEST_FILTER``, command-line
       precedence, empty and invalid patterns, ordering and failure status

   * - ``t1010-local-stack``
     - VM-first service configuration and stable public trust across starts
   * - ``t1011-completion``
     - The bash completion: commands and subcommands from ``--list-cmds``,
       options from ``--list-opts``, a value by its placeholder, and a
       command without subcommands that answers ``--list-cmds`` with
       nothing and logs nothing

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
       ``attest predict`` agreement, signatures accepted from either
       active signer and refused after that signer is revoked
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
     - ``uprobe`` and ``uretprobe`` functions, function offsets and raw
       file offsets, ``uprobe.multi`` and ``uretprobe.multi`` globs,
       sleepable ``.s`` forms included, to file offsets and the target's
       build ID, and the uprobe forms the builder refuses
   * - ``t3008-override-metadata``
     - kprobe override and ``fmod_ret`` attach metadata
   * - ``t3009-netfilter-metadata``
     - netfilter attach metadata
   * - ``t3010-unsupported-network-sections``
     - Attach kinds the builder refuses
   * - ``t3011-string-bounds``
     - Names and the tree repository are refused rather than cut
   * - ``t3012-xdp-metadata``
     - Signed XDP device-class masks, object inputs and invalid sections;
       two XDP programs of one upatch build with disjoint classes and are
       refused when they share one
   * - ``t3013-kprobe-multi-metadata``
     - ``kprobe.multi`` and ``kretprobe.multi`` sign their function list
       sorted, with the return kind, beside a uprobe target block; a
       section without a list, a glob, a name given twice, an empty
       element, a name of ``KSYM_NAME_LEN`` bytes and ``kprobe.session``
       are refused
   * - ``t3014-java-build``
     - A jar signs into a Java load whose signature covers its data, and
       an unload directive of it, by ``build`` and by ``bpm build``; a file
       that is no jar, a jar without a ``Premain-Class``, ``--java``
       alone, rodata on a Java upatch and a header relabelled BPF are
       refused
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
     - A live ``uprobe.multi`` load, refusal after a build ID change, a
       live ``uretprobe.multi`` load that runs and unloads, a live
       sleepable ``uprobe.multi.s`` load that reads user memory, and live
       ``uprobe`` and ``uretprobe`` loads that run once, report their
       checked ``/proc/self/fd/<n>`` target paths and unload
   * - ``t3108-status-many``
     - ``status --json`` with eighty loaded upatches lists all of them
   * - ``t3109-policy-labels``
     - A loaded upatch labels executable and ordinary files, ORing
       multiple policy bits with a preexisting xattr; its signed policy
       section binds verdict programs to shared task and socket policy
       maps
   * - ``t3110-double-load``
     - A second load of a loaded upatch is refused as ``already_loaded``
   * - ``t3111-xdp``
     - Native XDP class selection, veth pair deduplication with both
       endpoint index orderings, cross-namespace pairs, a bridge without
       native XDP skipped and listed under ``XdpCovered``, rollback, signed unload and descriptor
       and alternate-attachment lockdown; a repeated init adopts the
       archived XDP without another event. A veth with a peer MTU of 9000
       and the ``virtio_net`` guest adapter at MTU 9000 attach, which only a
       multi-buffer program can. A veth with too few rx queues, which its
       driver refuses with ``ENOSPC``, fails the load as
       ``xdp_driver_refused`` and leaves nothing, and an occupied device
       fails it as ``xdp_device_occupied``. Each case cleans up its state
       so a failed assertion does not contaminate later cases.
   * - ``t3112-xdp-reconcile``
     - ``upatch reconcile`` attaches a device added after load, adds no
       pin or event on a second pass, leaves a device another program
       occupies, without a warning, while ``status`` lists it under
       ``XdpCovered``, and attaches it once that program is unloaded, does not read a gone device as tampering, removes its
       pin without reusing a live index, does nothing after unload, and leaves the link on a veth
       end moved to another namespace. A changed archive is covered by
       the ``upatch_verify`` unit cases. An unload racing a pass is not
       reported as tampering, and a veth with too few rx queues, which
       its driver refuses, is warned about without stopping the pass.
       ``status`` lists a selected device under ``XdpCovered`` until a
       pass attaches it, and the refused veth for good. The reasons and
       the verdict are covered by the ``xdp`` and ``conditions`` unit
       cases.
   * - ``t3113-kprobe-multi``
     - Live ``kprobe.multi`` and ``kretprobe.multi`` links attach to two
       functions, run on entry and return, report their kind and count,
       unload cleanly, and reject a missing target
   * - ``t3114-java-agent``
     - A Java load under a umask of ``077`` writes the jar sealed,
       readable by an unprivileged user and unchangeable by root, in a
       directory root cannot move while the state root stays ``0700``,
       names it in ``JAVA_TOOL_OPTIONS`` in a ``0644`` file of a ``0755``
       directory, measures a ``java_load`` that ``status``
       counts as in place and lists with the location ``java``, and
       refuses a second load; one signed by a key
       not enrolled, one relabelled BPF with a loader its header bounds
       admit, and a BPF unload directive that names the agent are
       refused; the unload removes options and archive, measures a
       ``java_unload`` and leaves a jar whose agent does nothing

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
   * - ``t4005-tpm-session``
     - Salted HMAC and policy sessions, ECC and RSA credential
       activation, rejected key pins, forged and replayed extension
       replies, forged NV, PCR, clock and policy-digest readbacks, and
       refusal of TPM logging overrides during bootstrap and enforcement.
       An unsalted negative control accepts a forged acknowledgment
       with an empty or SHA-256 response HMAC; malformed lengths are refused.
       Salted sessions reject it and leave the real measured value unchanged
   * - ``t4006-keepalive-quotes``
     - The quotes of :src:`testing/fixtures/keepalive/quotes.tsv`: each
       row's ``body_sha256`` is SHA-256 of its body file, and fails on
       a body altered by one byte; every row verifies under
       ``shirudo-quote-check`` without a TPM, node A's rows under one
       key and node B's under another; a quote over an altered body is
       ``body_mismatch``; with the libtpms simulator built, the capture
       script rebuilds a file that verifies
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
   * - ``t4104-keepalive-quote``
     - The keepalive quote under ``shirudo-quote-check``: it covers the
       body, its signer is the attestation key of ``attest`` under the
       endorsement hierarchy, a later quote has a later clock, and a
       body altered by one byte is ``body_mismatch``

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
       exact root, the generator scripts and multiple config certificates
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
     - Bootstrap settings in the initrd, ordered config verification keys,
       duplicate paths and too many keys
   * - ``t5007-config-update``
     - Activation events, the pending latch, interruption, locks,
       symbolic links in state
   * - ``t5008-text-lines``
     - Long lines and NUL bytes in settings files
   * - ``t5009-config-stage``
     - Staging without activation or measurement, selection on the next
       TPM boot, cancellation, stale parents, malformed records and
       process death while replacing a staged selection
   * - ``t5100-verity-stage``
     - A new signer may be staged without live enrollment, activation or
       measurement; same-boot init leaves it staged and cancellation is
       idempotent
   * - ``t5101-verity-boot-signers``
     - The ``.dm-verity`` keyring, boot enrollment of a vouched signer
   * - ``t5102-verity-config``
     - Config classification, corruption, live activation from A to B,
       refusal of a kernel-trusted config signer not named by the runtime
   * - ``t5103-verity-cli``
     - Key and repository changes require a signed config
   * - ``t5104-verity-revocation``
     - Signed revocation unlinks the signer and purges its measured
       tracing and XDP upatches and their archives
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
     - Every tamper and integrity counter has a name and a meaning
   * - ``t6004-conditions``
     - Status conditions: both keyrings, register, pins, config
       activation
   * - ``t6005-mode-objects``
     - The embedded admission and seal objects include image
       enforcement
   * - ``t6006-harden``
     - Memory locking at startup, failing closed
   * - ``t6007-output-paths``
     - Output paths: no symbolic links, directories or devices; a failed
       write removes only the file written, where it was opened
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
     - Output paths aimed at sealed state; ``genkey`` refused on a target
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
     - ``PERF_EVENT_IOC_SET_BPF``, and a kprobe multi link of root's own
       for a loaded upatch's program
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
     - A substituted TPM is refused by its session key name; a proxy
       forwarding the enrolled TPM cannot suppress an extension and
       make a signed load succeed without measurement
   * - ``t6126-kexec``
     - ``kexec_file_load`` and, where available, ``kexec_load`` are
       refused and counted
   * - ``t6127-proc-substitution``
     - Config read through a substituted ``/proc``
   * - ``t6128-register-lock``
     - The lock that keeps register and eventlog in step, the same in a
       mount namespace of root's own
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
     - ``ptrace``, ``/proc`` reads and perf events on a running
       shirudo; only attach mode counts
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
       and undone by the next upatch load or unload
   * - ``t6144-returned-archive``
     - The archive directory with its mark evicted takes nothing and
       lets no labeled archive out; an archive without a record of its
       load is reported, not restored by init and removed by the next
       upatch command
   * - ``t6145-core-dump``
     - An exec of the runtime that fails after its mark is committed
       dumps core without authority: the dump cannot unlink a pin or
       replace a sealed file, and ``SealCoreDump`` counts it
   * - ``t6146-uprobe``
     - A uprobe set through tracefs on the runtime binary leaves the
       commands it reaches without authority, counted as
       ``SealUprobe``, until it is removed
   * - ``t6147-forged-records``
     - A load in a namespace with a ``/run`` of root's making and a
       forged pending record, or another boot ID bound over ``/proc``,
       detaches nothing: the undo pass takes only the records the
       register vouches for
   * - ``t6148-read-once``
     - A load and an unload stage nothing in sealed state, and the
       archive holds the bytes the load read
   * - ``t6149-config-root``
     - A directory of the config image bound in place of its mount, in a
       namespace with a ``/run`` of root's making, is refused as the
       config
   * - ``t6150-ancestor-rename``
     - The directories above the state root carry the ancestor mark; a
       rename of one and the removal of the mark are refused and counted,
       and a directory beside the state root still renames
   * - ``t6151-personality``
     - Started under ``setarch --uname-2.6``, shirudo still reads the
       kernel's release
   * - ``t6152-exec-shared``
     - The exec of the runtime binary by a task that shares its
       ``fs_struct`` is refused and counted; another program's is not
   * - ``t6153-xfs-attrmulti``
     - The ``XFS_IOC_ATTRMULTI_BY_HANDLE`` number on another file system
       is not refused or counted, and on an XFS image it is refused and
       counted. The XFS case needs XFS in the kernel and ``mkfs.xfs``,
       which the slim test VM kernel lacks
   * - ``t6154-lockdown``
     - A module without its signature, a PCI config write,
       ``/proc/kcore`` and ``/dev/mem``, where the kernel has them, are
       refused, all but the last counted on their integrity counters,
       which ``status``, its JSON and the keepalive report, and a read
       of ``/sys/power/state`` counts nothing
   * - ``t6155-mountpoint-removal``
     - From a namespace without ``/run``, an ``rmdir`` and a rename of
       the directory init's ``/run`` covers are refused and counted, and
       the private bpffs stays mounted
   * - ``t6156-rlimit``
     - A command writes past the file size limit it was started with,
       outlives an interval timer set before its exec, and refuses
       another task's ``prlimit``, counted as ``SealRlimit``

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
     - READMEs of local and OCI packages, archive integrity, a download
       kept in a memory file rather than in ``/tmp``, one key
       fingerprint from a certificate, a package and a download, and the
       control characters of a README and of a member name shown as
       ``?`` by ``info``, ``info upatches`` and ``info data``
   * - ``t7003-bpm-key``
     - ``bpm key`` from files and OCI references, ``bpm pull``, which
       replaces no file, not even after a failed digest, and names none
       after a layer title that is not a package name
   * - ``t7004-bpm-repo-update``
     - The repository update unit and timer and their package
       scriptlets, as text
   * - ``t7005-bpm-publish``
     - ``bpm build``, the ``fixes`` lists it takes and refuses, and its
       refusal of a target below another member and of members a target
       could not unpack together, ``bpm push`` with a signed index,
       ``bpm tree append`` and its refusal of an XDP device class two
       upatches of a tree select, which a Java upatch beside them does
       not trip, and of an entry no target would take,
       each before anything is uploaded, its refusal to extend a tree
       without ``--tree-id`` or with another tree's id, A-to-B tree
       signing-key rotation with explicit predecessor verification
   * - ``t7006-policy-labels``
     - Beefile policy declarations are serialized into the signed
       upatch section
   * - ``t7007-bpm-tree-fixes``
     - ``bpm tree append`` writes ``fixes`` on an ``add`` in byte order,
       after ``artifact`` and outside ``operation_digest``, none on a
       ``delete``, carries every earlier operation's list into the next
       generation, and refuses to carry a list it would not write
   * - ``t7008-bpm-tree-show``
     - ``bpm tree show`` prints the manifest digest and the signed
       document verbatim, ``fixes`` included, refuses a signature by
       another key, a wrong certificate, a tampered layer and a document
       ``tree sync`` would refuse with the errno sync reports, and
       writes nothing to the registry; with ``--walk`` prints a tree
       never sealed as without it and every segment of a tree sealed
       by ``--segment-ops 1`` oldest first, stops at ``seq`` 0 from a
       sealed segment, and refuses a tree whose sealed segment is gone;
       ``bpm tree append`` refuses the ``beta`` tree served in place of
       ``stable``
   * - ``t7009-bpm-tree-seal``
     - ``bpm tree append`` seals a segment at ``--segment-ops``, a value
       that may change between appends, or before one append would pass
       512 operations, never splits an append, tags the sealed manifest
       ``segment-<k>`` with its bytes unchanged and keeps a tag an earlier
       run left, starts the next segment with the sealed head, digest and
       a ``history_root`` recomputed independently, carries ``fixes`` and
       selectors across a seal, refuses a current segment that does not
       verify, refuses an XDP ``add`` whose class a live ``add`` of a
       sealed segment selects and takes it once a later segment deleted
       that ``add``, and fetches no sealed segment for an ``add`` without
       XDP classes
   * - ``t7010-bpm-slow-registry``
     - A registry that trickles a package fast enough for the low-speed
       limit is cut off at the transfer's total deadline
   * - ``t7011-bpm-config-base``
     - ``bpm config update`` refuses an ``oci://`` base package without
       ``--base-digest``, the option with a local base, a malformed
       digest and a registry that serves another manifest
   * - ``t7101-bpm-tree``
     - Tree sync with a selector
   * - ``t7102-bpm-tree-sequential``
     - Re-sync and the next generation
   * - ``t7103-bpm-tree-delete``
     - A delete operation and adding the upatch back
   * - ``t7104-bpm-tree-kconfig``
     - A kconfig selector the target cannot read stops the sync where it
       is; the operation applies once the config reads
   * - ``t7105-bpm-tree-loaded``
     - An add whose upatch is already loaded with its payload counts as
       installed; a direct load of it is still refused
   * - ``t7106-bpm-tree-outcomes``
     - The outcomes record: a line for an applied, an unmatched and a
       module-absent operation, one line for each ``seq`` after a sync
       killed between the register extend and its state, and the
       accepted publication on record after a sync that failed at a
       fetch; the record agrees with the tree eventlog and the
       operations' digests throughout
   * - ``t7107-bpm-tree-fixes-ignored``
     - A publication whose operations carry ``fixes``, well-formed and
       malformed, on an ``add``, a ``delete`` and an operation without a
       match, syncs with the outcomes, state and tree eventlog of the
       same operations without it
   * - ``t7108-bpm-tree-segments``
     - In ``functional/bpm-segments/``, a VM of its own, so that the node
       starts without a tree, on a tree ``bpm tree append --segment-ops
       2`` published and a bundle that lowers the walk limits to 4 and 6
       operations. A new node refuses a walk past its limit before it
       fetches a sealed segment, then walks back through four segments,
       past the running limit, and applies them with the tree eventlog,
       ``tree_op`` records, projection root and outcomes of the
       operations taken as one publication; a node inside the current
       segment fetches only it; a walk stopped between two segments, at
       a registry request held, or with an operation pending, resumes
       with a shorter walk and applies no operation twice; a forked
       predecessor fails the base check and a forked current segment the
       prefix check; a sealed segment the registry lost, a predecessor
       ending before its successor's base and a running node's walk past
       its limit are refused with nothing applied; a dry run walks and
       records nothing; ``init`` walks nothing and takes the projection
       root one publication gives; ``bpm tree show --walk``, run by the
       bundle on the operator host, printed every segment of the tree
       oldest first, each as plain ``show`` prints it and naming the
       one before
   * - ``t7109-bpm-tree-keepalive``
     - ``status --keepalive``: the keys of the body in order, its tree
       keys and mask as ``state.json`` and the outcomes record have them
       over the last 7 operations, the bundle's lowered window,
       flags bit 4 after a sync is killed after its load, and after the
       sync the loaded set its mask folds to and the masks of node A and
       node B
   * - ``t7110-bpm-tree-window``
     - In ``functional/bpm-segments/``, after ``t7108``, with the
       keepalive window lowered to 7 operations: ``status --keepalive``
       on a node of the segmented tree gives the ``base_seq``,
       ``base_root`` and mask of the outcomes record over the last 7
       operations up to the head, from inside a segment older than the
       recorded one, as the window slides with each segment and while an
       operation is pending, its operations past ``last_seq`` not reached

``otel`` (8)
~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 36 64

   * - ``t7111-bpm-tree-manifest``
     - The signed layers of a publication served under a manifest that
       is not the one ``bpm tree append`` writes are refused before the
       node records anything, and the publisher's form is taken again
   * - ``t7112-bpm-tree-java``
     - A Java upatch through the tree: an ``add`` installs its jar and
       names it in ``JAVA_TOOL_OPTIONS`` under a ``java_load``, a
       ``delete`` takes the agent and the options out under a
       ``java_unload``
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
     - ``status --keepalive``, ``status --otel`` without a TPM or an
       endpoint, and the keepalive log record: its string body, its one
       quote attribute and a body JSON cannot carry
   * - ``t8005-tls-policy``
     - TLS 1.3 with ``X25519MLKEM768`` only
   * - ``t8006-otel-transport``
     - OTLP environment variables, headers and limits
   * - ``t8007-keepalive-fixtures``
     - Every digest, root, set hash, mask and tree key of the keepalive
       fixtures recomputes from their example tree
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
   * - ``t8106-status-otel-quote``
     - ``status --otel`` on a target: one record, the body as a string
       with its keys in order, the quote as the one attribute and the
       severity of the verdict

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
     - The operator package built and installed in an operator VM
       without a TPM, which publishes ``kernel-obs`` and the Java agent
       ``e2e-java`` it compiles, and verifies the evidence, its
       ``java_load`` included; registry, tree sync, load, export and
       attestation on the target, and a JVM a user manager starts
       picking up ``JAVA_TOOL_OPTIONS`` and running the agent from its
       sealed jar
   * - ``t9106-policy-exec-graph``
     - A signed SHPL section labels five executables; its BPF policy
       allows unlabeled tasks to exec unlabeled files and 0x1, allows
       0x1 to exec 0x2, and denies 0x1 and socket policy B from execing
       unlabeled files; socket-storage bits allow 127.0.0.1 for policy A
       and deny it for B; final evidence includes the loaded policy upatch
   * - ``t9107-keepalive-backend``
     - The backend of ``tools/backend``: its tree ingest job loads the
       example publication through ``bpm tree show``, the example
       keepalives of node A and node B with their recorded quotes pass
       its collector and ``shirudo-quote-check``, and ``node_status``
       gives the example's results; a body altered in transit is
       ``body_mismatch``, a replayed record collapses and an older one
       does not become the latest
   * - ``t9109-pipeline``
     - The whole keepalive pipeline on a fresh edge node and node B, run
       by ``host.sh`` on the host: ``bpm build`` and ``bpm tree append``
       of a upatch with ``fixes``, tree sync on both nodes, quoted
       keepalives through the backend's collector and checker, its tree
       ingest and sbom-scan jobs, node B enrolled from its vTPM
       builder's names and the edge node left untrusted,
       ``node_status`` with the masks ``VA==`` and ``qA==``, each node's
       records against the backend's rows,
       every SBOM state, ``node_vulns`` exposure and a body altered in
       transit
   * - ``t9110-keepalive-history``
     - The backend's history of each node over a tree of segments, run by
       ``host.sh`` after ``t9109`` on the same nodes: ``bpm tree append
       --segment-ops 2`` past the lowered keepalive window, the ingest
       job loading every segment through ``bpm tree show --walk``, a
       running node's walk back, ``base_root`` verified against
       ``node_ops``, a node first seen past seq 0 reading ``gap`` and
       ``healthy``, and a shield below the window still ``shielded``
   * - ``t9111-pipeline-segments``
     - A backward walk on real data, run by ``host.sh`` after ``t9110`` on
       a second fresh edge node and node B: ``bpm tree append
       --segment-ops 2`` sealing three segments, a node without tree state
       and a node behind inside a sealed segment both fetching it by its
       digest, as the registry's access log shows, then applying forwards
       with the masks ``VQ==`` and ``mg==``, no walk once both are at the
       new segment's base, keepalives over all three segments and both
       nodes ``healthy``
   * - ``t9112-activation``
     - Enrollment through credential activation on a real vTPM, run by
       ``host.sh`` after ``t9110`` on the same nodes: an endorsement
       certificate from the edge node's own test CA chaining through
       ``attest challenge --ek-ca``, another node's CA refused, the
       challenge refused by another node, the answer verified with
       ``--expect-credential``, and the key moving from ``untrusted`` to
       ``enrolled`` in the backend

Unit suites and fuzz targets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The unit suites in :src:`testing/unit/` cover 34 of the modules in
:src:`util/`: ``attest``, ``bpm_oci``, ``bpm_package``, ``bpm_state``,
``bpm_tree``, ``bpm_tree_overlap``, ``bpm_tree_state``, ``chain``,
``chain_history``, ``conditions``, ``crypto_openssl``,
``eventlog``, ``format``, ``hex``, ``io``, ``java_agent``, ``json``,
``kernel_abi``,
``keepalive``, ``keepalive_quote``, ``kernel_build_id``,
``kernel_release``, ``keys``, ``measured``, ``options``,
``paths``, ``string``, ``sysinfo``, ``upatch``, ``upatch_decode``,
``upatch_pins``, ``upatch_resolve``, ``upatch_verify`` and ``xdp``, and
``overflow`` the arithmetic of
:src:`include/shirudo/overflow.h`. ``jar`` covers the
``shirudo-build`` checks of a Java agent's jar in
:src:`tools/shirudo-build/jar.c`: stored and deflated manifests, a
missing or empty ``Premain-Class``, one outside the main section, and
every truncation and byte flip of a jar. ``quote_check`` covers the rows of
``shirudo-quote-check`` in :src:`tools/quote-check/row.c`, on quotes a
software P-256 key signs: every reject reason, the signer's qualified
name, the empty PCR selection and the base64 of each field. The other
modules are reached through the test helpers, the fuzz targets and the binaries
the functional tests run.

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Fuzz target
     - Input
   * - ``attest``
     - Evidence as ``attest verify`` reads it, and challenges
   * - ``attest-report``
     - The report ``attest verify`` prints on evidence, as text and as
       JSON, which give the same checks and verdict
   * - ``beefile``
     - A Beefile
   * - ``bpm-index``
     - A repository index
   * - ``bpm-info``
     - A ``.bee`` package as ``bpm info`` prints its README, its
       upatches and the ``.rodata`` of each, as text and as JSON
   * - ``bpm-package``
     - A ``.bee`` package as ``bpm install`` unpacks it
   * - ``bpm-tar``
     - The Beefile inside a package archive
   * - ``cms``
     - Certificates and detached CMS signatures
   * - ``config``
     - ``shirudo.conf``, registry sources and ``upatch-tree.conf``
   * - ``config-update``
     - The config activation history in the target's state
   * - ``decoder``
     - Map data a Lua decoder reads
   * - ``elf``
     - The build ID of a uprobe target binary
   * - ``eventlog``
     - The eventlog and its replay
   * - ``image``
     - Runtime image bootstrap settings and a config image's verity
       superblock
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
   * - ``quote-check``
     - A row of ``shirudo-quote-check``: a keepalive quote and the
       digest of its body
   * - ``registry-auth``
     - The container auth file
   * - ``rodata``
     - The ``.rodata`` of a ``.upatch`` as ``bpm info data`` reads it
   * - ``serializer``
     - Serializer output pages
   * - ``tpm-wire``
     - TPM structures in evidence
   * - ``tree``
     - A upatch tree publication
   * - ``tree-state``
     - The tree's ``state.json``, eventlog and outcome lines
   * - ``upatch``
     - A ``.upatch`` container and its decoder table
   * - ``upatch-info``
     - A ``.upatch`` as ``upatch info`` prints it, as text and as JSON

``attest-report``, ``bpm-info`` and ``upatch-info`` hold what their
command prints from a file it has not verified to what
``text_sanitize()`` leaves for a terminal, UTF-8 with no control
character but a tab, a line feed and a carriage return before a line
feed, and its JSON to one document :src:`util/json.c` reads.

Backend tests
~~~~~~~~~~~~~

The SQL tests of :src:`tools/backend/test/` cover the backend's schema
against a ClickHouse container (:ref:`testing-backend`): the quote
check of every record and the reasons a record is refused, a key's
trust from ``untrusted`` to ``enrolled``, each status check and the
history it reads, ``node_vulns`` and its inputs, the
retention script and the views that keep boot baselines, the tree
ingest job on a single publication and on a walk over sealed segments,
the SBOM scan job on a store that holds an image in every state, and
the queries of :src:`tools/xtop/sql/nodes.sql` and
:src:`tools/xtop/sql/shields.sql`, with the names and types of their
columns, over nodes healthy, unhealthy, stale and without a tree or an
image, and a tree with one upatch deployed and one still rolling out
(``test/xtop-nodes``, ``test/xtop-shields``).

The unit tests of :src:`tools/xtop/test/` cover how xtop turns the rows
of those queries into nodes and shields, the health percent, the
roll-up by image, the status and severity of a shield and its
ClickHouse client; ``make -C tools/xtop tests`` type-checks the
program and runs them (:ref:`testing-xtop`).

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
       ``uprobe``, ``uretprobe``, ``uprobe.multi``, ``uretprobe.multi`` and
       ``uprobe.multi.s`` (``t3107``)
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
       ``t4104``, ``t9105``, ``t9109``, ``t9112``. Fuzz: ``attest``,
       ``attest-report``, ``tpm-wire``
   * - Eventlog
     - ``t4002``, ``t4102``, ``t5007``, ``t6114``, ``t6128``. Fuzz:
       ``eventlog``. Unit: ``eventlog``, ``io``
   * - Boot and initrd
     - ``t1006``, ``t4002``, ``t4101``, ``t5006``, ``t6115``,
       ``t6126``
   * - Config images
     - ``t4004``, ``t5001`` to ``t5008``, ``t5101`` to ``t5105``,
       ``t6112``, ``t6127``, ``t6130``, ``t6132``. Fuzz: ``config``,
       ``config-update``, ``image``
   * - Packages and repositories
     - ``t7001``, ``t7002``, ``t7003``, ``t7004``, ``t7005``,
       ``t7006``. Fuzz:
       ``beefile``, ``bpm-index``, ``bpm-info``, ``bpm-package``,
       ``bpm-tar``, ``oci-http``, ``oci-manifest``, ``oci-ref``,
       ``registry-auth``. Unit:
       ``bpm_oci``, ``bpm_package``
   * - upatch tree
     - ``t3011``, ``t5004``, ``t7005``, ``t7007``, ``t7008``, ``t7009``,
       ``t7101``, ``t7102``, ``t7103``, ``t7104``, ``t7105``, ``t7106``,
       ``t7107``, ``t7108``, ``t7109``, ``t7110``, ``t9105``, ``t9109``,
       ``t9110``, ``t9111``.
       Fuzz: ``tree``,
       ``tree-state``, ``kconfig``. Unit: ``bpm_tree``,
       ``bpm_tree_overlap``, ``bpm_tree_state``, ``chain_history``,
       ``kernel_build_id``, ``kernel_release``
   * - Policy labels
     - upatch labels and Beefile serialization: ``t3109``, ``t7006``.
       Unauthorized policy-xattr changes: ``t6111``. Task and socket
       inheritance: ``t6141``, ``t6142``
   * - Telemetry
     - ``t4006``, ``t4104``, ``t6139``, ``t7109``, ``t7110``, ``t8001`` to
       ``t8007``, ``t8101`` to ``t8106``, ``t9101`` to ``t9105``,
       ``t9107``, ``t9109``, ``t9110``, ``t9111``. Fuzz: ``otel``,
       ``quote-check``,
       ``serializer``.
       Unit: ``keepalive``, ``keepalive_quote``, ``sysinfo``
   * - Decoders
     - ``t3002``, ``t8102``, ``t9101``. Fuzz: ``decoder``
   * - Tamper counters
     - ``t6003``, ``t6108``, ``t6115``, ``t6118``, ``t6119``,
       ``t6120``, ``t6121``, ``t6124``, ``t6126``, ``t6135``,
       ``t6137``
   * - CLI
     - ``t1001``, ``t1002``, ``t1011``, ``t2001``, ``t3005``, ``t3106``,
       ``t3108``, ``t5004``, ``t5103``, ``t6007``, ``t6114``,
       ``t7001``, ``t8001``
   * - Build and packaging
     - ``t0005``, ``t0007``, ``t1003``, ``t1004``, ``t1005``,
       ``t7004``, ``t8003``
   * - CI scripts
     - ``t0001`` to ``t0008``
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
       ``t7103``, ``t7104``, ``t7105``, ``t7106``, ``t7107``, ``t7108``,
       ``t8005``, ``t9105``
   * - T8 Quantum-capable adversaries
     - ``t2001``, ``t2002``, ``t5001``, ``t8005``
   * - T9 A target lying about its state
     - ``t4001``, ``t4003``, ``t4004``, ``t4102``, ``t9105``, ``t9112``
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
     - ``t6120``, ``t6155``
   * - ``PinEntry``
     - ``t6121``
   * - ``PerfAttach``
     - ``t6119``
   * - ``SealEntry``
     - ``t6115``, ``t6118``, ``t6144``
   * - ``SealCopyUp``
     - ``t6124``
   * - ``SealPtrace``
     - ``t6134``, ``t6135``
   * - ``SealSignal``
     - ``t6143``
   * - ``ExecTraced``
     - ``t6137``
   * - ``ExecShared``
     - ``t6152``
   * - ``XattrHandle``
     - ``t6153``, on a kernel with XFS
   * - ``SealRlimit``
     - ``t6156``
   * - ``Kexec``
     - ``t6126``

Coverage of integrity counters
------------------------------

``t6003`` checks that every integrity counter has a name and a meaning.
``t6154`` asserts that a refusal moves ``ModuleSignature``, ``Kcore``
and ``PciAccess``, the last two where the kernel has them, and that
``status``, its JSON and the keepalive report the counters. No test
moves the others. The test guest boots without UEFI firmware, so it has
no efivarfs for ``HibernateLocation``, and ``KexecSignature`` cannot
move while the ``Kexec`` guard refuses every kexec image first.

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
  ``SSLKEYLOGFILE``. ``t6136`` covers the dynamic
  loader's variables only.
- A repository index or tree publication signed with a classical
  algorithm.
- Removing an empty sealed directory, ``chattr`` on sealed files, POSIX
  ACLs on them, and a hard link of a labeled inode into an unsealed
  directory. ``t6118`` covers hard links into sealed directories only.
- An eventlog larger than the size the readers accept.
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
- A boot restore that fails part way, among them one that finds a
  device another XDP program holds: only a reboot runs the restore.
  ``t3111`` covers the load, which attaches through the same code.
- Loading an older artifact signed by the same key, and an unload
  directive signed by another trusted key than the load.
- Stopping a running shirudo with ``SIGSTOP``, ``mount_setattr(2)``,
  hibernation and ``/dev/snapshot``, ``/dev/mem``, and TPM access over
  ``i2c-dev`` or ``spidev``.
- A write of the ``HibernateLocation`` EFI variable: the test guest
  boots without UEFI firmware and has no efivarfs.

Tests that assert behavior the threat model lists as a threat to
resolve. They change when that threat is resolved:

- ``t2003`` and ``t5003`` assert that a revoked signer's earlier
  vouches stay valid.
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
  simulator helper.
- Architectures. CI builds and runs the unit tests on arm64 and on
  riscv64, under QEMU user emulation, with the BPF objects built from
  the BTF of the x86-64 bpf-next kernel. The CI suite also runs unit,
  ``ci-checks`` and host functional tests on arm64 with ``VM=0``.
  Target VM tests, end-to-end tests and fuzzing run on x86-64 only. The
  test VM boots arm64 too, and ``t1007`` checks its arm64 settings without
  booting. riscv64 has no test VM.
- Kernels. CI boots bpf-next only. ``KERNEL=`` boots a release kernel
  by hand.

Parsers and units
~~~~~~~~~~~~~~~~~

- The dm-verity superblock check in :src:`util/config_image.c` has no
  fuzz target. ``t5001`` covers truncation and unsupported fields.
- 40 of the 69 modules in :src:`util/` have no unit suite of their own.

Related
-------

- :doc:`/contribute/testing/testing` to run the tests and write one
- :doc:`/security/threat-model` for the threats and residual risks
- :doc:`/security/tamper-counters` for what each counter means
