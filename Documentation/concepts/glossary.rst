..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: All readers

Glossary
========

The terms the shirudo documentation uses, each with the page that explains
it.

.. glossary::
   :sorted:

   anchor
      The SHA-256 of the string ``nvpcr-init:shirudo:0x<handle>:<name>``,
      with the measurement register's NV handle and TPM name, which
      ``init`` extends into PCR 9 right after it binds the register. It
      ties the register to the measured boot and closes the register's
      first-write branch until the next TPM reset. ``shirudo attest
      verify`` checks that PCR 9 carries it. See
      :doc:`/concepts/measurement-register`.

   arena
      A BPF map of type ``BPF_MAP_TYPE_ARENA``, a memory region from which
      BPF programs allocate records directly. A upatch that accumulates
      records keeps them in one arena, which its serializer reads as one
      consistent snapshot and can reset between exports.
      :src:`upatches/kernel-obs/obs_table.h` is the template for a
      double-buffered arena table. See
      :doc:`/upatches/write/maps-arenas-serializers`.

   attach metadata
      The signed ``UPGM`` section of a load artifact that tells shirudo
      how to attach each program: its role, its attach kind and, for
      kprobes and uprobes, the site. It is signed because the site of a
      kprobe, uprobe, ``cgroup_skb`` or ``netfilter`` program is chosen
      when the link is created, not by the program's instructions. After
      attaching, shirudo compares each link with it and refuses with
      ``attach_scope_mismatch`` on a difference. See
      :doc:`/concepts/upatches-and-packages`.

   attestation key
      The TPM key that signs evidence: a restricted ECDSA P-256 signing
      key, created as a primary under the endorsement hierarchy from a
      fixed template, so the same TPM always yields the same key.
      ``shirudo attest`` creates it for each run and flushes it
      afterwards. The operator pins its name when enrolling a target and
      passes it to ``shirudo attest verify --ak-name``. See
      :doc:`/concepts/measurement-register`.

   Beefile
      The definition of a bpm package: a file in a subset of TOML, in the
      package directory, that names the package and lists its upatch
      sources, read-only data generators, extra files and tree selectors.
      ``shirudo bpm build`` reads ``Beefile`` in the package directory, or
      the file that ``--file`` names. See :doc:`/reference/formats/beefile`.

   BPF keyring
      The kernel's ``.bpf`` keyring, which the kernel uses for a signed
      BPF program whose load names ``KEY_SPEC_BPF_KEYRING``. Booted with
      ``bpf.keyring_unsealed=1``, it starts open; ``init`` enrolls the
      trusted set and seals it, and ``lsm/key_permission`` keeps tasks
      without runtime authority from removing keys. ``lsm/bpf_prog_load``
      admits a load from userspace only when the kernel verified its
      signature against this keyring. See
      :doc:`/concepts/background/keyrings`.

   bootstrap settings
      The settings ``init`` needs before it trusts a config image. The
      initrd's ``/etc/shirudo/shirudo.conf`` names the runtime image and
      its root hash (``runtime.image``, ``runtime.root_hash``). The
      runtime image's ``etc/shirudo/shirudo.conf`` names the config image,
      its verification certificate and its PCR (``config.image``,
      ``config.verification_key``, ``config.pcr``) and holds the TPM
      settings; no config image can change them. See
      :doc:`/internals/config-images`.

   bpm package
      A versioned ``.bee`` file that ``shirudo bpm build`` makes from a
      Beefile: a gzip-compressed tar archive with the Beefile, the
      package's upatches and unload directives, its ``README.md``, the
      signing certificate and a record of the build environment. The
      package carries no signature of its own. A repository's signed index
      lists its digest, and each upatch inside is signed. See
      :doc:`/concepts/upatches-and-packages`.

   challenge
      The credential that ``shirudo attest challenge`` makes on the
      operator host for a target's endorsement key and the pinned
      attestation key name. The target's TPM recovers it with ``shirudo
      attest --challenge=<path>`` only when both keys are in that TPM, and
      ``shirudo attest verify --expect-credential`` checks the recovered
      value. It shows that the attestation key sits in the TPM the
      endorsement key identifies. See :doc:`/operate/run/attest`.

   config image
      A dm-verity image, mounted read-only and ``noexec`` at
      ``/run/shirudo/config``, that carries what an operator changes
      during operation: repositories and their certificates, the tree
      subscription, node labels, vouched and revoked certificates, and
      export settings. Its root hash is signed: shirudo verifies the
      signature against the runtime image's config certificates before
      it maps the image, and the kernel against its trusted keys and the
      sealed ``.dm-verity`` keyring. ``shirudo image update`` activates a
      new config image without a reboot and measures it into a dedicated
      PCR.
      See :doc:`/internals/config-images`.

   decoder
      A Lua function shipped inside a upatch that turns a snapshot of one
      map into OTLP log records or metrics. The program declares it with
      a ``struct decoder_manifest`` in ``.rodata``,
      ``shirudo-build`` embeds the source in the signed ``DCDB`` section,
      and ``shirudo upatch map`` runs it under LuaJIT. See
      :doc:`/upatches/write/decoders`.

   endorsement key
      A key that identifies a TPM, derived from its endorsement seed with
      a template the TCG fixes, and often described by a certificate from
      the TPM's manufacturer. shirudo uses it for credential activation,
      which ties the attestation key to this TPM, and checks the
      certificate's chain when the operator passes ``--ek-ca``. The
      evidence carries its public part and, when the TPM holds one, its
      certificate. See :doc:`/concepts/background/tpm`.

   enforcement programs
      The BPF LSM programs embedded in the ``shirudo`` binary, built from
      :src:`bpf/bpf2.c` (``bpf()`` admission, keyrings, the private bpffs,
      mounts, devices and the TPM) and :src:`bpf/seal.c` (the seal and the
      task marks). ``init`` loads them before their admission gates
      attach, so they are the one BPF code that does not pass the signed
      loader path; in production the authenticated initrd vouches for
      them. Their links are pinned in the private bpffs. See
      :doc:`/internals/enforcement`.

   eventlog
      The file ``/var/lib/shirudo/eventlog``, with one JSON line for every
      extend of the measurement register: the event digest, its type, the
      boot ID and the fields the digest covers. shirudo only appends to it
      and keeps the records of every boot. A verifier trusts it only as
      far as this boot's records replay to the value the TPM certifies.
      See :doc:`/reference/eventlog`.

   evidence
      The JSON document, of kind ``shirudo-attestation``, that ``shirudo
      attest --nonce=<hex>`` writes on a target. It carries a TPM quote
      over the selected PCRs and TPM certifications of the measurement
      register on both sides of the quote, bound to the request nonce,
      together with the attestation and endorsement keys, this boot's
      eventlog records and the boot measurement logs. ``shirudo attest
      verify`` checks it on the operator host. See :doc:`/operate/run/attest`.

   failure category
      A name for why an operation failed, such as ``tampered``,
      ``signature_rejected`` or ``payload_mismatch``. ``shirudo upatch
      load`` and ``unload`` print it and write it, with the phase the
      operation reached, into the ``--report`` document. ``tampered``
      means refresh the state and decide again, never retry the same
      input. See :doc:`/reference/failure-categories`.

   identity map
      A one-entry BPF array map, pinned at
      ``/run/shirudo/bpffs/identity``, in which ``init`` records what the
      enforcement programs compare against: the devices of the private
      bpffs and of ``/run/shirudo``, the ``.bpf`` keyring and the enrolled key
      serials, the runtime image's root hash, the NV index and its writer
      key, the endorsement key's name for TPM sessions and the
      ``.dm-verity`` keyring.
      ``init`` freezes it before the admission gates attach, so userspace
      cannot change it afterwards. See :doc:`/internals/enforcement`.

   init record
      The eventlog record of type ``init`` that ``shirudo init`` writes
      when it binds the measurement register. It carries the ``init``
      event's inputs, the values of PCRs 9 and 11 before the binding,
      whether the initrd made the binding, the register's TPM name, the
      anchor, the TPM reset count and the writer key's public part. In the
      initrd, ``init`` writes it to ``/run/shirudo/eventlog.pending``, and
      the root file system's run adopts it. See
      :doc:`/internals/measurement-register`.

   keepalive
      An OTLP log record named ``shirudo.keepalive`` that carries a
      target's status record and the TPM quote of it.
      ``shirudo-keepalive.timer`` runs ``shirudo status --otel`` about
      every minute, which sends one when an OTLP endpoint is configured
      and the TPM quotes. A missing keepalive tells a collector that a
      target stopped reporting; a present one is still the target's own
      account. See :doc:`/operate/run/telemetry`.

   load artifact
      A ``.upatch`` file that installs a upatch: a header with the name
      and the payload digest, the signed loader's instructions, the
      loader's data with the signed sections, and a CMS signature over the
      instructions followed by the data. ``shirudo build`` writes it, and
      ``shirudo upatch load`` loads it. See
      :doc:`/reference/formats/upatch-format`.

   map export
      The periodic export of upatch map contents.
      ``shirudo-map-export.timer`` runs ``shirudo upatch map --all`` about
      every five seconds, which reads the maps of every loaded upatch,
      runs their serializers and decoders, and sends the records to the
      destinations that the config image's ``map_export`` settings name.
      See :doc:`/operate/run/telemetry`.

   measurement register
      The TPM NV extend index, ``0x01818E00`` by default, that records
      every change to a target's BPF state during one boot. Each extend
      needs a signature from the per-boot writer key, and
      ``lsm/tpm_command`` keeps tasks without runtime authority from
      submitting one. It clears at every TPM reset, so its value depends
      only on the trusted certificates, the restored set, the tree
      position and the events since boot. See
      :doc:`/concepts/measurement-register`.

   metadata map
      The array map ``__loader.map`` that holds a signed loader's data
      during a load. shirudo creates it exclusive to the loader, by the
      SHA-256 of the loader's instructions, fills and freezes it, and
      passes it with the loader to ``BPF_PROG_LOAD``. The kernel verifies
      the signature over the instructions followed by the map's frozen
      contents. See :doc:`/internals/signed-loader`.

   NV extend index
      A TPM non-volatile index of type ``TPM2_NT_EXTEND``, which a write
      extends like a PCR instead of overwriting. shirudo's measurement
      register is one, with ``TPMA_NV_CLEAR_STCLEAR`` set so that it
      clears at every TPM reset, following systemd's NvPCRs. See
      :doc:`/concepts/background/tpm`.

   NV writer key
      An RSA-3072 key that ``init`` creates inside the TPM at every boot,
      and whose signature the measurement register's write policy
      requires for every extend. The identity map holds its public part
      and the input that recreates it, and each command recreates the key
      to sign one exact extend command. The key is no secret;
      ``lsm/tpm_command`` is what keeps other tasks from extending. See
      :doc:`/internals/measurement-register`.

   operator
      The role that holds the private ML-DSA-87 signing key, builds and
      signs upatches, publishes packages and verifies evidence. The
      operator is stateless: it writes only the key pair and the files
      the caller names, and it never opens a TPM or a kernel keyring. See
      :doc:`/concepts/operator-and-target`.

   operator host
      The machine where the operator's commands run and the signing key is
      kept. It needs the ``shirudo-build`` helper and clang, and no TPM.
      Its integrity is outside what shirudo protects. See
      :doc:`/concepts/operator-and-target`.

   payload digest
      SHA-256 over a load artifact's loader instructions followed by its
      data, stored as ``payload_sha256`` in the header. The target
      recomputes it before loading and refuses a mismatch. From then on it
      identifies the upatch: in the ``security.bpf.shirudo.payload``
      attribute on the pin directory, in the measurement events and in
      the unload directive that removes it. See
      :doc:`/concepts/upatches-and-packages`.

   pin
      A file in a BPF file system that keeps a BPF object, such as a link
      or a map, alive after the process that created it exits. shirudo's
      commands are one-shot, so every link and map that must stay is
      pinned in the private bpffs. Removing a pin detaches a link once
      nothing else holds it. See :doc:`/concepts/background/bpf`.

   predict
      ``shirudo attest predict``, which computes on the operator host the
      register values a target must hold: the set digest, the ``init``
      event, the register at boot and, with ``--event``, the register
      after later events. It uses the target's own functions, applied to
      the certificates and artifacts the operator names. See
      :doc:`/reference/cli/attest-predict`.

   private bpffs
      The BPF file system instance that ``init`` mounts at
      ``/run/shirudo/bpffs`` with mode ``0700``. It holds the pins of the
      enforcement links, the identity map, the tamper and integrity
      counters and every upatch's links and maps. BPF LSM hooks refuse unlink, rename and
      opening a pin there to tasks without runtime authority, and refuse
      every caller the unmount, move or remount of the mount ``init``
      made. See :doc:`/internals/enforcement`.

   projection root
      A hash chain over the upatch tree operations a target applied, kept
      in its tree state. The next boot's ``init`` event includes it, so
      the predicted register covers the tree, and ``shirudo attest predict
      --tree-root`` takes it as input. See
      :doc:`/concepts/upatches-and-packages`.

   repository
      A named OCI registry endpoint together with the certificate that
      signs its index. On a target, repositories come from the config
      image's ``etc/shirudo/bpm/registries.d/``, and ``shirudo bpm install
      <repository>/<package>`` installs from one. See
      :doc:`/operate/run/deliver-packages`.

   revocation
      Withdrawing trust from a signing key through a signed config image
      whose ``keys/revoked/`` directory names the key's certificate. When
      ``shirudo image update`` activates such a config, shirudo unlinks the
      key from the ``.bpf`` keyring, measures a key revocation event, and
      unloads and purges every upatch the key signed. ``shirudo keys
      revoke`` refuses and points to this path. See
      :doc:`/operate/maintain/keys`.

   runtime authority
      The right that a task mark grants: to run the ``bpf()`` commands,
      descriptor accesses, pin changes, sealed-state writes, keyring
      changes and TPM extends that the enforcement programs reserve for
      shirudo. It never replaces a signature, since a program load from
      userspace needs a verified signature whoever asks. See
      :doc:`/concepts/operator-and-target`.

   runtime image
      The dm-verity image, mounted read-only at ``/run/shirudo/runtime``,
      that carries the ``shirudo`` executable, the initial BPF certificate
      ``keys/cert.der``, the config verification certificates and the
      bootstrap settings. The UKI's initrd names its root hash, so the
      measured boot covers it. Every executable on it gains runtime
      authority when it runs. See :doc:`/internals/config-images`.

   seal
      The BPF LSM programs from :src:`bpf/seal.c` that protect shirudo's
      writable state and processes. They refuse writes, unlinks, renames,
      attribute changes and new entries on labeled inodes under
      ``/var/lib/shirudo`` to tasks without runtime authority, and keep
      other tasks from tracing a marked task. They do not revoke writable
      descriptors or mappings that existed before. See
      :doc:`/internals/seal`.

   seal label
      The extended attribute ``security.bpf.shirudo`` with a fixed
      64-character value that marks an inode the seal protects. ``init``
      labels shirudo's writable state, and a new inode under a labeled
      directory inherits the label. The label marks a target, not an
      authority, so copying it onto a binary grants nothing. See
      :doc:`/internals/seal`.

   selector
      The condition on a upatch tree operation: lists of architectures,
      kernel release prefixes, kernel build IDs, kernel configuration
      values and node labels. ``shirudo bpm tree sync`` evaluates it on
      the target and applies only matching operations, and a
      non-matching operation is skipped for good. See
      :doc:`/upatches/publish/publishing`.

   serializer
      A ``SEC("syscall")`` program in a upatch, named
      ``shirudo_serialize__<map>``, that renders one map into the
      upatch's ``shirudo_ser`` output map in chunks of 4096 bytes.
      ``shirudo upatch map`` runs it with ``BPF_PROG_TEST_RUN``, which
      gives one consistent snapshot of an arena and lets the serializer
      reset what it exported. See
      :doc:`/upatches/write/maps-arenas-serializers`.

   ``shirudo-build``
      The operator-only helper that the core ``shirudo`` binary executes
      for ``build``, ``bpm build``, ``bpm push``, ``bpm tree append``,
      ``bpm tree show``, ``bpm config update``, ``image build``, ``image verify`` and ``keys
      vouch``. It links the signer, runs clang and runs ``veritysetup``.
      The operator package installs it and the target package does not.
      See :doc:`/concepts/operator-and-target`.

   ``SHIRUDO_VERSION_ID``
      A build identity that ``shirudo version`` prints: SHA-256 over the
      source revision and a digest of the build configuration files. It
      does not hash the binary, so builds of one source for x86-64, arm64
      and riscv64 share it. ``shirudo upatch load
      --expect-version-id=<id>`` refuses with ``version_mismatch`` when
      the target's differs. See :doc:`/reference/cli/version`.

   signed index
      The JSON document at ``<namespace>/bpm-index:stable`` in a registry that
      lists each package's name, version, manifest digest and package
      digest, with a detached CMS signature. ``shirudo bpm push`` updates
      it and refuses to list a version again with different content, and
      ``shirudo bpm repo update`` verifies it against the repository's
      certificate. See :doc:`/reference/formats/bpm-formats`.

   signed loader
      A BPF program of type ``BPF_PROG_TYPE_SYSCALL``, generated by
      libbpf's ``gen_loader``, that creates a upatch's maps and loads its
      programs from inside the kernel. The operator signs its instructions
      followed by its data, and the kernel checks that signature at
      ``BPF_PROG_LOAD`` against the ``.bpf`` keyring. After ``init``, it
      is the only way BPF from userspace enters the kernel. See
      :doc:`/internals/signed-loader`.

   integrity counter
      A counter for one way to change or read the running kernel that
      the enforcement programs refuse, such as ``ModuleSignature``,
      ``DevMem`` or ``Kcore``. The counters live in a map pinned at
      ``/run/shirudo/bpffs/integrity``, apart from the tamper counters,
      and ``shirudo status`` reports them. See
      :doc:`/security/integrity-counters`.

   tamper counter
      A counter for one point at which the enforcement programs refuse a
      caller, such as ``BpfCommand``, ``PinUnlink`` or ``ObjGet``, or,
      for ``SealSignal``, let one through. The counters live in a map
      pinned at ``/run/shirudo/bpffs/tamper`` that only the enforcement
      programs increment, and ``shirudo status`` reports them. Not every
      refusal has a counter. See
      :doc:`/security/tamper-counters`.

   target
      A Linux machine with a TPM 2.0 that runs shirudo from an
      authenticated runtime image, enforces signed BPF in its kernel and
      measures every change into its TPM. It holds public certificates
      only, runs no daemon and pulls packages on timers. See
      :doc:`/concepts/operator-and-target`.

   task mark
      A per-task record in BPF task storage that the seal sets when a task
      successfully executes a file from the runtime image. A forked child
      inherits it, a successful exec of any other file clears it, and a
      failed exec leaves it unchanged. The enforcement programs consult it
      instead of the task's path or user. See :doc:`/internals/seal`.

   tree publication
      One generation of a upatch tree: a JSON document with the tree ID,
      the generation number, the digest of the manifest it replaces and
      the ordered operations, published with a detached CMS signature
      under a tag of the tree repository, ``stable`` by default. ``shirudo
      bpm tree append`` publishes the next generation, and targets verify
      it against the active config's trusted set. See
      :doc:`/reference/formats/bpm-formats`.

   trusted set
      The certificates a target enrolls in the ``.bpf`` keyring at boot:
      the runtime image's ``keys/cert.der``, and every certificate under
      the config image's ``keys/trusted/`` whose vouch verifies under a
      member, less those the config revokes. It holds at most 16
      certificates, and the ``init`` event covers its digest. See
      :doc:`/operate/maintain/keys`.

   unload directive
      A signed ``.upatch`` with the unload flag set that removes one
      upatch. Its signed sections name the upatch and the payload digest
      it must have. The target has the kernel verify the directive's
      loader without running it, and refuses with ``payload_mismatch``
      when the digest differs from the pin's. See
      :doc:`/concepts/upatches-and-packages`.

   upatch
      A signed BPF object, one or more programs with their maps and attach
      metadata, that a target loads, pins, archives and measures as one
      unit. It ships as a load artifact and leaves through an unload
      directive. See :doc:`/upatches/learn/concepts`.

   upatch tree
      A signed, append-only, ordered list of operations, each adding or
      deleting one upatch on the targets its selector matches. Targets
      subscribe through their config image, and ``shirudo bpm tree sync``
      applies new matching operations in sequence and measures each. See
      :doc:`/concepts/upatches-and-packages`.

   verdict
      The one-word result of a check. ``shirudo status`` reports an
      overall status of ``ok``, ``degraded``, ``reboot-pending``,
      ``init-pending``, ``lsm-off`` or ``tampered``, and ``OK``, ``WARN``
      or ``ALERT`` for each condition. ``shirudo attest verify`` ends with
      ``verdict: ok`` or ``verdict: fail``. See :doc:`/operate/run/read-status`.

   vouch
      A detached CMS signature by a trusted key over the prefix
      ``shirudo-key-vouch``, its terminating NUL and another certificate's
      DER. ``shirudo keys vouch`` makes one, and a config image ships it
      beside that certificate under ``keys/trusted/``, which admits the
      certificate to the trusted set at the next boot. A vouch carries no
      date, so it stays valid after its signer is revoked. See
      :doc:`/operate/maintain/keys`.
