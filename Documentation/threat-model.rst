..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

shirudo threat model
====================

This is the security design document.  It says what shirudo protects,
against whom, by which mechanism, and where each mechanism stops.  Read
it before changing anything on a security-relevant path: the
`architecture <architecture.rst>`__ says how the pieces fit, this
document says why they must.  A change that keeps the code's shape but
breaks one of the properties below is worse than no change, because it
ships a false sense of safety to fleets and devices that are hard to
patch.

1) Scope and assets
-------------------

shirudo protects a Linux target after ``shirudo init`` has attached its
enforcement programs.  The property it provides: from that point on,
the BPF programs running in the target kernel are exactly the set the
holder of the signing key authorised, every change to that set is
recorded in a TPM measurement an operator can check from one value, and
labelled target files receive the access checks described below.
Writable-state protection has the directory-entry and existing-reference
limits recorded in T11.

The assets, in the order an attacker would want them:

- the private signing key on the operator;
- the certificate on the target and the sealed bpf keyring it is
  enrolled in;
- the enforcement links and the identity map pinned in the private
  bpffs: losing them means losing enforcement;
- the loaded upatches, their pins and the payload xattrs that bind a
  pin to its artifact;
- the TPM measurement register and the eventlog that explains it;
- the installed artifacts and the configuration under
  ``/var/lib/shirudo`` and ``/etc/shirudo``;
- the status, reports and exported telemetry an operator acts on.

2) Trust boundaries
-------------------

The target trusted computing base is the kernel, with the BPF LSM
active and the signed-BPF verification path compiled in, plus shirudo:
the binary, its two embedded enforcement programs, the certificate in
the keyring, and the initrd that runs ``init`` before anything else,
which the measured boot records in PCRs 9 and 11.  Every other process
on the target, including root with every capability, is outside the
TCB and constrained by it.

Every target boots with authenticated runtime and config images. The initrd
initializes enforcement before untrusted workloads, enrolls its trust anchors
and seals the kernel BPF and dm-verity keyrings. Missing image settings or a
sealed empty BPF keyring stop initialization. There is no user-keyring staging
or executable-inode fallback.

Authenticated images are part of this boundary. The UKI supplies the runtime root hash, and the runtime image
supplies the config verification certificate, initial BPF anchors and TPM
settings. The config signature authorizes that image's contents; it does not
replace BPF signatures or vouch requirements. Every executable on the runtime
image has equal authority eligibility. The operator must keep general shells
and debuggers off that image unless their authority is intended. Host root
content and executable paths do not authenticate a caller.

The operator TCB is the operator host, clang/LLVM, libbpf and the
signing key. Image generation and offline verification additionally use
the standard ``veritysetup`` executable; generating an ext4 filesystem
uses ``mkfs.ext4``. These are operator tools, not target dependencies.
An upatch does what its author wrote; shirudo guarantees provenance,
not correctness.

Outside both: the OCI registry, the network, the TLS certificates of
registries and collectors, and whatever remote access an administrator
uses.  A registry can withhold or replay signed content; it cannot
forge any, because every package index, tree publication and loader is
authenticated on the target by its ML-DSA signature.

The kernel is trusted.  shirudo does not defend against a compromised
kernel, verifier, TPM or hardware, and it does not harden the kernel.

3) Adversaries
--------------

A.  Unprivileged local code.  Constrained by the kernel already;
    shirudo adds nothing it needs.

B.  Root on the target without the signing key.  The main adversary: a
    compromised administrator account, a container escape, a
    persistence implant.  It can issue any syscall, write any file,
    ptrace whatever the kernel lets it, and load modules where that is
    allowed.  shirudo must keep this adversary from loading BPF, from
    detaching or replacing shirudo's BPF, from altering shirudo's state
    unnoticed, and from making a tampered target look healthy.

C.  A network adversary between registry and target, or a hostile
    registry.  Can observe, drop, delay and replay.

D.  An adversary holding the operator's signing key.  Out of scope:
    that adversary is the operator.

4) Threats addressed
--------------------

T1  Loading unsigned BPF
    ``lsm/bpf`` admits a userspace ``BPF_PROG_LOAD`` only for a
    ``BPF_PROG_TYPE_SYSCALL`` program that carries a signature.  The
    kernel verifies that signature against the sealed bpf keyring
    named as ``attr.keyring_id = KEY_SPEC_BPF_KEYRING`` before the verifier
    runs. ``lsm/bpf_prog_load`` requires ``BPF_SIG_VERIFIED`` from that kernel
    keyring. Userspace map creation requires task authority committed after
    successful exec from the runtime device; the authenticated bootstrap
    task has temporary authority during initialization. Signed loader map
    creation runs in kernel context.  The payload is hash-locked to the loader by
    ``excl_prog_hash``.  Root without the key gets ``-EACCES`` or
    ``-ENOKEY``; a certificate planted in any other keyring is ignored,
    and a foreign-signed artifact fails with ``ENOKEY``.

T2  Detaching or replacing enforcement
    ``lsm/bpf`` denies ``LINK_DETACH``, ``LINK_UPDATE``,
    ``PROG_ATTACH``, ``PROG_DETACH`` and ``BTF_LOAD`` from userspace,
    and leaves ``LINK_CREATE``, ``RAW_TRACEPOINT_OPEN`` and ``OBJ_PIN``
    to a task authorized by successful runtime exec. Root cannot re-attach a vetted program
    at a site its signer never meant it for, nor pin objects of its own.
    The site a load attaches at is partly the caller's to arrange, and
    root runs ``shirudo upatch load``: a cgroup_skb program under a
    cgroup namespace root or a bind mount of a subtree, a netfilter
    program in a network namespace of the caller's own and a kprobe
    opened through a sysfs that names another PMU would each be
    measured as loaded while guarding nothing or the wrong thing, so
    the load compares the link the kernel reports with the attach
    metadata before pinning it and refuses ``attach_scope_mismatch``.
    The links are kept alive by pins in the private bpffs;
    ``inode_unlink`` and ``inode_rename`` there require that authority.
    The VFS unlinks a rename's victim without ``inode_unlink``, so both
    hooks are needed. ``sb_umount``, ``move_mount``, ``sb_mount`` and
    ``sb_remount`` deny direct operations against that superblock.
    Unmounting a parent mount and legacy mount moves remain gaps,
    described in residual risk 3. Infrastructure maps are
    frozen at creation, so even with the LSM gone userspace could not
    rewrite the identity map. ``lsm/bpf_map`` denies writable map fds
    to every process except shirudo; map updates and freezes have the
    same authority check. Userspace ``BPF_PROG_TEST_RUN`` requires that
    authority too; kernel-context loader calls remain allowed. Root therefore cannot invoke a signed
    serializer to drain or clear map state. Root may inspect pinned maps
    but cannot alter serializer arrays or writable-mmap arena state
    through the syscall interface.

T3  Tampering with shirudo's files and process
    Initialization labels existing files under ``/var/lib/shirudo`` with
    ``security.bpf.shirudo``. For labelled targets, the seal checks write
    open, unlink, both ends of rename, attribute and xattr changes.
    The trusted task mark authorizes the caller.
    Only an authorized caller may set the exact label, including on an
    unlabelled inode. A copied label marks a target, not caller authority.
    Any label size or read error requires authority except ``ENODATA``,
    ``EOPNOTSUPP``, ``EACCES`` and ``EPERM``; the permission exceptions
    preserve operations on files the caller cannot read. Scratch allocation
    failure also requires authority.
    New inodes inherit their parent's label in the creation transaction
    when the parent has a cached seal mark, and a marked directory takes
    new entries from shirudo alone: ``inode_create``, ``inode_mkdir``,
    ``inode_symlink``, ``inode_mknod``, ``inode_link`` and a rename into
    it require the caller's authority, so root brings in neither an
    inode with contents nor a link for shirudo to follow. Shirudo's
    writers hold the parent directory open to populate and retain that
    mark, open nothing in sealed state through a symbolic link, and take
    no entry without the label for shirudo's own: ``init`` labels the
    tree on its first run and afterwards ignores a foreign entry rather
    than labelling, following, restoring or failing on it. Directory
    eviction remains subject to residual risk 15; existing writable
    references are not revoked.
    The authority the seal grants shirudo is not root's to aim: a path
    root names for shirudo to write, a report, an export, evidence or
    a download, is opened as output, never a labelled inode, never
    created under a labelled directory and never through a symbolic
    link, and a registry download goes into the descriptor shirudo
    opened rather than a name reopened later.
    Ptrace and perf allocation checks deny against tasks already marked
    when those hooks run. Concurrent perf attachment and exec remain a
    separate, untested `race investigation <https://github.com/shirudo-dev/shirudo/issues/11>`__.
    Runtime executables reject traced callers and run in
    secure-exec mode, so the loader ignores unsafe environment variables.
    The process drops dumpability, forbids new privileges and locks
    sensitive buffers. The bpf keyring is sealed with
    ``KEYCTL_RESTRICT_KEYRING`` so no key can be linked into it for the
    rest of the boot, ``lsm/key_permission`` leaves writing, unlinking,
    revoking, invalidating and re-permissioning it and the keys it
    holds to tasks with runtime authority. The kernel refuses caller-supplied
    keyrings for signature verification. The BPF ring serial and enrolled key
    serials are frozen into the pinned identity map and checked by later loads.

T4  Substituting artifacts
    The signature covers the loader instructions and data, so the kernel
    refuses a modified loader.  The name an artifact loads under, the
    sites its programs attach at and the target an unload directive
    names and the payload it expects there ride in signed sections of
    the data, so the kernel refuses an edited one and the target
    refuses a header that disagrees with them; a load takes its attach
    sites from nowhere else.  An unload directive is itself a signed
    loader and goes through the same ``BPF_PROG_LOAD``.  Before
    detaching, shirudo compares the live pin's payload xattr, which only
    shirudo can write, against the directive's signed expected payload,
    and refuses ``payload_mismatch`` on disagreement or when the xattr
    is unreadable, so a directive detaches the upatch its signer made
    it for and no other.

T5  Silent state change
    Every init, load, unload and tree operation extends this boot's
    measurement register with a domain-separated digest and appends
    the event to the eventlog.  The register is an NV extend index
    that clears at TPM reset and is written only under its policy: the
    first write of a boot needs PCRs 9 and 11 to hold the values the
    policy was computed from, which ``init`` performs from the initrd
    before ``leave-initrd`` moves PCR 11, and ``init`` extends PCR 9
    with the index name right after that write, so nothing that runs
    later can bind, an index undefined and recreated at runtime cannot
    be written again, and one recreated under another policy has a name
    the eventlog does not know.  A load whose extension fails is
    undone, pins and archive, and reports ``tpm_error`` rather than
    running unmeasured; an unload or purge is measured before it
    detaches, so a process stopped between the two, or a TPM made
    unreachable for the moment, leaves a register that claims more
    than happened and never a detach it does not know; a re-run of
    ``init`` restores nothing once this boot's init event is on
    record, refuses ``tampered`` for an archived artifact that carries
    the label but is not loaded, and ignores one without the label,
    which someone else brought in and nothing would measure.  An eventlog
    that would overflow refuses ``eventlog_full`` before anything
    happens.  Every state-changing command reads the register first and
    refuses ``tampered`` when ``--expect-chain`` disagrees or the index
    is not the one ``init`` recorded, which also serialises concurrent
    operators.  ``shirudo status`` replays this boot's records and flags
    a register it cannot explain.  There is no unmeasured mode: a target
    without a TPM 2.0 does not initialise.  An init run from the initrd
    leaves its record under ``/run``, labelled, until the root's run
    appends it; a record forged or altered there fails the replay like
    any other.  The init record carries
    the TPM's reset count: ``init`` binds one register per reset,
    refuses ``tampered`` when the one it recorded is gone, and
    ``status`` and ``attest verify`` reject a boot with two init
    records for one reset, so the history a register holds cannot be
    restarted by rebinding it.

T6  The boot window
    Enforcement is BPF and does not survive a reboot by itself.
    ``shirudo-initrd.service`` runs ``init`` from the initrd, after the
    ``enter-initrd`` phase is measured and before the switch to the
    root file system, where it enrols the initrd's measured copy of the
    certificate in the still open bpf keyring and seals it, attaches
    the LSM with its pins under ``/run``, which systemd carries across
    the switch, re-applies the installed set all or nothing, binds the
    register and extends it by exactly one event an operator predicts
    from the certificate and the set.  ``shirudo.service`` then finishes
    from the root file system: labels and the eventlog record.  Until
    the initrd run has happened the target is unprotected; see residual
    risk 7.

T7  The delivery path
    The registry index is a detached CMS signature by the operator's
    key, checked against the certificate registered with the repository;
    a package installed from a repository is checked against the digests
    in that signed index; a tree publication is signed, carries
    per-operation digests and sequence continuity, and a ``delete`` is
    accepted only for an id loaded from the same tree.  TLS is 1.3 with
    hybrid ML-KEM only, so the transport is not the weak link even
    though it is not the trust anchor.

T8  Quantum-capable adversaries against the trust anchor
    Signing is ML-DSA-87 (FIPS 204) only: ``genkey`` makes nothing else,
    the builder refuses a classical key, and the pre-flight refuses a
    classical certificate, so a fleet cannot drift back by
    misconfiguration.  Digests are SHA-256 and SHA-512, which stay well
    above a 128-bit margin against Grover-style search.  Long-lived
    embedded fleets are the reason: a forgeable signature would let a
    future adversary install BPF on every device that still trusts the
    old certificate.

T9  A target lying about its state
    ``shirudo status`` is the target's own account and proves nothing
    by itself.  ``shirudo attest`` makes the TPM speak: a quote over
    the firmware, boot loader, kernel, initrd and systemd PCRs and a
    certification of the register, both signed by an attestation key
    the operator pinned by name and carrying the operator's nonce.  A
    challenge the operator made under the target's endorsement key
    (``shirudo attest challenge``) and the target activated while
    attesting proves that the attestation key sits in the TPM whose
    endorsement key and certificate the evidence carries.
    ``shirudo attest verify`` ties the certified index to the recorded
    PCR binding, replays the eventlog to the certified value and
    compares it with the value predicted from the certificate and the
    installed artifacts, so a substituted binary, a recreated index or
    an unexpected set is a failed check, not a healthy report.  Which
    firmware, kernel and initrd values are acceptable is the platform
    owner's policy; ``--expect-pcr`` pins them and the logs in the
    evidence explain them.

T10 An attempt that leaves no trace
    The named guard points count their refusals (a
    load that is no signed loader, one without a signature, one whose
    signature was verified against the wrong kind of keyring or the
    wrong keyring, a writable map descriptor, a rename of a pin, an
    unmount of the bpffs, a write to a sealed file, a ptrace of a
    shirudo task, and so on), in a map ``init`` pins and freezes, so
    that no task, shirudo included, can reset it from userspace while
    the hooks still add to it. ``shirudo status`` lists the counters
    that are not zero with what each means, ``status --json`` carries
    them all, and the keepalive takes them to the collector with the
    total as the ``shirudo.tamper_attempts`` attribute, so an attempt
    is seen where it was made and not only where it failed. A counter
    is evidence of an attempt, not of a compromise: the refusal is what
    moved it. Image-only device, parent-mount and process refusals do not
    yet have counters. An earlier image guard may refuse an operation
    before it reaches a shared counter; zero does not mean no attempts.


T11 Image-mode config and executable substitution
    dm-verity checks the runtime and config backing blocks. Runtime
    acceptance requires the exact root authenticated by the UKI. Config
    roots carry a detached ML-DSA signature over their 64 lowercase ASCII
    hex bytes, verified by the kernel's dm-verity trust path, including
    built-in trusted keys. The initrd enrolls its config certificate and
    seals the dedicated ``.dm-verity`` keyring. A signed config never grants
    runtime executable authority. Shirudo validates the standard superblock,
    fixed format and exact backing-file sizes, creates or validates a strict
    read-only mapping and reads every data block before parsing contents or
    measuring activation. Reused mappings undergo the same read. A signature
    alone does not authenticate backing bytes: corruption or incomplete reads
    refuse preparation. The target neither reconstructs the hash tree nor
    invokes ``veritysetup``. Shirudo observes the mapping
    metadata exposed by existing upstream hooks. The native ioctl hook restricts DM-control mutations to trusted
    image tasks, including through old or inherited FDs; this restriction
    applies to unrelated DM devices too. Config device classification also
    requires the root expected by the trusted task creating that mapping.
    Image mode requires 32-bit compatibility disabled in the kernel; its
    device-mapper checks cover native ioctls only.
    Enforcement uses existing LSM hooks; direct access to the dm-verity
    keyring requires the upstream keyring-ID API. The mount hooks do not
    cover every mount attribute change or
    unmount of a parent mount above the image mounts. A
    candidate config cannot supply bootstrap keys or TPM settings, and config symlinks and special
    files are refused. Repository certificate paths resolve inside the held
    config root. Complete settings validation precedes activation measurement;
    local key and repository mutations cannot override that signed config.

    Successful exec commits task authority; fork inherits it, failed exec
    preserves it and successful outside-image exec clears it. Memory checks
    remain necessary because dm-verity does not protect anonymous memory
    or permit untrusted executable libraries. Writable state retains its
    seal, enforced using this task authority. Initial sealing occurs in
    the authenticated initrd before hostile tasks. New inodes inherit a
    cached parent label during creation, subject to residual risk 15.
    The seal does not exclude every foreign directory entry or revoke
    existing writable descriptors or mappings. The historical
    `directory-entry investigation <https://github.com/shirudo-dev/shirudo/issues/13>`__
    describes the earlier baseline; the current cached-parent behavior is
    described in T3 and residual risk 15.

T12 Interrupted image activation
    The candidate and pending selection are durable before PCR extension.
    Validation failures before that point leave the active config usable.
    An interruption after it, including an ambiguous TPM response, requires
    manual reboot. The node keeps running; Shirudo does not initiate that
    reboot. Further state changes and config attestation refuse; no same-boot
    recovery or extension retry is attempted. Trusted startup re-verifies the
    selected image, reads its entire verified mapping, emits a fresh BOOT
    event and applies revocations before restoring upatches. Completion is
    recorded only after startup succeeds. Missing or invalid selected images
    fail initialization rather than silently choosing an older config.

5) Residual risks
-----------------

Each of these is known, documented and bounded; none is silent.

1.  The detach runs in userspace: the kernel's ``bpf_sys_bpf()`` cannot
    detach or unlink.  The directive's target name and expected payload
    are signed, so root cannot repoint a directive at another upatch;
    what root keeps is the moment, since every directive the operator
    published, in a package beside its load, is root's to apply at any
    time, and the register records each application.  An in-kernel
    detach would make the whole lifecycle signed BPF.

2.  ``CAP_SYS_RESOURCE`` can rewrite ``mm->exe_file``. The task mark is
    independent of that field, and ``task_prctl`` denies those operations to
    untrusted callers. Successful runtime exec grants authority; failed exec
    preserves the old mark and outside-image exec clears it. Runtime programs
    run with secure-exec, reject tracing and existing seccomp, and cannot map
    executable host or anonymous pages. Their command interface remains the
    authorization boundary. The authenticated initrd bootstrap binary and
    trusted runtime process memory remain in the TCB.

3.  A lazy unmount of a mount above ``/run/shirudo/bpffs``, such as
    ``umount -l /run``, can detach the bpffs with it. The kernel calls
    ``sb_umount`` for the requested parent mount alone, so the direct
    bpffs check does not stop this. Once its last references disappear,
    the pins can be released and enforcement can detach. The mount-tree
    check was reverted because it blocked systemd service startup.
    `Issue 22 <https://github.com/shirudo-dev/shirudo/issues/22>`__ tracks
    keeping the pins alive without depending on a visible mount tree.
    Mounting over ``/run/shirudo`` only hides the pins; it does not release
    them. Enforcement continues, but state-changing commands refuse
    ``lsm_detached`` while their pins are hidden.

    Legacy ``mount(MS_MOVE)`` bypasses the source check used by
    ``move_mount``. Runtime-image relocation succeeded in an isolated
    VM namespace; the corresponding baseline bpffs gap is source-derived.
    Relocation alone preserves device identity and does not detach pins
    or grant authority to host files. The separate `mount-move
    investigation <https://github.com/shirudo-dev/shirudo/issues/12>`__ records the evidence.

4.  TPM measurement writers are not yet bound to completed Shirudo
    operations. A caller with direct TPM-command access can append to the
    written NV register or the config PCR. Garbage makes replay fail and
    can deny service. A public digest of a valid operation can instead
    record a claim that the operation happened when it did not. A fresh
    nonce, a genuine TPM quote and replay of an externally supplied log do
    not prove who appended the digest or that the operation completed.
    The separate measurement-spoofing investigation is not fixed by image
    mode. Static PCRs prevent runtime reset, not unauthorized extends.
    Restricting measurement writers and handling operation/measurement
    ordering remain separate work; no IMA integration is added.

5.  Authenticated boot must verify the expected runtime root. dm-verity
    verifies runtime files but still trusts the UKI, kernel and trusted process
    memory. ``SHIRUDO_VERSION_ID`` is a skew guard, not authentication.

6.  There is no user-keyring staging fallback. Boot without the required
    enrollment parameters, authenticated settings or valid images fails
    initialization. A failed init does not create a protected target.

7.  The boot window before ``init`` has run.  Run from the initrd it
    is the initrd itself, which the measured boot records in PCRs 9 and
    11 and the verifier pins; PCR 11 carries the initrd phases only on
    a measured UKI boot, and without them the verifier has PCR 9 alone
    to tell the initrd binding from a later one.  Started from the root
    file system
    instead, every process that runs before it is unconstrained, the
    certificate is only staged, and the binding carries the
    post-``leave-initrd`` PCR 11 value, which ``--expect-bind-pcr=11``
    and ``--require-initrd`` reject.

8.  Registry withholding and replay.  A hostile registry can serve an
    old signed index, or none; it cannot serve a forged one.  Operators
    who need freshness compare the versions ``shirudo bpm list``
    reports and the register ``attest`` certifies against what they
    published.

9.  Classical pieces outside the boundary: WebPKI server certificates
    on registries and collectors (they authenticate the transport, not
    the artifacts), and the attestation key, which is ECDSA P-256
    because TPMs sign with nothing post-quantum today.  The evidence is
    therefore classical even though the artifacts it describes are not.

10. Endorsement key trust.  Credential activation ties the attestation
    key to the endorsement key in the evidence, and the endorsement
    certificate ties that key to a manufacturer.  ``challenge`` makes
    no challenge unless the certificate chains to the issuers given
    with ``--ek-ca``, the key is pinned with ``--ek-name`` from an
    inventory or a platform's API, or the operator waives the check
    with ``--trust-presented-ek``, which proves only that the same
    party answers each time; a TPM without a certificate, as virtual
    TPMs usually are, needs one of the latter two.  Which issuers to
    trust is the operator's decision.

11. The anchor shares PCR 9 with the initrd measurements and with
    systemd's ``nvpcr-init`` events and their separator, so ``attest
    verify`` proves the anchor exactly only when nothing is measured
    into PCR 9 after ``init``, which holds when it runs after
    ``systemd-pcrnvdone.service``; otherwise it says so and leaves the
    replay of the systemd measurement log, which the evidence carries,
    to the verifier's tooling.  ``--strict-anchor`` turns the note into
    a failure.

12. A root process that runs before ``init`` in the same boot phase
    can bind and write the register first, and a record it forges
    before the eventlog is sealed is indistinguishable from ``init``'s.
    From the initrd that phase is the initrd itself, measured and
    pinned; from the root file system it is the window of residual risk
    7, and the binding then carries a PCR 11 value the verifier can
    reject.

13. Revocation reaches a target only when its signed config is delivered
    and activated. A node that has not received it can still verify BPF signed
    by the old key. The config PCR records activation, and revoked signers'
    upatches receive unload events in the NV register. There is no local
    ``keys revoke`` override or push channel.

14. Shirudo accepts an older config when its signature is valid. A
    config PCR extension records the selection but does not enforce
    freshness. Replaying an older config can restore its older trust and
    revocation settings. Rollback prevention is deferred. The config
    verification certificate itself can change only with the authenticated
    runtime image and a reboot.

15. The label at creation follows a mark the seal keeps on a directory
    it has seen since the inode came into memory: one opened, one
    relabelled, or one created under a marked parent.  shirudo opens a
    directory before creating in it and puts the label on afterwards
    where the kernel could not. While the mark is absent another process
    can create under a labelled directory, or rename or link an inode
    with its contents into it, and the entry carries no label: shirudo
    opens sealed state without following a symbolic link, refuses an
    entry under a labelled directory that lacks the label, and ``init``
    ignores it rather than labelling it, so such an entry is inert until
    root removes it.

Deferred mitigations
~~~~~~~~~~~~~~~~~~~~

In scope and not yet built: restricting TPM measurement writers and binding
measurements to completed operations (residual risk 4); config rollback
prevention (residual risk 14); registering the register as a systemd
NvPCR, so that its name follows the UKI signing key instead of the PCR
values of each boot and systemd-aware verifiers find it in PCR 9 before
the separator, and measuring the anchor through ``systemd-pcrextend`` so
systemd's measurement log explains it (residual risk 11); signed PCR
policies for the kernel and initrd PCRs so a verifier needs no golden
values; an in-kernel detach so the pin removal is signed BPF rather
than userspace (residual risk 1); and a ``d_instantiate`` hook the BPF
LSM can sleep in, which would mark a directory the moment its dentry is
bound and close the eviction gap (residual risk 15).

6) Out of scope
---------------

- Compromise of the operator host or the signing key.
- A malicious or buggy kernel, verifier, TPM or hardware.
- Denial of service: removing the binary, cutting the network, filling
  the disk.  shirudo fails closed and loud; it does not fail over.
- Correctness or safety of an upatch an authorised signer built.
- Fleet inventory, rollout ordering, retries, scheduling and
  cross-target consistency.  shirudo reports one machine; aggregation
  is the collector's job.
- SSH, remote access and audit retention.  Those belong to the
  infrastructure the operator already runs.

7) Operational guidance
-----------------------

Keep the signing key on a host with the controls of a certificate
authority and never on a target.  Boot targets with
``bpf.keyring_unsealed=1 dm_verity.keyring_unsealed=1`` and run ``init``
from the authenticated initrd with valid runtime and config images. Check
``--require-initrd`` and ``--expect-bind-pcr=11`` against the UKI's measured
``enter-initrd`` value.  Give ``challenge``
the manufacturer's issuers with ``--ek-ca`` wherever the TPM has a
certificate.  Treat ``tampered`` as an incident to understand, not a
condition to retry.  Verify ``shirudo status`` after
every boot and every load; a target whose register the eventlog cannot
explain is not healthy just because it is still running.  Record the
attestation key name when a target is enrolled (``shirudo attest``
once, keep ``ak.name``), and let the fleet's health be ``shirudo attest
verify`` against a fresh nonce and the values ``shirudo attest
predict`` computes from what you installed, not a status the target
wrote about itself.  Build
upatches against the target kernel's BTF and read verifier logs from
the structured report.  Restrict who can register repositories and who
can run state-changing commands, and drop ``CAP_SYS_RESOURCE`` from
anything that does not need it.  Rotate the signing key in the order
the `key-lifecycle <key-lifecycle.rst>`__ guide gives, rebuild the
initrd after every change of binary or certificate, and reboot after
upgrading shirudo; the `operations <operations.rst>`__ guide has the
procedures.
