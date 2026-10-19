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
the target-local state shirudo depends on cannot be altered by anyone
but shirudo itself.

The assets, in the order an attacker would want them:

- the private signing key on the operator;
- the certificate on the target and the sealed bpf keyring it is
  enrolled in, or the sealed ``shirudo`` user keyring that stages it;
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

Two configurations exist and ``status`` names them.  In production the
kernel is booted with ``bpf.keyring_unsealed=1`` and ``init`` runs from
the initrd: the certificate goes into the kernel's bpf keyring, which
``init`` seals and nothing can replace, and the register binds while
PCR 11 holds the ``enter-initrd`` phase, which nothing that runs later
can bring back.  Staging is what a target gets when ``init`` runs from
the root file system on a kernel that sealed the bpf keyring empty at
boot: the certificate sits in a ``shirudo`` keyring under the user
keyring, sealed, and the register binds under the post-initrd phase
value.  Everything below holds in both; where the
staging configuration is weaker, the residual risk says so, and the
verifier can refuse staged evidence outright.

The operator TCB is the operator host, clang/LLVM, libbpf and the
signing key.  An upatch does what its author wrote; shirudo guarantees
provenance, not correctness.

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
    named as ``attr.keyring_id`` (or, while the certificate is staged,
    the sealed ``shirudo`` keyring's serial), before the verifier runs,
    and ``lsm/bpf_prog_load`` then requires the verdict
    ``BPF_SIG_VERIFIED`` from exactly that keyring kind and, while
    staging, that serial (the kernel records none for its own bpf
    keyring).  Userspace ``BPF_MAP_CREATE`` is restricted to the
    executable ``init`` recorded as shirudo; signed loader map creation
    runs in kernel context.  The payload is hash-locked to the loader by
    ``excl_prog_hash``.  Root without the key gets ``-EACCES`` or
    ``-ENOKEY``; a certificate planted in any other keyring is ignored,
    and a foreign-signed artifact fails with ``ENOKEY``.

T2  Detaching or replacing enforcement
    ``lsm/bpf`` denies ``LINK_DETACH``, ``LINK_UPDATE``,
    ``PROG_ATTACH``, ``PROG_DETACH`` and ``BTF_LOAD`` from userspace.
    The links are kept alive by pins in a private bpffs;
    ``inode_unlink`` on that filesystem allows only shirudo's own
    executable, and ``sb_umount``, ``move_mount``, ``sb_mount`` and
    ``sb_remount`` deny everyone, so neither ``rm`` nor ``umount`` nor
    mounting over the directory removes a pin. Infrastructure maps are
    frozen at creation, so even with the LSM gone userspace could not
    rewrite the identity map. ``lsm/bpf_map`` denies writable map fds
    to every process except shirudo; map updates and freezes have the
    same executable gate. Userspace ``BPF_PROG_TEST_RUN`` is restricted
    to shirudo's recorded executable; kernel-context loader calls remain
    allowed. Root therefore cannot invoke a signed
    serializer to drain or clear map state. Root may inspect pinned maps
    but cannot alter serializer arrays or writable-mmap arena state
    through the syscall interface. From the initrd, the identity records
    the root's binary as the executable that lasts and the initrd's
    own copy beside it for that one run; the copy is gone with the
    initrd, and its inode is on a file system nothing can reach after
    the switch.

T3  Tampering with shirudo's files and process
    Every inode under ``/var/lib/shirudo`` carries the
    ``security.bpf.shirudo`` label; the seal program allows write open,
    unlink, rename and xattr changes only to the process that runs the
    executable ``init`` recorded, by device and inode and never by path,
    and only that process may set the label. The label marks what is
    protected and is public; it is not what identifies the caller, as a
    file system root mounts can present it on any binary.
    Marked shirudo tasks cannot be ptraced or perf-sampled, and the
    process drops dumpability, forbids new privileges and locks
    sensitive buffers. The bpf keyring is sealed with
    ``KEYCTL_RESTRICT_KEYRING`` so no key can be linked into it for the
    rest of the boot, ``lsm/key_permission`` leaves writing, unlinking,
    revoking, invalidating and re-permissioning it and the keys it
    holds to shirudo's own executable, and the kernel then refuses
    every caller-supplied
    keyring for signature verification; a staged ``shirudo`` keyring is
    sealed with ``KEYCTL_SETPERM``.  The kind and serial of the keyring
    ``init`` sealed are frozen into the identity map, pinned in the
    bpffs and read back by every later command, so a swapped same-name
    keyring makes every load refuse ``tampered``.

T4  Substituting artifacts
    The signature covers the loader instructions and data, so the kernel
    refuses a modified loader.  An unload directive is itself a signed
    loader and goes through the same ``BPF_PROG_LOAD``.  Before
    detaching, shirudo compares the live pin's payload xattr, which only
    shirudo can write, against the directive's expected payload, and
    refuses ``payload_mismatch`` on disagreement or when the xattr is
    unreadable.

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
    the eventlog does not know.  A load whose extension fails
    reports ``tpm_error`` rather than succeeding unmeasured; an eventlog
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


5) Residual risks
-----------------

Each of these is known, documented and bounded; none is silent.

1.  The unload directive's target name and expected payload live in
    unsigned metadata.  The kernel's ``bpf_sys_bpf()`` cannot detach or
    unlink, so the detach runs in userspace, and root can repoint a
    signed directive at another upatch loaded under the same key, or
    edit the expected payload to match it.  ``payload_mismatch`` catches
    honest substitution; closing this fully needs an in-kernel detach so
    the compare runs against signed ``.rodata``.

2.  ``CAP_SYS_RESOURCE`` can rewrite ``mm->exe_file``.  Shirudo's
    ``task_prctl`` LSM hook denies ``PR_SET_MM_EXE_FILE`` and
    ``PR_SET_MM_MAP`` to every caller outside the frozen Shirudo
    executable identity, preventing a root process from impersonating
    Shirudo through these operations.  This also denies those two
    operations to checkpoint and restore tools.  A process that directly
    executes the recorded Shirudo binary is still identified as Shirudo,
    so its command interface remains the authorization boundary.  Bound
    ``CAP_SYS_RESOURCE`` out of untrusted contexts with
    ``CapabilityBoundingSet=`` and container capability profiles.

3.  A lazy (``MNT_DETACH``) unmount of an ancestor of
    ``/run/shirudo/bpffs`` tears the subtree down without firing
    ``sb_umount`` on the child.  The ancestor is ``/run`` or the root
    filesystem, a far higher bar than the direct unmount the guards
    close.  Mounting over ``/run/shirudo`` hides the pins without
    detaching anything: enforcement stays, and every state-changing
    command refuses ``lsm_detached`` until the mount is gone.

4.  Register denial of service.  A process that can open
    ``/dev/tpmrm0`` can extend PCR 9 or the written register with
    garbage, and with the owner auth (empty on most TPMs) undefine the
    index.  None of it is hidden: a garbage event fails the replay, a
    recreated index cannot be written and fails the name check, and
    ``status``, every state-changing command and ``attest verify``
    report ``tampered``, and ``init`` binds no other register before
    the next TPM reset; the attacker still cannot load BPF.  It costs
    the operator a reboot and an investigation.

5.  The binary on disk.  shirudo cannot defend its own executable
    against substitution or patching before it runs; that belongs to
    the distribution layer (signed packages, IMA appraisal, fs-verity,
    measured boot).  ``SHIRUDO_VERSION_ID`` is a skew guard, not an
    integrity check: a malicious binary can lie about it.

6.  While the certificate is staged in the user keyring, a keyring
    swap degrades to denial of service.  Root can unlink the sealed
    ``shirudo`` keyring and create a fake one with the same name; the
    serial frozen in the identity map turns that into a fail-closed
    refusal, for the rest of the boot, instead of a
    bypass.  The bpf keyring, the production anchor, can be neither
    unlinked nor substituted, and the kernel refuses every other
    keyring once it is sealed.

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

13. Revocation reaches a target only when run there.  ``shirudo keys
    revoke`` unlinks the key from the running kernel and keeps it out
    of every later boot, but a target the operator cannot reach keeps
    verifying against the revoked key until it is reached; shirudo has
    no push channel by design.  Evidence tells the two apart: a
    revoked node's register carries the ``key_revoke`` event, and
    ``attest predict --event=revoke:...`` names the value to expect.
    The set itself is guarded: the ``key_permission`` hook denies root
    the unlink, clear, revoke and invalidate that would otherwise empty
    the sealed keyring, so what used to be a denial of service with
    one keyctl is now shirudo's revocation primitive and nothing else.

Deferred mitigations
~~~~~~~~~~~~~~~~~~~~

In scope and not yet built: registering the register as a systemd
NvPCR, so that its name follows the UKI signing key instead of the PCR
values of each boot and systemd-aware verifiers find it in PCR 9 before
the separator, and measuring the anchor through ``systemd-pcrextend`` so
systemd's measurement log explains it (residual risk 11); signed PCR
policies for the kernel and initrd PCRs so a verifier needs no golden
values; and an in-kernel detach so the unload compare runs against
signed ``.rodata`` (residual risk 1).


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
``bpf.keyring_unsealed=1`` and run ``init`` from the initrd; a target
whose ``status`` says ``staging`` has its trust anchor in a user
keyring and its register bound after the initrd, and a fleet check
that passes ``--require-initrd`` and ``--expect-bind-pcr=11`` with the
UKI's ``enter-initrd`` value does not accept it.  Give ``challenge``
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
