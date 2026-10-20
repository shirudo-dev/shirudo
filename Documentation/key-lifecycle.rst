..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Key lifecycle
=============

shirudo's trust rests on the operator's ML-DSA-87 signing keys and
their self-signed certificates.  This guide covers them from creation
to retirement: what they sign, where the certificates go, how targets
come to trust one and then another, how to rotate a key without a gap
in protection, and what to do when one is compromised.  The
`threat-model <threat-model.rst>`__ says why the mechanisms are shaped
the way they are; this document says what to do.

The procedures below describe the ordinary installation. Image mode uses
signed config images for boot-time key enrollment and live revocation; its differences
are in section 8 and `config-images <config-images.rst>`__.

1) The keys in the system
-------------------------

The operator signing key
    ML-DSA-87 (FIPS 204), the only algorithm shirudo signs with.
    ``shirudo genkey`` writes ``signing_key.pem`` (mode 0600) and
    ``cert.der`` into ``/var/lib/shirudo/keys`` or ``--keys-dir``, and
    refuses to overwrite an existing pair without ``--force``.  The key
    signs every upatch, every unload directive, every package index,
    every tree publication and every vouch for another certificate.
    It lives on the operator and never on a target.  An organisation
    may have several, one per team or per era; a target can trust them
    all at once.

The certificate
    A self-signed X.509 v3 certificate over the signing key, valid for
    ten years from creation.  Certificates are all a target holds, and
    everything a target trusts chains to them: the kernel verifies
    every signed loader against the set ``init`` enrolled in the bpf
    keyring, and ``shirudo bpm`` verifies package indexes and tree
    publications against the certificate a repository was registered
    with.  The digest of the enrolled set enters every boot's ``init``
    event, so an operator who predicts a register value with ``shirudo
    attest predict`` predicts it for exactly those certificates.  A
    certificate is named by its fingerprint, the SHA-256 of its public
    key, which ``shirudo bpm key fingerprint`` and ``shirudo keys``
    print.

The attestation and endorsement keys
    These belong to the target's TPM, not to the operator: the
    attestation key is a fixed-template P-256 primary the operator pins
    by name at enrolment, and the endorsement key is the TPM's own,
    vouched for by the manufacturer's certificate.  Their lifecycle is
    the TPM's; the `tpm <tpm.rst>`__ document covers both.

Transport certificates
    The WebPKI certificates of registries and collectors authenticate
    the transport and nothing else; the artifacts carry their own
    signatures.  They are the infrastructure's to manage.

``shirudo keys`` shows what a host holds: the certificate and, on an
operator, the key on disk; on a target the trusted set with each
member's voucher, and the kernel keyring that holds it once ``init``
has run.  Two roles may share a host for development; production
operators and targets do not.

2) The trusted set on a target
------------------------------

A target trusts a set of certificates, kept under
``/var/lib/shirudo/keys``:

``cert.der``
    The primary.  The installer's ``--cert`` puts it there; so does
    ``shirudo bpm key add <cert.der>``, which stores certificates
    under ``keys/<fingerprint>.der`` and points ``cert.der`` at the
    first one it installs.  ``bpm key add`` refuses to point
    ``cert.der`` at a different certificate while one is active, and
    ``bpm key list`` shows what it installed.  The primary needs no
    vouch: it is the root the rest of the set chains to, and it gets
    onto a target by the organisation's provisioning path, not through
    shirudo.

``trusted/<fingerprint>.der`` and ``trusted/<fingerprint>.vouch``
    The further members, each beside the vouch that admits it.  A
    vouch is a detached CMS signature by a key already in the set over
    the certificate's DER (and a fixed prefix); the loader admits a
    certificate only with a vouch that verifies under the primary or
    under a member admitted before it, in rounds, so a chain of
    vouches works.  A file under ``trusted/`` without a valid vouch is
    not a member, whoever put it there: ``shirudo status`` counts it
    as unvouched and ``init`` leaves it out.  ``shirudo keys add
    <cert.der> --vouch <file>`` is the only way shirudo itself writes
    here.

``revoked/<fingerprint>.der``
    The certificates ``shirudo keys revoke`` has withdrawn.  A key
    named here is never enrolled again and ``keys add`` refuses it
    however well vouched.

The set is the same on every reader: ``init`` enrols it, ``status``
and ``keys`` report it, the pre-flight checks every member's
algorithm, and the digest the ``init`` event carries is the one
certificate's digest for a set of one and the SHA-256 over the sorted
digests for a larger set, which is what ``shirudo attest predict
--cert=... --cert=...`` computes from the same files in any order.

``/etc/shirudo/keys`` in the initrd
    The production configuration enrols the initrd's copies.  dracut's
    shirudo module copies ``cert.der`` and ``trusted/`` with the
    vouches into the initrd when it is built, so the enrolment is done
    by measured code with a measured set: a verifier that pins PCR 11
    to the UKI knows exactly which certificates the keyring holds.
    The revoked directory stays on the root, where ``init`` reads it
    through its bind.  The copies are taken at build time, so **a
    changed set needs the initrd rebuilt** (``shirudo-gen-initrd``);
    until then ``init`` enrols the old set and warns that the root's
    differs.  The `initrd <initrd.rst>`__ document describes that run.

Repositories registered with ``shirudo bpm config register add <name>
<endpoint> --key-file <cert.der>`` keep their own reference to the
certificate that must sign the repository's index, under
``/etc/shirudo/bpm``; a tree publication is verified the same way.
Registering a repository with a certificate the keyring does not hold
is possible and pointless: its packages would verify in userspace and
fail at the kernel.

The kernel does not check a certificate's validity period when it
verifies a signature, and shirudo adds no date check of its own.  The
ten years are a statement of intent and the trigger for rotation, not
a cut-off a target enforces.

3) What the design fixes
------------------------

Three facts shape every operation below:

* **The keyring takes keys at boot only.**  ``init`` enrols the set
  and seals the keyring; nothing can be added for the rest of the
  boot.  A certificate added with ``keys add`` is on disk at once and
  in the kernel after the next boot with a rebuilt initrd.  Removal is
  the exception: ``keys revoke`` unlinks a key from the sealed keyring
  there and then, which the ``key_permission`` hook in the enforcement
  programs lets shirudo alone do.
* **Boot-restore is all or nothing.**  On every boot ``init`` reloads
  the archived upatches under ``/var/lib/shirudo/upatches``.  An
  archive signed by a key the set no longer covers fails verification,
  the restore stops, and the target comes up with the LSM active but
  nothing loaded and no register bound (``degraded``) until the
  archive is cleaned up.  Revocation purges what the revoked key
  signed for that reason; a key that merely disappears from the set
  does not.
* **The archive is sealed.**  Only shirudo removes an archived upatch:
  through a signed unload directive the keyring accepts, or through
  ``keys revoke`` for everything the revoked key signed.  An archive
  signed by a key that left the set any other way can only be left
  behind by a reinstall of the state directory.

Together these make adding a key cheap and removing one deliberate,
and they make the order of a rotation matter.

4) Adding a key
---------------

A new key joins the fleet vouched for by one it already trusts.

On the operator holding the trusted key::

    shirudo keys vouch new-cert.der --keys-dir /var/lib/shirudo/keys

writes ``new-cert.der.vouch`` beside the certificate (``-o`` names
another file) and prints the new certificate's fingerprint.  A key
cannot vouch for its own certificate.  Distribute the certificate and
the vouch together; neither is secret.

On each target::

    sudo shirudo keys add new-cert.der --vouch new-cert.der.vouch
    sudo shirudo-gen-initrd

``keys add`` verifies the vouch under the members of the set, requires
the vouching certificate to be in the bpf keyring this boot, refuses a
revoked key, and writes the vouch and then the certificate under
``trusted/``.  It prints the fingerprint and is idempotent.  The kernel
learns of the new key at the next boot; ``shirudo status`` shows the
set on disk as ``certs`` and the keyring's count as ``certs_enrolled``
so the two can be told apart meanwhile.  Reboot the waves at the
fleet's own pace; the old keys keep working throughout.

Record the new set's ``init_event`` from ``shirudo attest predict
--cert=old.der --cert=new.der`` for the verifiers: a target that has
rebooted with the new set measures that value, one that has not still
measures the old.

5) Rotating a key
-----------------

With a second key enrolled, rotation is a sequence of ordinary steps
with no window in which the fleet is unprotected or unenforced.

1. Add the new key to every target (section 4) and let the fleet
   reboot into the enlarged set.  Nothing changes for the packages:
   the old key still signs them.
2. On the operator, rebuild the packages the fleet carries with the
   new key, as new versions (published versions are immutable), and
   publish them::

       shirudo bpm build ./example-shields --version 1.1.0 \
           --keys-dir /var/lib/shirudo/keys.next
       shirudo bpm push ./example-shields-1.1.0.bee oci://.../example-shields \
           --keys-dir /var/lib/shirudo/keys.next

   The registry's index is signed by whichever key ``push`` is given.
   Re-register the repositories on the targets with the new
   certificate first (``bpm config register remove`` and ``add
   --key-file``), or publish the new versions into a second repository
   and switch the targets over, so that no target is left with an
   index it cannot verify.
3. For a fleet that follows a tree, start a new tree (``--tree-id``)
   or a new reference published with the new key and point the targets
   at it; a tree cannot change keys mid-sequence, because a target
   verifies every publication against the certificate it registered
   and accepts a ``delete`` only for an id it loaded from the same
   tree.
4. Upgrade the packages on the targets, or let ``bpm tree sync`` pull
   the new tree.  Each upgrade unloads the old key's artifacts under
   the old key's own directives and loads the new key's; both keys are
   in the keyring, so every step verifies.
5. When ``shirudo upatch list`` on every target shows nothing signed by
   the old key, withdraw it: ``shirudo keys revoke <old fingerprint>``
   on each target (section 6), or, when the old key is the primary,
   ``--promote <new fingerprint>`` makes the new one ``cert.der``.
   Rebuild the initrd and reboot at the next opportunity so the next
   boot enrols the smaller set and its ``init`` event matches the
   verifiers' new expectation.

When the old pair is no longer needed anywhere, shred the private key
and keep the certificate: old evidence and old eventlogs name its
digest, and verifying them later needs it.

6) Revocation
-------------

A upatch
    Withdrawing a shield is a signed unload: ``bpm tree append --op
    delete`` for a fleet following a tree, ``bpm uninstall`` for a
    package installed by name, or ``upatch unload`` with the
    directive.  Every unload is measured, so an operator can tell from
    the evidence which nodes have acted.

A key
    ``shirudo keys revoke <fingerprint>`` on the target, from this
    moment and for good.  In order it: writes the certificate to
    ``keys/revoked/`` so no later boot enrols it; unlinks the key from
    the bpf keyring, so the kernel accepts nothing signed by it from
    that point; measures the revocation into the register as a
    ``key_revoke`` event; unloads, unpins and unarchives every archived
    upatch whose signer is that certificate, each loaded one measured
    as an ``upatch_unload`` with ``reason: key_revoke``; and removes
    the certificate and its vouch from ``trusted/``.  Loads signed by
    the other keys keep working throughout.  Rebuild the initrd
    afterwards; until the reboot the initrd's copy of the set still
    carries the key, and ``init`` leaves it out because the root's
    revoked directory names it.

    Two constraints.  Revocation needs the set enrolled in the bpf
    keyring; a target in the staging configuration holds the primary
    alone and rotates instead.  And the primary leaves only with an
    heir: ``--promote <fingerprint>`` makes another member
    ``cert.der``.  Members the revoked key vouched for stay enrolled
    for the rest of the boot, since that trust was established when
    the boot enrolled them, but they are unvouched from then on and
    need a new vouch under a remaining member (``keys add`` again)
    before the next boot, or they leave the set with it.  The last
    certificate goes only with ``--force``, which leaves the target
    verifying nothing until a reboot with a new one.

    ``bpm`` keeps its own record of installed packages; a package
    whose upatches a revocation purged still appears in ``bpm list``
    until ``bpm uninstall`` or the next ``bpm upgrade`` reconciles it.

    Revocation is per target and reaches a target only when run there.
    Deliver it through the organisation's configuration management,
    the same way the installer and the certificate got there; shirudo
    has no push channel.  ``shirudo attest verify
    --allow-runtime-events`` accepts the ``key_revoke`` record, and
    ``shirudo attest predict --event=revoke:<fingerprint>=<cert
    sha256>`` predicts the register it leaves, so the fleet's evidence
    says which nodes have revoked.

A compromised key
    The adversary holding the key is the operator, as far as a target
    can tell: whatever they sign loads and measures as authorised,
    until the key is revoked.  Detection is by content, not by
    signature: ``shirudo attest verify`` against ``shirudo attest
    predict`` fails for any node whose register certifies a set the
    operator did not publish, and the eventlog names each load.
    Response is the revocation above on every target, as fast as the
    fleet can be reached, then a review of every artifact the key
    signed and of the registry's index and tree publications for
    entries the operator did not make, and of the vouches the key made
    for other certificates.  Where the compromised key is the only
    one enrolled, the response is the rotation of section 5 compressed
    into the time the fleet allows: add a new key, reboot, re-sign,
    revoke.  A target whose binary or state is in doubt is reinstalled,
    not repaired; the `operations <operations.rst>`__ guide covers
    both.

7) Custody
----------

* The signing key belongs on a host with the controls of a certificate
  authority: offline or isolated, with access limited to the people
  who publish.  The operator role needs no network beyond the registry
  it pushes to.
* The key is a PEM file protected by file permissions; shirudo does
  not use PKCS#11 or an HSM.  Keep the directory on an encrypted
  volume and back it up encrypted, with the certificate beside it.
* Keep separate pairs for development, staging and production fleets
  with ``--keys-dir``, and never enrol a development certificate on a
  production target.  The test suites generate throwaway pairs of
  their own.
* A vouch extends the trust of every target that holds the vouching
  key.  Treat ``keys vouch`` like a signing operation: run it on the
  operator host, for a certificate whose holder you have verified out
  of band, and keep the vouch with the certificate it is for; it is
  useless for any other.
* Record each certificate's fingerprint and the ``init_event`` of the
  sets the fleet runs (``status --json`` on a target, ``attest
  predict`` on the operator), and check them wherever a certificate is
  copied: into the initrd, into a registry registration, into an
  inventory.
* Treat a key that left the operator host, even once, as compromised.

8) Keys in image mode
---------------------

The initial BPF certificate is inside the authenticated runtime image.
Additional certificates and their existing vouch signatures are in the
config image's ``keys/trusted/``; revocation records are in
``keys/revoked/``. A config signature approves that filesystem but does not
replace the BPF trust chain: a new BPF key still needs a valid vouch.

Image mode enrolls the authorized BPF trust set at boot, then installs the
existing reject-all keyring restriction. That restriction cannot be replaced
or bypassed by trusted image callers. There is no live key enrollment and
no new keyring restriction or key-lifetime kernel hooks are required.

To enroll a key, create its vouch on the operator and include the certificate
and vouch in the signed config selected for the next boot. Reboot is required
before the live keyring can use the new signer. Live update refuses a
candidate requiring a signer absent from the keyring before measuring it;
it does not accept that candidate as pending enrollment. To revoke a key,
include its certificate under ``keys/revoked/<fingerprint>.der`` in a new
signed config. Activation unlinks it and purges affected upatches. The config
PCR records the selected trust settings and the NV register records each
purged upatch's unload. Image-mode ``keys add``, ``bpm key add`` and
``keys revoke`` are refused; there is no target-local override. Removing
a certificate file alone is not a revocation.

The current CLI does not stage a new signer for the next boot. The saved
activation record selects its cached bundle ahead of the initial
``config.image`` default, so changing that default and rebooting is
insufficient on an already initialized target. A complete operational
rollout for changing that boot selection is not provided by this CLI;
provisioning must account for the existing selection without discarding its
journal. Do not use the refused live-update path as a staging operation.

The config PCR records the selected trust settings; the boot enrolls keys.
Merely omitting a certificate from a newer image does not revoke a key already
enrolled during this boot; use an explicit revocation record. Vouch
verification retains the historical chain to the initial runtime
certificate. Revoking a key for BPF signature verification does not erase
its earlier authorization of a successor or remove the immutable vouch
anchor.

The config verification certificate is a separate bootstrap trust choice.
It lives in authenticated runtime ``shirudo.conf`` as a reference to a
certificate inside that image. Replacing it requires a new runtime image,
an updated authenticated boot hash and reboot. Provide a config that the
new certificate verifies before rebooting. A config update cannot rotate
its own verification key.

Image mode accepts older correctly signed config images. Revocation
freshness therefore depends on selecting the intended config; neither its
signature nor its PCR measurement prevents rollback. This is a deferred
policy, not permanent local revocation storage.
