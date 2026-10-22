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

2) Enrollment, revocation and rotation
--------------------------------------

The initial BPF certificate is inside the authenticated runtime image.
Additional certificates and their existing vouch signatures are in the
config image's ``keys/trusted/``; revocation records are in
``keys/revoked/``. A config signature approves that filesystem but does not
replace the BPF trust chain: a new BPF key still needs a valid vouch.

Shirudo enrolls the authorized BPF trust set at boot, then installs the
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
purged upatch's unload. Target ``keys add``, ``bpm key add`` and
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

Shirudo accepts older correctly signed config images. Revocation
freshness therefore depends on selecting the intended config; neither its
signature nor its PCR measurement prevents rollback. This is a deferred
policy, not permanent local revocation storage.

3) Preparing a new signer
-------------------------

Generate the new key on its operator and have an already trusted operator
vouch for its public certificate::

    shirudo genkey --keys-dir new-operator-keys
    shirudo keys vouch new-operator-keys/cert.der \
        --keys-dir current-operator-keys -o new-cert.vouch
    shirudo bpm key fingerprint new-operator-keys/cert.der

Put the certificate and vouch at ``keys/trusted/<fingerprint>.der`` and
``keys/trusted/<fingerprint>.vouch`` in the config source. Build and sign the
image, then provision it as part of the authenticated boot rollout. A running
target refuses live config requiring an unenrolled signer. It must reboot
with the intended boot selection before accepting BPF from that key.

Keep both keys while rolling out newly signed upatches and repository
certificates. Once the new key is enrolled and its upatches replace the old
ones, deliver a config with the old certificate at
``keys/revoked/<fingerprint>.der``. Activation removes the old live key and
purges upatches it signed. Preserve earlier vouches needed to validate the
chain. Check the expected config root and predicted upatch register in
attestation, not just the target's local status.

4) Custody
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
