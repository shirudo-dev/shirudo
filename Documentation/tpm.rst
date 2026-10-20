..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

The TPM: measurement register and attestation
=============================================

shirudo uses the target's TPM 2.0 for two things.  A per-boot
measurement register records every change to the BPF state in a form
nobody on the target can rewrite, and on request the TPM signs that
register together with the platform PCRs so an operator can check a
target without believing anything the target says about itself.  This
document describes both as implemented, how they relate to systemd's
NvPCRs, which the register is modelled on, and what they do not yet
do.  The code is authoritative: ``util/chain.c`` (register and event
digests), ``util/tpm.c`` (libtss2 calls), ``util/tpm_wire.c`` (policy
digests, names and the TPM wire structures, used by both sides),
``util/eventlog.c``, ``util/attest.c`` and ``builtin-attest.c``.
`threat-model <threat-model.rst>`__ states what the design defends
against; `architecture <architecture.rst>`__ places it in the whole.

A TPM 2.0 is mandatory on a target.  There is no unmeasured mode: a
target that cannot bind its register does not initialise, and a load
whose extension fails refuses with ``tpm_error`` rather than succeed
unmeasured.  The operator side never touches a TPM.

1) The register
---------------

The register is an NV index, ``0x01818E00`` by default
(``SHIRUDO_NV_INDEX``), holding one SHA-256 digest.  Its attributes
are ``0x0E060048``:

``TPM2_NT_EXTEND``
    The index is extended, never overwritten: a write of ``d`` sets
    it to ``SHA256(old || d)``, the same operation a PCR performs.

``TPMA_NV_CLEAR_STCLEAR``
    The contents and the ``TPMA_NV_WRITTEN`` attribute clear at every
    TPM reset, so the register starts from 32 zero bytes at every
    boot, like a PCR, and holds this boot's history only.

``TPMA_NV_POLICYWRITE``
    The only way to write is a policy session that satisfies the
    index's write policy below; there is no password.

``TPMA_NV_OWNERREAD`` and ``TPMA_NV_AUTHREAD``
    Reads need no authorisation.

``TPMA_NV_NO_DA`` and ``TPMA_NV_ORDERLY``
    Failed authorisations do not count towards dictionary-attack
    lockout, and the index is written back to NV memory only at an
    orderly shutdown, which spares that memory for an index that
    changes with every event and is cleared at reset anyway.

Write policy
~~~~~~~~~~~~

The write policy is ``PolicyOR(written, init)`` with two branches:

* ``written`` is ``PolicyNvWritten(YES)``: once the index has been
  written this boot, anyone with access to the TPM may extend it,
  exactly as anyone may extend a PCR.  Appending history is not the
  threat; rewriting it is.

* ``init`` is ``PolicyNvWritten(NO)`` followed by ``PolicyPCR`` over
  PCRs 9 and 11 at the values they hold when ``init`` binds the
  register.  It admits the first write of a boot, and only while both
  still hold those values.  PCR 9 carries the initrd measurements and
  takes the anchor; PCR 11 carries systemd's boot phase and moves at
  ``leave-initrd``, so a register bound from the initrd can be bound by
  nothing that runs after it.

The index's TPM name is the SHA-256 of its public area (handle, name
algorithm, attributes, policy digest, size), prefixed with the
algorithm identifier ``000b``.  Because ``TPMA_NV_WRITTEN`` is part of
the attributes, the index has one name before its first write and
another after it; the written name is the one ``init`` records, the
anchor carries and every later comparison uses.

Binding at boot
~~~~~~~~~~~~~~~

``shirudo init`` is meant to run from the initrd, after
``systemd-pcrphase-initrd.service`` has measured ``enter-initrd`` into
PCR 11 and before the switch to the root file system, which is how
``shirudo-initrd.service`` orders itself (the ``initrd`` document);
it binds the register after it has re-applied the installed set, in
this order:

1. Read PCRs 9 and 11; the values are ``pcr_before`` and
   ``phase_before``.  Compute both policy branches, the policy digest
   and the two names from them.

2. If the index exists from an earlier boot, is unwritten and carries
   the expected unwritten name, keep it.  Otherwise define it under
   the computed policy, undefining a stale index first.  Defining and
   undefining need the owner hierarchy; when the TPM has an owner
   password, ``tpm.owner_auth`` in ``/etc/shirudo/shirudo.conf``
   supplies it.  The name the TPM reports is compared with the one
   computed in software; a mismatch is ``EPROTO``, not a retry.

3. Extend the index with the init event through the ``init`` branch.
   The session walks the branch on the TPM and its digest is read back
   with ``PolicyGetDigest`` and compared with the software policy, so
   a drift between ``util/tpm_wire.c`` and the TPM fails with a clear
   message instead of ``TPM2_RC_POLICY_FAIL``.

4. Anchor: extend PCR 9 with ``SHA256(anchor)`` where the anchor is
   the string ``nvpcr-init:shirudo:0x1818e00:<written name hex>``,
   systemd's ``nvpcr-init`` event format.  From this moment the
   ``init`` branch cannot be satisfied again until the next TPM
   reset, because PCR 9 no longer holds ``pcr_before``; once systemd
   measures ``leave-initrd``, PCR 11 does not hold ``phase_before``
   either.

5. Append the ``init`` record to the eventlog (section 3) with both
   PCR values, whether the initrd was running, the written name, the
   anchor and its digest, the register value and the TPM's reset
   count.

The phase measurements are ``systemd-pcrphase-initrd.service``'s,
which systemd runs only for a measured UKI boot; without them PCR 11
never moves, the binding is only as strong as the anchor in PCR 9 and
``init`` says so.  Run from the root file system instead, ``init``
binds all the same,
with the post-initrd PCR 11 value and ``bound_in: root`` on the
record, and warns; a verifier that pins the ``enter-initrd`` value or
requires the initrd binding rejects such evidence, which is what tells
a late binding, by ``init`` or by anyone else, from the real one.

The reset count, read with ``TPM2_ReadClock``, changes at every TPM
reset and nowhere else, so a record of this boot for the current count
means this register period already has its binding.  A re-run of
``init`` then finds the index written with the recorded name, reuses
it and adds no event; finds it gone, unwritten or renamed, it refuses
with ``tampered`` and binds nothing before the next TPM reset, because
a second binding would restart the history the record vouches for.
Without a record for the current count, whether the boot is new or
the TPM was reset without a reboot, the index is bound; one found
written by someone else first is undefined and bound again, with a
warning, and PCR 9 then carries both anchors.

Extending later
~~~~~~~~~~~~~~~

Every load, unload and tree operation extends the register through
the ``written`` branch, with the policy recomputed from the
``pcr_before`` on this boot's init record, and only after checking
that the live index carries the recorded name.  No register this boot
is ``tpm_error``; a live index whose name is not the recorded one is
``tampered``.  Every state-changing command also reads the register
first and refuses ``tampered`` when ``--expect-chain`` disagrees, which
serialises concurrent operators.

Consequences: an index undefined and recreated at runtime under the
same policy cannot be written, because PCRs 9 and 11 have moved; one
recreated
under another policy has a name the record does not know; and the
register value at any time is a pure function of the certificate, the
installed set, the tree root and the events since boot, so the
operator computes it with ``shirudo attest predict`` and never needs
history.

TPM access
~~~~~~~~~~

The TCTI is ``SHIRUDO_TPM_TCTI`` in the environment, else ``tpm.tcti``
in ``shirudo.conf``, else ``device:/dev/tpmrm0``, the kernel resource
manager.  Redirecting it on a target changes nothing for the operator:
the evidence is signed by the key the operator pinned, and a
substitute TPM fails verification.  libtss2's own logging is silenced
unless ``TSS2_LOG`` is set.

2) Events
---------

Every extension is a 32-byte digest with a domain-separating tag.
``\0`` marks the NUL that terminates the tag inside the hashed bytes.

init
    ``SHA256("shirudo-init\0" || cert_sha256 || set_digest ||
    tree_root)``.  ``cert_sha256`` covers the certificates ``init``
    enrolled: the digest of the one certificate's DER when the set has
    one member, else the SHA-256 over the members' DER digests sorted,
    which ``shirudo attest predict --cert=... --cert=...`` computes
    from the same files in any order.  ``set_digest`` is the SHA-256 of
    the listing of the re-applied set, one line ``<payload_sha256 hex>
    <name>\n`` per
    upatch, sorted by name.  ``tree_root`` is the upatch tree's
    projection root at boot, or 32 zero bytes without a tree.

upatch load
    ``SHA256("shirudo-upatch\0" || payload_sha256 || name)``.

upatch unload
    ``SHA256("shirudo-unload\0" || payload_sha256 || name)``.

tree operation
    ``SHA256("shirudo-tree\0" || seq || operation_digest)`` with
    ``seq`` as eight big-endian bytes and ``operation_digest`` the
    publication's digest of the operation.

key revocation
    ``SHA256("shirudo-key-revoke\0" || cert_sha256)`` with the revoked
    certificate's DER digest.  ``shirudo keys revoke`` extends it right
    after unlinking the key and before purging what the key signed,
    each loaded upatch of which then follows as its own unload event.

The register after an event is ``SHA256(register || event)``, starting
from zeros; ``chain_fold()`` and the eventlog replay use the
same fold.  Boot restore is exactly one init event however many
upatches it re-applies.

3) The eventlog
---------------

``/var/lib/shirudo/eventlog`` (``SHIRUDO_EVENTLOG_PATH`` overrides it
for the host-side tests) is append-only JSON lines, one per
extension, written with ``fsync`` and sealed like everything under
``/var/lib/shirudo``.  Every record carries ``schema`` (2), ``ts``,
``nv_index``, ``alg``, ``digest`` (the event), ``type`` and
``boot_id``.  By type:

``init``
    ``tpm_reset_count``, ``cert_sha256``, ``certs`` (the enrolled
    certificates' DER digests), ``set_digest``,
    ``tree_root``, ``set`` (the listing as ``name`` and
    ``payload_sha256`` pairs), ``pcr`` (9), ``pcr_before``,
    ``phase_pcr`` (11), ``phase_before``, ``bound_in`` (``initrd`` or
    ``root``), ``nv_name`` (the written name), ``anchor``,
    ``anchor_digest`` and ``chain`` (the register after the event).

``upatch_load`` and ``upatch_unload``
    ``upatch`` with ``name`` and ``payload_sha256``; an unload a
    revocation caused carries ``reason`` (``key_revoke``).

``tree_op``
    ``tree`` with ``seq``, ``op``, ``id`` and ``operation_digest``,
    and ``chain``.

``key_revoke``
    ``key`` with ``fingerprint`` (of the public key) and
    ``cert_sha256`` (of the DER, the value the event hashes).

"This boot" is every line with the running ``boot_id`` from its last
``init`` record on.  Replaying those lines from zeros must reproduce
the live register; ``shirudo status`` does that replay, checks that
the live index carries the recorded name and that the record is of
the TPM's current reset count, and reports ``register_bound``,
``register_anchored``, ``init_records``, ``register_rebound``,
``nv_name``, ``pcr``, ``pcr_before``, ``phase_pcr``, ``phase_before``,
``bound_in``, ``chain`` and ``chain_matches_eventlog``.  A register that exists without a record
of this boot, that the records do not explain, or that a second init
record for one reset count shows was bound again, is reported as a
mismatch.  An operation that would push the eventlog past
``eventlog.max_bytes`` refuses with ``eventlog_full`` before it
touches the TPM, so register and log never diverge.

4) Attestation
--------------

``shirudo attest`` makes the TPM speak.  It needs no enrolment state
on the target and leaves none behind.

The attestation key
~~~~~~~~~~~~~~~~~~~

The key is a primary object under the endorsement hierarchy created
from a fixed template: ECC NIST P-256, ECDSA with SHA-256, attributes
``fixedTPM``, ``fixedParent``, ``sensitiveDataOrigin``,
``userWithAuth``, ``restricted`` and ``sign``, no authorisation value
and no policy.  A primary with a fixed template is derived from the
TPM's endorsement seed, so the same TPM always yields the same key;
it is created for each run and flushed afterwards.  ``restricted``
means the TPM signs only structures it generated itself, so the key
cannot be used to sign arbitrary data.  Its name is the SHA-256 of its
marshalled public area, which ``attest`` recomputes and compares with
the name the TPM reports.  In the signed structures the signer appears
as the qualified name, ``SHA256(0x4000000B || name)``, the endorsement
hierarchy's handle followed by the key name.

The evidence
~~~~~~~~~~~~

``shirudo attest --nonce=<hex> [--pcrs=<list>] [--out=<path>]`` emits
one JSON document, ``kind`` ``shirudo-attestation``, ``schema`` 1:

``nonce``, ``pcr_bank``, ``pcr_mask``, ``pcrs``
    The nonce the verifier chose (up to 64 bytes), the SHA-256 bank,
    and the values of the selected PCRs, by default 0-7, 9 and 11-15.

``ak``
    ``public`` (the marshalled ``TPMT_PUBLIC``) and ``name``.

``ek``
    ``type`` (``ecc`` or ``rsa``), ``public`` and ``name`` of the
    endorsement key, created from the TCG default template of the type
    the endorsement certificate describes, the ECC one on a TPM that
    holds no certificate.  Section "Binding the key to the TPM" below
    says what it is for.

``quote``
    ``attest`` and ``signature``: ``TPM2_Quote`` over the selection
    with the nonce as qualifying data.  The PCRs are read beside the
    quote and the quote is kept only when its digest covers exactly
    those values; otherwise both are taken again, up to three times.

``register``
    ``nv_index``, ``pcr`` (9), ``name`` (the live index name),
    ``value``, and ``attest`` and ``signature`` from
    ``TPM2_NV_Certify`` of the index's 32 bytes at offset 0 with the
    same nonce.  The certification names the index, so it binds the
    value to the public area it was produced under.

``eventlog``
    This boot's records, verbatim.

``credential``
    ``value``, the credential recovered from the verifier's challenge
    when the evidence was requested with ``--challenge``, else
    ``null``.

``ek_certificate``
    The endorsement key certificate from NV ``0x01C0000A`` (ECC) or
    ``0x01C00002`` (RSA), base64, or ``null`` when the TPM holds none.
    It is carried for the operator's tooling; see section 7.

``logs``
    ``firmware`` (``/sys/kernel/security/tpm0/binary_bios_measurements``)
    and ``systemd`` (``/run/log/systemd/tpm2-measure.log``), base64 or
    ``null``, so the verifier can replay the PCRs it pins.

``version_id``, ``ts`` and ``boot_id`` describe the producer and are
not TPM-backed.  Without ``--nonce`` the document proves no freshness
and says so.

Binding the key to the TPM
~~~~~~~~~~~~~~~~~~~~~~~~~~

A signature by a key named ``000b...`` proves nothing about where that
key lives until the name is tied to a TPM.  The endorsement key does
that: it is derived from the TPM's endorsement seed by a template the
TCG fixes, and the endorsement certificate the manufacturer put in NV
describes exactly that key.  Credential activation makes the two keys
vouch for each other without ever exposing either.

On the operator, ``shirudo attest challenge --evidence=<path>
--out=<challenge> [--ek-ca=<bundle>]`` takes the endorsement key and
the attestation key name from an evidence document and checks that
the endorsement key's name matches its public area and that the area
is the TCG default template under the endorsement policy, so no
ordinary decryption key can pose as one.  When the evidence carries
an endorsement certificate, the certificate's key must be that key,
and with ``--ek-ca`` the certificate must chain to the PEM bundle of
issuers given.  The endorsement key has to be vouched for: by that
chain, by ``--ek-name`` from an inventory or a platform's API, or
explicitly waived with ``--trust-presented-ek``, which proves only that
the same party answers each time; the command makes no challenge
otherwise.  ``--ak-name`` makes the challenge for the pinned
attestation key rather than the one the document names.  It then draws
a random 32-byte credential and
protects it the way ``TPM2_MakeCredential`` does (Part 1, 24.4): a
seed only the endorsement key can recover, wrapped with RSA-OAEP under
the label ``IDENTITY`` for an RSA key or derived by KDFe from an
ephemeral P-256 ECDH agreement for an ECC key; a symmetric key from
``KDFa(seed, "STORAGE", name)`` that encrypts the credential with
AES-128-CFB; and an HMAC under ``KDFa(seed, "INTEGRITY")`` over the
encrypted credential and the attestation key name.  The challenge
document carries the blob and the wrapped seed; the credential itself
is printed once for the operator to keep and stored nowhere.

On the target, ``shirudo attest --nonce=<hex> --challenge=<path>``
loads the endorsement key of the challenge's type, refuses a challenge
made for another attestation key name, and has the TPM run
``TPM2_ActivateCredential`` under a ``PolicySecret`` session on the
endorsement hierarchy.  The TPM recovers the seed with the endorsement
key, recomputes the HMAC over the name of the loaded attestation key,
and decrypts the credential only when it matches; the value goes into
the evidence as ``credential``.  A blob made for another key or
another TPM is refused and the command fails rather than emit evidence
without the proof.

``shirudo attest verify ... --expect-credential=<hex>`` then checks the
recovered value.  Together with the signature checks this proves that
the key which signed the quote and the certification is a restricted
key inside the TPM that holds the endorsement key, and, through the
certificate, inside the TPM the manufacturer certified.  Everything
here is classical: TPMs hold RSA and P-256 endorsement keys and sign
with ECDSA, and no post-quantum algorithm is implemented by a TPM one
can buy or emulate, so the evidence stays classical even though the
artifacts it describes are not (residual risk 9).  The RSA branch
exists because many TPMs carry only an RSA endorsement certificate.

5) Verification and prediction
------------------------------

Both run on the operator and touch no TPM.

``shirudo attest verify --evidence=<path> --nonce=<hex> --ak-name=<hex>
[--ek-name=<hex>] [--cert=<cert.der> --upatch=<file>...
--expect=<name>=<hex>... --tree-root=<hex>] [--expect-chain=<hex>]
[--expect-pcr=<n>=<hex>...] [--expect-bind-pcr=<n>=<hex>...]
[--require-initrd] [--expect-credential=<hex>] [--allow-runtime-events]
[--strict-anchor]`` prints one line per check and a verdict.  The
checks, in order:

1. The nonce in the document is the one given.
2. The attestation key's public area is a P-256 ECDSA key with
   ``restricted``, ``sign``, ``fixedTPM``, ``fixedParent`` and
   ``sensitiveDataOrigin`` set; its name matches that public area; and
   it is the pinned name.  Without ``--ak-name`` the signer is only
   noted, and the command warns.  The endorsement key's name matches
   its public area and that area is the TCG default template under
   the endorsement policy; with ``--ek-name`` it is the pinned key;
   with ``--expect-credential`` the document's ``credential`` equals
   the value the challenge carried.
3. The quote: ECDSA signature by that key over the ``TPMS_ATTEST``,
   signer equal to the key's qualified name under the endorsement
   hierarchy, the nonce as extra data, the selection equal to
   ``pcr_mask``, every selected PCR listed, and the listed values
   hashing to the quoted digest.
4. The register certification: the same signature, signer and nonce
   checks, the certified index name equal to the listed name, and the
   certified 32 bytes at offset 0 equal to the listed value.
5. The binding: this boot has an ``init`` record; the name a register
   bound to that record's ``pcr_before`` and ``phase_before`` must
   have, computed in software from the handle, the attributes with
   ``TPMA_NV_WRITTEN``, the policy and the size, equals both the
   certified name and the recorded one.  Every ``--expect-bind-pcr``
   value equals the recorded one for that PCR, so the operator pins
   the ``enter-initrd`` phase value from the UKI, and
   ``--require-initrd`` fails unless the record says the binding was
   made while the initrd ran.
6. The reset: the boot holds one init record for the reset count the
   last one names, that count is the one the certification carries,
   and the quote and the certification carry the same reset count and
   firmware version, so a register bound again after boot cannot pass
   as the boot's.
7. The replay: this boot's records fold from zeros to the certified
   value.
8. The anchor: the record's anchor digest is the digest of the anchor
   string for the recorded name, and the quoted PCR 9 equals
   ``pcr_before`` extended by it.  When PCR 9 holds further
   measurements the check is a note unless ``--strict-anchor`` makes
   it a failure.
9. The expected state: with ``--cert`` the init event equals the one
   computed from the certificate, the ``--upatch`` and ``--expect``
   members and ``--tree-root``; the register equals ``--expect-chain``
   when given, else the value predicted for the set at boot, else,
   with events after boot, ``--allow-runtime-events`` decides; every
   ``--expect-pcr`` value matches the quote.  Events after boot are
   listed.

The verdict is ``ok`` only when every check passed; a document that is
not shirudo evidence exits 2.

``shirudo attest predict --cert=<cert.der> [--upatch=<file>...
--expect=<name>=<hex>... --tree-root=<hex>]
[--event=load|unload:<name>=<payload_sha256>...
--event=tree:<seq>=<operation_digest>...]`` prints ``set_digest``,
``init_event``, ``register_at_boot`` and, with events,
``register_after_events``, from the same functions the target uses.
With ``--bind-pcr=9=<hex> --bind-pcr=11=<hex>`` it also prints
``register_name``, the anchor string and ``pcr9_after_anchor``, so the
name and PCR 9 can be pinned from values the operator knows.

``shirudo attest challenge --evidence=<path> --out=<path>
[--ek-ca=<bundle>]`` is described in section 4; it prints its checks,
the path of the challenge it wrote and the credential to expect.

6) Relation to systemd's NvPCRs
-------------------------------

The register follows systemd's NvPCR construction (``*.nvpcr``
definitions, ``systemd-tpm2-setup-early``, ``systemd-pcrextend``;
see `TPM2 PCR Measurements Made by systemd
<https://systemd.io/TPM2_PCR_MEASUREMENTS/>`__), introduced in
systemd v259 and reworked in v262.  Shared with it:

* the index type and attributes, in particular ``TPM2_NT_EXTEND`` and
  ``TPMA_NV_CLEAR_STCLEAR``, so the register is a per-boot PCR in NV;
* the write policy shape, ``PolicyOR`` of a ``PolicyNvWritten(YES)``
  branch open to every TPM user and an initialisation branch that only
  a particular boot state satisfies;
* the index name as the anchor, certified by ``TPM2_NV_Certify``, and
  the ``nvpcr-init:<name>:0x<handle>:<tpm name>`` event string.

Different from it, and why it matters:

* **The initialisation branch.**  systemd v262 binds it with
  ``PolicyAuthorize`` to the UKI's PCR signing key (policy reference
  ``initrd``) and satisfies it with the signed ``PolicyPCR`` for PCR 11
  at ``enter-initrd``; the index is initialised in the initrd and the
  branch closes when ``leave-initrd`` is measured.  The name is then
  stable across kernel updates, and it is unsatisfiable at runtime
  whatever an attacker does.  v263 adds a plain ``PolicyPCR`` fallback
  where no signed policy exists, and that is shirudo's construction:
  a plain ``PolicyPCR`` over PCRs 9 and 11, bound from the initrd at
  ``enter-initrd`` and closed by ``leave-initrd`` and by the anchor.
  The name therefore changes with the initrd and the phase value, so
  the record carries both and the operator pins them from the UKI with
  ``--expect-bind-pcr``.

* **The anchor's PCR.**  Both measure the ``nvpcr-init`` event into PCR
  9.  systemd does so through ``systemd-pcrextend`` before
  ``nvpcr-separator``, and its verifiers trust a certified name only if
  it appears in the PCR 9 log before the separator; shirudo extends PCR
  9 itself, after the separator when ordered after
  ``systemd-pcrnvdone.service``, and keeps the anchor in its own
  eventlog, so the extension does not appear in systemd's measurement
  log and systemd-aware tooling has to take it from the evidence.

* **Registration.**  The register is not a ``*.nvpcr`` definition and
  has a handle of its own, so systemd neither initialises nor extends
  it, and systemd-aware verifiers do not know it.

Registering the register as a systemd NvPCR, so that its name follows
the UKI signing key and systemd anchors it before the separator while
shirudo only extends it, is the deferred step that would remove the
remaining differences; until then the two coexist without interfering.

7) Limits
---------

These are the known limits of the design as implemented; the
`threat-model <threat-model.rst>`__ residual risks give the full
context and the deferred mitigations the plan.

* **The binding values come from the record unless pinned.**
  ``verify`` recomputes the index name from the ``pcr_before`` and
  ``phase_before`` the init record claims; ``--expect-bind-pcr`` makes
  them values the operator knows, and ``predict --bind-pcr`` turns
  those into the expected name and PCR 9.  Root with the owner
  authorisation (empty on most TPMs) can still undefine the written
  index at runtime; from then on every extension and ``init`` itself
  refuse ``tampered`` until the next TPM reset, a denial of service and
  not an erasure.

* **The endorsement key's trust is the certificate's.**  Credential
  activation proves the attestation key sits beside the endorsement
  key in the evidence; whether that endorsement key belongs to a
  genuine TPM is what the endorsement certificate says, and only
  ``--ek-ca`` with the manufacturer's issuers checks it.  A TPM
  without a certificate, as virtual TPMs usually are, leaves the
  endorsement key pinned by its name as presented at enrolment.

* **PCR 9 after the anchor.**  The exact anchor check holds while
  nothing is measured into PCR 9 after ``init``; systemd's
  ``nvpcr-separator`` lands there, so ``init`` orders after
  ``systemd-pcrnvdone.service``.

* **The boot window.**  Run from the initrd, ``init`` can be preceded
  only by what the initrd runs before it, which the measured boot
  records; a binding made from the root file system is one the
  verifier can reject, not one it can prevent.

* **PCR 11 needs a UKI.**  systemd measures the initrd phases only on
  a measured UKI boot; a kernel and initrd loaded by grub or passed to
  QEMU directly leave PCR 11 at its boot value, ``init`` warns, and
  the verifier has PCR 9 alone to tell an initrd binding from a later
  one.

* **A TPM reset without a reboot.**  Resuming from hibernation resets
  the TPM but keeps the kernel's boot ID, so the register is gone while
  the record of this boot stands; every extension then fails
  ``tpm_error`` until ``init`` is run again, which the reset count on
  the record lets it do.

* **The evidence is classical.**  TPMs sign with ECDSA P-256; the
  artifacts the evidence describes are ML-DSA-87.

8) Testing
----------

``testing/tpm/t0033-tpm-wire.sh`` checks the policy digests, names, wire
parsers, the key derivations, the endorsement policy and the
credential blob against known vectors and an independent
implementation, without a TPM.  ``testing/tpm/t0034-register.sh`` drives the
whole register and attestation path, the initrd phases simulated as
PCR 11 extensions, the credential challenge with an ECC and an RSA
endorsement key included, against libtpms:
``testing/helper/tpmsim-cmd`` is a ``cmd:`` TCTI driver around the simulator,
built when ``pkg-config libtpms`` succeeds, and ``testing/helper/test-register``
exercises binding, extending, replay, recreation, a TPM reset and
``attest`` evidence and verification through ``SHIRUDO_TPM_TCTI``,
``SHIRUDO_EVENTLOG_PATH`` and ``SHIRUDO_KEYS_DIR``.  Deleting the
simulator's ``volatile`` state file is a TPM reset.  The target suite
runs the same path against swtpm in the QEMU VM (``make -C testing test-tgt``);
``contrib/swtpm.sh`` starts a software TPM for a development target.


Configuration image measurements
================================

Image mode adds a reserved static SHA-256 PCR for config selections. It does
not replace the upatch NV register or its PCR 9/11 bootstrap binding. The
PCR number and config verification certificate come from authenticated
runtime bootstrap settings; config images cannot override either.

Each BOOT or UPDATE event hashes ``"shirudo-config-root-v1\0"``, the
big-endian 32-bit event kind and the 32-byte binary root hash, then extends
this PCR before config effects. BOOT is 1 and UPDATE is 2. The durable
selection records TPM reset and restart counts. Once pending, an interrupted
activation blocks further state changes and config attestation until a
manual reboot; no same-boot retry is attempted. The node keeps running and
Shirudo never initiates the reboot. The
`config-images <config-images.rst>`__ guide gives the pending-selection rules.

``shirudo attest`` automatically includes this PCR and emits the current
boot's config history: schema, PCR index, reset/restart counts, initial PCR
and events containing sequence, kind and root hash. The quote binds PCR
values and TPM boot identity. Verify the intended config with both
``--expect-config-root=<64 hex>`` and ``--expect-config-pcr=<number>``.
The verifier derives each event digest and rejects malformed roots,
discontinuous sequences, incorrect boot identity, a mismatching selected
root or a replay that does not reach the quoted PCR. Pending activations
cannot produce healthy evidence through the normal CLI.

Without an expected config root, successful replay is reported as
consistency without operator approval. Neither this replay nor a static
PCR proves that only the trusted updater issued the TPM command: direct
measurement writers can record a selection without the corresponding
operation. Restricting writers remains separate work for both the config
PCR and the existing NV register; no IMA integration is added.
