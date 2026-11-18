..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: Kernel developers, security reviewers

Measurement register and attestation
====================================

shirudo records every change to a target's BPF state in a TPM register
that root on the target cannot rewrite or append to, and the TPM signs
that register on request. This page explains the register, its write
policy and binding, the events and the eventlog, the evidence, what the
operator's verifier computes, the separate config PCR, and the limits.
:src:`util/chain.c`, :src:`util/tpm.c`, :src:`util/tpm_wire.c`,
:src:`util/eventlog.c` and :src:`util/attest.c` are the reference.

Problem
-------

The operator needs to know which upatches a target runs. The target's
own report is worth nothing against root, which can make ``shirudo
status`` print anything. A file log is root's to edit. What is needed is
a record that only grows, that resets only when the machine starts over,
that only shirudo's own successful operations can extend, and that a key
root cannot use signs.

Why the obvious approaches fail
-------------------------------

A PCR only grows and resets with the TPM, but the PCRs are shared with
firmware, the boot loader, systemd and IMA, and a stock system has no
free static one; PCR 23 is resettable by software. An NV index of type
extend behaves like a PCR of one's own, which is what systemd's NvPCRs
use. Their write policy lets any process append, though. For shirudo
that is not enough: a public append lets root measure a load that never
happened, and evidence would then vouch for a state the kernel is not in.

We use an NV extend index like systemd does, and add an authorized
writer: an extension needs a signature from a TPM-held key, and the
kernel refuses the extension command itself to every task without
runtime authority.

Register
--------

The register is NV index ``0x01818E00`` (``NV_INDEX`` in
:src:`util/paths.h`, which a build may change), holding one SHA-256
digest. Its attributes are ``0x0E060048``:

- ``TPM2_NT_EXTEND``: a write of ``d`` sets the index to
  ``SHA256(old || d)``, as a PCR extend does
- ``TPMA_NV_CLEAR_STCLEAR``: contents and ``TPMA_NV_WRITTEN`` clear at
  every TPM reset and restart, so the register starts from 32 zero bytes
  and holds the history of one TPM boot
- ``TPMA_NV_POLICYWRITE``: the only way to write is a policy session
  that satisfies the write policy
- ``TPMA_NV_OWNERREAD`` and ``TPMA_NV_AUTHREAD``: anyone can read and
  certify it with an empty password
- ``TPMA_NV_NO_DA`` and ``TPMA_NV_ORDERLY``: failed authorizations do
  not count toward dictionary-attack lockout, and the TPM writes the
  index back to NV memory only at an orderly shutdown

The index's TPM name is ``000b`` followed by the SHA-256 of its public
area: handle, name algorithm, attributes, policy digest and size.
``TPMA_NV_WRITTEN`` is one of the attributes, so the index has one name
before its first write and another after it. The written name is the one
the record, the anchor and every later comparison use.

Write policy
~~~~~~~~~~~~

The write policy is ``PolicyOR(written, init)``, followed by
``PolicySigned`` and ``PolicyCommandCode(TPM2_CC_NV_Extend)``:

``written``
    ``PolicyNvWritten(YES)``. Every extension after the first takes this
    branch. It cannot initialize an index that was recreated and is
    unwritten.

``init``
    ``PolicyNvWritten(NO)`` followed by ``PolicyPCR`` over PCRs 9 and 11,
    with the SHA-256 of the values both held when ``init`` bound the
    register. It admits the first write of a TPM boot, and only while
    both PCRs still hold those values.

``PolicySigned`` names the boot's NV writer key and the policy reference
``shirudo-nv-writer-v1``. The writer signs the SHA-256 of the session's
TPM nonce, a zero expiration, the command hash and the reference. The
command hash covers ``TPM2_CC_NV_Extend``, the index name twice (as auth
handle and as index) and the event. The TPM checks that exact command
hash when it executes the extension, so a signature authorizes one event
on one index in one session.

NV writer
~~~~~~~~~

The writer is an RSA-3072 RSASSA SHA-256 primary key in the owner
hierarchy with object attributes ``0x00040072``: ``fixedTPM``,
``fixedParent``, ``sensitiveDataOrigin``, ``userWithAuth`` and ``sign``.
``init`` creates it from 32 random bytes in the ``unique`` field, and
freezes those bytes and the resulting 384-byte modulus in the identity
map. Each later command recreates the primary from the frozen input,
compares the public key with the frozen one, has the TPM sign the
authorization and flushes the key. The private key never leaves the TPM,
and nothing is kept in a persistent handle or a file.

The input is not secret. Any process can recreate the same key and have
the TPM sign. What protects the register is ``lsm/tpm_command``: the
kernel shows every command written to ``/dev/tpm0`` or ``/dev/tpmrm0`` to
that hook, and it refuses ``TPM2_NV_Extend`` of the frozen index to tasks
without runtime authority, including through descriptors opened before
``init`` or inherited from another process. The hook needs the carried
kernel patch described in :doc:`kernel-patches`.

A new host boot chooses new input and so a new key. A TPM reset within
the same host boot keeps the input, and so the key. A TPM clear changes
the owner seed, and the frozen key can no longer be recreated.

Authenticated TPM sessions
--------------------------

Shirudo employs trust on first use (TOFU) and trusts the TPM it finds during
initialization in the initrd by freezing the EK's name in the identity map.

Every TPM connection creates the standard ECC P-256 endorsement key
(EK) to transport a secret salt via ECDH to calculate an HMAC session key.
This salted HMAC session binds communication to the enrolled TPM.
Successful responses contain HMACs that shirudo verifies.

The session's audit flag allows shirudo to authenticate responses even from
commands that require no authorization, such as PCR and clock reads.
NV extensions use separately salted policy sessions with the existing
command-bound writer authorization. An intermediary that suppresses an
extension cannot invent or replay a successful response.

Binding at boot
---------------

``init`` binds the register once per TPM boot, normally from the initrd,
after it has restored the archived upatches (:doc:`boot-flow`). Figure 1
shows the binding and the extensions that follow it.

.. figure:: /images/internals-register-events.svg
   :alt: In the initrd, init defines the NV index under a write policy
         on PCRs 9 and 11, extends it with the init event, extends PCR 9
         with the anchor digest and writes the init record to
         eventlog.pending. Every later command extends the index with a
         tagged event digest and then appends its record to the
         eventlog, under eventlog.lock.

   Figure 1. Binding the register at boot and extending it later.

The binding takes these steps:

#. Open a salted session using the EK whose name ``init`` froze in the
   identity map. The session authenticates the TPM's successful replies.
#. Read the TPM's reset count. When this boot's eventlog already holds an
   ``init`` record for that count, the register was bound: if the index
   is written under the recorded name, ``init`` reuses it and adds no
   event; if it is gone, unwritten or renamed, ``init`` refuses with
   ``tampered`` and binds nothing before the next TPM reset.
#. Otherwise read PCR 9 and PCR 11 (``pcr_before``, ``phase_before``),
   compute both policy branches, the policy digest and the two names in
   software, and define the index with the owner authorization,
   replacing an index that is already written or has another name. The
   name the TPM reports must equal the computed one.
#. Extend the index with the ``init`` event through the ``init`` branch.
   The session's policy digest is read back and compared with the
   software policy before the extension.
#. Extend PCR 9 with SHA-256 of the anchor string
   ``nvpcr-init:shirudo:0x1818e00:<written name>``, systemd's
   ``nvpcr-init`` format. From then on PCR 9 no longer holds
   ``pcr_before``, so the ``init`` branch cannot be satisfied again before
   the next TPM reset. Once systemd measures ``leave-initrd``, PCR 11 no
   longer holds ``phase_before`` either.
#. Write the ``init`` record: both PCR values, whether the initrd was
   running (``bound_in``), the written name, the anchor and its digest,
   the register value, the reset count and the writer's public modulus.

Consequences follow. An index undefined and recreated under the same
policy cannot be written, because PCRs 9 and 11 have moved. One recreated
under another policy has a name the record does not know. And the
register value is a function of the trust set, the restored set, the
tree root and the events since boot, which the operator can compute.

Extending later
~~~~~~~~~~~~~~~

Every later extension uses a session authenticated with the pinned EK,
requires this boot's ``init`` record, recomputes the policy from
the recorded PCR values and writer key, and requires the live index to be
written, to carry the recorded name and policy, and the TPM's reset count
to equal the recorded one. A missing register is ``tpm_error``; a
register that is not the recorded one is ``tampered``.

Events
------

Every extension is a 32-byte SHA-256 digest that starts with a
NUL-terminated tag, so no event of one kind can be read as another. In
the formulas, ``\0`` is the NUL that ends the tag.

.. list-table::
   :header-rows: 1
   :widths: 18 52 30

   * - Event
     - Digest
     - Made by
   * - ``init``
     - ``SHA256("shirudo-init\0" || cert_sha256 || set_digest ||
       tree_root)``
     - ``init``, once per TPM boot
   * - ``upatch_load``
     - ``SHA256("shirudo-upatch\0" || payload_sha256 || name)``
     - ``upatch load``, ``bpm`` installs
   * - ``upatch_unload``
     - ``SHA256("shirudo-unload\0" || payload_sha256 || name)``
     - ``upatch unload``, ``bpm`` removals, revocation purges
   * - ``tree_op``
     - ``SHA256("shirudo-tree\0" || seq || operation_digest)``, ``seq``
       as eight big-endian bytes
     - ``bpm tree sync``
   * - ``key_revoke``
     - ``SHA256("shirudo-key-revoke\0" || cert_sha256)``
     - live config activation that revokes an enrolled key

``cert_sha256`` in the ``init`` event covers the BPF trust set in effect:
the SHA-256 of the certificate's DER when the set has one member, else
the SHA-256 over the members' DER digests in sorted order.
``set_digest`` is the SHA-256 of one line ``<payload_sha256 hex>
<name>\n`` per restored upatch, sorted by name. ``tree_root`` is the
upatch tree's projection root at boot, or 32 zero bytes without a tree.

Boot restore is one event however many upatches it restores, and the
root file system's ``init`` adds none. Every operation after that is its
own event. A live revocation extends ``key_revoke`` after it unlinks the
key and before it purges what the key signed; each loaded upatch it
purges follows as an ``upatch_unload`` with the reason ``key_revoke``.
Revocations a config carries at boot are not individual events; the
``init`` event's trust set reflects them.

Lean 4 proves that these encodings tell every two events apart, for
upatch names of every length ``upatch_name_valid()`` takes and every
sequence number, and that the ``init`` listing spells one set of distinct
names whatever order ``qsort()`` leaves. With the register's fold, equal
registers then come from the same events in the same order unless
SHA-256 collides among the strings the two histories hash. CBMC shows
that :src:`util/chain.c` hashes exactly the bytes the model encodes. The
proofs are in :doc:`/contribute/testing/proof-coverage`.

Eventlog
--------

``/var/lib/shirudo/eventlog`` holds one JSON line per extension: the
event digest and type, the boot ID, and the fields the digest was
computed from. Each line goes out with its newline in one write and is
followed by ``fsync``. A partial append is truncated away, and one that
was killed before it could be is skipped by every reader and dropped by
the next append, so that it cannot join the next record on its line.
The file is sealed like the rest of the state tree.
:doc:`/reference/eventlog` gives the format.

The ``init`` run in the initrd writes its record to
``/run/shirudo/eventlog.pending``, which crosses the switch to the root
file system with ``/run``. Every reader treats the pending record
as part of this boot's log. The root file system's ``init`` appends it to
the eventlog and removes the pending file, and so does the first append
that comes earlier. A record already in the eventlog is not appended
twice.

"This boot" is every line with the running boot ID from the last ``init``
record on. Replaying those lines from 32 zero bytes must reproduce the
live register. Readers load the whole log and the pending record into
memory and refuse a total above 8 MiB. ``eventlog.max_bytes`` in the
config image, unlimited by default, makes ``init``, ``upatch load`` and
``upatch unload`` refuse with ``eventlog_full`` before they load anything
or touch the TPM; revocations and tree operations do not check it.

Lock between extend and append
------------------------------

The register and the eventlog advance together only while one process at
a time extends and appends. Two measuring commands that each held a lock
of their own could interleave extend, extend, append, append, and leave a
log that replays the events in the other order. Every measuring command,
an upatch load or unload, a live revocation and a tree operation,
therefore holds ``/var/lib/shirudo/eventlog.lock`` from its extension to
its append; a load or an unload holds it from before it touches the pins,
and a revocation's purge of an upatch from its archive read until its
pins and archive are gone, so that a load of the same name cannot come
between the purge's event and its removal. The purge checks the signer
on what that read finds: an upgrade that replaced the upatch since the
revocation's scan with one another key signed leaves it in place.

The order of extension and state change is chosen per operation. A load
loads, archives and then extends; a failed archive copy or a refused
extension undoes the load, so no upatch runs unmeasured. An unload
extends first and detaches after, so a stopped process leaves a register
that records more than happened, never less. A load stopped between its
pins and its extension leaves pins, and after its archive copy an
archive, that the register does not cover: ``status`` reports them and
the next load or unload undoes them under the same lock before it acts,
so the register stays behind what runs for one command at most. A load
or unload that cannot read this boot's records, or cannot undo what they
do not cover, refuses rather than act beside pins it cannot account for. An
append that fails after
a successful extension is reported as a desync for the operator to
reconcile.

The undo removes what the records do not cover, so the records it reads
must be the register's and nobody else's. The boot ID and the eventlog
are paths, which root binds over in a mount namespace of its own. The
undo therefore takes the boot from the TPM, the last ``init`` record
whose ``nv_name`` and ``tpm_reset_count`` are the live index's name and
the TPM's reset count, derives every record's digest from its fields,
and folds them to the value the TPM reports for the register. Records
that do not fold make it refuse, ``tampered``, and so does the append
failure above until the next reboot. The pending record counts only
from a ``/run/shirudo`` that carries the seal label, which a directory
of root's making cannot.

``init`` binds the register and writes its record without taking this
lock, from the initrd, before any upatch command is admitted. Its run
from the root file system, which upatch commands can run beside, holds
the lock while it checks the archive against the pins.

Lean 4 proves this protocol for every sequence of loads, unloads,
purges, kills, failed steps, reboots and root's changes to unlabeled
archive files: once a command's undo pass is done every pin directory
holds one link of the payload this boot's records hold, no name ever
holds two links, every name the records hold runs with that payload,
this boot's records are the register's events in order but for appends
that failed after their extension, and ``init`` restores exactly the
archives whose last record is their load. The model takes the lock to
exclude and ``init`` to run as one step, which the gate that refuses
every command until ``init`` completes justifies. CBMC shows that
``measured_event()`` and ``measured_holds()`` fold the records as the
model does. The proofs are in :doc:`/contribute/testing/proof-coverage`.

Evidence
--------

``shirudo attest`` asks the TPM for two signed statements and collects
what a verifier needs to check them. It needs no enrollment state on the
target and leaves none. Figure 2 shows one run, with the credential
activation that enrollment adds.

.. figure:: /images/internals-attest-evidence.svg
   :alt: The operator runs attest predict and sends a nonce, with a
         credential challenge at enrollment. The target has the TPM create
         the attestation key from its fixed template, activate the
         credential when there is a challenge, quote the PCRs and certify
         the register with the nonce. It returns an evidence document with
         this boot's eventlog, and the operator runs attest verify.

   Figure 2. Collecting evidence. The operator holds no TPM; the nonce,
   the challenge and the document travel by whatever channel the operator
   uses to reach the target.

The attestation key is a primary under the endorsement hierarchy with a
fixed template: ECC NIST P-256, ECDSA with SHA-256, ``restricted`` and
``sign``, no authorization value and no policy. A primary with a fixed
template is derived from the endorsement seed, so the same TPM always
yields the same key and the same name. ``restricted`` means the key signs
only structures the TPM itself produced.

The evidence document carries:

- a ``TPM2_Quote`` over the SHA-256 bank of the selected PCRs, by default
  0 to 7, 9 and 11 to 15, plus the config PCR, with the verifier's nonce;
- a ``TPM2_NV_Certify`` of the register's 32 bytes with the same nonce,
  which names the index and so binds the value to its public area;
- the attestation key's public area and name, and the endorsement key's
  public area and name;
- this boot's eventlog records;
- the endorsement certificate from NV ``0x01C0000A`` (ECC) or
  ``0x01C00002`` (RSA) when the TPM holds one;
- the credential the TPM recovered, when the request carried a
  challenge;
- the firmware and systemd measurement logs, so that a verifier can
  replay the PCRs it pins;
- the config history (see below).

Credential activation
~~~~~~~~~~~~~~~~~~~~~

A signature by a key name proves nothing until the name is tied to a
TPM. ``shirudo attest challenge`` on the operator takes the endorsement
key from an evidence document, checks that it is the TCG default template
under the endorsement policy and, when vouched for by ``--ek-ca``,
``--ek-name`` or explicitly by ``--trust-presented-ek``, computes in
software what ``TPM2_MakeCredential`` computes: a random 32-byte
credential protected for the endorsement key and bound to the
attestation key's name. ``shirudo attest --challenge`` on the target has
the TPM run ``TPM2_ActivateCredential`` under a ``PolicySecret`` session
on the endorsement hierarchy; the TPM releases the credential only when
the attestation key it loaded has the name the challenge was made for.
``shirudo attest verify --expect-credential`` checks the value. Together
with the signature checks, this shows that the key that signed is a
restricted key in the TPM that holds the endorsement key.

Builder-recorded names
~~~~~~~~~~~~~~~~~~~~~~

Activation is one way to learn the attestation key's name. The other is
to take it from a builder that controlled the TPM before the target got
it, a hypervisor creating a virtual TPM or a provisioning step: the
builder creates both keys from the templates ``attest`` uses
(:doc:`/reference/cli/attest`) and records their names. Figure 3 sets the
two side by side. Both end in the same pinned names, and ``verify``
checks evidence the same way after either.

.. figure:: /images/internals-attest-names.svg
   :alt: Credential activation: the target sends evidence, the operator
         makes a challenge for an endorsement key it vouches for, the TPM
         releases the credential only to that attestation key, and verify
         checks it once. Builder-recorded names: the builder creates both
         keys in the TPM before handover and records their names. Both
         paths end in the inventory every later verify pins.

   Figure 3. Two ways to learn the attestation key's name.

On the builder path the name is trusted because the builder saw the key
created, not because the TPM proved anything to the operator. The
builder, and for a virtual TPM its host, joins the trusted base, and the
endorsement key in the evidence is the target's word: no challenge ties
it to the attestation key. The two paths combine. An endorsement key
name the builder recorded can vouch for the endorsement key in
``attest challenge --ek-name``, in place of a certificate chain.

What verify and predict compute
-------------------------------

``shirudo attest verify`` and ``shirudo attest predict`` run on the
operator and touch no TPM. ``verify`` prints one line per check and a
verdict. Figure 4 shows the four comparisons that tie what the target
wrote about itself to what the TPM signed or the operator computed.

.. figure:: /images/internals-attest-verify.svg
   :alt: The eventlog replay must equal the certified register value; the
         name computed from the init record must equal the certified name;
         pcr_before extended by the anchor digest must equal the quoted
         PCR 9; the init event must equal the one attest predict computes.

   Figure 4. What ``verify`` compares. Once the replay matches, the
   ``init`` record's fields are the ones the TPM measured.

It checks, in this order:

#. the nonce;
#. the attestation key: a restricted signing key with the required
   attributes, its name matching its public area, and with ``--ak-name``
   the pinned name; the endorsement key's template and name, and with
   ``--ek-name`` and ``--expect-credential`` the pinned key and the
   credential;
#. the quote: signature, signer, nonce, that it covers exactly the listed
   PCRs, and that the listed values hash to the quoted digest;
#. the register certification: signature, signer, nonce, the certified
   name and value equal to the listed ones, and the same TPM reset count
   and firmware version as the quote;
#. with ``--expect-config-root`` and ``--expect-config-pcr``, the config
   history;
#. the binding: this boot has an ``init`` record, the document names the
   verifier's own NV handle and PCRs 9 and 11, and the name a register
   bound to the recorded PCR values and writer key must have, computed in
   software, equals both the certified and the recorded name; each
   ``--expect-bind-pcr`` value equals the recorded one;
   ``--require-initrd`` requires ``bound_in`` to be ``initrd``;
#. the reset: one ``init`` record for the certified reset count;
#. the replay: this boot's records fold from zero to the certified value,
   and every event after ``init`` carries the digest its own fields
   produce;
#. the anchor: the recorded anchor digest is that of the anchor string
   for the recorded name, and the quoted PCR 9 equals ``pcr_before``
   extended by it; further PCR 9 measurements are a note unless
   ``--strict-anchor`` makes them a failure;
#. the expected state: with ``--cert``, ``--upatch``, ``--expect`` and
   ``--tree-root``, the ``init`` event equals the predicted one; the
   register equals ``--expect-chain``, or the predicted value at boot, or,
   with events after boot, ``--allow-runtime-events`` decides; each
   ``--expect-pcr`` matches the quote.

``predict`` prints ``set_digest``, ``init_event`` and
``register_at_boot`` from the certificates, the artifacts and the tree
root, using the target's own functions, and ``register_after_events``
for ``--event`` arguments. With ``--bind-pcr=9=<hex>``,
``--bind-pcr=11=<hex>`` and ``--writer-public=<hex>`` it also prints the
register's name, the anchor string and ``pcr9_after_anchor``.
:doc:`/reference/cli/attest-verify` and
:doc:`/reference/cli/attest-predict` list the options.

Config PCR
----------

Config activations are measured into a separate PCR, not into the
register. The runtime image's bootstrap settings choose it with
``config.pcr``: any static SHA-256 PCR from 0 to 15 except 9 and 11. A
config image cannot change the choice.

Each event is ``SHA256("shirudo-config-root-v1\0" || kind ||
root_hash)``, with the kind as a big-endian 32-bit number, 1 for the boot
event and 2 for a live update, and the 32-byte binary root hash. The
first event of a TPM boot records the PCR's value before it as
``initial_pcr``; the journal under ``/var/lib/shirudo/config-update``
records the sequence, the TPM's reset and restart counts and the root of
each event. :doc:`config-images` explains activation.

Evidence includes the config PCR in the quote and the config history.
``verify`` with ``--expect-config-root`` and ``--expect-config-pcr``
derives each event digest, requires one boot event followed by updates in
sequence for the quoted TPM boot, a replay from ``initial_pcr`` that
reaches the quoted PCR value, and the expected root as the selection.

Limits
------

These are properties of the design as implemented.
:doc:`/security/threat-model` gives their consequences.

The first TPM contact must be trusted.
    Session-key enrollment runs in the authenticated initrd against
    its kernel TPM device. Sessions protect later communications, not
    a bootstrap already controlled by an attacker. The operator's
    enrollment and attestation checks remain necessary.

Rebinding depends on the record.
    ``init`` decides that the register is already bound this boot from
    the eventlog, which it reads through the caller's view of the file
    system. Without a record for the current reset count, it binds the
    register again, with a warning when the index was already written,
    and PCR 9 then carries both anchors. A verifier that pins both
    binding PCRs to their initrd values with ``--expect-bind-pcr``
    rejects such evidence.

Owner authorization can remove the register.
    A process with the owner authorization, empty on many TPMs, can
    undefine the index. Extensions then fail and ``init`` refuses to bind
    again before the next TPM reset. This denies service; it does not
    erase what evidence already showed.

The verifier checks what it is asked to check.
    Without ``--ak-name`` the signer is only noted. Without ``--cert`` or
    ``--expect-chain`` no state is compared, and a verdict of ``ok``
    shows internal consistency only. ``--require-initrd`` reads the
    record's own ``bound_in``; ``--expect-bind-pcr=11`` is what proves an
    initrd binding. ``--allow-runtime-events`` accepts any well-formed
    events after boot.

The config PCR has no writer restriction.
    Any process that can send ``TPM2_PCR_Extend`` can extend the config
    PCR, and then every target command except ``shirudo status`` and
    ``shirudo image status`` refuses until a reboot because the PCR no
    longer replays.

PCR 11 needs a measured UKI boot.
    systemd measures the initrd phases only on a measured UKI boot.
    Without them PCR 11 does not move, ``init`` warns, and a verifier has
    only the anchor in PCR 9 to tell an initrd binding from a later one.

The evidence is classical.
    TPMs sign with ECDSA P-256 and the writer is RSA-3072, while the
    artifacts the evidence describes are signed with ML-DSA-87.

Related
-------

- :doc:`/concepts/background/tpm` for TPM PCRs, NV indices and
  sessions
- :doc:`/concepts/measurement-register` for the concept
- :doc:`/operate/run/attest` for attesting a target
- :doc:`/reference/eventlog` for the eventlog format
