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

``init`` in the initrd trusts the TPM it finds there, trust on first use,
and freezes the name of its endorsement key in the identity map.

Every TPM connection creates the standard ECC P-256 endorsement key
(EK) to transport a secret salt via ECDH to calculate an HMAC session key.
This salted HMAC session binds communication to the enrolled TPM.
Successful responses contain HMACs that shirudo verifies.

The session's audit flag allows shirudo to authenticate responses even from
commands that require no authorization, such as PCR and clock reads.
NV extensions use separately salted policy sessions with the existing
command-bound writer authorization. An intermediary that suppresses an
extension cannot invent or replay a successful response.

A TPM whose endorsement key has another name, or an identity map
without a frozen name, fails the connection, ``tpm: not the TPM init
bound``, and the command fails with ``tpm_error``. ``init`` compares
nothing while enforcement is not yet active, since that is when it
records the name.

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
         eventlog, under the register lock.

   Figure 1. Binding the register at boot and extending it later.

Figure 2 follows the binding command by command. The init branch of the
write policy can be satisfied only between the definition of the index
and the anchor's extension of PCR 9, and only by the session that
carries the writer's signature for that one extension.

.. figure:: /images/internals-register-binding.svg
   :alt: Before the guards attach, init creates the endorsement key and
         the NV writer and freezes their names in the identity map.
         After the restore it reads the TPM's reset count, which decides
         whether this boot's register is already bound, reads PCRs 9
         and 11, computes the policy, the index's two names and the
         anchor, defines the index, satisfies the init branch with
         PolicyNvWritten(NO), PolicyPCR, PolicyOR, the writer's
         PolicySigned and PolicyCommandCode, extends the index with the
         init event and extends PCR 9 with the anchor, which closes the
         init branch. systemd's leave-initrd moves PCR 11 later.

   Figure 2. The commands of the binding in the initrd, and the window
   in which the init branch is open.

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
   ``nvpcr-init`` format, and append the same record systemd writes for
   its own anchors (``content_type`` ``systemd``, ``eventType``
   ``nvpcr-init``) to systemd's userspace measurement log,
   ``/run/log/systemd/tpm2-measure.log``, under systemd's lock. The
   register is bound in the initrd, so the record precedes the
   ``nvpcr-separator`` that ``systemd-pcrnvdone`` measures in the
   host, and a verifier replays PCR 9 from the firmware log and that one
   log. A failure to log is reported and leaves PCR 9 extended: a
   verifier that cannot replay it fails closed. From then on PCR 9 no
   longer holds
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
   * - ``java_load``
     - ``SHA256("shirudo-java\0" || payload_sha256 || name)``
     - ``upatch load`` and ``bpm`` installs of a Java upatch
   * - ``java_unload``
     - ``SHA256("shirudo-java-unload\0" || payload_sha256 || name)``
     - ``upatch unload``, ``bpm`` removals and revocation purges of a
       Java upatch
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
<name>\n`` per restored upatch, sorted by name, a Java upatch's line
prefixed with ``java ``. A payload digest is hex alone, so a Java member
never lists like a BPF one. ``tree_root`` is the
upatch tree's projection root at boot, or 32 zero bytes without a tree.

Boot restore is one event however many upatches it restores, and the
root file system's ``init`` adds none. Every operation after that is its
own event. A live revocation extends ``key_revoke`` after it unlinks the
key and before it purges what the key signed; each loaded upatch it
purges follows as an ``upatch_unload`` with the reason ``key_revoke``.
Revocations a config carries at boot are not individual events; the
``init`` event's trust set reflects them.

Lean 4 proves that these encodings tell every two events apart, a Java
event from a BPF one included, for upatch names of every length ``upatch_name_valid()`` takes, load and
unload names of 1 to 256 bytes as ``attest predict`` takes them, and
every sequence number, and that the ``init`` listing spells one set of
distinct names whatever order ``qsort()`` leaves. With the register's
fold, equal registers then come from the same events in the same order
unless SHA-256 collides among the strings the two histories hash. For
``attest verify`` it proves more: whatever extended the register, the
values it folded in were the digests of the events the verifier
expects, unless SHA-256 collides among the strings of the two folds.
CBMC shows that :src:`util/chain.c` hashes exactly the bytes the model
encodes. The proofs are in :doc:`/contribute/testing/proof-coverage`.

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
config image, unlimited by default, makes ``upatch load`` and ``upatch
unload``, and the installs and removals of ``bpm`` and of a tree
operation, refuse with ``eventlog_full`` before they load anything or
touch the TPM. ``init`` checks it only when it binds the register, after
it has extended the config PCR and restored the archived upatches. The
``key_revoke`` and ``tree_op`` events do not check it.

.. _register-lock:

Lock between extend and append
------------------------------

The register and the eventlog advance together only while one process at
a time extends and appends. Two measuring commands that each held a lock
of their own could interleave extend, extend, append, append, and leave a
log that replays the events in the other order. Every measuring command,
a upatch load or unload, a live revocation and a tree operation,
therefore holds the register lock at least from its extension to its
append: an ``flock`` on the root of the private bpffs,
``/run/shirudo/bpffs``. That directory is the same inode in every mount
namespace, and root can neither mount over it nor add an entry to it,
where a lock file beside the eventlog is root's to cover with another
labeled inode in a namespace of its own. A command opens the directory,
reads the identity record pinned in it and checks that the directory
lies on the device the record names before it locks. Figure 3 shows the three that change the
loaded set, which hold it longer, the order of their steps and what a
failure or a stop between two of them leaves.

.. figure:: /images/internals-register-lock.svg
   :alt: Three lanes. A upatch load takes the lock, undoes what the
         records do not cover, loads and attaches, pins, archives,
         extends the register and appends to the eventlog, then lets
         the lock go. An unload undoes, verifies its directive, compares
         the payload, extends, appends and only then removes the pins
         and the archive. A revocation's purge reads the archive, checks
         its signer, extends, appends and removes the pins and the
         archive. Markers show that a load stopped before its extend
         leaves pins the next command undoes, that a failed archive or
         extend undoes the load, that a failure between extend and
         append is a desync, and that an unload stopped after its append
         leaves pins the next command removes.

   Figure 3. The steps of a load, an unload and a purge, the span each
   holds the register lock, and what an interruption leaves.

The eventlog reader decodes each payload digest and gives the measured set
its lowercase spelling. A pin and a log record with the same digest bytes
therefore agree even when a record uses uppercase hex digits.

A load changes the target before it measures, and an unload or a purge
measures before it changes it. A load that fails before its event can
then be undone, so no upatch runs unmeasured, and a stopped unload
leaves a register that records more than happened, never less. What a
stopped command leaves, the next load or unload undoes under the lock
before it acts, so the register stays behind what runs for one command
at most. A load or unload that cannot read this boot's records, or
cannot undo what they do not cover, refuses rather than act beside pins
it cannot account for.

A load and an unload hold the lock from before the undo pass, so that
the pass never takes a load in flight for a stopped one. A purge holds
it from its archive read, so that a load of the same name cannot come
between the purge's event and its removal, and checks the signer on
what that read finds: an upgrade that replaced the upatch since the
revocation's scan with one another key signed leaves it in place.

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
this boot's upatch records are the register's upatch events in order
but for appends that failed after their extension, and an ``init`` whose
every restore succeeds restores exactly the archives, of those its
config's revocations left, whose last record is their load. The model
takes the lock to exclude and ``init`` to run as one step, which the
gate that refuses every command until ``init`` completes justifies. It
leaves out the boot in which enforcement never came up, where the gate
admits commands and their undo pass refuses for want of an ``init``
record. CBMC shows that ``measured_event()`` and ``measured_holds()``
fold the records as the model does. The proofs are in
:doc:`/contribute/testing/proof-coverage`.

Evidence
--------

``shirudo attest`` asks the TPM for two signed statements and collects
what a verifier needs to check them. It needs no enrollment state on the
target and leaves none. Figure 4 shows one run, with the credential
activation that enrollment adds.

.. figure:: /images/internals-attest-evidence.svg
   :alt: The operator runs attest predict and sends a nonce, with a
         credential challenge at enrollment. The target has the TPM create
         the attestation key from its fixed template, activate the
         credential when there is a challenge, quote the PCRs and certify
         the register with the nonce. It returns an evidence document with
         this boot's eventlog, and the operator runs attest verify.

   Figure 4. Collecting evidence. The operator holds no TPM; the nonce,
   the challenge and the document travel by whatever channel the operator
   uses to reach the target.

The attestation key is a primary under the endorsement hierarchy with a
fixed template: ECC NIST P-256, ECDSA with SHA-256, ``restricted`` and
``sign``, no authorization value and no policy. A primary with a fixed
template is derived from the endorsement seed, so the same TPM always
yields the same key and the same name. ``restricted`` means the key signs
only structures the TPM itself produced.

The evidence document carries:

- a TPM quote of the selected SHA-256 PCRs, by default 0 to 7, 9 and
  11 to 15, plus the config PCR when selected;
- two certifications of the patch register, one before the PCR quote
  and one after it. In config NvPCR mode, the TPM certifies that index
  on both sides of the same quote as well;
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

The evidence binds the readings in this order. The opening certifications
carry the verifier's nonce. The quote carries the SHA-256 digest of two
32-byte values concatenated in order. The first is the SHA-256 digest
of the patch register's opening signature. The second is the digest of
the config NvPCR's opening signature, or 32 zero bytes when absent.
Each closing certification carries the SHA-256 digest of the quote
signature. All signature digests cover the binary TPMT_SIGNATURE.

For each index the verifier checks the same Name, 32-byte value and TPM
boot on both sides. The indexes can only extend during that boot, so the
certified values held when the TPM quoted the PCRs. If a register changes
during collection, collect again.

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
(:doc:`/reference/cli/attest`) and records their names. Figure 5 sets the
two side by side. Both end in the same pinned names, and ``verify``
checks evidence the same way after either.

.. figure:: /images/internals-attest-names.svg
   :alt: Credential activation: the target sends evidence, the operator
         makes a challenge for an endorsement key it vouches for, the TPM
         releases the credential only to that attestation key, and verify
         checks it once. Builder-recorded names: the builder creates both
         keys in the TPM before handover and records their names. Both
         paths end in the inventory every later verify pins.

   Figure 5. Two ways to learn the attestation key's name.

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
verdict. Figure 6 shows the four comparisons that tie what the target
wrote about itself to what the TPM signed or the operator computed.

.. figure:: /images/internals-attest-verify.svg
   :alt: The eventlog replay must equal the certified register value; the
         name computed from the init record must equal the certified name;
         pcr_before extended by the anchor digest must equal the quoted
         PCR 9; the init event must equal the one attest predict computes.

   Figure 6. What ``verify`` compares. Once the replay matches, the
   ``init`` record's fields are the ones the TPM measured.

It checks, in this order:

#. the nonce;
#. the attestation key: a restricted signing key with the required
   attributes, its name matching its public area, and with ``--ak-name``
   the pinned name; the endorsement key's template and name, and with
   ``--ek-name`` and ``--expect-credential`` the pinned key and the
   credential;
#. the quote's signature and signer, its commitment to the opening
   certifications, the PCR selection and the digest of the listed values;
#. both register certifications, including the request nonce on the
   opening reading and the commitment to the signed quote on the closing
   one. Both must certify the listed name and value and share the quote's
   reset count, restart count and firmware version;
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

``config.nvpcr = shirudo-config`` chooses the config NvPCR instead, NV
index ``0x01818E04``, and leaves every PCR to its usual owner. systemd
defines the NvPCR in the initrd from a ``shirudo-config.nvpcr``
definition, before the guards attach, initializes it to
``SHA256(0^64)`` and anchors its name in PCR 9. Its write policy is
``PolicyOR`` of the UKI's signed PCR 11 policy under the ``initrd``
reference and ``PolicyNvWritten``; shirudo asserts the second branch,
with the first read from ``/run/systemd/nvpcr/shirudo-config.auth``,
after checking that the index is an initialized extend index writable
only under exactly that policy. The events and their digests are the
same; only the register differs.

Each event is ``SHA256("shirudo-config-root-v1\0" || kind ||
root_hash)``, with the kind as a big-endian 32-bit number, 1 for the boot
event and 2 for a live update, and the 32-byte binary root hash. The
first event of a TPM boot records the PCR's value before it as
``initial_pcr``; the journal under ``/var/lib/shirudo/config-update``
records the sequence, the TPM's reset and restart counts and the root of
each event. :doc:`config-images` explains activation.

Evidence includes the config PCR in the quote and the config history:
the events of the TPM's reset count, which a resume or a TPM restart
keeps. ``verify`` with ``--expect-config-root`` and
``--expect-config-pcr`` derives each event digest, requires one boot
event followed by updates in sequence for the quote's reset count, a
replay from ``initial_pcr`` that reaches the quoted PCR value, and the
expected root as the selection. The restart count the history carries is
not compared.
With the config NvPCR (``config.nvpcr``) the evidence includes, instead of
the config PCR, a ``config_nvpcr`` object: the index's name and an
AK-signed certification of its contents on each side of the quote.
``verify`` requires both certifications from the quote's TPM boot, a history
that starts at ``SHA256(0^64)``, and a replay that reaches the certified
contents; ``--expect-config-nvpcr=<name>`` pins the index's name, which the
platform computes from its PCR public key.

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

A config PCR is a shared register.
    The guard reserves the configured PCR, but it is also a PCR other
    software may expect to own, and its value at the first event is
    whatever it held. The config NvPCR is Shirudo's alone and starts at a
    known value.

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

TPM command authority
======================

The kernel ``tpm_command`` LSM hook runs after the TPM driver copies a
userspace command into its buffer and before it submits the command. The BPF
guard therefore checks every write to the raw and resource-manager devices,
including writes through a descriptor another task opened. It does not inspect
kernel-internal TPM commands. The classifier is ``include/shirudo/tpm_command.h``;
the BPF program and the unit test include the same code.

The policy is frozen during authenticated initialization:

* Only the full Shirudo task role may mutate the measurement register
  ``0x01818E00``: definition, deletion, extension, writes, increments, bit
  changes, authorization changes and read/write locks.
* Only the full role may extend, reset or change the authorization of the
  configured config PCR.
* systemd defines its NvPCRs in the UAPI.19 Linux range
  (``0x01D10200`` to ``0x01D105FF``) from the initrd, before the guards attach,
  and anchors each in PCR 9. Afterwards it only extends them. Extensions stay
  available; every other mutation of an index in that range needs the full
  role, so no root process can delete and recreate an NvPCR that its anchor
  names.
* Every other PCR stays the platform's. systemd's ``systemd-pcrmachine`` and
  ``systemd-pcrfs`` extend PCR 15 as root, for example.
* The config NvPCR ``0x01818E04`` is Shirudo's: every mutation, extensions
  included, needs the full role. With it, the config PCR is free, so PCR 13
  is systemd-stub's again.
* Hierarchy changes, clear, global write locks, shutdown and other
  measurement-affecting administration need the full role, as do unknown and
  vendor commands. ``TPM2_Startup`` stays available: systemd probes a TPM that
  the firmware already initialized. Malformed headers and handle encodings are
  refused.
* Known read, attestation, session and cryptographic commands stay available.
  Unrelated NV indices keep their normal TPM authorization.

Denials increment ``TpmWrite`` in the tamper counters. ABI pre-flight rejects a
kernel without the hook. ``testing/helper/test-tpm-command`` covers the
classifier and ``testing/fuzz/fuzz-tpm-command`` fuzzes it.
