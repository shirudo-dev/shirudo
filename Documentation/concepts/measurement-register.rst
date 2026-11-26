..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

Measurement register
====================

Every change to a target's BPF state is recorded in a register inside the
target's TPM, and the TPM signs that record on request. This page explains
why the record lives in a per-boot TPM register, what it records, what the
eventlog beside it is for, and what attestation proves and what it does
not. :doc:`/internals/measurement-register` describes the register's
attributes, policy and evidence format in full.

Why the TPM
-----------

A target reports its own state through ``shirudo status``. That report is
the target's word. On a compromised target, root controls the files and
processes that produce it, and a status that says ``ok`` is what an
attacker would arrange.

An operator needs a record that root cannot rewrite afterwards, and a
signature on it that root cannot forge. A TPM provides both. A value it
holds can only be extended, never set, and it signs reports with keys that
never leave it. :doc:`/concepts/background/tpm` explains these operations.

Why not a PCR
-------------

The obvious place for the record is a PCR. On a typical Linux system the
firmware, the boot loader, systemd and IMA already measure into the PCRs,
and the one meant for applications, PCR 23, can be reset. A PCR also
accepts an extend from any process that can talk to the TPM, so it would
record events shirudo never made.

We use an NV extend index instead, the construction systemd uses for its
NvPCRs. It is a slot in the TPM's non-volatile memory that behaves like a
PCR: a write replaces its value with SHA-256 over the old value followed
by the event, and the value clears at every TPM reset. Its default handle
is ``0x01818E00``.

Why per boot
------------

BPF programs do not survive a reboot. At every boot, ``init`` loads the
archived upatches again and starts the register from zero, so the register
describes this boot's kernel and nothing older.

A per-boot register has a second benefit. Its value is a function of four
inputs: the trusted certificates, the upatch set restored at boot, the
upatch tree's projection root, and the events since boot. The operator
computes it with ``shirudo attest predict`` from files it already has, and
needs no history from the target.

Who can write it
----------------

A register is only as good as its writers. If any process could extend
it, root could record a load that never happened, and a correct value
would prove nothing.

The index's write policy requires a signature from a writer key for every
extend. ``init`` creates that key inside the TPM at boot, and the private
part never leaves the TPM. Each signature covers one exact extend command,
so it cannot be reused for another event. The first write of a boot is
possible only while PCRs 9 and 11 still hold the values ``init`` read when
it computed the policy. In production, ``init`` binds the register from
the initrd, before systemd moves PCR 11 on leaving it.

The writer key is not a secret, because any process can ask the TPM to
sign with it. What stops root is a BPF LSM program on the kernel's
``tpm_command`` hook: it refuses an ``NV_Extend`` of shirudo's index to
every task without runtime authority. That hook comes from a kernel patch
shirudo carries (:doc:`/internals/kernel-patches`). Figure 1 shows one
write, and the same attempt by root.

.. figure:: /images/concepts-register-write.svg
   :alt: A sequence between a task, the kernel's lsm/tpm_command hook
         and the TPM. upatch load, with runtime authority, starts a
         policy session on one of the two branches, has the NV writer
         key sign the session nonce and this exact NV_Extend, and sends
         NV_Extend, which the hook passes on and the TPM applies as
         register = SHA-256(register || event). root without runtime
         authority gets the same session and signature, but the hook
         refuses its NV_Extend with EACCES and counts TpmExtend.

   Figure 1. One write of the register. The TPM checks the policy, the
   kernel checks who sends the extension.

Right after binding, ``init`` extends PCR 9 with an anchor, the SHA-256 of
``nvpcr-init:shirudo:0x1818e00:<name>`` for the default index, where
``<name>`` is the index's TPM name. The anchor ties the index to the measured boot, and it moves PCR
9 away from the value the first-write branch needs, so that branch cannot
be satisfied again until the next TPM reset.

What gets recorded
------------------

Each event is SHA-256 over a domain tag followed by the event's fields.
The tags keep an event of one kind from being read as another. Table 1
lists the events.

.. list-table:: Table 1. Register events
   :header-rows: 1
   :widths: 18 42 40

   * - Event
     - When
     - Covers
   * - ``init``
     - Once per boot, when ``init`` binds the register
     - The trusted certificates, the restored upatch set and the tree's
       projection root
   * - upatch load
     - After a load is attached, pinned and archived
     - The payload digest and the upatch name
   * - upatch unload
     - Before an unload removes the pins
     - The payload digest and the upatch name
   * - tree operation
     - After ``bpm tree sync`` applied an operation
     - The operation's sequence number and digest
   * - key revocation
     - When ``shirudo image update`` activates a config that revokes an
       enrolled key, followed by an unload event for each loaded upatch
       that key signed
     - The revoked certificate's digest

A revocation applied at boot is not an event of its own. The ``init``
event covers the certificates that remain trusted.

Boot restore adds exactly one event, the ``init`` event, however many
upatches it restores, and a second run of ``init`` in the same boot adds
none. A state-changing command refuses with ``tampered`` when the register
is not the one ``init`` bound, or when it differs from an
``--expect-chain`` value the caller passed.

A load is measured after it is attached and archived, and undone when
the extend fails. A load process stopped between the attach and the
extend leaves the upatch attached without an event: ``shirudo status``
reports it under the ``UpatchesMeasured`` condition, the next load or
unload undoes it before it acts, and ``init`` at the next boot restores
no archive whose load the eventlog does not record. An unload is
measured before the pins go, so an interrupted unload leaves a register
that records more than happened. :doc:`/reference/eventlog`
lists the fields of each event.

Eventlog
--------

The register holds one digest. The eventlog,
``/var/lib/shirudo/eventlog``, explains it: one JSON line per extend, with
the event digest, its type, the boot ID and the fields the digest covers.
shirudo appends to it and never rewrites it, it keeps the records of every
boot, and the seal protects it like the rest of ``/var/lib/shirudo``. In
the initrd, ``init`` writes its record to ``/run/shirudo/eventlog.pending``,
and the root file system's run adopts it. Figure 2 shows how the register
and the eventlog advance together, and how a verifier replays them.

.. figure:: /images/concepts-register-chain.svg
   :alt: In the TPM, the register goes from v0, 32 zero bytes, to v1, v2
         and v3, each the SHA-256 of the previous value and an event
         digest: d1 for init, d2 for upatch_load of foo, d3 for
         upatch_unload of foo. Each event is also appended to
         /var/lib/shirudo/eventlog as a line with its type, fields and
         digest. attest verify derives d2 and d3 from their lines'
         fields, folds d1 to d3 from 32 zero bytes and compares the
         result with v3, which the TPM certified for the operator's
         nonce.

   Figure 2. The register and the eventlog during one boot, and the
   replay that checks them.

The eventlog is not trusted on its own. A verifier folds this boot's
records from zero and compares the result with the register the TPM
certified, so a changed digest breaks the replay. For every record after
the ``init`` record it also derives the digest from the record's fields,
so a changed field fails as well. The ``init`` record's fields are not
checked that way: its digest is compared with the one the operator
computes from its own certificates and artifacts, when the operator
passes them.

Register and log advance together. A load or unload that would push the
eventlog past the ``eventlog.max_bytes`` setting refuses with
``eventlog_full`` before it changes anything.

Config image activations are measured separately, into a static PCR that
the runtime image's bootstrap settings select. :doc:`/internals/config-images`
explains that measurement.

Attestation
-----------

To read the register without trusting the target, the operator chooses a
fresh nonce and runs ``shirudo attest --nonce=<hex>`` on the target. The
TPM certifies the patch register, quotes the selected PCRs and certifies
the register again. The two readings must agree, and each signature is
bound to the preceding step. The default PCRs are 0 to 7, 9 and 11 to 15.
The TPM uses its attestation key, a restricted signing key
that it derives from its endorsement seed with a fixed template, so the
same TPM always yields the same key. The command adds this boot's
eventlog records and the TPM's endorsement key, and writes the evidence
document.

The operator records the attestation key's name once, when it enrolls the
target. Credential activation, ``shirudo attest challenge`` on the
operator host and ``shirudo attest --challenge`` on the target, shows that
the key sits in the same TPM as the endorsement key. With ``--ek-ca``, the
endorsement certificate's chain ties that TPM to its manufacturer.

``shirudo attest verify`` then checks, on the operator host and without a
TPM:

- that the evidence answers the operator's nonce;
- the signatures, and that the attestation key is the pinned one;
- that the certified register has the name a register bound under
  shirudo's policy must have, given the PCR values recorded at binding;
- that this boot's records replay to the certified value, and that each
  digest after the ``init`` record's follows from its record's fields;
- that PCR 9 carries the anchor;
- with the certificates and artifacts, that the ``init`` event covers
  them, and with an expected value, that the register equals it.

:doc:`/operate/run/attest` shows the procedure.

What attestation proves
~~~~~~~~~~~~~~~~~~~~~~~

With a pinned attestation key, an endorsement key the operator trusts, a
fresh nonce and an expected state, a passing verification shows this: the
TPM, after the nonce was chosen, held a register that ``init`` bound under
shirudo's policy during this boot, whose records explain its value, and
whose value is the one the operator's own certificates and artifacts
produce. Only tasks with runtime authority can extend the register, and
shirudo extends it on every change, so the register describes the BPF
state that shirudo's commands established since boot.

What attestation does not prove
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- It does not show that a upatch is correct, only which upatches were
  loaded.
- It covers what shirudo measured. A compromised kernel, or code running
  in a task with runtime authority, can change BPF state or extend the
  register without the events meaning what they say. The kernel and
  shirudo are trusted.
- ``shirudo attest verify`` passes weaker checks than the ones above when
  the operator omits options. Without ``--ak-name`` it only warns that the
  signer is not pinned. Without ``--cert`` or ``--expect-chain`` it checks
  no expected state, and ``verdict: ok`` then means that the evidence is
  consistent with itself. ``--allow-runtime-events`` accepts any events
  after boot that replay. ``--require-initrd`` reads the target's own
  record, and pinning PCR 11 with ``--expect-bind-pcr`` is what shows that
  the binding happened in the initrd. The :doc:`/security/threat-model`
  lists these among the threats to resolve.
- It says nothing about earlier boots, because the register clears at
  every TPM reset.
- The evidence is signed with ECDSA on P-256, a classical algorithm,
  because TPMs implement no post-quantum signature. The artifacts it
  describes are signed with ML-DSA-87.
- ``shirudo status`` and the telemetry a target exports are not evidence.
  Both are the target's own account, read through the target's own
  software.

Root with the TPM's owner authorization, which is empty on many TPMs, can
undefine the index. From then on every extend fails with ``tpm_error`` or
``tampered``, and verification fails. This denies service, but it cannot
produce a register that verification accepts.

Related
-------

- :doc:`/internals/measurement-register` for the policy, the binding and
  the evidence format
- :doc:`/operate/run/attest` for enrolling and verifying targets
- :doc:`/security/threat-model` for the residual risks of the
  measurement
- :doc:`/concepts/background/boot` for PCRs 9 and 11 in a measured boot
