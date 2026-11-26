..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

TPM 2.0 and how shirudo uses it
===============================

A :term:`target`'s TPM 2.0 does two jobs for shirudo. It holds a per-boot
:term:`measurement register` that records every change to the
target's BPF state, and it signs evidence about that register and
the boot PCRs, so that an :term:`operator` can cryptographically verify the
target's state.
This page explains how shirudo uses the TPM. The event formats and the
:term:`eventlog` are in :doc:`/internals/measurement-register`, the
verification procedure in :doc:`/operate/run/attest`.

Every target needs a TPM 2.0 with an active SHA-256 PCR bank. There is
no unmeasured mode. The :term:`operator host` does not use a TPM.
Table 1 lists the TPM objects shirudo uses.

.. list-table:: Table 1. TPM objects shirudo uses
   :header-rows: 1
   :widths: 22 30 48

   * - Object
     - Kind
     - Purpose
   * - :term:`Measurement register <measurement register>`
     - :term:`NV extend index` ``0x01818E00``, owner hierarchy
     - Records ``init``, :term:`upatch` loads and unloads, tree operations and
       key :term:`revocations <revocation>`. Clears at every TPM reset and
       TPM restart.
   * - :term:`NV writer key`
     - RSA-3072 primary key, owner hierarchy
     - Authorizes each extension of the register. A new key every
       host boot.
   * - :term:`Attestation key <attestation key>`
     - ECC NIST P-256 primary key, endorsement hierarchy
     - Signs quotes and NV certifications. The same key for the life
       of the TPM's endorsement seed.
   * - :term:`Endorsement key <endorsement key>`
     - RSA 2048 or ECC NIST P-256 primary key, endorsement hierarchy
     - Ties the :term:`attestation key` to a certified TPM through credential
       activation.
   * - PCR 9
     - SHA-256 bank
     - Carries the register's :term:`anchor`.
   * - Config PCR
     - SHA-256 bank, chosen by ``config.pcr``
     - Records :term:`config image` activations, see
       :doc:`/internals/config-images`.

Roots of trust
--------------

A TPM is a small security processor separate from the main CPU: a
discrete chip, a firmware TPM in the processor's secure environment,
or a virtual TPM that a hypervisor or ``swtpm`` provides to a virtual
machine. It keeps keys and registers in shielded memory that only its
own commands can reach, and it never releases a private key it
generated.

Early boot stages hash the code and configuration they load and extend
those hashes into the TPM's PCRs; see :doc:`boot`. The TPM protects the
accumulated measurement values and signs evidence about them on request.
shirudo relies on the boot chain to measure what actually runs, and on
the TPM to preserve and report the results.

Hierarchies and seeds
---------------------

TPM 2.0 groups its keys into hierarchies. Each hierarchy has a secret
seed that never leaves the TPM and its own authorization:

- The platform hierarchy belongs to the firmware. Its seed is the
  platform primary seed, and its authorization is not available to the
  operating system.
- The storage, or owner, hierarchy belongs to the machine's owner. Its
  seed is the storage primary seed, its authorization the owner
  authorization. ``TPM2_Clear`` replaces the seed, which invalidates
  every key derived from it.
- The endorsement hierarchy carries the TPM's identity. Its seed, the
  endorsement primary seed, is created at manufacturing and changes
  only through ``TPM2_ChangeEPS`` under platform authorization. Its own
  authorization is the endorsement authorization.
- The null hierarchy has a seed that the TPM replaces at every reset.
  Its keys last until the next reset.

shirudo uses the owner hierarchy for the :term:`measurement register` and the
:term:`NV writer key`, and the endorsement hierarchy for the
:term:`attestation key` and the :term:`endorsement key`. It never uses the
platform or null
hierarchies. When the TPM has an owner authorization, shirudo takes it
from ``tpm.owner_auth`` in its authenticated configuration. The
endorsement authorization must be empty: shirudo has no setting for
it.

Primary keys from templates
---------------------------

A TPM can hold only a few keys at a time, so TPM 2.0 lets software
derive keys again instead of storing them. ``TPM2_CreatePrimary``
takes a hierarchy and a template, the public area of the key: its
algorithm and size, attributes, policy, and a ``unique`` field the
caller may fill with any bytes. The TPM derives the key from the
hierarchy's seed and the template. The same seed and the same template
give the same key every time, so the key needs no persistent slot.
Software creates it when it needs it and flushes it afterwards.

A key's Name is its name algorithm followed by the hash of its public
area. The Name commits to the public key and to every attribute, so
two parties that agree on a Name agree on the key and on what the TPM
allows it to do.

shirudo keeps no persistent objects in the TPM. Each command creates
the keys it needs and flushes them before it exits. The
:term:`attestation key`'s template is fixed, so its Name stays the same as
long as the endorsement seed does, and an :term:`operator` can pin it once
at enrollment.
The :term:`NV writer key`'s ``unique`` field is 32 random bytes that ``init``
draws at every host boot, so every boot has its own writer key.
``init`` freezes those bytes and the resulting public modulus in
shirudo's :term:`identity map`, a BPF map nothing can change for the rest of
the boot. Every later command creates the key again from the frozen
bytes and refuses one whose modulus differs. A ``TPM2_Clear`` replaces
the owner seed, so the key no longer matches and extensions fail
closed.

Endorsement key and certificate
-------------------------------

The :term:`endorsement key` (EK) is the TPM's identity. It is a primary key in
the endorsement hierarchy created from a template that the TCG
defines, so anyone who knows the template knows which key a given TPM
derives. The manufacturer creates the key at production, signs a
certificate for it and stores the certificate in the TPM's NV memory:
the RSA 2048 certificate at NV index ``0x01C00002``, the ECC NIST
P-256 one at ``0x01C0000A``. A verifier that trusts the manufacturer's
certificate authority can tell that an EK belongs to a genuine TPM.

The EK is a restricted decryption key, and its policy,
``TPM2_PolicySecret`` on the endorsement hierarchy, requires the
endorsement authorization to use it. It cannot sign. It decrypts
secrets that were encrypted to it, which is how credential activation,
described below, proves where another key lives.

``shirudo attest`` reads the EK certificate, the ECC one first, and
creates the EK of the certificate's type from the TCG default
template. If no certificate is found it creates the default ECC EK.
The :term:`evidence` carries the EK's public area and the certificate.
``shirudo attest challenge`` checks that the public area is the
TCG default template under the endorsement policy and that the
certificate describes that key. With ``--ek-ca`` it also checks
that the certificate chains to those issuers. Otherwise the
:term:`operator` pins the EK with ``--ek-name``, or accepts any EK
with ``--trust-presented-ek``.

Attestation keys
----------------

A key that signs whatever a caller asks would make a quote worthless,
because software could have it sign a quote it made up. A restricted
signing key can only sign structures the TPM
built itself, such as PCR quotes, which start with the
value ``TPM_GENERATED_VALUE`` (``0xFF544347``). It refuses to sign
outside data that could pass for one. A structure that starts with
that value and carries a valid signature by a restricted key came from
the TPM that holds the key.

shirudo's :term:`attestation key` (AK) is an ECC NIST P-256 primary key in the
endorsement hierarchy that signs with ECDSA and SHA-256. Its attributes
are ``fixedTPM``, ``fixedParent``, ``sensitiveDataOrigin``,
``userWithAuth``, ``restricted`` and ``sign``, and it has no
authorization value and no policy. ``shirudo attest`` creates the AK
when it collects evidence. ``attest verify`` checks that the AK's public
area has these attributes, that the Name matches the public area and,
with ``--ak-name``, that it is the key the operator pinned at enrollment.

PCRs, banks and extension
-------------------------

A PCR holds a digest that software can only extend: the TPM replaces
the value with the hash of the old value and the new digest. A TPM
keeps one bank of PCRs per hash algorithm, typically SHA-1 and
SHA-256, and an extension names a digest for each bank it changes. A
PC Client TPM has 24 PCRs per bank. A TPM reset or restart returns
them to their initial values (Table 2). Apart from a few PCRs that are
resettable on purpose, such as PCR 23 for applications, nothing else
does. Any process that can send commands
to the TPM can read the PCRs and extend the ones the operating system
uses. :doc:`boot` lists who extends which PCR during a boot.

shirudo uses the SHA-256 bank only, and ``init`` refuses a TPM
whose SHA-256 bank lacks PCR 9 or PCR 11. ``init`` reads PCRs 9 and 11
when it binds the register and extends PCR 9 with the
:term:`anchor`. When shirudo activates a :term:`config image`,
it extends the PCR selected by ``config.pcr`` with a measurement
identifying that image.
``shirudo attest`` quotes PCRs 0 to 7, 9 and 11 to 15 by default, and
the config PCR as well when a config image is active.

NV indices and the extend type
------------------------------

Besides PCRs, a TPM has NV indices: storage locations that an owner
defines with ``TPM2_NV_DefineSpace``. Each has a handle, a size,
attributes, an authorization value and a policy. Their types include
ordinary data, counters, bit fields and
NV extend index.
An :term:`NV extend index` behaves like a PCR:
``TPM2_NV_Extend`` sets it to the hash of
the old value and the new data. The first extension after the index
is defined starts from a zero digest and sets the attribute
``TPMA_NV_WRITTEN``.

The attributes decide who may read and write an index and when it
clears. ``TPMA_NV_CLEAR_STCLEAR`` clears the index's ``TPMA_NV_WRITTEN``
flag at every TPM reset and restart, so the next permitted extension
starts from a zero digest.
``TPMA_NV_ORDERLY`` lets extensions update the value in TPM RAM without
requiring a nonvolatile data write after every operation. This reduces
persistent-storage writes for a history that only needs to last for the
current boot.

An index's Name is the hash of its public area: handle, hash algorithm
identifier, attributes, policy and size. ``TPMA_NV_WRITTEN`` is one of
the attributes, so the Name changes at the first write. Unlike a PCR,
an index can be deleted with ``TPM2_NV_UndefineSpace`` and defined
again by anyone who satisfies the owner authorization. A recreated
index starts empty. This is why shirudo extends PCR 9 with the
:term:`anchor`, which incorporates the :term:`measurement register`'s
Name after its first write. Deleting the NV index does not remove
that anchor from PCR 9. A deletion and recreation of the NV index
with the same policy cannot be initialized since the policy requires
the old PCR 9 value which shirudo extended with the anchor.

shirudo's register is the index ``0x01818E00``, which a build can
change with ``NV_INDEX`` in :src:`util/paths.h`. It holds one SHA-256
digest and has the attributes ``0x0E060048``: ``TPM2_NT_EXTEND``,
``TPMA_NV_POLICYWRITE``, ``TPMA_NV_OWNERREAD``, ``TPMA_NV_AUTHREAD``,
``TPMA_NV_NO_DA``, ``TPMA_NV_ORDERLY`` and ``TPMA_NV_CLEAR_STCLEAR``.
Its authorization value is empty, so anyone can read it, and only a
policy session can write it. It is an NV index rather than a PCR
because a typical Linux system has no PCR that are not used already.

Authorization and sessions
--------------------------

Each TPM connection creates the standard ECC :term:`endorsement key`
and uses it to salt SHA-256 HMAC and policy sessions. ``init`` freezes
the EK's Name in the :term:`identity map` during trusted initrd setup.
Later connections require that same Name. Initial EK creation uses the
empty endorsement authorization before a session is established and
trusts the TPM device.

The HMAC session authorizes key creation, definition and deletion of
the :term:`measurement register`, register reads and signing. The owner
authorization from ``tpm.owner_auth`` is used in HMAC authorization,
not sent as a plaintext password. Register reads and signing use empty
authorization values. Even reads that require no permission use an authenticated
session, so a proxy cannot substitute the returned values.

Extending the register starts a new authenticated policy session in the TPM.
shirudo uses policy commands in that session to satisfy the register's write
policy.  The TPM checks that the session's policy digest matches the register's
policy and that its restrictions hold when executing the extension.  shirudo
uses these commands:

- ``TPM2_PolicyNvWritten`` requires an unwritten index for the first
  extension, or an already written index for later extensions.
- ``TPM2_PolicyPCR`` ties the first extension to the values of PCRs 9
  and 11 recorded at initialization.
- ``TPM2_PolicyOR`` accepts either the first-write or the already-written
  branch.
- ``TPM2_PolicySigned`` requires the :term:`NV writer key` to sign an
  authorization tied to the session's nonce and a command hash. This
  SHA-256 hash covers the command code, the target index's Name and the
  event data, so the authorization cannot be reused for a different index
  or event.
- ``TPM2_PolicyCommandCode`` restricts the authorized command to
  ``TPM2_NV_Extend``.

Before submitting the extension, shirudo calls ``TPM2_PolicyGetDigest``
through the authenticated session and compares the session's digest
with the policy it computed in software. The next section explains how
these conditions protect the register.

Credential activation uses a separate policy session for the
:term:`endorsement key`. shirudo satisfies that policy with
``TPM2_PolicySecret``, using the empty endorsement-hierarchy authorization.

Salted policy sessions authenticate successful extension replies. The
sessions do not encrypt command parameters. The TPM signatures on
attestation :term:`evidence` are separate from session authentication.
:doc:`/internals/measurement-register` describes the session checks in
detail, and `Limits`_ describes the transport risks.

Register binding
----------------

The register records what shirudo did. Root on
the :term:`target` must not be able to add events of its own, delete the
register and start a fresh history, or initialize the register later
in the boot process. An NV index alone stops none of this: root can define
an index, write it and delete it. We combine the policy assertions
above, the boot phases that :doc:`boot` describes and an LSM hook.

:ref:`Figure 1 <tpm-register-binding-figure>` shows how ``init`` binds the
register from the initrd.

.. _tpm-register-binding-figure:

.. figure:: /images/background-tpm-register.svg
   :alt: PCR 9 and PCR 11 values enter the write policy, the policy
         defines the NV index, and its public fields after the first write
         determine the anchor digest extended into PCR 9.

   Figure 1. Binding the register: (1) read PCRs 9 and 11, (2) define
   the index with the write policy, (3) write the first event through
   the init branch, (4) extend PCR 9 with the :term:`anchor`.

1. Compute the policy. ``shirudo init`` reads PCRs 9 and 11 and
   computes a policy that requires those values for the first write.
   Both the first and later writes require the :term:`NV writer key` to
   authorize the exact extension command. It also computes the index's
   expected Names before and after the first write.
2. Define and check the index. ``init`` defines it with that policy,
   replacing any index at the handle that is written or has another Name.
   It refuses with ``EPROTO`` if the Name the TPM reports differs from the
   expected one.
3. Write the initial event. ``init`` obtains the writer key's signature
   and checks the session's policy digest before submitting the first
   extension. The TPM enforces the policy and records the init event.
   This sets ``TPMA_NV_WRITTEN``, changing the index's Name.
4. Record the :term:`anchor`. ``init`` extends PCR 9 with the SHA-256 of
   ``nvpcr-init:shirudo:0x1818e00:<written-name>``, systemd's anchor
   format, where ``<written-name>`` is the index's written Name in
   lowercase ASCII hex. The same record goes into systemd's userspace
   measurement log, ``/run/log/systemd/tpm2-measure.log``, as an
   ``nvpcr-init`` event, before systemd measures ``nvpcr-separator``.

The Name contains the two-byte SHA-256 algorithm identifier ``0x000B``
followed by the SHA-256 hash of the index's public fields. Those fields
use TPM wire encoding: integers are big-endian, and the 32-byte policy
digest is preceded by its two-byte length, ``0x0020``. The hash includes
the complete attribute bitmask, with ``TPMA_NV_WRITTEN`` set after the
first write.

After step 4, PCR 9 no longer holds the value the init branch
requires, and once systemd measures ``leave-initrd``, PCR 11 does not
either. Nothing can satisfy the init branch again before the next TPM
reset, so an index that is deleted and recreated under the same policy
can never be written. An index recreated under another policy has
another Name, which matches neither the :term:`anchor` in PCR 9 nor the record
``init`` kept.

Every later extension goes through the written branch, which also
requires the writer key's signature over the session nonce and a SHA-256
hash covering the extension command code, the index's Name and the event
data. Before it extends, shirudo checks that the live index carries the
Name and policy ``init`` recorded, that the TPM
reports the recorded reset count, and that the writer key it creates
from the frozen bytes has the recorded modulus.

The signature alone does not keep other processes out. The bytes the
writer key derives from are not a secret, so any process that recreates
the key could ask the TPM to sign. An LSM hook in the kernel keeps
them out. The companion kernel change in the
:src:`testing/kernel/`
adds an LSM hook, ``tpm_command``, that sees every command written to
``/dev/tpm0`` or ``/dev/tpmrm0`` before the driver sends or queues it.
shirudo's ``lsm/tpm_command``
program refuses ``TPM2_NV_Extend`` of the frozen index to any task
without :term:`runtime authority`. It also refuses, to every task, a command
too short to carry a command code and a ``TPM2_NV_Extend`` too short to
name its index. Each rejection increments the
``TpmExtend`` :term:`tamper counter`. All other
commands pass, including extensions of other NV indices, signing and
PCR extensions.

The construction follows systemd's NvPCRs, which :doc:`boot`
introduces: the same index type, the two-branch policy and the
``nvpcr-init`` :term:`anchor`. It differs in three ways. systemd's written
branch needs no further authorization, so anyone can append to an
NvPCR; shirudo requires a signed, command-bound authorization and the
LSM check on every write, because its events assert that an operation
happened. systemd binds the init branch to PCR 11 through a signed PCR
policy from the UKI, or through a plain ``TPM2_PolicyPCR`` on PCR 11
where none exists; shirudo binds it with a plain ``TPM2_PolicyPCR``
over PCRs 9 and 11, so the register's Name changes with the initrd and
the UKI, and the :term:`operator` pins both values with ``--expect-bind-pcr``.
And the register is not a ``.nvpcr`` definition: systemd neither
initializes nor extends it, and its anchor appears in shirudo's
:term:`eventlog`, not in systemd's measurement log.

Quotes and NV certification
---------------------------

``TPM2_Quote`` signs a ``TPMS_ATTEST`` structure with a restricted
key. The structure carries ``TPM_GENERATED_VALUE``, the qualified Name
of the signing key, the caller's nonce, the TPM's clock information
and firmware version, the PCR selection and the digest of the selected
PCR values. It proves that the TPM held those values when it signed,
and the nonce proves that it signed after the verifier asked.
``TPM2_NV_Certify`` signs the same kind of structure for an NV index,
with the index's Name, an offset and the contents.

``shirudo attest`` collects the selected PCR values and a TPM quote
containing their digest. The TPM certifies the measurement register's
Name and value before and after the quote. The opening certification
answers the verifier's nonce, the quote commits to the opening signatures,
and the closing certifications commit to the signed quote.
The :term:`evidence`
document also carries the public areas of the AK and EK, this boot's
shirudo :term:`eventlog` records, the config history, the firmware
and systemd event logs and the EK certificate.

Only the quote and the certification are signed by the TPM. The rest
of the document is the :term:`target`'s own account, which ``attest verify``
checks against the signed values. In particular, it recomputes the
register's Name from the PCR values and the writer key that the
:term:`init record` names. A register bound under other PCR values or with
another writer key has another Name and fails. :doc:`/operate/run/attest` lists
the checks and the options that pin each value.

Credential activation
---------------------

A signature by an AK proves nothing about where the AK lives until its
Name is tied to a TPM the verifier trusts. The EK certificate
identifies a TPM, but the EK cannot sign. Credential activation
connects the two.

``TPM2_MakeCredential`` needs no TPM; anyone can compute it in software
from the EK's public key. It encrypts a secret so that only the TPM
holding that EK can recover it, and only for a key with a given Name.
``TPM2_ActivateCredential`` takes the EK and a loaded key. The TPM
recovers a seed with the EK, checks an HMAC over the loaded key's
Name, and releases the secret only when the Name matches.

``shirudo attest challenge`` computes the credential on the
:term:`operator host`. It draws a random 32-byte credential and a seed,
which it wraps
with RSA-OAEP under the label ``IDENTITY`` for an RSA EK or derives
from an ephemeral ECDH agreement on P-256 for an ECC EK. From the seed
it derives an AES-128-CFB key and an HMAC key with the TPM's key
derivation function. On the :term:`target`, ``shirudo attest --challenge``
calls ``TPM2_ActivateCredential`` to recover the challenge secret for the
loaded AK and includes the result in the :term:`evidence` document.
On the operator host, ``attest verify --expect-credential`` compares it.
Together with the attribute checks on the AK, this shows that the key
that signed the evidence is a restricted key fixed in the TPM
that holds the EK.

Reset count and clock
---------------------

A TPM keeps a clock and two counters, the reset count and the restart
count. Which of them a power transition moves depends on how the
operating system shut the TPM down before it: ``TPM2_Shutdown(STATE)``
asks the TPM to save its state, and the next ``TPM2_Startup`` either
restores it or starts clear. Table 2 lists the three cases.

.. list-table:: Table 2. TPM startups and what they change
   :header-rows: 1
   :widths: 22 18 22 38

   * - Event
     - Counts
     - PCRs and register
     - shirudo
   * - Reboot: TPM reset, ``Startup(CLEAR)`` without a saved state
     - Reset count up, restart count to 0
     - Both cleared
     - ``init`` binds the register anew from the initrd.
   * - Resume from hibernation: TPM restart, ``Startup(CLEAR)`` after
       ``Shutdown(STATE)``
     - Restart count up
     - Both cleared
     - Refused from ``init`` on, through ``lsm/locked_down``. Should a
       restart happen anyway, the reset count says the TPM boot goes on:
       extensions fail with ``tpm_error``, commands refuse with
       ``EUCLEAN`` as the config PCR no longer holds its replay, and
       ``init`` neither records a config boot event nor binds the
       register again, until a reboot.
   * - Resume from sleep: TPM resume, ``Startup(STATE)`` after
       ``Shutdown(STATE)``
     - Restart count up
     - Both restored
     - The TPM boot goes on: commands run as before, a pending config
       activation stays pending and ``init`` records nothing, until a
       reboot. A command the suspend interrupts refuses.

``TPM2_ReadClock`` reads the counts, and every quote and certification
carries them. For keys outside the
endorsement and platform hierarchies the TPM obfuscates the counts in
signed structures. shirudo's AK is in the endorsement hierarchy, so the
:term:`evidence` carries the real values.

``init`` records the reset count in its :term:`eventlog` record, and uses it
to decide whether it has already bound the register in this TPM
period. An extension refuses when the TPM's reset count is not the
recorded one. ``attest verify`` checks that the quote and the
certification carry the same reset count and that it is the one the
:term:`init record` names. Config activation records both counts.

Device interface
----------------

Linux exposes each TPM as two character devices. ``/dev/tpm0`` is the
raw device. Only one process can have it open at a time, and that
process sees the TPM's real handles and must manage its few slots for
objects and sessions itself. ``/dev/tpmrm0`` goes through the kernel's
resource manager. Any number of processes can open it, and the kernel
swaps objects and sessions in and out so that each open file sees only
its own. The kernel's own TPM users, such as the kernel's
Integrity Measurement Architecture (IMA) and trusted keys,
reach the TPM without either device.

shirudo talks to the TPM through the tpm2-tss library and the
TPM Command Transmission Interface (TCTI)
named by ``tpm.tcti`` in its authenticated configuration,
``device:/dev/tpmrm0`` by default. While an authenticated image is
active it accepts only a ``device:`` TCTI, so its commands pass through
the character device and the ``tpm_command`` hook, and it ignores the
``SHIRUDO_TPM_TCTI`` environment variable.

Limits
------

The :doc:`/security/threat-model` gives the full analysis of each of
these.

- The first TPM contact in the authenticated initrd is trusted.
  ``init`` pins the ECC endorsement primary used to salt later HMAC
  and policy sessions. Successful replies and measurement readbacks are
  authenticated, but a substituted device can still drop requests and
  deny service. See :doc:`/internals/measurement-register`.
- The owner authorization is protected in transit by HMAC authorization,
  but root on the :term:`target` can read it from the
  :term:`runtime image`.
- The ``tpm_command`` guard covers ``TPM2_NV_Extend`` of the register
  only. ``TPM2_NV_UndefineSpace`` with the owner authorization and
  ``TPM2_PCR_Extend`` of PCR 9 or the config PCR remain open to root.
  They cannot rewrite the history, but they stop further extensions,
  fail ``--strict-anchor`` or block config commands until the next
  boot.
- The guard sees commands written to the TPM character devices.
  Kernel-internal TPM use and direct access to the TPM's bus are
  outside it, and every executable in the :term:`runtime image` runs with
  :term:`runtime authority` and can extend the register.
- A TPM restart without a reboot stops shirudo's commands until the
  next reboot, and a resume leaves a pending config activation pending
  until then (Table 2).
- The algorithms are classical: ECDSA P-256 for the AK, RSA-3072 for
  the writer key, RSA 2048 or P-256 for the EK. Version 185 of the
  TPM 2.0 library specification adds ML-DSA and ML-KEM, but shirudo
  does not yet use them. See :doc:`pqc`.
- An EK is only as trustworthy as its certificate chain or the
  enrollment pin. Virtual TPMs usually have no EK certificate.
- ``attest verify`` warns but proceeds without ``--ak-name``, so the
  :term:`operator` has to pin the AK on every verification.

Related
-------

- :doc:`boot` for measured boot, PCR 11 phases and NvPCRs
- :doc:`/internals/measurement-register` for events and the :term:`eventlog`
- :doc:`/operate/run/attest` to attest a :term:`target`
- :doc:`/security/threat-model` for the residual risks
- `TPM 2.0 Library specification
  <https://trustedcomputinggroup.org/resource/tpm-library-specification/>`__
- `TCG EK Credential Profile
  <https://trustedcomputinggroup.org/resource/http-trustedcomputinggroup-org-wp-content-uploads-tcg-ek-credential-profile/>`__
- `TPM2 PCR Measurements Made by systemd
  <https://systemd.io/TPM2_PCR_MEASUREMENTS/>`__
