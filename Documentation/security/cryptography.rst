..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Security reviewers

Cryptography
============

Every cryptographic algorithm shirudo uses, where it uses it, and what
accepts other algorithms. OpenSSL 3.5 or newer provides the userspace
side, tpm2-tss talks to the TPM, and the kernel verifies loader
signatures and config roots. The :doc:`threat-model` gives the threats
each use answers.

Signatures
----------

.. list-table::
   :header-rows: 1
   :widths: 18 22 20 40

   * - Object
     - What is signed
     - Signed by
     - Verified by
   * - upatch loader, load or unload directive
     - The loader's instructions followed by the data of its frozen
       metadata map
     - ``shirudo build`` and ``shirudo bpm build`` on the operator
     - The kernel at ``BPF_PROG_LOAD``, against the ``.bpf`` keyring
       that ``attr.keyring_id`` names
   * - Repository index
     - The index document
     - ``shirudo bpm push``
     - ``shirudo bpm`` on the target, against the repository
       certificate in the signed config image
   * - Tree publication
     - The publication document
     - ``shirudo bpm tree append``
     - ``shirudo bpm tree sync``, against the runtime image's primary
       certificate
   * - Config root
     - The 64 lowercase hex characters of the dm-verity root hash
     - The operator's image tooling, with the config key
     - The kernel when shirudo creates the mapping, against the keyrings
       of assumption A7; ``shirudo image verify`` offline
   * - Vouch
     - The bytes ``shirudo-key-vouch``, a NUL byte, and the DER of the
       vouched certificate
     - ``shirudo keys vouch``
     - ``init`` and ``shirudo image update``, against the certificates
       already in the trusted set

All five use one format, produced by one function on the operator:

- Algorithm: ML-DSA-87 (FIPS 204). The signing code refuses any other
  key, the smaller ML-DSA parameter sets included
- Container: a detached CMS ``SignedData`` with no certificates; the
  signer is named by its subject key identifier. shirudo's own checks
  take the signer only from the certificate they are given, never from
  one the container carries
- With OpenSSL 3.x: signed attributes with a SHA-512 message digest and
  no signing time, because OpenSSL 3.x cannot sign ML-DSA without
  signed attributes and the kernel accepts only SHA-512 for ML-DSA in
  that form
- With OpenSSL 4: no signed attributes; ML-DSA signs the content
  directly

``shirudo genkey`` creates the ML-DSA-87 key and a self-signed X.509
certificate. ``shirudo keys vouch``, ``shirudo keys add`` and the image
tooling for the config certificate refuse a certificate whose key is not
ML-DSA-87.

What accepts other algorithms
-----------------------------

The ML-DSA-87 rule is enforced where shirudo signs, not everywhere it
verifies:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Verifier
     - Accepts
   * - Kernel, loader signatures
     - Any algorithm the kernel's X.509 and PKCS#7 code supports for a
       certificate in ``.bpf``. ``init`` enrolls the runtime image's
       certificate and the vouched signers without checking their
       algorithm. The pre-flight check ``cert_algorithm`` refuses
       anything but ML-DSA-87, but in the initrd it reads
       ``/etc/shirudo/keys``, not that set (threat model U4).
   * - Target, config roots
     - ML-DSA-87 under one of the runtime bootstrap's config certificates.
       The target checks this exact set before the kernel's dm-verity
       signature check (threat model A7).
   * - ``shirudo bpm``, indexes and tree publications
     - Whatever algorithm the repository certificate or active BPF signer holds
       (threat model U4).
   * - Vouch check on the target
     - Whatever algorithm the vouching certificate holds; the vouched
       certificate's algorithm is not checked on the target.
   * - TLS peers and endorsement key certificates
     - Whatever their certificate authorities use (residual risk R9).

Certificate validity
--------------------

No verifier enforces a certificate's validity period. shirudo's own
CMS and chain checks for signatures set ``X509_V_FLAG_NO_CHECK_TIME``.
The kernel compares a signature's signing time with the signer's
validity only when the signature carries a signing time, and shirudo's
signatures carry none: every one is made with OpenSSL's
``CMS_NO_SIGNING_TIME``. ``shirudo genkey`` writes no expiration date;
the certificate's ``notAfter`` is ``99991231235959Z``, the value RFC 5280
gives a certificate with no well-defined expiration. ``shirudo status``
and ``shirudo keys`` show only the date a certificate was issued. Retire
a key by revoking it (residual risks R13 and R16).

Digests
-------

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Use
     - Algorithm
     - Input
   * - Payload digest of an upatch (``payload_sha256``)
     - SHA-256
     - The signed bytes: loader instructions followed by the map data
   * - ``excl_prog_hash`` of the metadata map
     - SHA-256
     - The loader's instructions
   * - Register events
     - SHA-256
     - A domain tag (``shirudo-init``, ``shirudo-upatch``,
       ``shirudo-unload``, ``shirudo-key-revoke``, ``shirudo-tree``)
       followed by the event's fields
   * - Register value
     - SHA-256
     - The TPM's NV extend: the old value followed by the event
   * - Register anchor in PCR 9
     - SHA-256
     - The string ``nvpcr-init:shirudo:0x1818e00:<name>``, where
       ``<name>`` is the index's TPM name in hex
   * - Config activation events
     - SHA-256
     - ``shirudo-config-root-v1``, the event kind and the root hash
   * - Certificate identity
     - SHA-256
     - The certificate's DER (``cert_sha256``) and its public key
       (fingerprint)
   * - OCI manifests and blobs
     - SHA-256
     - The content, compared with the ``sha256:`` digest that references
       it
   * - dm-verity images
     - SHA-256
     - Hash tree format 1 with 4096-byte data and hash blocks
   * - CMS signed attributes, OpenSSL 3.x
     - SHA-512
     - The signed content
   * - Seal label
     - SHA-256
     - The xattr name; the label is a public constant, not a secret

TLS
---

Every HTTPS connection, to a registry, an image download or a
collector, uses the same policy:

- TLS 1.3 only.
- Key exchange groups ``X25519MLKEM768`` (preferred) and
  ``SecP256r1MLKEM768``, both hybrid with ML-KEM-768.
- ``tls.classical_hosts`` in the runtime image's bootstrap settings
  lists exact host names that may also use ``X25519`` and
  ``secp256r1``. Each host of a redirect must be listed itself, and
  shirudo logs a warning when a classical group is negotiated.
- Cipher suites: OpenSSL's TLS 1.3 defaults; shirudo does not set them.
- The peer certificate is verified against the system's certificate
  authorities, or a CA file that ``BPM_OCI_CA_FILE`` or the export
  settings name. ``map_export.otel_insecure`` turns verification off
  for a collector.

TPM
---

.. list-table::
   :header-rows: 1
   :widths: 22 38 40

   * - Object
     - Algorithm
     - Use
   * - Attestation key
     - ECDSA on NIST P-256 with SHA-256; a restricted signing primary
       with a fixed template under the endorsement hierarchy
     - Signs ``TPM2_Quote`` and ``TPM2_NV_Certify`` with the verifier's
       nonce, up to 64 bytes. The operator pins its name after enrollment.
   * - Endorsement key
     - The TCG default template, RSA-2048 with the exponent 65537 or ECC
       P-256, with AES-128 in CFB mode as its symmetric algorithm
     - Credential activation for ``shirudo attest challenge``; the ECC
       primary also salts TPM sessions, with its name frozen at init
   * - Credential
     - RSA-OAEP with SHA-256 and the label ``IDENTITY`` for an RSA
       endorsement key, or an ephemeral ECDH on P-256 with KDFe for an
       ECC one; then KDFa with HMAC-SHA256, AES-128-CFB and HMAC-SHA256
     - Made in software by ``shirudo attest challenge`` on the operator
   * - Endorsement certificate chain
     - X.509, verified with OpenSSL against the ``--ek-ca`` bundle; an
       intermediate in the bundle counts as a trust anchor
     - ``shirudo attest challenge``
   * - NV writer
     - RSA-3072, exponent 65537, RSASSA-PKCS1-v1_5 with SHA-256; an
       owner-hierarchy primary whose unique field is a 32-byte random
       seed drawn at each boot
     - Signs, inside the TPM, the SHA-256 of the session nonce, a zero
       expiration, the command hash of the exact ``TPM2_NV_Extend`` and
       the policy reference ``shirudo-nv-writer-v1``
   * - Measurement register
     - NV extend index ``0x01818E00`` with SHA-256 as its name algorithm
     - The write policy: ``PolicyOR`` of ``PolicyNvWritten`` and of
       ``PolicyNvWritten`` with ``PolicyPCR`` over PCRs 9 and 11 in the
       SHA-256 bank, then ``PolicySigned`` by the NV writer and
       ``PolicyCommandCode`` for ``TPM2_NV_Extend``
   * - PCRs
     - The SHA-256 bank
     - Reads, quotes, the anchor in PCR 9 and the config PCR

Sessions and authorization:

- SHA-256 HMAC and policy sessions are salted with the standard ECC
  endorsement primary whose name ``init`` freezes. Successful responses,
  including NV, PCR and clock readbacks, are authenticated. The HMAC
  session has the audit attribute to cover commands without an
  authorization handle.
- The sessions are unbound and have no symmetric algorithm: parameters
  are not encrypted. The owner authorization from ``tpm.owner_auth`` is
  used in HMAC authorization, not transmitted as a password. Initial
  endorsement-primary creation uses the empty endorsement authorization
  and trusts the initrd's TPM device.

Key custody
-----------

.. list-table::
   :header-rows: 1
   :widths: 24 30 46

   * - Key
     - Where it lives
     - Custody
   * - Signing key
     - ``signing_key.pem`` beside ``cert.der`` in the operator's key
       directory
     - An unencrypted PEM file. The signing code refuses one that is
       not a regular file of mode ``0600``. Only ``shirudo-build`` links
       the signing code, and no target holds the key.
   * - Config key
     - With the operator
     - Signs config roots; its certificate travels in the runtime image
       and is enrolled in ``.dm-verity``.
   * - Attestation, endorsement and NV writer keys
     - In the TPM
     - The private parts never leave the TPM. The primaries are
       recreated from their templates when needed. The NV writer's seed
       is in the identity map and is not secret.
   * - TPM owner password
     - ``tpm.owner_auth`` in the runtime image's settings
     - Readable by root on the target (residual risk R20).

Related
-------

- :doc:`threat-model`, threats T5, T8 and T9 and residual risk R9
- :doc:`/concepts/background/bpf-signing` and
  :doc:`/concepts/background/tpm` for the background
