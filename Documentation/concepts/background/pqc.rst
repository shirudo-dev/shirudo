..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

Post-quantum cryptography
=========================

shirudo signs everything it ships with ML-DSA-87 and negotiates TLS
with a hybrid post-quantum key exchange. This page explains why a
fleet that exists today has to care about quantum computers, what the
new algorithms are, where the industry stands, and exactly which parts
of shirudo use post-quantum and which remain classical.

Problem
-------

RSA, Diffie-Hellman and elliptic-curve cryptography rest on factoring
and discrete logarithms. Shor's algorithm solves both efficiently on a
large enough quantum computer, so such a machine would recover private
keys from public ones. Hash functions and symmetric ciphers fare far
better: the best known quantum attack on them, Grover's search, at most
halves their bit strength, which SHA-256 and AES-256 absorb.

No such computer exists today, and nobody knows when one will. Two
properties of a fleet make that uncertainty a present problem.

Recorded traffic can be decrypted later. An adversary who stores a
TLS session today can recover its keys once a quantum computer exists,
if the key exchange was classical. NIST calls this "harvest now,
decrypt later". Registry passwords and the kernel activity a target
exports can stay sensitive for years.

Trust anchors outlive their algorithms. A target verifies every upatch
against keys enrolled at provisioning, and a device in the field may
run for a decade. If those keys are classical, a future adversary who
can derive the private key from the certificate can sign loaders every
such target accepts. NIST's transition report makes the same point for
code signing on devices whose verification code cannot be updated
after manufacture [#ir8547]_. Swapping the algorithm later means
re-provisioning every target, and NIST estimates that a cryptographic
transition takes 10 to 20 years.

NIST standards
--------------

NIST published three post-quantum standards on August 13, 2024:

ML-KEM (FIPS 203)
    A key-encapsulation mechanism built on module lattices. One side
    publishes an encapsulation key, the other returns a ciphertext, and
    both derive the same shared secret. Parameter sets ML-KEM-512, -768
    and -1024 target NIST security categories 1, 3 and 5.

ML-DSA (FIPS 204)
    A lattice-based signature scheme. ML-DSA-44, -65 and -87 target
    categories 2, 3 and 5. ML-DSA-87 has a 2592-byte public key and a
    4627-byte signature, against 64 bytes for an ECDSA P-256 signature.

SLH-DSA (FIPS 205)
    A stateless hash-based signature scheme whose security rests only
    on its hash function. Its signatures take 7856 to 49856 bytes, and
    signing is slower. shirudo does not use it.

Hybrid key exchange
-------------------

A new algorithm has had less scrutiny than X25519. TLS 1.3 therefore
deploys ML-KEM in hybrid groups. In ``X25519MLKEM768`` the client sends
an ML-KEM-768 encapsulation key together with an X25519 share, and the
server answers with a ciphertext and its own share. Both shared secrets,
concatenated, feed the TLS key schedule, so an attacker has to break
both to recover the session keys. RFC 10024 defines this group
(code point ``0x11EC``) and ``SecP256r1MLKEM768`` and
``SecP384r1MLKEM1024`` [#rfc10024]_.

Hybrid key exchange protects confidentiality. The server still proves
its identity with a classical certificate signature, which an attacker
would have to forge during the handshake, so that part can move later.

Where the industry is
---------------------

- NIST will deprecate quantum-vulnerable public-key algorithms after
  2030 and disallow them under its standards after 2035, and requires
  the most sensitive federal systems to adopt post-quantum key
  establishment by the end of 2030 and signatures by the end of 2031
  [#ir8547]_.
- The NSA's CNSA 2.0 suite for national security systems selects
  ML-KEM-1024 and ML-DSA-87, with LMS and XMSS for firmware signing,
  and schedules software and firmware signing to use only CNSA 2.0
  algorithms by 2030 [#cnsa]_.
- OpenSSL 3.5, released on April 8, 2025 and supported until April
  2030, implements ML-KEM, ML-DSA and SLH-DSA, prefers hybrid groups,
  and sends ``X25519MLKEM768`` and ``X25519`` key shares by default
  [#openssl]_.
- Chrome, Firefox on the desktop, and Apple's iOS, iPadOS and macOS 26
  enable hybrid key exchange by default. Cloudflare reported in October
  2025 that most human-initiated traffic to its network used it
  [#cloudflare]_.
- Linux 7.0 added ML-DSA verification to the kernel's crypto library and
  ML-DSA-44, -65 and -87 keys for module signing
  (``CONFIG_MODULE_SIG_KEY_TYPE_MLDSA_87`` and its siblings). For
  ML-DSA in PKCS#7 with signed attributes, the kernel accepts only a
  SHA-512 message digest (``crypto/asymmetric_keys/public_key.c``).
- Google announced in March 2026 that Android 17 brings ML-DSA to
  Android Verified Boot, the Keystore (ML-DSA-65 and ML-DSA-87) and APK
  signing, and starts moving remote attestation to post-quantum
  certificate chains [#android]_.

What shirudo signs
------------------

``shirudo genkey`` creates only ML-DSA-87 keys, and the signer in
``shirudo-build`` refuses any other key. We chose the largest parameter
set because the key is a trust anchor that has to outlive several
hardware generations. Every signature is a detached CMS (PKCS#7)
signature. OpenSSL 3.x cannot sign ML-DSA in CMS without signed
attributes, so with it the CMS carries them over a SHA-512 digest, the
only digest the kernel accepts for ML-DSA in that form. OpenSSL 4 signs
the content directly. The kernel needs ``CONFIG_CRYPTO_MLDSA`` to
verify either form.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Object
     - Verified by
   * - Signed loaders and unload directives
     - The kernel at ``BPF_PROG_LOAD``, against the ``.bpf`` keyring
   * - Config image roots, the 64 hex characters of the root hash
     - The kernel's dm-verity signature check, against the
       ``.dm-verity`` keyring and the kernel's own trusted keys
   * - Vouches for additional signing certificates
     - shirudo, against the enrolled trust set
   * - Repository indexes
     - shirudo, against the repository certificate in the signed config
   * - upatch tree publications
     - shirudo, against the runtime image's ``keys/cert.der``

``init``'s pre-flight check refuses a certificate in the trust set it
reads whose key is not ML-DSA-87, and ``shirudo keys vouch`` refuses to
vouch for or with any other key. shirudo identifies certificates by the
SHA-256 of their public key. Payload digests, OCI digests, the
measurement register, the TPM PCR bank and the dm-verity hash trees use
SHA-256.

Transport
---------

Every HTTPS client in shirudo, for registries, config image downloads
and OTLP export, requires TLS 1.3 and offers only ``X25519MLKEM768``
and ``SecP256r1MLKEM768``. A server that supports neither fails the
handshake.

``tls.classical_hosts`` lists exact DNS names for which shirudo also
offers ``X25519`` and ``secp256r1``, for servers that do not support
hybrid groups yet. Wildcards and IP addresses are refused, a redirect
must reach a listed host itself, and shirudo logs a warning when such a
connection negotiates a classical group. On a target the list comes
from the runtime image's ``etc/shirudo/shirudo.conf``, on the operator
host from ``/etc/shirudo/shirudo.conf``.

What stays classical
--------------------

- The TPM keys. The attestation key is ECDSA P-256 with SHA-256, the
  endorsement key shirudo accepts is RSA-2048 or ECC P-256, credential
  activation uses RSA-OAEP or ECDH P-256 with AES-128-CFB and
  HMAC-SHA256, and the NV writer key, created at each boot, is
  RSA-3072. TPM evidence and the register's write authorization rest on
  classical assumptions.
- TLS server authentication. Registries and collectors present WebPKI
  certificates, usually RSA or ECDSA.
- Kernel keys outside shirudo's keyrings. The dm-verity check also
  accepts config signatures from the kernel's built-in trusted keys and,
  depending on the kernel configuration, its secondary and platform
  keyrings. Distribution keys there are usually RSA or ECDSA.

Limits
------

shirudo requires ML-DSA-87 when it creates a key, when it signs, when
it vouches and in ``init``'s pre-flight check, but not everywhere it
verifies a signature.
Index and tree signatures are verified with whatever key the configured
certificate holds, and no step refuses a classical repository
certificate.

Certificate validity periods are not enforced. shirudo's own checks
skip them, and its signatures carry no signing time for the kernel to
compare, and ``shirudo genkey`` writes certificates without an
expiration date. A key stops being trusted when a signed config revokes
it, not at a date in its certificate.

``BPM_OCI_SCHEME=http`` turns TLS off for registry access, and
``map_export.otel_insecure`` turns off certificate verification for the
OTLP collector. See :doc:`oci` and the :doc:`/security/threat-model`.

References
----------

.. [#ir8547] NIST IR 8547, `Transition to Post-Quantum Cryptography
   Standards <https://csrc.nist.gov/pubs/ir/8547/final>`__, October 2026.
.. [#rfc10024] `RFC 10024 <https://www.rfc-editor.org/info/rfc10024>`__,
   Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for
   TLS 1.3.
.. [#cnsa] NSA, `Commercial National Security Algorithm Suite 2.0
   <https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF>`__
   and the `CNSA 2.0 FAQ
   <https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/1/CSI_CNSA_2.0_FAQ_.PDF>`__.
.. [#openssl] OpenSSL, `3.5 release notes
   <https://openssl-library.org/news/openssl-3.5-notes/>`__ and
   `release table <https://openssl-library.org/source/>`__.
.. [#cloudflare] Cloudflare, `State of the post-quantum Internet in 2025
   <https://blog.cloudflare.com/pq-2025/>`__.
.. [#android] Google, `Security for the Quantum Era: Implementing
   Post-Quantum Cryptography in Android
   <https://blog.google/security/security-for-the-quantum-era-implementing-post-quantum-cryptography-in-android/>`__.

The standards are `FIPS 203 <https://csrc.nist.gov/pubs/fips/203/final>`__,
`FIPS 204 <https://csrc.nist.gov/pubs/fips/204/final>`__ and
`FIPS 205 <https://csrc.nist.gov/pubs/fips/205/final>`__.

Related
-------

- :doc:`/security/cryptography`
- :doc:`bpf-signing`
- :doc:`dm-verity`
- :doc:`tpm`
- :doc:`oci`
- :doc:`/operate/maintain/keys`
- :doc:`/reference/configuration`
