..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

shirudo keys
============

Show the key material this host holds, and vouch for or add a signing
certificate.

Runs on: any host for the display, the operator host for ``vouch``, and
only a host without an active config image for ``add``. Requires: root on a target,
with the runtime binary. Changes measured state: no.

Usage
-----

.. code-block:: none

   shirudo keys [--keys-dir <dir> | --keys-dir=<dir>] [--json]
   shirudo keys add <certificate> (--vouch <vouch> | --vouch=<vouch>)
                    [--keys-dir <dir> | --keys-dir=<dir>]
   shirudo keys vouch <certificate> [-o <vouch> | --output <vouch>]
                      [--keys-dir <dir> | --keys-dir=<dir>]
                      [--key <signing-key>] [--cert <certificate>]
   shirudo keys revoke
   shirudo keys --list-cmds

``keys`` without a subcommand, or with an option first, shows the key
material.

Display
-------

``shirudo keys`` prints what is present:

- the certificate ``cert.der`` and the signing key ``signing_key.pem`` in
  the keys directory: subject, issuer, algorithm, both fingerprints and
  the date the certificate was issued
- the trusted set, when it has more than the primary certificate or
  holds revoked or unvouched entries: each member's SPKI fingerprint, the
  SHA-256 of its certificate and the certificate that vouched for it
- the ``.bpf`` and ``.dm-verity`` keyrings ``init`` froze: each one's
  serial, the frozen serial and every member, whatever its type, marked
  ``(frozen)`` when ``init`` recorded it and ``(not frozen)`` otherwise

The keys directory is ``--keys-dir``, else ``$SHIRUDO_KEYS_DIR``, else
``/var/lib/shirudo/keys``. On a target with an active config image it is
always the runtime image's ``/run/shirudo/runtime/keys``, and the image
gate refuses ``--keys-dir``.

keys add
--------

``keys add`` installs a certificate into the trusted set of a keys
directory, so that ``init`` enrolls it at the next boot:

#. It refuses on a host with an active config image, which every
   production target has, with ``target: add vouched BPF signers to the
   signed config selected for boot and reboot to enroll them``. On such a
   target, add vouched signers to the signed config image, select it
   with ``shirudo image stage`` and reboot when appropriate (see
   :doc:`/operate/maintain/keys`).
#. It requires an ML-DSA-87 certificate and a trusted set under the keys
   directory, and refuses a certificate listed under ``<dir>/revoked``.
#. The vouch must verify under a certificate already in the set. With the
   default keys directory, that certificate must also be in the ``.bpf``
   keyring this boot.
#. A certificate already in the set is reported and left alone. The set
   holds at most 16 certificates.
#. It installs the certificate and its vouch under ``<dir>/trusted``,
   logs ``keys add: fingerprint=<fp> vouched_by=<fp> path=<path>`` at
   audit priority, and prints the certificate's fingerprint.

The new certificate takes effect when the initrd is rebuilt with it
(``shirudo-gen-initrd``) and the target reboots.

keys vouch
----------

``keys vouch`` executes the ``shirudo-build`` helper, which signs a vouch
for another certificate with this operator's key:

#. It resolves the key and certificate like :doc:`build`.
#. It refuses a certificate that is not ML-DSA-87 and the operator's own
   certificate.
#. It writes the vouch to ``-o``, else ``<certificate>.vouch``, and prints
   the vouched certificate's fingerprint.

keys revoke
-----------

``keys revoke`` takes no argument and always fails with:

.. code-block:: none

   keys revoke: put revocation records in a signed config image, then run `shirudo image update`

A revocation is the revoked certificate, placed in a signed config image as
``keys/revoked/<fingerprint>.der``, where ``<fingerprint>`` is the
lowercase hexadecimal SHA-256 of its public key (SPKI). When :doc:`image` ``update`` activates that image, the target
removes the certificate from the ``.bpf`` keyring, measures a
``key_revoke`` event in the register and unloads every archived upatch the
certificate signed (see :doc:`/operate/maintain/keys`).

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 18 22 25 35

   * - Option
     - Argument
     - Default
     - Description
   * - ``--keys-dir``
     - ``<dir>``, next argument or after ``=``
     - ``$SHIRUDO_KEYS_DIR``, else ``/var/lib/shirudo/keys``
     - Display, ``add`` and ``vouch``: the keys directory.
   * - ``--json``
     - none
     - off
     - Print the key material as one JSON object: ``schema`` (1),
       ``cert`` and ``signing_key`` (objects, or ``null`` when absent),
       ``trusted_set`` (a list of ``fingerprint``, ``sha256``,
       ``primary`` and ``voucher``) and ``keyrings`` (``.bpf`` and
       ``.dm-verity``, each with ``present``, ``serial``,
       ``frozen_serial`` and ``members``).
   * - ``--vouch``
     - ``<vouch>``, next argument or after ``=``
     - none, required
     - ``add``: the vouch an enrolled key signed for the certificate.
   * - ``-o``, ``--output``
     - ``<vouch>``
     - ``<certificate>.vouch``
     - ``vouch``: where to write the vouch.
   * - ``--key``
     - ``<signing-key>``
     - from the keys directory
     - ``vouch``: the signing key.
   * - ``--cert``
     - ``<certificate>``
     - from the keys directory
     - ``vouch``: the signing certificate.
   * - ``--list-cmds``
     - none
     -
     - Print ``add``, ``revoke`` and ``vouch``, one per line.

``vouch`` takes ``-o``, ``--output``, ``--key`` and ``--cert`` with the
value as the next argument only.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - Display: key material was found and the keyring is consistent.
       ``add``: the certificate is trusted. ``vouch``: the vouch was
       written.
   * - 1
     - Display: no key material on the host, the certificate or a keyring
       cannot be read, the signing key is not the certificate's, or a
       keyring ``init`` froze is gone. ``add``: refused or failed,
       including on a host with an active config image. ``vouch``: the
       key is unusable, the certificate cannot be read, is not ML-DSA-87
       or is the signing key's own, or signing or writing failed.
       ``revoke``: always.
   * - 2
     - An unknown option or subcommand, a missing certificate or
       ``--vouch``, an extra argument, or an unusable keys directory path.
   * - 127
     - ``vouch``: ``shirudo`` cannot execute the helper.

Files and environment
---------------------

- ``<dir>/cert.der``, ``<dir>/signing_key.pem``, ``<dir>/trusted/``,
  ``<dir>/revoked/``
- ``/run/shirudo/runtime/keys`` on a target with a config image
- ``SHIRUDO_KEYS_DIR``: the default keys directory, refused by the image
  gate

Examples
--------

Show the key material on a target:

.. code-block:: console

   target# shirudo keys
   Certificate (/run/shirudo/runtime/keys/cert.der):
     Subject:               /CN=shirudo
     Issuer:                /CN=shirudo  (self-signed)
     Public key:            ML-DSA-87
     Fingerprint:           SHA256:c00c2d9a30c11dd98bb53200ac79c744b063a50489e5780968ea97bcb5745eb1
     SPKI fingerprint:      SHA256:6bd6b1a28b631295a013102d358d371d52ab1c894587aedceaf02e472c88f858
     Issued:                2026-11-03T14:52:11Z

   Signing key (/run/shirudo/runtime/keys/signing_key.pem):
     Present:               no, a target holds no private key

   Trusted set (2 members, 0 revoked, 0 unvouched):
     a8be2bb837b0f052f7652f9edf446594a5465eed614d939964ddfcc96e61ba7f
       sha256 79b04130628135a03630a0ed9e92a574f8701847404ec281469348a09b9b3b45
       vouched by 6bd6b1a28b631295a013102d358d371d52ab1c894587aedceaf02e472c88f858
     6bd6b1a28b631295a013102d358d371d52ab1c894587aedceaf02e472c88f858  (primary)
       sha256 c00c2d9a30c11dd98bb53200ac79c744b063a50489e5780968ea97bcb5745eb1

   Keyring (.bpf):
     Serial:                272801410
     Frozen serial:         272801410  (matches)
     Members (2):
       serial=465853497   type=asymmetric  shirudo: 30dee65057025367c4c384928bcf1e4cd8fe0265  (frozen)
       serial=91435879    type=asymmetric  shirudo: 7fa1d435249690766f8b1397122775d26f1ed92e  (frozen)

   Keyring (.dm-verity):
     Serial:                799624487
     Frozen serial:         799624487  (matches)
     Members (1):
       serial=403194297   type=asymmetric  shirudo: 7fa1d435249690766f8b1397122775d26f1ed92e  (frozen)

Vouch for a second operator's certificate:

.. code-block:: console

   operator$ shirudo keys vouch other-cert.der -o other-cert.der.vouch --keys-dir ~/shirudo-keys

Related
-------

- :doc:`/operate/maintain/keys`
- :doc:`genkey`
- :doc:`image`
- :doc:`/security/cryptography`
