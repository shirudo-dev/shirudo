..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

shirudo attest
==============

Produce a TPM-signed evidence document for this target, and activate the
operator's credential challenge when given one.

Runs on: target, as root with the runtime binary. Requires: a TPM and a
measurement register bound this boot by ``init``. Changes measured state:
no.

Usage
-----

.. code-block:: none

   shirudo attest [--nonce=<nonce>] [--pcrs=<list>] [--challenge=<challenge>]
                  [-o <path> | --output=<path>]
   shirudo attest verify ...
   shirudo attest predict ...
   shirudo attest challenge ...
   shirudo attest --list-cmds

Every option takes its value after ``=`` or as the next argument, and
``-o`` is ``--output``. ``attest`` with no argument produces evidence. It
does not print help. The subcommands run on the operator host:
:doc:`attest-verify`, :doc:`attest-predict`, :doc:`attest-challenge`.

Description
-----------

``attest`` collects and signs, with the TPM's attestation key:

- opening certifications of the patch register (NV index ``0x01818E00``)
  and optional config NvPCR with the verifier's nonce,
- a quote of the selected PCRs bound to the opening signatures,
- closing certifications of the same registers bound to the quote signature,
- this boot's eventlog, the config activation records, and the firmware
  and systemd measurement logs,
- the public areas and names of the attestation key and the endorsement
  key, and the endorsement certificate when the TPM holds one.

The attestation key is a fixed-template primary under the endorsement
hierarchy. With ``--challenge``, ``attest`` activates the credential the
operator made for that key and includes it, which proves that the key
lives in the same TPM as the endorsement key (:doc:`attest-challenge`).

Both keys are primaries under the endorsement hierarchy, created from the
templates below, so one TPM always yields the same keys and names. A
builder that creates them from the same templates in the same TPM reads
the names the evidence will carry. The endorsement key is the ECC one,
or the RSA one when the TPM holds only an RSA endorsement certificate.

.. list-table::
   :header-rows: 1
   :widths: 20 36 44

   * - Field
     - Attestation key
     - Endorsement key
   * - Type
     - ECC
     - ECC, or RSA
   * - Name algorithm
     - SHA-256
     - SHA-256
   * - Attributes
     - ``0x00050072``: ``fixedTPM``, ``fixedParent``,
       ``sensitiveDataOrigin``, ``userWithAuth``, ``restricted``,
       ``sign``
     - ``0x000300B2``: ``fixedTPM``, ``fixedParent``,
       ``sensitiveDataOrigin``, ``adminWithPolicy``, ``restricted``,
       ``decrypt``
   * - Authorization policy
     - Empty
     - ``837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa``,
       ``PolicySecret`` on the endorsement hierarchy
   * - Symmetric
     - Null
     - AES-128 in CFB mode
   * - Scheme
     - ECDSA with SHA-256
     - Null
   * - Key
     - NIST P-256, KDF null
     - NIST P-256, KDF null; or RSA-2048, exponent 0 (65537)
   * - ``unique``
     - Empty
     - 32 zero bytes each for x and y; 256 zero bytes for RSA

The endorsement key templates are the TCG EK Credential Profile's
default low-range templates, L-2 for ECC and L-1 for RSA.

Without ``--nonce``, ``attest`` warns that the evidence proves no
freshness.

:doc:`/operate/run/attest` describes the procedure from enrollment to
verification.

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 18 26 18 38

   * - Option
     - Argument
     - Default
     - Description
   * - ``--nonce``
     - ``<nonce>``, hexadecimal, up to 64 bytes
     - none
     - Freshness value from the verifier, carried in the quote and the
       certification.
   * - ``--pcrs``
     - ``<list>``, comma-separated PCRs 0 to 23
     - 0-7, 9, 11-15
     - PCRs to quote.
   * - ``--challenge``
     - ``<challenge>``, a file
     - none
     - Credential challenge from ``attest challenge`` to activate.
   * - ``--output``, ``-o``
     - ``<path>``
     - standard output
     - Write the evidence to ``<path>`` with mode 0600. A path in sealed
       state is refused.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - The evidence was written.
   * - 1
     - No TPM answered (``attest: no TPM answered (tpm_error)``), the
       register is not bound this boot, the TPM refused the challenge
       (``attest: the TPM refused the challenge; the attestation key or
       the endorsement key is not this TPM's``), this boot's eventlog
       could not be read to its end (``attest: eventlog <path>
       unreadable: <error>``), or producing or writing the evidence
       failed. A boot without an ``init`` record is no error: its
       evidence carries an empty ``eventlog``, which ``attest verify``
       fails.
   * - 2
     - A usage error: an unknown option, an option given twice, a value
       missing or empty, or an argument. An invalid ``--nonce`` or
       ``--pcrs``, or a ``--challenge`` file that is not a shirudo
       credential challenge.

Files and environment
---------------------

- Reads the TPM, ``/var/lib/shirudo/eventlog``, the config activation
  records and the firmware and systemd event logs
- Writes ``--output``

Examples
--------

On the operator host, make a nonce:

.. code-block:: console

   operator$ openssl rand -hex 32

On the target, produce evidence for that nonce:

.. code-block:: console

   target# shirudo attest --nonce=a707993af885f29e88a1f9e936a3ccf9806b8d8b02c43dfe56fe571ce0f200d3 --output=ev.json

``attest`` prints nothing on success and writes ``ev.json`` with mode
0600. The document is JSON with the keys ``schema``, ``kind``
(``shirudo-attestation``), ``version_id``, ``ts``, ``boot_id``, ``nonce``,
``pcr_bank``, ``pcr_mask``, ``pcrs``, ``ak``, ``ek``, ``quote``,
``register``, ``eventlog``, ``config``, ``credential``,
``ek_certificate`` and ``logs``. Read the attestation key name to pin at
enrollment:

.. code-block:: console

   operator$ jq -r .ak.name ev.json
   000b6e354140b22198138167393ecd1233cfc27e8b16ef0b2b60cce88563c5588dbc

Related
-------

- :doc:`attest-verify`
- :doc:`attest-challenge`
- :doc:`attest-predict`
- :doc:`/operate/run/attest`
- :doc:`/internals/measurement-register`
