..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

shirudo-quote-check
===================

Check keepalive quotes without a TPM. A keepalive quote is a
``TPM2_Quote`` that selects no PCR and carries the SHA-256 of a keepalive
body as its qualifying data. ``shirudo-quote-check`` is a program of its
own, not a ``shirudo`` command. A telemetry backend runs it as a filter:
rows in, one verdict per row out.

Runs on: a backend host, installed by the operator package as
``$(bindir)/shirudo-quote-check``. Requires: nothing. It reads no file,
keeps no state, holds no key list and opens no connection. Changes
measured state: no.

The program is a static PIE: it needs no shared library and no dynamic
loader, unlike the other programs of the operator package. Copy the one
file to where the backend runs it, into a database container for one,
and it runs there whatever C library and OpenSSL that system has.

Usage
-----

.. code-block:: none

   shirudo-quote-check

The program takes no option besides ``-h`` and ``--help``, which print
the usage on standard error. It reads rows from standard input until
the input ends and writes one line to standard output for each row, in
the order of the rows. It flushes standard output after every line, so
a caller that keeps the process running gets each answer before it sends
the next row.

Input
-----

One row per line, in the TabSeparated format of ClickHouse: four fields
with a tab between them.

.. list-table::
   :header-rows: 1
   :widths: 18 82

   * - Field
     - Content
   * - ``attest``
     - The ``TPMS_ATTEST`` the TPM signed, without the ``TPM2B`` size, in
       standard base64 with padding. At most 1024 bytes.
   * - ``sig``
     - The marshalled ``TPMT_SIGNATURE`` over it, in standard base64 with
       padding. At most 160 bytes.
   * - ``ak``
     - The marshalled ``TPMT_PUBLIC`` of the attestation key, without the
       ``TPM2B`` size, in standard base64 with padding. At most 512
       bytes.
   * - ``body_sha256``
     - The SHA-256 of the keepalive body the row belongs to, as 64 hex
       digits of either case.

A base64 field is accepted only when it is the encoding of its bytes:
no white space, no line break and no missing padding. The last row may
end without a newline.

Checks
------

The program runs these checks in order. The first one that fails decides
the reason.

.. list-table::
   :header-rows: 1
   :widths: 6 70 24

   * - Step
     - Check
     - Reason on failure
   * - 1
     - The row has four fields, the three base64 fields decode within
       their sizes and ``body_sha256`` is 64 hex digits.
     - ``malformed``
   * - 2
     - ``ak`` parses as an ECC key on NIST P-256 with the ECDSA scheme
       and SHA-256.
     - ``malformed``
   * - 3
     - ``attest`` parses as a quote (``TPM_ST_ATTEST_QUOTE``) with one
       SHA-256 selection in which no PCR is set.
     - ``malformed``
   * - 4
     - The signer in ``attest`` is the qualified name of ``ak`` under the
       endorsement hierarchy: ``0x000b`` and SHA-256 over
       ``TPM_RH_ENDORSEMENT`` and the name of ``ak``.
     - ``bad_signature``
   * - 5
     - ``sig`` parses as an ECDSA signature with SHA-256.
     - ``malformed``
   * - 6
     - The signature verifies over the SHA-256 of the ``attest`` bytes
       with the key in ``ak``. A key that is no point of the curve
       verifies nothing.
     - ``bad_signature``
   * - 7
     - The qualifying data of the quote equals ``body_sha256``.
     - ``body_mismatch``

``shirudo attest`` signs its quotes with the same kind of key over a
nonce the caller chooses, and refuses an empty PCR selection. Step 3
therefore keeps an attestation quote from passing as a keepalive quote.

A row that passes proves that the body is unchanged since the key in
``ak`` signed its hash. It does not prove that the key lives in a TPM,
and the program does not decide which keys a backend accepts.
:doc:`attest-challenge` and :doc:`attest-verify` tie an attestation key
to a TPM.

Compared with attest verify
---------------------------

``shirudo attest verify`` and this program check a signature and its
signer with the same two functions of :src:`util/tpm_wire.c`,
``tpm_attest_verify()`` and ``tpm_attest_signer()``: the ECDSA signature
over the SHA-256 of the ``attest`` bytes, where a key that is no point
of the curve verifies nothing, and the signer as the key's qualified
name under the endorsement hierarchy, compared in constant time. Both
parse the key with the same ``TPMT_PUBLIC`` parser, which refuses a
curve other than NIST P-256 and an ECDSA hash other than SHA-256. What
each asks of the key and how it reports differ:

.. list-table::
   :header-rows: 1
   :widths: 36 32 32

   * - Check
     - ``shirudo-quote-check``
     - ``shirudo attest verify``
   * - The key is an ECC key with the ECDSA scheme
     - Yes, step 2
     - Yes
   * - The key has no symmetric algorithm
     - No: the parser also takes AES-128-CFB
     - Yes
   * - The key's attributes include restricted, sign, fixedTPM,
       fixedParent and sensitiveDataOrigin
     - No
     - Yes
   * - After a check fails
     - Stops: the first failure decides the reason
     - Goes on and reports every check, unless a structure does not
       parse

The attribute check would prove little here. The ``ak`` field travels
with the row from the node, so its attributes are what the node
declares, and a software P-256 key can carry the same bits (U1 of
:doc:`/security/threat-model`). That a key is a TPM's comes only from
credential activation, :doc:`attest-challenge` and ``shirudo attest
--challenge``, or from the records of the builder that created it, and
from pinning its name in :doc:`attest-verify`; a backend treats every
node as ``untrusted`` until the operator records it as ``enrolled``
(R17).

Output
------

One JSON object per row, on one line. A row that passes:

.. code-block:: none

   {"ok":1,"ak_name":"<hex>","ak_public":"<base64>","reset_count":<n>,"clock":<n>}

.. list-table::
   :header-rows: 1
   :widths: 18 82

   * - Key
     - Value
   * - ``ak_name``
     - The name of the attestation key, 68 hex digits: ``000b`` and the
       SHA-256 of the ``TPMT_PUBLIC`` bytes. This is the name ``shirudo
       attest verify --ak-name`` takes.
   * - ``ak_public``
     - The ``ak`` field as given.
   * - ``reset_count``
     - ``resetCount`` of the quote's clock information, the number of TPM
       resets.
   * - ``clock``
     - ``clock`` of the quote's clock information, the TPM's count of
       milliseconds, as an unsigned 64-bit number.

``reset_count`` and ``clock`` order the quotes of one key.

A row that fails:

.. code-block:: none

   {"ok":0,"reason":"<reason>"}

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Reason
     - Meaning
   * - ``malformed``
     - The row, a field or a structure does not parse, the key is not a
       P-256 ECDSA key, or the quote is not a quote of no PCR. A line
       longer than the longest row and a line that holds a NUL are
       ``malformed`` too.
   * - ``bad_signature``
     - The signer is not the key as an endorsement primary, or the
       signature does not verify.
   * - ``body_mismatch``
     - The signature is valid and the quote covers another body.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 12 88

   * - Status
     - Meaning
   * - 0
     - The input ended. Every row has its line, whatever the verdicts.
   * - 1
     - Reading, writing or a check could not run, for example on a
       closed output or without memory. The program prints
       ``shirudo-quote-check: <reason>`` on standard error. The row it
       stopped at has no line.
   * - 2
     - An argument or an option other than ``-h`` or ``--help``, reported
       on one line.

Examples
--------

Check one row from a file. The row is one the unit suite makes with a
software key, hence the clock:

.. code-block:: console

   $ shirudo-quote-check < row.tsv
   {"ok":1,"ak_name":"000b5df9f114316811380fc4fcba38a6d03d306cb68efed75bc004f1bf8de9f75e78","ak_public":"ACMACwAFAHIAAAAQABgACwADABAAIKjxXZuRCOfQVIxeeEc3RYztqHejfb0I4q4eQxf8XcPfACDPkDqNmcCyzRlbPKHkxo/pC3z5bzCd2jbT7BpEAy7veg==","reset_count":2309737967,"clock":18364758544493064720}

A row with three fields:

.. code-block:: console

   $ printf 'a\tb\tc\n' | shirudo-quote-check
   {"ok":0,"reason":"malformed"}

Build it in a checkout:

.. code-block:: console

   $ make quote-check
   $ tools/quote-check/shirudo-quote-check --help

Related
-------

- :doc:`attest-verify`
- :doc:`/concepts/background/tpm`
- :doc:`/reference/files`
