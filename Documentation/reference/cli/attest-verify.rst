..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

shirudo attest verify
=====================

Check an evidence document offline against the pinned keys and the state
you expect the target to be in.

Runs on: operator host, offline. It uses no TPM. Requires: the evidence
and the nonce it was requested with. Changes measured state: no.

Usage
-----

.. code-block:: none

   shirudo attest verify --evidence=<evidence> --nonce=<nonce>
                         [--ak-name=<name>] [--ek-name=<name>]
                         [--expect-credential=<credential>]
                         [--cert=<certificate>]... [--upatch=<file>]...
                         [--expect=[java:]<name>=<digest>]... [--tree-root=<digest>]
                         [--expect-chain=<register>] [--allow-runtime-events]
                         [--expect-config-root=<root>
                          (--expect-config-pcr=<pcr> | --expect-config-nvpcr=<name>)]
                         [--expect-pcr=<pcr>=<value>]...
                         [--expect-bind-pcr=<pcr>=<value>]...
                         [--strict-anchor] [--require-initrd] [--json]

Every option takes its value after ``=`` or as the next argument. On a
host where enforcement is up the image gate refuses ``--cert``. Run
``verify`` where enforcement is not up.

Description
-----------

``verify`` prints one line per check, ``OK`` or ``FAIL``, and one per
note, ``NOTE``, followed by ``verdict: ok`` or ``verdict: fail``. It
checks:

- the request nonce in the opening certifications, the opening signatures
  bound into the PCR quote, and the quote signature bound into each closing
  certification
- the attestation key: restricted, fixed to its TPM, its name matching its
  public area and, with ``--ak-name``, the pinned name
- the endorsement key: its name and the TCG default template, and with
  ``--ek-name`` the pinned name. With ``--expect-credential``, the
  credential the target recovered
- the quote and the register certification: signed by the attestation key
  as an endorsement primary, covering the listed PCRs and index, of one
  TPM boot with the same reset and restart counts, with each register
  retaining its certified value across the quote
- the config root history against the quoted config PCR, and with
  ``--expect-config-root`` the approved root
- the register's public area against the recorded PCR 9 and 11 binding,
  the init record of this TPM reset, the eventlog replay to the certified
  value and the anchor in PCR 9
- the expected state: with ``--cert`` (and ``--upatch``, ``--expect``,
  ``--tree-root``) the init event, and the events after boot, which fail
  unless ``--allow-runtime-events``. With ``--expect-chain``, the register
  value

Without ``--ak-name``, ``verify`` warns that the signer is not pinned, and
a document from any TPM passes the key checks. Without ``--cert`` or
``--expect-chain``, it compares no state and prints the register value as
a note. A ``verdict: ok`` then says only that the document is consistent
in itself. Pin the keys at enrollment (:doc:`attest-challenge`) and always
give the expected state.

:doc:`quote-check` checks a keepalive quote's signature and signer
with the same functions as ``verify``, and fewer fields of the
attestation key; its page lists the differences.

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 26 24 50

   * - Option
     - Argument
     - Description
   * - ``--evidence``
     - ``<evidence>``, a file
     - Required. The document ``shirudo attest`` wrote.
   * - ``--nonce``
     - ``<nonce>``, hexadecimal, up to 64 bytes
     - Required. The nonce the evidence was requested with.
   * - ``--ak-name``
     - ``<name>``, 68 hex characters
     - The attestation key name pinned at enrollment.
   * - ``--ek-name``
     - ``<name>``, 68 hex characters
     - The endorsement key name pinned at enrollment.
   * - ``--expect-credential``
     - ``<credential>``, 64 hex characters
     - The credential of the challenge given to the target. Needs
       ``--ak-name``.
   * - ``--cert``
     - ``<certificate>``, DER
     - A certificate the target enrolls. Repeat for each, up to 16.
   * - ``--upatch``
     - ``<file>``
     - An artifact archived on the target at boot. Repeatable, each
       upatch name once across ``--upatch`` and ``--expect``. Needs
       ``--cert``.
   * - ``--expect``
     - ``[java:]<name>=<digest>``
     - An archived upatch by name and payload digest, ``java:`` before
       the name for a Java upatch. Repeatable. The name is one a upatch
       can have, see :doc:`/concepts/upatches-and-packages`, and comes
       once. Needs ``--cert``.
   * - ``--tree-root``
     - ``<digest>``, 64 hex characters
     - The upatch tree projection root at boot. Needs ``--cert``.
   * - ``--expect-chain``
     - ``<register>``, 64 hex characters
     - The register value after the expected events.
   * - ``--allow-runtime-events``
     - none
     - Accept loads, unloads and revocations after boot.
   * - ``--expect-config-root``
     - ``<root>``, 64 hex characters
     - The approved config image root hash. Needs
       ``--expect-config-pcr`` or ``--expect-config-nvpcr``.
   * - ``--expect-config-pcr``
     - ``<pcr>``, 0 to 15, not 9 or 11
     - The PCR the config activation extends.
   * - ``--expect-config-nvpcr``
     - ``<name>``, 68 hex characters
     - The TPM name of the config NvPCR the config activation extends,
       in place of ``--expect-config-pcr``. The evidence must certify it.
   * - ``--expect-pcr``
     - ``<pcr>=<value>``, PCR 0 to 23
     - A PCR value the quote must carry. Repeatable.
   * - ``--expect-bind-pcr``
     - ``<pcr>=<value>``, PCR 0 to 23
     - A PCR value the register was bound under. Repeatable.
   * - ``--strict-anchor``
     - none
     - Require PCR 9 to hold only the anchor.
   * - ``--json``
     - none
     - Print one JSON object: ``schema`` (1), ``verdict`` (``ok`` or
       ``fail``) and ``checks``, a list of ``result`` (``ok``, ``fail``
       or ``note``) and ``text``.
   * - ``--require-initrd``
     - none
     - Fail unless ``init`` bound the register from the initrd.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - ``verdict: ok``.
   * - 1
     - ``verdict: fail``.
   * - 2
     - A usage error: an unknown option, an option given twice, the same
       PCR twice to ``--expect-pcr`` or ``--expect-bind-pcr``, a value
       missing, empty or invalid, an argument, ``--evidence`` or
       ``--nonce`` missing, or an option that needs another. An
       unreadable evidence file or a file that is not a shirudo evidence
       document.

Examples
--------

Verify evidence against the predicted register value, with the
attestation key pinned:

.. code-block:: console

   operator$ shirudo attest verify --evidence=ev.json --nonce=$NONCE --ak-name=<ak-name> --expect-chain=<register>
     OK    nonce matches the request
     OK    attestation key: restricted, fixed to this TPM
     OK    attestation key: name matches its public area
     OK    attestation key: the pinned key
     OK    endorsement key: name matches its public area
     OK    endorsement key: TCG default template under the endorsement policy
     OK    quote: ECDSA signature by the attestation key
     OK    quote: signed by the key as an endorsement primary
     OK    quote: carries the nonce
     OK    quote: covers the PCRs the document lists
     OK    quote: PCR digest matches the listed values
     OK    register: ECDSA signature by the attestation key
     OK    register: signed by the key as an endorsement primary
     OK    register: carries the nonce
     OK    register: certification names the listed index
     OK    register: certified contents match the listed value
     OK    quote and certification are of one TPM boot
     OK    config: config root history matches the quoted PCR
     NOTE  config root has no operator approval; use --expect-config-root with --expect-config-pcr
     NOTE  config records a selection; direct TPM writer protection is deferred
     OK    eventlog: this boot has an init record
     OK    register: the document names index 0x01818E00 and PCRs 9 and 11
     OK    register: public area is bound to PCRs 9 and 11 as recorded
     NOTE  binding: made in the initrd
     OK    eventlog: one init record for this TPM reset (1 this boot)
     OK    register: init record is of the TPM's current reset count
     OK    eventlog: 2 records replay to the certified value
     OK    anchor: record digest matches the index name
     OK    anchor: PCR 9 equals the recorded value extended by the anchor
     OK    state: register equals the expected value
     NOTE  event after boot: upatch_load basic
   verdict: ok

``$NONCE`` holds the nonce given to ``shirudo attest``, ``<ak-name>`` the
name pinned at enrollment and ``<register>`` the
``register_after_events`` line of :doc:`attest-predict`.

Verify against the enrolled certificates and require an initrd binding.
Events after boot fail the check without ``--allow-runtime-events``:

.. code-block:: console

   operator$ shirudo attest verify --evidence=ev.json --nonce=$NONCE --ak-name=<ak-name> --cert=cert.der --require-initrd --strict-anchor

The end of that report, for a target that loaded and unloaded a upatch
after boot:

.. code-block:: none

     OK    binding: made while the initrd ran
     OK    eventlog: one init record for this TPM reset (1 this boot)
     OK    register: init record is of the TPM's current reset count
     OK    eventlog: 3 records replay to the certified value
     OK    anchor: record digest matches the index name
     OK    anchor: PCR 9 equals the recorded value extended by the anchor
     FAIL  state: init event covers the expected certificate, set and tree root
     FAIL  state: 2 events after boot change the register
     NOTE  event after boot: upatch_load shirudo-test-basic
     NOTE  event after boot: upatch_unload shirudo-test-basic
   verdict: fail

The first ``FAIL`` line says that the target enrolls a certificate set
other than the one given: that target enrolls two certificates and the
command names one.

Related
-------

- :doc:`attest`
- :doc:`attest-predict`
- :doc:`attest-challenge`
- :doc:`quote-check`
- :doc:`/operate/run/attest`
- :doc:`/security/threat-model`
