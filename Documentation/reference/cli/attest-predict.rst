..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

shirudo attest predict
======================

Compute the measurement register value a target reaches from the
certificates it enrolls, the upatches it restores at boot and the events
after boot.

Runs on: operator host, offline. It uses no TPM and no target state.
Requires: the certificates the target enrolls. Changes measured state: no.

Usage
-----

.. code-block:: none

   shirudo attest predict --cert=<certificate>... [--upatch=<file>]...
                          [--expect=<name>=<digest>]... [--tree-root=<digest>]
                          [--event=<event>]...
                          [--bind-pcr=9=<value> --bind-pcr=11=<value>
                           --writer-public=<modulus>] [--json]

Every option takes its value after ``=`` or as the next argument. On a
host where enforcement is up the image gate refuses ``--cert``.

Description
-----------

``predict`` recomputes what ``init`` and later commands measure:

#. The init event covers the digest of the enrolled certificate set
   (every ``--cert``, in any order), the set of upatches archived at boot
   (every ``--upatch`` and ``--expect``) and the upatch tree root.
#. The register starts at zero and is extended with the init event. The
   result is ``register_at_boot``.
#. Each ``--event``, in the order given, extends it further. The result
   is ``register_after_events``.
#. With the PCR 9 and 11 values at binding and the writer's public key,
   ``predict`` also computes the register's TPM name, the anchor record
   and the PCR 9 value after the anchor.

The certificate set must be exactly the set the target enrolls: the
primary certificate and every vouched one.

Pass ``register_at_boot`` or ``register_after_events`` to
``upatch load --expect-chain`` or ``attest verify --expect-chain``.

Events
~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - ``--event=``
     - Event
   * - ``load:<name>=<payload-sha256>``
     - ``upatch load`` of ``<name>``
   * - ``unload:<name>=<payload-sha256>``
     - ``upatch unload`` of ``<name>``, with the digest the directive
       names
   * - ``tree:<sequence>=<operation-digest>``
     - an operation ``bpm tree sync`` applied
   * - ``revoke:<label>=<certificate-sha256>``
     - a key revocation. ``<certificate-sha256>`` is the SHA-256 of the
       revoked certificate. ``<label>`` is required and not used.

The eventlog entry of each event (:doc:`/reference/eventlog`)
carries the values.

Output
~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Line
     - Value
   * - ``set_digest:``
     - digest of the upatch set archived at boot
   * - ``init_event:``
     - the init event
   * - ``register_at_boot:``
     - the register after ``init``
   * - ``register_after_events:``
     - the register after the ``--event`` values, only with ``--event``
   * - ``register_name:``, ``anchor:``, ``pcr9_after_anchor:``
     - the register's TPM name, the anchor record and PCR 9 after it,
       only with ``--bind-pcr`` and ``--writer-public``

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 22 30 48

   * - Option
     - Argument
     - Description
   * - ``--cert``
     - ``<certificate>``, DER
     - Required. A certificate the target enrolls. Repeat for each, up to
       16.
   * - ``--upatch``
     - ``<file>``
     - An artifact archived on the target at boot. Repeatable, each
       upatch name once across ``--upatch`` and ``--expect``.
   * - ``--expect``
     - ``<name>=<digest>``
     - An archived upatch by name and payload digest. Repeatable. The
       name is one an upatch can have, see
       :doc:`/concepts/upatches-and-packages`, and comes once.
   * - ``--tree-root``
     - ``<digest>``, 64 hex characters
     - The upatch tree projection root at boot. Default: all zero.
   * - ``--event``
     - ``<event>``, see above
     - An event after boot. Repeatable, applied in order.
   * - ``--json``
     - none
     - Print the values as one JSON object with ``schema`` (1) and the
       keys above.
   * - ``--bind-pcr``
     - ``9=<value>`` or ``11=<value>``
     - PCR values the register was bound under. Give both.
   * - ``--writer-public``
     - ``<modulus>``, 768 hex characters
     - The 384-byte RSA modulus of the init record's writer key. Required
       with ``--bind-pcr``.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - The values were printed.
   * - 1
     - The register's write policy could not be computed, or memory ran
       out.
   * - 2
     - A usage error: no ``--cert``, an unknown option, an option given
       twice, the same PCR twice to ``--bind-pcr``, a value missing,
       empty or invalid, an argument, more than 256 ``--event``, or
       ``--bind-pcr`` without both PCRs or without ``--writer-public``.
       An unreadable file or an invalid event.

Examples
--------

Predict the register at boot for a target that enrolls one certificate and
restores nothing:

.. code-block:: console

   operator$ shirudo attest predict --cert=cert.der
   set_digest: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
   init_event: 1014642f2d76b1eb10b4872c4299a70e191be0eb2958de65a7098bfe92a93124
   register_at_boot: 33ec2c3ed20693c2e40131e693a11b169b91efd8f7438f86313c915e512121e5

Predict the register of a target that enrolls two certificates, after one
load:

.. code-block:: console

   operator$ shirudo attest predict --cert=cert.der --cert=own.der --event=load:basic=46f3d9f5f6568bddb7692cad28e99a86a3104192d8a2251f9ef9ec6d593c2035
   set_digest: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
   init_event: cb206abf8e514bc714fc69f372d464d2c7512f1489431aed2319551c5ed34b9a
   register_at_boot: d1bdb80f7c0cfc1560f0a5a0b974d282bfd05fc95852b7649d59a054b450aa51
   register_after_events: ff0eb201e073fdeeba80a4b268f039bea58ec6dd2998e6651c4834ee99f3e103

On that target, ``status`` showed ``Chain: d1bdb80f...`` after boot and
``ff0eb201...`` after ``upatch load basic.upatch``.

Related
-------

- :doc:`attest-verify`
- :doc:`upatch-load`
- :doc:`/internals/measurement-register`
- :doc:`/reference/eventlog`
