..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

shirudo upatch unload
=====================

Apply a signed unload directive: measure the unload, detach the named
upatch and remove its pin and archive copy.

Runs on: target, as root with the runtime binary. Requires: ``init``
completed this boot, and a directive signed by a key in the ``.bpf``
keyring. Changes measured state: yes, one ``upatch_unload`` event, except
when the upatch is not loaded.

Usage
-----

.. code-block:: none

   shirudo upatch unload [--expect-chain=<register>] [--expect-version-id=<version-id>]
                         [--no-precheck] [--no-version-check] [--report=<path>]
                         <directive>

The options are those of :doc:`upatch-load`, with the same meaning.

Description
-----------

An unload directive names the upatch and the payload digest it expects,
both in signed sections (see :doc:`build`). ``unload``:

#. Compares ``--expect-version-id``, as ``load`` does.
#. Reads the directive once into a private staging file and refuses a
   LOAD artifact, a directive whose target name is not signed or differs
   from the header, and an unsafe name (``parser_rejected``).
#. Runs the pre-flight checks of ``load``, unless ``--no-precheck``.
#. Refuses when the eventlog would exceed ``eventlog.max_bytes``
   (``eventlog_full``).
#. Takes the register lock, which it holds to the end, and undoes the
   pins and archives this boot's records do not cover, or refuses when
   it cannot, as ``load`` does.
#. Loads the directive's loader with ``BPF_PROG_LOAD`` against the
   ``.bpf`` keyring, so that the kernel verifies its signature before
   anything is removed.
#. Reads the payload digest that ``load`` recorded on the upatch's pin
   directory and compares it with the signed one. A difference, or a
   digest that cannot be read, is refused with ``payload_mismatch``. A
   directive signed with an all-zero digest never matches.
#. When the upatch has no pin, it removes the archive copy if it holds
   the directive's payload and is a BPF upatch, reports
   ``already_unloaded`` and exits with 0 without measuring. An archive of
   another payload or of a Java upatch stays, and the unload is refused
   with ``payload_mismatch``.
#. It extends the register with the ``upatch_unload`` event and appends
   it to the eventlog. The event comes first: a failed extend leaves the
   upatch attached.
#. It removes the pin directory, which detaches the links, and then
   ``/var/lib/shirudo/upatches/<name>.upatch``. When the pin cannot be
   removed after the event was measured, the report says
   ``detach_failed``. Repeat the unload.

The directive of a Java upatch (see :doc:`/upatches/write/java-agents`)
has no loader. ``unload`` checks its signature over the signed data
against the certificates of the ``.bpf`` keyring (``java_verify``
phase), and refuses with ``payload_mismatch`` unless the archive is the
Java upatch with the directive's payload. Without an archive it reports
``already_unloaded``. It then extends the register with the
``java_unload`` event, replaces ``/run/shirudo-java/<name>.jar`` with a
jar whose agent does nothing, removes the archive, and rewrites
``/run/environment.d/shirudo.conf``. The jar stays until the next boot:
a user manager started before the unload still names it in
``JAVA_TOOL_OPTIONS``, and a JVM does not start when a ``-javaagent``
jar is missing. A BPF unload directive that names a Java upatch is
refused with ``payload_mismatch``.

An unload moves the register forward. It never returns the register to
the value it had before the load.

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 24 20 10 46

   * - Option
     - Argument
     - Default
     - Description
   * - ``--expect-chain``
     - ``<register>``, 64 hex characters
     - none
     - Refuse unless the register holds this value before the unload.
   * - ``--expect-version-id``
     - ``<version-id>``
     - none
     - Refuse unless this binary's ``SHIRUDO_VERSION_ID`` equals the
       value.
   * - ``--no-version-check``
     - none
     - off
     - Skip the ``--expect-version-id`` comparison.
   * - ``--no-precheck``
     - none
     - off
     - Skip the pre-flight checks, with a warning.
   * - ``--report``
     - ``<path>`` or ``-``
     - none
     - Write the JSON report (:ref:`upatch-report`) to ``<path>`` or to
       standard output.

Exit status and failure categories
----------------------------------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - The upatch was unloaded and the unload measured, or it was not
       loaded (``already_unloaded``).
   * - 1
     - Refused or failed.
   * - 2
     - A usage error: an unknown option or one given twice, a value
       missing or empty, a second file, no file, or an
       ``--expect-chain`` that is not 64 hexadecimal characters.

``unload`` reports these categories: ``version_mismatch``,
``kernel_abi_unsupported``, ``keyring_missing``, ``tampered``,
``eventlog_full``, ``parser_rejected``, ``signature_rejected``,
``signature_unsupported``, ``lsm_denied``, ``verifier_rejected``,
``payload_mismatch``, ``detach_failed``, ``tpm_error``,
``already_unloaded`` and ``unknown``. See
:doc:`/reference/failure-categories`.

Files and environment
---------------------

- Reads the directive, the pin directory's
  ``security.bpf.shirudo.payload`` attribute and
  ``/var/lib/shirudo/eventlog``
- Removes ``/run/shirudo/bpffs/upatches/<name>/`` and
  ``/var/lib/shirudo/upatches/<name>.upatch``. Extends the register and
  appends to the eventlog

Examples
--------

Unload with a directive bound to the loaded payload:

.. code-block:: console

   target# shirudo upatch unload shirudo-test-basic.unload.upatch
   upatch unload: signed loader accepted, keyring 272801410, 165 instructions
   upatch unload: shirudo-test-basic carries the directive's payload
   upatch unload: shirudo-test-basic measured, register 256f5ad373d8728c777455949bef6ee362c2460c06740ac971f7fba5b19315cc
   upatch unload: shirudo-test-basic detached and unpinned

A directive that expects a different payload is refused:

.. code-block:: console

   target# shirudo upatch unload --report=- shirudo-test-basic-mismatch.unload.upatch
   upatch unload: signed loader accepted, keyring 272801410, 165 instructions
   upatch unload: payload_mismatch, the upatch loaded under 'shirudo-test-basic' is not what the directive expects; refused
   upatch unload failed: name=shirudo-test-basic phase=pin category=payload_mismatch err=1 (Operation not permitted) message=loaded payload does not match directive

The report of that refusal carries ``"phase":"pin"``,
``"errno_name":"EPERM"`` and ``"category":"payload_mismatch"``.

Related
-------

- :doc:`upatch-load`
- :doc:`build`
- :doc:`upatch-list`
- :doc:`/reference/failure-categories`
