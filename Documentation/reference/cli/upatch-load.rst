..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

shirudo upatch load
===================

Load a signed ``.upatch`` into the target kernel: verify the signature, run
the loader, pin the resulting links and extend this boot's measurement
register.

Runs on: target, as root with the runtime binary. Requires: ``init``
completed this boot. Changes measured state: yes, one ``upatch_load``
event.

Usage
-----

.. code-block:: none

   shirudo upatch load [--expect-chain=<register>] [--expect-version-id=<version-id>]
                       [--no-precheck] [--no-version-check] [--report=<path>]
                       <file>

Every option with a value takes it after ``=`` or as the next argument.
``--help`` anywhere on the line prints the help. Progress and error
messages go to standard error, so with ``--report=-`` standard output
carries only the report.

Description
-----------

#. With ``--expect-version-id``, ``load`` compares the value with this
   binary's ``SHIRUDO_VERSION_ID`` and refuses on a difference
   (``version_mismatch``).
#. It copies the file to a private staging file and reads it once. Every
   later step uses that copy.
#. Pre-flight, unless ``--no-precheck``: the kernel has the
   signed-loader interface (``kernel_abi_unsupported``), ``init`` froze a
   trust anchor this boot (``keyring_missing``), the ``.bpf`` keyring is
   the frozen one and the LSM link is pinned (``tampered``), and with
   ``--expect-chain`` the register holds that value (``tampered``,
   message ``chain_drift``).
#. It refuses when the eventlog would exceed ``eventlog.max_bytes``
   (``eventlog_full``).
#. It takes the register lock, ``/var/lib/shirudo/eventlog.lock``, which
   it holds to the end, and undoes the pins and archives this boot's
   records do not cover: those of a load stopped before its extend, of
   an unload stopped after it, and an archive brought back after its
   unload, which ``status`` reports under ``UpatchesMeasured``. It
   refuses (``tpm_error``) when it cannot read this boot's records or
   cannot undo one of them. A upatch of the same name that is loaded is
   refused (``already_loaded``).
#. It parses the artifact: a LOAD artifact, a safe and signed name, a
   payload digest that matches the payload, valid attach metadata
   (``parser_rejected``). For a uprobe it checks each target binary
   against its recorded build ID (``target_verify`` phase).
#. It loads the loader with ``BPF_PROG_LOAD`` against the ``.bpf``
   keyring. The kernel checks the signature before the verifier runs
   (``signed_loader_load`` phase).
#. It runs the loader, which loads the payload programs and maps
   (``payload_load`` phase).
#. It attaches every program and pins the links under
   ``/run/shirudo/bpffs/upatches/<name>/``, where a dot in the name becomes
   ``~d``, with the payload digest in the directory's
   ``security.bpf.shirudo.payload`` extended attribute (``link_create``
   phase).
#. It copies the artifact to ``/var/lib/shirudo/upatches/<name>.upatch``,
   the archive that ``init`` restores at boot (``persist`` phase).
#. It extends the register with the ``upatch_load`` event for the name and
   payload digest, and appends the event to the eventlog (``tpm_extend``
   phase).

When the copy to the archive or the register extend fails, ``load``
removes the pins and the archive again, so that no upatch runs
unmeasured. When the extend succeeded and only the eventlog append failed,
the upatch stays loaded and the report says ``tpm_error``. A ``load``
stopped between its pins and its extend leaves the pins: ``status``
reports them as ``tampered`` and the next ``load`` or ``unload`` undoes
them before it acts.

``--no-precheck`` skips step 3 only. The kernel signature check and the
LSM still apply. ``bpm`` passes it when it loads the upatches of a
package.

For XDP, the signed device-class mask selects interfaces present in the
initial network namespace at load time, with one endpoint per veth pair.
Each program can produce several ``link_<n>`` pins. Native XDP is
required: a device without it is logged and skipped. A device that has
native XDP but refuses it in its current settings is an error. An upatch with no
attachable device yet still loads, and
:doc:`/reference/cli/upatch-reconcile` attaches it when one appears. A
device that is occupied or does not report multi-buffer XDP, and any other
error, undoes all links the load
created. :doc:`/upatches/write/attach-kinds` defines the classes and limits.

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
     - Refuse unless the register holds this value before the load, for
       example ``register_at_boot`` from :doc:`attest-predict`.
   * - ``--expect-version-id``
     - ``<version-id>``
     - none
     - Refuse unless this binary's ``SHIRUDO_VERSION_ID`` equals the
       value (string comparison).
   * - ``--no-version-check``
     - none
     - off
     - Skip the ``--expect-version-id`` comparison.
   * - ``--no-precheck``
     - none
     - off
     - Skip the pre-flight checks, ``--expect-chain`` included, with a
       warning.
   * - ``--report``
     - ``<path>`` or ``-``
     - none
     - Write the JSON report to ``<path>`` (mode 0644), or to standard
       output with ``-``. A path in sealed state is refused.

.. _upatch-report:

Report
------

``--report`` writes one JSON object, also when the command fails:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Key
     - Value
   * - ``schema``
     - ``1``
   * - ``result``
     - ``ok`` or ``failed``
   * - ``op``
     - ``upatch_load`` or ``upatch_unload``
   * - ``phase``
     - ``pre_flight``, ``parse``, ``target_verify``,
       ``signed_loader_load``, ``payload_load``, ``link_create``, ``pin``,
       ``persist``, ``tpm_extend`` or ``done``
   * - ``errno``, ``errno_name``
     - the error number and its name, or ``null``
   * - ``category``
     - the failure category, ``ok`` on success
   * - ``message``
     - a short description
   * - ``verifier_log``
     - the kernel verifier's log, when it gave one
   * - ``loader_return``
     - the loader's return value
   * - ``upatch``
     - ``path``, ``name`` and ``payload_sha256`` of the artifact
   * - ``kernel``
     - ``release``, the running kernel
   * - ``tpm``
     - ``nv_index`` and ``chain_after``, the register after the event, on
       success, ``null`` otherwise

Exit status and failure categories
----------------------------------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - The upatch is loaded and measured.
   * - 1
     - Refused or failed. The report and the message name the category.
   * - 2
     - A usage error: an unknown option, an option given last without
       its value, a second file, no file, or an ``--expect-chain`` that
       is not 64 hexadecimal characters. Also ``attach_target_missing``
       for missing probe targets.

``load`` reports these categories: ``version_mismatch``,
``kernel_abi_unsupported``, ``keyring_missing``, ``tampered``,
``eventlog_full``, ``already_loaded``, ``parser_rejected``,
``signature_rejected``, ``signature_unsupported``, ``lsm_denied``,
``verifier_rejected``, ``attach_target_missing``, ``binary_mismatch``,
``attach_scope_mismatch``, ``xdp_multibuf_unsupported``,
``xdp_driver_refused``, ``xdp_device_occupied``, ``tpm_error`` and
``unknown``.
:doc:`/reference/failure-categories` gives the cause and the action for
each. Handle ``tampered`` as an incident
(:doc:`/operate/troubleshoot/incident-tampered`).

Files and environment
---------------------

- Reads the artifact, ``/var/lib/shirudo/eventlog`` and
  ``eventlog.max_bytes``
- Writes ``/run/shirudo/bpffs/upatches/<name>/``,
  ``/var/lib/shirudo/upatches/<name>.upatch``, the eventlog and the
  register

Examples
--------

Load an artifact and print the report:

.. code-block:: console

   target# shirudo upatch load --report=- shirudo-test-basic.upatch
   upatch load: signed loader accepted, keyring 272801410, 124 instructions
   upatch load: loader ran, 0 maps and 1 programs
   upatch load: program 0 (raw_tracepoint) pinned at /run/shirudo/bpffs/upatches/shirudo-test-basic/link
   upatch load: shirudo-test-basic loaded, 1 programs, keyring 272801410
   upatch load: shirudo-test-basic measured, register 7f63313a31ac8ddd3a6a16fce2038322c9c782d5787155d2dc18dfa582dff548

Load only when the register holds the value you predicted:

.. code-block:: console

   target# shirudo upatch load --expect-chain=<register> fix.upatch

``<register>`` is the ``register_at_boot`` or ``register_after_events``
line of :doc:`attest-predict` for the state you expect. When the register
differs, ``load`` refuses before it touches the kernel:

.. code-block:: none

   upatch load: pre-flight refused (category: tampered, message: chain_drift): live register c50b22ac27c5bb6a90ee5ff9b440fbbd5bb60b84a2aa7b395daec3f330886fcd is not the expected one; run status and pass the refreshed value

The message suggests repeating the command with the live value. Do not.
A register that differs from your prediction is an incident
(:doc:`/operate/troubleshoot/incident-tampered`).

A refusal for an artifact signed by a key the target does not trust:

.. code-block:: console

   target# shirudo upatch load --report=- shirudo-test-foreign.upatch
   BPF_PROG_LOAD (signed loader): Required key not available
   loader verifier log:
   signature verification failed: -126

The report of that refusal names ``"phase":"signed_loader_load"``,
``"errno_name":"ENOKEY"`` and ``"category":"keyring_missing"``.

Related
-------

- :doc:`upatch-unload`
- :doc:`build`
- :doc:`attest-predict`
- :doc:`/reference/failure-categories`
- :doc:`/internals/signed-loader`
- :doc:`/upatches/test/debugging`
