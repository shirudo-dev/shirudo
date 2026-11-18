..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

shirudo upatch get
==================

Describe a loaded upatch as the kernel holds it: attach point, program
source from BTF line info, and its pinned maps with their contents.

Runs on: target, as root with the runtime binary. Requires: the upatch is
loaded. Changes measured state: no.

Usage
-----

.. code-block:: none

   shirudo upatch get <name> [--json] [--show-full]

Description
-----------

``get`` opens the first link of the upatch ``<name>`` and reports:

- ``Location``: the attach point in ``SEC()`` form, for example
  ``fentry/do_nanosleep``.
- the program ID, the load time and the payload digest recorded on the
  pin.
- ``Missed runs``: the runs of its programs the kernel skipped since the
  load, summed over every link of a kind that counts them, with one line
  per program when more than one does. ``not counted for this attach
  kind`` for an upatch of none of them, ``unavailable`` when a link or
  program cannot be read. :ref:`runs-the-kernel-skips` says which kinds
  count and what.
- the source lines from the program's BTF line info, which the signed
  loader installed. They are exact but cover only the lines the compiler
  kept.
- every pinned map with its BTF key and value types and its contents.

``get`` reads serializer-backed maps without draining them, so it does not
take records from the export timer. It uses only reads the LSM allows to
the runtime binary.

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 18 12 12 58

   * - Option
     - Argument
     - Default
     - Description
   * - ``--json``
     - none
     - off
     - Print one JSON object: ``schema`` and ``upatch`` with ``name``,
       ``location``, ``prog_id``, ``loaded_at``, ``age``,
       ``payload_sha256``, ``missed_runs`` (the total, or ``null`` when
       no program counts them or they cannot be read), ``programs`` (one
       object per counted program, with its ``location`` and
       ``missed_runs``), ``source`` and ``maps``.
   * - ``--show-full``
     - none
     - off
     - Print every map entry instead of the first 256 of each map.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - The upatch was described. A map that cannot be read is reported in
       the output.
   * - 1
     - The upatch is not loaded or its program cannot be read
       (``upatch get: '<name>': <error>``), or the JSON document could not
       be built.
   * - 2
     - A usage error: no name, a second name, an unknown option or one
       given twice, or an invalid name.

Examples
--------

Describe a loaded upatch:

.. code-block:: console

   target# shirudo upatch get shirudo-test-basic
   Name:                  shirudo-test-basic
   Location:              fentry/do_nanosleep
   Program ID:            72
   Loaded at:             2026-11-03T14:54:33Z  (1s ago)
   Payload sha256:        8aee7072a1a15e4dddc93ad6b253a0e2e70ad6cdf767442aa8a1c1997bc3069f  (signature-bound)
   Missed runs:           0
   Maps:                  none

   Source (kernel BTF line_info):

     <checkout>/testing/fixtures/basic.bpf.c:
           9: int BPF_PROG(shirudo_test_basic)

``<checkout>`` is the path of the checkout on the operator host, where the
compiler saw the source.

Related
-------

- :doc:`upatch-list`
- :doc:`upatch-map`
- :doc:`upatch-info`
- :doc:`/upatches/test/debugging`
