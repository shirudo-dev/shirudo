..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

shirudo upatch reconcile
========================

Attach each loaded XDP upatch to the devices its signed classes select
and that it is not attached to yet.

Runs on: target, as root with the runtime binary, after ``init`` has
finished on the root file system. Requires: the sealed ``.bpf`` keyring.
Changes measured state: no.

Usage
-----

.. code-block:: none

   shirudo upatch reconcile [--report=<path>]

Description
-----------

``reconcile`` runs one pass and exits. For every upatch with an XDP
program pinned under ``/run/shirudo/bpffs/upatches/``, it hashes the
sealed archive, compares the result with the pinned payload, and reads
the signed device classes from that archive. It then asks each selected
device what it runs:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - The device runs
     - ``reconcile``
   * - This program
     - Leaves it.
   * - Nothing
     - Attaches a link and pins it as the next ``link_<n>``.
   * - Anything else
     - Leaves it. A program already on a device is never replaced.

It also removes the pin of a link whose device is gone. A pass that has
nothing to do does not take the register lock. A selected device that
keeps refusing is not nothing to do: every pass takes the lock, checks
the archive again, retries it and logs a warning, on each udev event
for the device and every 60 seconds from the timer. ``status`` reports
such a device under ``XdpCovered``, and it is for the operator to end,
as :doc:`/operate/run/read-status` describes.

``reconcile`` adds no event to the register: the measured state is the
upatch, not the devices it reaches.

Every upatch is checked before any is attached. An archive that differs
from what the records say was loaded stops the pass with ``tampered``,
and no upatch gets a new link until that is resolved. Pins of a load
still in progress, or of one that stopped before its record, are skipped,
as is an upatch unloaded or replaced during the pass; ``status`` reports
a load that stopped under ``UpatchesMeasured``.

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 18 12 12 58

   * - Option
     - Argument
     - Default
     - Description
   * - ``--report``
     - path
     - none
     - Write the operation report as JSON, ``-`` for standard output.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 12 88

   * - Status
     - Meaning
   * - 0
     - The pass finished. A device that is occupied, has no native XDP, or
       changed or went away during the pass is left for the next pass and
       does not change the status. Neither does a driver refusing the
       program or a device without multi-buffer XDP, but those are logged
       as a warning on every pass.
   * - 1
     - The pass stopped: see the category in the report.
   * - 2
     - A usage error.

See also
--------

- :doc:`/reference/failure-categories`
- :doc:`/upatches/write/attach-kinds`
