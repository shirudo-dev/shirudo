..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

shirudo upatch list
===================

List the upatches archived on this host next to the ones loaded now, and
flag drift between the two.

Runs on: target, as root with the runtime binary. On a host without
shirudo state it lists nothing. Requires: nothing. Changes measured state:
no.

Usage
-----

.. code-block:: none

   shirudo upatch list [--json]

Description
-----------

``list`` reads the archive ``/var/lib/shirudo/upatches/*.upatch``, which
``init`` restores at boot, and the pin directories under
``/run/shirudo/bpffs/upatches/``:

- one row per archived artifact: its name, ``LOADED`` ``yes`` or
  ``no``, its type (``load`` or ``unload``), its payload kind (``bpf``
  or ``java``) and the first 16 hexadecimal characters of its payload
  digest. A Java upatch is loaded while its installed jar is the
  archived one.
- one row per pinned upatch without an archive copy, marked
  ``not archived, gone at reboot``

An archived artifact that cannot be read is listed as ``unreadable``.

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
     - Print one JSON object: ``schema`` (1) and ``upatches``, a list of
       ``name``, ``type``, ``payload_type``, ``loaded``, ``archived`` and
       ``payload_sha256``. A upatch without an archive has ``type`` and
       ``payload_sha256`` ``null`` and no ``payload_type``.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - The list was printed.
   * - 1
     - The JSON document could not be built.
   * - 2
     - A usage error: an unknown option, ``--json`` given twice, or an
       argument.

Examples
--------

List the upatches of a target with one loaded upatch:

.. code-block:: console

   target# shirudo upatch list
   Archived upatches (/var/lib/shirudo/upatches):
     NAME                      LOADED  TYPE    KIND  PAYLOAD
     shirudo-test-basic        yes     load    bpf   8aee7072a1a15e4d..

The same target after the unload:

.. code-block:: console

   target# shirudo upatch list
   Archived upatches (/var/lib/shirudo/upatches):
     none

Related
-------

- :doc:`upatch-get`
- :doc:`upatch-load`
- :doc:`status`
