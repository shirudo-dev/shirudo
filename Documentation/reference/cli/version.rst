..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: All readers

shirudo version
===============

Print the release and the ``SHIRUDO_VERSION_ID`` that ``upatch load
--expect-version-id`` compares against.

Runs on: any host, with any copy of the binary, since the image gate does
not apply. Requires: locked process memory, like every command
(:doc:`shirudo`). Changes measured state: no.

Usage
-----

.. code-block:: none

   shirudo version [--version-id]

Description
-----------

Without an option, ``version`` prints two lines::

   shirudo (<describe><extraversion>, "<release-name>")
   version-id: <version-id>

``<describe>`` is ``git describe`` of the build tree, or the :src:`VERSION`
file outside a git checkout. ``<version-id>`` is a SHA-256 over the git
commit, a dirty-tree flag and a digest of the build configuration
(``config.mk`` and :src:`Makefile.shirudo`). Two builds of one commit with
different build configurations therefore have different ids, for
example an operator package and a target package built on different
hosts.

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 22 12 12 54

   * - Option
     - Argument
     - Default
     - Description
   * - ``--version-id``
     - none
     - off
     - Print only the version id, on one line.

Exit status
-----------

0, or 2 for a usage error: an unknown option, ``--version-id`` given
twice, or an argument.

Examples
--------

Print the release and the id:

.. code-block:: console

   target# shirudo version
   shirudo (58d3fa7-dirty-rc0, "Social BPF Coding")
   version-id: 58b05ab35a2bcefaa649faf15f8c6be0211e24cea710450c1a29298c3b5c7de0

Print the id alone, to pass to ``--expect-version-id``:

.. code-block:: console

   target# shirudo version --version-id
   58b05ab35a2bcefaa649faf15f8c6be0211e24cea710450c1a29298c3b5c7de0

Related
-------

- :doc:`upatch-load`
- :doc:`/operate/maintain/upgrade`
