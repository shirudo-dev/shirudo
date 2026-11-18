..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Formats
=======

The formats shirudo reads and writes, in the order a upatch meets them:
the Beefile that describes a package, the signed ``.upatch`` container,
the package and the signed index that lists it, the upatch tree, the
``shirudo status --json`` document a target reports, and the OTLP
documents it exports, its keepalive and its map logs and metrics.

.. toctree::
   :titlesonly:

   beefile
   upatch-format
   bpm-formats
   upatch-tree
   status-json
   otlp
   keepalive
   map-export
