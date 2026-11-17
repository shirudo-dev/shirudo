..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Tables
======

Every table of :src:`tools/backend/sql/`, one page per file. The
engine, key, TTL and columns of each table, and the views that write, fire on and read it,
are read from the schema when the documentation is built; the pages add
only what the schema cannot say. A table the schema has and these pages
do not document, or a column either side lacks, fails the build.

.. toctree::
   :maxdepth: 1

   ingest
   reference
   latest
   status
   vulns
