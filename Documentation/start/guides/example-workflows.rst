..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Example workflows
=================

Each of these tutorials takes one use case through the whole pipeline on
the test VM, with the services of :doc:`backend`: it publishes a
package, appends it to the upatch tree the target follows, shows its
effect on the target and in the backend, and takes it back. The packages
are the ones under :src:`upatches/`: shields that block a kernel and a
JDK vulnerability, a sandbox around a web server, and observability of
what the target runs.

.. toctree::
   :titlesonly:

   live-patching
   system-hardening
   runtime-observability
