..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Quick guides
============

These tutorials continue from the :doc:`/start/quickstart` and run in its
test VM. Each takes one task from start to finish: writing a upatch of
your own, shipping one as a package through an OCI registry, and
enrolling the target's TPM to verify what the target runs.

The backend guide then starts a registry, a collector and the example
backend on your host, and the :doc:`example workflows
<example-workflows>` take a use case each through the whole pipeline
with them: live patching, system hardening and runtime observability.

.. toctree::
   :titlesonly:

   first-upatch
   publish-package
   attest-target
   backend
   example-workflows
