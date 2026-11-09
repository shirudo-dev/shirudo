..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

CLI
===

One page per command, with the syntax the parser accepts. Every page
states where the command runs, what it requires and whether it changes
measured state, and lists its options, exit statuses and failure
categories.

:doc:`/reference/cli/shirudo` describes what every command shares: how
command names resolve, the runtime binary a target must use, the image
gate that runs before most commands, the ``shirudo-build`` helper and
the exit statuses. :doc:`/reference/cheat-sheet` collects command lines
for common tasks.

.. toctree::
   :titlesonly:

   shirudo
   init
   status
   config
   version
   genkey
   build
   keys
   upatch-load
   upatch-unload
   upatch-list
   upatch-info
   upatch-get
   upatch-map
   upatch-reconcile
   bpm
   attest
   attest-verify
   attest-predict
   attest-challenge
   image
   gen-tools
