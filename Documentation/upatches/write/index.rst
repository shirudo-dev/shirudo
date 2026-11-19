..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Write
=====

Where a program can attach, how a upatch keeps and exports its state in
maps, arenas and serializers, how a Lua decoder turns that state into
telemetry, what a program can miss or cannot rely on, and how to test
the memory ordering that programs on several CPUs rely on. It also
covers how a Java agent ships as an upatch.

.. toctree::
   :titlesonly:

   attach-kinds
   maps-arenas-serializers
   decoders
   pitfalls
   java-agents
   memory-consistency/index
