..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

upatches
========

These pages are for upatch authors: engineers who turn a kernel fix or
an observation into a signed upatch and ship it as a package. Start with
:doc:`/upatches/learn/concepts`, then follow
:doc:`/upatches/learn/kernel-fix-tutorial` from a real kernel fix to a
published package. :doc:`/upatches/write/attach-kinds` and
:doc:`/reference/formats/beefile` are the references to keep at hand, and
:doc:`/upatches/test/debugging` explains each way a load can fail.

- :doc:`learn/index`: concepts, the kernel-fix tutorial and the example
  packages
- :doc:`write/index`: attach kinds, maps, arenas and serializers, Lua
  decoders, and memory consistency
- :doc:`test/index`: test a upatch on a target and debug a failed load
- :doc:`publish/index`: the Beefile and publishing a package

.. toctree::
   :hidden:

   learn/index
   write/index
   test/index
   publish/index
