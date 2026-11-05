..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Memory consistency
==================

An upatch's programs run on every CPU at once. A hook on one CPU fills a
record in an arena while a hook on another CPU looks up the same key, and
the serializer reads a table that hooks may still write to. Each of them
sees the others' stores in an order the CPU chooses, which need not be
the order of the source.

x86-64 keeps stores in program order and lets only a later load pass an
earlier store, so code that lacks a barrier mostly works there. arm64 and
riscv64 reorder far more. On them the same code can let a reader see a
published index before the record it points to. A test on an x86-64
build host therefore says little about the targets that run an upatch on
arm64 or riscv64.

BPF gives a program three ways to order its accesses. The atomics that
return a value are fully ordered: ``atomic_fetch_add``,
``atomic_fetch_and``, ``atomic_fetch_or``, ``atomic_fetch_xor``, ``xchg``
and a ``cmpxchg`` that succeeds. ``load_acquire`` and ``store_release``
order the accesses after or before them. And a load through an index or
a pointer that an earlier ``READ_ONCE()`` returned stays after that
load, an address dependency. The JIT turns each into the CPU's own
instructions. Whether a given choice of them is enough for a pattern is
the question a litmus test answers.

:doc:`hazards` lists the patterns that go wrong in BPF code, what to
write instead and the Coccinelle rules that refuse them, and
:doc:`blitmus` tests an ordering on real hardware.

.. toctree::
   :titlesonly:

   hazards
   blitmus
