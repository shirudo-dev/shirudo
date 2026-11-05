..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: upatch authors

Test memory ordering with blitmus
=================================

`blitmus <https://github.com/puranjaymohan/blitmus>`_ turns a litmus
test, the notation of the kernel's memory model for a pattern of
concurrent accesses, into BPF programs. It runs each process of the test
on a CPU of its own through ``BPF_PROG_TEST_RUN`` and counts how often
the outcome the test asks about occurs. The accesses go through the same
BPF JIT as an upatch's, on real hardware, so a run on each architecture
an upatch targets shows whether the ordering its programs rely on holds
there.

Use it for an upatch whose programs share state across CPUs: a table
that hooks fill while the serializer drains it, a record published
through an index, or a lock or a lock-free list built from atomics. This
page writes the insert path of the :src:`upatches/kernel-obs/obs_table.h`
template as a litmus test and runs it.

blitmus tests how accesses on different CPUs are ordered once clang,
the verifier, the JIT and the CPU have handled them. It runs the test's
code, not the upatch's programs at their attach points, and each process
alone on its CPU. It shows nothing about runs that interleave on one
CPU, or about what happens inside maps and helpers, such as an element
that a delete hands to the next update. :doc:`hazards` covers those.

Before you begin
----------------

- A machine of each architecture the upatch targets, x86-64, arm64 and
  riscv64, or a KVM guest on one
- Root on it, with the kernel version and configuration the targets run
- The clang the upatch build runs, ``make``, a C compiler, the libelf and
  zlib headers, Python 3 and git
- The upatch source

A guest that QEMU emulates without KVM barely reorders accesses, so a
run there shows nothing. The JIT that lowers the accesses is part of
what a run tests, which is why the kernel has to match the targets'.

Do not use a shirudo target for the runs. blitmus loads unsigned BPF
programs, and the ``lsm/bpf`` hook of a target refuses them.

Write the test
--------------

1. List the accesses through which programs on different CPUs
   communicate, and write each with the litmus primitive for the
   instruction clang emits for it:

   .. list-table::
      :header-rows: 1
      :widths: 44 24 32

      * - In the upatch
        - BPF instruction
        - In the litmus test
      * - ``READ_ONCE(x)``, ``WRITE_ONCE(x, v)`` from ``misc.h``
        - Load, store
        - ``READ_ONCE(*x)``, ``WRITE_ONCE(*x, v)``
      * - ``__sync_fetch_and_add(p, v)``
        - ``atomic_fetch_add``
        - ``atomic_fetch_add(v, p)``
      * - ``__sync_fetch_and_or(p, v)``, ``__sync_fetch_and_and(p, v)``,
          ``__sync_fetch_and_xor(p, v)``
        - ``atomic_fetch_or``, ``atomic_fetch_and``, ``atomic_fetch_xor``
        - None, ``atomic_fetch_add(v, p)`` orders the same
      * - ``__sync_val_compare_and_swap(p, old, new)``
        - ``cmpxchg``
        - ``cmpxchg(p, old, new)``
      * - ``__atomic_exchange_n(p, v, __ATOMIC_SEQ_CST)``
        - ``xchg``
        - ``xchg(p, v)``
      * - ``__atomic_store_n(p, v, __ATOMIC_RELEASE)``
        - ``store_release``
        - ``smp_store_release(p, v)``
      * - ``__atomic_load_n(p, __ATOMIC_ACQUIRE)``
        - ``load_acquire``
        - ``smp_load_acquire(p)``
      * - ``__atomic_fetch_add(p, v, __ATOMIC_RELAXED)``, result unused
        - Atomic add without fetch
        - ``atomic_add(v, p)``

   clang 20 and later emit ``atomic_fetch_add`` for
   ``__sync_fetch_and_add()`` even when the result is unused, so that
   call is fully ordered either way. ``load_acquire`` and
   ``store_release`` need instruction set v4, which the upatch build
   selects with ``-mcpu=v4``. :doc:`hazards` says what each access
   orders.

   The JIT lowers ``atomic_fetch_or``, ``atomic_fetch_and`` and
   ``atomic_fetch_xor`` to other instructions than ``atomic_fetch_add``,
   so a test that writes them as ``atomic_fetch_add`` checks the pattern
   but not those instructions. A value-returning atomic on a variable no
   other access in the test uses, such as a statistics counter, orders
   like ``smp_mb()``, which blitmus provides.

   blitmus has no ``smp_rmb()`` or ``smp_wmb()``, as BPF has no
   instruction for a read or a write barrier alone, and no RCU or lock
   helpers. A section under ``bpf_spin_lock()`` cannot be tested. A lock
   built from atomics can, by writing its acquire and release as the
   atomics it uses.

   Write each process body without braces, as blitmus reads a body up to
   its first ``}``, and declare each register as ``int r<n>;``.

2. Write the pattern as a litmus test. Each process, ``P0``, ``P1`` and
   so on, is the code of one CPU, and the variables are shared. ``exists``
   names an outcome of the registers at the end. The ``Result`` line says
   how often the kernel's memory model allows that outcome: ``Never``,
   ``Sometimes`` or ``Always``.

   The insert path of ``obs_table.h`` fills a new entry and then
   publishes its index in the bucket head with
   ``__sync_val_compare_and_swap()``. A reader on another CPU loads the
   head with ``READ_ONCE()`` and reads the entry through that index. A
   reader that sees the new index must see the filled entry, so the
   outcome where it sees the index and an empty entry is forbidden. Save
   the test as ``MP+cmpxchg+addr.litmus``:

   .. code-block:: text

      C MP+cmpxchg+addr

      (*
       * Result: Never
       *
       * blitmus: arena
       *)

      {}

      P0(int *key, int *head)
      {
          WRITE_ONCE(key[1], 1);
          cmpxchg(head, 0, 1);
      }

      P1(int *key, int *head)
      {
          int r0;
          int r1;

          r0 = READ_ONCE(*head);
          r1 = READ_ONCE(key[r0]);
      }

      exists (1:r0=1 /\ 1:r1=0)

   ``key[r0]`` makes ``key`` an array that ``P1`` indexes with the value
   it loaded, which keeps the address dependency of the template's
   ``&state->entries[idx]``. ``blitmus: arena`` also builds a variant
   with the variables in an arena, where the template keeps its table.

3. Write a control: the same test with the publishing store weakened, so
   that the memory model allows the outcome. A run in which the control
   never shows its outcome has not reordered anything, and a 0 for the
   real test from that run says nothing. Save it as
   ``MP+once+addr.litmus``:

   .. code-block:: text

      C MP+once+addr

      (*
       * Result: Sometimes
       *)

      {}

      P0(int *key, int *head)
      {
          WRITE_ONCE(key[1], 1);
          WRITE_ONCE(*head, 1);
      }

      P1(int *key, int *head)
      {
          int r0;
          int r1;

          r0 = READ_ONCE(*head);
          r1 = READ_ONCE(key[r0]);
      }

      exists (1:r0=1 /\ 1:r1=0)

   x86-64 keeps two stores in order, so the control never shows its
   outcome there. Use the ``SB+poonceonces`` test that ships with blitmus
   as the control on x86-64. ``MP+addrfold``, which also ships with
   blitmus, is the control for a reader's address dependency: the
   compiler folds it away, and arm64 shows the outcome.

Build and run
-------------

4. Clone blitmus with its submodules, add the tests and build them with
   the clang the upatch build runs, ``/usr/bin/clang`` or
   ``/usr/lib/llvm-23/bin/clang`` as
   :doc:`/operate/plan/system-requirements` lists:

   .. code-block:: console

      $ git clone https://github.com/puranjaymohan/blitmus.git
      $ cd blitmus
      $ git submodule update --init --recursive
      $ cp <path>/MP+cmpxchg+addr.litmus litmus_tests/
      $ cp <path>/MP+once+addr.litmus litmus_tests/
      $ make CLANG=<clang>

   ``<path>`` is the directory that holds the tests, and ``<clang>`` the
   path of that clang. Another clang can lower an access to another
   instruction, and the run then tests code the upatch does not run.

   ``make`` converts every test in ``litmus_tests/`` and builds one
   program per test into ``bin/``, named after the test in lower case
   with ``_`` for ``+``: ``bin/mp_cmpxchg_addr``, the arena variant
   ``bin/mp_cmpxchg_addr_arena`` and ``bin/mp_once_addr``. For a test
   that uses a primitive blitmus cannot express it prints
   ``Skipping <test>: unsupported primitive(s): <names>`` and builds no
   program.

5. Run the programs as root:

   .. code-block:: console

      # ./bin/mp_cmpxchg_addr
      # ./bin/mp_cmpxchg_addr_arena
      # ./bin/mp_once_addr

   Each runs the processes 41 million times by default. ``-i <n>`` runs
   them ``<n>`` times 10,000. ``./run.sh`` runs every program in ``bin/``
   and prints a table of the results.

Verify
------

6. Read the end of the output. The histogram marks the ``exists``
   outcome with ``*``. ``Witnesses`` counts the runs that ended in that
   outcome as ``Positive`` and the others as ``Negative``, and
   ``Observation`` says how often the outcome was seen. ``Allowed`` on
   the ``Test`` line names the kind of condition, not a verdict. For a
   ``Result: Never`` test, ``Positive`` must be 0, and for its control on
   arm64 and riscv64 it must not be. The program exits with status 1
   when the CPU produced an outcome the test forbids, or missed one that
   ``Result: Always`` requires. It also exits non-zero when the run did
   not complete, and standard error then says why: an option it does
   not accept, programs that failed to load, or a test run that failed.
   Status 1 alone does not tell the two apart; standard error does.

7. Run the same tests on each architecture the upatch targets. A
   forbidden outcome on arm64 or riscv64 that x86-64 never shows is the
   usual sign of a missing barrier. Make the access in the upatch
   stronger, for example a ``WRITE_ONCE()`` that publishes an index into
   a value-returning atomic, change the test to match and run it again.

A run that never shows a forbidden outcome is evidence, not proof:
blitmus samples executions, and a CPU can order more than the memory
model requires. arm64 with LSE atomics orders a failed ``cmpxchg``, and
x86-64 orders an atomic add without fetch. Code that relies on such an
ordering passes there and fails on a CPU that does not give it.

``herd7`` with the kernel's memory model in ``tools/memory-model/``
checks a pattern against the model itself. It reads its own litmus
syntax, which has no arrays such as ``key[r0]``, so write the pattern
with pointers for it. It checks the source, not the program clang
emits: a dependency the compiler folds away passes ``herd7`` and fails
blitmus.

Next steps
----------

- :doc:`/upatches/write/maps-arenas-serializers` for the arena table and
  its serializer
- :doc:`/contribute/arch-support` for the architectures an upatch runs on
- The `blitmus README <https://github.com/puranjaymohan/blitmus#readme>`_
  for the annotations that test arena page reuse
