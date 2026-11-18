..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: upatch authors

Concurrency hazards
===================

Runs of a upatch's programs overlap on different CPUs, and on one CPU
a run can stop halfway while another one runs. Code that looks right
for one run at a time loses updates, mixes up records or decides on
data that changed under it. This page lists the hazards that recur in
BPF code, what to write instead, and the Coccinelle rule in
:src:`testing/coccinelle/` that refuses it in the tree where a rule can.

When a run can stop halfway
---------------------------

A BPF program never moves to another CPU while it runs. Whether another
run can start on its CPU before it ends depends on the kernel's
preemption model and on the program type. The models x86-64, arm64 and
riscv64 offer differ in one thing that matters here, preemptible RCU,
``CONFIG_PREEMPT_RCU``:

.. list-table::
   :header-rows: 1
   :widths: 22 14 26 38

   * - Model
     - Preemptible RCU
     - Non-sleepable, non-``syscall`` programs run with
     - Note
   * - ``PREEMPT``
     - Yes
     - Migration disabled
     - Another task can preempt a run.
   * - ``PREEMPT_LAZY`` alone
     - No
     - Preemption disabled
     - The test VM's kernel. Tasks are preempted, but not while a
       program runs.
   * - ``PREEMPT_RT``
     - Yes
     - Migration disabled
     - A section with bottom halves disabled can be preempted too.
   * - ``PREEMPT_DYNAMIC``
     - Yes
     - Migration disabled
     - The default and the one distribution kernels use. It picks
       ``full`` or ``lazy`` at boot and keeps preemptible RCU in both.
   * - ``none``, ``voluntary``
     - Not offered
     - Not offered
     - Kernels before 7.0 only, where no task preempted a running
       program. The kernels shirudo needs have neither.

``kprobe``, ``kretprobe`` and ``xdp`` programs run with preemption or
bottom halves disabled on every model, ``syscall`` programs with only
migration disabled on any kernel, and a sleepable program can sleep. On
every kernel an interrupt can run a softirq on top of a run in a
process, and an interrupt or an NMI can run other programs on top of any
run. Besides, the kernel skips a second run of some program types on
the CPU while one runs. The table gives, for each attach kind ``shirudo
build`` accepts (:doc:`/upatches/write/attach-kinds` lists them),
whether the kernel skips such a nested run and whether a run of another
task can come in between on the CPU under each model:

.. list-table::
   :header-rows: 1
   :widths: 28 24 16 16 16

   * - Programs
     - Nested run skipped
     - Another task between, without preemptible RCU
     - With preemptible RCU
     - On ``PREEMPT_RT``
   * - ``kprobe``, ``kretprobe``
     - Yes, while any ``kprobe`` or ``kretprobe`` program runs on the
       CPU
     - No
     - No
     - No
   * - ``fentry``, ``fexit``, ``fmod_ret``, ``tp_btf``
     - Yes, of the same program
     - No
     - Yes
     - Yes
   * - ``lsm``, ``uprobe``, ``uretprobe``, ``uprobe.multi``,
       ``uretprobe.multi``
     - No
     - No
     - Yes
     - Yes
   * - ``syscall``
     - No
     - Yes
     - Yes
     - Yes
   * - ``lsm.s``, ``fentry.s``, ``fexit.s``, ``fmod_ret.s``,
       ``uprobe.s``, ``uretprobe.s``, ``uprobe.multi.s``,
       ``uretprobe.multi.s``
     - Of the same program for ``fentry.s``, ``fexit.s`` and
       ``fmod_ret.s``; no for the others
     - Yes
     - Yes
     - Yes
   * - ``cgroup_skb``, ``netfilter``
     - No
     - No
     - Yes
     - Yes
   * - ``xdp``
     - No
     - No
     - No
     - Yes

What the table cannot carry:

- A sleepable run gives the CPU to another run at any sleeping call.
- An ``lsm`` hook a softirq calls can run on top of one a process
  called.
- An egress ``cgroup_skb`` run from a process can be preempted by
  another task's egress run on the same CPU, and an ingress run in a
  softirq can run on top of it. ``netfilter`` programs run at IPv6
  pre-routing, mostly in a softirq.
- ``xdp`` programs run in a device's NAPI poll with bottom halves
  disabled, so no task and no other softirq comes between on one CPU
  but on ``PREEMPT_RT``. The receive queues of a device run on
  different CPUs at once.

The test kernel is built with ``PREEMPT_LAZY`` alone, without
preemptible RCU, so a run in the test VM shows the preemption cases only
for ``syscall`` and sleepable programs. Do not build a program on a
guarantee that only its current attach type gives: an ``fentry`` program
moved to ``lsm`` loses it.

Where each hazard applies
-------------------------

The hazards below are of two kinds. Those of runs that interleave on one
CPU, per-CPU memory used as scratch and a per-CPU counter updated
without an atomic, depend on the preemption model and on the program
types that share the memory, as the table of `When a run can stop
halfway`_ says. Those of runs on different CPUs at once depend on
neither and apply on every kernel. Fix a hazard where it applies and not
elsewhere: a busy flag or an atomic that no interleaving needs costs
time on every run and hides the reasoning behind the code that does need
one. A upatch whose correctness depends on the preemption model says in
its ``README.md`` which model it is written for, as ``kernel-obs`` does
for the test VM's kernel.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Hazard
     - Applies
   * - Per-CPU memory used as scratch, a slot picked by CPU number, a
       per-CPU counter updated without an atomic
     - Where a second run that uses the memory can start on the CPU
       before the first ends. Read it from the table of `When a run can
       stop halfway`_, in the column of the target's model: memory one
       program uses alone is at risk where its row says Yes and its
       nested run is not skipped; memory several programs share is at
       risk where any of their rows says Yes. On every kernel also where
       a program that an interrupt, a softirq or an NMI runs shares the
       memory with one that a process runs.
   * - Updates of shared values, inserting a missing key,
       compare-and-swap, using a value after deleting its entry, reading
       user memory twice
     - On every kernel: other CPUs, or another thread, run at the same
       time.
   * - Publishing a record
     - On every kernel. arm64 and riscv64 reorder the stores, and the
       compiler may on any architecture.
   * - Switching buffers
     - On every kernel. With preemptible RCU a preempted run keeps the
       old buffer for longer.

Per-CPU memory used as scratch
------------------------------

A per-CPU map value is shared by every run on its CPU, not private to
one. A run that stores into it and uses the stored data later can find
it overwritten by a run that came in between. A slot of a plain array
picked with ``bpf_get_smp_processor_id()`` is the same thing built by
hand.

Use memory that belongs to the run instead:

- Task storage, for a program that runs in the context of the task it
  serves. Only that task's runs reach it, and a preempting task has its
  own. A program a softirq runs finds the task it interrupted as the
  current one, so keep such programs off that storage. The seal keeps
  its label buffer there.
- The stack, for what fits in it.
- A busy flag in the per-CPU value, taken with an atomic exchange and
  given back with a release store. A run that finds the flag taken
  skips its work and counts the skip.

Where no second run can come in between, as the tables above give, the
per-CPU value is the run's own and needs none of this. No rule refuses
the pattern: whether it is a hazard depends on the kernel a upatch is
written for and on the programs that share the memory, which a rule
cannot tell, so review decides.

Updates of shared values
------------------------

``count++`` is a load, an add and a store. Two CPUs that run it on the
same value at once lose one of the increments. That holds for the value
of a map that is not per-CPU, and for inode, socket and cgroup storage,
which hooks on different CPUs reach for the same inode, socket or
cgroup. Update such a value with ``__sync_fetch_and_add()``,
``__sync_fetch_and_or()`` and their kin, which do it in one instruction.
``bpf_map_rmw`` refuses the plain forms: ``++``, ``--``, ``+=``, ``-=``,
``|=``, ``&=``, ``x = x + n`` and ``x = x - n``. A global variable is a
value too, of the one array map that holds the object's ``.bss`` or
``.data``, which every CPU shares; ``bpf_map_rmw`` does not see it, so
update it the same way.

A per-CPU counter needs an atomic only where a run can come in between
on the same CPU: in a program the kernel does not guard, as listed
above, or when several programs update the same map. Task storage needs
none while only its own task's runs write it; a program that writes
another task's storage, a child's in ``task_alloc`` for instance, or
that a softirq runs needs the atomic.

Inserting a missing key
-----------------------

A lookup that finds nothing followed by an update with ``BPF_ANY``
races with another CPU doing the same: both find the key missing, both
insert, and the later insert overwrites what the first one stored, and
any update made to it in between. Insert with ``BPF_NOEXIST``, and when
it returns ``-EEXIST``, look the key up again and use the entry the
other CPU made. ``bpf_check_then_insert`` refuses the ``BPF_ANY`` form.

Using a value after deleting its entry
--------------------------------------

``bpf_map_delete_elem()`` gives a hash map's element back to the map's
free list at once, without waiting for an RCU grace period. An update on
this CPU or another one can take it and fill it with another entry while
a pointer from an earlier lookup still reads it: RCU keeps the memory
valid, not its contents. Read or copy what the code needs before the
delete. ``bpf_map_use_after_delete`` refuses a read through the pointer
after a delete from the same map; it cannot tell whether the two keys
are equal and takes any delete. Testing the pointer against ``NULL``
reads nothing and is left alone.

An update of a key the hash map already holds does the same to the old
element: the map links a new element in its place and hands the old one
to the next update on that CPU. A program that holds a pointer from a
lookup and updates the value through it changes the entry in place; one
that replaces the entry with ``bpf_map_update_elem()`` while other runs
hold pointers to it lets them read or write a stranger's entry. No rule
refuses this.

Compare-and-swap
----------------

A compare-and-swap can fail: another CPU changed the value first. Code
that drops the result goes on as if it had won. Check it, and retry or
give up, as the insert path of :src:`upatches/kernel-obs/obs_table.h`
does after four attempts. A failed compare-and-swap also orders no other
access. ``bpf_cas_unchecked`` refuses a dropped result.

Publishing a record
-------------------

A program that fills a record and then stores a pointer or an index to
it publishes the record. A reader on another CPU that loads the pointer
must see the filled record, but arm64 and riscv64 let it see the
pointer first unless the store orders the filling stores before it.
``WRITE_ONCE()`` does not. Publish with a release store,
``__atomic_store_n(&p, record, __ATOMIC_RELEASE)``, or with an atomic
that returns a value, as a successful compare-and-swap does. The reader
loads the pointer with ``READ_ONCE()`` and reads through it, an address
dependency, or with a load-acquire,
``__atomic_load_n(&p, __ATOMIC_ACQUIRE)``. Use the load-acquire when the
path that reads through the index first tests it for equality with a
constant, as ``if (idx == 1)`` does: the compiler can then use the
constant in place of the index and lose the dependency. A bounds check
such as ``idx > CAPACITY`` keeps it.

The arena table template publishes its active buffer with a release
store. ``bpf_publish`` refuses ``WRITE_ONCE()`` of a pointer. It does not
see an index published with ``WRITE_ONCE()``.

Which accesses order what:

- ``__sync_fetch_and_add()`` and its kin, ``__sync_lock_test_and_set()``,
  ``__atomic_exchange_n()`` and a successful compare-and-swap are full
  barriers. clang 20 and later emit the value-returning instruction for
  ``__sync_fetch_and_add()`` and its kin even when the result is unused.
  Older clang emits the atomic without fetch there, which orders nothing.
- ``__atomic_fetch_add(p, v, __ATOMIC_RELAXED)`` with its result unused
  orders nothing, nor does a failed compare-and-swap. With its result
  used, clang emits the value-returning instruction, which orders more
  than the source asks for.
- A release store orders the accesses before it, and a load-acquire the
  accesses after it. ``__sync_lock_release()`` is a release store. clang
  refuses ``__atomic_load_n()`` and ``__atomic_store_n()`` with
  ``__ATOMIC_SEQ_CST``.

Switching buffers
-----------------

A double buffer that a reader drains while programs fill the other half
has no grace period in BPF: a program that loaded the active pointer
just before the switch still writes into the half being drained. The
reader must expect those late writes. The arena table template counts
the entries it finds in the spare half at the next switch as lost and
clears it, so a late write costs a record, not the table. No rule finds
this; design for it.

Reading user memory twice
-------------------------

User memory can change between two reads of the same address: another
thread of the process writes it meanwhile. A program that checks the
first copy and acts on the second checks different data. Read it once
into memory of the program's own and use that copy, and in an LSM hook,
prefer the kernel's copy in the hook's arguments.
``bpf_user_double_fetch`` refuses two reads of one address.

What the rules cannot see
-------------------------

The ``bpf_`` rules match code within one function, so a hazard spread
over several functions passes them, and they cannot parse a file that
defines its own token-pasting macros, such as
:src:`upatches/kernel-obs/obs_table.h`. Write the ordering between CPUs
that such code relies on as a litmus test and run it, as :doc:`blitmus`
shows. blitmus does not cover runs that interleave on one CPU or what
happens inside maps and helpers, so review decides those.

Related
-------

- :doc:`blitmus` to test an ordering on each architecture
- :doc:`/upatches/write/pitfalls` for what a program misses or cannot
  rely on
- :doc:`/upatches/write/maps-arenas-serializers` for the arena table and
  its serializer
- :doc:`/contribute/code/developer-guide` for the Coccinelle rules
