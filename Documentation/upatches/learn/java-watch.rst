..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: upatch authors, security reviewers

How java-watch works
====================

A Java upatch reaches only the JVMs that start with its ``-javaagent``
option (:doc:`/upatches/write/java-agents`). The ``java-watch`` upatch of
:src:`upatches/java-watch` lists the JVMs that run on a node and, for
each, the sealed agent jars it opened, so that the JVMs the option did
not reach show up. This page follows its BPF program,
:src:`upatches/java-watch/java-watch.bpf.c`, from the load to the read:
what each hook stores, which state the table goes through, how runs on
several CPUs share it and where it stops. The package itself is
described in :doc:`examples`.

The programs
------------

Every program observes. The LSM programs return the result they were
given and change nothing.

.. list-table::
   :header-rows: 1
   :widths: 30 26 44

   * - Program
     - Section
     - Role
   * - ``shirudo_test__java_watch``
     - ``syscall``
     - Runs once after the attachment and allocates the table.
   * - ``jw_mmap_file``
     - ``lsm/mmap_file``
     - A process maps ``libjvm.so`` executable: it takes a slot.
   * - ``jw_file_open``
     - ``lsm.s/file_open``
     - A JVM opens a sealed agent jar: the slot records it.
   * - ``jw_exec``
     - ``lsm/bprm_committed_creds``
     - The process executes another program: its slot is freed.
   * - ``jw_exit``
     - ``tp_btf/sched_process_exit``
     - The last thread of the process exits: its slot is freed.
   * - ``shirudo_serialize__jvms``
     - ``syscall``
     - ``shirudo upatch map java-watch jvms`` and the map export read
       the table through it.

The state
---------

The table
~~~~~~~~~

The JVMs live in one ``struct jw_table`` in the arena ``obs_i_arena``:
a counter ``overflow`` of the JVMs that found no free slot, and 512
slots of 288 bytes, 37 pages of the 40 the arena allows. The table is
allocated once and never moves; the global ``jw_table`` points to it.

.. list-table:: A slot, ``struct jw_slot``
   :header-rows: 1
   :widths: 8 18 74

   * - Offset
     - Field
     - Content
   * - 0
     - ``seq``
     - The slot's state in bits 0 and 1 and its generation above them.
   * - 8
     - ``tgid``
     - The process ID in the initial PID namespace, the leader's
       ``tgid``.
   * - 12
     - ``euid``
     - The effective user ID of the thread that mapped ``libjvm.so``.
   * - 16
     - ``start_ns``
     - The leader's ``start_boottime``.
   * - 24
     - ``cgroup``
     - The cgroup of the thread that mapped ``libjvm.so``.
   * - 32
     - ``seen_ns``
     - The boot time of the mapping.
   * - 40
     - ``mnt_ns``
     - The inode number of the mount namespace.
   * - 44
     - ``jvm_dev``
     - The device of the ``libjvm.so`` it mapped.
   * - 48
     - ``jvm_ino``
     - The inode of that ``libjvm.so``, which with ``jvm_dev`` names the
       JDK.
   * - 56
     - ``more_agents``
     - Set once a fifth agent found no entry.
   * - 64
     - ``agents[4]``
     - Four entries of 56 bytes: the jar's inode ``ino``, ``ready``,
       ``name_cut`` and its file name ``name``, 40 bytes with the NUL.

An agent entry is taken when its ``ino`` turns nonzero, and complete
when ``ready`` is 1.

The sequence word
~~~~~~~~~~~~~~~~~

A slot's ``seq`` holds one of three states, ``FREE`` (0), ``CLAIMED``
(1) and ``LIVE`` (2), in its low two bits, and a generation above them.
Each change is one atomic operation on the word:

.. code-block:: text

          compare-and-swap            release store
   FREE g ─────────────────▶ CLAIMED g ─────────────▶ LIVE g
     ▲                                                  │
     └───────────── compare-and-swap ───────────────────┘
                    to FREE g+1

The arena's pages start zeroed, so every slot starts free in generation
0. A free always moves the slot to the next generation: a slot taken
again by another JVM never has the ``seq`` it had for the previous one.
That is how the serializer and the agent path tell the same JVM from a
reused slot.

The process's reference
~~~~~~~~~~~~~~~~~~~~~~~

Task storage ``obs_i_jvm_task`` keeps a ``struct jw_ref`` with the
slot's index ``idx``, its ``seq`` when it went ``LIVE`` and a ``state``:

.. code-block:: text

   NONE ──compare-and-swap──▶ CLAIMING ──release──▶ READY    a slot was taken
                                       └─release──▶ FAILED   no table or no free slot

It is kept on the thread group leader, so that every thread of the JVM
finds its slot with one lookup instead of a search of the table.
``idx`` and ``seq`` are written before the release store of ``READY``,
and every reader loads ``state`` with acquire before it reads them. A
``FAILED`` reference is never tried again.

The scratch
~~~~~~~~~~~

``bpf_get_file_xattr()`` can sleep and writes through a dynptr, which
has to point to map memory rather than to the stack. Task storage
``obs_i_jvm_scr`` gives each thread that opens a candidate jar 64 bytes
for the label.

``jvms`` is a one-element array that holds nothing: it gives the table
the name that ``shirudo upatch map`` and the decoder manifest use.
``shirudo_ser`` is the chunk the serializer fills.

The load
--------

shirudo attaches the programs, then runs ``shirudo_test__java_watch``
once. It allocates the 37 pages of the table and publishes the pointer
with a release store to ``jw_table``. A failed allocation fails the
load.

Every other program reaches the table through ``jw_table_get()``, which
holds a call to ``bpf_arena_alloc_pages()`` for zero pages that runs
only while ``jw_table`` is still NULL. The verifier binds a program to
an arena only when its code names the arena map, and the hooks
otherwise reach the arena only through the pointer; the call is that
reference, and asks for nothing.

A JVM that maps ``libjvm.so`` between the attachment and that run finds
no table. Its reference becomes ``FAILED`` and it is not listed, nor
counted in ``overflow``.

A JVM appears
-------------

``lsm/mmap_file`` runs for every ``mmap()`` of a file before the mapping
is made. The dynamic loader maps the executable segments of
``libjvm.so`` one by one, so a JVM reaches it more than once.

.. code-block:: text

   jw_mmap_file(file, reqprot, prot, flags, ret)
    ├─ ret, no file, no PROT_EXEC, or a name other than "libjvm.so"
    │    └─ return ret                       every other process ends here
    ├─ ref = the leader's task storage, created
    ├─ compare-and-swap ref->state NONE → CLAIMING
    │    └─ it was not NONE: return          another segment or thread was first
    └─ jw_claim()
        ├─ start = (tgid * 0x9e3779b1) >> 23       a slot of 0..511
        ├─ for up to 16 slots from start:
        │    not FREE: next slot
        │    compare-and-swap seq → CLAIMED: lost, next slot
        │    jw_fill()                       the fields, the agents cleared
        │    release store seq = LIVE        the slot is published
        │    ref->idx, ref->seq
        │    release store ref->state = READY
        └─ none free: overflow + 1, ref->state = FAILED

The compare-and-swap on the reference lets one mapping of one thread
take the slot, so a process never holds two. The fields are written
while the slot is ``CLAIMED``, a state readers skip, and the release
store of ``LIVE`` makes them visible together. ``jw_fill()`` writes
every field and clears ``ino``, ``ready`` and ``name_cut`` of each agent,
so nothing of the slot's previous JVM remains.

A JVM looks only at the 16 slots its process ID hashes to. One that
finds them all taken is counted in ``overflow`` and not listed, however
many slots are free elsewhere in the table.

A JVM opens an agent
--------------------

``lsm.s/file_open`` runs for every open on the host. It is sleepable
only for the extended attribute read.

.. code-block:: text

   jw_file_open(file, ret)
    ├─ ret or no file: return ret
    ├─ jw_task_ref()         the leader's reference, under RCU, READY with acquire
    │    └─ not a JVM: return 0              every other process ends here
    ├─ jw_in_agent_dir()     "*.jar" whose parent directory is named "shirudo-java"
    │    └─ no: return 0                     the JVM's other opens end here
    ├─ jw_sealed()           security.bpf.shirudo read into the scratch, 64 bytes long
    │    └─ no: return 0                     a copy, or a jar root put there
    └─ jw_add_agent()

The checks run from the cheapest: one task storage lookup for any open,
two name comparisons for an open of a JVM, and the attribute read only
for a jar in a ``shirudo-java`` directory.

The directory is matched by its name, not its path, so a bind mount of
``/run/shirudo-java`` in a container counts. The trust comes from the
seal label: only a task with shirudo's runtime authority can set
``security.bpf.shirudo`` (:doc:`/internals/seal`), so a jar that carries
it is one shirudo wrote. The program checks that the value is the
length of a label, not which label it is.

.. code-block:: text

   jw_add_agent(ref, file)
    ├─ slot->seq != ref->seq: return         the slot is no longer this JVM's
    ├─ for each of the four agents:
    │    ino == this jar's inode: return     already recorded
    │    ino taken: next
    │    compare-and-swap ino 0 → this inode
    │      same inode won: return            another thread recorded it
    │      another inode won: next
    │    the name and name_cut
    │    release store ready = 1
    └─ all four taken: more_agents = 1

The inode number takes the entry, the name follows, and ``ready``
publishes it. A JVM's threads open jars at once, and each step allows
for another thread between it and the next. An agent is told apart by
its inode: the same jar opened twice gives one entry, two copies give
two.

The comparison of ``seq`` is enough without a lock, because a slot is
freed only when no thread of its process can be in this path: on an
exit, after the last thread is gone, and on an exec, after
``de_thread()`` killed every other thread.

The process executes another program
------------------------------------

``lsm/bprm_committed_creds`` runs after ``de_thread()``: the task that
executes is now the leader and the only thread.

.. code-block:: text

   jw_exec(bprm)
    ├─ a reference on the task:
    │    free its slot if READY
    │    delete the reference                a new JVM in it takes a new slot
    └─ no reference:
         jw_free_process(tgid, start_boottime)

When a thread other than the leader executes, ``de_thread()`` makes it
the leader with the old leader's ``tgid`` and ``start_boottime``, and
the old leader, which carried the reference, goes. The identity stays:
``jw_free_process()`` reads the 16 slots of the process ID's probe and
frees the live one with both values. ``start_boottime`` keeps a reused
process ID from freeing another process's slot.

Every exec on the host that is not a JVM's takes the second branch and
reads 16 slots.

A free is a compare-and-swap from the exact ``LIVE`` word to ``FREE`` of
the next generation. Whichever of the exec and the exit comes first
frees the slot; the other finds a different word and does nothing, and
neither can free a slot another JVM took since.

The process exits
-----------------

``tp_btf/sched_process_exit`` fires for every thread that exits.
``jw_exit`` acts only when ``group_dead`` says it is the last one, and
frees the slot of the leader's reference. It does not delete the
reference: the kernel frees task storage with the leader's
``task_struct``, which outlives the last thread until the leader is
reaped. No LSM hook marks the end of a process, which is why this one
program is a tracepoint.

Reading the list
----------------

``shirudo upatch map java-watch jvms`` and the map export run
``shirudo_serialize__jvms`` with a cursor, a slot index, and run it
again from ``next_cursor`` until the chunk is marked done. Each run
fills one page of 4032 bytes in records of 256 bytes: a header, then up
to 14 JVMs.

.. list-table:: The page header, record 0
   :header-rows: 1
   :widths: 10 12 78

   * - Offset
     - Type
     - Content
   * - 0
     - ``u32``
     - ``0x534d564a``, ``JVMS``
   * - 4
     - ``u16``
     - Version, 1
   * - 6
     - ``u16``
     - The size of a record's header, 64
   * - 8
     - ``u16``
     - The size of a record, 256
   * - 10
     - ``u16``
     - Records per page, 14
   * - 12
     - ``u32``
     - Slots, 512
   * - 16
     - ``u32``
     - ``overflow``
   * - 20
     - ``u32``
     - Agents per slot, 4
   * - 24
     - ``u64``
     - The boot time of this read

.. list-table:: A record
   :header-rows: 1
   :widths: 10 12 78

   * - Offset
     - Type
     - Content
   * - 0
     - ``u32``
     - The slot index
   * - 4
     - ``u32``
     - Flags: bit 0 present, bit 1 more agents, bit ``8 + i`` the name
       of agent ``i`` cut
   * - 8
     - ``u32``, ``u32``
     - ``tgid``, ``euid``
   * - 16
     - ``u64`` x 3
     - ``start_ns``, ``cgroup``, ``seen_ns``
   * - 40
     - ``u32``, ``u32``
     - ``mnt_ns``, ``jvm_dev``
   * - 48
     - ``u64``
     - ``jvm_ino``
   * - 56
     - ``u32``
     - The number of agents that follow
   * - 64
     - 4 x 48 bytes
     - Each agent's ``ino`` and its 40-byte name, packed

Each slot is read as a seqlock reader:

.. code-block:: text

   jw_emit_slot()
    ├─ seq1 = seq, acquire          not LIVE: skip
    ├─ copy the fields
    ├─ copy each agent whose ready is 1, acquire
    ├─ seq2 = fetch-and-add of 0 to seq
    └─ seq1 == seq2: keep the record, else the next one overwrites it

The acquire load of ``seq`` pairs with the release store that made the
slot ``LIVE``, and the fetch-and-add is a full barrier that keeps every
read of a field before the second read of ``seq``. A slot freed while it
was copied, and maybe taken again, has another generation: the record
is dropped, and the page's byte count never covers it.

The serializer writes nothing to the arena and does not read
``SERIAL_CTX_F_PEEK``. The table is the set of JVMs running now, not an
interval of events, so every read returns the whole list. Each record is
one JVM's consistent state; a read of several pages is not one snapshot,
and can miss a JVM that took a slot behind the cursor or list one that
exited during the read.

The decoder, :src:`upatches/java-watch/decoders/jvms.lua`, takes
``overflow`` and the read's boot time from each page's header, and turns
each record with bit 0 set into a JVM. It converts ``start_ns`` and
``seen_ns`` to Unix time from the export's own time and that boot time,
sets ``patched`` when the record names an agent, and counts the JVMs
without one in ``unpatched``. The fields are listed in the package's
README, included in :doc:`examples`.

One JVM from start to exit
--------------------------

.. code-block:: text

   java -javaagent:/run/shirudo-java/foo.jar -cp app.jar Main

   execve("java")              jw_exec: no reference, 16 slots read, none matches
   libjvm.so mapped r-x        jw_mmap_file: reference NONE → CLAIMING,
                               slot FREE g → CLAIMED g → LIVE g, reference READY
   more of libjvm.so mapped    jw_mmap_file: the reference is not NONE, nothing
   the JVM opens its modules   jw_file_open: READY, not a jar in shirudo-java
   the JVM opens foo.jar       jw_file_open: sealed, agents[0] = foo.jar, ready
   upatch map java-watch jvms  serializer: LIVE g before and after, listed, patched
   the last thread exits       jw_exit: LIVE g → FREE g+1
   upatch map java-watch jvms  serializer: FREE, not listed

A JVM started without the option takes the same steps without the open
of ``foo.jar`` and is listed without an agent. A child that ``fork()``
creates gets no task storage from its parent; it is listed once it maps
``libjvm.so`` itself, as a ``java`` it executes does.

Runs that share the table
-------------------------

Runs on several CPUs share the slots, and the program uses no per-CPU
memory, so it is correct under every preemption model
(:doc:`/upatches/write/memory-consistency/hazards`). Every shared update
is atomic or made while the slot is ``CLAIMED`` and seen by no one else.

.. list-table:: Release and acquire pairs
   :header-rows: 1
   :widths: 38 34 28

   * - Release
     - Acquire
     - Carries
   * - ``seq`` set ``LIVE`` in ``jw_claim()``
     - ``seq`` in ``jw_emit_slot()`` and ``jw_free_process()``
     - The slot's fields
   * - ``state`` set ``READY`` in ``jw_claim()``
     - ``state`` in ``jw_task_ref()`` and ``jw_free_ref()``
     - ``idx`` and ``seq``
   * - ``ready`` set in ``jw_add_agent()``
     - ``ready`` in ``jw_emit_slot()``
     - The agent's name and ``name_cut``
   * - ``jw_table`` set in ``shirudo_test__java_watch``
     - ``READ_ONCE()`` in ``jw_table_get()``
     - The table

.. list-table:: Compare-and-swap, and who it decides between
   :header-rows: 1
   :widths: 40 60

   * - Word
     - Racers
   * - ``state`` from ``NONE`` to ``CLAIMING``
     - The segments of ``libjvm.so`` and the threads of one process
   * - ``seq`` from ``FREE`` to ``CLAIMED``
     - The JVMs of other processes probing the same slot
   * - An agent's ``ino`` from 0
     - The threads of one JVM opening jars at once
   * - ``seq`` from ``LIVE g`` to ``FREE g+1``
     - The exec and the exit of one process

Cost
----

.. list-table::
   :header-rows: 1
   :widths: 26 38 36

   * - Program
     - Any process
     - A JVM
   * - ``lsm/mmap_file``
     - A ``PROT_EXEC`` test and a nine-byte name comparison on an
       executable mapping of a file
     - A task storage creation, a compare-and-swap and up to 16 slots,
       once
   * - ``lsm.s/file_open``
     - One task storage lookup under RCU
     - Two name comparisons per open; the attribute read only for a jar
       in ``shirudo-java``
   * - ``lsm/bprm_committed_creds``
     - A task storage lookup and 16 slots
     - A compare-and-swap and a task storage deletion
   * - ``tp_btf/sched_process_exit``
     - The ``group_dead`` test; a task storage lookup on the last thread
     - A compare-and-swap
   * - ``shirudo_serialize__jvms``
     - Only on a read: 512 slots, 14 records per run
     -

The arena takes 37 pages, about 144 KiB, at the load. Each JVM adds a
24-byte reference, and each of its threads that opens a candidate jar
64 bytes of scratch.

Where it stops
--------------

- A JVM is a process that maps a file named ``libjvm.so``. A renamed
  copy runs unlisted, any process that maps a file of that name is
  listed, and a native image has no ``libjvm.so``.
- A JVM that started before the load, or between the attachment and the
  table's allocation, is not listed. After a reboot ``init`` restores
  the upatch before any JVM starts.
- A JVM whose 16 slots are taken is counted in ``overflow`` and not
  listed. A fifth agent sets ``more_agents`` and is not named.
- An agent is a jar named ``*.jar`` in a directory named
  ``shirudo-java`` whose seal attribute has a label's length; the
  label's value is not compared.
- An opened jar says the agent ran at the start, not that it still
  guards what it patched: the application can undo what Java code in it
  did (R24 in :doc:`/security/threat-model`).
- ``pid`` is the process ID in the initial PID namespace; ``mnt_ns`` and
  ``cgroup_id`` tell the container.
