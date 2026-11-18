..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: upatch authors

Maps, arenas and serializers
============================

A upatch that observes builds up records in the kernel, and the operator
wants them out of the target at a steady rate, in complete and bounded
snapshots. This page explains why such state lives in a BPF arena, how a
serializer program turns it into records, what draining and peeking mean,
and what the export reads.

Why plain maps are not enough
-----------------------------

The obvious design keeps records in a hash map and lets the exporter read
it from userspace, one ``BPF_MAP_GET_NEXT_KEY`` and ``BPF_MAP_LOOKUP_ELEM``
at a time. Two things go wrong. The programs keep writing while the
exporter walks, so the snapshot mixes entries from different moments and
can miss or repeat keys. And nothing empties the map: once it is full,
every new key is refused, silently, until someone deletes entries, which
from userspace is yet another racing walk.

A structure with more shape than a flat table, a tree, a ring or several
maps that refer to each other, cannot be read consistently from userspace
at all. Its invariants hold only for code that takes the same locks or
follows the same ordering as the writers, and that code runs in the
kernel.

So we keep accumulating state in one place the upatch's own programs
control, and have a program of the upatch render it. Hash and array maps
remain for what cannot live elsewhere: task, socket and per-CPU scratch
state, lookup keys the kernel owns, and the serializer's output map.

Why an arena
------------

A ``BPF_MAP_TYPE_ARENA`` map is memory that the upatch's programs allocate
from and address with ordinary pointers. That gives three properties a
hash map lacks. The upatch can keep two copies of a table and switch
between them, so an export reads a buffer that no hook writes to any more.
The serializer can reset that buffer when the export is done, so the table
holds one export interval and never fills up for good. And when an
interval runs out of room, the table can count the refused records and
report the count with the snapshot.

Userspace cannot iterate an arena through ``bpf()``: the kernel has no
key walk for it, and ``shirudo upatch map`` reports such a map as one
whose contents require a serializer. A program uses at most one arena, so
a upatch keeps all its tables in one. The arena needs a 64-bit kernel
with an MMU and a BPF JIT that supports arenas: x86-64, arm64, and
riscv64 on CPUs with the Zacas extension. :doc:`/contribute/arch-support`
lists the conditions.

obs_table.h template
--------------------

:src:`upatches/kernel-obs/obs_table.h` is the template for such a table. A
source defines the table's name, key and value types, capacity, bucket
count, record size and record encoder, and includes the file once per
table. Each inclusion produces a hash table in the arena and a serializer
for it.

The table is double-buffered, as Figure 1 shows. Hooks insert into the
active buffer. A probe chain of bounded length finds an existing key, and
a new key takes the next free slot. When the slots run out, the insert
fails and the ``overflow`` count goes up. Records are therefore deltas
over one export interval.

.. figure:: /images/upatches-double-buffer.svg
   :alt: Hooks write into the active buffer. An export swaps the buffers,
         a serializer renders the drained buffer page by page into the
         shirudo_ser map, and the drained buffer is cleared after the last
         page.

   Figure 1. One table of an ``obs_table.h`` instance. The export swaps
   the buffers, renders the drained one and clears it after its last page.

The first serializer run of an export swaps the buffers. The serializer
then renders the drained buffer, page by page, and clears it after the
last page. If an export stopped before its last page, the next swap finds
the drained buffer still full: it counts those records as ``lost``,
clears the buffer and goes on. Every page starts with a header record that
carries the interval's start, the number of records, the ``overflow`` and
``lost`` counts, and the time the serializer ran on the boot-time clock,
which a decoder uses to turn record timestamps into wall-clock time.

A serializer is named after a map, and the builder requires that map to
exist. When all tables live in one arena, a table has no map of its own,
so ``kernel-obs`` declares a one-entry array map per table, ``exec``,
``net`` and the others, to carry the name the serializer, the decoder and
the operator use.

The arena's pages are allocated once, after the programs are attached, by
the upatch's test-run program ``shirudo_test__<id>``, which shirudo runs at
load. The kernel binds a program to an arena only when the program refers to
the arena map directly, so ``kernel-obs`` makes a no-op allocation call on a
cold path in every program that dereferences arena pointers it did not
allocate itself.

Serializer interface
--------------------

A serializer is a ``SEC("syscall")`` program named
``shirudo_serialize__<map>``. It writes into ``shirudo_ser``, an array map
with a ``__u32`` key and ``struct serial_chunk`` values that the
upatch defines with 1 to 256 entries. :src:`bpf/lib/serializer.h`
holds the definitions. The builder refuses a serializer that is not in
``SEC("syscall")``, targets a map that does not exist or is
``shirudo_ser`` itself, or duplicates another one, and refuses a upatch
with a serializer and without a valid ``shirudo_ser``.

``shirudo upatch map`` runs the serializer with ``BPF_PROG_TEST_RUN``,
once per page:

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Context field
     - Meaning
   * - ``magic``, ``version``
     - ``SERIAL_MAGIC`` and ``SERIAL_VERSION``, 1
   * - ``flags``
     - ``SERIAL_CTX_F_PEEK`` when the reader asks for a peek
   * - ``max_chunks``
     - the number of entries of ``shirudo_ser``
   * - ``chunk_payload_size``
     - 4032, the payload bytes of one chunk
   * - ``page_index``
     - 0 for the first page, then 1, 2 and so on
   * - ``cursor``
     - 0 for the first page, then the previous page's ``next_cursor``
   * - ``invocation_id``
     - a random number that is the same for every page of one read

Before each run, shirudo clears ``shirudo_ser``. The serializer fills
chunks 0 to ``total_chunks - 1``, each a 64-byte header and 4032 bytes of
payload. Every chunk carries its own ``chunk_index`` and repeats the
page's ``total_chunks``, ``page_index``, ``cursor``, ``next_cursor``,
``invocation_id`` and ``bytes_total``. On the last page, chunk 0 has
``SERIAL_F_DONE`` in ``flags``. A negative return or a non-zero
``status`` in a chunk fails the read. shirudo checks the
magic, the version, the invocation id, the page index and cursor, the
chunk count and the byte counts, concatenates the chunks' payloads into a
page, and runs the serializer again with ``next_cursor`` until a page is
done. A page that is not done and does not advance the cursor fails the
read, and so does a read that is not done after 256 pages. A lock keyed by
the id of ``shirudo_ser`` keeps two readers of the same upatch apart.

The cursor's meaning belongs to the serializer: an index into a table, a
position in a tree walk, anything that lets the next run continue where
the last one stopped.

Draining and peeking
--------------------

Whether a read consumes the data is the serializer's decision. shirudo
passes one flag, ``SERIAL_CTX_F_PEEK``, and nothing else. The
convention every shipped serializer follows: without the flag, the read
drains. It hands over the interval collected since the previous export
and resets it, as ``obs_table.h`` does with its swap and clear. With the
flag, it reads the interval that is still being collected and changes
nothing, and ``obs_table.h`` marks such a page header as a peek.

On a target, ``shirudo-map-export.timer`` runs ``shirudo upatch map
--all`` five seconds after each previous run, and every such run drains.
A manual ``shirudo upatch map <upatch> <map>`` drains too and takes the
records away from the exporter. Add ``--peek`` to look without taking.

What the export reads
---------------------

``shirudo upatch map`` reads the pins under
``/run/shirudo/bpffs/upatches/<name>/``. For each map, it runs the map's
serializer when the upatch pinned one and collects the pages. A map
without a serializer it reads directly, key by key, with its BTF types
when the upatch was built with them. The text form shows the first 256
entries unless ``--show-full`` is given. Ring buffers, perf event arrays,
stack trace maps, program arrays and arenas are not read directly. The
``shirudo_ser`` map is not listed, and maps that were not pinned, those
with a dot in the name or the ``obs_i_`` prefix, are not visible at all.

The pages or entries then go to the map's decoder, which turns them into a
log record or a metric. :doc:`/upatches/write/decoders` describes that step, and
:doc:`/operate/run/telemetry` the export to a collector.

Only tasks with shirudo's runtime authority can do any of this. The LSM
refuses ``BPF_PROG_TEST_RUN``, opening a pinned map or obtaining a map
descriptor by id to every other task, root included, so the records reach
the operator only through shirudo's own export path.

Limits
------

- A snapshot covers one export interval. Records from an interval whose
  export stopped part way are counted as ``lost``, not delivered.
- One read returns at most 256 pages of at most 256 chunks of 4032 bytes.
  A table that renders more fails the read with ``E2BIG``.
- Draining is a convention of the serializer, not something shirudo
  enforces. A serializer that ignores the peek flag drains on a peek.
- The arena's size is fixed when the upatch is built. A larger table means
  a new build and a new load.

Related
-------

- :doc:`/upatches/write/attach-kinds` for the serializer and test-run roles
- :doc:`/upatches/learn/examples` for ``kernel-obs``, which uses this template
  for all its tables
- :doc:`/reference/cli/upatch-map` for the command's options
