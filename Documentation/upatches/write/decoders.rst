..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: upatch authors

Write a Lua decoder
===================

A decoder turns a snapshot of one map into the record that shirudo
exports: the body of an OTLP log record, or a list of OTLP metrics. It is
a Lua function that the BPF source declares and the build signs into the
upatch, so it has the same signer as the program whose data it reads.
This page shows how to declare one, write it, check it and run it.

Before you begin
----------------

- A upatch source with the map to export, and the layout of that map:
  the records its serializer writes, or its key and value types.
  :doc:`/upatches/write/maps-arenas-serializers` covers serializers.
- The test VM or another target to run the decoder on, as
  :doc:`/upatches/test/testing` describes.
- Familiarity with Lua 5.1, the language LuaJIT runs.
  :doc:`/concepts/background/luajit` covers what shirudo uses it for.

Declare the decoder
-------------------

1. Decide on the signal. A log decoder returns a table that becomes the
   body of one log record per snapshot. A metric decoder returns OTLP
   metrics with names, units and data points of its choosing.

2. Include ``decoder.h`` after ``vmlinux.h`` and declare a
   manifest in ``.rodata``. ``kernel-obs`` declares this one, through a
   macro, for ``watch_stat``, a per-CPU array whose one value holds two
   ``__u64`` counters, ``checked`` and ``matched``:

   .. code-block:: c

      #include "decoder.h"

      const struct decoder_manifest watch_stat_decoder SEC(".rodata") = {
              .magic = DECODER_MANIFEST_MAGIC,
              .version = UPATCH_DECODER_VERSION,
              .language = UPATCH_DECODER_LANG_LUA,
              .api_version = 1,
              .input_format = UPATCH_DECODER_INPUT_MAP_V1,
              .export_signal = UPATCH_DECODER_EXPORT_METRIC,
              .upatch = "kernel-obs",
              .map = "watch_stat",
              .source = "decoders/watch_stat.lua",
              .entrypoint = "decode",
      };

   The builder finds manifests by their magic in the object's ``.rodata``,
   so declare the manifest ``const``. It also passes over a manifest with
   an empty string field or a zero ``language``, ``api_version``,
   ``input_format`` or ``export_signal``, without an error, so check the
   result as step 6 shows. Set the fields as follows:

   .. list-table::
      :header-rows: 1
      :widths: 22 78

      * - Field
        - Value
      * - ``magic``, ``version``
        - The constants shown. With any other value the builder does not
          recognize the manifest and builds the upatch without it.
      * - ``language``, ``api_version``, ``input_format``
        - The constants shown. Any other value fails the build with
          ``unsupported decoder ABI for '<upatch>/<map>'``.
      * - ``export_signal``
        - ``UPATCH_DECODER_EXPORT_LOG`` or
          ``UPATCH_DECODER_EXPORT_METRIC``.
      * - ``upatch``
        - The upatch name, at most 63 characters. In a package that is the
          source's base name.
      * - ``map``
        - The name of a map of the object, at most 15 characters. One
          decoder per map.
      * - ``source``
        - The Lua file, at most 63 characters, relative to the directory
          of the ``.bpf.c`` file, or to the current directory when the
          input is a ``.bpf.o``. No leading ``/``, no ``.`` or ``..``
          component, no backslash. Not empty, at most 16 MiB.
      * - ``entrypoint``
        - The function to call, at most 31 characters.

Write the function
------------------

3. Create the Lua file. The chunk either defines a global function with
   the entrypoint's name, returns a function, or returns a table that has
   one under that name. shirudo calls it with one argument, the input
   table:

   .. list-table::
      :header-rows: 1
      :widths: 38 62

      * - Field
        - Content
      * - ``schema``
        - ``1``
      * - ``upatch``, ``map``
        - the upatch and map names
      * - ``startTimeUnixNano``
        - when the upatch was loaded, as a decimal string
      * - ``timeUnixNano``
        - the time of the snapshot, as a decimal string
      * - ``data.name``, ``data.type``
        - the map's name and type, such as ``percpu_array``
      * - ``data.max_entries``, ``data.n_entries``
        - the map's capacity and the entries read
      * - ``data.key_size``, ``data.value_size``, ``data.n_cpus``
        - sizes in bytes, and the number of CPUs for a per-CPU map
      * - ``data.truncated``
        - whether the read stopped at the entry limit
      * - ``data.entries[i].key_hex``, ``.value_hex``
        - a directly read entry in hex. A per-CPU value holds one 8-byte
          aligned slot per CPU.
      * - ``data.serialized``, ``data.serialized_pages``,
          ``data.serialized_bytes``
        - whether a serializer produced the snapshot, and its size
      * - ``data.pages[i]``
        - one serializer page: ``page_index``, ``cursor``,
          ``next_cursor``, ``done``, ``flags``, ``chunks``, ``bytes`` and
          ``data_hex``

   Lua numbers cannot hold a 64-bit value exactly, so shirudo passes
   timestamps as decimal strings, and these host functions exchange
   64-bit values as decimal strings too:

   .. list-table::
      :header-rows: 1
      :widths: 42 58

      * - Function
        - Returns
      * - ``shirudo.page_slots(page, size)``
        - the page's payload cut into slots of ``size`` bytes, in order,
          respecting chunk boundaries
      * - ``shirudo.fixed_records(pages, size)``
        - the slots of all pages, indexed by each page's ``cursor`` plus
          the slot's position
      * - ``slot:u8(off)``, ``slot:u16(off)``, ``slot:u32(off)``
        - a little-endian integer at ``off``, 0 when out of range
      * - ``slot:u64(off)``
        - a little-endian 64-bit value as a decimal string
      * - ``slot:cstring(off, len)``
        - the bytes from ``off`` up to the first NUL, at most ``len``
      * - ``shirudo.u64_add(a, b)``, ``shirudo.u64_sub(a, b)``
        - exact sum and difference of two decimal strings. The sum stops
          at the largest value and the difference at 0.
      * - ``shirudo.hex_u64(hex, off)``
        - the little-endian 64-bit value at byte ``off`` of a hex string,
          as a decimal string

   The ``watch_stat`` decoder adds up both counters over all CPUs and
   returns one monotonic sum with a data point for each:

   .. literalinclude:: ../../../upatches/kernel-obs/decoders/watch_stat.lua
      :language: lua

4. Return the record. A log decoder returns a table. With ``--otel`` it
   becomes the log record's body: a table whose keys are 1 to n becomes
   an array, any other table a key-value list, a whole number up to 2^53
   an ``intValue`` and any other number a ``doubleValue``. A metric
   decoder returns an array of OTLP ``Metric`` objects, exactly as they
   appear in the ``metrics`` array of a ``scopeMetrics`` entry. A string
   or a key that is not valid UTF-8 is exported with U+FFFD in place of
   each bad byte and of each NUL.

   To turn a timestamp a serializer took on the boot-time clock into wall
   clock time, subtract its age from ``timeUnixNano``. The ``kernel-obs``
   decoders do it with the time the serializer ran, which their page
   header carries:

   .. code-block:: lua

      shirudo.u64_sub(input.timeUnixNano, shirudo.u64_sub(boot_now, ts))

The decoder runs in a restricted LuaJIT state:

- It is loaded as source text. LuaJIT does not verify bytecode, so a
  precompiled chunk is refused.
- The JIT compiler is off, so that the instruction count sees every
  instruction. One snapshot may take 1,000,000 virtual machine
  instructions, loading the chunk included, and 32 MiB of memory, and the
  result may nest 32 levels deep. ``pcall`` catches the error the limit
  raises, but from then on every instruction raises it again.
- ``io``, ``os``, ``package``, ``require``, ``debug``, ``jit``, ``ffi``,
  ``dofile``, ``loadfile``, ``load``, ``loadstring``, ``module``,
  ``collectgarbage``, ``newproxy``, ``xpcall`` and ``print`` are
  removed, and so are the pattern functions ``string.find``,
  ``string.match``, ``string.gmatch`` and ``string.gsub``, whose
  backtracking on a recorded string the instruction count never sees.
  The rest of the base library and the ``string``, ``table``, ``math``
  and ``bit`` libraries remain.
- shirudo reads the decoder from the archived copy of the upatch,
  ``/var/lib/shirudo/upatches/<name>.upatch``, opens it as sealed state
  and runs it only when its bytes are the payload loaded, as the digest
  on the pin directory records. A decoder that did not arrive inside the
  signed artifact of the loaded upatch never runs.

An error raised in the decoder drops that snapshot with a message on
standard error, its control characters replaced. It never produces a
partial record.

Build and check it
------------------

5. Build the upatch as usual. The builder reads each manifest, resolves
   ``source`` and embeds the file in the signed ``DCDB`` section. It
   refuses the build when a manifest names another upatch, a map the
   object does not have, a second decoder for the same map, or a source
   it cannot read.

6. Confirm that the decoder is in the artifact:

   .. code-block:: console

      operator$ shirudo upatch info <file>.upatch

   ``<file>`` is your upatch. The ``Decoders`` section lists each decoder
   with its target as ``<upatch>/<map>``, the language and API version,
   the input format ``shirudo.map.v1``, the export signal, and the source
   file with its entry point and size.

Run it on a target
------------------

7. Load the upatch on the target, then run the decoder against the live
   map without draining it:

   .. code-block:: console

      target# shirudo-runtime upatch map <upatch> <map> --json --peek

   ``shirudo-runtime`` is the command in the test VM, as
   :doc:`/upatches/test/testing`
   explains. ``<upatch>`` and ``<map>`` are the names in the manifest. The
   command prints what the decoder returned as one JSON document. A failure
   prints one of ``upatch map: decoder load failed: <message>``, ``upatch
   map: decoder entrypoint '<name>' not found``, ``upatch map: decoder
   failed: <message>`` or ``upatch map: decoder encode failed: <message>``,
   and the instruction limit shows as ``decoder instruction limit
   exceeded``.

8. Send one snapshot to a collector:

   .. code-block:: console

      target# shirudo-runtime upatch map <upatch> <map> --peek --otel \
          --otel-endpoint=<url>

   ``<url>`` is the collector's OTLP/HTTP base URL. A log decoder's record
   goes to ``<url>/v1/logs``, a metric decoder's metrics to
   ``<url>/v1/metrics``.

A map without a decoder is exported over OTLP as a log record whose body
lists its entries or serializer pages in hex, and ``--json`` reports ``No
data available`` for it. An unsigned per-CPU integer map without a decoder
is classified as a metric and then fails to export over OTLP with the same
message, so give such a map a metric decoder.

Next steps
----------

- :doc:`/operate/run/telemetry` to export every map on a schedule
- :doc:`/reference/formats/otlp` for the documents on the wire
- The decoders under :src:`upatches/kernel-obs/decoders/` for complete log
  decoders over arena tables, timestamps included
