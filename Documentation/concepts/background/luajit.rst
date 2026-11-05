..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

LuaJIT and the decoder sandbox
==============================

A upatch that records observations leaves them in BPF maps as binary
records only its author knows how to read. shirudo turns those bytes into
OpenTelemetry records with a small Lua program, the decoder, that the
author ships and signs together with the BPF programs. This page explains
why decoders are Lua, what LuaJIT is, how shirudo runs a decoder and what
it restricts, and where those restrictions stop.

Why decoders exist
------------------

A serializer walks an arena structure in kernel context and writes
fixed-size records into 4096-byte pages. The pages are correct and
complete, but they are bytes: a timestamp in boot-time nanoseconds at
offset 16, a command name of up to 16 bytes at offset 96, a counter per
CPU. A collector cannot do anything with them until someone applies the
record layout.

The obvious places to put that knowledge do not work. Built into shirudo,
every new record layout would need a new shirudo release, while upatches
are written and shipped on their own schedule. Rendered generically from
BTF, a flat map of counters comes out readable, but a record in an arena
page has no BTF type the reader can find, and the meaning of its fields,
which timestamp to convert and which counters to sum, is the author's. A
native plug-in, a shared object loaded into shirudo, would be arbitrary
machine code running in a process that holds runtime authority.

What remains is a small program in a memory-safe language, written by the
upatch author, delivered inside the signed artifact and run by an
interpreter that shirudo embeds and restricts. shirudo uses Lua for it.

Lua and LuaJIT
--------------

Lua is a small scripting language designed to be embedded in a host
program. The host creates an interpreter state through a C API, decides
which libraries the state can see, loads code into it and calls functions
in it. Lua code has no access to files, processes or the network except
through library functions the host makes available.

LuaJIT is an implementation of Lua 5.1, with its C API and ABI, and a
few extensions from Lua 5.2. It pairs an interpreter written in assembler
with a trace compiler that turns frequently run code into machine code,
and adds an FFI library through which Lua code can call C functions and
touch raw memory. shirudo links LuaJIT as one of its fixed libraries and
uses only its interpreter.

Three statements in the LuaJIT documentation shape how shirudo uses it.
LuaJIT does not verify the bytecode it loads, so crafted bytecode can
crash the interpreter. Compiled traces ignore the debug hooks that an
embedder uses to interrupt running code. And the documentation
recommends sandboxing untrusted Lua code at the process level rather
than inside the interpreter.

How a decoder reaches the target
--------------------------------

The BPF source declares each decoder in ``.rodata`` with a
``struct decoder_manifest`` from
:src:`bpf/lib/decoder.h`. The manifest starts with the magic
``DECD`` and names the language (``1``, Lua), the host API version, the
input format (``1``), the signal to export (``1`` for a log, ``2`` for a
metric), the upatch and map it decodes, the Lua source file relative to
the BPF source, and the entry point.

``shirudo-build`` finds the manifests when it builds the artifact, reads
each source file and embeds the sources in the ``DCDB`` section of the
loader's data before it signs. The kernel's signature check of the
loader therefore covers the decoders, and a decoder cannot be added or
changed without the signing key. The format is in
:doc:`/reference/formats/upatch-format`.

On the target, ``shirudo upatch load`` keeps the artifact it loaded as
``/var/lib/shirudo/upatches/<name>.upatch``, sealed state that only
shirudo writes. At export, shirudo opens that archived copy as sealed
state, looks for the decoder whose upatch and map names match the map
being exported and runs it. There is no decoder search path and no
directory to drop a script into.

Running a decoder
-----------------

shirudo creates a fresh interpreter state for every decoder run and
closes it afterwards, so nothing a decoder leaves behind reaches the next
run. The state allocates through a function that refuses to hold more
than 32 MiB in total. The limit covers everything the state allocates,
the input table included, and a decoder that reaches it fails with a
memory error.

The allocator function uses LuaJIT's allocator for addresses its garbage
collector can represent, including on arm64 where the libc heap can sit
above its 47-bit limit. A separate empty state owns the allocator arena
and releases it after the decoder state closes. Decoder allocations are
zeroed and scrubbed before release. The memory limit also covers finalizers
run at close. The empty owner state and allocator bookkeeping are outside
that limit.

The state opens the standard libraries and then removes these globals:
``io``, ``os``, ``package``, ``require``, ``debug``, ``jit``, ``ffi``,
``dofile``, ``loadfile``, ``load``, ``loadstring``, ``module`` and
``collectgarbage``. What remains is the language itself with ``string``,
``table``, ``math``, ``bit``, ``coroutine``, ``pcall`` and the other base
functions, ``print`` among them.

shirudo turns off the JIT compiler for the state, so every instruction
runs in the interpreter where the instruction hook sees it. It loads the
decoder as source text only, in mode ``"t"``, so LuaJIT refuses a
bytecode chunk.

A count hook runs every 10,000 interpreter instructions and draws from a
budget of one million instructions. The budget covers both running the
chunk at the top of the source and the call to the entry point. When the
budget is spent, the hook raises the error ``decoder instruction limit
exceeded``.

The entry point receives one table: the upatch and map names, the start
and current time as decimal nanosecond strings, the map's type and sizes,
and either its entries as hex strings or the serializer's pages. A global
table ``shirudo`` provides helpers that split pages into fixed-size
slots, read integers and strings from a slot at an offset, and do exact
64-bit arithmetic on decimal strings, since a Lua number cannot hold a
nanosecond timestamp. The accessors read only the copy of the data they
were given and return zero or an empty string for an offset out of range.

A log decoder returns a table, which becomes the body of the log record.
A metric decoder returns a list of OpenTelemetry metric objects. shirudo
serializes the result itself, refuses nesting deeper than 32 levels and
output larger than its size limits, and drops the snapshot with a
diagnostic on any error rather than export a partial record.
:doc:`/upatches/write/decoders` describes the input table, the helpers and the
return contract in full.

How shirudo uses it
-------------------

shirudo runs decoders in ``shirudo upatch map`` when it exports a map
over OTLP or as JSON, which is what the map export timer does with
``shirudo upatch map --all``. Reading shirudo's maps and
running a serializer require runtime authority, so the decoder runs
inside a process that holds it. ``--all`` decodes the maps one after the
other in that one process. :doc:`opentelemetry` explains what happens to
the records afterwards, and :doc:`/operate/run/telemetry` sets up the export.

Limits
------

- The instruction budget is a Lua error like any other. ``pcall``,
  ``xpcall`` and ``coroutine.resume`` catch it. Once the budget is spent,
  the hook raises again every 10,000 instructions, but a loop around
  ``pcall`` catches each error and runs without end.
- Time spent inside a C function, such as ``string.rep``, a pattern match
  in ``string.find`` or one of the ``shirudo`` helpers, does not count
  against the budget.
- There is no wall-clock deadline. A decoder that does not finish stalls
  every export after it in the same run, until the systemd unit's start
  timeout stops the service. A command run by hand has no such timeout.
- The global list is a denylist. Every function of the standard library
  that the list does not name stays available. ``print`` writes to the
  command's standard output, the stream that ``--json`` without a path
  also writes to.
- A decoder runs inside a process with runtime authority, not in a
  separate process. The LuaJIT interpreter is therefore part of the
  target's trusted computing base, and a flaw in it that a signed decoder
  can reach runs with shirudo's authority.
- At export, shirudo reads the decoder from the archived artifact again.
  The seal protects that file, but shirudo does not verify its signature
  a second time or compare it with the payload digest of the programs it
  loaded.

These limits bound a mistake or misbehavior in a decoder that carries a
valid signature. A decoder without one never runs. The threat model
lists the residual risks in :doc:`/security/threat-model`.

Related
-------

- :doc:`/upatches/write/decoders` for writing a decoder
- :doc:`/upatches/write/maps-arenas-serializers` for the records a decoder
  reads
- :doc:`opentelemetry` for the records a decoder produces
- :doc:`/security/threat-model` for the residual risks
