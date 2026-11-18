..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: upatch authors

upatch concepts
===============

An upatch is the unit of BPF code that shirudo installs on a target. The
author writes an ordinary BPF object in C. ``shirudo build`` turns it into
a signed ``.upatch`` file, and the target loads that file through the one
path the kernel accepts from userspace: a signed loader. This page explains
what the author writes, what the build adds around it, what the target does
with it, and what an upatch cannot do.

We use the name "upatch" as an easier-to-type representation of "µpatch" or 
"micropatch". 

BPF program
-----------

The author's side of an upatch is libbpf-style BPF C: programs in
``SEC()`` sections, maps in ``SEC(".maps")``, types from ``vmlinux.h``.
The smallest upatch the test suite builds is one ``fentry`` program:

.. code-block:: c

   // SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
   #include "vmlinux.h"
   #include <bpf/bpf_helpers.h>
   #include <bpf/bpf_tracing.h>

   char _license[] SEC("license") = "Dual BSD/GPL";

   SEC("fentry/do_nanosleep")
   int BPF_PROG(shirudo_test_basic)
   {
           return 0;
   }

The license must be GPL-compatible. The kernel refuses an LSM program
that is not, and most tracing helpers are GPL-only. ``Dual BSD/GPL`` is
the project's choice and matches the ``GPL-2.0 OR BSD-2-Clause`` SPDX tag
of every file that is compiled into a BPF object.

The program reads kernel structures through CO-RE: clang records each
field access as a relocation against the types in ``vmlinux.h``, and the
target kernel resolves the relocations against its own BTF when the
program loads. CO-RE carries an upatch across builds of the same kernel
generation, not across kernels that removed or renamed what it reads. A
hard-coded offset signs as well as a CO-RE access and fails on the wrong
kernel in the same way. :doc:`/concepts/background/co-re-btf` explains the
mechanism.

The section name is the attach point. :doc:`/upatches/write/attach-kinds` lists
the sections the builder accepts and how the target attaches each one.

Why the build wraps the program in a loader
-------------------------------------------

The author's programs cannot be signed as they are. Between the build
and the verifier their instructions change: map descriptors are patched
in, CO-RE relocations are resolved against the target's BTF, and kernel
symbol references are resolved. A signature over the built instructions
would not match what the kernel checks. The kernel's signed-BPF design
therefore signs a loader, a ``BPF_PROG_TYPE_SYSCALL`` program that does
those steps in the kernel, together with the data it loads. shirudo's LSM
admits no other ``BPF_PROG_LOAD`` from userspace than such a signed
loader.

``shirudo build`` compiles the source with clang, then runs libbpf's loader
generator over the object. The generator records every step that loading
the object takes, map creation, the BTF load, each program load with its
CO-RE relocation records and the lookup of its attach target, as the
instructions of a loader program. The author's program instructions, the
maps' initial values and the BTF become the loader's data. The build signs
the loader instructions followed by that data with the operator's ML-DSA-87
key and writes both, with the signature, into the ``.upatch`` file.

On the target, ``shirudo upatch load`` puts the data into a frozen array
map that only this loader can use, and passes the loader to
``BPF_PROG_LOAD`` with the signature and the ``.bpf`` keyring. The kernel
checks the signature over the instructions and the frozen map contents
before the verifier runs. Every instruction of the payload is inside the
signed data, so the one signature covers it.
:doc:`/internals/signed-loader` follows the path call by call, and
:doc:`/concepts/background/bpf-signing` describes the kernel side.

When the loader runs, it creates the maps and loads the programs from
kernel context and hands their descriptors back. It cannot attach them:
the generated loader creates no links, and a program running in the kernel
cannot pin anything to a file system. shirudo attaches each program from
userspace and pins the link, so the link survives the exit of the one-shot
command.

What the build signs besides the code
-------------------------------------

The ``.upatch`` header is not signed. Everything the target bases a
decision on is placed in signed sections appended to the loader's data,
where the loader never reads them but the signature covers them:

``NAME``
    The upatch name. The target refuses a file whose header name differs
    from the signed one.
``UPGM``
    The attach metadata of a load: the number of programs and maps and,
    for each program, its role, its attach kind and, where the kind needs
    one, the target symbol, offset or uprobe binary. The builder derives
    it from the section names. The target refuses a file whose header
    counts differ from the signed ones.
``UNLD``
    The payload digest an unload directive expects to find on the upatch
    it removes.
``DCDB``
    The Lua decoders the source declares, with their source text.

The header also carries ``payload_sha256``, the SHA-256 of the loader
instructions followed by the data. The target recomputes it and refuses a
mismatch, because that digest is what the pin records, what the
measurement register extends and what an unload directive is bound to.
:doc:`/reference/formats/upatch-format` gives every field.

What the target keeps
---------------------

A successful load leaves three things behind. The pins hold the programs
and maps in shirudo's private BPF file system. The archive copy at
``/var/lib/shirudo/upatches/<name>.upatch`` is what ``shirudo init``
restores on the next boot. The measurement register and the eventlog
record the load. The pins of one upatch live in one directory:

.. code-block:: none

   /run/shirudo/bpffs/upatches/<name>/
       link                one attach program, or
       link_0, link_1, ... one per attach program, in object order
       test                the test-run program, when there is one
       serializers/<map>   one serializer program per map it renders
       maps/<map>          the upatch's maps

``<name>`` is the upatch name with every ``.`` written as ``~d``, because
the BPF file system does not accept every dotted name. The directory
carries the payload digest in the ``security.bpf.shirudo.payload``
extended attribute, which unload compares against.

Maps whose names contain a dot are not pinned: these are libbpf's
``.rodata``, ``.data``, ``.bss`` and ``.kconfig``. Maps whose names start
with ``obs_i_`` are not pinned either, because that prefix marks state that
is private to the upatch. A map that cannot be pinned is logged and the load
stands without it.

Load directives and unload directives
-------------------------------------

A load directive, the ordinary ``.upatch``, carries programs and maps.
An unload directive carries no payload. ``shirudo build --unload <name>``
generates it from a small template that is built into the helper. It
holds the name of the upatch to remove in ``NAME`` and the payload digest
that upatch must have in ``UNLD``.

``shirudo upatch unload`` loads the directive's loader only so that the
kernel verifies its signature, and never runs it. It then compares the
signed digest with the payload attribute of the pin directory. A
different digest fails with ``payload_mismatch``, so a directive removes
the exact build its signer made it for and nothing else. When nothing of
that name is pinned, the result is ``already_unloaded`` and nothing is
measured. The other way round, a load of an artifact whose upatch is
loaded is refused as ``already_loaded`` before anything is touched: a
second copy would rebind the serializers to maps nothing reads. ``bpm``
takes an artifact whose own payload is the one loaded as installed, so
that it can retry an install a stop cut off after the load.

Build every unload directive with ``--payload-sha256`` set to the digest
of the load it undoes. Without the option, the helper looks for an
archive copy under ``/var/lib/shirudo/upatches/`` on the host where it
runs and, failing that, signs an all-zero digest. No loaded upatch
carries an all-zero digest, so such a directive fails with
``payload_mismatch`` on every target where the upatch is loaded.

Names
-----

One name follows an upatch everywhere: the pin directory, the archive
file, the eventlog record and the target of its unload directive.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Name
     - Rule
   * - upatch name
     - 1 to 255 characters of ``A-Z``, ``a-z``, ``0-9``, ``.``, ``_`` and
       ``-``, each ``.`` counting as two, not starting with ``.``. The
       builder refuses anything else,
       and the target refuses it again at load.
   * - name from ``shirudo build``
     - The input's base name without ``.bpf.c``, ``.bpf.o`` or ``.o``.
       ``--name`` sets another.
   * - name in a package
     - The base name of the ``source`` in the Beefile, the same rule
       without an override. :doc:`/reference/formats/beefile` has the details.
   * - tree id
     - Equal to the upatch name. :doc:`/upatches/publish/publishing` explains
       why.
   * - upatch with decoders
     - At most 63 characters, because the decoder manifest holds the
       upatch name in a 64-byte field.
   * - map
     - At most 15 characters. The kernel keeps 15 characters of a map
       name, and decoders and serializers name their map in a 16-byte
       field. ``shirudo_ser`` is reserved for serializer output.
   * - serializer
     - ``shirudo_serialize__<map>`` in ``SEC("syscall")``, one per map.
   * - test-run program
     - ``shirudo_test__<id>`` in ``SEC("syscall")``, at most one per
       upatch.
   * - loader program
     - The first 15 characters of the upatch name, with any character
       other than letters, digits, ``_`` and ``.`` replaced by ``_``, is
       the name the kernel records for the signed loader.

Programs, maps and decoders
---------------------------

A program has one of three roles, all recorded in the signed attach
metadata. An attach program is linked to the site its section names. A
serializer renders one map into records when the map is exported. A
test-run program runs once at load, right after the attachments, which is
how an upatch initializes state such as an arena before its first export.
A negative return from the test-run program fails the load.

An upatch that accumulates records keeps them in one BPF arena and ships a
serializer that walks them. :doc:`/upatches/write/maps-arenas-serializers`
explains why.
A map becomes a log record or a metric through a decoder, a Lua function
that the source declares in ``.rodata`` and the build signs into the
upatch. :doc:`/upatches/write/decoders` shows how to write one.

What an upatch cannot do
------------------------

It cannot run code the operator did not sign. The kernel checks the
loader's signature against the sealed ``.bpf`` keyring before the verifier
runs, and the payload, the attach sites, the name and the decoders are all
part of the signed data. The limit is what a signature means: it shows who
built the upatch, not that the upatch is correct. A signed upatch does
whatever its source does within what the verifier allows for its program
type, which for ``fmod_ret``, ``lsm``, ``cgroup_skb`` and ``netfilter``
includes refusing calls and dropping packets. Test it on a kernel like the
target's before it ships.

It cannot attach anywhere other than where its signed metadata says.
Before shirudo pins a link, it compares what the kernel reports about the
link with the metadata: the link type and attach type, the kprobe symbol
and offset, the uprobe file offset, the cgroup, the netfilter hook and
network namespace, the number of offsets and the direction of a uprobe
multi link. A mismatch
unpins what the load made and fails with ``attach_scope_mismatch``. For
fentry, fexit, ``fmod_ret``, LSM and ``tp_btf`` programs the site is the
BTF target the verifier bound at load.

It cannot use a program type that has no pinnable link. The builder
refuses socket filters, ``sk_skb`` and every other section
outside the list in :doc:`/upatches/write/attach-kinds`, because only a pinned
link keeps a program attached after the command exits and lets the unload path
detach it.

It cannot stay loaded unmeasured. A load whose archive copy or register
extend fails is undone, a load stopped before its extend is undone by the
next load or unload and reported by ``status`` until then, and ``init``
restores only an archived upatch whose load the eventlog records.

It cannot be removed without the signer. A loaded upatch goes away through
a signed unload directive bound to its payload, or through a key
revocation in a signed config image, which purges the upatches of the
revoked key. shirudo's LSM programs refuse every userspace command that
detaches or replaces a link, and refuse removing a pin to every task
without shirudo's runtime authority. :doc:`/security/threat-model` lists
what remains.

Related
-------

- :doc:`/upatches/learn/kernel-fix-tutorial` takes one upatch from a kernel fix
  to a published package.
- :doc:`/reference/cli/build` for every ``shirudo build`` option.
- :doc:`/concepts/upatches-and-packages` for how upatches, packages and
  the tree relate.
