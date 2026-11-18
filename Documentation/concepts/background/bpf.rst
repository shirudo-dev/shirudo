..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

BPF in brief
============

The Linux kernel can run small programs that userspace hands it at run
time, at points the kernel defines, without a kernel module and without a
reboot. This mechanism is BPF. shirudo uses it twice: its own enforcement
is a set of BPF programs, and every upatch it ships is one. This page
explains the parts of BPF that the rest of the documentation relies on.

Programs and the verifier
-------------------------

A BPF program is a sequence of instructions for a small virtual machine
with ten general-purpose 64-bit registers and a read-only frame pointer.
Userspace passes the instructions to the kernel with the ``bpf()``
system call and its ``BPF_PROG_LOAD`` command.

The kernel does not trust these instructions. Before it accepts a
program, the verifier walks every path through it and tracks the type
and value range of every register and stack slot. It rejects a program
that could read uninitialized memory, access memory out of bounds, call a
function it may not call or fail to terminate. A program that passes is
translated to native code by the JIT compiler.

Every program has a type, such as ``BPF_PROG_TYPE_LSM`` or
``BPF_PROG_TYPE_CGROUP_SKB``. The type decides where the program can run,
what context it receives as its argument and which functions it may
call.

The verifier proves that a program is safe to run in the kernel. It does
not prove that the program does what its author meant: a program that
passes can still deny an operation it should allow, or slow down a hot
path. Trust in who wrote a program has to come from somewhere else, which
is what :doc:`bpf-signing` provides.

Maps
----

A program keeps state in maps, key-value stores that live in the kernel.
A map has a type (array, hash, per-task storage, ring buffer, arena and
others), a key size, a value size and a maximum number of entries.

A program refers to a map through an instruction that the loader patches
with the map's reference before the load. Userspace reaches the same map
through a file descriptor and the map commands of ``bpf()``, such as
``BPF_MAP_LOOKUP_ELEM`` and ``BPF_MAP_UPDATE_ELEM``. ``BPF_MAP_FREEZE``
makes a map read-only to userspace for the rest of its life. Programs can
still write a frozen map.

Helpers and kfuncs
------------------

A program cannot call arbitrary kernel functions. It can call helpers, a
fixed set of functions with numbers in the kernel's userspace API, such
as ``bpf_map_lookup_elem()``. It can also call kfuncs, kernel functions
that the kernel exports to BPF and describes in its type information.

Helpers are a stable interface. kfuncs are not: they can change or
disappear between kernel releases, and each is available only to the
program types and hooks the kernel registers it for. The verifier checks
every call against the function's prototype.

Attach points and links
-----------------------

Loading a program does not run it. A program runs once it is attached to
a hook: the entry or exit of a kernel function, an LSM hook, a
tracepoint, a kprobe, the packet path of a cgroup or a netfilter hook.

The attachment is a kernel object of its own, a BPF link. Userspace
creates it with ``BPF_LINK_CREATE`` or, for some tracing and LSM
programs, with ``BPF_RAW_TRACEPOINT_OPEN``. While the link exists, the
program runs at the hook. When the last reference to the link goes away,
the kernel detaches the program.

Pinning in bpffs
----------------

Programs, maps and links are reference counted. A file descriptor holds
a reference, and so does a program's use of a map. When a process
exits, its descriptors close, and an object that nothing else holds is
freed. An attached program detaches with its link.

To make an object outlive the process that created it, userspace pins
it. ``BPF_OBJ_PIN`` creates a file for the object in a BPF file system,
bpffs (file system type ``bpf``). The pin holds a reference until it is
removed, and ``BPF_OBJ_GET`` turns a pin back into a file descriptor.

A pin is an inode, so file system operations apply to it. Removing the
file drops its reference, and unmounting a bpffs instance that no other
mount shares drops every pin in it.

Programs that load programs
---------------------------

A program of type ``BPF_PROG_TYPE_SYSCALL`` attaches nowhere. Userspace
runs it on demand with ``BPF_PROG_TEST_RUN``. It is always sleepable and
may call the ``bpf_sys_bpf()`` helper, which issues a subset of
``bpf()`` commands from inside the kernel: it creates, updates and
freezes maps, loads programs and type information, and creates links.

libbpf's gen_loader turns a whole BPF object into one such program, the
loader, plus a data blob that holds everything the loader needs: the
programs' instructions, the map definitions with their initial contents,
and the relocation records. A light skeleton, generated with
``bpftool gen skeleton -L``, wraps the loader and its data in a C header.
The generated code places the data in an array map, loads the loader and
runs it. The loader then creates the maps and loads the programs.

A loader issues its ``bpf()`` commands from inside the kernel. The LSM
hooks therefore see them with their ``kernel`` argument set, which is how
a policy can tell a loader's calls from those of a userspace process (see
:doc:`bpf-lsm`). gen_loader emits no attachments, so the process that ran
the loader attaches and pins the programs itself.

How shirudo uses BPF
--------------------

shirudo uses BPF for its enforcement and for upatches.

The ``shirudo`` binary embeds two BPF objects, ``bpf2`` and ``seal``,
that hold its LSM programs. ``shirudo init`` loads them with libbpf,
attaches each program to its hook and pins every link under
``/run/shirudo/bpffs``, a private bpffs that init mounts with mode
``0700``. shirudo runs no daemon that could hold descriptors instead, so
these pins are what keep enforcement attached after init exits. See
:doc:`/internals/enforcement` and :doc:`/internals/seal`.

A upatch carries a signed loader that gen_loader produced on the
operator host. ``shirudo upatch load`` loads the loader with its
signature, runs it with ``BPF_PROG_TEST_RUN``, attaches the payload
programs the loader created and pins their links under
``/run/shirudo/bpffs/upatches/<name>/``, with the upatch's maps under
``maps/`` beside them. See
:doc:`/internals/signed-loader` and :doc:`/upatches/write/attach-kinds`.

Because the pins are all that hold these links, shirudo's LSM programs
refuse to remove or rename an entry in the private bpffs for any task
without runtime authority, and refuse to unmount it for every task. They
also refuse tasks without runtime authority a descriptor to the pinned
maps and links, by pin or by id.

Limits
------

The verifier bounds what a program can do to the kernel, not what it
decides. A upatch that passes the verifier can still break a workload by
denying the wrong operation. shirudo signs and measures upatches so that
an operator knows which programs run; it does not judge whether they are
correct. See :doc:`/upatches/test/testing` for testing a upatch before it
ships.
