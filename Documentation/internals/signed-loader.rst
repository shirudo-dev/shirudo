..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: Kernel developers, security reviewers

Signed loader path
==================

Root on a Linux host can normally load any BPF program. This page
explains how shirudo takes that away while keeping BPF usable for
upatches: what the operator signs, which ``bpf()`` calls a load makes,
which kernel checks decide each of them, how an unload works, and where
the mechanism stops.

Problem
-------

Every upatch is BPF, so shirudo cannot switch BPF off. It needs a kernel
that accepts BPF the operator signed and refuses BPF from anyone else,
root with every capability included. Root can issue any system call, so
the decision has to sit where root cannot step around it.

Why a check in userspace fails
------------------------------

The obvious design puts a privileged service in front of ``bpf()``: the
service checks a signature and then makes the system call. The check and
the load are then two steps in two places. Root does not have to ask the
service; it calls ``bpf()`` itself, and the kernel cannot tell the vetted
call from the other one. A userspace check also checks a file, while the
kernel loads bytes that root can change between the two.

We need the kernel to verify the signature on the same call that loads
the code, over the bytes it loads.

What the operator signs
-----------------------

The operator does not ship the upatch program itself. ``shirudo build``
compiles the source, and libbpf's gen_loader turns the object into a
loader: a ``BPF_PROG_TYPE_SYSCALL`` program whose instructions make the
``bpf()`` calls that create the upatch's maps, load its programs and
attach its LSM, fentry, fexit, fmod_ret and BTF tracepoint programs. The
loader's data blob carries everything those calls need, the payload
programs' instructions included. The builder appends signed sections to
the data (the upatch name, the attach metadata, the unload target and the
decoders) and signs ``loader_insns || data`` with ML-DSA-87 as a detached
CMS signature. The ``.upatch`` container carries the loader instructions,
the data, the signature, and in its header the name and
``payload_sha256``, which is SHA-256 of ``loader_insns || data``.
:doc:`/reference/formats/upatch-format` has the byte layout.

One signature therefore covers every instruction that ends up attached,
because the payload instructions are part of the signed data.

Metadata map
------------

The kernel cannot verify a signature over data it has not seen, so the
data travels to the kernel before the loader does, in an array map that
only this loader can use. The target creates the map, ``__loader.map``,
with one element whose value is the data blob. It sets
``excl_prog_hash`` to SHA-256 of the loader instructions, which makes the
map exclusive: the verifier refuses to bind it to any program whose
digest differs. It writes the data and freezes the map, so nothing can
change the value after the check.

``BPF_PROG_LOAD`` passes the map in ``fd_array`` with ``fd_array_cnt``
set to 1. With ``fd_array_cnt`` set, the verifier binds the map at the
start of the load and verifies the signature over the instructions
followed by the frozen value of each such map. The kernel refuses a signed load
whose bound map is not an array, not frozen, has active writers or is not
exclusive.

Calls a load makes
------------------

``shirudo upatch load`` runs these steps. The first column says who makes
the call: userspace, which ``lsm/bpf`` sees with ``kernel`` false, or the
loader inside the kernel, which ``lsm/bpf`` sees with ``kernel`` true.

.. list-table::
   :header-rows: 1
   :widths: 12 30 58

   * - Caller
     - Call
     - What decides it
   * - userspace
     - pre-flight
     - The kernel ABI check passes, the ``.bpf`` keyring serial equals
       the frozen identity record, and ``lsm_link`` is pinned. With
       ``--expect-chain``, the register equals the given value.
   * - userspace
     - read and parse the file
     - The file is read once into ``/var/lib/shirudo/incoming``. The
       signed name must equal the header name, ``payload_sha256`` must
       equal SHA-256 of ``loader_insns || data``, and the signed attach
       metadata must parse. Each ``uprobe.multi`` target is opened and
       its GNU build ID compared before any BPF loads.
   * - userspace
     - ``BPF_MAP_CREATE`` of ``__loader.map``
     - ``lsm/bpf`` allows it to a task with runtime authority, else
       ``EACCES`` (``MapCreate``).
   * - userspace
     - ``BPF_MAP_UPDATE_ELEM``, ``BPF_MAP_FREEZE``
     - ``lsm/bpf``, runtime authority (``MapWrite``).
   * - userspace
     - ``BPF_PROG_LOAD`` of the loader
     - ``lsm/bpf`` at system call entry: the type must be
       ``BPF_PROG_TYPE_SYSCALL`` and ``signature_size`` non-zero. Inside
       ``bpf_check()``, the kernel resolves ``fd_array``, verifies the
       signature against the keyring ``keyring_id`` names, then calls
       ``lsm/bpf_prog_load``, then runs the verifier's analysis.
   * - userspace
     - ``BPF_PROG_TEST_RUN`` of the loader
     - ``lsm/bpf``, runtime authority (``ProgRun``). The loader then
       runs in the kernel.
   * - loader
     - ``BPF_MAP_CREATE``, ``BPF_MAP_UPDATE_ELEM``, ``BPF_MAP_FREEZE``,
       ``BPF_PROG_LOAD`` through ``bpf_sys_bpf()``
     - ``lsm/bpf`` and ``lsm/bpf_prog_load`` see ``kernel`` true and
       allow. The verifier checks each payload program as usual.
   * - loader
     - ``BPF_LINK_CREATE`` through ``bpf_sys_bpf()`` for programs with
       the signed loader-link role
     - ``lsm/bpf`` sees ``kernel`` true and allows. The link is returned
       in the program's context slot. If a later attachment fails, the
       loader closes the links it already created.
   * - userspace
     - ``BPF_LINK_CREATE`` or ``BPF_RAW_TRACEPOINT_OPEN`` for programs
       with the signed attach role
     - ``lsm/bpf``, runtime authority (``ProgAttach``). shirudo then
       compares the link the kernel reports with the signed metadata and
       refuses ``attach_scope_mismatch`` when they differ.
   * - userspace
     - ``BPF_OBJ_PIN`` of each link and map
     - ``lsm/bpf``, runtime authority (``ObjPin``), and the bpffs inode
       guards.
   * - userspace
     - archive, extend, append
     - The artifact is copied to ``/var/lib/shirudo/upatches/``, the
       register is extended with the load event and the eventlog takes
       the record. A failed copy or a refused extension undoes the load.

``shirudo bpm`` installs, upgrades and tree operations skip the
pre-flight row (they pass ``--no-precheck``); the keyring comparison runs
again inside the load, so those paths keep it.

The builder enables generated attachment for LSM, fentry, fexit,
fmod_ret and BTF tracepoint programs. Serializers and test-run programs
are loaded without attachment. Kprobe, uprobe, cgroup and netfilter
programs retain userspace attachment, including in an object that also
carries loader-created links.

The loader returns the descriptors of what it created in its context
buffer. Programs with the signed loader-link role must return a link
created by the loader. The target checks that the link references the
returned program and has a supported tracing or LSM attachment type,
then checks the signed attach kind and pins the link. A missing link
fails the load. Programs with the attach role use userspace attachment.
The target closes returned links on every exit and removes pins made by
an attach-and-pin operation that fails. Pinning remains in userspace
because ``bpf_sys_bpf()`` has no ``BPF_OBJ_PIN``. Each link is pinned at
``/run/shirudo/bpffs/upatches/<name>/link``, or ``link_<n>`` for several,
serializers under ``serializers/`` and maps under ``maps/`` beside it. A
dot in the name is written as ``~d`` there. The directory carries the
``security.bpf.shirudo.payload`` extended attribute with the payload
digest, which only a task with runtime authority can set.
:doc:`kernel-interfaces` lists the attributes each call sets.

Attachment is not atomic. A hook can run before the loader returns,
before its link is pinned and before the load is measured. Closing a
link after a failure detaches it but does not undo effects of hooks that
ran. The bootstrap LSM objects retain the staged attachment order in
:doc:`enforcement`.

Telling the loader apart from root
----------------------------------

A signature check alone is not enough. The loader calls back into
``bpf()`` to create maps and load programs, and those calls look like the
ones root would make. The ``lsm/bpf`` and ``lsm/bpf_prog_load`` hooks
receive a ``bool kernel`` argument. It is true when the call comes
through a kernel pointer, which is how ``bpf_sys_bpf()`` issues the
loader's calls, and false for a system call from userspace. Calls with
``kernel`` true are allowed: they come from a loader the kernel already
verified and that an authorized task is running. Userspace calls are
filtered.

Admission in lsm/bpf_prog_load
------------------------------

The kernel records the result of its signature check on the program:
``prog->aux->sig.verdict``, ``sig.keyring_type`` and
``sig.keyring_serial``. ``lsm/bpf_prog_load`` runs after that check and
reads them. A userspace load is admitted only when the verdict is
``BPF_SIG_VERIFIED`` and the keyring kind is ``BPF_SIG_KEYRING_BPF``. A
program the kernel did not verify, such as one whose load sets a
signature size but no signature, is refused ``LoadUnverified``. A program
verified against the built-in, secondary or platform keyring is refused
``LoadKeyringKind``; the kernel verifies such a signature, so the kind
check is what keeps those keyrings out.

The hook also compares a non-zero serial with the keyring serial ``init``
froze. For the ``.bpf`` keyring the kernel records serial 0, because it
resolves that keyring without taking a reference, so this comparison
never runs and ``LoadKeyring`` does not count. The kind check pins the
keyring: there is one ``.bpf`` keyring, and ``init`` sealed it around the
trusted set. A caller-supplied user keyring never reaches the hook: with
``bpf.keyring_unsealed=1`` on the command line, which shirudo requires,
the kernel refuses any ``keyring_id`` other than the system selectors and
``KEY_SPEC_BPF_KEYRING`` with ``EPERM``.

Root without the key fails earlier than this. Creating the metadata map
needs runtime authority, so a root process with a validly signed
``.upatch`` cannot even prepare the load, and running a loaded loader
needs runtime authority too.

Unload directives
-----------------

An unload directive is a ``.upatch`` whose header marks it as an unload.
Its signed sections name the upatch it removes and the payload digest
that upatch must have. ``shirudo upatch unload`` loads the directive's
loader through the same ``BPF_PROG_LOAD`` as a load, so the kernel
verifies its signature against ``.bpf`` exactly as it verifies a load.
The command never runs that loader.

The detach is userspace work. The command reads the payload digest from
the extended attribute on the pin directory and compares it in constant
time with the signed one; a mismatch, or an attribute it cannot read, is
``payload_mismatch``. It then extends the register with the unload event,
and only then removes the map pins, the link pins and the directory, and
the archived copy. A process stopped between the two leaves a register
that records an unload that did not finish, never a detach the register
does not know. A missing pin directory is ``already_unloaded`` and
extends nothing.

Removing the pins detaches because a pin is the only reference shirudo
keeps to a link, and the link detaches when its last reference goes.
``lsm/bpf`` refuses ``BPF_OBJ_GET`` and ``BPF_LINK_GET_FD_BY_ID`` to
tasks without runtime authority, and ``lsm/file_open`` refuses to open a
pin as a file, so root cannot take a second reference to a shirudo link
by pin or by id. ``BPF_LINK_DETACH`` is refused to every userspace
caller, shirudo included.

Limits
------

The unload directive authorizes the detach, but it does not perform it.
The detach runs in userspace because ``bpf_sys_bpf()`` offers no detach
or unpin command; :src:`bpf/unload.c` is a placeholder for the in-kernel
version. An unload directive is bound to the upatch name and payload
digest, not to the key that signed the load.

The ``kernel`` argument is true for every call through a kernel pointer,
which includes BPF that kernel code loads with ``kern_sys_bpf()``, such
as a light skeleton in a module. shirudo admits those as it admits a
loader's calls. A signed loader can issue every command
``bpf_sys_bpf()`` allows, ``BPF_MAP_GET_FD_BY_ID`` and
``BPF_LINK_CREATE`` among them, and the guards do not limit what it does
with them: an upatch does what its signer wrote.

The two enforcement objects are loaded without a signature from the
authenticated initrd; their trust comes from the boot chain. Pins keep
upatches attached, so the pins depend on the private bpffs staying
mounted, which the mount guards in :doc:`enforcement` protect.

:doc:`/security/threat-model` states the residual risks.

Related
-------

- :doc:`/concepts/background/bpf-signing` for the kernel's signed BPF
  support
- :doc:`enforcement` for every hook and counter
- :doc:`kernel-interfaces` for the exact ``bpf()`` attributes
- :doc:`/reference/formats/upatch-format` for the container
