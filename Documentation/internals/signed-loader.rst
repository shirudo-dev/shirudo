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

Upatches are BPF, so shirudo cannot switch BPF off. It needs a kernel
that accepts BPF the operator signed and refuses BPF from anyone else,
root with every capability included. Root can issue any system call, so
the decision has to sit where root cannot step around it.

A Java upatch is the exception: it carries a jar and no loader, so it
never takes this path. The target checks its signature in userspace, as
the Java payloads section of :doc:`/reference/formats/upatch-format`
describes, and :doc:`/security/threat-model` (T15, R24) says why that
makes it a mitigation and not a boundary against root.

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
``bpf()`` calls that create the upatch's maps and load its programs. The
loader's data blob carries everything those calls need, the payload
programs' instructions included. The builder appends signed sections to
the data (the upatch name, the attach metadata, the unload target, the
decoders and the policy labels) and signs ``loader_insns || data`` with
ML-DSA-87 as a detached CMS signature. The ``.upatch`` container carries the loader instructions,
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

``shirudo upatch load`` runs the steps of the table below. Figure 1 shows
its ``bpf()`` calls, the hook that decides each, and the order of the
kernel's checks inside the loader's ``BPF_PROG_LOAD``. The calls from
userspace reach ``lsm/bpf`` with ``kernel`` false; the loader's own calls,
made inside the test run, reach it with ``kernel`` true.

.. figure:: /images/internals-signed-load.svg
   :alt: A sequence with four lifelines: shirudo upatch load, bpf() with
         lsm/bpf at entry, bpf_check() with the .bpf keyring, and the
         loader. shirudo creates, fills and freezes __loader.map with
         runtime authority, then loads the loader. lsm/bpf checks at
         entry that it is a SYSCALL program with a signature size;
         inside bpf_check() the kernel binds the map, verifies the
         signature over the instructions and the map's value against
         .bpf, runs lsm/bpf_prog_load on the verdict and keyring kind,
         and then the analysis, which compares the map's hash. A test
         run, again with authority, starts the loader, whose nested
         map and program calls reach bpf() with kernel true and are
         allowed. Then shirudo creates and checks the links and pins
         them.

   Figure 1. The ``bpf()`` calls of a signed load. The numbers give the
   order of the checks on the loader's ``BPF_PROG_LOAD``.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Step
     - What decides it
   * - read the file
     - The file is read once, into memory, and every later step takes
       its bytes from that read: the name and payload measured, the
       loader the kernel verifies and the copy archived.
   * - pre-flight
     - The kernel ABI check passes, the ``.bpf`` keyring serial equals
       the frozen identity record, and ``lsm_link`` is pinned. With
       ``--expect-chain``, the register equals the given value.
   * - take the register lock, undo
     - The register lock is held from here to the append. The undo pass
       removes pins and archives this boot's records do not cover, and
       refuses when the records do not fold to the register.
   * - check the artifact
     - The signed name must equal the header name, ``payload_sha256``
       must equal SHA-256 of ``loader_insns || data``, and the signed
       attach metadata must parse. Each ``uprobe``, ``uretprobe``,
       ``uprobe.multi`` and ``uretprobe.multi`` target is opened and its
       GNU build ID compared before any BPF loads.
   * - ``BPF_MAP_CREATE`` of ``__loader.map``
     - ``lsm/bpf`` allows it to a task with runtime authority, else
       ``EACCES`` (``MapCreate``).
   * - ``BPF_MAP_UPDATE_ELEM``, ``BPF_MAP_FREEZE``
     - ``lsm/bpf``, runtime authority (``MapWrite``).
   * - ``BPF_PROG_LOAD`` of the loader
     - ``lsm/bpf`` at entry, then the kernel's signature check and
       ``lsm/bpf_prog_load`` inside ``bpf_check()``, in the order of
       Figure 1 (``LoadNotLoader``, ``LoadUnsigned``, ``LoadUnverified``,
       ``LoadKeyringKind``).
   * - ``BPF_PROG_TEST_RUN`` of the loader
     - ``lsm/bpf``, runtime authority (``ProgRun``).
   * - (loader) ``BPF_MAP_CREATE``, ``BPF_MAP_UPDATE_ELEM``,
       ``BPF_MAP_FREEZE``, ``BPF_PROG_LOAD`` through ``bpf_sys_bpf()``
     - ``lsm/bpf`` and ``lsm/bpf_prog_load`` see ``kernel`` true and
       allow. The verifier checks each payload program as usual.
   * - ``BPF_LINK_CREATE`` or ``BPF_RAW_TRACEPOINT_OPEN``, per program
     - ``lsm/bpf``, runtime authority (``ProgAttach``). shirudo then
       compares the link the kernel reports with the signed metadata and
       refuses ``attach_scope_mismatch`` when they differ.
   * - ``BPF_OBJ_PIN`` of each link and map
     - ``lsm/bpf``, runtime authority (``ObjPin``), and the bpffs inode
       guards.
   * - archive, extend, append
     - The artifact is copied to ``/var/lib/shirudo/upatches/``, the
       register is extended with the load event and the eventlog takes
       the record. A failed copy or a refused extension undoes the load.

``shirudo bpm`` installs, upgrades and tree operations skip the
pre-flight row (they pass ``--no-precheck``); the keyring comparison runs
again inside the load, so those paths keep it.

When the signed ``SHPL`` section is present, shirudo opens its pinned
``shirudo_task_policy`` and ``shirudo_sock_policy`` before the test run
and supplies both descriptors at their signed indices in the loader's
context. The generated loader reuses them; it neither creates nor pins
private copies.

The loader returns the descriptors of what it created in its context
buffer, and the command attaches and pins them. Links are created in
userspace because gen_loader emits no link creation and
``bpf_sys_bpf()`` has no ``BPF_OBJ_PIN``. Each link is pinned at
``/run/shirudo/bpffs/upatches/<name>/link``, or ``link_<n>`` for several,
serializers under ``serializers/``, maps under ``maps/`` and the test-run
program at ``test`` beside it. A dot in the name is written as ``~d``
there. The directory carries the
``security.bpf.shirudo.payload`` extended attribute with the payload
digest, which only a task with runtime authority can set.
:doc:`kernel-interfaces` lists the attributes each call sets.
XDP expands each program's signed class mask into links on matching
interfaces in the initial network namespace, with one endpoint per veth
pair, using native driver mode only.
Artifacts containing XDP always use ``link_<n>`` pins, including when only
one link is created, and pin each XDP program at ``xdp_prog_<n>``, which
keeps it loaded while no device matches its class mask. A load that finds
no matching device succeeds and attaches nothing until ``upatch
reconcile`` finds one. Devices without native XDP, and devices that
vanish or change during the attach, are skipped; any other attachment
failure removes all links the load created.

Telling the loader apart from root
----------------------------------

A signature check alone is not enough. The loader calls back into
``bpf()`` to create maps and load programs, and those calls look like the
ones root would make. What tells them apart is where the attributes come
from: ``bpf_sys_bpf()`` passes a kernel pointer, which the kernel hands
to ``lsm/bpf`` and ``lsm/bpf_prog_load`` as ``bool kernel``. Calls with
``kernel`` true come from a loader the kernel already verified and that
an authorized task is running, so they are allowed; userspace calls are
filtered. ``lsm/bpf_map`` and ``lsm/bpf_prog`` take no such argument.
They see the descriptors of the loader's maps and programs too, and
pass them because the task that runs the loader has runtime authority.

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
with them: a upatch does what its signer wrote.

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
