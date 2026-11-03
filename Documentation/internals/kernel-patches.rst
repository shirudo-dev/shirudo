..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Kernel developers, security reviewers

Carried kernel patches
======================

The kernel patches in :src:`kernel/` of the shirudo tree. The test kernel
build applies them; a production kernel needs the same changes.

Summary
-------

.. list-table::
   :header-rows: 1
   :widths: 34 22 22 22

   * - Patch
     - Author
     - In bpf-next
     - Architectures
   * - ``0001-x86-ftrace-Mark-jmp-mode-by-clearing-bit-63-of-the-trampoline-address.patch``
     - Daniel Borkmann
     - No
     - x86-64
   * - ``0002-tpm-Let-LSMs-inspect-userspace-commands.patch``
     - KP Singh
     - No
     - All
   * - ``0003-bpf-Remove-the-unused-bpf_obj_get_user-stub.patch``
     - Anton Protopopov
     - No
     - All
   * - ``0004-bpf-Accept-a-kernel-pathname-in-BPF_OBJ_GET.patch``
     - Anton Protopopov
     - No
     - All
   * - ``0005-bpf-Allow-BPF_OBJ_GET-in-bpf_sys_bpf.patch``
     - Anton Protopopov
     - No
     - All

"In bpf-next" was checked against the bpf-next tree at commit
``4169c9c90532``: ``include/linux/ftrace.h`` there still marks jmp mode
with bit 0, and ``include/linux/lsm_hook_defs.h`` has no ``tpm_command``
hook. ``0003`` to ``0005`` are not posted yet.

How the test kernel applies them
--------------------------------

``make -C testing kernel`` passes ``KERNEL_PATCHES``, which defaults to
:src:`kernel/` when that directory holds patches.
:src:`testing/vm/build-kernel.sh` applies each patch in name order with
``git apply --index`` and commits it, and skips a patch whose reverse
already applies. A patch that applies neither way fails the build.

x86 ftrace jmp mode
-------------------

Subject
    x86/ftrace: Mark jmp mode by clearing bit 63 of the trampoline
    address

Fixes
    ``0c3772a8db1f`` ("x86/ftrace: Implement DYNAMIC_FTRACE_WITH_JMP"),
    first released in v6.19.

Files
    ``arch/x86/kernel/ftrace_64.S``, ``include/linux/ftrace.h``,
    ``kernel/trace/Kconfig``.

What it changes
    With ``CONFIG_DYNAMIC_FTRACE_WITH_JMP``, which only x86-64 selects,
    ``ftrace_call_replace()`` emits a ``jmp`` instead of a ``call`` when
    bit 0 of the target is set, the mark of a direct trampoline entered
    by a jump. The same code patches the call of the ftrace callback in
    ``ftrace_caller``, ``ftrace_regs_caller`` and the ftrace trampolines,
    but a callback is a C function and can start at an odd address. It
    does with gcc 13 and ``CONFIG_CC_OPTIMIZE_FOR_SIZE=y``: gcc 13 has no
    ``-fmin-function-alignment``, and ``-falign-functions=16`` does not
    apply to functions optimized for size. The call then becomes a jump
    to the byte before the callback, which decodes as another instruction
    and swallows part of the callback's prologue; the callback runs
    without a return address and returns through the saved registers.
    The patch marks jmp mode by
    clearing bit 63 instead, which is set in every x86-64 kernel text
    address, so no callback can carry the mark, and a marked address
    that is used without being unmarked is not canonical and faults.

Why shirudo needs it
    The list callback ``ftrace_ops_list_func()`` is installed whenever two
    ``ftrace_ops`` are registered, and every
    ``update_ftrace_direct_mod()`` registers a stub ops for the sites it
    modifies. Detaching one of several BPF LSM programs from a busy hook
    is such an update. shirudo puts several programs on the same hooks,
    ``bpf2`` and ``seal`` share nine, and an upatch unload detaches
    programs from hooks that other tasks are running. The test kernel's
    slim configuration sets ``CONFIG_CC_OPTIMIZE_FOR_SIZE=y``.

Without it
    On an affected x86-64 build, a task that runs the hook during the
    trampoline update can take a kernel page fault on an instruction
    fetch, and the kernel oopses. Builds whose callbacks start at even
    addresses, and other architectures, are not affected.

TPM command LSM hook
--------------------

Subject
    tpm: Let LSMs inspect userspace commands

Files
    ``drivers/char/tpm/tpm-dev-common.c``,
    ``include/linux/lsm_hook_defs.h``, ``include/linux/security.h``,
    ``security/security.c``.

What it changes
    ``tpm_common_write()``, the write handler of both ``/dev/tpm0`` and
    ``/dev/tpmrm0``, calls a new hook,
    ``security_tpm_command(file, command, command_len)``, after it has
    copied the command from userspace and validated the header, and
    before it sends or queues the command. ``command_len`` is the length
    the header declares, so trailing bytes of the write are not part of
    the decision; the command stays in the device buffer until the hook
    returns. The patch also refuses a header whose declared length is
    smaller than the header itself.

Why shirudo needs it
    The key that authorizes extensions of shirudo's NV register lives in
    the TPM and is recreatable by any process that knows its public input,
    which the identity map holds. A guard on the key cannot work, so
    ``lsm/tpm_command`` guards the command: it refuses
    ``TPM2_NV_Extend`` of the frozen index to tasks without runtime
    authority. A check when the device is opened would miss descriptors
    opened earlier or inherited from another process; the hook sees every
    command. :doc:`measurement-register` explains the writer.

Without it
    The kernel's BTF has no ``bpf_lsm_tpm_command``, so the ``bpf2``
    object fails to load and ``init`` fails at "loading enforcement". The
    boot is not stopped, and the target runs without enforcement, as
    :doc:`boot-flow` describes.

BPF_OBJ_GET from signed loaders
-------------------------------

Subjects
    bpf: Remove the unused bpf_obj_get_user() stub; bpf: Accept a kernel
    pathname in BPF_OBJ_GET; bpf: Allow BPF_OBJ_GET in bpf_sys_bpf()

Files
    ``include/linux/bpf.h``, ``kernel/bpf/inode.c``,
    ``kernel/bpf/syscall.c``.

What it changes
    ``BPF_OBJ_GET`` reads the pathname through a ``bpfptr_t``, so that a
    ``BPF_PROG_TYPE_SYSCALL`` program can pass one in kernel memory; such
    a path is copied into a ``PATH_MAX`` buffer and looked up with
    ``kern_path()``, with the root, the current directory and the
    credentials of the current task, and without ``BPF_F_PATH_FD``. The
    ``bpf_sys_bpf()`` helper then accepts ``BPF_OBJ_GET``. The first
    patch only removes a stub without callers, so that the others apply
    as they are.

Why shirudo needs it
    A program that attaches to a program of another upatch is loaded
    with the target's descriptor as ``attach_prog_fd``. The signed loader
    opens the target by its pin, a path in the loader's data that the
    signature covers. :doc:`/upatches/write/attach-kinds` describes the kind.

Without it
    The loader's ``BPF_OBJ_GET`` fails, and the upatch fails in phase
    ``payload_load``. Every other upatch is unaffected.

Related
-------

- :doc:`kernel-interfaces` for the other kernel requirements
- :doc:`/contribute/testing/testing` for building and booting the test kernel
