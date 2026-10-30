..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators, security reviewers

Tamper counters
===============

Each point at which one of shirudo's guards refuses a caller has a
counter. The guard adds one to it when it refuses. The counters live in
the array map ``shirudo_tamper``, which ``init`` creates, freezes and
pins at ``/run/shirudo/bpffs/tamper`` at every boot, so they count this
boot's refusals. No task resets them from userspace; only the hooks add
to them. Threat T10 of the :doc:`threat-model` explains their purpose.

Counters
--------

The name and the meaning are what ``shirudo status`` prints. The hooks
are the section names of the BPF programs in :src:`bpf/` that move the
counter.

.. list-table::
   :header-rows: 1
   :widths: 17 31 33 19

   * - Counter
     - Meaning
     - Hooks and condition
     - Errno
   * - ``LoadNotLoader``
     - program load that is not a signed loader
     - ``lsm/bpf``: ``BPF_PROG_LOAD`` of a type other than
       ``BPF_PROG_TYPE_SYSCALL``, every userspace caller
     - ``EACCES``
   * - ``LoadUnsigned``
     - loader-type program load without a signature
     - ``lsm/bpf``: ``BPF_PROG_LOAD`` of a syscall program without a
       signature, every userspace caller
     - ``EACCES``
   * - ``LoadUnverified``
     - program load whose signature the kernel did not verify
     - ``lsm/bpf_prog_load``, every userspace caller
     - ``EACCES``
   * - ``LoadKeyringKind``
     - program signed against a keyring of the wrong kind
     - ``lsm/bpf_prog_load``: a signature verified against the
       built-in, secondary or platform keyring, every userspace caller
     - ``EACCES``
   * - ``LoadKeyring``
     - program signed against a keyring that is not the anchor
     - ``lsm/bpf_prog_load``: a keyring serial other than the frozen
       one, every userspace caller. The kernel records serial 0 for
       ``.bpf``, which the hook does not compare, so this counter does
       not move on the target kernel.
     - ``EACCES``
   * - ``MapCreate``
     - map creation by another executable
     - ``lsm/bpf``: ``BPF_MAP_CREATE``
     - ``EACCES``
   * - ``MapWrite``
     - map update or freeze by another executable
     - ``lsm/bpf``: ``BPF_MAP_UPDATE_ELEM``, ``BPF_MAP_FREEZE``
     - ``EACCES``
   * - ``MapFdWrite``
     - writable map descriptor for another executable
     - ``lsm/bpf_map``: a writable descriptor
     - ``EACCES``
   * - ``ProgRun``
     - test run of a program by another executable
     - ``lsm/bpf``: ``BPF_PROG_TEST_RUN``
     - ``EACCES``
   * - ``ProgAttach``
     - link or raw tracepoint attach by another executable
     - ``lsm/bpf``: ``BPF_LINK_CREATE``, ``BPF_RAW_TRACEPOINT_OPEN``
     - ``EACCES``
   * - ``ObjPin``
     - pin of a BPF object by another executable
     - ``lsm/bpf``: ``BPF_OBJ_PIN``
     - ``EACCES``
   * - ``BpfCommand``
     - detach, update, delete or unclassified bpf() command
     - ``lsm/bpf``: every command not listed elsewhere, such as
       ``BPF_LINK_DETACH``, ``BPF_LINK_UPDATE``, ``BPF_PROG_ATTACH``,
       ``BPF_BTF_LOAD`` and the map deletions, from every userspace
       caller, shirudo included
     - ``EACCES``
   * - ``ExeIdentity``
     - executable change through PR_SET_MM
     - ``lsm/task_prctl``: ``PR_SET_MM_EXE_FILE``, ``PR_SET_MM_MAP``
     - ``EPERM``
   * - ``KeyringWrite``
     - write, unlink, revoke or invalidate on the anchor keyring
     - ``lsm/key_permission``: write, setattr, unlink or a search
       through an unpossessed reference on ``.bpf``, ``.dm-verity``,
       the config key or an enrolled key
     - ``EACCES``
   * - ``PinUnlink``
     - unlink of a pin in the private bpffs
     - ``lsm/inode_unlink`` in the private bpffs
     - ``EPERM``
   * - ``PinRename``
     - rename of a pin in the private bpffs
     - ``lsm/inode_rename``, either directory in the private bpffs
     - ``EPERM``
   * - ``PinXattr``
     - xattr change on a pin in the private bpffs
     - ``lsm/inode_setxattr``, ``lsm/inode_removexattr`` in the private
       bpffs
     - ``EPERM``
   * - ``BpffsUmount``
     - unmount of the private bpffs
     - ``lsm/sb_umount``: the bpffs superblock, every caller
     - ``EPERM``
   * - ``BpffsUmountAbove``
     - unmount of a mount above the private bpffs
     - ``lsm/sb_umount``: an unmount whose subtree or propagation
       reaches the recorded bpffs mount, or a tree the walk cannot
       finish, every caller
     - ``EPERM``
   * - ``BpffsMount``
     - move, mount over or remount of the private bpffs
     - ``lsm/move_mount``, ``lsm/sb_mount``, ``lsm/sb_remount``, every
       caller
     - ``EPERM``
   * - ``SealWrite``
     - write open of a sealed file
     - ``lsm.s/file_open``
     - ``EACCES``
   * - ``SealUnlink``
     - unlink of a sealed file
     - ``lsm.s/inode_unlink``
     - ``EACCES``
   * - ``SealRename``
     - rename of or over a sealed file
     - ``lsm.s/inode_rename``: a labeled source or victim
     - ``EACCES``
   * - ``SealSetattr``
     - truncate, chmod, chown or utimes of a sealed file
     - ``lsm.s/inode_setattr``
     - ``EACCES``
   * - ``SealXattr``
     - xattr change on a sealed file
     - ``lsm.s/inode_setxattr``, ``lsm.s/inode_removexattr``
     - ``EACCES``
   * - ``SealLabel``
     - seal or policy label changed by another executable
     - ``lsm.s/inode_setxattr`` or ``lsm.s/inode_removexattr``: the exact
       names ``security.bpf.shirudo`` or
       ``security.bpf.shirudo.policy`` on any inode
     - ``EACCES``
   * - ``SealPtrace``
     - ptrace of a shirudo task
     - ``lsm/ptrace_access_check``
     - ``EACCES``
   * - ``SealPerf``
     - perf event bound to a shirudo task
     - ``lsm/perf_event_alloc``
     - ``EACCES``
   * - ``ExecTraced``
     - exec of shirudo by a traced task
     - ``lsm.s/bprm_check_security`` in the seal object, and
       ``lsm/bprm_check_security`` in the ``bpf2`` object
     - ``EACCES``, or ``EPERM`` from the ``bpf2`` hook
   * - ``SealEntry``
     - entry created, linked or renamed into a sealed directory
     - ``lsm/inode_create``, ``lsm/inode_mkdir``,
       ``lsm/inode_symlink``, ``lsm/inode_mknod``, ``lsm/inode_link`` in
       the seal object, and ``lsm.s/inode_rename`` for the destination
     - ``EACCES``
   * - ``PerfAttach``
     - program attached to a perf event by another executable
     - ``lsm/file_ioctl``, ``lsm/file_ioctl_compat``: the ioctl number
       of ``PERF_EVENT_IOC_SET_BPF`` on any file
     - ``EACCES``
   * - ``PinEntry``
     - directory or link made in the private bpffs by another executable
     - ``lsm/inode_mkdir``, ``lsm/inode_symlink``, ``lsm/inode_link`` in
       the ``bpf2`` object
     - ``EPERM``
   * - ``SealCopyUp``
     - overlay copy-up of a sealed inode
     - ``lsm/inode_copy_up``
     - ``EPERM``
   * - ``Kexec``
     - kexec image or initramfs load
     - ``lsm/kernel_load_data``, ``lsm/kernel_read_file``, every caller
     - ``EPERM``
   * - ``TpmExtend``
     - extension of shirudo's TPM NV index by another executable
     - ``lsm/tpm_command``: ``TPM2_NV_Extend`` of the frozen index
       without runtime authority, or a command too short to inspect
       from any caller
     - ``EACCES``
   * - ``ObjGet``
     - pin, map or link opened by another executable
     - ``lsm/bpf``: ``BPF_OBJ_GET``, ``BPF_MAP_GET_FD_BY_ID``,
       ``BPF_LINK_GET_FD_BY_ID``; ``lsm/bpf_map``: a read-only
       descriptor; ``lsm/file_open`` in the ``bpf2`` object: a
       non-directory inode in the private bpffs
     - ``EACCES``

Unless the row says every caller, a task with runtime authority is
not refused and moves nothing.

Refusals without a counter
--------------------------

A zero counter does not mean nobody tried. These refusals move no
counter:

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - Refusal
     - Where
   * - The kernel's own signature errors at ``BPF_PROG_LOAD``, such as
       ``ENOKEY``, ``EKEYREJECTED``, ``EPERM`` for a caller-supplied
       keyring and ``EACCES`` for CO-RE relocations
     - The kernel, before ``lsm/bpf_prog_load`` runs
   * - rmdir in the private bpffs
     - ``lsm/inode_rmdir``
   * - Inode and mount operations on the ``/run/shirudo`` tmpfs
     - The ``bpf2`` inode guards and ``lsm/sb_umount``,
       ``lsm/move_mount``, ``lsm/sb_mount``, ``lsm/sb_remount``
   * - Unmount, move, mount over and remount of the runtime and config
       image mounts
     - ``lsm/sb_umount``, ``lsm/move_mount``, ``lsm/sb_mount``,
       ``lsm/sb_remount``
   * - Device-mapper control ioctls
     - ``lsm/file_ioctl``, ``lsm/file_ioctl_compat``
   * - A dm-verity mapping that is already recorded, or whose root
       cannot be read
     - ``lsm.s/bdev_setintegrity``
   * - Exec of a runtime file under a seccomp filter, and an exec for
       which task storage cannot be allocated
     - ``lsm.s/bprm_check_security``
   * - A fork that cannot copy a task mark
     - ``lsm/task_alloc``
   * - A new inode under a marked directory that cannot receive the
       label
     - ``lsm/inode_init_security``
   * - Executable mappings of an authorized task that are writable or
       not from the runtime image
     - ``lsm/mmap_file``, ``lsm/file_mprotect``
   * - Refusals by another LSM ordered before ``bpf``
     - The kernel calls no BPF program for an operation another LSM
       already refused
   * - shirudo's own refusals, such as ``tampered``,
       ``payload_mismatch`` and ``attach_scope_mismatch``
     - Userspace

Reading the counters
--------------------

Read the counters with ``shirudo status`` started from the runtime
image, the way the drop-in that ``shirudo-gen-runtime --unit-output``
generates starts ``init``. A binary outside the runtime image cannot
open the counter map, and its attempt moves ``ObjGet``.

``shirudo status`` prints the section ``Tamper attempts (refused this
boot):`` with one line per counter that is not zero: its name, its
count and its meaning. It prints ``none`` when every counter is zero,
and ``(none recorded: init has not pinned the counters this boot)``
before ``init`` has run.

``shirudo status --json`` carries every counter under
``tamper_attempts``, with the sum in ``total`` and each counter by name
in ``counters``, so a collector's keys stay the same from one record to
the next. The value is ``null`` before ``init`` has pinned the map.

The keepalive, ``shirudo status --otel``, sends the same status as an
OTLP log record and adds the total as the attribute
``shirudo.tamper_attempts``. The attribute is absent when the counters
cannot be read.

What a non-zero counter means
-----------------------------

A counter that moved means that a guard refused an operation this boot.
The refusal is what moved it: the operation did not happen.

A non-zero counter does not mean:

- That the target is compromised. A refused attempt is an attempt.
- That root made the attempt. ``lsm/bpf`` runs before the kernel checks
  capabilities, so an unprivileged process moves the counters of
  ``bpf()`` commands.
- That a foreign program made it. ``BpfCommand``, ``Kexec``,
  ``BpffsUmount``, ``BpffsUmountAbove``, ``BpffsMount`` and a malformed
  TPM command count refusals of shirudo's own tasks too, and a shirudo
  binary outside the runtime image moves ``ObjGet``.
- That the operation was the one the meaning names. ``PerfAttach``
  counts the ioctl number on any file, whatever the device.

A counter does not change the verdict of ``shirudo status``. It is the
target's own account, like the rest of the status, and it travels
unauthenticated to the collector. Only ``shirudo attest verify`` is
evidence. To act on a counter, see
:doc:`/operate/troubleshoot/incident-tampered`.

Related
-------

- :doc:`threat-model`, threat T10, for the purpose and the limits
- :doc:`/internals/enforcement` for the hooks
