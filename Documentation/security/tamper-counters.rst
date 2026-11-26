..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators, security reviewers

Tamper counters
===============

Each point at which one of shirudo's guards refuses a caller has a
counter. The guard adds one to it when it refuses. One point counts
what it lets through: ``SealSignal``, a signal to a shirudo task from a
task without authority, which no hook refuses. The counters live in
the array map ``shirudo_tamper``, which ``init`` creates, freezes and
pins at ``/run/shirudo/bpffs/tamper`` at every boot, so they count this
boot's refusals. No task resets them from userspace; only the hooks add
to them. Threat T10 of the :doc:`threat-model` explains their purpose.
Refusals of changes to the running kernel count apart, as
:doc:`integrity-counters`.

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
     - unmount of a mount above the private bpffs or a refused host pivot
     - ``lsm/sb_umount``: an unmount whose subtree or propagation
       reaches the recorded bpffs mount, or a tree the walk cannot
       finish, with the checked initrd handoff exception.
       ``lsm/sb_pivotroot`` counts a refused pivot in the protected
       namespace. ``lsm/inode_rmdir``,
       ``lsm/inode_unlink``, ``lsm/inode_rename``: the removal or rename
       of the mount point of that mount or of one above it, which
       detaches or moves the mounts on it in every namespace, to a task
       without authority
     - ``EPERM``
   * - ``BpffsMount``
     - move, mount over or remount of the private bpffs, or a refused
       legacy propagation change on its mount ancestry
     - ``lsm/move_mount``, ``lsm/sb_mount``, ``lsm/sb_remount``, every
       caller
     - ``EPERM``
   * - ``SealWrite``
     - write open of a sealed file
     - ``lsm.s/file_open``
     - ``EACCES``
   * - ``SealUnlink``
     - unlink of a sealed file or removal of a sealed directory
     - ``lsm.s/inode_unlink``, ``lsm.s/inode_rmdir``
     - ``EACCES``
   * - ``SealRename``
     - rename of or over a sealed file, or of or over a directory above
       the state root
     - ``lsm.s/inode_rename``: a labeled source or victim, or one that
       carries the ``security.bpf.shirudo.ancestor`` mark
     - ``EACCES``
   * - ``SealSetattr``
     - truncate, chmod, chown, utimes or chattr of a sealed file
     - ``lsm.s/inode_setattr``, ``lsm.s/inode_file_setattr``
     - ``EACCES``
   * - ``SealXattr``
     - xattr or ACL change on a sealed file
     - ``lsm.s/inode_setxattr``, ``lsm.s/inode_removexattr``,
       ``lsm.s/inode_set_acl``, ``lsm.s/inode_remove_acl``
     - ``EACCES``
   * - ``SealLabel``
     - seal or policy label changed by another executable
     - ``lsm.s/inode_setxattr`` or ``lsm.s/inode_removexattr``: the exact
       names ``security.bpf.shirudo``, ``security.bpf.shirudo.policy`` or
       ``security.bpf.shirudo.ancestor`` on any inode
     - ``EACCES``
   * - ``SealPtrace``
     - ptrace of a shirudo task
     - ``lsm/ptrace_access_check``: an access mode that includes
       ``PTRACE_MODE_ATTACH``, such as ``ptrace(2)`` attach,
       ``/proc/<pid>/mem``, ``process_vm_readv(2)`` and
       ``pidfd_getfd(2)``
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
     - entry into a sealed directory, or a sealed inode linked
     - ``lsm.s/inode_create``, ``lsm.s/inode_mkdir``,
       ``lsm.s/inode_symlink``, ``lsm.s/inode_mknod`` and
       ``lsm.s/inode_link`` in the seal object, which read the
       directory's label, ``lsm.s/inode_link`` for a labeled source, and
       ``lsm.s/inode_rename`` for the destination
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
     - ``lsm.s/inode_copy_up``, every caller
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
   * - ``TpmWrite``
     - protected TPM mutation by an unauthorized task
     - ``lsm/tpm_command``: from a task without runtime authority, a
       mutation of shirudo's register or the config PCR, a mutation other
       than an extension of a systemd NvPCR, a hierarchy or clear
       command, or an unknown or malformed command
     - ``EACCES``
   * - ``ObjGet``
     - pin, map, link or XDP program opened by another executable
     - ``lsm/bpf``: ``BPF_OBJ_GET``, ``BPF_MAP_GET_FD_BY_ID``,
       ``BPF_LINK_GET_FD_BY_ID``; ``lsm/bpf_map``: a read-only
       descriptor; ``lsm/bpf_prog``: an XDP program descriptor;
       ``lsm/file_open`` in the ``bpf2`` object: a
       non-directory inode in the private bpffs
     - ``EACCES``
   * - ``SealSignal``
     - signal to a shirudo task (let through)
     - ``lsm/task_kill``: a signal other than 0 to a marked task from a
       task without authority; the signal is delivered. The kernel's
       own signals pass no hook and are not counted: ``SIGKILL`` from
       ``cgroup.kill`` or the OOM killer, ``SIGPIPE`` on a pipe whose
       reader is gone. Nor is the cgroup freezer, which stops a task
       without a signal
     - none
   * - ``SealCoreDump``
     - core dump of a shirudo task, which acts without authority
     - Any hook that asks for runtime authority, the first time a
       marked task that is dumping core asks: the task loses its
       authority for good, and the hook refuses the operation and moves
       its own counter
     - the hook's
   * - ``SealUprobe``
     - uprobe in a shirudo task, which acts without authority
     - Any hook that asks for runtime authority, the first time a
       marked task whose memory a uprobe reached asks: the task loses
       its authority for good, and the hook refuses the operation and
       moves its own counter
     - the hook's
   * - ``XattrHandle``
     - XFS attribute change by file handle, which passes no xattr hook
     - ``lsm/file_ioctl``, ``lsm/file_ioctl_compat``:
       ``XFS_IOC_ATTRMULTI_BY_HANDLE`` on an XFS file system, reads
       included, from a task without authority
     - ``EACCES``
   * - ``ExecShared``
     - exec of the runtime binary by a task that shares its file system
       context
     - ``lsm.s/bprm_check_security``: an exec of the runtime binary
       while another process shares the task's root and working
       directory (``CLONE_FS``)
     - ``EACCES``
   * - ``SealRlimit``
     - resource limit of a shirudo task changed by another task
     - ``lsm/task_setrlimit``: ``prlimit`` on a marked task from a task
       without authority, which could have the kernel stop it with
       ``SIGXFSZ`` or ``SIGXCPU``
     - ``EPERM``

Unless the row says every caller, a task with runtime authority is
not refused and moves nothing.

.. note::

   Every ptrace mode against a shirudo task is refused, but only an
   attach-mode access is counted. A read-mode probe, such as journald
   reading ``/proc/<pid>/exe`` for a log line or ``ps`` reading
   ``/proc/<pid>/stat``, or a read of ``environ``, ``maps`` or the
   ``fd`` links, is refused silently: the caller gets ``EACCES`` and may
   log it, but ``SealPtrace`` and the keepalive do not move. Honest
   system services make read-mode checks against every process that
   logs, so counting them would make a healthy node read as tampered.

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
   * - A read-mode ptrace access check against a shirudo task, such as
       a read of ``/proc/<pid>/exe``, ``environ``, ``maps`` or the
       ``fd`` links, ``kcmp(2)`` and ``process_madvise(2)``
     - ``lsm/ptrace_access_check``
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

``shirudo status`` prints the section ``Tamper attempts (this
boot):`` with one line per counter that is not zero: its name, its
count and its meaning. It prints ``none`` when every counter is zero,
``none recorded before init`` before ``init`` has pinned the map, and
``unavailable:`` with the error when the map cannot be read.

``shirudo status --json`` carries every counter under
``tamper_attempts``, with the sum in ``total`` and each counter by name
in ``counters``, so a collector's keys stay the same from one record to
the next. The value is ``null`` before ``init`` has pinned the map.

The keepalive, ``shirudo status --otel``, carries every counter in the
``tamper`` list of its body, zeros included and in the order of this
page, and the TPM quotes the body. The list is ``null``, and bit 3 of
the body's ``flags`` set, when the counters cannot be read.

What a non-zero counter means
-----------------------------

A counter that moved means that a guard refused an operation this boot.
The refusal is what moved it: the operation did not happen. The one
exception is ``SealSignal``, which counts a signal the seal delivered:
the task it went to may have been stopped, and the next upatch load or unload
and ``shirudo status`` find what a stopped load left. ``SealCoreDump``
counts a shirudo task that dumped core, after a crash or after an exec
that failed past its point of no return, which root can bring about
with a small stack limit; the dump did not get the task's authority.
``SealUprobe`` counts a shirudo task whose memory a uprobe reached, one
that root set through tracefs or perf on the runtime binary or on a
library it maps.

A non-zero counter does not mean:

- That the target is compromised. A refused attempt is an attempt.
- That root made the attempt. ``lsm/bpf`` runs before the kernel checks
  capabilities, so an unprivileged process moves the counters of
  ``bpf()`` commands.
- That a foreign program made it. ``BpfCommand``, ``Kexec``,
  ``BpffsUmount``, ``BpffsUmountAbove``, ``BpffsMount``, ``SealCopyUp``
  and a malformed TPM command count refusals of shirudo's own tasks
  too, and a shirudo binary outside the runtime image moves ``ObjGet``.
- That the operation was the one the meaning names. ``PerfAttach``
  counts the ioctl number on any file, whatever the device.

A counter does not change the verdict of ``shirudo status``. It is the
target's own account, like the rest of the status, and it travels
unauthenticated to the collector. Only ``shirudo attest verify`` is
evidence. To act on a counter, see
:doc:`/operate/troubleshoot/incident-tampered`.

Related
-------

- :doc:`integrity-counters` for the attempts on the running kernel
- :doc:`threat-model`, threat T10, for the purpose and the limits
- :doc:`/internals/enforcement` for the hooks
