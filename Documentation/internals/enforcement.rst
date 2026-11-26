..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: Kernel developers, security reviewers

Enforcement in the kernel
=========================

shirudo's enforcement is a set of BPF LSM programs that ``shirudo init``
attaches early in boot. This page explains what they protect, how they
tell shirudo from root, in which order ``init`` attaches them and why,
and ends with a reference table of every hook.

Problem
-------

A signature gate on program loads is not enough on its own. Root could
leave the gate in place and remove what makes it work: unlink the pin
that keeps a link attached, unmount the bpffs that holds the pins, write
a map that a guard reads, unlink the certificate from the keyring, extend
the measurement register with an event of its own choosing, trace the
process that holds authority, or boot another kernel by kexec with this
boot's TPM state. Each of these is an ordinary system call that root is
allowed to make.

A check in userspace cannot refuse any of them, for the reason
:doc:`signed-loader` gives: root does not have to ask. The refusal has to
happen in the kernel, on the call itself. BPF LSM programs do that. Each
one runs at an LSM hook, sees the call's arguments and the calling task,
and returns an error that the kernel hands back to the caller.

Two objects
-----------

The binary embeds two BPF objects. ``bpf2`` (:src:`bpf/bpf2.c`) holds BPF
admission and the guards of shirudo's own kernel state. ``seal``
(:src:`bpf/seal.c`) holds the task marks, the process protection and the
checks on writable state. Both share the LSM helpers and the verity
device records of :src:`bpf/lib/`.
``init`` loads both without a signature, from the binary the
authenticated initrd carries.

The objects share eight maps, which ``init`` hands from ``bpf2`` to
``seal`` with ``bpf_map__reuse_fd()`` and pins in the private bpffs:

.. list-table::
   :header-rows: 1
   :widths: 22 22 56

   * - Map
     - Pin
     - Contents
   * - ``shirudo_bpffs_sb``
     - ``identity``
     - The record ``init`` freezes: device numbers of the private bpffs
       and of ``/run/shirudo``, the state root device and inode, the runtime
       root hash, the ``.bpf``
       keyring serial and kind, the serials of the enrolled keys, the
       ``.dm-verity`` keyring and key serials, the NV index, the NV
       writer's public modulus and seed, and the ECC endorsement key
       name used to salt authenticated sessions. Created with
       ``BPF_F_RDONLY_PROG``, so the verifier refuses any BPF program
       that writes it; only ``init``'s one update before the freeze
       populates it.
   * - ``shirudo_tasks``
     - ``task_authority``
     - Task storage with each task's mark and exec candidate.
   * - ``shirudo_unlink_grant``
     - ``unlink_grant``
     - Task storage for the inode number of one open upatch directory
       in the private bpffs. A grant lasts until release, removal of
       that directory, successful exec or task exit.
   * - ``shirudo_task_policy``
     - ``task_policy``
     - Task storage with committed policy bits and the exec candidate.
   * - ``shirudo_sock_policy``
     - ``socket_policy``
     - Socket storage for committed policy bits, cloned from listeners
       to accepted sockets.
   * - ``shirudo_devices``
     - ``devices``
     - The dm-verity devices recorded as runtime or config, up to 128.
   * - ``shirudo_roots``
     - ``config_roots``
     - Task storage with the config root an authorized task expects to
       map next.
   * - ``shirudo_tamper``
     - ``tamper``
     - One counter per refusal point, see :doc:`/security/tamper-counters`.
   * - ``shirudo_integrity``
     - ``integrity``
     - One counter per way to change or read the running kernel that
       ``bpf2`` refuses, see :doc:`/security/integrity-counters`.

``init`` freezes every one of them against userspace writes except
``shirudo_roots``, which an authorized task writes before each config
mapping. ``bpf2`` also keeps ``shirudo_mnt_rec`` for the bpffs
mount it records, and ``seal`` keeps its scratch buffer and
``seal_dir_marks``, the inode storage of its marks on files and
directories.

A map no BPF program ever writes, such as ``shirudo_bpffs_sb``, is
created with ``BPF_F_RDONLY_PROG`` as well as frozen: freezing
(``BPF_MAP_FREEZE``) blocks only the syscall side, so without the flag
a BPF program could still write the map's value through a lookup's
return pointer and the verifier would allow it. A map a BPF program
does write, even once, such as ``shirudo_mnt_rec`` or the task, socket
and inode storage maps above, does not take the flag. The same applies
to a map a future change adds: set ``BPF_F_RDONLY_PROG`` at creation
the moment no BPF program writes it, and drop the flag the moment one
does.

Telling shirudo from root
-------------------------

Every guard that allows shirudo what it refuses to everyone else asks one
question: does the calling task have runtime authority? A task has it
when it carries a mark in ``shirudo_tasks`` that a core dump or a uprobe
has not revoked. Figure 1 in :ref:`seal-task-marks` shows how a task
gets, keeps and loses the mark.

The ``bpf()`` hooks have a second discriminator. ``lsm/bpf`` and
``lsm/bpf_prog_load`` receive ``bool kernel``, which is true for calls a
signed loader makes from inside the kernel. Those calls are allowed;
userspace calls are filtered.

No guard looks at the user ID, a capability or the path of the
executable. Root has all of those, and a path can be replaced.

What the hooks guard
--------------------

The BPF system call
    ``lsm/bpf`` admits a userspace ``BPF_PROG_LOAD`` only for a
    ``BPF_PROG_TYPE_SYSCALL`` program with a signature, and
    ``lsm/bpf_prog_load`` admits it only when the kernel verified it
    against the ``.bpf`` keyring. Map creation, update and freeze, test
    runs, link creation, raw tracepoint attach and pinning need runtime
    authority. Every command shirudo has not classified, including
    ``BPF_LINK_DETACH``, ``BPF_LINK_UPDATE``, ``BPF_PROG_DETACH``,
    ``BPF_BTF_LOAD`` and every map delete, is refused to every userspace
    caller, shirudo included, so a command a later kernel adds stays
    refused until someone classifies it.

Descriptors and pins
    A descriptor keeps its object alive. A link held open stays attached
    after shirudo unpins it for an unload, a revocation purge or the undo
    of a refused load, and no LSM hook sees a link descriptor being handed
    out. A map descriptor reads what the serializers own and, if
    writable, changes what the guards read. ``lsm/bpf`` therefore refuses
    ``BPF_OBJ_GET``, ``BPF_MAP_GET_FD_BY_ID`` and ``BPF_LINK_GET_FD_BY_ID``
    to a task without runtime authority. ``lsm/bpf_map``, which every
    route to a map descriptor passes, refuses every map descriptor to
    such a task, read-only or writable. ``lsm/file_open`` refuses such a
    task the opening of anything but a directory in the private bpffs,
    since a pin opened as a file reads a map's contents; directories stay
    listable. ``BPF_PROG_GET_FD_BY_ID`` stays allowed for types other than
    XDP. ``lsm/bpf_prog`` keeps XDP descriptors to runtime authority,
    since netlink can attach them without passing through ``bpf()``.
    ``BPF_BTF_GET_FD_BY_ID`` stays allowed. Root without authority cannot read
    shirudo's maps or hold one of its links open by pin or by id.
    ``lsm/file_ioctl`` refuses ``PERF_EVENT_IOC_SET_BPF``, which binds a
    program to a perf event without a ``bpf()`` command, to the same
    tasks.

The private bpffs and /run/shirudo
    The pins are the only reference that keeps the enforcement links and
    the upatch links attached once ``init`` exits. The inode hooks of
    ``bpf2`` refuse unlink, rmdir, mkdir, symlink, hard link, rename and
    extended attribute changes in the private bpffs and in the
    ``/run/shirudo`` tmpfs to tasks without runtime authority. The mount
    hooks refuse to every caller, shirudo included, the unmount, move,
    remount and mount-over of the bpffs, and any unmount that would take
    the recorded bpffs mount down with it, through its subtree or through
    mount propagation.

Keyrings and the register
    ``lsm/key_permission`` refuses write, setattr, unlink and
    unpossessed search on the ``.bpf`` and ``.dm-verity`` keyrings and the
    keys ``init`` recorded, so root cannot remove a trust anchor.
    ``lsm/tpm_command`` refuses ``TPM2_NV_Extend`` of shirudo's NV index
    to tasks without runtime authority, so a signature from the
    TPM-held writer key is not enough to change the register.

Images and device mapper
    ``lsm.s/bdev_setintegrity`` records which dm-verity devices hold the
    runtime image and the config image, the mount hooks refuse to unmount,
    move or cover them, and ``lsm/file_ioctl`` allows a task without
    runtime authority only the read-only device-mapper control commands.

Exec and processes
    ``seal`` grants and inherits the task mark, keeps ptrace and
    task-bound perf events away from marked tasks and counts a signal to
    one from a task without authority. ``bpf2`` runs every
    runtime executable in secure-exec mode, so the dynamic loader ignores
    ``LD_PRELOAD`` and the other unsafe variables, and refuses
    ``PR_SET_MM_EXE_FILE`` and ``PR_SET_MM_MAP`` to tasks without
    authority. ``seal`` refuses a task with runtime authority executable
    memory that does not come from the runtime image.

Kexec
    A kexec hands the machine to a kernel and initrd of the caller's
    choosing with the TPM as it is, so the evidence of this boot would
    vouch for whatever runs after. ``lsm/kernel_load_data`` and
    ``lsm/kernel_read_file`` refuse every kexec image and initramfs to
    every caller.

Lockdown
    ``lsm/locked_down`` refuses, to every caller, what the kernel's
    lockdown in integrity mode refuses, the ways root has to change the
    running kernel, and ``/proc/kcore``, which that mode leaves
    readable, an unsigned module among them. The hibernation check is
    refused without a count, as every read of ``/sys/power/state`` makes
    one, and ``lsm/file_open`` refuses a write of the
    ``HibernateLocation`` EFI variable, from which the next boot's
    initrd would resume. The kernel's lockdown LSM, where it runs,
    decides first, and covers the boot before ``init``.

Writable state
    ``seal`` refuses changes to labeled inodes under
    ``/var/lib/shirudo`` to tasks without runtime authority.
    :doc:`seal` explains the labels.

Attach order
------------

``init_lsm()`` in :src:`builtin-init.c` brings the enforcement up in this
order:

#. Load ``bpf2``.
#. Fill the identity map and freeze it.
#. Seed the bootstrap mark for its own process through a pidfd, freeze
   ``shirudo_tasks``, ``shirudo_devices``, ``shirudo_tamper``,
   ``shirudo_task_policy``, ``shirudo_sock_policy`` and
   ``shirudo_integrity``, and pin them with ``shirudo_roots``. Pin the
   identity map.
#. Attach ``task_prctl``, ``bprm_check_security``, ``inode_rmdir``,
   ``inode_rename``, ``inode_mkdir``, ``inode_symlink``, ``inode_link``,
   ``kernel_load_data``, ``kernel_read_file`` and ``locked_down``.
#. Attach ``file_ioctl``, ``file_ioctl_compat``, ``bdev_setintegrity``
   and ``bdev_free_security``.
#. Attach ``inode_unlink``, ``inode_setxattr``, ``inode_removexattr``,
   ``key_permission`` and ``tpm_command``.
#. Attach the mount guards ``sb_umount``, ``move_mount``, ``sb_mount``,
   ``sb_remount`` and the ``file_open`` recorder, open the bpffs root so
   the recorder notes the mount, and freeze that record.
#. Load ``seal`` on the shared maps, freeze its scratch map, and attach
   its twenty-nine hooks, then ``mmap_file`` and ``file_mprotect``.
#. Attach ``lsm/bpf_map``, then ``lsm/bpf_prog``, then
   ``lsm/bpf_prog_load``, then ``lsm/bpf``.

``init`` pins every link as it attaches it, before the next fallible
step. A link that is not pinned detaches when ``init`` exits, and a
crash would leave an attached link nobody owns.

The order follows from three constraints. First, ``init`` loads the two
objects without a signature, and ``lsm/bpf`` and ``lsm/bpf_prog_load``
refuse an unsigned program load to every caller, ``init`` included, so
they attach last. Second, every guard reads the identity map, so the map
is complete and frozen before the first guard attaches; no guard ever
decides on a half-written record. Third, the
bpffs mount must be immutable before admission goes live, so the mount
guards and the bpffs inode guards attach before the seal and the
admission gates. ``init`` itself passes every guard on the way because
its bootstrap mark is in place before the first one attaches.

When any step fails, ``init`` unpins every link it attached and removes
the map pins, so no partial enforcement survives a failed ``init``. A
crash skips that cleanup. When it came before the identity map was
pinned, the next ``init`` removes the map pins it left. When it came
later, every later ``init`` in the same boot refuses before it loads
anything, with ``init: authenticated image settings: <error>``, and the
guards attached so far stay until the next reboot.

Order at run time
-----------------

The order in which programs run on one hook is the reverse of the order
in which they attached. The kernel's BPF trampoline puts a new program at
the head of the list, and for an LSM hook that returns a value, a
non-zero return ends the list. Where ``bpf2`` and ``seal`` share a hook
(``bprm_check_security``, ``file_open``, ``inode_unlink``,
``inode_rmdir``, ``inode_rename``, ``inode_setxattr``,
``inode_removexattr``, ``inode_mkdir``, ``inode_symlink``,
``inode_link``), the ``seal``
program runs first, and when it refuses, its errno and counter are the
ones the caller sees. A traced exec of a runtime file, for example, fails with
``EACCES`` from ``seal`` rather than ``EPERM`` from ``bpf2``.

The BPF LSM is one LSM among those the kernel runs. The kernel stops at
the first LSM that refuses, and each shirudo program returns an earlier
refusal unchanged. shirudo's verdicts can only add refusals to those of
SELinux, AppArmor, Smack or Yama; they never turn one of their refusals
into a permission.

Counters
--------

Most refusals increment a counter in ``shirudo_tamper``, a map
``init`` freezes against userspace writes and pins as ``tamper``.
``shirudo status`` reads it back. The counters, their meanings and what
an operator does about each are in :doc:`/security/tamper-counters`. The
table below names the counter of each refusal and says where a refusal
is not counted.

Hook reference
--------------

The programs of ``bpf2`` and those of ``seal`` have a table each.
"Authority" means runtime authority as above. The last column says
what the program does when it cannot decide: when a read fails, when
storage cannot be allocated, or when the record it needs is missing.

Hooks in bpf2
~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 22 44 16 18

   * - Hook
     - Refuses, and allows
     - Errno and counter
     - Cannot decide
   * - ``lsm/bpf``
     - With ``kernel`` false: a program load of another type than
       ``BPF_PROG_TYPE_SYSCALL``, or without a signature size, to every
       caller. Map create, update and freeze, test run, link create, raw
       tracepoint open, object pin, object get, map and link fd by id,
       to a task without authority. Every unclassified command to every
       caller. Allows every call with ``kernel`` true and the read-only
       commands: map lookups, ``GET_NEXT_ID``, ``PROG_GET_FD_BY_ID``,
       ``BTF_GET_FD_BY_ID``, ``OBJ_GET_INFO_BY_FD``, ``PROG_QUERY``,
       ``TASK_FD_QUERY``.
     - ``EACCES``: ``LoadNotLoader``, ``LoadUnsigned``,
       ``MapCreate``, ``MapWrite``, ``ProgRun``, ``ProgAttach``,
       ``ObjPin``, ``ObjGet``, ``BpfCommand``
     - Closed: unclassified commands are refused.
   * - ``lsm/bpf_prog_load``
     - A userspace load the kernel did not verify, verified against
       another keyring kind than ``.bpf``, or with a non-zero keyring
       serial other than the frozen one. Allows ``kernel`` true.
     - ``EACCES``: ``LoadUnverified``, ``LoadKeyringKind``,
       ``LoadKeyring`` (never reached: the kernel records serial 0 for
       ``.bpf``)
     - Closed: no frozen keyring serial refuses every load, uncounted.
   * - ``lsm/bpf_map``
     - Every map descriptor to a task without authority.
     - ``EACCES``: ``MapFdWrite`` (writable), ``ObjGet``
       (read-only)
     - Closed.
   * - ``lsm/bpf_prog``
     - An XDP program descriptor to a task without authority, including
       acquisition by program ID. Other program types stay allowed.
     - ``EACCES``: ``ObjGet``
     - Closed.
   * - ``lsm/file_open``
     - Opening a non-directory inode of the private bpffs, through any
       mount of it, to a task without authority. Records the bpffs mount
       when the bootstrap task opens its root. Opening a
       ``HibernateLocation`` EFI variable for writing, to every caller.
     - ``EACCES``: ``ObjGet``. ``EPERM`` for the EFI variable:
       ``HibernateLocation``
     - Closed.
   * - ``lsm/file_ioctl``, ``lsm/file_ioctl_compat``
     - ``PERF_EVENT_IOC_SET_BPF`` on any file,
       ``XFS_IOC_ATTRMULTI_BY_HANDLE`` on an XFS file system, which
       changes attributes past every xattr hook, and every device-mapper
       control command except ``DM_VERSION``, ``DM_LIST_DEVICES``,
       ``DM_DEV_STATUS``, ``DM_DEV_WAIT``, ``DM_TABLE_DEPS``,
       ``DM_TABLE_STATUS``, ``DM_LIST_VERSIONS`` and
       ``DM_GET_TARGET_VERSION`` on the control device (10:236), to a
       task without authority.
     - ``EACCES``: ``PerfAttach``, ``XattrHandle``. ``EPERM``
       for DM, uncounted
     - Closed: unknown DM commands are refused.
   * - ``lsm/inode_unlink``, ``lsm/inode_rmdir``, ``lsm/inode_mkdir``,
       ``lsm/inode_symlink``, ``lsm/inode_link``, ``lsm/inode_rename``,
       ``lsm/inode_setxattr``, ``lsm/inode_removexattr``
     - The operation in the private bpffs or the ``/run/shirudo`` tmpfs
       to a task without authority. Rename checks both directories.
       On any file system, unlink, rmdir and rename refuse such a task
       the mount point of the recorded bpffs mount or of a mount above
       it, which the kernel would detach or move in every namespace.
     - ``EPERM``. In the bpffs: ``PinUnlink``, ``PinEntry``
       (mkdir, symlink, link), ``PinRename``, ``PinXattr``. A mount
       point: ``BpffsUmountAbove``. Rmdir by a runtime task outside its
       grant counts as ``PinUnlink``.
     - On the private bpffs a runtime task also needs a per-task grant
       to unlink or remove an upatch directory or its children. The
       ioctl hooks issue and release the grant on the open directory.
       Removing that directory or committing an exec clears it.
       Renames are refused after bootstrap.
   * - ``lsm/sb_umount``
     - To every caller: unmounting the bpffs, an unmount whose subtree or
       propagation reaches the recorded bpffs mount, unmounting
       ``/run/shirudo``, unmounting the runtime image. Unmounting a
       config image to a task without authority.
     - ``EPERM``: ``BpffsUmount``, ``BpffsUmountAbove``; image
       and ``/run/shirudo`` refusals uncounted
     - Host PID 1 may detach the recorded initrd root once a matching
       bpffs mount survives on the target root. A walk beyond 1024
       mounts, 32 levels or 4 masters is refused.
   * - ``lsm/sb_pivotroot``
     - A pivot in the namespace containing the recorded bpffs. Host
       PID 1 may pivot from the recorded initrd root to the recorded
       target root.
     - ``EPERM`` and ``BpffsUmountAbove``.
     - A pivot in another mount namespace proceeds.
   * - ``lsm/move_mount``
     - To every caller: moving the bpffs, the ``/run/shirudo`` mount or
       the runtime image, or moving a mount onto the bpffs or the runtime
       image. Moving a mount onto a path in ``/run/shirudo``, and moving
       a config image or onto one, to a task without authority.
     - ``EPERM``: ``BpffsMount``; others uncounted
     - Closed.
   * - ``lsm/sb_mount``
     - A mount onto the bpffs or runtime image. A legacy propagation
       change on the bpffs or its ancestry, with the host PID 1
       exceptions for the initrd handoff and restoring shared mounts.
       A mount onto a
       path in ``/run/shirudo`` or on a config image to a task without
       authority. The source of a bind or legacy move is not checked.
     - ``EPERM``: ``BpffsMount``; others uncounted
     - Closed.
   * - ``lsm/sb_remount``
     - Remounting the bpffs, ``/run/shirudo`` or a recorded image, to
       every caller.
     - ``EPERM``: ``BpffsMount``; others uncounted
     - Closed.
   * - ``lsm.s/bdev_setintegrity``
     - Records a dm-verity device as runtime when its SHA-256 root equals
       the frozen runtime root, or as config when it equals the root an
       authorized task staged for this mapping; the staged root is used
       once. Refuses a second record for a recorded device, a root it
       cannot read, disk sequence 0 and a full record map.
     - ``EPERM``, ``EACCES``, ``ENOMEM``, uncounted
     - Other mappings get no record and so no authority.
   * - ``lsm/bdev_free_security``
     - Removes the device record.
     - None
     - The kernel can skip this call; lookups also compare the device
       number and disk sequence.
   * - ``lsm/key_permission``
     - Write, setattr, unlink, and search through an unpossessed
       reference, on the ``.bpf`` keyring, the ``.dm-verity`` keyring and
       its key, and the keys enrolled in ``.bpf``, to a task without
       authority. Allows view, read, link and possessed search, and every
       other key.
     - ``EACCES``: ``KeyringWrite``
     - Open before ``init`` records a keyring serial.
   * - ``lsm/tpm_command``
     - ``TPM2_NV_Extend`` of shirudo's NV index to a task without
       authority. A command shorter than 10 bytes, an ``NV_Extend``
       shorter than 18 bytes, or one it cannot read, to every caller.
       Allows every other command.
     - ``EACCES``: ``TpmExtend``
     - Closed for malformed commands.
   * - ``lsm/task_prctl``
     - ``PR_SET_MM`` with ``PR_SET_MM_EXE_FILE`` or ``PR_SET_MM_MAP`` to
       a task without authority. Answers the enforcement probe, option
       ``0x53520001``, with errno 1002.
     - ``EPERM``: ``ExeIdentity``
     - Closed.
   * - ``lsm/bprm_check_security``
     - Sets secure-exec for every exec of a runtime file, and refuses a
       traced one. The ``seal`` program on this hook runs first.
     - ``EPERM``: ``ExecTraced``
     - A file not recorded as runtime gets no secure-exec, and no mark.
   * - ``lsm/kernel_load_data``, ``lsm/kernel_read_file``
     - Every kexec kernel image and initramfs, by either system call, to
       every caller.
     - ``EPERM``: ``Kexec``
     - Unconditional.
   * - ``lsm/locked_down``
     - Every lockdown reason of integrity mode, an unsigned module
       included, and ``LOCKDOWN_KCORE``, to every caller.
     - ``EPERM``: the integrity counter of the reason;
       hibernation uncounted
     - Unconditional; the kernel's lockdown LSM decides first.

Hooks in seal
~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 22 44 16 18

   * - Hook
     - Refuses, and allows
     - Errno and counter
     - Cannot decide
   * - ``lsm.s/bprm_check_security``
     - Stages the mark candidate: trusted when the file is a direct, not
       overlay, inode on a recorded runtime device. Refuses a trusted
       candidate that is traced, shares its ``fs_struct`` with another
       process or has a seccomp filter.
     - ``EACCES``: ``ExecTraced``, ``ExecShared``;
       seccomp uncounted
     - Closed: no task storage refuses the exec with ``ENOMEM``.
   * - ``lsm.s/bprm_committed_creds``
     - Commits the staged candidate as the task's mark when an exec
       succeeds, and clears a revocation.
     - None
     - No task storage leaves the task without authority.
   * - ``lsm.s/bprm_creds_for_exec``, ``lsm.s/bprm_check_security``,
       ``lsm.s/bprm_committed_creds``
     - Seed with the task's committed bits, accumulate the original
       executable and each interpreter, then commit. An absent policy or
       a file system without xattrs contributes zero bits; a policy value
       other than 8 bytes, or one that cannot be read, refuses the exec.
     - ``EACCES``, uncounted
     - Failed exec leaves committed policy unchanged.
   * - ``lsm/socket_post_create``
     - Copies nonzero committed task policy bits into socket storage.
       ``BPF_F_CLONE`` carries listener storage to accepted sockets.
     - ``ENOMEM``, uncounted
     - No storage is needed when the task has no policy bits.
   * - ``lsm/task_alloc``
     - Copies a marked parent's mark, with its revocation, and any
       committed policy bits to the child.
     - ``ENOMEM``, uncounted
     - Closed: no storage for the mark or the bits refuses the fork.
   * - ``lsm/task_kill``
     - A signal other than 0 to a marked task from a task without
       authority. Let through, root may end a command that hangs and
       systemd stops the runs its timers start, and counted, so that a
       load stopped between its pins and its extend shows before the
       next command undoes what it left.
     - None; counts ``SealSignal``
     - Which signal is an attack: a stop by root and one by systemd
       count alike (R2). The kernel's own signals and the freezer pass
       no hook.
   * - ``lsm/task_setrlimit``
     - A change of a marked task's resource limits by another task
       without authority, ``prlimit``, which could have the kernel
       signal it. The task resets its own limits when it starts.
     - ``EPERM``: ``SealRlimit``
     - Closed.
   * - ``lsm/ptrace_access_check``
     - Every ptrace access mode against a marked task, which covers
       attach, ``/proc/<pid>/mem``, ``pidfd_getfd()``,
       ``process_vm_readv()`` and the read-mode ``/proc`` files such as
       ``exe``, ``environ`` and ``maps``.
     - ``EACCES``: ``SealPtrace``, attach mode only
     - Closed.
   * - ``lsm/mm_read_access``
     - A read-only access to a marked task's memory that
       ``mm_access()`` would grant ``CAP_PERFMON`` after the ptrace check
       refused it: ``environ``, ``maps``, ``smaps``, ``pagemap``.
     - ``EACCES``, uncounted
     - Closed, with carried patch 0024.
   * - ``lsm/perf_event_alloc``
     - A perf event bound to a marked task. CPU-wide events have no task
       and are not checked.
     - ``EACCES``: ``SealPerf``
     - Not applicable.
   * - ``lsm/mmap_file``
     - An executable mapping in a task with runtime authority, other
       than the bootstrap task, that is writable or does not come from a
       runtime file.
     - ``EACCES``, uncounted
     - Closed.
   * - ``lsm/file_mprotect``
     - In the same tasks: making an executable mapping writable, or making
       executable a mapping that was not, or that is not from a runtime
       file.
     - ``EACCES``, uncounted
     - Closed.
   * - ``lsm.s/file_open``
     - A write open of a labeled file to a task without authority. On a
       directory open, and on a read open by an authorized task, records
       or clears the mark from the label; a write open only records it.
     - ``EACCES``: ``SealWrite``
     - :ref:`The label verdict <seal-label-verdict>`.
   * - ``lsm.s/inode_unlink``, ``lsm.s/inode_rmdir``,
       ``lsm.s/inode_setattr``, ``lsm.s/inode_removexattr``
     - The operation on a labeled inode to a task without authority.
       Setattr covers truncate, chmod, chown and timestamps. Removing the
       seal or the policy label or the ancestor mark is refused on any
       inode without authority.
     - ``EACCES``: ``SealUnlink``, ``SealSetattr``,
       ``SealXattr``, ``SealLabel``
     - :ref:`The label verdict <seal-label-verdict>`.
   * - ``lsm.s/inode_set_acl``, ``lsm.s/inode_remove_acl``,
       ``lsm.s/inode_file_setattr``
     - A POSIX ACL change or a change of the inode flags (``chattr``) on
       a labeled inode to a task without authority.
     - ``EACCES``: ``SealXattr``, ``SealSetattr``
     - :ref:`The label verdict <seal-label-verdict>`.
   * - ``lsm.s/inode_setxattr``
     - Setting ``security.bpf.shirudo``,
       ``security.bpf.shirudo.policy`` or
       ``security.bpf.shirudo.ancestor`` on any inode, and any other name
       on a labeled inode, to a task without authority.
     - ``EACCES``: ``SealLabel``, ``SealXattr``
     - :ref:`The label verdict <seal-label-verdict>`.
   * - ``lsm.s/inode_rename``
     - A labeled source, a labeled destination directory or a labeled
       inode it would replace, or a source or replaced directory that
       carries the ancestor mark, to a task without authority.
     - ``EACCES``: ``SealRename``, ``SealEntry``
     - :ref:`The label verdict <seal-label-verdict>`.
   * - ``lsm.s/inode_create``, ``lsm.s/inode_mkdir``,
       ``lsm.s/inode_symlink``, ``lsm.s/inode_mknod``,
       ``lsm.s/inode_link``
     - A new entry in a labeled directory to a task without authority,
       read from the entry's parent dentry, and a hard link of a labeled
       inode anywhere. Each refreshes the directory's mark.
     - ``EACCES``: ``SealEntry``
     - :ref:`The label verdict <seal-label-verdict>`.
   * - ``lsm/inode_init_security``
     - Labels a new inode under a marked directory, inside the creation,
       and marks the new inode. Refuses the creation when it cannot add
       the label.
     - ``EACCES``, uncounted
     - Cannot read: the entry hook of the same operation refreshed the
       parent's mark from its label just before.
   * - ``lsm.s/inode_copy_up``
     - The overlay copy-up of a labeled inode, by anyone.
     - ``EPERM``: ``SealCopyUp``
     - As :ref:`the label verdict <seal-label-verdict>`, but a label,
       any other read error and a failure to allocate the scratch
       buffer refuse every caller.
   * - ``lsm.s/inode_post_setxattr``, ``lsm.s/inode_post_removexattr``
     - Refresh an inode's mark from its label after the change.
     - None
     - No label, or a label of another length, removes the mark; a
       failed read leaves it.

The label verdict the ``seal`` rows name is the table of
:ref:`seal-label-verdict`, which says what each result of a label read
decides and why.

Limits
------

The hooks decide only what reaches them. These paths do not:

- The ``kernel`` argument is true for every ``bpf()`` call through a
  kernel pointer, including BPF that kernel code loads with
  ``kern_sys_bpf()``, such as a light skeleton in a module.
- ``BPF_PROG_GET_FD_BY_ID`` stays open except for XDP descriptors,
  which ``lsm/bpf_prog`` guards. ``lsm/bpf`` and
  ``lsm/file_ioctl`` refuse the ``bpf()`` attach commands and the perf
  ioctl to tasks without authority; other kernel interfaces that take a
  program descriptor are not hooked here.
- On the pinned kernel, propagation changes through ``mount_setattr(2)``
  have no LSM hook. The source of a bind or legacy move is absent from
  ``lsm/sb_mount``.
- A perf event bound to a task before that task execs the runtime image
  survives the exec, and CPU-wide events and probes on the runtime
  binary are not checked.
- ``lsm/tpm_command`` sees commands written to ``/dev/tpm0`` and
  ``/dev/tpmrm0``. A TPM reached around the kernel's TPM character
  devices is outside it. The hook is not in bpf-next;
  :doc:`kernel-patches` describes the patch the test kernel carries.
- ``shirudo_roots`` and the inode marks are not frozen, by design.
  Device records are limited to 128.
- Several refusals are uncounted, as the table shows.

:doc:`seal` lists the gaps of the writable-state seal, and
:doc:`/security/threat-model` gives the residual risks.

Related
-------

- :doc:`/concepts/background/bpf-lsm` for how BPF LSM programs work
- :doc:`signed-loader` for the load path these hooks guard
- :doc:`/security/tamper-counters` for the counters
