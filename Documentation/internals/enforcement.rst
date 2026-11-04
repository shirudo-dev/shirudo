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

The objects share seven maps, which ``init`` hands from ``bpf2`` to
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
       and of ``/run/shirudo``, the runtime root hash, the ``.bpf``
       keyring serial and kind, the serials of the enrolled keys, the
       ``.dm-verity`` keyring and key serials, the NV index, the NV
       writer's public modulus and seed, the attestation key name and
       the ECC endorsement key name used to salt authenticated sessions.
   * - ``shirudo_tasks``
     - ``task_authority``
     - Task storage with each task's mark and exec candidate.
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

``init`` freezes every one of them against userspace writes except
``shirudo_roots``, which an authorized task writes before each config
mapping. ``bpf2`` also keeps ``shirudo_mnt_rec`` for the bpffs
mount it records, and ``seal`` keeps its scratch buffer and the inode
storage of directory marks.

Telling shirudo from root
-------------------------

Every guard that allows shirudo what it refuses to everyone else asks one
question: does the calling task have runtime authority? A task has it
when it carries a mark in ``shirudo_tasks``. A task gets the mark by a
successful exec of a file on the authenticated runtime image, or, for the
``init`` process in the initrd, from a seed ``init`` writes before it
freezes the map. A fork inherits the mark. :doc:`seal` explains how the
mark is granted and cleared.

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
    listable. ``BPF_PROG_GET_FD_BY_ID`` and ``BPF_BTF_GET_FD_BY_ID`` stay
    allowed. Root without runtime authority therefore cannot read
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
    authority. ``seal`` refuses a marked task executable memory that does
    not come from the runtime image.

Kexec
    A kexec hands the machine to a kernel and initrd of the caller's
    choosing with the TPM as it is, so the evidence of this boot would
    vouch for whatever runs after. ``lsm/kernel_load_data`` and
    ``lsm/kernel_read_file`` refuse every kexec image and initramfs to
    every caller.

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
   ``shirudo_task_policy`` and ``shirudo_sock_policy``, and pin them
   with ``shirudo_roots``. Pin the identity map.
#. Attach ``task_prctl``, ``bprm_check_security``, ``inode_rmdir``,
   ``inode_rename``, ``inode_mkdir``, ``inode_symlink``, ``inode_link``,
   ``kernel_load_data`` and ``kernel_read_file``.
#. Attach ``file_ioctl``, ``file_ioctl_compat``, ``bdev_setintegrity``
   and ``bdev_free_security``.
#. Attach ``inode_unlink``, ``inode_setxattr``, ``inode_removexattr``,
   ``key_permission`` and ``tpm_command``.
#. Attach the mount guards ``sb_umount``, ``move_mount``, ``sb_mount``,
   ``sb_remount`` and the ``file_open`` recorder, open the bpffs root so
   the recorder notes the mount, and freeze that record.
#. Load ``seal`` on the shared maps, freeze its scratch map, and attach
   its twenty-seven hooks, then ``mmap_file`` and ``file_mprotect``.
#. Attach ``lsm/bpf_map``, then ``lsm/bpf_prog_load``, then ``lsm/bpf``.

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
the map pins, so no partial enforcement survives a failed ``init``.

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

``bpf2`` and ``seal`` name the object. "Authority" means runtime
authority as above. The last column says what the program does when it
cannot decide: when a read fails, when storage cannot be allocated, or
when the record it needs is missing.

.. list-table::
   :header-rows: 1
   :widths: 17 37 8 18 20

   * - Hook
     - Refuses, and allows
     - Errno
     - Counter
     - Cannot decide
   * - ``lsm/bpf`` (``bpf2``)
     - With ``kernel`` false: a program load of another type than
       ``BPF_PROG_TYPE_SYSCALL``, or without a signature size, to every
       caller. Map create, update and freeze, test run, link create, raw
       tracepoint open, object pin, object get, map and link fd by id,
       to a task without authority. Every unclassified command to every
       caller. Allows every call with ``kernel`` true and the read-only
       commands: map lookups, ``GET_NEXT_ID``, ``PROG_GET_FD_BY_ID``,
       ``BTF_GET_FD_BY_ID``, ``OBJ_GET_INFO_BY_FD``, ``PROG_QUERY``,
       ``TASK_FD_QUERY``.
     - ``EACCES``
     - ``LoadNotLoader``, ``LoadUnsigned``, ``MapCreate``, ``MapWrite``,
       ``ProgRun``, ``ProgAttach``, ``ObjPin``, ``ObjGet``,
       ``BpfCommand``
     - Closed: unclassified commands are refused.
   * - ``lsm/bpf_prog_load`` (``bpf2``)
     - A userspace load the kernel did not verify, verified against
       another keyring kind than ``.bpf``, or with a non-zero keyring
       serial other than the frozen one. Allows ``kernel`` true.
     - ``EACCES``
     - ``LoadUnverified``, ``LoadKeyringKind``, ``LoadKeyring`` (never
       reached: the kernel records serial 0 for ``.bpf``)
     - Closed: no frozen keyring serial refuses every load, uncounted.
   * - ``lsm/bpf_map`` (``bpf2``)
     - Every map descriptor to a task without authority.
     - ``EACCES``
     - ``MapFdWrite`` (writable), ``ObjGet`` (read-only)
     - Closed.
   * - ``lsm/file_open`` (``bpf2``)
     - Opening a non-directory inode of the private bpffs, through any
       mount of it, to a task without authority. Records the bpffs mount
       when the bootstrap task opens its root.
     - ``EACCES``
     - ``ObjGet``
     - Closed.
   * - ``lsm/file_ioctl``, ``lsm/file_ioctl_compat`` (``bpf2``)
     - ``PERF_EVENT_IOC_SET_BPF`` on any file, and every device-mapper
       control command except ``DM_VERSION``, ``DM_LIST_DEVICES``,
       ``DM_DEV_STATUS``, ``DM_DEV_WAIT``, ``DM_TABLE_DEPS``,
       ``DM_TABLE_STATUS``, ``DM_LIST_VERSIONS`` and
       ``DM_GET_TARGET_VERSION`` on the control device (10:236), to a
       task without authority.
     - ``EACCES`` (perf), ``EPERM`` (DM)
     - ``PerfAttach``; DM refusals uncounted
     - Closed: unknown DM commands are refused.
   * - ``lsm/inode_unlink``, ``lsm/inode_rmdir``, ``lsm/inode_mkdir``,
       ``lsm/inode_symlink``, ``lsm/inode_link``, ``lsm/inode_rename``,
       ``lsm/inode_setxattr``, ``lsm/inode_removexattr`` (``bpf2``)
     - The operation in the private bpffs or the ``/run/shirudo`` tmpfs
       to a task without authority. Rename checks both directories.
       Other file systems are not checked.
     - ``EPERM``
     - In the bpffs: ``PinUnlink``, ``PinEntry`` (mkdir, symlink, link),
       ``PinRename``, ``PinXattr``. Rmdir and ``/run/shirudo`` refusals
       uncounted.
     - Closed for those two file systems.
   * - ``lsm/sb_umount`` (``bpf2``)
     - To every caller: unmounting the bpffs, an unmount whose subtree or
       propagation reaches the recorded bpffs mount, unmounting
       ``/run/shirudo``, unmounting the runtime image. Unmounting a
       config image to a task without authority.
     - ``EPERM``
     - ``BpffsUmount``, ``BpffsUmountAbove``; image and ``/run/shirudo``
       refusals uncounted
     - Closed: a walk beyond 1024 mounts, 32 levels or 4 masters is
       refused.
   * - ``lsm/move_mount`` (``bpf2``)
     - To every caller: moving the bpffs, the ``/run/shirudo`` mount or
       the runtime image, or moving a mount onto the bpffs or the runtime
       image. Moving a mount onto a path in ``/run/shirudo``, and moving
       a config image or onto one, to a task without authority.
     - ``EPERM``
     - ``BpffsMount``; others uncounted
     - Closed.
   * - ``lsm/sb_mount`` (``bpf2``)
     - To every caller: a mount onto the bpffs or the runtime image, and
       a propagation change of the ``/run/shirudo`` mount. A mount onto a
       path in ``/run/shirudo`` or on a config image to a task without
       authority. The source of a bind or legacy move is not checked.
     - ``EPERM``
     - ``BpffsMount``; others uncounted
     - Closed.
   * - ``lsm/sb_remount`` (``bpf2``)
     - Remounting the bpffs, ``/run/shirudo`` or a recorded image, to
       every caller.
     - ``EPERM``
     - ``BpffsMount``; others uncounted
     - Closed.
   * - ``lsm.s/bdev_setintegrity`` (``bpf2``)
     - Records a dm-verity device as runtime when its SHA-256 root equals
       the frozen runtime root, or as config when it equals the root an
       authorized task staged for this mapping; the staged root is used
       once. Refuses a second record for a recorded device, a root it
       cannot read, disk sequence 0 and a full record map.
     - ``EPERM``, ``EACCES``, ``ENOMEM``
     - Uncounted
     - Other mappings get no record and so no authority.
   * - ``lsm/bdev_free_security`` (``bpf2``)
     - Removes the device record.
     - None
     - None
     - The kernel can skip this call; lookups also compare the device
       number and disk sequence.
   * - ``lsm/key_permission`` (``bpf2``)
     - Write, setattr, unlink, and search through an unpossessed
       reference, on the ``.bpf`` keyring, the ``.dm-verity`` keyring and
       its key, and the keys enrolled in ``.bpf``, to a task without
       authority. Allows view, read, link and possessed search, and every
       other key.
     - ``EACCES``
     - ``KeyringWrite``
     - Open before ``init`` records a keyring serial.
   * - ``lsm/tpm_command`` (``bpf2``)
     - ``TPM2_NV_Extend`` of shirudo's NV index to a task without
       authority. A command shorter than 10 bytes, an ``NV_Extend``
       shorter than 18 bytes, or one it cannot read, to every caller.
       Allows every other command.
     - ``EACCES``
     - ``TpmExtend``
     - Closed for malformed commands.
   * - ``lsm/task_prctl`` (``bpf2``)
     - ``PR_SET_MM`` with ``PR_SET_MM_EXE_FILE`` or ``PR_SET_MM_MAP`` to
       a task without authority. Answers the enforcement probe, option
       ``0x53520001``, with errno 1002.
     - ``EPERM``
     - ``ExeIdentity``
     - Closed.
   * - ``lsm/bprm_check_security`` (``bpf2``)
     - Sets secure-exec for every exec of a runtime file, and refuses a
       traced one. The ``seal`` program on this hook runs first.
     - ``EPERM``
     - ``ExecTraced``
     - A file not recorded as runtime gets no secure-exec, and no mark.
   * - ``lsm.s/bprm_check_security`` (``seal``)
     - Stages the mark candidate: trusted when the file is a direct, not
       overlay, inode on a recorded runtime device. Refuses a trusted
       candidate that is traced or has a seccomp filter.
     - ``EACCES``
     - ``ExecTraced``; seccomp uncounted
     - Closed: no task storage refuses the exec with ``ENOMEM``.
   * - ``lsm.s/bprm_committed_creds`` (``seal``)
     - Commits the staged candidate as the task's mark when an exec
       succeeds.
     - None
     - None
     - No task storage leaves the task without authority.
   * - ``lsm.s/bprm_creds_for_exec``, ``lsm.s/bprm_check_security``,
       ``lsm.s/bprm_committed_creds`` (``seal``)
     - Seed with the task's committed bits, accumulate the original
       executable and each interpreter, then commit. An absent policy or
       a file system without xattrs contributes zero bits; a malformed
       or unreadable policy xattr refuses exec.
     - ``EACCES``
     - Uncounted
     - Failed exec leaves committed policy unchanged.
   * - ``lsm/socket_post_create`` (``seal``)
     - Copies nonzero committed task policy bits into socket storage.
       ``BPF_F_CLONE`` carries listener storage to accepted sockets.
     - ``ENOMEM``
     - None
     - No storage is needed when the task has no policy bits.
   * - ``lsm/task_alloc`` (``seal``)
     - Copies a marked parent's mark and any committed policy bits to the
       child.
     - ``ENOMEM``
     - None
     - Closed: no storage refuses the fork of a marked parent.
   * - ``lsm/task_kill`` (``seal``)
     - A signal other than 0 to a marked task from a task without
       authority. Let through, root may end a command that hangs and
       systemd stops the runs its timers start, and counted, so that a
       load stopped between its pins and its extend shows before the
       next command undoes what it left.
     - None
     - ``SealSignal``
     - Which signal is an attack: a stop by root and one by systemd
       count alike (R2).
   * - ``lsm/ptrace_access_check`` (``seal``)
     - Every ptrace access mode against a marked task, which covers
       attach, ``/proc/<pid>/mem``, ``pidfd_getfd()`` and
       ``process_vm_readv()``.
     - ``EACCES``
     - ``SealPtrace``
     - Closed.
   * - ``lsm/perf_event_alloc`` (``seal``)
     - A perf event bound to a marked task. CPU-wide events have no task
       and are not checked.
     - ``EACCES``
     - ``SealPerf``
     - Not applicable.
   * - ``lsm/mmap_file`` (``seal``)
     - An executable mapping in a marked task, other than the bootstrap
       task, that is writable or does not come from a runtime file.
     - ``EACCES``
     - Uncounted
     - Closed.
   * - ``lsm/file_mprotect`` (``seal``)
     - In the same tasks: making an executable mapping writable, or making
       executable a mapping that was not, or that is not from a runtime
       file.
     - ``EACCES``
     - Uncounted
     - Closed.
   * - ``lsm/kernel_load_data``, ``lsm/kernel_read_file`` (``bpf2``)
     - Every kexec kernel image and initramfs, by either system call, to
       every caller.
     - ``EPERM``
     - ``Kexec``
     - Unconditional.
   * - ``lsm.s/file_open`` (``seal``)
     - A write open of a labeled file to a task without authority. On a
       directory open, and on any open by an authorized task, records or
       clears the mark from the label; a write open records it.
     - ``EACCES``
     - ``SealWrite``
     - See the label verdict below.
   * - ``lsm.s/inode_unlink``, ``lsm.s/inode_rmdir``,
       ``lsm.s/inode_setattr``, ``lsm.s/inode_removexattr`` (``seal``)
     - The operation on a labeled inode to a task without authority.
       Setattr covers truncate, chmod, chown and timestamps. Removing the
       seal or the policy label is refused on any inode without
       authority.
     - ``EACCES``
     - ``SealUnlink``, ``SealSetattr``, ``SealXattr``, ``SealLabel``
     - See the label verdict below.
   * - ``lsm.s/inode_set_acl``, ``lsm.s/inode_remove_acl``,
       ``lsm.s/inode_file_setattr`` (``seal``)
     - A POSIX ACL change or a change of the inode flags (``chattr``) on
       a labeled inode to a task without authority.
     - ``EACCES``
     - ``SealXattr``, ``SealSetattr``
     - See the label verdict below.
   * - ``lsm.s/inode_setxattr`` (``seal``)
     - Setting ``security.bpf.shirudo`` or
       ``security.bpf.shirudo.policy`` on any inode, and any other name
       on a labeled inode, to a task without authority. Policy values
       must be exactly 8 bytes.
     - ``EACCES``
     - ``SealLabel``, ``SealXattr``
     - See the label verdict below.
   * - ``lsm.s/inode_rename`` (``seal``)
     - A labeled source, a labeled destination directory or a labeled
       inode it would replace, to a task without authority.
     - ``EACCES``
     - ``SealRename``, ``SealEntry``
     - See the label verdict below.
   * - ``lsm.s/inode_create``, ``lsm.s/inode_mkdir``,
       ``lsm.s/inode_symlink``, ``lsm.s/inode_mknod``,
       ``lsm.s/inode_link`` (``seal``)
     - A new entry in a labeled directory to a task without authority,
       read from the entry's parent dentry, and a hard link of a labeled
       inode anywhere. Each refreshes the directory's mark.
     - ``EACCES``
     - ``SealEntry``
     - See the label verdict below.
   * - ``lsm/inode_init_security`` (``seal``)
     - Labels a new inode under a marked directory, inside the creation,
       and marks the new inode. Refuses the creation when it cannot add
       the label.
     - ``EACCES``
     - Uncounted
     - Cannot read: the entry hook of the same operation refreshed the
       parent's mark from its label just before.
   * - ``lsm.s/inode_copy_up`` (``seal``)
     - The overlay copy-up of a labeled inode, by anyone.
     - ``EPERM``
     - ``SealCopyUp``
     - As the label verdict below, but a label, any other read error
       and a failure to allocate the scratch buffer refuse every caller.
   * - ``lsm.s/inode_post_setxattr``, ``lsm.s/inode_post_removexattr``
       (``seal``)
     - Refresh an inode's mark from its label after the change.
     - None
     - None
     - No label removes the mark; a failed read leaves it.

The label verdict of the ``seal`` hooks reads ``security.bpf.shirudo``
with the xattr kfuncs, which with the carried patch 0002 return it
without the calling task's permission and upstream check that
permission first. No label (``ENODATA``) and no security
extended attributes on the file system (``EOPNOTSUPP``) count as
unlabeled, and the operation goes ahead. A label the caller may not
read (``EACCES``, ``EPERM``) counts as unlabeled unless the inode, or
the directory the operation changes, carries a mark, which requires
runtime authority. A label of any length, any other read error and a
failure to allocate the scratch buffer require runtime authority.
:doc:`seal` explains why and what follows from it.

Limits
------

The hooks decide only what reaches them. These paths do not:

- The ``kernel`` argument is true for every ``bpf()`` call through a
  kernel pointer, including BPF that kernel code loads with
  ``kern_sys_bpf()``, such as a light skeleton in a module.
- ``BPF_PROG_GET_FD_BY_ID`` stays open. ``lsm/bpf`` and
  ``lsm/file_ioctl`` refuse the ``bpf()`` attach commands and the perf
  ioctl to tasks without authority; other kernel interfaces that take a
  program descriptor are not hooked here.
- ``mount_setattr(2)`` has no LSM hook, ``pivot_root(2)`` is not hooked,
  and ``lsm/sb_mount`` does not check the source of a bind or legacy
  move.
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
