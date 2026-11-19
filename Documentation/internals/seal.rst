..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: Kernel developers, security reviewers

Seal labels and task marks
==========================

shirudo keeps state that has to survive a reboot on a writable file
system, under ``/var/lib/shirudo``. This page explains how the ``seal``
BPF object keeps root from changing that state: labels that mark the
inodes to protect, task marks that say which processes may change them,
and the places where the mechanism stops.

Problem
-------

The archived upatches that boot restore loads, the eventlog, the package
and tree state, the image cache and the config activation journal cannot
live on a read-only image, because shirudo changes them. Several of them
are not signed: the activation journal, the tree cursor and the package
state decide what shirudo restores, skips or reports. Root can write any
file, so without more, root could edit them.

Why the obvious approaches fail
-------------------------------

File ownership and modes do not stop root. A check on the caller's user
ID or capabilities does not either, because the attacker is root.

A check on the caller's executable fails too. A path names whatever root
puts there. An inode identity can be copied around with an overlay,
replaced with ``PR_SET_MM_EXE_FILE``, or reached by a process that root
starts from that executable under a tracer or with a preloaded library.
A label on the caller's executable is a value root can copy onto any
binary.

We need two separate facts: which inodes are shirudo's, and which
processes run shirudo's code. Labels answer the first and task marks the
second, and a label never authorizes a caller.

.. _seal-task-marks:

Task marks
----------

A task mark is an entry in ``shirudo_tasks``, a task storage map that
both enforcement objects share. A task with a mark that a core dump or
a uprobe has not revoked has runtime authority, and every guard that
lets shirudo do what it refuses to others tests for it.

A mark is granted only by a successful exec from the authenticated
runtime image. ``lsm.s/bprm_check_security`` stages a candidate on each
binary handler pass and keeps the last one. The candidate is trusted
when all of these hold:

- the file is a direct inode, not an overlay copy: the real data inode
  the kernel reports for the file is the file's own inode;
- the inode is on a read-only superblock whose block device is recorded
  as the runtime device, with the same device number and disk sequence;
- the task is not traced;
- no other process shares the task's root and working directory;
- the task has no seccomp filter.

A traced exec of a runtime file is refused (``ExecTraced``), and so are
one by a task that shares its ``fs_struct`` with another process
(``ExecShared``), which exec does not unshare, and one with a seccomp
filter, because a tracer, the other process or a filter installed
before the exec would control the trusted process.

Figure 1 shows the states of a task's mark and what moves a task
between them. ``lsm.s/bprm_committed_creds`` commits the candidate when
an exec succeeds, so that every successful exec replaces the mark: a
runtime file gives a fresh one, any other file none. A failed exec
never reaches that hook and changes nothing. ``lsm/task_alloc`` gives
every child its parent's state.

.. figure:: /images/internals-task-authority.svg
   :alt: Four states: no mark, the bootstrap mark, an exec mark and a
         revoked mark. init in the initrd enters the bootstrap mark
         through a pidfd. From any state, a successful exec of a runtime
         file leads to an exec mark and an exec of any other file to no
         mark. From the bootstrap mark or an exec mark, the first
         authority check that finds a core dump or a uprobe leads to
         revoked. A failed or refused exec keeps the state, and a fork
         copies it to the child.

   Figure 1. A task's runtime authority. The bootstrap and exec marks
   carry authority, a revoked mark does not, and every marked state is
   protected from other tasks.

A task that dumps core keeps its mark but loses its authority. An exec
can still fail after ``bprm_committed_creds`` has committed the mark,
when the new stack cannot take the argument pointers, and the task then
dies by ``SIGSEGV`` and dumps core before the new program has run a
single instruction. The kernel's dump code runs as the task: it unlinks
the file ``kernel.core_pattern`` names, root's choice, and creates it
anew. The revocation is counted as ``SealCoreDump``, and the operation
that finds it is refused as it is for any task without authority. The
mark stays, so the protections below still keep other tasks off the
dumping task.

A task whose memory a uprobe reaches loses its authority the same way,
counted as ``SealUprobe``. Root sets a uprobe on any file it can name,
the runtime binary included, through ``uprobe_events`` in tracefs or a
perf event on the ``uprobe`` PMU, and no LSM hook sees either. A probe
can carry a reference counter, a 16-bit value at a file offset of the
probed binary, and the kernel adds one to it in every process that maps
the binary writable at that offset, at every exec and every
registration: a probe placed on the binary's data changes the variables
shirudo reads before ``main()`` runs. The kernel sets
``MMF_HAS_UPROBES`` in the memory of a process before it installs a
probe there, and the check of authority reads that flag. The kernel
installs probes in every mapping of a probed file that could be
executable, so shirudo reads the binaries uprobe upatches target with
``pread()`` rather than mapping them: the static runtime binary maps no
file but itself, and the flag in its memory means a probe on it.

Policy bits
-----------

An executable may carry ``security.bpf.shirudo.policy``, an 8-byte native
``__u64`` bitset. During exec, ``bprm_check_security`` ORs the bitsets
from the original file and each interpreter into a task-local candidate
in ``shirudo_task_policy``. ``bprm_committed_creds`` commits that value only after
exec succeeds. The candidate starts with the task's committed bits, so
policy accumulates across execs as well as interpreter handlers. A failed
exec leaves the committed value unchanged. A fork or clone inherits the
committed bits. The xattr remains on the inode. Only a task with runtime
authority may set, update or remove it. An absent policy or a file system
without xattrs contributes zero bits; invalid lengths and other read
errors refuse the exec.

``socket_post_create`` snapshots a task's committed bits into
``shirudo_sock_policy`` when it creates a socket. A socket with no policy
uses no storage and reads as zero. If nonzero policy storage cannot be
allocated, socket creation fails. The map uses ``BPF_F_CLONE`` so an
accepted socket inherits the listener's snapshot, even when the task
calling ``accept()`` has since accumulated other bits.

The device record that the exec check consults comes from
``lsm.s/bdev_setintegrity``: it records a dm-verity device as runtime
when its root hash equals the runtime root the UKI authenticated, which
``init`` froze in the identity map. :doc:`config-images` explains the
images.

Every executable on the runtime image is equally eligible. The image
holds the ``shirudo`` binary, its loader and libraries when it is linked
dynamically, and any ``--extra-binary`` the operator added; each extra
binary is a further holder of runtime authority.

Bootstrap seed
~~~~~~~~~~~~~~

``init`` in the initrd runs before any runtime image is recorded, so it
cannot have earned a mark by exec. Before it freezes ``shirudo_tasks``,
it writes a bootstrap mark for its own process through a pidfd. The
bootstrap mark has the same authority as an exec mark. It is also exempt
from the executable-memory checks of ``lsm/mmap_file`` and
``lsm/file_mprotect``, because the initrd binary is not on the runtime
image. The seed lives as long as that process and the children it forks;
the root file system's ``init`` runs from the runtime image and earns its
mark by exec.

Protecting marked tasks
~~~~~~~~~~~~~~~~~~~~~~~

A mark is only worth as much as the integrity of the process that holds
it. ``lsm/ptrace_access_check`` refuses every ptrace access to a marked
task. It counts one whose mode includes ``PTRACE_MODE_ATTACH``
(``SealPtrace``), which covers attach, ``/proc/<pid>/mem``,
``pidfd_getfd()`` and ``process_vm_readv()``, and refuses a read-mode
one uncounted, because journald reads ``/proc/<pid>/exe`` of every
process it logs for and a counted read would rise on an honest node.
``lsm/mm_read_access``, a hook of carried patch 0005, refuses the
read-only access ``mm_access()`` grants ``CAP_PERFMON`` after that
refusal, to ``environ``, ``maps`` and the other memory files. ``lsm/perf_event_alloc``
refuses a perf event bound to a marked task (``SealPerf``).
``lsm/task_kill`` lets a signal to a marked task through, since root
may end a command that hangs and systemd stops the runs its timers
start, and counts one from a task without authority (``SealSignal``),
so that a command stopped on purpose shows in the counters. The
kernel's own signals pass no hook: those a file size or CPU time limit
or an interval timer raise, the command forestalls by resetting its
limits and disarming the timers it inherited when it starts, and
``lsm/task_setrlimit`` refuses another task a change of its limits
(``SealRlimit``). ``SIGKILL`` from ``cgroup.kill`` or the OOM killer,
``SIGPIPE`` and the cgroup freezer stay uncounted.
``lsm/mmap_file`` and ``lsm/file_mprotect`` refuse a task with runtime
authority executable memory that is writable or that does not come
from the runtime image. ``bpf2`` makes every exec of a runtime file a
secure-exec, so the dynamic loader ignores ``LD_PRELOAD`` and its kin,
and refuses ``PR_SET_MM_EXE_FILE`` and ``PR_SET_MM_MAP`` to tasks
without authority.

Labels
------

A label is the extended attribute ``security.bpf.shirudo`` on an inode
under ``/var/lib/shirudo``. Its value is a fixed 64-character string, the
SHA-256 of the attribute name, the same on every target. The value is
public and carries no authority. The seal treats an inode that has the
attribute, with any value, as protected.

The first ``init`` labels the tree. When ``/var/lib/shirudo`` itself has
no label and enforcement is not yet attached, ``init`` labels every
regular file and directory on that file system under it. After that,
shirudo labels each inode as it creates it, and ``init`` never labels an
entry again: an unlabeled entry, or an entry of a kind shirudo never
makes, is someone else's and is logged and ignored. With enforcement
attached, ``init`` refuses a state root without a label, because that is
a tree bound over the path rather than the one it sealed.

``init`` also labels ``/run/shirudo``, so that the init record it leaves
there for the root file system is sealed from its creation, and
``/run/shirudo-java``, the one sealed directory every user may read,
which holds the jars of the Java upatches. The runtime
and config images carry no labels; dm-verity protects them.

What the seal checks
--------------------

For a labeled inode, these operations need runtime authority:

- a write open (``SealWrite``);
- unlink, or the removal of a directory (``SealUnlink``);
- rename of it, or rename over it (``SealRename``);
- truncate, chmod, chown and timestamp changes through
  ``inode_setattr``, and a change of the inode flags with ``chattr``
  through ``inode_file_setattr`` (``SealSetattr``);
- setting or removing any extended attribute or POSIX ACL
  (``SealXattr``).

Setting or removing the attribute ``security.bpf.shirudo`` itself, or
``security.bpf.shirudo.policy``, needs runtime authority on every inode,
labeled or not (``SealLabel``), so root cannot label an inode of its own
as shirudo's.

The directories above the state root are not labeled, since root makes
entries in ``/var/lib`` freely, but renaming one would move the sealed
tree aside, and the next boot's bootstrap run would label whatever root
put at ``/var/lib/shirudo``. That run marks each of them, up to the root
of the state's file system, with ``security.bpf.shirudo.ancestor``, and
a rename of a marked directory, or over one, needs runtime authority
(``SealRename``), as does setting or removing the mark (``SealLabel``).

A labeled directory takes new entries only from a task with runtime
authority: ``inode_create``, ``inode_mkdir``, ``inode_symlink``,
``inode_mknod``, ``inode_link`` and a rename into it (``SealEntry``).
Each of these hooks reads the directory's label from the new entry's
parent dentry. A label stops writes to an inode, but a rename or a hard
link brings an inode in with its contents, and a symbolic link sends
whoever follows it elsewhere. A hard link of a labeled inode is refused
anywhere to the same tasks (``SealEntry``), so a sealed inode keeps its
label where shirudo put it. ``inode_copy_up`` refuses the overlay
copy-up of a labeled inode to every caller (``SealCopyUp``): a write
through an overlay mounted over sealed state would otherwise land in the
upper directory and leave the sealed inode as it was.

.. _seal-label-verdict:

Reading the label
~~~~~~~~~~~~~~~~~

The seal reads the label with the ``bpf_get_file_xattr()`` and
``bpf_get_dentry_xattr()`` kfuncs. With the carried kernel patch they
return a ``security.bpf.`` label as the in-kernel LSMs read theirs,
without the calling task's permission. Upstream they first check that
the calling task may read the inode, against its raw ids, and root can
make any label unreadable to a caller that may still write: through an
idmapped bind mount or an ACL, and then acting at a file system uid
that cannot read. A seal that refused every operation whose label read
failed would refuse every write-only open and every unlink of a file the
caller cannot read, on every file system; one that let every failed
read through would let root shed every label.

The table gives the verdict of each read result, ``seal_verdict()`` in
:src:`bpf/seal.c`. Every hook that decides on a label uses it.

.. list-table::
   :header-rows: 1
   :widths: 24 34 42

   * - Read result
     - Verdict
     - Why
   * - A label, of any length
     - Labeled: the operation needs runtime authority.
     - The inode is shirudo's; the value carries no meaning.
   * - ``ENODATA``, ``EOPNOTSUPP``
     - Unlabeled: the operation goes ahead.
     - No label, or a file system without security extended attributes.
   * - ``EACCES``, ``EPERM``
     - Labeled when the inode, or the directory the operation changes,
       carries a mark; otherwise unlabeled.
     - The read failed for the caller, which upstream root can arrange.
       The mark remembers a label the seal read before. With the carried
       patch these errors do not occur.
   * - Any other error, or no scratch buffer for the read
     - Labeled: the operation needs runtime authority.
     - A read that fails for another reason does not show that the
       inode is unlabeled.

Three checks differ. Setting or removing the label, the policy label or
the ancestor mark needs runtime authority whatever the read says
(``SealLabel``). The ancestor mark lets a rename through only on
``ENODATA`` or ``EOPNOTSUPP``. ``inode_copy_up`` refuses every caller,
with or without authority, where the table requires authority.

Labeling at creation
---------------------

A file shirudo creates must carry its label from the moment it exists;
a window in which it has none is a window in which the seal does not
protect it. ``lsm/inode_init_security`` runs inside the file system's
creation transaction and gives the new inode its parent's label with
``bpf_inode_init_xattr()``. If it cannot add the label, it refuses the
creation: no inode is better than one of shirudo's without its label.

That hook cannot sleep, so it cannot read the parent's extended
attribute. It uses a cached mark instead: ``seal_dir_marks``, inode
storage that records an inode's label, on files and directories alike.
The table gives every event that sets or clears a mark and what each
result of its label read does. A label of another length than the
seal's counts as no label here.

.. list-table::
   :header-rows: 1
   :widths: 30 25 15 15 15

   * - Event
     - Hook
     - Label read
     - No label
     - Read fails
   * - A directory opened, by any task
     - ``lsm.s/file_open``
     - marks
     - clears
     - keeps
   * - A file opened for reading by a task with authority
     - ``lsm.s/file_open``
     - marks
     - clears
     - keeps
   * - A file opened for writing, by any task
     - ``lsm.s/file_open``
     - marks
     - keeps
     - keeps
   * - An entry made in a directory, by any task: the directory
     - ``lsm.s/inode_create`` and the other entry hooks
     - marks
     - clears
     - keeps
   * - An extended attribute set or removed, by any task
     - ``lsm.s/inode_post_setxattr``, ``lsm.s/inode_post_removexattr``
     - marks
     - clears
     - keeps
   * - An inode created under a marked directory
     - ``lsm/inode_init_security``
     - marks, with the label it adds
     - not reached
     - not reached

A read open by a task without authority, and the hooks that only decide,
leave marks alone.

shirudo's writers keep the mark in place. They open the parent directory
and create files relative to that descriptor, which holds the inode in
memory for the duration, and they set the label from userspace as well
when the kernel could not. After the seal attaches, ``init`` walks the
state tree once more; the walk opens every directory and fills the marks.

shirudo's readers do not trust an entry because it is there. They open
each path component without following symbolic links and require every
entry under a labeled directory to carry its parent's label; anything
else is reported as a foreign entry and refused. A path a caller names
for shirudo to write, such as ``--report`` or ``--output``, must be an
unlabeled regular file outside any labeled directory, so a task with
runtime authority cannot be pointed at sealed state.

Limits
------

These are properties of the mechanism as it is. The
:doc:`/security/threat-model` states their consequences.

Marks are a cache
    A mark is a cache of a label the seal read. When the kernel evicts
    an inode, under memory pressure or through ``vm.drop_caches``, its
    mark goes with it, and nothing opens: every hook that decides reads
    the label, and the entry hooks read the directory's from the new
    entry's parent dentry and refresh its mark on the way, which
    ``inode_init_security``, the one hook without a dentry, labels the
    new inode from in the same operation. On a kernel without the
    carried patches 0003 and 0004, the seal's entry hooks do not load
    and ``init`` fails.

Label reads on an upstream kernel
    Without the carried xattr patch, the kfuncs check that the calling
    task may read the inode, and every LSM's ``inode_permission`` hook
    takes part. A read that fails for the caller, through an idmapped
    mount, an ACL or another LSM's policy, makes a labeled inode
    without a mark look unlabeled to the seal; a marked one is refused,
    and the same failure on an open leaves the mark. The policy label
    read at exec fails the same way for a caller that may run a file
    but not read it, such as an unprivileged user running a ``--x``
    binary, and the exec is refused: a policy that cannot be read is
    not taken for none, since root could make the read fail to shed
    the bits.

Bind mounts
    No mount guard covers the state file system, and shirudo's opens
    follow mount points. A bind mount over a sealed path makes shirudo
    read and write what lies under the mount.

Existing descriptors
    The seal checks operations when they start. A descriptor opened for
    writing, or a writable mapping, that exists before a file is
    labeled keeps working; the seal revokes nothing.

Below the file system
    The hooks see VFS operations. Writes to the block device under the
    file system, or to the disk while the target is down, do not pass
    through them. Across a reboot, signatures and the measurement
    register protect what matters, not the seal.

Related
-------

- :doc:`/concepts/background/xattrs` for extended attributes and the
  ``security.bpf.`` namespace
- :doc:`enforcement` for every hook and its counter
- :doc:`/security/tamper-counters` for the ``Seal*`` counters
