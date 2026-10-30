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

Task marks
----------

A task mark is an entry in ``shirudo_tasks``, a task storage map that
both enforcement objects share. A task with a mark has runtime
authority, and every guard that lets shirudo do what it refuses to
others tests for it.

A mark is granted only by a successful exec from the authenticated
runtime image. ``lsm.s/bprm_check_security`` stages a candidate on each
binary handler pass and keeps the last one. The candidate is trusted
when all of these hold:

- the file is a direct inode, not an overlay copy: the real data inode
  the kernel reports for the file is the file's own inode;
- the inode is on a read-only superblock whose block device is recorded
  as the runtime device, with the same device number and disk sequence;
- the task is not traced;
- the task has no seccomp filter.

A traced exec of a runtime file is refused (``ExecTraced``), and so is
one with a seccomp filter, because a tracer or a filter installed before
the exec would control the trusted process. ``lsm.s/bprm_committed_creds``
commits the candidate when the exec succeeds. A failed exec never reaches
that hook and leaves the existing mark alone. A successful exec of a file
that is not on the runtime image commits an untrusted candidate and so
clears the mark. ``lsm/task_alloc`` copies a parent's mark to every
child.

Policy bits
-----------

An executable may carry ``security.bpf.shirudo.policy``, an 8-byte native
``__u64`` bitset. During exec, ``bprm_check_security`` ORs the bitsets
from the original file and each interpreter into a task-local candidate
in ``policy_map``. ``bprm_committed_creds`` commits that value only after
exec succeeds; a successful exec with no policy bits clears the previous
value, while a failed exec leaves it unchanged. A fork or clone inherits
the committed bits. The xattr remains on the inode. Only a task with
runtime authority may set, update or remove it. An absent policy or a
file system without xattrs contributes zero bits; invalid lengths and
other read errors refuse the exec.

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
task (``SealPtrace``), which also covers ``/proc/<pid>/mem``,
``pidfd_getfd()`` and ``process_vm_readv()``. ``lsm/perf_event_alloc``
refuses a perf event bound to a marked task (``SealPerf``).
``lsm/mmap_file`` and ``lsm/file_mprotect`` refuse a marked task
executable memory that is writable or that does not come from the
runtime image. ``bpf2`` makes every exec of a runtime file a secure-exec,
so the dynamic loader ignores ``LD_PRELOAD`` and its kin, and refuses
``PR_SET_MM_EXE_FILE`` and ``PR_SET_MM_MAP`` to tasks without
authority.

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
there for the root file system is sealed from its creation. The runtime
and config images carry no labels; dm-verity protects them.

What the seal checks
--------------------

For a labeled inode, these operations need runtime authority:

- a write open (``SealWrite``);
- unlink (``SealUnlink``);
- rename of it, or rename over it (``SealRename``);
- truncate, chmod, chown and timestamp changes through
  ``inode_setattr`` (``SealSetattr``);
- setting or removing any extended attribute (``SealXattr``).

Setting the attribute ``security.bpf.shirudo`` itself needs runtime
authority on every inode, labeled or not (``SealLabel``), so root cannot
label an inode of its own as shirudo's.

A directory with a cached mark takes new entries only from a task with
runtime authority: ``inode_create``, ``inode_mkdir``, ``inode_symlink``,
``inode_mknod``, ``inode_link`` and a rename into it (``SealEntry``). A
label stops writes to an inode, but a rename or a hard link brings an
inode in with its contents, and a symbolic link sends whoever follows it
elsewhere. ``inode_copy_up`` refuses the overlay copy-up of a marked inode
(``SealCopyUp``): a write through an overlay mounted over sealed state
would otherwise land in the upper directory and leave the sealed inode as
it was.

Reading the label
~~~~~~~~~~~~~~~~~

The seal reads the label with the ``bpf_get_file_xattr()`` and
``bpf_get_dentry_xattr()`` kfuncs. Both first check that the calling
task may read the inode. If the seal refused every operation whose label
read failed, it would refuse every write-only open and every unlink of a
file the caller cannot read, on every file system. So these results count
as unlabeled and the operation goes ahead: no label (``ENODATA``), no
security extended attributes on the file system (``EOPNOTSUPP``), and a
label the caller may not read (``EACCES``, ``EPERM``). A label of any
length, any other error, and a failure to allocate the scratch buffer
the kfunc writes into require runtime authority.

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
storage that records a directory's label. A directory gets its mark when
any task opens it and its label is read, when an extended attribute on it
changes, and when it is created under a marked parent. A directory open
whose label read finds nothing removes the mark.

shirudo's writers keep the mark in place. They open the parent directory
and create files relative to that descriptor, which holds the inode in
memory for the duration, and they set the label from userspace as well
when the kernel could not. After the seal attaches, ``init`` walks the
state tree once more; the walk opens every directory and fills the marks.

shirudo's readers do not trust an entry because it is there. They open
each path component without following symbolic links and require every
entry under a labeled directory to carry its parent's label; anything
else is reported as a foreign entry and refused. A path a caller names
for shirudo to write, such as ``--report`` or ``--out``, must be an
unlabeled regular file outside any labeled directory, so a task with
runtime authority cannot be pointed at sealed state.

Limits
------

These are properties of the mechanism as it is. The
:doc:`/security/threat-model` states their consequences.

Directory eviction
    A mark is a cache. When the kernel evicts a directory's inode,
    under memory pressure or through ``vm.drop_caches``, its mark goes
    with it until the next open of that directory. In that window,
    creation, links and renames into the directory are not checked, and
    ``inode_init_security`` adds no label.

Hard links to labeled inodes
    ``inode_link`` checks the destination directory's mark, not the
    source inode. Root can hard-link a labeled file into an unsealed
    directory on the same file system. shirudo replaces state by writing
    a new file and renaming it over the old one, so the old inode stays
    reachable through that link. While a directory's mark is absent, such
    a link can be made inside a sealed directory, where it carries a
    valid label.

Label reads under another LSM
    The kfuncs' read permission check runs every LSM's
    ``inode_permission`` hook for the calling task. A policy of another
    LSM that lets a task write or unlink a file but not read it makes a
    labeled inode look unlabeled to the seal, and the same failure on
    a directory open removes the directory's mark.

Operations without a check
    The seal does not attach ``inode_rmdir``, ``inode_file_setattr`` or
    the ACL hooks ``inode_set_acl`` and ``inode_remove_acl``. Root can
    remove an empty labeled directory, set the immutable or append-only
    flag on sealed files with ``chattr``, and change their POSIX ACLs.

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
