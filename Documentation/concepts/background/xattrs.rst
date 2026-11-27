..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

Extended attributes
===================

A security policy often has to mark files: this one belongs to the
policy, that one may be executed. Owner and mode bits cannot carry such
a mark, and a list of paths breaks as soon as a file is renamed or a
directory is bind-mounted elsewhere. Extended attributes attach the mark
to the inode itself. This page explains them, how security modules use
them, and how shirudo's seal does.

Names and namespaces
--------------------

An extended attribute (xattr) is a name and a value stored with an
inode. Userspace reads and writes them with ``getxattr(2)``,
``setxattr(2)``, ``listxattr(2)`` and ``removexattr(2)``. Every name
starts with a namespace prefix, and the namespace decides who may access
it:

``user.``
    Ordinary file permissions apply: reading needs read permission on
    the file, writing needs write permission. Only regular files,
    directories and sockets take them, and on a sticky directory only
    its owner or a privileged task may write them.

``trusted.``
    Reading and writing both need ``CAP_SYS_ADMIN``.

``security.``
    Reserved for security modules. The file system layer does not
    restrict reading. Writing needs ``CAP_SYS_ADMIN`` in the file system's
    user namespace, unless a security module takes over that check for
    its own names, and every write also passes the ``inode_setxattr``
    hooks of all active LSMs.

``system.``
    Used by the kernel itself, for POSIX ACLs for example. The file
    system decides access.

How security modules label inodes
---------------------------------

An LSM that keeps per-file state stores it as a ``security.`` xattr:
SELinux uses ``security.selinux``, IMA ``security.ima``, file
capabilities ``security.capability``. The label travels with the inode
through renames and bind mounts.

A label is most useful when an inode carries it from the moment it
exists. When a file system creates an inode, it calls the
``inode_init_security`` hook. Each LSM may fill reserved slots with the
xattrs the new inode should carry, and the file system writes them as
part of the same operation that creates the inode. A file system without
that support passes no slots, and the inode starts unlabeled.

Later changes go through ``setxattr(2)`` and ``removexattr(2)``. The
``inode_setxattr`` and ``inode_removexattr`` hooks run before the change
and can refuse it. The ``inode_post_setxattr`` and
``inode_post_removexattr`` hooks run after it.

security.bpf. namespace and its kfuncs
--------------------------------------

BPF LSM programs (see :doc:`bpf-lsm`) can work with xattrs through
kfuncs:

``bpf_get_file_xattr()`` and ``bpf_get_dentry_xattr()``
    Read an xattr whose name starts with ``user.`` or ``security.bpf.``.
    They first check that the current task may read the inode
    (``inode_permission()`` with ``MAY_READ``) and return its error if
    not; carried patch 0021 skips that check for
    ``security.bpf.`` names (:doc:`/internals/kernel-patches`). Both
    may sleep, so only sleepable programs call them.

``bpf_set_dentry_xattr()`` and ``bpf_remove_dentry_xattr()``
    Write or remove a ``security.bpf.`` xattr, after a check that the
    current task may write the inode. Only sleepable LSM programs may
    call them.

``bpf_inode_init_xattr()``
    Fills one of the slots of the ``inode_init_security`` hook with a
    ``security.bpf.`` xattr, so that a new inode is created with it. Only
    a program on that hook may call it, and the BPF LSM reserves two
    slots per inode.

Userspace can also write ``security.bpf.`` names with ``setxattr(2)``,
under the rules of the ``security.`` namespace.

File system support
-------------------

Whether a file system stores ``security.`` xattrs depends on the file
system and its configuration. ext4 stores them with
``CONFIG_EXT4_FS_SECURITY``. tmpfs stores ``security.``, ``trusted.``
and ``user.`` names with ``CONFIG_TMPFS_XATTR``. On a file system without
support, the calls fail with ``EOPNOTSUPP``.

bpffs, the file system that holds BPF pins, supports xattrs since Linux
7.2. Like tmpfs, it keeps them in memory with the inode, so they last as
long as the pin or directory they sit on and go away with the mount. It
serves the ``security.`` and ``trusted.`` namespaces only; a ``user.``
name fails with ``EOPNOTSUPP``. Because bpffs can be mounted inside a
user namespace, it caps the ``security.`` xattrs of one inode at 128
names and 128 KiB of values, while ``trusted.`` names need
``CAP_SYS_ADMIN`` in the initial user namespace. A new pin or directory
takes the xattrs that LSMs supply at creation, so
``bpf_inode_init_xattr()`` works on bpffs too. A BPF LSM program can
therefore label a pinned map, program or link, or a directory of pins,
the same way it labels a file.

overlayfs needs care. Before the first write to a file from a lower
layer, overlayfs copies the file up into the upper layer, and the copy
takes the lower file's xattrs with it, labels included. The write then
changes the copy, and the original stays as it was.

Xattrs and BPF inode storage
----------------------------

BPF has a second place for per-inode data: a map of type
``BPF_MAP_TYPE_INODE_STORAGE`` (see :doc:`bpf-lsm`). A BPF LSM program
passes the map and an inode to ``bpf_inode_storage_get()`` and gets a
pointer to that inode's value, created on first use when the program
passes ``BPF_LOCAL_STORAGE_GET_F_CREATE``; ``bpf_inode_storage_delete()``
removes it. The kernel keeps the value in the BPF LSM's part of the
inode's security blob, ``i_security``. It therefore exists only while the
inode is in memory, and the ``inode_free_security`` hook frees it with
the inode. For the same reason the map type needs the BPF LSM active from
boot; without it, creating such a map fails with ``EOPNOTSUPP``. From
userspace, the key of the map is a file descriptor of the file: a lookup,
update or delete with that descriptor reaches the value of its inode, and
the map cannot be iterated.

The two differ in almost every property a policy cares about:

.. list-table::
   :header-rows: 1
   :widths: 20 40 40

   * - Property
     - Extended attribute
     - Inode storage
   * - Where it lives
     - With the inode in the file system, on disk for a disk file system
     - In kernel memory, with the in-memory inode
   * - How long it lasts
     - Across eviction from the inode cache and across reboots, as long
       as the file system keeps it
     - Until the inode leaves the inode cache, at the latest until the
       next boot
   * - Who reads it
     - Any task, through ``getxattr(2)`` under the namespace rules
     - BPF programs that use the map, and tasks that hold the map's
       descriptor
   * - Who changes it
     - Userspace through ``setxattr(2)`` and ``removexattr(2)``,
       subject to every LSM's hooks, and BPF through the write kfuncs
     - BPF programs that use the map, and tasks that hold the map's
       descriptor
   * - Access from BPF
     - Kfuncs that may sleep, so sleepable programs only; they take a
       dentry or a file and check the caller's permission on the inode
     - Helpers that any BPF LSM program may call, sleepable or not; they
       take a ``struct inode`` and check no permission
   * - Size of a value
     - Up to 64 KiB (``XATTR_SIZE_MAX``); a file system may allow less
     - Fixed by the map, up to just under 64 KiB
   * - Copied with the file
     - By an overlay copy-up, and by copy and backup tools that preserve
       xattrs
     - Never; an overlay inode and the inode below it each have their
       own

Neither replaces the other, and a policy that marks files usually needs
both. The xattr is the record. It outlives the inode cache and the boot,
userspace and other tools can see it, and a new inode can receive it in
the same operation that creates it. Inode storage is the working copy,
which any hook can consult cheaply, including the hooks that cannot read
an xattr at all.

Those hooks are more than one might expect. A BPF program may sleep only
on the hooks the kernel lists as sleepable, and the read kfuncs need a
dentry or a file. The hooks that decide a new entry receive the
directory they change as a ``struct inode``; its dentry is only the new
entry's ``d_parent``, a pointer the verifier does not trust. Two kernel
project patches change that (:doc:`/internals/kernel-patches`):
0022 adds ``inode_mkdir``, ``inode_link``, ``inode_copy_up`` and the ACL
and inode flag hooks to the sleepable set, and 0023 lets a program pass
``dentry->d_parent`` to the read kfuncs. Whether a hook can read the
label it decides by, the directory's or for ``inode_copy_up`` the copied
inode's, then comes out as follows:

.. list-table::
   :header-rows: 1
   :widths: 26 32 16 26

   * - Hook
     - Receives the directory as
     - Sleepable
     - Reads its label
   * - ``inode_init_security``
     - An inode, with no dentry at all
     - No
     - Never
   * - ``inode_copy_up``
     - No directory; the copied inode as a dentry
     - With 0022
     - With 0022
   * - ``inode_link``, ``inode_mkdir``
     - An inode, and the new entry as a dentry
     - With 0022
     - With 0022 and 0023
   * - ``inode_create``, ``inode_mknod``, ``inode_symlink``
     - An inode, and the new entry as a dentry
     - Yes
     - With 0023
   * - ``inode_rename``
     - Two inodes, and both entries as dentries
     - Yes
     - With 0023
   * - ``file_open``
     - A file, when it opens the directory itself
     - Yes
     - Yes

Upstream, then, only ``file_open`` reads the label it decides by, and
``inode_init_security``, where a policy labels a new inode, never can.

The usual pattern follows from that. A sleepable hook that has a dentry
or a file, ``file_open`` for instance, reads the xattr and stores what
the policy needs in inode storage, and ``inode_post_setxattr`` and
``inode_post_removexattr`` refresh or drop the copy when the xattr
changes. The other hooks consult the copy. The copy is a cache, and its
weak point follows from the table: when the inode leaves the inode
cache, the copy goes with it, and until a sleepable hook reads the xattr
again, the other hooks find nothing. A policy has to decide what a
missing copy means at each hook. A task that needs the copy to stay can
hold the directory or file open, which keeps its inode in memory.

Inode storage also suits state that should not outlive the boot or end
up in the file system at all, such as the result of a check made when
the file was opened.

How shirudo uses xattrs
-----------------------

shirudo's seal marks writable state with the xattr
``security.bpf.shirudo``. Its value is a fixed 64-character string, the
same on every target; the seal treats any inode that carries a label
under that name as protected. ``shirudo init`` labels the state tree
under ``/var/lib/shirudo`` on its first run, and ``/run/shirudo`` and
``/run/shirudo-java`` on every boot. From then on, every inode created in a labeled directory
receives the label as it is created, with ``bpf_inode_init_xattr()``.

The seal's sleepable programs read the label with
``bpf_get_file_xattr()`` and ``bpf_get_dentry_xattr()``. A labeled inode
may be opened for writing, removed, renamed, changed in its attributes or
xattrs only by a task with runtime authority. Only such a task may set
the label itself; anyone else's attempt counts as ``SealLabel``, and
other xattr changes on a labeled inode as ``SealXattr``. The label marks
what is protected; it never grants authority to the task that carries
or copies it.

The seal pairs the label with inode storage in the pattern above. When
one of its sleepable programs reads a label, on every open of a
directory, on an open of a file for writing and after an xattr change,
it records the label for that inode in the ``seal_dir_marks`` map, or
drops the record when there is no label. The hooks that add an entry to
a directory, by creation, link or rename, read the directory's label
from the new entry's parent dentry, require runtime authority when it
is labeled (``SealEntry``) and refresh the record on the way.
``lsm/inode_init_security``, which has no dentry to read from, gives a
new inode the label of its directory's record, refreshed a moment
before by the entry hook of the same operation, and records a new
directory in turn, so a subtree created in one go needs no reopen.
``lsm.s/inode_copy_up`` refuses an overlay copy-up of a labeled inode
(``SealCopyUp``).
Like every map of shirudo's, ``seal_dir_marks`` is refused to tasks
without runtime authority, so userspace can neither read nor change a
record. See :doc:`/internals/seal`.

The second xattr, ``security.bpf.shirudo.payload``, sits on each upatch
directory in the private bpffs, ``/run/shirudo/bpffs/upatches/<name>``.
``shirudo upatch load`` writes the 32-byte SHA-256 of the payload there.
``shirudo upatch unload`` reads it and refuses with ``payload_mismatch``
when it differs from the digest the signed unload directive names, or
cannot be read. shirudo's ``lsm/inode_setxattr`` and
``lsm/inode_removexattr`` programs refuse xattr changes in the private
bpffs to every task without runtime authority (``PinXattr``). See
:doc:`/reference/files` for the paths.

Limits
------

Upstream, the read kfuncs check the calling task's read permission even
for ``security.bpf.`` names; carried patch 0021 drops that check
for them. On a kernel without the patch, when another LSM, an ACL
or an idmapped mount denies that task read access, the seal decides by
the record of the inode, or of the directory the operation changes, and
a labeled inode without a record looks unlabeled. :doc:`/internals/seal`
lists this among its limits.

The seal's records in inode storage are lost when an inode leaves the
inode cache, and nothing depends on them: the hooks read the label, and
the record a creation labels from is refreshed by the entry hook that
precedes it. A file system without ``security.`` xattrs cannot carry
the label at all.
