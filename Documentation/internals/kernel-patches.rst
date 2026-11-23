..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Kernel developers, security reviewers

Carried kernel patches
======================

The kernel changes shirudo needs. :src:`testing/kernel/patches/` carries
these changes for the test suite. A production kernel needs the same
changes.

Summary
-------

.. list-table::
   :header-rows: 1
   :widths: 34 22 22 22

   * - Patch
     - Author
     - In bpf-next
     - Architectures
   * - ``0020-tpm-Let-LSMs-inspect-userspace-commands.patch``
     - KP Singh
     - No
     - All
   * - ``0021-bpf-Read-security.bpf-xattrs-for-LSM-programs-without-the-callers-permission.patch``
     - Daniel Borkmann
     - No
     - All
   * - ``0022-bpf-Let-sleepable-LSM-programs-attach-to-the-remaining-inode-hooks.patch``
     - Daniel Borkmann
     - No
     - All
   * - ``0023-bpf-Treat-dentry-d_parent-as-a-trusted-pointer.patch``
     - Daniel Borkmann
     - No
     - All
   * - ``0024-mm-Let-LSMs-check-read-only-remote-mm-access-under-CAP_PERFMON.patch``
     - Daniel Borkmann
     - No
     - All

"In bpf-next" was checked against the bpf-next tree at commit
``57fae4059380``: ``include/linux/lsm_hook_defs.h`` there has no
``tpm_command`` hook, ``fs/bpf_fs_kfuncs.c`` checks the calling task's
read permission before it returns a ``security.bpf.`` xattr to an LSM
program, the sleepable hook set of ``kernel/bpf/bpf_lsm.c`` lacks
``inode_mkdir``, ``inode_link``, ``inode_set_acl``, ``inode_remove_acl``,
``inode_file_setattr`` and ``inode_copy_up``, the verifier trusts
``d_inode`` of a dentry but not ``d_parent``, and ``may_access_mm()``
grants a read-mode access to ``CAP_PERFMON`` without asking an LSM.

An x86-64 target also needs upstream commit ``31ac959c915c``
("x86/ftrace: Mark jmp mode by clearing bit 63 of trampoline address"),
which bpf-next and the bpf fixes tree for 7.4 contain and which the
tree does not carry; :doc:`/operate/plan/system-requirements` says
why.

How the test kernel includes them
---------------------------------

:src:`testing/kernel/build-kernel.sh` applies the patches to the pinned
bpf-next commit and builds the kernel package with the configuration in
:src:`testing/kernel/`. CI checks the BTF ABI and LSM hooks before it
stages the image for the test VM.

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
    The kernel's BTF has no ``bpf_lsm_tpm_command``, so the pre-flight
    check ``kernel_lsm_hooks`` fails and ``init`` stops before it loads
    anything. The boot is not stopped, and the target runs without
    enforcement, as :doc:`boot-flow` describes.

Label reads without the caller's permission
-------------------------------------------

Subject
    bpf: Read security.bpf xattrs for LSM programs without the caller's
    permission

Files
    ``fs/bpf_fs_kfuncs.c``.

What it changes
    ``bpf_get_dentry_xattr()`` and ``bpf_get_file_xattr()`` check that
    the calling task may read the inode before they return an extended
    attribute, for ``user.`` and ``security.bpf.`` names alike. The
    patch skips that check for ``security.bpf.`` names, which a BPF LSM
    program keeps for itself, as SELinux, Smack and EVM read their
    labels with ``__vfs_getxattr()`` in kernel context. ``user.`` names
    keep the check.

Why shirudo needs it
    The seal reads ``security.bpf.shirudo`` in the hooks that decide the
    calling task's operation, and that task is the one the seal may
    refuse. With the check, the task's read permission decides whether
    the seal sees the label, and root arranges a read that fails: an
    idmapped bind mount shows its files as another id's, an ACL grants
    another id a write without a read, a file system uid set with
    ``setfsuid()`` keeps ``CAP_SYS_ADMIN`` without the DAC capabilities,
    and another LSM's ``inode_permission`` policy refuses the read.
    :doc:`seal` explains the verdict.

Without it
    The seal loads and runs. A label read that fails with ``EACCES`` or
    ``EPERM`` is decided by the mark of the inode, or of the directory
    the operation changes, and a labeled inode without a mark looks
    unlabeled to the seal. :doc:`seal` lists this under its limits.

Sleepable programs on the remaining inode hooks
-----------------------------------------------

Subject
    bpf: Let sleepable LSM programs attach to the remaining inode hooks

Files
    ``kernel/bpf/bpf_lsm.c``.

What it changes
    The kernel keeps a list of the LSM hooks that take a sleepable BPF
    program. The patch adds ``inode_mkdir``, ``inode_link``,
    ``inode_set_acl``, ``inode_remove_acl``, ``inode_file_setattr`` and
    ``inode_copy_up`` to it. Each is called from process context with
    the inode lock held, as the hooks already in the list are, and may
    sleep.

Why shirudo needs it
    The seal reads labels with ``bpf_get_dentry_xattr()``, which sleeps,
    so only a sleepable program can decide an operation by a label.
    ``lsm.s/inode_mkdir`` and ``lsm.s/inode_link`` read the label of the
    directory the entry goes into, ``lsm.s/inode_set_acl``,
    ``lsm.s/inode_remove_acl`` and ``lsm.s/inode_file_setattr`` the
    label of the inode they change, and ``lsm.s/inode_copy_up`` the
    label of the inode an overlay copies up, instead of a mark that an
    eviction of the inode empties.

Without it
    The kernel refuses the ``lsm.s/`` form of those programs, so the
    ``seal`` object fails to load and ``init`` fails at "loading
    enforcement", with the result the TPM command hook describes.

Trusted dentry parent
---------------------

Subject
    bpf: Treat dentry->d_parent as a trusted pointer

Files
    ``kernel/bpf/verifier.c``.

What it changes
    The verifier lists the fields of a kernel structure that a program
    may read as trusted pointers. For ``struct dentry`` it lists
    ``d_inode``; the patch adds ``d_parent`` beside it, as trusted or
    null, so a program checks it for NULL before use. The parent of a
    dentry an inode hook receives is stable while the hook runs, under
    the parent's inode lock the caller holds, and is never NULL, since
    the root's points to itself.

Why shirudo needs it
    ``inode_create``, ``inode_mkdir``, ``inode_symlink``,
    ``inode_mknod``, ``inode_link`` and ``inode_rename`` receive the
    directory an entry goes into as a ``struct inode`` and the entry as
    a dentry. ``bpf_get_dentry_xattr()`` takes a dentry, and the only
    one the seal has for the directory is ``dentry->d_parent``. The
    seal reads the directory's label from it and refreshes the
    directory's mark on the way, which ``inode_init_security`` labels
    the new inode from.

Without it
    The verifier refuses ``d_parent`` as the kfunc's argument, so the
    ``seal`` object fails to load and ``init`` fails at "loading
    enforcement", with the result the TPM command hook describes.

Read-only mm access hook
------------------------

Subject
    mm: Let LSMs check read-only remote mm access under CAP_PERFMON

Files
    ``kernel/fork.c``, ``include/linux/lsm_hook_defs.h``,
    ``include/linux/security.h``, ``security/security.c``.

What it changes
    ``may_access_mm()``, which ``mm_access()`` asks before it hands out
    another task's memory, grants a read-mode access to a caller with
    ``CAP_PERFMON`` or ``CAP_SYS_ADMIN`` after ``ptrace_may_access()``
    refused it, since commit ``0c555a3c1bc9`` ("mm,procfs: allow
    read-only remote mm access under CAP_PERFMON"). The patch has it
    call a new hook, ``security_mm_read_access(task, mode)``, before
    it grants the access that way, and refuse it when the hook does.
    An access ``ptrace_may_access()`` allows is not checked again.

Why shirudo needs it
    The seal refuses every ptrace mode against a task with runtime
    authority, and ``ptrace_may_access()`` asks it, but the perfmon path
    comes after that refusal: root opened ``/proc/<pid>/environ``,
    ``maps``, ``smaps``, ``numa_maps``, ``pagemap`` and ``auxv`` of a
    running command, its environment and the layout of its memory. The
    seal attaches ``lsm/mm_read_access`` and refuses a marked task there
    too.

Without it
    The kernel's BTF has no ``bpf_lsm_mm_read_access``, so the pre-flight
    check ``kernel_lsm_hooks`` fails and ``init`` stops before it loads
    anything, with the result the TPM command hook describes.

Related
-------

- :doc:`kernel-interfaces` for the other kernel requirements
- :doc:`/contribute/testing/testing` for building and booting the test kernel
