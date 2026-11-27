..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Kernel developers, security reviewers

Kernel interfaces
=================

The kernel interfaces shirudo uses on a target, with the exact arguments.
The operator side uses none of them. :doc:`signed-loader` and
:doc:`enforcement` explain why each is needed.

Kernel baseline
---------------

.. list-table::
   :header-rows: 1
   :widths: 22 48 30

   * - Commit
     - Subject
     - First release
   * - ``b55d26bd1891``
     - block,lsm: add LSM blob and new LSM hooks for block devices
     - v6.12
   * - ``0c3772a8db1f``
     - x86/ftrace: Implement DYNAMIC_FTRACE_WITH_JMP
     - v6.19
   * - ``033724b1c627``
     - dm-verity: add dm-verity keyring
     - v7.0
   * - ``63a673e8a411``
     - bpf: Expose signature verdict via bpf_prog_aux
     - v7.2
   * - ``3f8c65b06faf``
     - bpf: have bpf_real_data_inode() take a struct file
     - v7.2
   * - ``9722955b5430``
     - bpf: Add simple xattr support to bpffs
     - v7.2
   * - ``264d8fd2794f``
     - bpf, keys: Add a bpf keyring for program signature validation
     - bpf-next
   * - ``abaa0835b4f3``
     - bpf: Refuse caller-supplied keyrings when the bpf one is active
     - bpf-next
   * - ``ff0d1c0915d1``
     - bpf, lsm: Let BPF LSM provide xattrs at inode creation
     - bpf-next
   * - ``1041fca2ee8a``
     - keys: add KEY_SPEC_DM_VERITY_KEYRING
     - 7.4 cycle

bpf-next contains the signed-loader ABI at merge ``0867b7bfa9de``.
The test suite uses the pinned artifact built from :src:`testing/kernel/`.
shirudo defines ``KEY_SPEC_DM_VERITY_KEYRING`` (-10) itself when
the UAPI headers lack it. The ``tpm_command`` LSM hook, the label reads
without the calling task's permission, the sleepable form of six inode
hooks, the trusted ``d_parent`` and the ``mm_read_access`` LSM hook are
not in bpf-next;
:doc:`kernel-patches` lists the patches the test kernel carries. A
kernel is admitted by the ABI check below, not by its release string.

XDP attachment
--------------

XDP uses ``BPF_LINK_CREATE`` with ``attach_type=BPF_XDP``,
``target_ifindex`` from runtime discovery and ``flags=XDP_FLAGS_DRV_MODE``.
shirudo verifies ``BPF_LINK_TYPE_XDP`` and the returned ``xdp.ifindex``
before pinning. Discovery uses kernel ``RTM_GETLINK`` replies,
``ETHTOOL_GDRVINFO`` and devlink ``DEVLINK_CMD_PORT_GET``; it does not
read sysfs to classify devices. The program a device runs, in any mode,
comes from the ``IFLA_XDP`` attributes of the same dump:
``IFLA_XDP_DRV_PROG_ID``, and ``IFLA_XDP_SKB_PROG_ID`` or
``IFLA_XDP_HW_PROG_ID`` for a program shirudo did not attach. Before attaching, shirudo reads
``NETDEV_A_DEV_XDP_FEATURES`` with ``NETDEV_CMD_DEV_GET`` on the ``netdev``
generic netlink family and refuses a device that reports
``NETDEV_XDP_ACT_BASIC`` without ``NETDEV_XDP_ACT_RX_SG``, as the kernel
never compares a program's multi-buffer flag with the device's. The
``lsm/bpf_prog`` guard refuses XDP
descriptors to unauthorized callers, including ``BPF_PROG_GET_FD_BY_ID``,
because netlink accepts these descriptors outside ``bpf()``.

Signing ABI check
-----------------

``kernel_abi_check()`` (:src:`util/kernel_abi.c`) reads the running kernel's
BTF and requires:

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Member
     - Required type
   * - ``struct bpf_map.sha``
     - ``u8[32]``, not a bit field
   * - ``struct bpf_map.excl_prog_sha``
     - pointer to a byte, not a bit field
   * - ``struct bpf_prog_aux.sig``
     - struct
   * - ``struct bpf_prog_aux.sig.keyring_serial``
     - ``s32``
   * - ``struct bpf_prog_aux.sig.keyring_type``
     - ``u8``
   * - ``struct bpf_prog_aux.sig.verdict``
     - ``u8``

The pre-flight runs it as ``signed_loader_kernel_abi``, and every
``upatch load`` and ``upatch unload`` without ``--no-precheck`` runs it
before ``BPF_PROG_LOAD``. A failure is ``kernel_abi_unsupported``.
Beside it the pre-flight runs ``kernel_lsm_hooks``: it reads the hooks
of every ``lsm`` and ``lsm.s`` program from the embedded ``bpf2`` and
``seal`` objects and refuses a kernel whose BTF has no
``bpf_lsm_<hook>`` for one, naming the hooks it lacks.
``lsm/bpf_prog_load`` compares ``sig.verdict`` with ``BPF_SIG_VERIFIED``
and ``sig.keyring_type`` with ``BPF_SIG_KEYRING_BPF``; these enum values
are compiled into ``bpf2`` from the ``vmlinux.h`` of the build.

Signature verification
----------------------

Kernel behavior a signed load relies on (``bpf_prog_verify_signature()``
in ``kernel/bpf/verifier.c``):

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Input
     - Behavior
   * - ``signature``, ``signature_size``
     - Size 1 to 64 KiB. Verified when ``signature`` is set.
   * - ``keyring_id``
     - ``0``: built-in keys, kind ``BPF_SIG_KEYRING_BUILTIN``. ``1``:
       secondary keyring. ``2``: platform keyring. ``KEY_SPEC_BPF_KEYRING``
       (-9): the ``.bpf`` keyring, kind ``BPF_SIG_KEYRING_BPF``, serial
       recorded as 0; ``ENOKEY`` when the keyring is empty or not sealed.
       Any other id: a user keyring, refused with ``EPERM`` when booted
       with ``bpf.keyring_unsealed=1``.
   * - ``fd_array``, ``fd_array_cnt``
     - The maps resolved from ``fd_array`` are folded into the signed
       data: ``insns || value(map_0) || ...``. Each must be an array, frozen,
       without active writers, and exclusive (``excl_prog_sha`` set).
   * - ``core_relo_cnt``
     - Must be 0 for a signed program (``EACCES``).
   * - Result
     - On success, ``prog->aux->sig`` records serial, kind and
       ``BPF_SIG_VERIFIED``. Figure 1 of :doc:`signed-loader` gives the
       order of this check, ``security_bpf()`` and
       ``security_bpf_prog_load()``.

A map with ``excl_prog_hash`` set binds only to a program whose SHA-256
digest equals it.

BPF system calls of a load
--------------------------

Every call below is made from userspace with ``kernel`` false, except
where the caller is the loader.

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Command
     - Attributes set
   * - ``BPF_MAP_CREATE``
     - ``map_type`` ``BPF_MAP_TYPE_ARRAY``, ``key_size`` 4,
       ``value_size`` the data length, ``max_entries`` 1, ``map_name``
       ``__loader.map``, ``excl_prog_hash`` SHA-256 of the loader
       instructions, ``excl_prog_hash_size`` 32.
   * - ``BPF_MAP_UPDATE_ELEM``
     - ``map_fd``, ``key`` 0, ``value`` the data, ``flags`` 0.
   * - ``BPF_MAP_FREEZE``
     - ``map_fd``.
   * - ``BPF_PROG_LOAD``
     - ``prog_type`` ``BPF_PROG_TYPE_SYSCALL``, ``insns``, ``insn_cnt``,
       ``license`` ``Dual BSD/GPL``, ``prog_flags`` ``BPF_F_SLEEPABLE``,
       ``prog_name`` the upatch name with characters other than
       ``[A-Za-z0-9_.]`` replaced by ``_``, cut to 15, ``signature``,
       ``signature_size``, ``keyring_id`` ``KEY_SPEC_BPF_KEYRING``,
       ``fd_array`` holding the map, ``fd_array_cnt`` 1, ``log_level`` 1,
       ``log_size`` 16 MiB, ``log_buf``.
   * - ``BPF_PROG_TEST_RUN``
     - ``prog_fd`` the loader, ``ctx_in`` and ``ctx_size_in``: a context
       of ``sz``, ``flags``, ``log_level`` 1, ``log_size`` 16 MiB and
       ``log_buf``, followed by one map descriptor (``map_fd``,
       ``max_entries``, ``initial_value``) per map and one program
       descriptor (``prog_fd``) per program, and 1024 bytes of padding.
       The loader fills the descriptors.
   * - loader: ``BPF_MAP_CREATE``, ``BPF_MAP_UPDATE_ELEM``,
       ``BPF_MAP_FREEZE``, ``BPF_PROG_LOAD`` through ``bpf_sys_bpf()``
     - As gen_loader recorded them.
   * - ``BPF_RAW_TRACEPOINT_OPEN``, ``BPF_LINK_CREATE``
     - One per program, with the attributes of its attach kind in the
       table below.
   * - ``BPF_OBJ_GET_INFO_BY_FD``
     - On each link before it is pinned, compared as the table below
       says; a mismatch is ``attach_scope_mismatch``.
   * - ``BPF_OBJ_PIN``
     - Links at ``upatches/<name>/link`` or ``link_<n>``, serializer
       programs at ``serializers/<map>``, the test-run program at
       ``test``, each XDP program at ``xdp_prog_<n>``, maps at
       ``maps/<map>``, under ``/run/shirudo/bpffs``.

The attach kinds are those of :doc:`/upatches/write/attach-kinds`,
numbered as in the signed attach metadata. Every call is
``BPF_LINK_CREATE`` except where the table says otherwise.

.. list-table::
   :header-rows: 1
   :widths: 16 22 34 28

   * - Kind
     - ``attach_type``
     - Target and other attributes
     - Checked before pinning
   * - 0, an LSM program
     - ``BPF_LSM_MAC``
     - ``target_fd`` 0.
     - A raw tracepoint or tracing link.
   * - 0, a ``cgroup_skb`` program
     - ``BPF_CGROUP_INET_INGRESS`` or ``BPF_CGROUP_INET_EGRESS``, from
       the function name
     - As kinds 3 and 4.
     - As kinds 3 and 4.
   * - 0, any other program
     - None: ``BPF_RAW_TRACEPOINT_OPEN``
     - ``raw_tracepoint.name`` 0, ``prog_fd``.
     - A raw tracepoint or tracing link.
   * - 1, 2: kprobe, kretprobe
     - ``BPF_PERF_EVENT``
     - ``target_fd`` a perf event of the kprobe PMU, below.
     - Perf event type, function name and offset as signed.
   * - 3, 4: ``cgroup_skb``
     - ``BPF_CGROUP_INET_INGRESS``, ``BPF_CGROUP_INET_EGRESS``
     - ``target_fd`` an ``O_DIRECTORY`` descriptor of
       ``/sys/fs/cgroup``.
     - ``cgroup_id`` 1.
   * - 5: ``fmod_ret``
     - ``BPF_MODIFY_RETURN``
     - ``target_fd`` 0.
     - A tracing link of ``BPF_MODIFY_RETURN``.
   * - 6: netfilter
     - ``BPF_NETFILTER``
     - ``pf`` 10 (``NFPROTO_IPV6``), ``hooknum`` 0
       (``NF_INET_PRE_ROUTING``), ``priority`` -450
       (``NF_IP6_PRI_RAW_BEFORE_DEFRAG``), ``flags`` 0.
     - ``pf``, ``hooknum`` and ``priority`` as set, and the caller's
       network namespace cookie (``SO_NETNS_COOKIE``) 7.
   * - 7, 9: ``uprobe.multi``, ``uretprobe.multi`` and their ``.s``
       forms
     - ``BPF_TRACE_UPROBE_MULTI``
     - ``path_fd`` the target binary's descriptor, opened and checked
       by build ID, ``offsets``, ``cnt``, ``flags``
       ``BPF_F_UPROBE_MULTI_PATH_FD``, with
       ``BPF_F_UPROBE_MULTI_RETURN`` for kind 9. The signed loader sets
       ``BPF_F_SLEEPABLE`` for an ``.s`` form at load.
     - Offset count and the return flag.
   * - 8: XDP
     - ``BPF_XDP``
     - ``target_ifindex`` a selected device, ``flags``
       ``XDP_FLAGS_DRV_MODE``.
     - ``BPF_LINK_TYPE_XDP`` and ``xdp.ifindex`` of the selected device.
       The device class and peer scope are checked again after the
       attach, and the initial network namespace once before the
       devices are read.
   * - 10, 11: uprobe, uretprobe and their ``.s`` forms
     - ``BPF_PERF_EVENT``
     - ``target_fd`` a perf event of the uprobe PMU, below.
     - Perf event type, the file offset as signed and
       ``ref_ctr_offset`` 0.

A kprobe link's perf event comes from ``perf_event_open(2)`` with
``type`` read from ``/sys/bus/event_source/devices/kprobe/type``,
``config1`` the symbol, ``config2`` the offset, the bit named in
``.../kprobe/format/retprobe`` set in ``config`` for a kretprobe, ``pid``
-1, ``cpu`` 0 and ``PERF_FLAG_FD_CLOEXEC``. A uprobe link's comes from
the same call on the uprobe PMU, ``/sys/bus/event_source/devices/uprobe``,
with ``config1`` the path ``/proc/self/fd/<n>`` of the target binary's
checked descriptor and ``config2`` the recorded file offset.

An unload directive makes the first four calls and no others.

``init`` loads ``bpf2`` and ``seal`` with libbpf (``BPF_BTF_LOAD``,
``BPF_MAP_CREATE``, ``BPF_PROG_LOAD`` of ``BPF_PROG_TYPE_LSM``), attaches
each program with ``BPF_LINK_CREATE`` and ``BPF_LSM_MAC``, and pins it.
It populates the identity map with ``BPF_MAP_UPDATE_ELEM``, seeds
``shirudo_tasks`` with a pidfd as key, and freezes maps with
``BPF_MAP_FREEZE``.

Extended attributes
-------------------

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Name
     - Use
   * - ``security.bpf.shirudo``
     - The seal label on writable state, on ``/run/shirudo`` and on
       ``/run/shirudo-java``.
   * - ``security.bpf.shirudo.payload``
     - The 32-byte payload digest on each upatch's pin directory in the
       private bpffs.
   * - ``security.bpf.shirudo.policy``
     - The 8-byte policy bitset of an executable, which the seal adds to
       the task's bits at exec.
   * - ``security.bpf.shirudo.ancestor``
     - The mark on each directory between the state root and the root
       of its file system, which the seal guards against a rename.

LSM hooks
---------

.. list-table::
   :header-rows: 1
   :widths: 50 20 30

   * - Hook
     - Object
     - Kernel condition
   * - ``bpf``, ``bpf_map``, ``bpf_prog``, ``bpf_prog_load``
     - ``bpf2``
     - ``CONFIG_BPF_SYSCALL``
   * - ``key_permission``
     - ``bpf2``
     - ``CONFIG_KEYS``
   * - ``tpm_command``
     - ``bpf2``
     - Carried patch
   * - ``mm_read_access``
     - ``seal``
     - Carried patch
   * - ``task_prctl``, ``bprm_check_security``, ``inode_unlink``,
       ``inode_rmdir``, ``inode_mkdir``, ``inode_symlink``,
       ``inode_link``, ``inode_rename``, ``inode_setxattr``,
       ``inode_removexattr``, ``kernel_load_data``, ``kernel_read_file``,
       ``locked_down``, ``file_open``, ``sb_umount``, ``move_mount``, ``sb_mount``,
       ``sb_remount``, ``file_ioctl``, ``file_ioctl_compat``,
       ``bdev_setintegrity`` (sleepable), ``bdev_free_security``
     - ``bpf2``
     - None
   * - ``perf_event_alloc``
     - ``seal``
     - ``CONFIG_PERF_EVENTS``
   * - ``bprm_creds_for_exec``, ``bprm_check_security``,
       ``bprm_committed_creds``, ``file_open``, ``inode_unlink``,
       ``inode_rmdir``, ``inode_setattr``, ``inode_setxattr``,
       ``inode_removexattr``, ``inode_post_setxattr``,
       ``inode_post_removexattr`` (all sleepable); ``task_alloc``,
       ``task_kill``, ``task_setrlimit``, ``ptrace_access_check``,
       ``socket_post_create``,
       ``inode_init_security``, ``mmap_file``, ``file_mprotect``
     - ``seal``
     - None
   * - ``inode_create``, ``inode_symlink``, ``inode_mknod``,
       ``inode_rename`` (all sleepable)
     - ``seal``
     - Carried patch 0023, for the read of ``dentry->d_parent``
   * - ``inode_mkdir``, ``inode_link``, ``inode_set_acl``,
       ``inode_remove_acl``, ``inode_file_setattr``, ``inode_copy_up``
       (all sleepable)
     - ``seal``
     - Carried patch 0022, and 0023 for ``inode_mkdir`` and
       ``inode_link``

A hook the kernel's BTF lacks fails the pre-flight check
``kernel_lsm_hooks``, before ``init`` loads anything. :doc:`enforcement`
gives each hook's verdicts.

Kfuncs and helpers
------------------

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Kfunc
     - Use
   * - ``bpf_get_file_xattr()``, ``bpf_get_dentry_xattr()``
     - Read ``security.bpf.shirudo``, ``security.bpf.shirudo.policy``
       and ``security.bpf.shirudo.ancestor``.
       Sleepable; upstream they check ``MAY_READ`` for the calling task
       first, which carried patch 0021 skips for ``security.bpf.``
       names.
   * - ``bpf_inode_init_xattr()``
     - Add the label in ``inode_init_security``.
   * - ``bpf_real_data_inode()``
     - Tell an overlay copy from a direct inode at exec. Sleepable.
   * - ``bpf_iter_num_new()``, ``bpf_iter_num_next()``,
       ``bpf_iter_num_destroy()``
     - Bounded loops (``bpf_for``) of the mount walk.

Helpers: ``bpf_map_lookup_elem()``, ``bpf_map_update_elem()``,
``bpf_map_delete_elem()``, ``bpf_task_storage_get()``,
``bpf_inode_storage_get()``, ``bpf_inode_storage_delete()``,
``bpf_sk_storage_get()``, ``bpf_get_current_task_btf()``,
``bpf_probe_read_kernel()``, ``bpf_probe_read_kernel_str()``,
``bpf_bprm_opts_set()`` with ``BPF_F_BPRM_SECUREEXEC``,
``bpf_dynptr_from_mem()``, ``bpf_strncmp()``.

Map types: ``BPF_MAP_TYPE_ARRAY``, ``BPF_MAP_TYPE_HASH``,
``BPF_MAP_TYPE_TASK_STORAGE``, ``BPF_MAP_TYPE_INODE_STORAGE``,
``BPF_MAP_TYPE_SK_STORAGE``.

Keyrings
--------

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - Call
     - Use
   * - ``keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_BPF_KEYRING)``
     - Serial of ``.bpf``.
   * - ``add_key("asymmetric", NULL, <der>, KEY_SPEC_BPF_KEYRING)``
     - Enroll a BPF certificate.
   * - ``keyctl(KEYCTL_RESTRICT_KEYRING, KEY_SPEC_BPF_KEYRING, NULL,
       NULL)``
     - Seal ``.bpf``: no restriction type, every later link refused.
   * - ``keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_DM_VERITY_KEYRING)``,
       ``add_key(..., KEY_SPEC_DM_VERITY_KEYRING)``,
       ``keyctl(KEYCTL_RESTRICT_KEYRING, KEY_SPEC_DM_VERITY_KEYRING, ...)``
     - The same for ``.dm-verity`` (-10) and the config verification
       certificates.
   * - ``keyctl(KEYCTL_READ, <ring>)``, ``keyctl(KEYCTL_DESCRIBE, <key>)``
     - List a keyring and compare it with the expected set.
   * - ``keyctl(KEYCTL_UNLINK, <key>, <ring>)``
     - Remove a revoked certificate from ``.bpf``.
   * - ``add_key("asymmetric", ..., KEY_SPEC_THREAD_KEYRING)``
     - Probe whether the kernel parses a certificate, then unlink it.
   * - ``add_key("user", "shirudo-verity-<hex>", <sig>,
       KEY_SPEC_THREAD_KEYRING)``,
       ``keyctl(KEYCTL_SETPERM, <key>, KEY_POS_SEARCH)``
     - Hand a config root signature to dm-verity as
       ``root_hash_sig_key_desc``.
   * - ``keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_USER_KEYRING)``
     - Pre-flight check that keys are available.

Device mapper and loop
----------------------

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Call
     - Use
   * - ``LOOP_CTL_GET_FREE``, ``LOOP_CONFIGURE``
     - Attach an image file read-only with ``LO_FLAGS_READ_ONLY``,
       ``LO_FLAGS_AUTOCLEAR``, 4096-byte blocks and a size limit.
   * - ``LOOP_GET_STATUS64``
     - Check that a loop device still backs the image file.
   * - ``DM_DEV_CREATE``, ``DM_TABLE_LOAD`` with ``DM_READONLY_FLAG``,
       ``DM_DEV_SUSPEND`` to resume, ``DM_TABLE_STATUS``,
       ``DM_DEV_REMOVE``, ``DM_LIST_DEVICES``
     - Create, check, list and remove ``verity`` mappings.
   * - ``BLKGETDISKSEQ``, ``BLKGETSIZE64``, ``BLKROGET``
     - Identify a mapping and check its size and read-only state.

Process setup and prctl
-----------------------

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Call
     - Use
   * - ``prctl(0x53520001)``
     - Enforcement probe. ``lsm/task_prctl`` fails it with errno 1002
       when ``bpf2`` is attached; ``EINVAL`` or ``ENOSYS`` means it is
       not.
   * - ``personality(PER_LINUX)``
     - Drops the personality flags the caller passed down, ``UNAME26``
       among them, which would have ``uname()`` report a 2.6 release to
       the tree selector. A failure ends the command.
   * - ``setrlimit(RLIMIT_FSIZE, RLIMIT_CPU)`` to unlimited,
       ``setitimer()`` of the three interval timers to zero
     - Exec keeps the limits and timers the caller set, with which the
       kernel would stop the command by ``SIGXFSZ``, ``SIGXCPU`` or
       ``SIGALRM``. A failure ends the command.
   * - ``prctl(PR_SET_DUMPABLE, 0)``, ``prctl(PR_SET_NO_NEW_PRIVS, 1)``,
       ``prctl(PR_SET_PTRACER, 0)``
     - Process hardening before every command.
   * - ``setrlimit(RLIMIT_CORE, 0)``, ``mlockall(MCL_CURRENT |
       MCL_FUTURE)``
     - No core dumps; memory kept out of swap. A failed ``mlockall``
       ends the command.
   * - ``pidfd_open(getpid(), 0)``
     - Key for the bootstrap mark in ``shirudo_tasks`` and the expected
       config root in ``shirudo_roots``.

Mounts
------

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Mount
     - Options
   * - ``tmpfs`` at ``/run/shirudo``
     - ``nosuid,nodev,noexec``, ``mode=0700,size=16M``, made private
       recursively.
   * - ``bpf`` at ``/run/shirudo/bpffs``
     - ``nosuid,nodev,noexec``, ``mode=0700``.
   * - ext4 runtime image at ``/run/shirudo/runtime``
     - ``ro,nodev,nosuid``, ``noload``.
   * - ext4 config image at ``/run/shirudo/config``
     - ``ro,nodev,nosuid,noexec``, ``noload``.
   * - bind of ``/sysroot/var/lib/shirudo`` at ``/var/lib/shirudo``
     - Recursive, in the initrd only, detached when ``init`` exits.

Kconfig
-------

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - Option
     - Why
   * - ``CONFIG_BPF``, ``CONFIG_BPF_SYSCALL``, ``CONFIG_BPF_JIT``
     - ``bpf()``, the JIT, bpffs.
   * - ``CONFIG_SECURITY``, ``CONFIG_BPF_LSM``, ``CONFIG_BPF_EVENTS``,
       ``bpf`` in ``CONFIG_LSM`` or ``lsm=``
     - The BPF LSM. ``CONFIG_BPF_LSM`` depends on ``CONFIG_BPF_EVENTS``.
   * - ``CONFIG_SECURITYFS``
     - ``/sys/kernel/security/lsm`` for the ``bpf_lsm_active`` check.
   * - ``CONFIG_FUNCTION_TRACER``, ``CONFIG_DYNAMIC_FTRACE``,
       ``CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS``
     - BPF trampolines, which every LSM program attaches through.
   * - ``CONFIG_DEBUG_INFO_BTF``
     - CO-RE, the ABI check, the check of the pinned guard links.
   * - ``CONFIG_PERF_EVENTS``
     - The ``perf_event_alloc`` hook.
   * - ``CONFIG_KEYS``, ``CONFIG_ASYMMETRIC_KEY_TYPE``,
       ``CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE``,
       ``CONFIG_X509_CERTIFICATE_PARSER``,
       ``CONFIG_PKCS7_MESSAGE_PARSER``,
       ``CONFIG_SYSTEM_DATA_VERIFICATION``
     - The keyrings, certificates and CMS verification.
   * - ``CONFIG_CRYPTO_MLDSA``, ``CONFIG_CRYPTO_SHA512``,
       ``CONFIG_CRYPTO_SHA256``
     - ML-DSA-87 certificates and signatures; the SHA-512 digest in the
       CMS signed attributes; SHA-256 digests.
   * - ``CONFIG_TCG_TPM`` and a driver, ``CONFIG_TCG_TIS`` or
       ``CONFIG_TCG_CRB``
     - The TPM.
   * - ``CONFIG_MD``, ``CONFIG_BLK_DEV_DM``, ``CONFIG_DM_VERITY``,
       ``CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG``, ``CONFIG_BLK_DEV_LOOP``,
       ``CONFIG_EXT4_FS``
     - The runtime and config images.
   * - ``CONFIG_EXT4_FS_SECURITY``
     - Security extended attributes when the state is on ext4.
   * - ``CONFIG_TMPFS``, ``CONFIG_TMPFS_XATTR``
     - The label on ``/run/shirudo``.
   * - ``CONFIG_BLK_DEV_INITRD``
     - The initrd ``init`` runs in.

``CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG_SECONDARY_KEYRING`` and
``CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG_PLATFORM_KEYRING`` widen the keys
the kernel's own check of a config accepts, but the target checks the
signature against the runtime image's certificates first; see
:doc:`config-images`. ``CONFIG_SECCOMP=n``
is handled: the seal then sees no seccomp state. The attach kinds of
upatches can need further options; see :doc:`/upatches/write/attach-kinds`.

The pre-flight check ``module_signatures`` refuses a kernel that builds
modules without ``CONFIG_MODULE_SIG``, and tells it from the running
kernel, since a target need not have ``/proc/config.gz``: from a BTF
function only the option builds, ``__module_address`` for
``CONFIG_MODULES`` and ``mod_verify_sig`` for ``CONFIG_MODULE_SIG``.
Without ``CONFIG_MODULE_SIG``, ``module_sig_check()`` is a stub that
asks no LSM about an unsigned module.

The test kernel configuration sets these options and the
additional options the test fixtures and VM need.

Kernel command line
-------------------

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Parameter
     - Why
   * - ``bpf.keyring_unsealed=1``
     - The kernel leaves ``.bpf`` open for ``init`` to enroll and seal,
       and refuses user keyrings for signed loads. Without it, the
       keyring is sealed empty at boot and ``init`` fails.
   * - ``dm_verity.keyring_unsealed=1``
     - The kernel leaves ``.dm-verity`` open for ``init`` to enroll the
       config verification certificates and seal.
   * - ``lsm=`` including ``bpf``
     - When ``CONFIG_LSM`` does not include it.

``shirudo-gen-initrd --print-cmdline`` prints the two keyring parameters.
Both belong on the UKI's authenticated command line.
