..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

Interoperability
================

On a target where shirudo enforces, its LSM programs refuse operations
that other software on the host may rely on. This page lists them by
area. Each entry names the mechanism, what the other software sees, the
tamper counter that moves, and what to do. The refusals start when
``init`` attaches the guards in the initrd and last until the next boot.
:doc:`/internals/enforcement` describes every hook, and
:doc:`/security/tamper-counters` every counter.

``lsm/bpf`` runs before the kernel checks capabilities, so unprivileged
processes move counters too. Software that probes for BPF support at
startup, systemd among it, moves several counters on every target, which
is why
:doc:`/operate/run/read-status` asks you to learn the baseline of your hosts.

Other BPF users
---------------

:Mechanism: After ``init``, a program load from userspace passes
   ``lsm/bpf`` only as a ``BPF_PROG_TYPE_SYSCALL`` loader with a
   signature, and ``lsm/bpf_prog_load`` only when the kernel verified
   that signature against the ``.bpf`` keyring ``init`` froze. Map
   creation, map writes, test runs, attaching and pinning are reserved to
   tasks with runtime authority, which only an exec of a file on the
   runtime image grants. ``lsm/bpf_map`` refuses every map descriptor to
   other tasks. Every ``bpf()`` command that shirudo has not classified
   is refused.
:Still allowed: ``BPF_PROG_GET_FD_BY_ID``, ``BPF_BTF_GET_FD_BY_ID``,
   ``BPF_OBJ_GET_INFO_BY_FD``, the ``*_GET_NEXT_ID`` commands,
   ``BPF_PROG_QUERY``, ``BPF_TASK_FD_QUERY``, and lookups through a map
   descriptor a process already holds. Classic BPF, as seccomp filters
   and ``SO_ATTACH_FILTER`` in libpcap use it, does not go through
   ``bpf()`` and is not affected.
:What to do: Plan a target as a host where only signed upatches run BPF.
   Keep BPF-based agents, network plugins and tracing tools off
   enforcing targets, or ship what they do as upatches
   (:doc:`/upatches/index`). Run one-off investigations with bcc or
   bpftrace on a host that does not enforce.

Each refused call fails with ``EACCES`` (``Permission denied``). The
program load rows apply to every task, the others to tasks without
runtime authority:

.. list-table::
   :header-rows: 1
   :widths: 58 42

   * - Call
     - Counter
   * - ``BPF_PROG_LOAD`` of any type other than ``BPF_PROG_TYPE_SYSCALL``
     - ``LoadNotLoader``
   * - ``BPF_PROG_LOAD`` of a ``BPF_PROG_TYPE_SYSCALL`` program without a
       signature
     - ``LoadUnsigned``
   * - ``BPF_PROG_LOAD`` of a loader whose signature the kernel did not
       verify against the ``.bpf`` keyring ``init`` froze, for example
       one signed by a key the target does not trust
     - ``LoadUnverified``, ``LoadKeyringKind`` or ``LoadKeyring``
   * - ``BPF_MAP_CREATE``
     - ``MapCreate``
   * - ``BPF_MAP_UPDATE_ELEM``, ``BPF_MAP_FREEZE``
     - ``MapWrite``
   * - A writable map descriptor
     - ``MapFdWrite``
   * - ``BPF_OBJ_GET``, ``BPF_MAP_GET_FD_BY_ID``,
       ``BPF_LINK_GET_FD_BY_ID``, a read-only map descriptor, opening a
       pin in shirudo's private bpffs, an XDP program descriptor
     - ``ObjGet``
   * - ``BPF_LINK_CREATE``, ``BPF_RAW_TRACEPOINT_OPEN``
     - ``ProgAttach``
   * - ``BPF_OBJ_PIN``
     - ``ObjPin``
   * - ``BPF_PROG_TEST_RUN``
     - ``ProgRun``
   * - The ``PERF_EVENT_IOC_SET_BPF`` ioctl
     - ``PerfAttach``
   * - Every other command, among them ``BPF_TOKEN_CREATE``,
       ``BPF_BTF_LOAD``, ``BPF_LINK_DETACH``, ``BPF_LINK_UPDATE``,
       ``BPF_PROG_ATTACH``, ``BPF_PROG_DETACH``, ``BPF_ITER_CREATE`` and
       ``BPF_MAP_DELETE_ELEM``
     - ``BpfCommand``

What common software sees:

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Software
     - Effect
   * - Loaders built on libbpf
     - A recent libbpf first tries to create a BPF token from
       ``/sys/fs/bpf`` (``BpfCommand``), then loads a trivial program to
       see whether loading works (``LoadNotLoader``). The load fails and
       libbpf logs ``Couldn't load trivial BPF program``.
   * - ``bpftool``
     - ``prog show``, ``prog dump``, ``cgroup`` and ``perf`` work,
       because programs and queries stay readable. ``map show``,
       ``link show`` and ``btf show`` stop at the first map or link with
       ``Error: can't get map by id (<id>): Permission denied`` or the
       same for a link. ``net show`` prints that error for every link
       and goes on. Each refused id moves ``ObjGet``. The column of
       owning processes needs an iterator program, whose refusal
       ``bpftool`` does not print but the counters record. ``--bpffs``
       tries every pin in every bpffs mount, and each pin of shirudo's
       moves ``ObjGet``.
   * - ``perf``
     - Counting and sampling without BPF work. Options that load BPF
       programs, such as ``perf stat --bpf-counters``, ``perf record
       --off-cpu`` and ``perf lock contention --use-bpf``, fail. Events
       bound to a shirudo task are refused, see `Debuggers, tracing and
       /proc`_.
   * - bcc, bpftrace
     - Fail at their first map creation or program load. Nothing they
       compile runs.
   * - Cilium and other BPF datapaths
     - The agent cannot create its maps or load its programs, so the
       datapath does not come up.
   * - Tetragon, Falco's eBPF drivers
     - Cannot load their programs. Falco's kernel module driver loads
       when it is signed with a key the kernel trusts, see `Module
       loading and kernel live patching`_.
   * - XDP and tc programs from ``ip`` and ``tc``, sched_ext schedulers,
       HID-BPF
     - The program load is refused.
   * - systemd
     - Starts units without its BPF-based settings, see the next section.

systemd's BPF-based settings
----------------------------

:Mechanism: systemd probes whether BPF works when a manager starts: the
   system manager at boot and at every re-execution, including the switch
   from the initrd to the root file system, and every user manager. The
   probes load programs, which ``init`` has already closed off. systemd
   then treats the features as unsupported for the lifetime of that
   manager and starts units without them. This section describes
   systemd 262.
:Symptom: The units start. Their BPF-based restrictions do not hold.
   Each refused probe moves a counter: ``LoadNotLoader`` for the program
   loads, ``MapCreate`` for the map ``RestrictFileSystems=`` creates, and
   ``BpfCommand`` for other commands, such as libbpf's token attempt.
:What to do: Do not rely on these settings on a target. Enforce address
   and interface policy with nftables, or with a signed upatch of the
   ``cgroup_skb`` or ``netfilter`` attach kind
   (:doc:`/upatches/write/attach-kinds`). No upatch attach kind covers cgroup
   device programs.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Setting
     - On an enforcing target
   * - ``IPAddressAllow=``, ``IPAddressDeny=``, ``IPAccounting=``,
       ``IPIngressFilterPath=``, ``IPEgressFilterPath=``
     - Not applied. For the first unit that uses them, the manager logs
       ``unit configures an IP firewall, but the local system does not
       support BPF/cgroup firewalling.``
   * - ``DeviceAllow=``, ``DevicePolicy=``
     - Not applied. On cgroup v2 the device controller exists only as a
       ``BPF_PROG_TYPE_CGROUP_DEVICE`` program.
   * - ``BPFProgram=``
     - Not applied.
   * - ``SocketBindAllow=``, ``SocketBindDeny=``,
       ``RestrictNetworkInterfaces=``, ``BindNetworkInterface=``
     - Not applied. The manager logs the failed probe at debug level
       only.
   * - ``RestrictFileSystems=``
     - Not applied. At startup the system manager logs
       ``bpf-restrict-fs: Failed to create BPF map: Permission denied``.

Seccomp filters and shirudo's own commands
------------------------------------------

:Mechanism: The seal grants runtime authority at an exec of a file on
   the runtime image only when the task is not traced and has no seccomp
   filter, so that neither a debugger nor a filter installed beforehand
   controls the new process. ``lsm.s/bprm_check_security`` refuses such
   an exec. A seccomp filter passes to every child and survives exec.
:Symptom: Running the runtime ``shirudo`` fails with ``EACCES``
   (``Permission denied``). No counter moves.
:Affected: systemd unit settings that install a seccomp filter, among
   them ``SystemCallFilter=``, ``SystemCallArchitectures=``,
   ``SystemCallLog=``, ``RestrictAddressFamilies=``,
   ``RestrictNamespaces=``, ``RestrictRealtime=``,
   ``RestrictSUIDSGID=``, ``LockPersonality=``,
   ``MemoryDenyWriteExecute=``, ``PrivateDevices=``, ``ProtectClock=``,
   ``ProtectHostname=yes``, ``ProtectKernelTunables=``,
   ``ProtectKernelModules=`` and ``ProtectKernelLogs=``, on a unit that
   runs shirudo or on any unit whose processes start it. A container with
   a seccomp profile. systemd's ``RestrictFileSystemAccess=``: with it
   enabled, systemd 262 installs a seccomp filter in PID 1, which every
   later process on the host inherits, so no runtime command can run at
   all. This last case is a reading of the systemd 262 source and is not
   tested.
:What to do: Add none of these settings to shirudo's units or to their
   drop-ins (:doc:`/reference/systemd-units`). Do not enable
   ``RestrictFileSystemAccess=`` on a target. Run shirudo commands from a
   root shell or a unit without a seccomp filter.

BPF loaded before init
----------------------

:Mechanism: Before ``init`` attaches ``lsm/bpf`` in the initrd, any
   process can load and attach BPF, and what it attaches stays (R7 in
   :doc:`/security/threat-model`). It stays as long as something holds
   it: a pin, an open descriptor, or an attachment that needs neither,
   such as ``BPF_PROG_ATTACH`` to a cgroup. In-kernel loaders, such as
   the ``bpf_preload`` module, pass the gates at any time (R18).
:Symptom: After ``init``, the owner of such a program can no longer
   detach it with ``bpf()`` (``BpfCommand``), write or delete map
   elements (``MapWrite``, ``BpfCommand``), or reopen its maps and links
   by pin or by id (``ObjGet``). It can still look up elements through a
   map descriptor it holds, close descriptors, and remove its pins from
   any bpffs other than shirudo's, which releases the object when nothing
   else holds it. systemd's manager re-executes at the switch to the root
   file system and sets up its BPF features again after ``init``, so the
   previous section applies to them.
:What to do: Keep the initrd free of BPF loaders you do not trust. The
   initrd is part of the trusted computing base, and its PCR 9 and
   PCR 11 measurements are what a verifier pins (:doc:`/operate/run/attest`).

systemd-keyring-setup
---------------------

:Mechanism: systemd 263 adds ``systemd-keyring-setup``. It runs in the
   initrd before ``shirudo-initrd.service`` and again on the root file
   system, enrolls certificates of its own, and seals ``.bpf``,
   ``.dm-verity`` and ``.fs-verity`` with a chain restriction, also when
   it has no certificate to enroll. ``init`` enrolls the config
   certificate and the BPF signers itself and seals both keyrings against
   every further key. It refuses a keyring that another task sealed or
   filled first, and shirudo does not adopt the keyrings that tool set
   up.
:Symptom: ``init`` fails in the initrd. It stops at the ``.dm-verity``
   keyring with one of
   ``initrd boot keys: add config verification certificate: <error>``,
   ``initrd boot keys: check dm-verity verification keys: Key was rejected
   by service`` or, when the tool enrolled
   nothing, ``initrd boot keys: dm-verity keyring sealed empty at boot;
   boot with dm_verity.keyring_unsealed=1: Required key not available``,
   which names the boot parameter even when it is set. ``init: BPF
   keyring initialization failed`` follows. The boot then continues
   without enforcement (U11). If ``init`` ran first, the tool's run on
   the root file system is refused by ``lsm/key_permission`` and moves
   ``KeyringWrite``.
:What to do: Keep ``systemd-keyring-setup`` off targets: do not install
   it in the initrd or on the root file system, or mask its unit in both.

kexec and kdump
---------------

:Mechanism: ``lsm/kernel_load_data`` and ``lsm/kernel_read_file`` refuse
   every kexec image and kexec initramfs to every task, shirudo included,
   through ``kexec_load(2)`` and ``kexec_file_load(2)`` alike. A crash
   kernel goes through the same checks. A kexec would boot a kernel of
   the caller's choosing while the TPM keeps this boot's register and
   PCRs.
:Symptom: The load fails with ``EPERM`` (``Operation not permitted``)
   and moves ``Kexec``. The kdump service cannot load its crash kernel,
   and ``systemctl kexec`` fails.
:What to do: Plan targets without kdump. Use crash capture that needs no
   second kernel, such as pstore, which shirudo does not hook. Reboot
   through the firmware instead of kexec.

Shutdown initramfs and soft reboot
----------------------------------

:Mechanism: The mount guards keep the private bpffs and every mount above
   it in place in the host's mount namespace, so that nothing detaches
   the pins (R3 in :doc:`/security/threat-model`). Host PID 1 is exempt
   only while it switches from the initrd root to the root file system,
   and the exemption ends when it has unmounted the initrd root. From
   then on ``lsm/sb_mount`` refuses every caller a legacy request to make
   ``/`` or another mount above the bpffs private and a legacy
   ``MS_MOVE`` in that namespace, and ``lsm/sb_pivotroot`` every pivot
   there. systemd changes root a second time in two places, both as
   PID 1: ``systemd-shutdown`` returns to a shutdown initramfs unpacked
   at ``/run/initramfs``, and a soft reboot enters ``/run/nextroot``.
   Each begins by making ``/`` recursively private, then pivots, then
   falls back to ``MS_MOVE``.
:Symptom: Every shutdown moves ``BpffsMount`` once: ``systemd-shutdown``
   asks for private mounts before it unmounts, logs ``Failed to make
   mounts private, ignoring`` and goes on. With an executable
   ``/run/initramfs/shutdown`` it then logs ``Failed to set "/" mount
   propagation to private: Operation not permitted`` and ``Failed to
   switch root to "/run/initramfs"``, moves ``BpffsMount`` again, does
   not run the shutdown initramfs and reboots, halts or powers off from
   the root file system. Storage below the root that only the shutdown
   initramfs detaches, such as device mapper, MD RAID or a network block
   device, is not detached before the reset. ``systemctl soft-reboot``
   with an operating system tree at ``/run/nextroot`` logs ``Failed to
   switch root, trying to continue`` and restarts userspace on the root
   it had. A caller that reaches the pivot is refused with ``EPERM`` and
   moves ``BpffsUmountAbove``. This is a reading of the hooks and of the
   systemd 259 source and is not tested on a target; ``t6158`` covers
   the refusals themselves.
:What to do: Do not rely on a shutdown initramfs on targets, and choose
   root storage that is consistent once ``systemd-shutdown`` has
   remounted it read-only. Do not place a tree at ``/run/nextroot``:
   change the root file system with a full reboot, which also gives the
   new root a boot of its own to be measured in. Count the shutdown's
   ``BpffsMount`` into the baseline of your hosts.

Module loading and kernel live patching
---------------------------------------

:Mechanism: shirudo loads signed modules only.
   ``lsm/kernel_load_data`` and ``lsm/kernel_read_file`` let every load
   other than a kexec image or initramfs through, and the kernel checks
   the module's signature. When the signature is missing or the kernel
   cannot verify it, and the kernel does not refuse the module itself,
   it asks lockdown, and ``lsm/locked_down`` refuses it from ``init`` on
   (A4 in :doc:`/security/threat-model`). A livepatch module, as kpatch
   or the kernel's ``klp-build`` produce, is a kernel module like any
   other.
:Symptom: ``init_module(2)`` and ``finit_module(2)`` of an unsigned
   module fail with ``EPERM`` (``modprobe`` prints ``Operation not
   permitted``), and the integrity counter ``ModuleSignature`` counts
   it. ``modprobe --force``, which strips the version checks, makes a
   signed module count as unsigned.
:What to do: Build the kernel with ``CONFIG_MODULE_SIG``, as
   :doc:`/operate/plan/hardening` lists and the pre-flight check
   ``module_signatures`` requires, and sign every module the
   target loads, livepatch modules included, with a key the kernel
   trusts. A signed module runs as kernel code outside every shirudo
   check. Unloading a
   module that a kprobe upatch targets leaves the upatch loaded and
   measured but without effect, a reading of the kernel source (R21).
   shirudo's tests do not cover a livepatch and a upatch on the same
   function.

Other LSMs
----------

:Mechanism: The kernel calls the active LSMs in the order of ``lsm=``,
   or ``CONFIG_LSM`` without it, and stops at the first refusal
   (:doc:`/concepts/background/bpf-lsm`). shirudo's programs pass an
   earlier refusal on unchanged. The pre-flight check ``bpf_lsm_active``
   checks that ``bpf`` is in the list, not where.
:Order: Either order refuses what any active LSM refuses. The order
   decides who sees the attempt. With ``bpf`` after SELinux, AppArmor,
   Smack or Landlock, an operation one of them refuses never reaches
   shirudo's programs and moves no counter. With ``bpf`` before them,
   shirudo's refusal ends the walk and the other LSM does not see or log
   the attempt.
:Seal labels: With the kernel project patch, the seal reads a file's
   label as the in-kernel LSMs read theirs, without the caller's read
   permission, and no other LSM's ``inode_permission`` policy can hide
   it. On an upstream kernel the kfunc checks that permission, every
   LSM that implements the hook takes part, SELinux and Smack among
   them, and a policy that grants write or unlink but refuses read
   makes a sealed file without a mark look unlabeled (see the seal in
   :doc:`/security/threat-model`).
:Policies: shirudo ships no SELinux, AppArmor or Smack policy. A policy
   that confines shirudo's processes must allow what they use, among it
   ``bpf()``, mounts under ``/run/shirudo``, loop and device-mapper
   devices, the ``.bpf`` and ``.dm-verity`` keyrings, the TPM device and
   the ``security.bpf.shirudo`` extended attributes.
:What to do: Run no other LSM whose policy root can change at runtime.
   Choose the order by which LSM you want to account for refusals.

Hibernation and suspend
-----------------------

:Mechanism: shirudo refuses hibernation from ``init`` on:
   ``lsm/locked_down`` refuses the kernel's hibernation check, and
   ``lsm/file_open`` the write of the ``HibernateLocation`` EFI variable
   from which systemd's initrd would resume (A9 in
   :doc:`/security/threat-model`). The behavior of the register across
   hibernation is not analyzed. Before a suspend, the kernel's TPM
   driver sends ``TPM2_Shutdown(STATE)`` to a TPM 2.0 unless the TPM
   stays powered, and the TPM counts that in its restart count
   (:doc:`/concepts/background/tpm`). The config activation record holds
   the TPM's reset count, which a resume leaves, so the TPM boot goes on;
   a command the suspend interrupts sees the restart count move and
   refuses.
:Symptom: ``/sys/power/state`` lists no ``disk``, and ``systemctl
   hibernate`` fails as hibernation is not supported. After a resume
   from suspend, shirudo commands run as before. A config activation
   that was pending stays pending, and every state-changing command
   refuses, until the next reboot; ``shirudo init`` run by hand does not
   end it. The test VM, with suspend support added to its kernel, shows
   this in the ``deep`` (S3) mode of ``/sys/power/mem_sleep``, on
   QEMU 8.2's ``q35`` machine with SeaBIOS 1.16.3 and swtpm 0.7.3:
   SeaBIOS sends ``TPM2_Startup(STATE)`` on resume, and the restart
   count goes up while the reset count, the PCRs and the register stay.
   ``upatch load``, ``upatch unload`` and ``attest`` run, and ``attest
   verify`` accepts the evidence. With an activation pending, ``init``,
   ``upatch load``, ``upatch unload`` and ``attest`` print ``Operation
   now in progress`` and exit 1, and the next reboot completes the
   activation. Firmware that sends ``TPM2_Startup(CLEAR)`` on resume
   makes it a TPM restart instead, which
   :doc:`/operate/maintain/backup-recovery` describes. The ``s2idle``
   mode is not tested.
:What to do: Turn hibernation off as :doc:`/operate/plan/hardening` lists, and
   keep targets from sleeping, for example with ``AllowSuspend=no`` and
   ``AllowHibernation=no`` in ``/etc/systemd/sleep.conf``. After an
   unplanned resume with an activation pending, reboot; see
   :doc:`/operate/maintain/backup-recovery`.

Containers and Kubernetes
-------------------------

:BPF: The gates apply in every namespace. ``BPF_TOKEN_CREATE`` is refused
   (``BpfCommand``), so a bpffs mounted with ``delegate_cmds=`` and its
   kin gives a container nothing. A container may mount a bpffs of its
   own, but nothing can be pinned there (``ObjPin``).
:Device rules: On cgroup v2, container runtimes and systemd enforce
   device access with ``BPF_PROG_TYPE_CGROUP_DEVICE`` programs, and their
   loads are refused (``LoadNotLoader``). How a runtime reacts is up to
   the runtime: test yours on an enforcing target.
:Networking: A network plugin built on BPF cannot run. Use one that does
   not need BPF.
:Mounts: The ``/run/shirudo`` tmpfs, the private bpffs and the runtime
   and config image mounts, and their copies in every other mount
   namespace, cannot be unmounted or remounted one by one, and no task
   without runtime authority mounts over them. The calls fail with
   ``EPERM``, which ``umount(8)`` reports as ``must be superuser to
   unmount``. They move ``BpffsUmount`` or ``BpffsMount`` for the bpffs
   and no counter for the others. An unmount of a mount above them in
   another namespace is refused only when it propagates into the bpffs
   mount of ``init``'s namespace or a mount above it
   (``BpffsUmountAbove``). Tearing a namespace down is not affected. R3
   in :doc:`/security/threat-model` lists the mount operations the guards
   do not see.
:Pins: Directories of the private bpffs stay listable. Opening a pin is
   refused (``ObjGet``).
:What to do: Run shirudo commands on the host, not in a container.
   Inside a container with a seccomp profile they cannot run at all, see
   `Seccomp filters and shirudo's own commands`_.

Debuggers, tracing and /proc
----------------------------

:Mechanism: The seal marks a task at its exec of a runtime file, and a
   fork inherits the mark. ``lsm/ptrace_access_check`` refuses every
   ptrace access check against a marked task, both attach and read
   modes, but counts only attach mode, and ``lsm/perf_event_alloc`` refuses a perf event bound to one.
   An exec of a runtime file by a traced task is refused. The ptrace
   check runs after the kernel's own user and capability checks, so only
   root, or a caller running as the same user, reaches it.
:Symptom: See the table below.
:What to do: Debug shirudo where it does not enforce, such as the test
   VM (:doc:`/contribute/testing/testing`). A read-mode refusal shows
   only as ``EACCES`` to the caller, never in ``SealPtrace``.

.. list-table::
   :header-rows: 1
   :widths: 46 30 24

   * - Action
     - Result
     - Counter
   * - ``gdb --pid``, ``strace --attach`` on a running shirudo command
     - ``EACCES``
     - ``SealPtrace``
   * - Starting shirudo under ``strace`` or ``gdb``
     - The exec fails with ``EACCES``
     - ``ExecTraced``
   * - Starting shirudo from a process that shares its root and working
       directory with another, made with ``clone(CLONE_FS)``
     - The exec fails with ``EACCES``
     - ``ExecShared``
   * - Reading ``/proc/<pid>/mem`` of a shirudo command
     - ``EACCES``
     - ``SealPtrace``
   * - Reading ``/proc/<pid>/exe``, ``environ``, ``maps`` or the ``fd``
       links of a shirudo command
     - ``EACCES``
     - None
   * - Reading ``/proc/<pid>/stat`` of a shirudo command, as ``ps`` and
       ``top`` do
     - Succeeds, with the fields that need the check zeroed
     - None
   * - journald receiving a log line from a shirudo command
     - journald cannot read ``/proc/<pid>/exe``, so the entry has no
       ``_EXE=`` field
     - None
   * - ``perf record --pid``, ``perf stat --pid`` on a shirudo command
     - ``EACCES``
     - ``SealPerf``
   * - System-wide ``perf``, tracefs and kprobe events
     - Not refused
     - none

A task-bound perf event that a process opened before the exec that marks
the task is not refused (D9 in :doc:`/security/threat-model`).

XFS dump and restore
--------------------

:Mechanism: ``lsm/file_ioctl`` refuses ``XFS_IOC_ATTRMULTI_BY_HANDLE``
   on an XFS file system to every task without runtime authority, since
   XFS changes the attributes a handle names without passing an xattr
   hook, and a seal label removed that way would unseal the inode.
:Symptom: ``xfsdump`` and ``xfsrestore``, which read and write extended
   attributes through that ioctl, fail on the attributes with
   ``EACCES``, and ``XattrHandle`` moves.
:Not refused: Reading and writing attributes through ``getfattr``,
   ``setfattr`` and the other xattr system calls, which the seal checks
   as it checks every xattr change.
:What to do: Back up XFS file systems on a target with a tool that reads
   attributes through the xattr system calls, or without extended
   attributes.

TPM tools
---------

:Mechanism: ``lsm/tpm_command`` sees every command written to
   ``/dev/tpm0`` and ``/dev/tpmrm0``. It refuses ``TPM2_NV_Extend`` of
   shirudo's register, NV index ``0x01818E00``, to every task without
   runtime authority. shirudo itself reaches the TPM through
   ``device:/dev/tpmrm0`` by default, the kernel's resource manager, and
   on a target refuses a TCTI that is not a ``device:`` one, which rules
   out a userspace resource manager such as ``tpm2-abrmd``.
:Symptom: ``tpm2_nvextend`` of that index fails: the write to the device
   returns ``EACCES`` and ``TpmExtend`` moves. Every other command works:
   reading PCRs and NV indices, quotes, keys, other NV indices.
:Not refused: Extending PCRs, which a verifier then sees in PCR 9 or the
   config PCR (R4, R11), and undefining the register with the owner
   password, after which measuring commands refuse until the next TPM
   reset (R20).
:What to do: Keep other software from measuring into PCR 9, PCR 11 and
   the config PCR, and keep the owner password from tools that do not
   need it.

Keyrings and keyctl
-------------------

:Mechanism: ``lsm/key_permission`` guards the ``.bpf`` and
   ``.dm-verity`` keyrings and the keys in them. It refuses write,
   set-attribute and unlink to every task without runtime authority, and
   a search through a reference the caller does not possess, which is
   how ``keyctl`` reaches a key by its serial. The kernel's own search
   during signature verification stays open.
:Symptom: ``keyctl add``, ``link``, ``unlink``, ``clear``, ``revoke``,
   ``invalidate``, ``setperm``, ``chown`` and ``restrict_keyring`` on
   these keyrings or their keys fail with ``EACCES`` and move
   ``KeyringWrite``. shirudo does not refuse reading them, as ``keyctl
   show``, ``list``, ``describe`` and ``read`` do.
:What to do: Keep tools that manage these keyrings off targets. They
   conflict with ``init`` as `systemd-keyring-setup`_ does.

Related
-------

- :doc:`/security/threat-model`
- :doc:`/security/tamper-counters`
- :doc:`/operate/plan/hardening`
- :doc:`/operate/run/read-status`
- :doc:`/operate/troubleshoot/troubleshooting`
