..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: upatch authors

Attach kinds
============

The section name of a program decides where it attaches. ``shirudo build``
reads it, refuses the sections below the table, and records the attach
kind and target in the signed attach metadata. After the signed loader
has created the programs, ``shirudo upatch load`` attaches each one, checks
the link against the metadata and pins it.

.. list-table::
   :header-rows: 1
   :widths: 27 18 33 22

   * - Section
     - Program type
     - Attached by
     - Target kernel needs
   * - ``fentry/<function>``, ``fentry.s/<function>``
     - tracing
     - ``BPF_RAW_TRACEPOINT_OPEN``
     - the base requirements
   * - ``fexit/<function>``, ``fexit.s/<function>``
     - tracing
     - ``BPF_RAW_TRACEPOINT_OPEN``
     - the base requirements
   * - ``fmod_ret/<function>``, ``fmod_ret.s/<function>``
     - tracing
     - ``BPF_LINK_CREATE``, ``BPF_MODIFY_RETURN``
     - ``CONFIG_FUNCTION_ERROR_INJECTION`` for functions marked for error
       injection
   * - ``lsm/<hook>``, ``lsm.s/<hook>``
     - LSM
     - ``BPF_LINK_CREATE``, ``BPF_LSM_MAC``
     - the base requirements
   * - ``tp_btf/<tracepoint>``
     - tracing
     - ``BPF_RAW_TRACEPOINT_OPEN``
     - the base requirements
   * - ``kprobe/<symbol>``, ``kprobe/<symbol>+<offset>``
     - kprobe
     - ``perf_event_open`` on the kprobe PMU, ``BPF_LINK_CREATE``,
       ``BPF_PERF_EVENT``
     - ``CONFIG_KPROBES``, ``CONFIG_KPROBE_EVENTS``
   * - ``kretprobe/<symbol>``
     - kprobe
     - as ``kprobe``, with the return-probe bit set
     - ``CONFIG_KPROBES``, ``CONFIG_KPROBE_EVENTS``
   * - ``uprobe/<path>:<function>[+<offset>]``, ``uprobe/<path>:0x<offset>``,
       their ``uprobe.s`` forms
     - kprobe
     - ``perf_event_open`` on the uprobe PMU, ``BPF_LINK_CREATE``,
       ``BPF_PERF_EVENT``
     - ``CONFIG_UPROBE_EVENTS``
   * - ``uretprobe/<path>:<function>``, ``uretprobe/<path>:0x<offset>``,
       their ``uretprobe.s`` forms
     - kprobe
     - as ``uprobe``, with the return-probe bit set
     - ``CONFIG_UPROBE_EVENTS``
   * - ``uprobe.multi/<path>:<glob>``, ``uprobe.multi.s/<path>:<glob>``
     - kprobe
     - ``BPF_LINK_CREATE``, ``BPF_TRACE_UPROBE_MULTI``,
       ``BPF_F_UPROBE_MULTI_PATH_FD``
     - ``CONFIG_UPROBE_EVENTS``
   * - ``uretprobe.multi/<path>:<glob>``,
       ``uretprobe.multi.s/<path>:<glob>``
     - kprobe
     - as ``uprobe.multi``, with ``BPF_F_UPROBE_MULTI_RETURN``
     - ``CONFIG_UPROBE_EVENTS``
   * - ``cgroup_skb/ingress``, ``cgroup_skb/egress``
     - cgroup skb
     - ``BPF_LINK_CREATE`` on ``/sys/fs/cgroup``,
       ``BPF_CGROUP_INET_INGRESS`` or ``BPF_CGROUP_INET_EGRESS``
     - ``CONFIG_CGROUP_BPF``, cgroup v2 at ``/sys/fs/cgroup``
   * - ``netfilter``
     - netfilter
     - ``BPF_LINK_CREATE``, ``BPF_NETFILTER``, IPv6 pre-routing
     - ``CONFIG_NETFILTER``, ``CONFIG_NETFILTER_BPF_LINK``
   * - ``xdp/<decimal-mask>``
     - XDP
     - ``BPF_LINK_CREATE``, ``BPF_XDP``, native driver mode
     - native XDP and multi-buffer support on selected devices
   * - ``syscall``, named ``shirudo_serialize__<map>``
     - syscall
     - not attached, run by ``shirudo upatch map``
     - the base requirements
   * - ``syscall``, named ``shirudo_test__<id>``
     - syscall
     - not attached, run once at load
     - the base requirements

The base requirements are the kernel options shirudo itself needs, listed
in :doc:`/operate/plan/system-requirements`. They include BPF trampolines, BTF
and the BPF LSM, which is why the BTF-based kinds need nothing more.

Every attached program becomes one link pinned at
``/run/shirudo/bpffs/upatches/<name>/link`` when the upatch has one attach
program, and at ``link_0``, ``link_1`` and so on, in the order of the
object, when it has several. ``<name>`` has every ``.`` written as ``~d``.
An upatch containing XDP always uses ``link_0``, ``link_1`` and so on,
because one program can attach to several interfaces.

fentry and fexit
----------------

``fentry`` runs at the entry of a kernel function with its arguments,
``fexit`` at its return with the arguments and the return value. Write
the program with ``BPF_PROG()`` and the function's parameters. The
verifier checks the prototype against the kernel's BTF.

The signed loader looks the function up in the target's BTF and loads the
program with that BTF id as its attach target. shirudo then calls
``BPF_RAW_TRACEPOINT_OPEN`` with no name, so the kernel attaches at the
BTF id the program carries. A function that is not in the target's BTF,
often because the compiler inlined it, fails inside the loader, as
``verifier_rejected`` in phase ``payload_load``, and never reaches the
attach step.

``fentry.s`` and ``fexit.s`` declare sleepable programs. The kernel admits
them only on functions it allows to sleep in, such as those on its
error-injection list.

fmod_ret
--------

``fmod_ret`` runs at the entry of a function. A non-zero return skips the
function body, and the caller receives that value. This is the kind for a
shield that refuses a call before the vulnerable code runs.

shirudo attaches with ``BPF_LINK_CREATE`` and attach type
``BPF_MODIFY_RETURN``, without a fallback. The kernel admits ``fmod_ret``
only on ``security_*`` hooks, on system call entry points and on
functions marked for error injection or return modification. The
error-injection marks take effect only with
``CONFIG_FUNCTION_ERROR_INJECTION``. On any other function the load fails
in phase ``payload_load``. ``fmod_ret.s`` declares the sleepable variant.

The kernel skips a run of an ``fmod_ret`` program that is already running
on the CPU, and the call then goes through. :doc:`pitfalls` says when, and
why an ``lsm`` program is the place to refuse an operation where a hook
covers it.

lsm
---

``lsm/<hook>`` attaches a program to the LSM hook ``security_<hook>``
calls, for example ``lsm/file_open`` or ``lsm/socket_connect``. The
program receives the hook's arguments and the return value of the BPF LSM
programs that ran before it on the same hook. A non-zero return on a hook
that returns ``int`` refuses the operation. ``lsm.s/<hook>`` declares a
sleepable program, which the kernel admits only on hooks it lists as
sleepable.

shirudo attaches with ``BPF_LINK_CREATE`` and ``BPF_LSM_MAC``. Every
target that runs shirudo has the BPF LSM active, because shirudo's own
enforcement programs are LSM programs.

tp_btf
------

``tp_btf/<tracepoint>`` attaches to a kernel tracepoint, for example
``tp_btf/sched_process_exec``, and receives the tracepoint's raw
arguments with their BTF types. Tracepoints are stable observation points
that the kernel maintains on purpose.

The loader resolves the tracepoint by BTF, and shirudo attaches with
``BPF_RAW_TRACEPOINT_OPEN`` as for ``fentry``.

kprobe and kretprobe
--------------------

``kprobe/<symbol>`` and ``kretprobe/<symbol>`` attach at the entry or the
return of any kernel function that kallsyms lists, whether or not it is in
BTF. ``kprobe/<symbol>+<offset>`` probes an instruction inside the
function. The offset is decimal or ``0x`` hexadecimal. A leading zero is
refused rather than read as octal, and a ``kretprobe`` takes no offset.
The program reads its arguments from ``struct pt_regs``, so the source
defines the ``__TARGET_ARCH_*`` macro for ``bpf_tracing.h``.

shirudo reads the kprobe PMU's type from
``/sys/bus/event_source/devices/kprobe/type`` and, for a return probe, the
return-probe bit from ``.../kprobe/format/retprobe``, opens a perf event
for the symbol and offset, and attaches the program to it with
``BPF_LINK_CREATE`` and ``BPF_PERF_EVENT``.

A kprobe may call ``bpf_override_return()`` to refuse a call. The kernel
allows that only at the entry of a function on its error-injection list
and with ``CONFIG_BPF_KPROBE_OVERRIDE``. Elsewhere the kernel refuses
the link, and the load fails in phase ``link_create``.

uprobe and uretprobe
--------------------

``uprobe/<path>:<function>`` and ``uretprobe/<path>:<function>`` attach to
the entry or the return of one function in a userspace binary, in every
process, for example ``SEC("uprobe//usr/bin/example:fooFunc")``.
``<path>`` is absolute. ``uprobe/<path>:<function>+<offset>`` probes an
instruction inside the function; the offset is decimal or ``0x``
hexadecimal, a leading zero is refused rather than read as octal, and a
``uretprobe`` takes none. ``<path>:0x<offset>`` in place of a function
probes that file offset in the binary, for code no symbol names. The
program reads its arguments and, in a ``uretprobe``, the return value from
``struct pt_regs``, as a ``kprobe`` does.

The builder resolves the function as libbpf does, refusing a name that
matches no symbol or several at different addresses, adds the offset and
records the one file offset it gets with the binary's GNU build ID in the
signed metadata, as for ``uprobe.multi``. It refuses an offset that lies
outside the file, and one beyond 4 GiB, because the kernel reports a
uprobe link's offset in 32 bits.

On the target, shirudo opens and checks the binary as for
``uprobe.multi``, then reads the uprobe PMU's type from
``/sys/bus/event_source/devices/uprobe/type`` and, for a return probe, the
return-probe bit from ``.../uprobe/format/retprobe``, and opens a perf
event on every CPU for ``/proc/self/fd/<n>``, the descriptor it checked,
at the recorded offset. The kernel resolves that path to the inode
shirudo checked, not to whatever ``<path>`` names later. shirudo attaches
the program to the event with ``BPF_LINK_CREATE`` and ``BPF_PERF_EVENT``.

``uprobe.s`` and ``uretprobe.s`` declare sleepable programs, as the
``.s`` forms of ``uprobe.multi`` do, with the same attach kinds, 10 and 11.

uprobe.multi and uretprobe.multi
--------------------------------

``uprobe.multi/<path>:<glob>`` and ``uretprobe.multi/<path>:<glob>``
attach to the entry or the return of every function in a userspace binary
whose symbol matches the glob, in every process, for example
``SEC("uprobe.multi//usr/bin/example:*Func")``. ``<path>`` is absolute.
The glob has libbpf's syntax: ``*`` matches any sequence and ``?`` one
character. A return program reads the return value with
``PT_REGS_RC()``; by then the registers no longer hold the arguments.

These kinds are resolved on the operator host. The builder opens the binary
at ``<path>``, matches the glob against its function symbols, converts the
matches to sorted file offsets and records them with the binary's GNU
build ID in the signed metadata. It refuses a glob that matches nothing
and a binary without a build ID.

On the target, shirudo opens ``<path>``, requires a regular file, opens it
again through ``/proc/self/fd`` and compares device and inode, checks that
every offset lies inside the file, and compares the build ID. A different
binary fails with ``binary_mismatch`` in phase ``target_verify``, before
any BPF is loaded. shirudo keeps that descriptor open and attaches with
``BPF_LINK_CREATE``, ``BPF_TRACE_UPROBE_MULTI`` and
``BPF_F_UPROBE_MULTI_PATH_FD``, and ``BPF_F_UPROBE_MULTI_RETURN`` for
``uretprobe.multi``, so the probes land in the inode it checked, not in
whatever the path names later. There is no path fallback.

``uprobe.multi.s`` and ``uretprobe.multi.s`` declare sleepable programs,
which may call ``bpf_copy_from_user()`` and fault in the user memory they
read. They take the same attach kinds, 7 and 9: ``BPF_F_SLEEPABLE`` is a
load flag the signed loader sets, so the signature covers it, and the
target attaches them as it does the others.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Limit
     - Value
   * - path
     - absolute, shorter than 4096 bytes
   * - build ID
     - 1 to 64 bytes
   * - offsets per program
     - 1 to 1,048,576
   * - glob
     - one pattern, without ``,`` or ``|`` alternation

cgroup_skb
----------

``cgroup_skb/ingress`` and ``cgroup_skb/egress`` see every IP packet that
a socket on the host receives or sends, as a ``struct __sk_buff``. The
program returns 1 to pass the packet and 0 to drop it.

shirudo opens ``/sys/fs/cgroup`` and attaches with ``BPF_LINK_CREATE``
and ``BPF_CGROUP_INET_INGRESS`` or ``BPF_CGROUP_INET_EGRESS``, so the link
sits on the root of the unified cgroup hierarchy. The kernel runs every
program attached there and drops a packet if one of them says so.

netfilter
---------

``netfilter`` attaches a program as a netfilter hook for IPv6 at
``NF_INET_PRE_ROUTING`` with priority ``NF_IP6_PRI_RAW_BEFORE_DEFRAG``
(-450). The program runs before connection tracking and before IPv6
defragmentation, so it sees fragments as they arrive. It receives a
``struct bpf_nf_ctx`` and returns ``NF_ACCEPT`` or ``NF_DROP``.

shirudo fixes the family, hook and priority. The section name carries
none of them. A shield that needs another family or hook is written as a
``cgroup_skb`` or ``lsm`` program.

XDP
---

``xdp/<decimal-mask>`` signs a device-class selection, rather than a
device name or an ifindex. For example, ``SEC("xdp/3")`` selects network
ports and virtual devices; ``SEC("xdp/27")`` selects all classes. The
mask is mandatory, nonzero and contains only the bits below. Bare
``xdp``, ``xdp.frags``, devmap and cpumap sections are refused;
``xdp/<decimal-mask>`` already means multi-buffer.

A device runs one native XDP program at a time, so the XDP programs of
one upatch must select disjoint classes: ``shirudo build`` refuses
``SEC("xdp/3")`` beside ``SEC("xdp/2")``. ``bpm tree append`` refuses an
upatch that selects a class another upatch of the tree selects on the
same nodes. Two upatches loaded another way can still select the same
device. While such a device is there, the second one's ``upatch load``
fails with ``xdp_device_occupied``. When the device appears after both
loaded, reconcile attaches the first, ``status`` lists the device for
the second under ``XdpCovered`` as ``another XDP program attached``, and
the next boot restore fails on it.

.. list-table::
   :header-rows: 1
   :widths: 12 22 66

   * - Bit
     - Class
     - Devices
   * - 1
     - Network-facing
     - Hardware-backed NICs and physical devlink ports.
   * - 2
     - Virtual
     - Software interfaces, host tap devices, devlink representors and
       Xen netback interfaces in dom0.
   * - 8
     - VM
     - Guest adapters using virtio-net, vmxnet3, Hyper-V netvsc or Xen
       netfront. Emulated hardware and passthrough NICs use their
       hardware class.
   * - 16
     - Unknown
     - Devices without sufficient classification evidence. This bit is
       a catchall class, not a wildcard; 27 selects every class.

A shared class is checked at these places:

.. list-table::
   :header-rows: 1
   :widths: 24 46 30

   * - Place
     - Check
     - Result
   * - ``shirudo build``
     - Two XDP programs of one upatch select the same class.
     - The build is refused.
   * - ``upatch load``
     - The same, when the target reads the signed attach metadata of
       the artifact.
     - ``parser_rejected``
   * - ``bpm tree append``
     - An upatch selects a class another upatch of the tree selects on
       the same nodes.
     - The append is refused and nothing is published.
   * - ``upatch load``
     - None across loaded upatches. The kernel refuses the second link
       on a device both select.
     - ``xdp_device_occupied``, and the load is undone.

``upatch load`` does not compare the classes of the loaded upatches. It
would have to read and verify every loaded archive on each load, and the
checks above and the kernel's refusal already cover the case.

Bit 4 is not a class, and a mask with it is refused. Loopback has no
native XDP, so it has no class and no mask selects it. Every other
interface has exactly one class. A device on the ``xen-backend`` bus,
Xen's netback in dom0, is virtual: it is the host end of a guest's link,
though its driver is named ``vif`` as netfront's is. shirudo then checks
the driver names ``virtio_net``, ``vmxnet3``, ``hv_netvsc``,
``xen-netfront`` and ``vif`` for VM adapters, then ``netdevsim``, which
is virtual whatever its devlink port says. Next it uses devlink port
flavour: physical ports are network-facing; CPU, DSA, PCI PF, VF, SF
and virtual ports are virtual; other flavours are unknown. Without a
devlink port, a device with a hardware parent
bus is network-facing, a device with a kernel software link kind is
virtual, and the rest are unknown. Facts come from rtnetlink, devlink
and ethtool, without interface-name or sysfs heuristics.

At load and boot restore, shirudo snapshots interfaces in the initial
network namespace, selects matching classes and attaches in increasing
ifindex order. A veth pair gets one attachment: the endpoint in the
initial namespace when its peer is elsewhere, or the lower ifindex when
both ends are in that namespace. Peer namespace information prevents
equal ifindexes in separate namespaces from being mistaken for a pair.
Pairs entirely outside the initial namespace are excluded. Discovery
tolerates interfaces changing under it: a snapshot the kernel reports
as interrupted is retried, and an interface renamed or removed during
the snapshot, or a veth whose peer is not in it, is left out rather than
failing the load. So is a device whose driver name or devlink port
cannot be read, with a warning naming it: it need not be one the upatch
selects, so it does not fail the load or the boot restore, and
``status`` lists it under ``XdpCovered`` as ``not classified`` until a
later read succeeds, unless it runs the upatch. A lookup that cannot be
made at all, out of memory or descriptors, timed out, refused with
``EPERM`` or ``EACCES``, still fails the load: it would leave every
device out. A kernel that does not answer a netlink request within
5 seconds fails the load with ``ETIMEDOUT``, and is not asked again.

Links use ``XDP_FLAGS_DRV_MODE``: shirudo runs XDP in the driver only.
Generic XDP, which runs in the stack after the socket buffer is built,
is not supported, as it filters too late to be of use, so a driver
without native XDP is not covered. A device that runs a generic or
offloaded program, which shirudo never attaches, holds its XDP slot: it
is occupied like one running another driver-mode program, and ``status``
says ``another XDP program attached``. A device without native XDP, which
refuses with ``EOPNOTSUPP`` and reports no XDP features, such as a
bridge, is logged and skipped. Any other refusal is the driver ruling XDP
out in its current settings, and fails with the load category
``xdp_driver_refused``: ``EOPNOTSUPP`` from a device that reports native
XDP, as ``virtio_net`` gives while the host does GRO_HW or checksum
offload and ``bnxt`` with header-data split, ``EINVAL`` from ``mlx5``
with LRO or hardware GRO on, ``ENOSPC`` from a veth with fewer rx queues
than its peer has tx queues, and ``ERANGE`` from a driver whose MTU is
too large. The journal names the driver's own errno. A device that
changes or goes away during attachment is skipped too. An XDP program
with no device to attach to still loads: a pin of its own, ``xdp_prog_<i>``,
keeps it, and ``status`` shows it as ``xdp (waiting for a device)``. Other
errors undo the load's links, including an occupied XDP attachment point
or a driver refusing the program. Boot restore fails the same way, and
``init`` stops with the register unbound. Only a device that went away
during the restore is skipped. A device that an upatch restored before
this one holds fails the restore like any other, also one that reconcile
only warned about before the reboot. A setting root makes after boot is the reconcile pass's to meet,
which leaves the device unattached, warns, and lets ``status`` list it. Existing XDP
programs are never replaced. Device classification and peer identity
are rechecked around attachment, and the returned link's ifindex is
checked before pinning. A link the kernel reports on another device is
``attach_scope_mismatch`` and fails the load, the restore or the
reconcile pass, never a skipped device. The link reports no namespace:
the load checks its own before it reads the devices, and a run outside
the initial namespace fails as ``attach_scope_mismatch`` too.

Every XDP program is loaded with ``BPF_F_XDP_HAS_FRAGS``, so it can run on
a device whose MTU does not fit one buffer. A selected device with native
XDP must report multi-buffer support, ``NETDEV_XDP_ACT_RX_SG``. One that
does not fails ``upatch load`` with ``xdp_multibuf_unsupported``, and the
load is undone, so a single such device under the signed mask stops it:
narrow the mask. Boot restore fails on such a device too. Reconcile leaves
it unattached, logs a warning, and ``status`` lists it under
``XdpCovered``. In a tree, a failed ``add`` stops ``bpm tree sync`` at
that operation, so scope it with a node label.

These drivers report multi-buffer XDP in Linux bpf-next at 53435562a725:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Driver
     - Hardware or use
   * - ``veth``
     - Virtual Ethernet pairs
   * - ``virtio_net``
     - Virtio guest adapters, with mergeable receive buffers
   * - ``ice``, ``i40e``, ``idpf``
     - Intel
   * - ``mlx5``
     - NVIDIA ConnectX, with LRO and hardware GRO off
   * - ``bnxt``
     - Broadcom NetXtreme
   * - ``ionic``
     - AMD Pensando
   * - ``fbnic``
     - Meta
   * - ``atlantic``
     - Marvell (Aquantia) AQtion
   * - ``mvneta``
     - Marvell Armada, without hardware buffer management
   * - ``enetc``
     - NXP
   * - ``bonding``
     - When every slave supports it

The list is a guide. What counts is what the device reports when it is
attached, and that can depend on its configuration: a ``veth`` with fewer
rx queues than its peer has tx queues reports nothing. ``ena``, ``gve``,
``mana``, ``netvsc``, ``vmxnet3``, ``xen-netfront``, ``igb``, ``igc``,
``ixgbe`` and ``mlx4`` have native XDP without multi-buffer.

Load and restore each discover devices once.
:doc:`/reference/cli/upatch-reconcile` repeats that discovery later: it
attaches a loaded upatch to any selected device it does not run on yet
and removes the pin of a link whose device has gone. Removing a device
detaches its XDP link, so ``init`` and ``status`` do not count XDP link
pins as they do other links: they require the ``xdp_prog_<i>`` pin of each
XDP program and a link for each other attach program of the upatch.
The signed artifact and TPM measurement
cover the class policy, not a fixed device inventory. The location
``status`` and ``upatch get`` report names the first device still
attached and how many more there are, as in ``xdp/eth0 (+1)``.

The table sums up what each condition does at load and boot restore, at
reconcile and in ``status``. Skipped means the program is not attached
to that device and the operation carries on with the others; reconcile
tries the device again on its next pass. Failed means the operation
stops: a load is undone, ``init`` stops with the register unbound, and
a reconcile pass exits 1.

.. list-table::
   :header-rows: 1
   :widths: 17 15 24 12 12 20

   * - Condition
     - Load category
     - Journal
     - Load and boot restore
     - Reconcile
     - ``status``
   * - No native XDP, such as a bridge
     - none
     - ``XDP: skipping <device> (ifindex <n>, class <c>): native XDP
       unsupported``
     - Skipped
     - Skipped
     - ``degraded``, ``no native XDP``
   * - No multi-buffer support
     - ``xdp_multibuf_unsupported``
     - ``XDP: attach <device> (ifindex <n>): the device does not report
       multi-buffer XDP support``
     - Failed
     - Skipped, with a warning on every pass
     - ``degraded``, ``no multi-buffer XDP``
   * - The driver refuses in its current settings
     - ``xdp_driver_refused``
     - ``XDP: the driver of <device> refused the program: <error>``
     - Failed
     - Skipped, with a warning on every pass
     - ``degraded``, ``not attached``
   * - Another XDP program on the device, in any mode
     - ``xdp_device_occupied``
     - ``XDP: attach <device> (ifindex <n>): the device runs another XDP
       program``
     - Failed
     - Skipped, without a warning
     - ``degraded``, ``another XDP program attached``
   * - A link on another device, or a run outside the initial network
       namespace
     - ``attach_scope_mismatch``
     - ``XDP: attach <device> (ifindex <n>): the link is not on the
       device it was made for``
     - Failed
     - Failed
     - No condition of its own
   * - The device changed or went away during the attach
     - none
     - ``XDP: skipping <device> (ifindex <n>): <reason>``
     - Skipped
     - Skipped
     - None
   * - The driver name or devlink port cannot be read
     - none
     - ``XDP: cannot classify <device> (ifindex <n>), it sits out:
       <error>``
     - Skipped
     - Skipped
     - ``degraded``, ``not classified: <error>``
   * - No device matches the mask
     - none
     - ``XDP: no attachable interface matches signed class mask <n> yet``
     - Loads and waits
     - Attaches when a device appears
     - ``ok``, location ``xdp (waiting for a device)``
   * - The archive differs from the loaded payload
     - not a load failure
     - ``upatch reconcile: the archive of <name> is not what was loaded
       (tampered)``
     - Not checked
     - Failed, ``tampered``
     - ``tampered``, ``UpatchesMeasured``
   * - An ``xdp_prog_<i>`` pin is missing
     - not a load failure
     - ``upatch reconcile: an XDP program of <name>: <error>``
     - Not checked
     - Failed, ``tampered``
     - ``tampered``, ``UpatchesMeasured``
   * - An ``xdp_prog_<i>`` pin holds no XDP program
     - not a load failure
     - The same line
     - Not checked
     - Failed, ``tampered``
     - None: ``status`` checks that the pin exists, not what it holds
   * - The guards refuse the pin or the link
     - not a load failure
     - The same line, or the report message ``the guards refused the XDP
       link``
     - Not checked
     - Failed, ``lsm_denied``
     - The verdict does not change. The tamper counters count a refusal
       by shirudo's own guards.
   * - The pin cannot be opened for lack of descriptors or memory
     - not a load failure
     - The same line
     - Not checked
     - Failed, ``unknown``
     - None

``status`` reports what it finds itself, not the result of a reconcile
pass, and the keepalive carries the verdict of ``status``. A load that
fails is undone, so it does not change the verdict; the journal, the
report and the tree sync report carry the failure. A boot restore that
fails leaves the host ``reboot-pending``. :doc:`/reference/failure-categories`
has the errno and the remedy of each category, and
:doc:`/operate/run/read-status` each reason ``XdpCovered`` gives.

Programs that attach nowhere
----------------------------

Two roles are recognized by the program's name, and both must be in
``SEC("syscall")``. Any other ``syscall`` program is refused.

``shirudo_serialize__<map>``
    Renders ``<map>`` into records for export. shirudo pins it at
    ``serializers/<map>`` under the upatch's pin directory, and
    ``shirudo upatch map`` runs it with ``BPF_PROG_TEST_RUN``. The upatch
    must also define the ``shirudo_ser`` output map. One serializer per
    map. :doc:`/upatches/write/maps-arenas-serializers` describes the interface.
``shirudo_test__<id>``
    Pinned as ``test`` and run once with ``BPF_PROG_TEST_RUN`` and a
    zeroed 16-byte context, after all attachments. A negative return fails
    the load. At most one per upatch.

The LSM allows ``BPF_PROG_TEST_RUN`` from userspace only to tasks with
shirudo's runtime authority, so root cannot run a pinned serializer or
test-run program itself.

Refused sections
----------------

``shirudo build`` refuses these sections with the message shown, before
it generates a loader.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Section
     - Message
   * - ``kprobe``, ``kretprobe`` without a symbol, ``kprobe.multi*``,
       ``kretprobe.multi*``
     - ``unsupported kprobe section '<section>'; use kprobe/<symbol> or
       kretprobe/<symbol>``
   * - ``uprobe`` and ``uretprobe`` without a binary, other ``uprobe.*``
       and ``uretprobe.*`` forms, ``uprobe.session`` and
       ``uprobe.session.s`` among them
     - ``unsupported uprobe section '<section>'; use
       uprobe[.s]//absolute/path:function[+offset],
       uretprobe[.s]//absolute/path:function,
       uprobe.multi[.s]//absolute/path:function_glob or
       uretprobe.multi[.s]//absolute/path:function_glob``
   * - ``uprobe`` or ``uretprobe`` with a relative path, no function or a
       malformed offset
     - ``invalid uprobe section '<section>'; expected
       uprobe[.s]//absolute/path:function[+offset],
       uretprobe[.s]//absolute/path:function or a 0x file offset in place
       of the function``
   * - ``uretprobe`` or ``uretprobe.s`` with ``+<offset>``
     - ``uretprobe offsets are unsupported in section '<section>'``
   * - ``sk_skb``, ``sk_skb/*``
     - ``unsupported sk_skb section '<section>'; supported network packet
       sections are cgroup_skb/ingress, cgroup_skb/egress, and netfilter``
   * - ``socket``, ``socket_filter`` and their ``/`` forms
     - ``unsupported socket filter section '<section>'; shirudo upatches
       require a pinnable bpf_link lifecycle``
   * - ``cgroup_skb``, ``cgroup/skb``, other ``cgroup_skb/*``
     - ``unsupported cgroup_skb section '<section>'; use cgroup_skb/ingress
       or cgroup_skb/egress``
   * - ``fmod_ret``, ``fmod_ret.s`` without a function
     - ``unsupported fmod_ret section '<section>'; use fmod_ret/<symbol> or
       fmod_ret.s/<symbol>``
   * - every other section, ``tp/``, ``raw_tp/``, ``xdp`` and ``tc`` among
       them
     - ``unsupported section '<section>'; supported are fentry, fexit,
       fmod_ret, lsm, tp_btf, kprobe, kretprobe, uprobe[.s],
       uretprobe[.s], uprobe.multi[.s], uretprobe.multi[.s], cgroup_skb,
       netfilter and xdp/<mask>``
   * - ``syscall`` with another program name
     - ``SEC("syscall") program '<name>' must be named shirudo_test__<id>``

Attach-scope check
------------------

The site a kprobe, uprobe, cgroup or netfilter program attaches at depends
on state that root can arrange on the target: the mount of
``/sys/fs/cgroup``, the network namespace of the loading process, the
sysfs files that name the kprobe and uprobe PMUs. Before shirudo pins a
link, it asks the kernel about the link and compares the answer with the
signed metadata:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Kind
     - The kernel must report
   * - ``cgroup_skb``
     - a cgroup link on cgroup id 1, the root of the unified hierarchy
   * - ``netfilter``
     - a netfilter link for IPv6, pre-routing, priority -450, created by a
       task in the initial network namespace
   * - ``kprobe``, ``kretprobe``
     - a perf event link of the kprobe or kretprobe type, with the same
       symbol and offset
   * - ``uprobe``, ``uretprobe``
     - a perf event link of the uprobe or uretprobe type, with the recorded
       file offset and no reference counter. Not the file name: the
       descriptor the event was opened through fixes the inode, and the
       name the kernel reports can differ from the signed path by a
       symlink
   * - ``uprobe.multi``, ``uretprobe.multi``
     - a uprobe multi link with as many offsets as recorded and the same
       direction
   * - ``fmod_ret``
     - a tracing link with attach type ``BPF_MODIFY_RETURN``
   * - ``fentry``, ``fexit``, ``lsm``, ``tp_btf``
     - a tracing or raw tracepoint link

On a mismatch shirudo closes the link, which detaches it, removes the pins
this load made and fails with ``attach_scope_mismatch`` in phase
``link_create``.

Missing attach targets
----------------------

``attach_target_missing`` reports a site that does not exist on this
target: a ``kprobe`` symbol that kallsyms does not list, often because the
module that holds it is not loaded, a kernel without the kprobe PMU, a
missing ``/sys/fs/cgroup``, or the binary of a uprobe, uretprobe or
their multi forms that is not there. ``shirudo upatch load`` exits with status 2 for
it, not 1.

The BTF-based kinds never report it. ``fentry``, ``fexit``, ``fmod_ret``,
``lsm`` and ``tp_btf`` targets are looked up inside the signed loader, and
a missing one fails the load as ``verifier_rejected`` in phase
``payload_load`` with errno ``ENOENT``.

``bpm tree sync`` treats an ``add`` that fails with
``attach_target_missing`` as applied: it logs ``bpm tree: skipped <id>:
module not loaded``, measures the operation and moves past it, and does
not retry it when the module loads later. ``bpm install`` and ``bpm
upgrade`` fail and roll back instead. Narrow tree selectors keep an entry
away from targets that lack its site.

Related
-------

- :doc:`/upatches/learn/concepts` for the roles, pins and names
- :doc:`/upatches/test/debugging` for every failure category of a load
- :doc:`/internals/kernel-interfaces` for the system calls in detail
