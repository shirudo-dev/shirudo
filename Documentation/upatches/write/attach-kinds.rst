..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: upatch authors

Attach kinds
============

The section name of a program decides where it attaches. ``shirudo build``
reads it, refuses the sections below the table, and records the attach
kind, target and program role in the signed attach metadata. The signed
loader attaches supported tracing and LSM programs. ``shirudo upatch
load`` attaches the remaining programs, validates the links and pins them.
Existing artifacts with the userspace attach role retain that path.

.. list-table::
   :header-rows: 1
   :widths: 27 18 33 22

   * - Section
     - Program type
     - Attached by
     - Target kernel needs
   * - ``fentry/<function>``, ``fentry.s/<function>``
     - tracing
     - Loader: ``BPF_LINK_CREATE``, ``BPF_TRACE_FENTRY``
     - the base requirements
   * - ``fexit/<function>``, ``fexit.s/<function>``
     - tracing
     - Loader: ``BPF_LINK_CREATE``, ``BPF_TRACE_FEXIT``
     - the base requirements
   * - ``fmod_ret/<function>``, ``fmod_ret.s/<function>``
     - tracing
     - Loader: ``BPF_LINK_CREATE``, ``BPF_MODIFY_RETURN``
     - ``CONFIG_FUNCTION_ERROR_INJECTION`` for functions marked for error
       injection
   * - ``lsm/<hook>``, ``lsm.s/<hook>``
     - LSM
     - Loader: ``BPF_LINK_CREATE``, ``BPF_LSM_MAC``
     - the base requirements
   * - ``tp_btf/<tracepoint>``
     - tracing
     - Loader: ``BPF_LINK_CREATE``, ``BPF_TRACE_RAW_TP``
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
   * - ``uprobe.multi/<path>:<glob>``
     - kprobe
     - ``BPF_LINK_CREATE``, ``BPF_TRACE_UPROBE_MULTI``,
       ``BPF_F_UPROBE_MULTI_PATH_FD``
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

fentry and fexit
----------------

``fentry`` runs at the entry of a kernel function with its arguments,
``fexit`` at its return with the arguments and the return value. Write
the program with ``BPF_PROG()`` and the function's parameters. The
verifier checks the prototype against the kernel's BTF.

The signed loader looks the function up in the target's BTF and loads the
program with that BTF id as its attach target. It then creates a link
with ``BPF_LINK_CREATE`` and ``BPF_TRACE_FENTRY`` or ``BPF_TRACE_FEXIT``,
using the BTF target the program carries. A function that is not in the target's BTF,
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

The signed loader attaches with ``BPF_LINK_CREATE`` and attach type
``BPF_MODIFY_RETURN``, without a fallback. The kernel admits ``fmod_ret``
only on ``security_*`` hooks, on system call entry points and on
functions marked for error injection or return modification. The
error-injection marks take effect only with
``CONFIG_FUNCTION_ERROR_INJECTION``. On any other function the load fails
in phase ``payload_load``. ``fmod_ret.s`` declares the sleepable variant.

lsm
---

``lsm/<hook>`` attaches a program to the LSM hook ``security_<hook>``
calls, for example ``lsm/file_open`` or ``lsm/socket_connect``. The
program receives the hook's arguments and the return value of the BPF LSM
programs that ran before it on the same hook. A non-zero return on a hook
that returns ``int`` refuses the operation. ``lsm.s/<hook>`` declares a
sleepable program, which the kernel admits only on hooks it lists as
sleepable.

The signed loader attaches with ``BPF_LINK_CREATE`` and ``BPF_LSM_MAC``.
Every
target that runs shirudo has the BPF LSM active, because shirudo's own
enforcement programs are LSM programs.

tp_btf
------

``tp_btf/<tracepoint>`` attaches to a kernel tracepoint, for example
``tp_btf/sched_process_exec``, and receives the tracepoint's raw
arguments with their BTF types. Tracepoints are stable observation points
that the kernel maintains on purpose.

The signed loader resolves the tracepoint by BTF and attaches with
``BPF_LINK_CREATE`` and ``BPF_TRACE_RAW_TP``.

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

uprobe.multi
------------

``uprobe.multi/<path>:<glob>`` attaches to the entry of every function in
a userspace binary whose symbol matches the glob, in every process, for
example ``SEC("uprobe.multi//usr/bin/example:*Func")``. ``<path>`` is
absolute. The glob has libbpf's syntax: ``*`` matches any sequence and
``?`` one character.

This kind is resolved on the operator host. The builder opens the binary
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
``BPF_F_UPROBE_MULTI_PATH_FD``, so the probes land in the inode it checked,
not in whatever the path names later. There is no path fallback.

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
   * - ``uprobe``, ``uprobe/*``, ``uretprobe*``, other ``uprobe.*`` forms
     - ``unsupported uprobe section '<section>'; use
       uprobe.multi//absolute/path:function_glob (entry probes only)``
   * - ``sk_skb``, ``sk_skb/*``
     - ``unsupported sk_skb section '<section>'; supported network packet
       sections are cgroup_skb/ingress, cgroup_skb/egress, and netfilter``
   * - ``socket``, ``socket_filter`` and their ``/`` forms
     - ``unsupported socket filter section '<section>'; Shirudo upatches
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
       fmod_ret, lsm, tp_btf, kprobe, kretprobe, uprobe.multi, cgroup_skb
       and netfilter``
   * - ``syscall`` with another program name
     - ``SEC("syscall") program '<name>' must be named shirudo_test__<id>``

Attach-scope check
------------------

The site a kprobe, uprobe, cgroup or netfilter program attaches at depends
on state that root can arrange on the target: the mount of
``/sys/fs/cgroup``, the network namespace of the loading process, the
sysfs file that names the kprobe PMU. Before shirudo pins a link, it asks
the kernel about the link and compares the answer with the signed
metadata:

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
   * - ``uprobe.multi``
     - a uprobe multi link with as many offsets as recorded
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
missing ``/sys/fs/cgroup``, or a ``uprobe.multi`` binary that is not
there. ``shirudo upatch load`` exits with status 2 for it, not 1.

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
