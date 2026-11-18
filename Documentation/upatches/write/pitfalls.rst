..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: upatch authors

Pitfalls
========

A program that loads and runs can still miss the events it is meant to
see, decide on data that is not what it looks like, or let through what
it is meant to refuse. Neither the verifier nor a test in a quiet VM
shows any of it. This page lists what the kernel does that a upatch has
to plan for, for the attach kinds ``shirudo build`` accepts.
:doc:`memory-consistency/hazards` covers the runs that interleave.

.. _runs-the-kernel-skips:

Runs the kernel skips
---------------------

The kernel skips some runs of a program. It counts most in the program's
``recursion_misses``, which ``struct bpf_prog_info`` reports, and some in
the link, which ``struct bpf_link_info`` reports:

- A ``kprobe``, ``kretprobe``, ``kprobe.multi`` or ``kretprobe.multi``
  run, while another program of these four kinds runs on the CPU, and
  while the CPU is in a ``bpf()`` call that looks up, updates or deletes
  a map element from userspace, as shirudo makes when it reads a
  upatch's maps. A ``kprobe`` hit inside the handler of another
  ``kprobe`` is missed by the kprobe itself, and counted in the link's
  ``perf_event.kprobe.missed``.
- A ``kprobe.multi`` or ``kretprobe.multi`` hit while ftrace already
  traces a function in the same context on the CPU, such as a watched
  function the program calls itself, and the return of a function a
  ``kretprobe.multi`` watches when the task's return stack is full. The
  kernel counts neither. A return it has no room to keep the probe's
  data for is counted in the link's ``kprobe_multi.missed``, which
  ``struct bpf_link_info`` reports, not in ``recursion_misses``.
- An ``fentry``, ``fexit``, ``fmod_ret`` or ``tp_btf`` run of a program
  that is already running on the CPU: one a preempted task left there
  with preemptible RCU, or one an NMI interrupted.
- The return of a function a ``kretprobe`` watches, when more calls of
  it are in flight than the probe has instances for: the larger of 10
  and twice the number of CPUs. The link's ``perf_event.kprobe.missed``
  counts it.
- The return of a function a ``uretprobe``, a ``uretprobe.multi`` or
  their ``.s`` forms watch, when the task already waits on the returns of
  64 calls that return probes watch, and the return of a function that
  leaves by ``longjmp()`` or ends the thread. The kernel logs the first
  case, rate-limited, and counts neither.

A detector built on these kinds can therefore miss the event it looks
for, and a count it keeps is a lower bound. ``lsm``, ``xdp``,
``cgroup_skb`` and ``netfilter`` programs are never skipped.

``shirudo status`` shows, in its ``MISSED`` column and ``missed_runs``,
the sum of what the kernel counts for each upatch: every program's
``recursion_misses`` and every kprobe link's own counter, and ``shirudo
upatch get`` shows it per program. For a uprobe kind it shows ``-`` and
``null``, as the kernel counts none of the runs it skips, and the sum
leaves out what the kernel does not count for the others either.

Enforce in lsm programs
-----------------------

``fmod_ret`` refuses a call when its program returns non-zero. A run the
kernel skips returns nothing, and the call goes through as if the
program had returned 0. Another task can make that happen on purpose: it
calls the function on a CPU where a run of the program waits, which an
``fmod_ret.s`` run that sleeps leaves on any kernel and a preempted
``fmod_ret`` run with preemptible RCU. Refuse an operation in an ``lsm``
program, which the kernel runs every time its hook is reached, and keep
``fmod_ret`` for functions no LSM hook covers, knowing that it can be
bypassed.

LSM hook order and outcome
--------------------------

``security_<hook>()`` calls the LSMs in the order ``lsm=`` or
``CONFIG_LSM`` gives and stops at the first one that refuses. An ``lsm``
program never sees an operation that an LSM before the BPF LSM refused,
such as SELinux, AppArmor or Landlock, and a refusal by the program
keeps the LSMs after it from seeing it. Hooks that return nothing run
every LSM.

A hook runs before the operation it guards, which can still fail after
it: an LSM later in the order refuses it, memory runs out, the network
does not answer. A record taken in ``socket_connect`` or ``file_open``
is of an attempt. Where the outcome matters, take it from a hook the
kernel calls afterwards, such as ``socket_post_create`` or
``bprm_committed_creds``.

The current task in a softirq
-----------------------------

``cgroup_skb`` ingress, ``netfilter`` and the socket hooks the network
stack calls on receive run in a softirq, on top of whatever task the CPU
was running. There ``bpf_get_current_pid_tgid()``,
``bpf_get_current_task_btf()``, ``bpf_get_current_comm()`` and
``bpf_get_current_cgroup_id()`` describe that task, not the packet.
Attribute a packet by its socket, with ``bpf_skb_cgroup_id()`` or
socket storage, and keep such programs off task storage. An ``xdp``
program runs there too, before the packet has a socket, so nothing
attributes it: decide on the packet alone.

What an xdp program does not see
--------------------------------

``xdp`` runs in the driver on receive, before the kernel builds an
``sk_buff``:

- It sees what a device receives, not what the host sends out of it. On
  a veth pair with one endpoint attached, it sees only what arrives at
  that endpoint.
- It sees only the devices it is attached to, and a device with no program
  passes everything. :doc:`attach-kinds` says which devices are selected
  and when.
- It sees packets as they arrive, before GRO joins them, so a transfer
  is many runs.
- A VLAN tag the NIC stripped is not in the packet.
- Direct packet access reaches only a packet's first buffer. Every
  ``xdp/<mask>`` program is loaded with multi-buffer support, so on a large
  MTU the rest of a frame is in fragments and ``ctx->data_end`` stops at the
  first one. Read past it with ``bpf_xdp_load_bytes()``, and take the frame's
  length from ``bpf_xdp_get_buff_len()``.

RCU pointers in sleepable programs
----------------------------------

In a sleepable program, a pointer read from a field the kernel protects
with RCU, such as ``task->real_parent``, is trusted only between
``bpf_rcu_read_lock()`` and ``bpf_rcu_read_unlock()``. Outside them the
verifier marks it untrusted: a load through it becomes a read that
tolerates a fault and can return memory the kernel freed and reused, and
a kfunc that needs a trusted argument refuses it. Walk such pointers
inside the lock and copy out what the program needs.

Map updates that fail
---------------------

``bpf_map_update_elem()`` and ``bpf_map_delete_elem()`` on a hash map
take a lock on the key's bucket and fail with ``-EDEADLK`` or
``-ETIMEDOUT`` when a run nests on a CPU that holds it, as a ``kprobe``
or an NMI inside another update can. An update of a new key fails with
``-E2BIG`` when the map is full. Check the result and count the
failures, or the program loses records without a trace.

An LRU hash map never fails for lack of room, but it keeps part of its
free elements on each CPU's own list and evicts from the shared lists
once these run short, so an insert can evict an entry before the map is
full. Size it with room to spare, and expect a lookup to miss a key that
was inserted earlier.

Values userspace writes
-----------------------

An update of an array map element from userspace copies the value
without a lock, so a program that reads it meanwhile can see part of the
old value and part of the new one. Give the value a ``struct
bpf_spin_lock`` and update it with ``BPF_F_LOCK``, read it under
``bpf_spin_lock()``, or have userspace write a fresh element and switch
an index to it.

Attach points that miss calls
-----------------------------

A ``kprobe`` on a function the compiler inlined into some of its
callers fires only for the calls that reach the out-of-line copy, and a
kernel built with another configuration or compiler inlines differently.
An ``fentry`` on a function without a BTF entry fails to attach, which
is the better failure. A probe on a system call's entry point misses the
same operation started through ``io_uring`` or from inside the kernel;
an LSM hook sits on the operation itself. Prefer ``lsm``, ``tp_btf`` and
``fentry`` to ``kprobe``, and test that a detector fires on the kernel it
ships to: a probe that never fires looks the same as no attack.

Related
-------

- :doc:`attach-kinds` for each attach kind and what the kernel needs for it
- :doc:`memory-consistency/hazards` for runs that interleave
- :doc:`maps-arenas-serializers` for the maps a upatch keeps state in
