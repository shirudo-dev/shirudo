..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

How shirudo compares
====================

shirudo combines mechanisms that also exist on their own: signed BPF,
the BPF LSM, kernel keyrings, dm-verity and TPM measurement. Each of the
approaches below solves part of the problem shirudo addresses: change
what a running kernel does without a reboot, keep control of which code
runs, and be able to prove it later. For each, this page says what it
does, what it leaves open, and whether shirudo complements it, builds on
it or takes its place.

Kernel live patching
--------------------

Kernel live patching redirects calls of a kernel function to a
replacement function. The kernel's livepatch subsystem installs the
redirection through ftrace and switches tasks to the new code one by one
under a consistency model, and a patch can attach extra data to existing
structures through shadow variables. A live patch is a kernel module,
built from a source patch with kpatch-build or with ``klp-build`` from
the kernel tree's ``scripts/livepatch/``.

A live patch can replace any function that ftrace can trace, so it can
carry the fix itself. It is native kernel code: no verifier checks it, it
is built for one kernel build, and who may load it is decided by module
signature enforcement and lockdown. The livepatch subsystem does not
measure the patches it applies into the TPM, though IMA can measure
module loads.

shirudo complements live patching. A upatch cannot replace a function
body. It can refuse a call before the function runs, at an LSM hook, a
``security_*`` function, a system call entry, a function marked for
error injection or a function the kernel build tagged because it returns
errors, and it can observe or filter
(:doc:`/upatches/write/attach-kinds`). In exchange, the BPF verifier checks
every program, CO-RE lets one artifact load on more than one kernel
build, and each load and unload is measured. A target can run both:
shirudo does not gate module loading (:doc:`/operate/plan/interoperability`).
Used together, a upatch blocks a vulnerable path until a live patch or a
fixed kernel is in place, and a signed unload directive removes it then.

IMA and IPE
-----------

IMA measures files when the kernel executes, maps or loads them, as
modules, firmware or kexec images among others, into a PCR and a
measurement list. IMA appraisal checks those files against a hash or a
signature, kept in their ``security.ima`` attribute or appended to the
file. IPE is an LSM that decides on the same kinds of operations by an
immutable property of where a file comes from: the initramfs, a
dm-verity device with a given root hash or a signed one, or an fs-verity
digest or signature.

Both work on files. Neither IMA's policy functions, listed in
``Documentation/ABI/testing/ima_policy`` of the kernel tree, nor IPE's
operations include a BPF program load. A BPF program reaches the kernel
as bytes in a ``bpf()`` call, not as a file the kernel reads, so a
system that runs only verified executables can still load any BPF
program its root asks for. The kernel's BPF signing documentation names
IPE as an LSM that could enforce signed BPF in the future.

shirudo complements both. It covers ``bpf()``, which they do not. For
its own executable it uses the idea behind IPE's ``dmverity_roothash``
property: only an exec of a file on the dm-verity device whose root hash
the UKI pinned gives a process shirudo's authority
(:doc:`/internals/seal`). IMA can run on the same target. shirudo
measures into its own register, anchored in PCR 9, not into IMA's list
(:doc:`/concepts/measurement-register`).

Policy engines on the BPF LSM
-----------------------------

The BPF LSM, first proposed as kernel runtime security instrumentation
(KRSI), lets privileged users attach BPF programs to LSM hooks and so
implement access control and audit policies at runtime. Engines built
on BPF add policy management on top. Tetragon, for example, describes
itself as eBPF-based security observability and runtime enforcement:
tracing policies, as Kubernetes custom resources, name kprobes,
tracepoints or uprobes, filter events in the kernel and act on them, by
overriding a return value or sending a signal. Policies load at startup
from flags, or at runtime through Kubernetes or a command-line client.

The BPF LSM is a mechanism. It refuses nothing until programs attach,
and it does not decide on its own which other programs may load or who
may detach them. An engine's protection of itself depends on what its
own policy covers, and its agent, which takes policy changes at runtime,
is part of what a host must trust.

shirudo is a BPF LSM policy too, with a fixed purpose: it governs
``bpf()`` itself, so that only signed loaders install BPF, and it guards
its own links, maps and state. It takes no policy at runtime. Every
change is a signed artifact that a one-shot command loads and the
register records. An engine that loads its own programs cannot run on
an enforcing target. Its hooks and its logic can be written as upatches
with the ``lsm``, ``fentry`` or ``kprobe`` attach kinds, and a policy
change then becomes a signed build.

Signed BPF and BPF tokens
-------------------------

The kernel verifies the signature of a BPF loader program, over its
instructions and the metadata map it installs, against a keyring, and
records the verdict on the program. On its own it requires nothing: an
unsigned program loads as before, and an LSM has to refuse what it does
not want (:doc:`/concepts/background/bpf-signing`).

BPF tokens delegate part of ``bpf()`` to a user namespace. A bpffs
instance mounted with ``delegate_cmds=``, ``delegate_maps=``,
``delegate_progs=`` and ``delegate_attachs=`` lets a process in that
namespace create a token and use the delegated commands, map types,
program types and attach types, with capabilities checked in that
namespace. A token cannot be created in the initial user namespace.
Tokens decide who may use which part of ``bpf()``, not which code runs.

shirudo builds on signing. It is the LSM that acts on the verdict: a
load from userspace passes only when the kernel verified it against the
``.bpf`` keyring that ``init`` enrolled, sealed and froze. Around that
it adds the enrollment of trusted keys, the guards for its own objects,
delivery and measurement. It refuses ``BPF_TOKEN_CREATE``, so tokens
give nothing on an enforcing target.

dm-verity and measured boot
---------------------------

dm-verity checks every block read from a device against a hash tree
whose root hash is trusted, and the kernel can require a signature on
that root hash (:doc:`/concepts/background/dm-verity`). In a measured
boot, the firmware, the boot loader and systemd extend TPM PCRs with
what they load, so that a quote shows what booted
(:doc:`/concepts/background/boot`).

Both describe what was on disk and what started. A BPF program enters
the kernel later, through a system call from any process with the
privilege, with no read from a verified device in between, and nothing
in the boot measurements records it. A kernel and an initrd that
attested correctly can run any BPF program minutes later.

shirudo builds on both. The signed UKI, measured into PCR 11, pins the
root hash of the runtime image. The runtime and config images are
dm-verity devices, and the kernel verifies the config image's signature.
``init`` binds the measurement register under PCR 9 and PCR 11 and
anchors it in PCR 9, and every upatch state change extends it. The
register carries measured boot past the boot, into the BPF state of the
running kernel.

Security agents with daemons
----------------------------

A traditional security agent is a long-running privileged process on
each host. It keeps a channel to a management service, receives policy
and code over it, applies them and reports back. Its kernel parts, if it
has any, live as long as the process holds them.

The daemon and its channel are part of the host's trusted computing
base and of its attack surface. Root can stop the process. What it
reports is its own account unless hardware vouches for it.

For delivering and enforcing BPF on a target, shirudo takes this
model's place. The target runs no daemon and listens on no socket.
Enforcement stays in links pinned in a private bpffs after ``init``
exits. Packages arrive by pull, from timers. The status keepalive is the
target's own account, quoted by a key no one has tied to a TPM, and only
TPM-signed evidence that
the operator verifies off the target is proof
(:doc:`/concepts/operator-and-target`). shirudo has no inventory,
rollout orchestration or remote response; those stay with the
infrastructure that already runs the fleet. Its own limits are in
:doc:`/security/threat-model`: root can run every command of the
runtime binary (R2), and telemetry has no proof of origin (R17).

Summary
-------

.. list-table::
   :header-rows: 1
   :widths: 24 38 38

   * - Approach
     - Covers
     - shirudo
   * - Kernel live patching
     - Replacing kernel functions, with native code in a module
     - Complements: refuses or observes with verified BPF, measured
   * - IMA and IPE
     - Files the kernel executes, maps or loads
     - Complements: covers ``bpf()``
   * - Policy engines on the BPF LSM
     - Policies that change at runtime, through an agent
     - Takes the place of the engine's loader. Policies become signed
       upatches
   * - Signed BPF and BPF tokens
     - A verdict on a loader's origin, and delegation of privilege
     - Builds on signing. Refuses tokens
   * - dm-verity and measured boot
     - What was on disk and what booted
     - Builds on both, and measures the BPF state after boot
   * - Agents with daemons
     - Policy and code over a management channel
     - Takes the agent's place for BPF delivery, without a daemon

Related
-------

- :doc:`/concepts/operator-and-target`
- :doc:`/concepts/upatches-and-packages`
- :doc:`/operate/plan/interoperability`
- :doc:`/security/threat-model`
- `Livepatch <https://docs.kernel.org/livepatch/livepatch.html>`__ and
  `Integrity Policy Enforcement
  <https://docs.kernel.org/admin-guide/LSM/ipe.html>`__ in the kernel
  documentation
- `LSM BPF Programs <https://docs.kernel.org/bpf/prog_lsm.html>`__ and
  the LWN article `Kernel runtime security instrumentation
  <https://lwn.net/Articles/798157/>`__
- `kpatch <https://github.com/dynup/kpatch>`__
- `Tetragon tracing policies
  <https://tetragon.io/docs/concepts/tracing-policy/>`__
