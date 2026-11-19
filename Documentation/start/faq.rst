..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: All readers

FAQ
===

Short answers to the questions newcomers ask most, each with the page
that explains it.

What is a upatch?
------------------

A signed BPF program that shirudo loads into the running kernel without a
reboot. See :doc:`/upatches/learn/concepts`.

Is shirudo ready for production?
--------------------------------

Not yet. shirudo is pre-release and has no stable releases or supported
release branches, and the architectures are not all at the same stage.
See :doc:`/reference/versions` and :doc:`/contribute/arch-support`.

Does shirudo replace kernel updates?
------------------------------------

No. A upatch covers the time until the machine runs a kernel with the
fix. :doc:`/start/what-is-shirudo` describes what shirudo does and does
not do.

Can root turn shirudo off?
--------------------------

Not without the signing key: root cannot load unsigned BPF, detach the
enforcement or change shirudo's state. Root with a way into the kernel
itself, such as a kernel exploit or a kernel without lockdown, goes
around every check made in that kernel. :doc:`/security/security-model`
lists what shirudo protects and where it stops, and
:doc:`/operate/plan/hardening` lists the kernel settings it relies on.

Does a target need a TPM?
-------------------------

Yes. Every target needs a TPM 2.0, which records every change to the
loaded upatches and signs the evidence for a remote verifier. There is no
mode without one. See :doc:`/concepts/background/tpm`.

Which kernel does a target need?
--------------------------------

A kernel with the signed-loader ABI of bpf-next and the ``tpm_command``
patch in the shirudo kernel build, plus a second patch on x86-64.
:doc:`/operate/plan/system-requirements` lists the kernel options and
:doc:`/internals/kernel-patches` the patches.

Is there a daemon or an open port?
----------------------------------

No. Every operation is a one-shot command, run by hand or by a systemd
timer, and nothing on a target listens for connections. Targets pull
packages from OCI registries and push telemetry to a collector. See
:doc:`/concepts/operator-and-target`.

Does shirudo send data anywhere?
--------------------------------

Only where you configure it to. With no repository, tree or export
endpoint configured, shirudo sends nothing. :doc:`/operate/plan/overhead`
lists every request it makes.

Can Cilium, Falco or bpftrace run on a target?
----------------------------------------------

Not as they are. shirudo admits only BPF loaded by signed loaders, so
tools that load their own programs fail at their first map or program.
Their logic can ship as signed upatches instead.
:doc:`/operate/plan/interoperability` goes through common tools.

What happens when the registry is unreachable?
----------------------------------------------

Nothing changes on the target. Loaded upatches keep running, the update
fails and the next run of the timer tries again. See
:doc:`/operate/plan/scalability`.

What happens when init fails at boot?
-------------------------------------

The boot continues, and what the target enforces depends on where
``init`` stopped. :doc:`/operate/deploy/initialize` lists each case and
what to do.

Can I sign with an existing key?
--------------------------------

No. shirudo signs with ML-DSA-87 only, a post-quantum algorithm, and
the signing code refuses any other key. Create the key with
``shirudo genkey``, as :doc:`/operate/maintain/keys` describes.

Do I need to know BPF to write a upatch?
-----------------------------------------

A upatch is plain BPF C. :doc:`/start/guides/first-upatch` writes one
from scratch, and :doc:`/upatches/learn/kernel-fix-tutorial` takes a real
kernel fix to a published package.

Which architectures does shirudo run on?
----------------------------------------

x86-64, arm64 and riscv64, at different stages: CI tests x86-64, the
test VM also runs on arm64, and no riscv64 target has booted yet.
:doc:`/contribute/arch-support` compares the three.

How much does shirudo cost on a target, and how far does it scale?
------------------------------------------------------------------

:doc:`/operate/plan/overhead` gives the files, memory, CPU time and
network traffic of one target, and :doc:`/operate/plan/scalability` how
the registry load grows with a fleet and where a target and a upatch
reach their limits.

Is there a talk that introduces shirudo?
----------------------------------------

Yes, it was first presented at the Linux Plumbers Conference 2026 in
Prague in the talk `shirudo: BPF live-patching infra for the agentic
era <https://lpc.events/event/20/contributions/2437/>`__. Its page
links the slides and the video.
