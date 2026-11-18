..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

Who is shirudo for
==================

shirudo is for teams that need to change what runs in their Linux
kernels while the machines run, with proof of every change, whether to
block a vulnerable code path, harden the kernel, contain workloads or
observe them. This page describes who uses which part of shirudo, and
when it is not a fit yet.

Fleet operators
---------------

Platform and infrastructure teams that run Linux servers or Kubernetes
nodes. They roll out what their machines need in the kernel as upatches,
without waiting for the next reboot cycle:

- Mitigations that block a vulnerable code path in a short time, removed
  once the fixed kernel runs
- Hardening that removes attack surface a workload does not need
- Sandboxes for containers and Pods
- Runtime security and observability, with data exported over
  OpenTelemetry

shirudo complements kernel live patching, which carries the fix itself,
by blocking the vulnerable path in a shorter time until a live patch or
a fixed kernel is in place. Targets pull signed packages from an OCI
registry on a timer, and nothing on a target listens for connections.
There is no agent to keep running and no control plane to operate.

Start with :doc:`/operate/plan/system-requirements` and
:doc:`/operate/deploy/deployment-checklist`.

Security teams
--------------

Security operations and detection engineering teams. They get:

- Visibility into the kernel and userspace applications through upatches
  that install signed BPF programs on uprobes and kernel hook points
- Mitigations, hardening and sandboxes that fleet operators roll out
- Status keepalives, tamper counters and what upatches observe, over
  OpenTelemetry into the SIEM or log store they already run
- TPM-signed evidence of what each target runs, which they verify
  offline instead of trusting what the target reports about itself

Start with :doc:`/operate/integrations/index` and
:doc:`/operate/run/attest`.

Embedded and edge device makers
-------------------------------

Devices that stay in the field for years are hard to patch and reboot
rarely. A device gets upatches the same way a server does, pulled on a
timer from a registry.

The target side is one static binary with no daemon, built for x86-64,
arm64 and riscv64, and it adds little to the trusted computing base
beyond the kernel. Signatures use ML-DSA-87, the post-quantum parameter
set with the largest margin, so a key that anchors the devices' trust
can outlive hardware generations.

Start with :doc:`/operate/plan/system-requirements` and
:doc:`/contribute/arch-support`.

upatch authors
--------------

Kernel and BPF engineers who write mitigations, hardening, containment
and observability. An upatch is plain BPF C, compiled with clang and
checked by the BPF verifier, and CO-RE lets one artifact load on more
than one kernel build. Authors attach to LSM hooks, kernel functions,
tracepoints, userspace functions, cgroup socket buffers and netfilter.

The code is small and readable, so language models can help write and
review it. The signature then proves who built it and that it was not
tampered with.

Start with :doc:`/start/guides/first-upatch` and
:doc:`/upatches/learn/kernel-fix-tutorial`.

Teams that contain workloads
----------------------------

Teams that run containers, Kubernetes Pods or LLM agents and want
confinement the workload cannot reach. For LLM agents this limits the
blast radius, so an agent that misbehaves or is taken over can reach
only what the rules allow. The rules ship as signed upatches:

- Which programs a workload may run
- Which files it may write
- Which hosts it may reach

Root on the machine cannot detach them without the operator's signing
key, and every change to them is measured.

Start with :doc:`/upatches/write/attach-kinds`.

Security reviewers
------------------

Reviewers and auditors who need to know what a machine runs and what
shirudo guarantees. The security model and the threat model state each
mechanism, where it stops and which tests back it. Attestation gives
evidence a reviewer can check without trusting the machine.

Start with :doc:`/security/security-model` and
:doc:`/security/threat-model`.

When shirudo is not a fit yet
-----------------------------

- shirudo has no release. ``main`` is the development branch, and no
  format carries a compatibility promise yet.
- A target needs a bpf-next kernel with the signed-loader interface and
  the patches shirudo carries, a TPM 2.0, and a unified kernel image
  booted through ``systemd-stub`` with a systemd initrd built by dracut.
  There is no fallback for an older kernel.
- On an enforcing target, only signed upatches run BPF. BPF-based
  agents, network plugins and tracing tools such as bcc and bpftrace stay
  off those targets, or what they do ships as upatches.
- shirudo has no fleet inventory, no push channel and no remote
  management. Targets pull from OCI registries, and how an administrator
  reaches a target is not shirudo's concern.
- One shirudo instance runs per host.

Next steps
----------

- :doc:`what-is-shirudo` for what shirudo does and does not do
- :doc:`quickstart` to take an upatch through its whole life on a test
  VM
- :doc:`/operate/plan/interoperability` for what enforcement refuses on
  a target
