..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

What is shirudo
===============

shirudo is a BPF security platform for Linux. It delivers BPF programs,
called upatches, to running machines without a reboot, and it restricts the
``bpf()`` system call so that the kernel accepts BPF from userspace only
inside a loader signed with the operator's key. Every change to the loaded
set is measured into a TPM register, and the TPM signs that record on
request.

Problem
-------

A kernel fix reaches a fleet only when every machine has booted a kernel
that carries it. The fix is often public long before that, and for a fleet
with a reboot cycle of days or weeks, that gap is when an attacker who reads
the fix can use the bug.

BPF can close the gap. A BPF program attached to an LSM hook or to the
vulnerable function can refuse the dangerous call in the running kernel,
and it can be loaded and removed without a reboot.

The same capability is a risk. If root can load BPF, an attacker who gains
root can load BPF too: to hide, to read kernel memory through tracing, or
to detach the mitigation. A mechanism that patches the kernel at runtime
has to keep everyone else from doing the same. On a shirudo target, root
without the operator's signing key must not be able to run BPF that the
operator did not ship.

What shirudo does
-----------------

- It locks down ``bpf()``. After ``shirudo init``, the kernel admits a
  program load from userspace only for a signed loader whose signature it
  verifies against the certificates in its sealed ``.bpf`` keyring. BPF LSM
  programs refuse the commands that detach or replace loaded programs, and
  keep every process without shirudo's runtime authority from opening
  their links and maps.
- It delivers upatches. The operator publishes signed packages to an OCI
  registry, and targets pull them on a systemd timer, by default about once
  a minute. A single ``.upatch`` file copied to the target by any other
  means loads through the same signature check.
- It measures. Every load, unload, upatch tree operation and key
  revocation extends a per-boot register in the TPM. The operator verifies
  TPM-signed evidence offline against the artifacts it shipped.
- It protects its own state. The binary and its settings come from
  dm-verity images, its writable state under ``/var/lib/shirudo`` carries
  labels that BPF LSM programs enforce, and its pins live in a private BPF
  file system whose unlink, rename and unmount the same programs refuse.
- It exports what upatches observe. When an endpoint is configured, map
  contents and status keepalives go to an OpenTelemetry collector over
  OTLP.

What shirudo does not do
------------------------

- It does not judge what a upatch does. The signature proves who built the
  code and that it was not tampered with. The kernel's BPF verifier still
  checks memory safety, but whether the program is a correct mitigation is
  the author's responsibility.
- It does not replace kernel updates. A upatch covers the time until the
  machine runs a fixed kernel.
- It has no daemon, no listening socket, no push channel, no SSH
  integration and no fleet inventory. Every target operation is a one-shot
  command, run by hand or by a timer.
- It does not defend against a compromised kernel, BPF verifier, TPM or
  hardware, and it does not harden the kernel. The kernel and shirudo form
  the target's trusted computing base.
- It does not retain logs. Its commands log through ``syslog(3)``, and
  retention is the job of journald and the systems behind it.
- It protects a target only from the moment ``shirudo init`` has attached
  its enforcement. Production targets run ``init`` from the initrd, before
  other workloads start. If ``init`` fails there, the boot continues
  without enforcement, and only ``shirudo status`` and attestation show
  it.

The :doc:`/security/threat-model` states each of these limits with the
mechanism behind it.

Two roles
---------

One binary serves two roles. The operator holds the private ML-DSA-87
signing key, builds and signs upatches, publishes packages and verifies
evidence. The operator-only commands run in a separate helper,
``shirudo-build``, which is not installed on targets. A target holds only
public certificates, enforces the signatures and keeps the measurement in
its TPM. :doc:`/concepts/operator-and-target` explains what each side holds
and why.

A target needs a bpf-next development kernel with the signed BPF loader
interface and the BPF LSM, the kernel patches listed in
:doc:`/internals/kernel-patches`, and a TPM 2.0. The operator host needs
current clang. Both run on x86-64, arm64 and riscv64.
:doc:`/operate/plan/system-requirements` lists the details.

Next steps
----------

- :doc:`how-it-works` follows one upatch from a kernel fix to a measured
  load and back.
- :doc:`quickstart` takes a upatch through its whole life on a test VM.
- :doc:`/security/security-model` summarizes what shirudo protects and
  where each mechanism stops.
