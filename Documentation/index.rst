..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

shirudo documentation
=====================

.. rst-class:: etymology

shirudo (Japanese シールド, pronounced "shee-roo-doh") means "shield".

shirudo is a BPF-based security platform: Linux targets run only the BPF
their operator signed, every change is measured into the TPM, and
functionality ships as signed :doc:`upatches <upatches/learn/concepts>`
(BPF programs) that targets pull from OCI registries.

Use cases
---------

shirudo makes sure only signed upatches run and records every change.
What an upatch does is up to whoever writes it. Typical uses:

.. container:: grid

   .. container::

      Shield vulnerable code paths

      Stop a known kernel or userspace bug from being reached until a
      fixed version is running. Rolls out faster than a kernel update and
      complements kernel live patching.

   .. container::

      System hardening

      Remove attack surface a workload does not need, and limit what
      containers, Kubernetes Pods and LLM agents can access.

   .. container::

      Runtime security and observability

      See what kernel and userspace applications, LLM agents included,
      are doing. upatches collect data in BPF maps and send it to
      collectors over OpenTelemetry.

   .. container::

      Embedded and edge devices

      Devices that are hard to patch get upatches the same way servers
      do. shirudo runs on x86-64, arm64 and riscv64 and adds little to the
      trusted computing base beyond the kernel.

Properties
----------

shirudo is built on a set of properties for a BPF security platform:

- Always on: the platform is part of the trusted computing base and starts
  from initrd in early boot
- Signed and sealed: BPF is admitted only through loaders signed against
  the sealed BPF keyring, and the platform guards its own assets against
  a root user who does not hold the signing key
- In-kernel control plane: every load and unload is a signed loader the
  kernel verifies before it runs
- Measured: a TPM-backed register records every operation on upatches,
  and the TPM signs it for a remote verifier
- Lightweight core: shirudo protects its own assets and nothing else.
  Everything else ships as upatches
- Plain BPF C: upatches are small BPF C programs that engineers and
  agents can read, generate and maintain. Commands take and produce
  structured data
- Pull in, push out: targets pull upatches from OCI registries and push
  telemetry to collectors; nothing on a target listens for connections

Hardening starts in the kernel
------------------------------

shirudo is one layer of a target's defense. It decides which BPF runs
and records every change, and it relies on the kernel for everything
else. An attacker with code execution in the kernel can bypass any check
made there, shirudo's included. Expose only the attack surface the
workload needs, and build the kernel so the bugs that remain are hard to
exploit.

upatches shrink the attack surface and block a known vulnerable code
path until a fixed kernel is deployed. The kernel's own memory-corruption
mitigations are still required.

The :doc:`security/threat-model` states where each of these mechanisms
stops.

By role
-------

- New to shirudo: :doc:`/start/quickstart`, then :doc:`/start/faq`
- Operators, who deploy and run targets:
  :doc:`/operate/deploy/deployment-checklist`, then
  :doc:`/operate/run/read-status`
- upatch authors: :doc:`/start/guides/first-upatch`, then
  :doc:`/upatches/learn/kernel-fix-tutorial`
- Security reviewers: :doc:`/security/security-model`, then
  :doc:`/security/threat-model`
- Contributors: :doc:`/contribute/code/develop-locally`

Documentation
-------------

Note: BPF and eBPF are two names for the same technology (`eBPF on
Wikipedia <https://en.wikipedia.org/wiki/EBPF#Branding>`__). This
documentation uses BPF throughout, the term the Linux kernel community
uses.

- :doc:`start/index`: build shirudo, boot a protected test target and take
  one upatch through its whole life, then install it
- :doc:`concepts/index`: the mechanisms shirudo builds on, from BPF signing
  and the BPF LSM to dm-verity, TPM 2.0 and post-quantum cryptography, and
  a glossary
- :doc:`operate/index`: system requirements, deployment, attestation,
  monitoring, upgrades, troubleshooting and incident response for targets
  in production
- :doc:`upatches/index`: write, test, package and publish upatches
- :doc:`security/index`: the security model, the threat model and the
  threats still to resolve, cryptography and tamper counters
- :doc:`internals/index`: how shirudo works inside the kernel and on the
  target, and why it is built this way
- :doc:`reference/index`: every command, format, setting, event, failure
  category, file and unit, and a cheat sheet
- :doc:`contribute/index`: work on shirudo itself, its tests and its
  documentation

.. toctree::
   :hidden:

   start/index
   concepts/index
   operate/index
   upatches/index
   security/index
   internals/index
   reference/index
   contribute/index
