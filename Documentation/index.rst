..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

shirudo manual
==============

shirudo ("shields", Japanese) is a BPF security platform.  It ships
BPF live patches, called upatches, to Linux targets without a reboot,
and it makes sure a target runs only the BPF its operator signed.  Once
``shirudo init`` has run, the kernel accepts BPF from userspace only
inside a signed loader program whose signature verifies against the
certificate in a sealed kernel keyring; root without the signing key
cannot load, replace or detach BPF, and every state change is measured
into a per-boot TPM register the TPM certifies on request.  The
userspace side is one agentless
``shirudo`` binary: no daemon, no listening socket, one-shot commands
driven by systemd timers that pull signed packages from OCI registries
and push state to an OTLP collector.

The kernel's CVE stream runs at dozens of fixes a day and exploitation
now regularly precedes the patch, while a fleet reboot cycle takes
weeks.  shirudo exists for the window in between: an agent or an
engineer derives a BPF shield from the fix, the operator signs it, and
the fleet pulls it within the hour, measured and revocable.

This index points at the documents in the tree.  The code is
authoritative for behaviour; the documents describe it and say why it
is the way it is.

1) Which document
-----------------

Checking whether a host can run shirudo
    `requirements <requirements.rst>`__ lists the kernel options, the
    operator toolchain and the target runtime, with the reason for
    each.

Deploying shirudo
    `getting-started <getting-started.rst>`__ walks through building,
    creating a signing key, initialising a target, loading an upatch
    and publishing packages to a registry.

Using executable and config images
    `config-images <config-images.rst>`__ describes the opt-in dm-verity
    mode: separate runtime and config images, operator generation,
    bootstrap trust, live config and key updates, static-PCR measurements,
    interrupted activation, manual reboot, enforcement and current limitations.

Writing and shipping upatches
    `upatch <upatch.rst>`__ is the author's and operator's guide: the
    BPF side of a upatch, building and signing, testing on a target,
    the Beefile and ``bpm build``, publishing to a registry and to the
    signed upatch tree, and what a target does with both.

    `features <features.rst>`__ lists every attachment kind a upatch
    can have, what the kernel does at that point, how the loader
    attaches there and what the target needs for it.

Keys
    `key-lifecycle <key-lifecycle.rst>`__ covers the signing keys and
    their certificates from creation to retirement: the trusted set a
    target enrols, vouching for a new key, rotation, revocation and
    custody.

Running targets
    `operations <operations.rst>`__ is the day-two guide: the units
    and timers, what to watch, upgrading shirudo and the kernel,
    decommissioning, backup, recovery, and every failure category.

Understanding what shirudo does
    `architecture <architecture.rst>`__ describes why shirudo exists,
    its design properties, the signed-loader path, the kernel
    enforcement programs, the target state, and the delivery and
    observability paths.

Reviewing the security design
    `threat-model <threat-model.rst>`__ states the trust boundaries,
    the adversaries, the threats shirudo addresses with the mechanism
    behind each, and the residual risks.

Measuring and attesting a target
    `initrd <initrd.rst>`__ describes the production configuration:
    the run of ``init`` inside the initrd, what the root file system's
    run finishes, what an initrd must contain and how the generator
    and the installer build one.

    `tpm <tpm.rst>`__ describes the per-boot measurement register,
    the events and the eventlog, the TPM-signed evidence and its
    verification, how they relate to systemd's NvPCRs and what they
    do not yet do.

Shipping state to a collector
    `telemetry <telemetry.rst>`__ explains the OTLP export of map
    snapshots and status keepalives and how to feed them into the
    OpenTelemetry Collector, ClickHouse, Splunk or a collector of your
    own.

Reading or writing a ``.upatch``
    `upatch-spec <upatch-spec.rst>`__ is the byte-level reference for
    the signed artifact.

Contributing
    `contributing <contributing.rst>`__ covers commit messages, the
    mandatory ``Signed-off-by:`` and the kernel's tags.
    `coding-style <coding-style.rst>`__ is the kernel's coding style,
    copied verbatim from ``Documentation/process/coding-style.rst``
    and applied to userspace C and BPF alike.

2) Companion files in the repository root
-----------------------------------------

``AGENTS.md``
    Guidance for coding agents contributing to shirudo; ``CLAUDE.md``
    imports it for Claude Code.

``README.md``
    A short overview of what shirudo is and where to look.

``CODE_OF_CONDUCT.md``
    The community Code of Conduct, based on the CNCF one; conduct
    concerns go to conduct@shirudo.ai.

``LICENSE``
    BSD-2-Clause for userspace.  BPF programs declare ``Dual BSD/GPL``
    because the kernel's LSM hook framework requires a GPL-compatible
    licence.  Vendored files keep their upstream SPDX identifiers.

``upatches/``
    The packages shirudo ships, each with its ``Beefile``.

``vendor/libbpf/``
    Vendored libbpf and BPF UAPI headers with shirudo's BSD shims for
    the kernel's ``tools/include`` internals; refreshed by ``make
    bpf-deps``, see its ``README.md``.

``contrib/``
    ``swtpm.sh`` for a software TPM, the test VM scripts, and the
    kernel configurations they use.
