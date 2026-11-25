..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: Kernel developers, security reviewers

Architecture overview
=====================

This page names the parts of shirudo, says where each one runs and how
they depend on each other, and points to the page that explains each part
in depth. It describes the implementation; when the code and this page
disagree, the code is right.

Problem
-------

A target runs BPF that its operator ships as signed upatches, and root on
the target must not be able to run BPF of its own, remove what the
operator installed without a record, or rewrite the record. Root can issue
every system call, so none of these properties can rest on a userspace
process that root could stop, trace or bypass. We put each decision into
the kernel, on the call that changes state, and keep the userspace part
small, short-lived and verified at boot. A Java upatch is the one
exception: a JVM, not the kernel, loads its jar, so its signature is
checked in userspace, and it is a mitigation in the JVMs it reaches, not
a boundary against root (:doc:`/security/threat-model`, R24).

The operator side has the opposite problem. It holds the only secret, the
ML-DSA-87 signing key, and it must not need any state about the targets,
so that losing or rebuilding an operator host loses nothing but the key.

Operator and target
-------------------

One ``shirudo`` executable serves both roles. The role follows from what
is present on the machine, not from a build option. The operator holds
``signing_key.pem`` in its keys directory; a target holds the sealed
kernel keyrings, the private bpffs and the TPM register that ``shirudo
init`` set up this boot.

The operator commands, ``shirudo build``, ``shirudo bpm build``,
``shirudo bpm push``, ``shirudo bpm tree append``, ``shirudo bpm tree
show``, ``shirudo bpm config update``, ``shirudo image build``,
``shirudo image verify`` and ``shirudo keys vouch``, execute the separate
``shirudo-build`` helper. Only that helper
links the CMS signer (:src:`util/sign.c`) and the package builder and
publisher (:src:`tools/shirudo-build/`). It runs ``clang`` to compile BPF,
libbpf's gen_loader to produce the signed loader, and ``veritysetup`` to
format and check images. The core binary finds it through
``SHIRUDO_BUILD``, the compiled-in libexec directory or ``PATH``.

On the target, commands use linked libraries and kernel interfaces only:
libbpf for ``bpf()``, raw ``keyctl(2)`` for keyrings, tpm2-tss over the
kernel TPM device for the register, libcrypto for digests and
certificates, libcurl for registries and OTLP. No target command starts
another program. Every command is a one-shot process; there is no daemon
and no listening socket.

Components
----------

Figure 1 shows the components and the paths between them.

.. figure:: /images/internals-architecture.svg
   :alt: The operator host publishes to an OCI registry. The target pulls
         from it and sends telemetry to a collector. On the target,
         userspace commands from the runtime image call into the kernel,
         which holds the BPF LSM programs, the signed upatches, the
         keyrings, the private bpffs and the image devices, and reach the
         TPM only through the kernel's TPM device, where
         lsm/tpm_command checks each command. The TPM holds the register
         and signs evidence that the operator checks offline.

   Figure 1. Components on the operator host and on a target. Nothing
   connects into the target; it pulls packages and pushes telemetry.

The binary embeds three BPF objects, compiled from :src:`bpf/` and included
with ``.incbin`` in :src:`util/loader.c`:

``bpf2``
    BPF admission (``lsm/bpf``, ``lsm/bpf_map``, ``lsm/bpf_prog``,
    ``lsm/bpf_prog_load``),
    the guards of the private bpffs and of ``/run/shirudo``, the mount
    guards, the keyring and TPM command guards, the kexec and lockdown
    refusals, the secure-exec of runtime files and the refusal of a
    traced one, the ``PR_SET_MM`` refusal, the device-mapper, perf and
    XFS attribute ioctl guards and the dm-verity device records.

``seal``
    Task marks and policy bits (``bprm_creds_for_exec``,
    ``bprm_check_security``, ``bprm_committed_creds``, ``task_alloc``,
    ``socket_post_create``), process protection
    (``ptrace_access_check``, ``mm_read_access``, ``perf_event_alloc``,
    ``task_kill``, ``task_setrlimit``, ``mmap_file``, ``file_mprotect``)
    and the label checks on writable state.

``unload``
    The template that ``shirudo-build`` turns into the loader of an unload
    directive. The target never runs it.

``shirudo init`` loads ``bpf2`` and ``seal`` without a signature. They
are part of the binary that the authenticated initrd carries; the BPF
keyring does not cover them. All other BPF enters through the signed
loader path.

Two read-only dm-verity images carry what the target trusts:

Runtime image
    Mounted at ``/run/shirudo/runtime`` with ``ro,nodev,nosuid``. It holds
    the target binary, its bootstrap ``etc/shirudo/shirudo.conf``, the
    initial BPF certificate ``keys/cert.der`` and the config verification
    certificates. The UKI names its exact root hash.

Config image
    Mounted at ``/run/shirudo/config`` with ``ro,nodev,nosuid,noexec``. It
    holds registries, the upatch tree subscription, node labels,
    export settings, further vouched BPF certificates and revocations. A
    CMS signature over its root hash authorizes it, and a live update can
    replace it.

Writable state lives under ``/var/lib/shirudo``: the archived upatches
that boot restore loads, the eventlog, the package and tree state, the
image cache and the config activation journal. The first ``init`` labels
the tree with the ``security.bpf.shirudo`` extended attribute, shirudo
labels every inode it creates there, and the seal refuses changes to
labeled inodes by tasks without runtime authority.

Per-boot state lives under ``/run/shirudo``, a private tmpfs mount that
systemd carries from the initrd into the root file system. The private
bpffs at ``/run/shirudo/bpffs`` holds the pins that keep every
enforcement link and every upatch link attached, the frozen identity
map, the task, device and config-root maps and the tamper counters.
``/run/shirudo/eventlog.pending`` carries the record of the initrd run to
the root file system.

The systemd units run the commands. ``shirudo-initrd.service`` runs
``shirudo init`` in the initrd. ``shirudo.service`` runs it again in the
root file system through a drop-in that starts the binary from the
runtime image. Timers start ``shirudo bpm repo update`` and ``shirudo bpm
upgrade``, ``shirudo bpm tree sync``, the status keepalive and the map
export. A udev rule for every new network device, and a timer after
boot, start ``shirudo upatch reconcile``, which attaches XDP upatches to
the devices that match.

The TPM holds the measurement register, an NV extend index anchored in
PCR 9, the config PCR the bootstrap settings select, and the attestation
key that signs evidence. The ECC EK salts the authenticated TPM
session; init freezes EK's name in the identity map.

How the parts depend on each other
----------------------------------

Runtime authority ties the kernel and userspace parts together. A task
has it when it carries a mark in the task map that both BPF objects
share. It gets the mark by a successful exec of a file on the runtime
image, or, as the initrd's ``init`` process, from a seed ``init`` writes
before it freezes the map. Every guard that lets shirudo do what it
refuses to everyone else asks for that mark, not for a user ID, a
capability or an executable path.

The keyrings tie the operator to the target. ``init`` enrolls the
initial certificate and the vouched certificates of the selected config
in ``.bpf``, the config verification certificates in ``.dm-verity``, and
seals both. The kernel verifies every upatch loader against ``.bpf`` and
every config root against its dm-verity trust path. The operator never
touches either keyring.

The register ties the target's state to evidence. Every change of the
loaded set, every tree operation and every live key revocation extends it
under a domain-separated tag, and the eventlog records the event beside
it. The operator predicts the register from the artifacts it signed and
checks evidence the TPM signed, without trusting the target's own account.

Delivery runs in one direction. The operator publishes to an OCI
registry, and a target timer pulls, verifies and loads. A ``.upatch``
copied to the target by any other means loads through the same path.
shirudo has no push transport and no fleet state.

Where to read more
------------------

- :doc:`signed-loader` explains how a signed loader installs a upatch,
  and why a userspace check could not.
- :doc:`enforcement` lists every LSM hook, what it refuses and in which
  order ``init`` attaches them.
- :doc:`seal` explains task marks and the labels on writable state.
- :doc:`boot-flow` follows ``init`` from the initrd to the root file
  system.
- :doc:`measurement-register` explains the register, the eventlog and
  attestation.
- :doc:`config-images` explains the runtime and config images and live
  activation.
- :doc:`kernel-interfaces` and :doc:`kernel-patches` list what shirudo
  needs from the kernel.
- :doc:`design-decisions` gives the reasons behind the design.
- :doc:`/security/threat-model` states what the design defends against
  and where it stops.

Authenticated runtime entry
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Runtime services start ``/run/shirudo/runtime/usr/bin/shirudo`` directly.
``make runtime`` links it as a separate static-PIE ELF, and
``shirudo-gen-runtime`` stages those exact bytes, validated by
``shirudo-runtime-elf``. A static target needs no interpreter or host
library lookup. A dynamic extra binary needs the fixed runtime interpreter
and its complete library closure from the same image.

Starting the runtime through its dynamic loader made the loader the
executable. The guard could not tell that from a direct loader invocation
on any other binary of the image, which then got the full Shirudo role.
Fresh full authority is now granted only on exec of an executable the
bootstrap bound from the image's ``usr/bin``; the loader started directly
from the image gets none.

The bootstrap binds the entry after it creates the final runtime mapping:
the mapping's device number, its disk sequence and the inodes of the
regular executables of its ``usr/bin``, ``usr/bin/shirudo`` first, go into
``shirudo_rt_ent``, a versioned one-slot map. At most 16 executables are
bound; a symlink, a directory or a non-executable file is not.
The map is read-only to BPF programs. Only the bootstrap may open it
writable, and it freezes the map after the one installation. An empty,
malformed or mismatched binding grants no role. Executable mappings of a
trusted task must come from the bound runtime, and the boot completion
and runtime configuration paths check the binding again.
