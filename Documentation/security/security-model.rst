..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: Security reviewers, Operators

Security model
==============

shirudo restricts the ``bpf()`` system call so that only loaders signed
with the operator's key install BPF code, root included. Every change to
the set of loaded upatches is measured in the TPM, and an operator
checks that measurement with evidence the TPM signs. This page is the short
version of the :doc:`threat-model`, which states each mechanism, its
limits and the gaps not closed yet.

What shirudo provides
---------------------

.. list-table::
   :header-rows: 1
   :widths: 20 32 30 18

   * - Goal
     - Mechanism
     - Limit
     - Threat model
   * - Only signed BPF enters the kernel
     - ``lsm/bpf`` admits only signed loaders from userspace. The kernel
       verifies them against the sealed ``.bpf`` keyring, and
       ``lsm/bpf_prog_load`` admits only that keyring.
     - Any artifact the key ever signed loads. In-kernel BPF users and
       classic BPF are outside the gate.
     - :ref:`T1 <tm-t1>`, R16, R18
   * - Enforcement stays attached
     - Detach, update and foreign attach commands are refused; pins,
       descriptors and the private bpffs mount are guarded.
     - The pins depend on the mount tree; a stopped runtime command
       keeps its descriptors.
     - :ref:`T2 <tm-t2>`, R3, U17
   * - Only shirudo changes its state
     - The seal labels ``/var/lib/shirudo`` and checks every change to
       a labeled inode; keyrings and authorized processes are guarded.
     - Offline writes bypass it.
     - :ref:`T3 <tm-t3>`, R19
   * - Every change is measured
     - Loads, unloads, revocations and tree operations extend a TPM NV
       register whose writes ``lsm/tpm_command`` keeps to shirudo;
       salted sessions authenticate TPM acknowledgments and readbacks.
     - Initial session-key enrollment trusts the initrd; the config
       PCR is not guarded.
     - :ref:`T5 <tm-t5>`, R4, U9
   * - A verifier can tell
     - ``shirudo attest`` returns a TPM quote and a certification of the
       register; ``shirudo attest verify`` checks them offline.
     - Only the TPM-signed parts are evidence, and only with the
       verifier pinning the key, the binding and the expected state.
     - :ref:`T9 <tm-t9>`, U1
   * - Attempts leave a trace
     - Guards count their refusals in a frozen map that ``shirudo
       status`` and the keepalive report.
     - Some refusals move no counter; telemetry is not authenticated.
     - :ref:`T10 <tm-t10>`, R17
   * - Delivered content is authentic
     - Indexes, tree publications and configs are signed; the kernel
       verifies loaders and config roots.
     - A registry can withhold and replay signed content.
     - :ref:`T7 <tm-t7>`, :ref:`T11 <tm-t11>`, R8

Main adversary
--------------

The adversary shirudo is built against is root on the target without
the signing key: a compromised administrator account, a container
escape, a persistence implant. Capabilities do not stop it, so shirudo
does not rest on capabilities. A task gains authority only by a
successful exec of a file on the dm-verity runtime image, and the
guards let only such tasks through. Root can still run the runtime binary,
so the command interface is the boundary: root can make shirudo do
anything a shirudo command does, and every such change to the loaded
set is measured.

The other adversaries are unprivileged code, root with mount-namespace
and device control, the network and the registries, a malicious
collector, and the holder of a compromised signing key. The
:ref:`adversaries <tm-adversaries>` section says what each can do.

What shirudo assumes
--------------------

The properties above hold only on a deployment that provides the
:ref:`assumptions <tm-assumptions>`. In brief:

- A trusted kernel with the BPF LSM, the signed-loader ABI and the
  carried kernel patches
- Module signature enforcement and lockdown in integrity mode, no
  32-bit compatibility, no hibernation and no writes under mounted
  file systems
- Secure Boot with a signed, measured UKI and an authenticated kernel
  command line
- A kernel whose dm-verity trust path consults only keys trusted to
  sign shirudo configs
- A TPM 2.0 reachable only through the kernel driver
- A runtime image without generic tools
- An operator host that keeps the signing key safe

shirudo checks only some of these. The pre-flight of ``shirudo init``
checks that the BPF LSM is active and that the kernel has the
signed-loader ABI. It does not check lockdown, the kernel configuration
or the boot chain (U10).

What you must do
----------------

The deployer and the verifier each have a part that no code does for
them. The :ref:`duties <tm-duties>` section lists it in full. The
essentials:

- Build and boot the kernel as :doc:`/operate/plan/hardening` describes.
- Start every shirudo unit from the runtime image, and keep the units'
  environment files empty.
- Verify each target with ``shirudo attest verify`` and always pass
  ``--ak-name``, the binding PCRs, an expected state and the expected
  config root, as :doc:`/operate/run/attest` describes.
- Treat ``shirudo status``, keepalives and tamper counters as the
  target's own account, and a ``tampered`` status as an incident
  (:doc:`/operate/troubleshoot/incident-tampered`).

Related
-------

- :doc:`threat-model` for every mechanism, limit and open gap
- :doc:`tamper-counters` for what the counters record
- :doc:`cryptography` for the algorithms
