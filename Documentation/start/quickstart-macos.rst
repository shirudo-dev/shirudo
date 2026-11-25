..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: First-time users

Set up a Linux host on macOS
============================

shirudo builds and runs on Linux only, and its test VM needs KVM. On a
Mac, a Lima VM takes the place of the Linux host the
:doc:`/start/quickstart` asks for: it is the operator host, and the test
VM, the target, runs inside it with nested virtualization.
:src:`infra/lima/shirudo.yaml` sets that VM up.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Where
     - What runs there
   * - The Mac
     - ``limactl``, and the checkout you start the VM from.
   * - Lima VM, as the operator
     - Ubuntu 26.04 on arm64 with clang and LLVM 23 and every package the
       quickstart lists. It builds in your checkout, which it shares
       with the Mac.
   * - Test VM, as the target
     - The bpf-next kernel and the runtime image, with a software TPM
       (``swtpm``) inside the Lima VM. The Mac's own hardware takes no
       part.

Before you begin
----------------

- An Apple M3 or later running macOS 15 or later. Earlier Macs, Intel
  ones included, offer no nested virtualization, and the test VM does not
  boot without it.
- Lima 2.2 or later (``limactl --version``), for instance from Homebrew
  (``brew install lima``).
- About 100 GiB of free disk and 8 GiB of memory for the VM.
- A checkout of shirudo on the Mac.

Create the VM
-------------

1. In the root of your checkout, create and start the VM. ``checkout``
   names the checkout, which the VM shares at the same path:

   .. code-block:: console

      $ limactl start --progress --name=shirudo-dev --param checkout="$PWD" infra/lima/shirudo.yaml

   .. raw:: html

      <details>
      <summary>Using a Git worktree</summary>

   If you're using a Git worktree, run the command below to share the
   repository too.

   .. code-block:: console

      $ limactl start --progress --name=shirudo-dev --param checkout="$PWD" \
          --mount="$(git rev-parse --path-format=absolute --git-common-dir)" \
          infra/lima/shirudo.yaml

   .. raw:: html

      </details>

   The VM takes 8 GiB of memory and Lima's default of at most 4 CPUs.
   Add ``--cpus=<count>`` to give the VM more CPUs.

2. From your checkout, open a shell in the VM:

   .. code-block:: console

      $ limactl shell shirudo-dev

   The shell opens in your checkout. An edit on the Mac shows up in the
   VM at once, and the build writes its output, ``build/`` and
   ``artifacts/`` among it, into the checkout. ``build/test-vm`` is a
   link to the VM's own disk: QEMU and swtpm need Unix sockets, which
   the shared checkout does not carry.

3. Check that the VM can run the test VM. ``/dev/kvm`` must be readable
   and writable, and the locked-memory limit must be ``unlimited``:

   .. code-block:: console

      $ test -r /dev/kvm && test -w /dev/kvm && echo kvm ok
      kvm ok
      $ ulimit -l
      unlimited

Continue with the quickstart
----------------------------

In the VM shell, start the quickstart at :ref:`quickstart-kernel-artifact`.
Every ``operator$`` command runs in the Lima VM. The quick guides and
:doc:`/contribute/code/develop-locally` work the same way; the VM has
Docker for the registry and the collector of the latter.

Delete the VM
-------------

When you are done, delete the VM and its disk from the Mac:

.. code-block:: console

   $ limactl delete --force shirudo-dev

Troubleshooting
---------------

``limactl start`` fails with ``field `mounts[0].location` must be an absolute path``
   The command did not pass ``--param checkout=<path>``.

``limactl start`` fails on nested virtualization or on the probe for nested KVM
   The Mac does not offer nested virtualization: it is older than an M3
   or runs a macOS before 15.

A nested guest stalls during boot
   On the first start, provisioning tries one nested KVM appliance boot
   with a 150-second deadline, including kernel selection. It reports any
   failure and lets setup continue. The console is saved inside the VM at
   ``~/test-vm/kvm-appliance-check.log``. A new VM created with the GICv3
   traps already requested skips this check because the traps take effect
   after a restart.

   ``make -C testing vm`` can stall while libguestfs boots its appliance to
   prepare the runtime image, or later while the test target boots. To
   check the appliance on its own, stop the stalled command and run this
   in the Lima shell from the checkout:

   .. code-block:: console

      operator$ testing/vm/build-bundle.sh --check-kvm-appliance

   The check uses the bundle's appliance kernel selection and boots the
   appliance with KVM required. It prints the console and allows 150
   seconds for kernel selection, appliance preparation, and readiness.
   Exit status 124 means the deadline expired. If the command
   reports an error, use its diagnostics. After the appliance passes,
   ``make -C testing vm`` still has to reach ``VM ready`` separately.
   ``TEST_VM_TIMEOUT=180 make -C testing vm`` sets the target readiness
   deadline in seconds. On a target failure, inspect ``console.log`` and
   ``qemu.log`` in the preserved VM state directory.

   If the console shows a nested guest starts booting and then stops
   making progress, try the GICv3 traps below. A timeout can also come
   from slow preparation or other boot problems.

   On some Macs, a nested guest can stall when it accesses GICv3
   interrupt-controller registers directly. The traps make KVM in the
   outer Lima VM intercept and emulate those accesses. This can affect
   both the libguestfs appliance and the test target.

   * For an existing VM, run ``sudo sh infra/lima/enable-gicv3-traps.sh``
     in its Lima shell from the updated checkout.
   * For a new VM, add ``--param gicv3Traps=true`` to the creation command
     above. The template leaves the traps off by default.

   If any of the three settings below is still missing from the Lima VM's
   ``/proc/cmdline`` after the opt-in, restart the outer VM from the Mac:

   .. code-block:: console

      $ limactl stop shirudo-dev && limactl start shirudo-dev

   The outer Linux kernel reads the settings at boot. Reopen the Lima
   shell, confirm that ``cat /proc/cmdline`` shows all three settings, and
   retry the step that stalled.
   The settings are ``kvm-arm.vgic_v3_group0_trap=1``,
   ``kvm-arm.vgic_v3_group1_trap=1``, and
   ``kvm-arm.vgic_v3_common_trap=1``.

The test VM state path probe fails, or ``make vm`` cannot create the vTPM keys
   If ``build/test-vm`` is a directory in the shared checkout, Lima leaves
   it in place. Ubuntu's AppArmor profile denies ``swtpm`` writes there.
   After stopping any test VMs that use that directory, move it aside and
   link the path to the Lima VM's disk. Run these commands in the checkout
   from the Lima shell.

   .. code-block:: console

      operator$ mkdir -p "$HOME/test-vm" && \
          mv -T build/test-vm "build/test-vm.saved-$(date +%Y%m%d-%H%M%S)" && \
          ln -sT "$HOME/test-vm" build/test-vm

   Retry the step that boots the test target. The saved directory holds
   the logs and state from the earlier run.
