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

      $ limactl start --name=shirudo-dev --param checkout="$PWD" infra/lima/shirudo.yaml

   A git worktree keeps its repository outside the checkout, and the
   build asks git which files to copy into its container. Share the
   repository too:

   .. code-block:: console

      $ limactl start --name=shirudo-dev --param checkout="$PWD" \
          --mount="$(git rev-parse --path-format=absolute --git-common-dir)" \
          infra/lima/shirudo.yaml

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

      operator$ test -r /dev/kvm && test -w /dev/kvm && echo kvm ok
      kvm ok
      operator$ ulimit -l
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
