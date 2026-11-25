..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators

Upgrade shirudo and the kernel
==============================

The trusted ``shirudo`` binary lives in the runtime image, and the UKI
pins that image's root hash. A new shirudo build therefore takes a new
runtime image, a new initrd, a new UKI and a reboot. A new kernel takes a
new initrd, a new UKI and a reboot, and the archived upatches must load
on it. This page covers both.

Config images and upatch packages change while the target runs and need
no reboot:

.. list-table::
   :header-rows: 1
   :widths: 30 40 30

   * - Change
     - What you rebuild
     - Takes effect
   * - shirudo binary
     - Runtime image, UKI bootstrap file, initrd, UKI
     - After a reboot
   * - Kernel
     - Initrd, UKI
     - After a reboot
   * - Config image
     - Config image, activated with ``shirudo image update``
     - At once
   * - Packages of upatches
     - Packages, published to a registry
     - Within a minute, through the timers

:doc:`/operate/run/deliver-packages` covers packages, and
:doc:`/reference/cli/image` covers ``image update``.

Before you begin
----------------

- A target set up as described in :doc:`/operate/deploy/boot-integration`, and
  the files you built for it: ``runtime.conf``, the BPF signing
  certificate and the config signing key.
- A root shell on the target. On the target, ``shirudo`` means the
  runtime image's binary, ``/run/shirudo/runtime/usr/bin/shirudo``. See
  :ref:`runtime-invocation`.
- A canary target with the same packages as the fleet, to try a new
  kernel on first.

Version ID
----------

Every build of shirudo carries a version ID. ``shirudo version`` prints
it after the release:

.. code-block:: console

   target# shirudo version
   shirudo (58d3fa7-dirty-rc0, "Social BPF Coding")
   version-id: 58b05ab35a2bcefaa649faf15f8c6be0211e24cea710450c1a29298c3b5c7de0

The build computes the ID as a SHA-256 over the source revision, a
``-dirty`` mark when the tree has uncommitted changes, and a digest of
``config.mk`` and :src:`Makefile.shirudo`. The revision comes from git, or
from the :src:`VERSION` file outside a git checkout. ``config.mk`` records
the library flags of the build host, so two builds of one commit on
different hosts get different IDs, and an operator package built on
another host than the target package carries another ID. The ID does not
cover the compiler or the contents of the libraries.

``shirudo upatch load`` and ``upatch unload`` compare the ID with
``--expect-version-id`` and refuse with ``version_mismatch`` when it
differs. In this example the path of the artifact is shortened:

.. code-block:: console

   target# shirudo upatch load --expect-version-id=0000000000000000000000000000000000000000000000000000000000000000 --report=- shirudo-test-lifecycle.upatch
   upatch load: version mismatch, the operator expects 0000000000000000000000000000000000000000000000000000000000000000 and the target is 58b05ab35a2bcefaa649faf15f8c6be0211e24cea710450c1a29298c3b5c7de0; deploy a matching shirudo or pass --no-version-check
   {"schema":1,"result":"failed","op":"upatch_load","phase":"pre_flight","errno":1,"errno_name":"EPERM","category":"version_mismatch","message":"SHIRUDO_VERSION_ID mismatch (operator vs target)",...}

Take the expected ID from the binary in the runtime image, never from the
operator's own binary. After an upgrade, update the ID that your
automation passes.

Upgrade shirudo
---------------

Build on the operator host
~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Build the new static target binary with ``make target``, or take
   ``/usr/bin/shirudo`` from the new target package.

2. Record its version ID:

   .. code-block:: console

      operator$ ./shirudo-target version --version-id

   Like every shirudo command, it locks its memory first, so it needs
   ``CAP_IPC_LOCK`` or a large enough ``RLIMIT_MEMLOCK``.

3. Build the new runtime image under a prefix of its own:

   .. code-block:: console

      operator$ shirudo-gen-runtime --binary ./shirudo-runtime \
          --bootstrap-binary ./shirudo-target \
          --bootstrap-conf runtime.conf --cert <bpf-cert> \
          --config-cert <config-keys-dir>/cert.der --output runtime-2 \
          --keys-dir <config-keys-dir> --unit-output runtime-service-2.conf

   Use the same ``runtime.conf`` and certificates as before.
   ``<bpf-cert>`` is the primary BPF signing certificate and
   ``<config-keys-dir>`` holds the config signing key.

4. Write a UKI bootstrap file for the new image, ``uki-bootstrap-2.conf``:

   .. code-block:: ini

      runtime.image = /sysroot/var/lib/shirudo-runtime/runtime-2
      runtime.root_hash = <runtime-2-root-hash>

   ``<runtime-2-root-hash>`` is the content of ``runtime-2.roothash``.
   The next step explains the path.

Stage and boot on the target
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

shirudo has no command that installs a runtime image on a running
target, and the seal refuses root's new entries and writes under
``/var/lib/shirudo``. Stage the image elsewhere, on the file system that
holds ``/var/lib/shirudo``, which the initrd mounts before init runs.
The initrd reads the root file system below ``/sysroot``, so the UKI
bootstrap file names the image by that path. The test suite does not
cover this layout. Remove a staged image only when no UKI you keep names
it.

1. Copy the new runtime image to the target:

   .. code-block:: console

      target# install -d -m 0700 /var/lib/shirudo-runtime
      target# install -m 0644 runtime-2.img runtime-2.verity runtime-2.roothash \
          /var/lib/shirudo-runtime/

2. Install the new target package. The initrd embeds its
   ``/usr/bin/shirudo``, which must be the same build as the binary in
   ``runtime-2``.

3. For a dynamically linked binary, install ``runtime-service-2.conf`` as
   ``/etc/systemd/system/shirudo.service.d/runtime.conf`` and update the
   other drop-ins from :ref:`unit-drop-ins` to its invocation. For the
   static binary the drop-ins stay as they are.

4. Generate the initrd with the new bootstrap file:

   .. code-block:: console

      target# shirudo-gen-initrd --bootstrap-conf uki-bootstrap-2.conf \
          --cert <bpf-cert> --kver <kernel-release> \
          --output /boot/initrd-shirudo-<kernel-release>-2.img
      target# shirudo-gen-initrd --check /boot/initrd-shirudo-<kernel-release>-2.img

5. Build and sign a UKI from the kernel, this initrd and the same command
   line, and install it as the default boot entry. Keep the previous UKI
   as a second entry, and keep the previous runtime image where its UKI
   expects it.

6. Reboot:

   .. code-block:: console

      target# systemctl reboot

Verify the upgrade
~~~~~~~~~~~~~~~~~~

1. Check that the runtime binary is the new build:

   .. code-block:: console

      target# shirudo version --version-id

   The ID must be the one you recorded on the operator host.

2. Check init as described in :doc:`/operate/deploy/initialize`:
   ``shirudo status`` reports ``ok``, ``shirudo status --show-full``
   shows ``Bound in: initrd``, and ``shirudo image status`` reports
   ``Pending: no`` and ``Consistent: yes``.

3. Update your verifiers. The new initrd and UKI change the PCR values
   that init records when it binds the register, which a verifier pins
   with ``--expect-bind-pcr``. :doc:`/operate/run/attest` describes how to
   record them.

When the new build fails to initialize, boot the previous UKI and read the
journal of the failed boot.

Upgrade the kernel
------------------

The runtime image does not depend on the kernel, so a kernel upgrade
keeps the image and the UKI bootstrap file. The archived upatches are
the risk: init restores every one of them at boot, and a upatch that
does not load on the new kernel stops the restore. Check them on a
canary target before you upgrade the fleet.

1. Confirm that the new kernel meets :doc:`/operate/plan/system-requirements`.

2. Boot the new kernel on a canary target with steps 4 to 8, and check
   it as described in :doc:`/operate/deploy/initialize`.

3. On every target, remove the upatches that do not load on the new
   kernel before you reboot into it. Uninstall such a package:

   .. code-block:: console

      target# shirudo bpm uninstall <package>

   Retract a upatch that the upatch tree manages with a delete operation,
   as :doc:`/operate/run/deliver-packages` describes. Unload a upatch that
   you loaded by hand with its unload directive.

4. Install the new kernel package.

5. Generate the initrd for the new kernel with the bootstrap file of the
   running image:

   .. code-block:: console

      target# shirudo-gen-initrd --bootstrap-conf <uki-bootstrap-file> \
          --cert <bpf-cert> --kver <new-kernel-release> \
          --output /boot/initrd-shirudo-<new-kernel-release>.img
      target# shirudo-gen-initrd --check /boot/initrd-shirudo-<new-kernel-release>.img

   Do not use an initrd that your distribution's kernel hooks generate:
   they run dracut with the host configuration and without the UKI
   bootstrap file.

6. Build and sign a UKI from the new kernel, this initrd and the same
   command line. Install it as the default entry and keep the previous
   kernel's UKI as a second entry.

7. Reboot:

   .. code-block:: console

      target# systemctl reboot

8. Check init as described in :doc:`/operate/deploy/initialize`, and update the
   PCR values your verifiers pin.

When an archived upatch does not load on the new kernel, init stops the
restore and the target stays ``reboot-pending`` at every boot of that
kernel. :ref:`boot-restore-lockout` describes the way out, which needs
the previous kernel's UKI.

Next steps
----------

- :doc:`/operate/deploy/initialize` for the checks after every boot
- :doc:`/operate/run/attest` to update what verifiers expect
- :doc:`/operate/maintain/backup-recovery` for the state to keep across upgrades
