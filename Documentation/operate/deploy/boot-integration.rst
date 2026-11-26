..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators

Boot integration
================

A production target starts shirudo from an authenticated initrd, before
any workload runs. The initrd verifies a dm-verity runtime image that
holds the trusted ``shirudo`` binary, and a signed config image that
holds the settings you may change later. This page takes one target
from operator keys to a verified first boot.

Figure 1 shows what you build on which host and where each file goes.
:doc:`/internals/boot-flow` explains what happens at boot, and
:doc:`/internals/config-images` explains the images.

.. figure:: /images/operate-boot-artifacts.svg
   :alt: Three hosts. On the operator host, shirudo-gen-image builds the
         config image from config-root, shirudo-gen-runtime builds the
         runtime image and runtime-service.conf, and you write
         uki-bootstrap.conf from runtime.roothash. Arrows copy the images
         to /var/lib/shirudo/images on the target, runtime-service.conf
         to the drop-in of shirudo.service, and uki-bootstrap.conf to
         shirudo-gen-initrd, which builds the initrd. The initrd and the
         kernel image go to the Secure Boot signing host, which builds
         the UKI with the keyring parameters, and the signed UKI returns
         to the target.

   Figure 1. What boot integration builds on each host. An arrow between
   hosts is a copy you make.

Before you begin
----------------

- A target that meets :doc:`/operate/plan/system-requirements`, with the
  kernel options and command line from :doc:`/operate/plan/hardening`
  planned.
- The target package installed on the target. It installs the static
  ``shirudo`` binary, the systemd units, ``shirudo-gen-initrd`` and the
  dracut module ``90shirudo``. dracut must be installed.
- The operator package, ``mkfs.ext4`` and ``veritysetup`` on the operator
  host. The operator package installs the image generators in
  ``/usr/libexec/shirudo/gen-image/`` and the helper in
  ``/usr/libexec/shirudo/shirudo-build``. In a checkout they are
  :src:`tools/gen-image/` and ``tools/shirudo-build/shirudo-build``.
- The static target binary of the build you deploy: ``shirudo-target``
  from ``make target`` in a checkout, or ``/usr/bin/shirudo`` from the
  target package. Use the same build on the target and in the runtime
  image.
- The BPF signing certificate and the config signing key, created as
  described in :doc:`/operate/maintain/keys`. They may be the same key.
- Tooling to build and sign a UKI for Secure Boot, for example systemd's
  ``ukify``.

On the operator host, put the generators and the helper where the
commands below find them:

.. code-block:: console

   operator$ export PATH=/usr/libexec/shirudo/gen-image:$PATH
   operator$ export SHIRUDO_BUILD=/usr/libexec/shirudo/shirudo-build

Bootstrap files
---------------

A target reads two different bootstrap files. Both are called
``shirudo.conf`` on the target, and they take different keys.

.. list-table::
   :header-rows: 1
   :widths: 22 30 48

   * - File
     - Where it ends up
     - Keys
   * - Runtime bootstrap file
     - ``etc/shirudo/shirudo.conf`` in the runtime image, read as
       ``/run/shirudo/runtime/etc/shirudo/shirudo.conf``
     - Required: ``config.image``, ``config.verification_key``,
       ``config.pcr``. Optional: ``tpm.tcti``, ``tpm.owner_auth``,
       ``tls.classical_hosts``. A ``runtime.*`` key is refused.
   * - UKI bootstrap file
     - ``/etc/shirudo/shirudo.conf`` in the initrd, inside the signed UKI
     - Required: ``runtime.image``, ``runtime.root_hash``. Optional:
       ``tpm.owner_auth``.

At boot each file authenticates the next, as Figure 2 shows. Write the
runtime bootstrap file first: the UKI bootstrap file names the root hash
of the runtime image that carries it. :doc:`/reference/configuration`
describes every key.

.. figure:: /images/reference-config-chain.svg
   :alt: The UKI, signed for Secure Boot, carries the initrd's bootstrap
         with runtime.image, runtime.root_hash and tpm settings. Its root
         hash pins the runtime image, whose runtime bootstrap holds
         config.image, config.verification_key, config.pcr and the tpm
         and tls settings, beside the config certificates.
         config.image selects the config image and the certificates
         verify its signed root; the config image holds eventlog and
         map_export settings, repositories, the upatch tree, node labels
         and keys. The host file and the unit environment files are not
         authenticated.

   Figure 2. Where a target's settings come from, and what authenticates
   each file.

When the TPM owner hierarchy has a password, set ``tpm.owner_auth`` in
both files. Init reads it from the UKI file when it creates the TPM
writer key in the initrd, and from the runtime file when it defines the
register and in every later command. Give the UKI file mode ``0600``
before you generate the initrd: init refuses an owner password from a
file that another user could read.

Build the config image
----------------------

The config image holds the settings you can replace later with
``shirudo image update``. Its ``etc/shirudo/shirudo.conf`` is mandatory
and accepts only ``eventlog.max_bytes`` and ``map_export.*`` keys.

1. Create the source tree of the config image on the operator host:

   .. code-block:: console

      operator$ mkdir -p config-root/etc/shirudo

2. Write ``config-root/etc/shirudo/shirudo.conf``:

   .. code-block:: ini

      eventlog.max_bytes = 0

   shirudo refuses a config image whose file holds any other key, a line
   longer than 1023 bytes, or a line that is not a comment and has no
   ``=``. Repository definitions, the upatch tree subscription, node
   labels and further trusted keys go in the same tree.
   :doc:`/operate/run/deliver-packages` and :doc:`/operate/maintain/keys`
   describe them. The tree holds only regular files and directories, at
   most 65536 entries and 32 levels deep.

3. Build and sign the image:

   .. code-block:: console

      operator$ shirudo-gen-image --source config-root --output initial \
          --keys-dir <config-keys-dir> --kind config

   ``<config-keys-dir>`` holds ``signing_key.pem`` and ``cert.der`` of the
   config signing key. The generator writes the four ``initial.*`` files
   of Figure 1 and prints the root hash. It refuses to overwrite existing
   files and a source tree that holds a private key, a symbolic link or a
   special file.

4. Check the signature offline:

   .. code-block:: console

      operator$ shirudo image verify initial --cert <config-keys-dir>/cert.der

   The command prints the root hash again. ``image verify`` takes exactly
   this argument order.

Build the runtime image
-----------------------

1. Write the runtime bootstrap file, ``runtime.conf``:

   .. code-block:: ini

      config.image = /var/lib/shirudo/images/initial
      config.verification_key = /run/shirudo/runtime/etc/shirudo/config-cert.der
      config.pcr = 14
      tpm.tcti = device:/dev/tpmrm0

   ``config.image`` names the config image's prefix on the target. It must
   be below ``/var/lib/shirudo/images/``. Init uses it only on the first
   boot: from then on the activation record selects the config.
   ``config.verification_key`` must be a path inside the runtime image,
   and ``shirudo-gen-runtime`` puts the config certificate at the path
   shown. For config-key overlap, repeat ``--config-cert`` when generating
   the runtime; it installs numbered certificates and writes all their
   paths into this bootstrap. See :doc:`/operate/maintain/keys`.
   ``config.pcr`` is the TPM PCR that records config activations:
   0 to 15, except 9 and 11. Choose a PCR that nothing extends after the
   initrd has run, because a later extension makes every command but
   ``status`` refuse until the next reboot. :doc:`/operate/plan/hardening`
   discusses the choice. The test VM uses 14. A target needs a ``device:`` TCTI.

2. Build the runtime image and the drop-in for ``shirudo.service``:

   .. code-block:: console

      operator$ shirudo-gen-runtime --binary <target-binary> \
          --bootstrap-conf runtime.conf --cert <bpf-cert> \
          --config-cert <config-keys-dir>/cert.der --output runtime \
          --keys-dir <config-keys-dir> --unit-output runtime-service.conf

   ``<target-binary>`` is the static target binary. ``<bpf-cert>`` is the
   primary BPF signing certificate, which the image carries as
   ``keys/cert.der``. The generator writes the four ``runtime.*`` files
   and the drop-in of Figure 1, prints the root hash on standard output
   and the runtime invocation on standard error.

   Every executable on the runtime image runs with shirudo's authority.
   Add one with ``--extra-binary`` only when it should have that
   authority, and never add a shell or an interpreter.

3. Read the runtime root hash:

   .. code-block:: console

      operator$ cat runtime.roothash

Write the UKI bootstrap file
----------------------------

1. On the operator host, write ``uki-bootstrap.conf`` with the runtime
   root hash:

   .. code-block:: ini

      runtime.image = /var/lib/shirudo/images/runtime
      runtime.root_hash = <runtime-root-hash>

   ``<runtime-root-hash>`` is the 64-character content of
   ``runtime.roothash``. ``runtime.image`` is the runtime image's prefix as
   the initrd sees it. The initrd checks the image against this hash and
   refuses any other.

Copy the files to the target
----------------------------

The rest of the procedure runs on the target, in a directory only root
can read, until you build the UKI.

1. Copy what you built on the operator host into that directory, with
   ``scp`` or any channel you trust:

   - ``runtime.img``, ``runtime.verity`` and ``runtime.roothash``;
   - ``initial.img``, ``initial.verity``, ``initial.roothash`` and
     ``initial.p7s``;
   - ``runtime-service.conf``;
   - ``uki-bootstrap.conf``;
   - the primary BPF signing certificate, ``<bpf-cert>``.

2. Give the UKI bootstrap file mode ``0600``:

   .. code-block:: console

      target# chmod 0600 uki-bootstrap.conf

Place the images on the target
------------------------------

Place the images before the first boot with enforcement. Once init has
run, the seal refuses root's writes and new entries under
``/var/lib/shirudo``.

1. Create the image directory on the target's root file system:

   .. code-block:: console

      target# install -d -m 0700 -o root -g root /var/lib/shirudo/images

2. Copy the runtime image into it:

   .. code-block:: console

      target# install -m 0644 runtime.img runtime.verity runtime.roothash \
          /var/lib/shirudo/images/

   The runtime image needs these three files. Its root hash comes from the
   UKI, so the target does not use ``runtime.p7s``.

3. Copy the config image into it:

   .. code-block:: console

      target# install -m 0644 initial.img initial.verity initial.roothash \
          initial.p7s /var/lib/shirudo/images/

   A config image needs all four files.

``/var/lib/shirudo`` must be a directory on the root file system, or on a
file system the initrd mounts below ``/sysroot`` (``x-initrd.mount``).
``shirudo-initrd.service`` remounts ``/sysroot`` read-write, because init
writes the activation record there before it extends the config PCR.

.. _unit-drop-ins:

Install the unit drop-ins
-------------------------

The shipped target units already invoke
``/run/shirudo/runtime/usr/bin/shirudo`` directly and gate on
``ConditionPathIsMountPoint=/run/shirudo/runtime``. For the static PIE
target package, all six root-filesystem services work without drop-ins;
installing the ``shirudo.service`` drop-in from ``--unit-output`` is
only needed to clear ``EnvironmentFile=`` and drop
``$SHIRUDO_INIT_ARGS`` on ``shirudo.service``:

.. code-block:: console

   target# install -D -m 0644 runtime-service.conf \
       /etc/systemd/system/shirudo.service.d/runtime.conf
   target# systemctl daemon-reload

For a dynamically linked binary, pass ``--unit-dir <dir>`` to
``shirudo-gen-runtime`` to generate ``<unit>.d/runtime.conf`` for all
six target services (``shirudo``, ``shirudo-keepalive``,
``shirudo-map-export``, ``shirudo-xdp-reconcile``,
``shirudo-bpm-repo-update`` and ``shirudo-bpm-tree-sync``), copy the
generated ``*.service.d`` directories into ``/etc/systemd/system/`` and
run ``systemctl daemon-reload``. ``shirudo-initrd.service`` needs no
drop-in: it runs in the initrd, from the binary the UKI authenticates.
:doc:`/reference/systemd-units` lists the units and their schedules.

The deb and rpm packages enable ``shirudo.service`` and the five timers
for the next boot. Their message "To enforce now: systemctl start
shirudo.service" does not apply: the unit runs only when the initrd has
mounted the runtime image at ``/run/shirudo/runtime``.

Build the initrd
----------------

1. Generate the initrd on the target:

   .. code-block:: console

      target# shirudo-gen-initrd --bootstrap-conf uki-bootstrap.conf \
          --cert <bpf-cert> --kver <kernel-release> \
          --output /boot/initrd-shirudo-<kernel-release>.img

   ``<kernel-release>`` is the release of the kernel the UKI boots.
   ``<bpf-cert>`` is the primary BPF signing certificate. The initrd
   carries it for the pre-flight check and for the unit's start
   condition. The initrd embeds the installed ``/usr/bin/shirudo``,
   ``uki-bootstrap.conf`` as ``/etc/shirudo/shirudo.conf``,
   ``shirudo-initrd.service`` enabled, the TPM drivers and the dm-verity,
   loop and ext4 modules.

   With ``--bootstrap-conf`` or ``--cert``, the generator runs dracut with
   a configuration of its own and ignores ``/etc/dracut.conf`` and
   ``/etc/dracut.conf.d/``. Pass further dracut options after ``--``.

2. Check the result:

   .. code-block:: console

      target# shirudo-gen-initrd --check /boot/initrd-shirudo-<kernel-release>.img

   The check fails unless the archive holds the binary, the certificate,
   the bootstrap file, the unit and its enablement,
   ``systemd-pcrphase-initrd.service`` and ``/etc/initrd-release``.

The generator also says that the kernel command line lacks
``bpf.keyring_unsealed=1`` and ``dm_verity.keyring_unsealed=1`` when the
running kernel was booted without them. The next step adds them.

Build and sign the UKI
----------------------

1. Print the kernel parameters the initrd needs:

   .. code-block:: console

      target# shirudo-gen-initrd --print-cmdline
      bpf.keyring_unsealed=1 dm_verity.keyring_unsealed=1

2. Copy the initrd and the kernel image of ``<kernel-release>`` to the
   host that holds your Secure Boot signing key, the operator host in
   most deployments. There, build a UKI from them and a command line that
   carries both parameters, and sign it for Secure Boot.

   Without the parameters the kernel seals both keyrings empty at boot,
   and init fails. The command line also needs ``bpf`` in the ``lsm=``
   list, unless ``CONFIG_LSM`` has it already, and the settings from
   :doc:`/operate/plan/hardening`.

3. Copy the signed UKI to the target's EFI system partition and make it
   the default boot entry.

The UKI must boot through systemd's stub, so that
``systemd-pcrphase-initrd.service`` measures the ``enter-initrd`` phase
into PCR 11 before init binds the measurement register. Without a
measured UKI, init logs that PCR 11 holds no phase measurement, and a
verifier cannot tell an initrd binding from a later one.

No other unit may seal ``.bpf`` or ``.dm-verity`` before
``shirudo-initrd.service`` runs, for example systemd's
``systemd-keyring-setup`` where your systemd ships it. Init refuses a
keyring that another task restricted, and fails.

.. _runtime-invocation:

Run shirudo on the target
-------------------------

On a production target, the only ``shirudo`` with runtime authority is
the binary on the runtime image, ``/run/shirudo/runtime/usr/bin/shirudo``.
shirudo's LSM programs grant that authority to a process when it executes
a file from the authenticated runtime image. Any other copy of the
binary, the package's ``/usr/bin/shirudo`` included, is refused before
the command starts:

.. code-block:: console

   target# /usr/bin/shirudo status
   shirudo: image state: Permission denied

The exit status is 1. No wrapper ships for interactive use. Define an
alias in your root shell:

.. code-block:: console

   target# alias shirudo=/run/shirudo/runtime/usr/bin/shirudo

The operate pages write ``target# shirudo`` for this binary. A
dynamically linked runtime binary runs through the image's loader, with
the invocation that ``shirudo-gen-runtime`` prints. Of the target
commands, only ``version`` and ``help`` work from another copy.

Boot and verify
---------------

1. Reboot the target into the UKI:

   .. code-block:: console

      target# systemctl reboot

2. Read the status report:

   .. code-block:: console

      target# shirudo status
      Host:                  docs
      Roles:                 target
      Status:                ok
      Version ID:            d0d7aa800303439023907d1979d917d46a21bec21f816689c138728a28e84af9

      Conditions:
        TYPE               STATUS  DETAIL
        LsmAttached        OK      lsm/bpf link present and pinned
        KeyringSealed      OK      bpf serial 272801410, dm-verity serial 799624487, pins match
        ChainIntact        OK      live register equals the eventlog replay
        UpatchesMeasured   OK      every pinned or archived upatch is in this boot's records
        TpmMeasured        OK      NV index 0x01818E00 readable
        ConfigActive       OK      config 6d5ed552f448.. is active
        XdpCovered         OK      every device an XDP upatch selects runs it

      Tamper attempts (this boot):
        LoadNotLoader            15  program load that is not a signed loader
        MapCreate                 1  map creation by another executable
        BpfCommand                8  detach, update, delete or unclassified bpf() command
        BpffsUmount               1  unmount of the private bpffs
        SealWrite                 1  write open of a sealed file
        SealEntry                 2  entry into a sealed directory, or a sealed inode linked

      Integrity attempts (this boot):
        none

      Loaded upatches (1):
        NAME                      LOCATION                       MAPS  MISSED  STATUS                        AGE
        shirudo-test-basic        fentry/do_nanosleep               0       0  success                       1s

      Folded: keyrings, TPM measurement, assets (--show-full)

   Check for ``Status: ok`` and every condition ``OK``. The
   ``LsmAttached`` condition confirms the LSM link is pinned.
   ``ConfigActive`` names the first 12 hex digits of the active config
   root. ``shirudo status --show-full`` prints the folded
   TPM measurement section, whose ``Bound in:`` line must read
   ``initrd``. :doc:`/operate/run/read-status` explains every section.

3. Check the config activation:

   .. code-block:: console

      target# shirudo image status
      Config root hash:      6d5ed552f4487728d1ccec8604ddb44b66b18e3430614c20bb4d284995f99f63
      PCR:                   14
      Sequence:              1
      TPM reset count:       1
      Restart count:         0
      Pending:               no
      Consistent:            yes

   ``Config root hash`` is the root of ``initial``, ``PCR`` is
   ``config.pcr``, ``Pending`` is ``no`` and ``Consistent`` is ``yes``.
   The command exits 1 when the activation is pending or inconsistent,
   and ``--json`` prints the same fields as one JSON document.

4. Read both init runs in the journal:

   .. code-block:: console

      target# journalctl -b -u shirudo-initrd.service -u shirudo.service

   The initrd run ends with
   ``tpm: register bound in the initrd and extended (index 0x01818E00,
   PCR 9 anchored, <n> upatches in set)`` and
   ``init: complete (LSM active, writable state sealed)``. The root run
   logs ``tpm: register already bound this boot; chain unchanged`` and
   completes. :doc:`/operate/deploy/initialize` describes both runs and what to
   do when one fails.

Next steps
----------

- :doc:`/operate/deploy/initialize` to check init after every boot and handle
  its failures
- :doc:`/operate/run/attest` to enroll the target's attestation key
- :doc:`/operate/run/deliver-packages` to deliver upatches from a registry
- :doc:`/operate/maintain/upgrade` to replace the runtime image or the kernel
