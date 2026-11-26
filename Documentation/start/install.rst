..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators

Install shirudo
===============

shirudo installs in one of two roles. The operator host holds the signing
key and builds, signs and publishes. A target verifies and enforces. Each
role has its own package, built from a checkout, and one host takes one
role. This page installs the packages, or the same files from source, and
lists what a target needs before it enforces anything.

Before you begin
----------------

- Decide which hosts are operators and which are targets.
  :doc:`/concepts/operator-and-target` explains the split.
- A checkout of shirudo on a build host that meets the build requirements
  in :doc:`/operate/plan/system-requirements`.
- ``dpkg-deb`` (package ``dpkg-dev``) to build ``.deb`` packages, or
  ``rpmbuild`` (package ``rpm`` on Debian and Ubuntu, ``rpm-build`` on
  Fedora) to build ``.rpm`` packages.
- The target package links everything statically and installs on any
  supported distribution. The operator package links the build host's
  shared libraries, so build it on the distribution you install it on.

Packages
--------

.. list-table::
   :header-rows: 1
   :widths: 22 18 60

   * - Package
     - Host
     - Installs
   * - ``shirudo-operator``
     - Operator host
     - - ``/usr/bin/shirudo``, linked against the host's shared libraries
       - the helper ``/usr/libexec/shirudo/shirudo-build``
       - ``/usr/bin/shirudo-quote-check``, a static PIE that checks
         keepalive quotes for a telemetry backend
       - the image generators ``shirudo-gen-image``,
         ``shirudo-gen-runtime`` and ``shirudo-gen-verity`` under
         ``/usr/libexec/shirudo/gen-image/``
       - ``/usr/share/shirudo/vmlinux.h``, the one the package was built
         with
       - the BPF headers under ``/usr/share/shirudo/bpf/include/``
       - bash completion

       It depends on clang 23, LLVM and ``veritysetup``
       (``cryptsetup-bin`` or ``cryptsetup``) and installs no systemd
       unit. :doc:`/operate/plan/system-requirements` says where clang 23
       comes from.
   * - ``shirudo-target``
     - Target
     - - ``/usr/bin/shirudo``, a static PIE
       - ``/usr/bin/shirudo-gen-initrd``
       - the dracut module ``/usr/lib/dracut/modules.d/90shirudo``
       - the units ``shirudo.service`` and ``shirudo-initrd.service``
       - the services ``shirudo-map-export``, ``shirudo-keepalive``,
         ``shirudo-xdp-reconcile``, ``shirudo-bpm-repo-update`` and
         ``shirudo-bpm-tree-sync``, each with its timer
       - the udev rule ``90-shirudo-xdp-reconcile.rules``
       - bash completion

       It carries no key and no configuration file.

Both packages install ``/usr/bin/shirudo``, so they conflict, and a host
holds only one of them. On a development host that plays both roles, run
shirudo from a checkout as in the :doc:`quickstart`.

Build the packages
------------------

1. In the checkout, build the ``.deb`` packages:

   .. code-block:: console

      $ make -C packaging bindeb-pkg

   The build starts from ``make clean``, rebuilds with the prefix
   ``/usr`` and writes ``shirudo-target_<version>_<arch>.deb`` and
   ``shirudo-operator_<version>_<arch>.deb`` to the checkout root.
   For ``.rpm`` packages, run ``make -C packaging binrpm-pkg`` instead,
   which writes ``shirudo-target-<version>-<release>.<arch>.rpm`` and
   ``shirudo-operator-<version>-<release>.<arch>.rpm``.

2. To build the operator package for another distribution, build only
   that package on a host of that distribution:

   .. code-block:: console

      $ make -C packaging bindeb-pkg PKG_ROLES=operator

   ``PKG_ROLES=target`` builds only the target package. On Fedora,
   which ships no static ``libcrypto``, the operator build also
   downloads and builds a static OpenSSL for ``shirudo-quote-check``
   and needs ``perl`` and ``glibc-static`` for it.

Install the operator package
----------------------------

1. Install the package on the operator host:

   .. code-block:: console

      # apt install ./shirudo-operator_<version>_<arch>.deb

   On an RPM distribution, run
   ``dnf install ./shirudo-operator-<version>-<release>.<arch>.rpm``.

2. Check that ``shirudo`` finds its helper:

   .. code-block:: console

      operator$ shirudo build --help
      ...
      SHIRUDO_BUILD, /usr/libexec/shirudo/shirudo-build, then shirudo-build on PATH.
      ...

   The second path is where the package installed the helper.

Install the target package
--------------------------

1. Install the package on the target:

   .. code-block:: console

      # apt install ./shirudo-target_<version>_<arch>.deb
      ...
      shirudo: shirudo.service enabled; it runs 'shirudo init' early on the
      shirudo: next boot. To enforce now: systemctl start shirudo.service
      shirudo: shirudo-map-export.timer enabled for the next boot
      shirudo: shirudo-keepalive.timer enabled for the next boot
      shirudo: shirudo-xdp-reconcile.timer enabled for the next boot
      shirudo: shirudo-bpm-repo-update.timer enabled for the next boot
      shirudo: shirudo-bpm-tree-sync.timer enabled for the next boot

   On an RPM distribution, run
   ``dnf install ./shirudo-target-<version>-<release>.<arch>.rpm``. The RPM
   prints the same lines on its first installation.

   The package enables ``shirudo.service`` and the five timers for the next
   boot and starts none of them. Starting ``shirudo.service`` by hand does
   nothing yet, whatever the message says: the unit runs only when
   ``/run/shirudo/runtime`` is mounted, and the shirudo initrd mounts it at
   boot. Removing the package disables the units again.

2. Check the pre-flight on the target:

   .. code-block:: console

      target# shirudo init --check-only

   It lists each prerequisite of ``init`` with its result and changes no
   enforcement state. On a fresh target it reports what is still missing,
   such as the certificate.

Install the target from a tarball
---------------------------------

``make -C packaging bintar-pkg`` builds two target tarballs,
``shirudo.tar.gz`` and ``shirudo-static.tar.gz``. Both carry the same
static target binary and the other files of the target package, with the
binaries under ``/usr/local/bin``.

1. Unpack the tarball on the target:

   .. code-block:: console

      $ tar -xzf shirudo.tar.gz

2. Run its installer as root:

   .. code-block:: console

      # ./shirudo-installer/install.sh
      shirudo installer: installed into /

   The installer copies the files and reloads systemd. It enables no unit:
   enable ``shirudo.service`` and the timers yourself with
   ``systemctl enable``. Set ``DESTDIR=<dir>`` to stage the files into
   ``<dir>`` instead.

Install from source
-------------------

The install targets of the checkout install the same files as the
packages, with the binaries under ``/usr/local`` unless you set
``prefix``. Like the packages, the two roles install the same
``bin/shirudo``, so install one role per host.

1. On an operator host, build and install the operator role:

   .. code-block:: console

      # make install-operator

2. On a target, build and install the target role:

   .. code-block:: console

      # make install-target

   This builds OpenSSL, libcurl and tpm2-tss from source first and links
   the static target binary against them and the static archives that
   :doc:`/operate/plan/system-requirements` lists. It enables no unit.

3. Check the installation on either host:

   .. code-block:: console

      $ shirudo version

   It prints the release and the version ID that ``upatch load
   --expect-version-id`` compares against.

Before a target enforces
------------------------

Installing ``shirudo-target`` protects nothing by itself. A target
enforces once it boots through the shirudo initrd with everything that
``init`` verifies there:

- A kernel that meets :doc:`/operate/plan/system-requirements`, booted with
  the BPF LSM active and with ``bpf.keyring_unsealed=1
  dm_verity.keyring_unsealed=1``, so that ``init`` can enroll the trusted
  certificates and then seal the ``.bpf`` and ``.dm-verity`` keyrings.
- A TPM 2.0 that the kernel exposes as ``/dev/tpmrm0``.
- The operator's certificate in ``/var/lib/shirudo/keys/cert.der``, which
  the dracut module copies into the initrd.
- A dm-verity runtime image and a signed config image, built on the
  operator host with the image generators, and the bootstrap
  configuration that names them.
- An initrd built with ``shirudo-gen-initrd``, booted from an
  authenticated unified kernel image.
- For a static PIE target package, the shipped root-filesystem units
  already invoke ``/run/shirudo/runtime/usr/bin/shirudo``. For a
  dynamically linked binary, install the drop-ins that
  ``shirudo-gen-runtime --unit-dir`` writes for all six target services.

:doc:`/operate/deploy/boot-integration` sets these up. After the reboot,
``shirudo status`` on the target shows ``Status: ok`` with every
condition ``OK``, and ``shirudo status --show-full`` shows ``Bound in:
initrd``.

Next steps
----------

- :doc:`/operate/deploy/boot-integration` brings an installed target up.
- :doc:`/operate/deploy/deployment-checklist` lists every step of a rollout.
- :doc:`/operate/maintain/keys` creates the signing key on the operator host.
- :doc:`quickstart` tries everything in a test VM first.
