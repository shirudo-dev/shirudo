..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

Image and initrd generators
===========================

Four Bash scripts build the signed images and the initrd a target boots
with: ``shirudo-gen-image``, ``shirudo-gen-runtime`` and
``shirudo-gen-verity`` on the operator host, ``shirudo-gen-initrd`` on the
target.

.. list-table::
   :header-rows: 1
   :widths: 24 30 46

   * - Script
     - Installed by, to
     - Purpose
   * - ``shirudo-gen-image``
     - operator package, ``$(libexecdir)/shirudo/gen-image/``
     - Build a signed image from a directory.
   * - ``shirudo-gen-runtime``
     - operator package, ``$(libexecdir)/shirudo/gen-image/``
     - Build the signed runtime image and its ``shirudo.service`` drop-in.
   * - ``shirudo-gen-verity``
     - operator package, ``$(libexecdir)/shirudo/gen-image/``
     - Sign an existing ext4 image. ``shirudo image build`` runs it.
   * - ``shirudo-gen-initrd``
     - target package, ``$(bindir)``
     - Build and check the initrd with the dracut module ``90shirudo``.

``$(libexecdir)`` is ``/usr/libexec`` in the distribution packages and
``/usr/local/libexec`` after ``make install``. Every option of the scripts
takes its value as the next argument. None accepts ``--option=<value>``.
A script that fails prints ``<script>: <reason>`` and exits with 1, or
with the status of the tool that failed. ``-h`` and ``--help`` print the
usage on standard output.

Runs on: as listed above. Requires: listed per script. Changes measured
state: no. A target measures the images when it activates them.

shirudo-gen-image
-----------------

.. code-block:: none

   shirudo-gen-image --source <directory> --output <prefix> --keys-dir <dir>
                     [--kind config|runtime] [--size <mib>] [--builder <helper>]

Builds an ext4 file system of ``--size`` MiB from ``<directory>`` (owner
root, no journal, 4096-byte blocks) and signs it with
``shirudo-gen-verity``. It writes ``<prefix>.img``, ``.verity``,
``.roothash`` and ``.p7s`` and replaces no existing file.

It refuses a source that contains a file named ``signing_key.pem``, a
special file, a source that contains the keys directory, and for
``--kind config`` any symbolic link. Files that do not fit ``--size``
make it fail with ``<n> KiB of files do not fit an image of <size> MiB;
raise --size``. Requires ``mkfs.ext4`` and ``veritysetup``.

.. list-table::
   :header-rows: 1
   :widths: 20 30 50

   * - Option
     - Default
     - Description
   * - ``--source``
     - required
     - Directory that becomes the root of the image.
   * - ``--output``
     - required
     - Output prefix.
   * - ``--keys-dir``
     - required
     - Operator keys directory, outside ``--source``.
   * - ``--kind``
     - ``config``
     - ``config`` or ``runtime``.
   * - ``--size``
     - 1
     - File system size in MiB, 1 to 1048576.
   * - ``--builder``
     - ``$SHIRUDO_BUILD``, else ``shirudo-build``
     - The helper that signs the root hash.

shirudo-gen-runtime
-------------------

.. code-block:: none

   shirudo-gen-runtime --binary <shirudo> --bootstrap-conf <file>
                       --cert <certificate> --config-cert <certificate>
                       --output <prefix> --keys-dir <dir>
                       [--size <mib>] [--builder <helper>]
                       [--unit-output <file>] [--extra-binary <file>]...
                       [--config-cert <additional-certificate>]...

Builds the runtime image, the image whose root hash the bootstrap
settings pin. It holds:

- ``usr/bin/shirudo``: ``--binary``, the target binary without its
  symbols and debug sections, as ``llvm-strip`` writes it
- ``etc/shirudo/shirudo.conf``: ``--bootstrap-conf``
- ``keys/cert.der``: ``--cert``, the initial BPF signing certificate
- ``etc/shirudo/config-cert.der``: the first ``--config-cert``;
  additional certificates are ``config-cert-2.der``, ``config-cert-3.der``
  and on. Any of them may sign a config image
- for a dynamically linked binary, its ELF interpreter and libraries
  under their own paths, found with ``ldd``
- each ``--extra-binary`` under ``usr/bin/`` with its libraries

It prints the runtime invocation on standard error, for example
``/run/shirudo/runtime/usr/bin/shirudo init`` for a static binary. With
``--unit-output`` it writes a systemd drop-in for ``shirudo.service``
that clears ``EnvironmentFile=`` and ``ExecStart=`` and runs the runtime
binary with ``init``. No drop-in is written for the other units.

``ldd`` runs the inputs' dynamic loader on the operator host: pass only
trusted binaries. Requires ``readelf``, ``ldd`` and ``llvm-strip``.

.. list-table::
   :header-rows: 1
   :widths: 20 30 50

   * - Option
     - Default
     - Description
   * - ``--binary``
     - required
     - The ``shirudo`` binary for the target.
   * - ``--bootstrap-conf``
     - required
     - The bootstrap ``shirudo.conf``
       (:doc:`/reference/formats/configuration`).
   * - ``--cert``
     - required
     - The initial BPF signing certificate.
   * - ``--config-cert``
     - required
     - The config image verification certificate. Repeatable, at most 16.
       With several certificates, the generator replaces the bootstrap's
       ``config.verification_key`` entries with their installed paths.
       With one certificate it preserves the bootstrap file.
   * - ``--output``
     - required
     - Output prefix.
   * - ``--keys-dir``
     - required
     - Operator keys directory that signs the image.
   * - ``--size``
     - 15
     - File system size in MiB, 1 to 1048576. The default holds the
       stripped static target binary and its certificates. A dynamic
       binary with its libraries or an ``--extra-binary`` may need more.
   * - ``--builder``
     - ``$SHIRUDO_BUILD``, else ``shirudo-build``
     - The signing helper.
   * - ``--unit-output``
     - none
     - Write the ``shirudo.service`` drop-in to this new file.
   * - ``--extra-binary``
     - none
     - A further trusted executable for the image. Repeatable.

shirudo-gen-verity
------------------

.. code-block:: none

   shirudo-gen-verity <filesystem-image> -o <prefix> [--kind config|runtime]
                      [--keys-dir <dir>] [--key <signing-key>]
                      [--cert <certificate>] [--salt <salt>]
                      [--builder <helper>]

Formats the dm-verity hash tree of an existing ext4 image with
``veritysetup``, signs the root hash, verifies the result and prints the
root hash. :doc:`image` describes it as ``shirudo image build``, which
passes ``--builder`` itself.

.. list-table::
   :header-rows: 1
   :widths: 20 30 50

   * - Option
     - Default
     - Description
   * - ``-o``, ``--output``
     - required
     - Output prefix.
   * - ``--kind``
     - ``config``
     - ``config`` or ``runtime``. Validated, no other effect.
   * - ``--keys-dir``
     - ``$SHIRUDO_KEYS_DIR``, else ``/var/lib/shirudo/keys``
     - Directory of the signing key and certificate.
   * - ``--key``, ``--cert``
     - from ``--keys-dir``
     - Signing key and certificate.
   * - ``--salt``
     - chosen by ``veritysetup``
     - 64 hexadecimal characters.
   * - ``--builder``
     - ``$SHIRUDO_BUILD``, else ``shirudo-build``
     - The signing helper.

shirudo-gen-initrd
------------------

.. code-block:: none

   shirudo-gen-initrd [--kver <release>] [--output <file>]
                      [--cert <certificate>] [--trusted-dir <dir>]
                      [--binary <file> --binary-path <path>]
                      [--unit <file>] [--bootstrap-conf <file>]
                      [--kmoddir <dir>] [--no-kernel] [--module-dir <dir>]
                      [-- <dracut-arguments>]
   shirudo-gen-initrd --check [<file>] [--kver <release>] [--output <file>]
   shirudo-gen-initrd --print-cmdline

Runs ``dracut --force --add shirudo`` for a kernel release, then checks
the result. It requires ``dracut``, and root unless ``--output`` names
where to write: without it the initrd replaces the one the host boots.
Run as another user, dracut writes every member of the archive as owned
by root. The initrd holds the
binary at its root file system path, the primary certificate as
``/etc/shirudo/keys/cert.der``, the trusted certificates and their vouches
under ``/etc/shirudo/keys/trusted/``, the bootstrap
``/etc/shirudo/shirudo.conf`` and ``shirudo-initrd.service``, enabled.

When ``--module-dir`` or the script's own directory holds
``module-setup.sh``, dracut runs on a private copy of its base directory
whose ``modules.d/90shirudo`` is that module, and the host's
``/usr/lib/dracut`` is left as it is. Otherwise the module comes from
``/usr/lib/dracut/modules.d/90shirudo``. Paths given on the command line reach the module through a
generated ``dracut.conf`` that also leaves out the host's drop-ins.

The check lists the archive with ``lsinitrd`` and fails unless it holds
the shirudo binary, ``etc/shirudo/keys/cert.der``,
``etc/shirudo/shirudo.conf``, ``shirudo-initrd.service`` and its
enablement, ``systemd-pcrphase-initrd.service`` and
``etc/initrd-release``. After a build, the script warns when the running
kernel's command line lacks ``bpf.keyring_unsealed=1`` or
``dm_verity.keyring_unsealed=1``.

.. list-table::
   :header-rows: 1
   :widths: 22 33 45

   * - Option
     - Default
     - Description
   * - ``--kver``
     - ``uname -r``
     - Kernel release.
   * - ``--output``
     - ``/boot/initrd.img-<release>`` on Debian without
       ``/boot/loader/entries`` or ``/etc/kernel/cmdline``,
       ``/boot/initramfs-<release>.img`` elsewhere
     - Initrd to write, or to check.
   * - ``--check``
     - the ``--output`` path
     - Only check an initrd.
   * - ``--print-cmdline``
     - off
     - Print the kernel parameters the initrd needs and exit.
   * - ``--cert``
     - ``/var/lib/shirudo/keys/cert.der``
     - Primary certificate to embed.
   * - ``--trusted-dir``
     - ``trusted/`` beside the certificate
     - Further certificates and their vouches.
   * - ``--binary``
     - the installed ``shirudo``
     - Binary to embed. Needs ``--binary-path``.
   * - ``--binary-path``
     - the binary's path
     - Where the binary lives on the root file system.
   * - ``--unit``
     - the installed ``shirudo-initrd.service``
     - Unit to embed.
   * - ``--bootstrap-conf``
     - ``/etc/shirudo/shirudo.conf``
     - Bootstrap settings to embed. The module fails without a readable
       file.
   * - ``--kmoddir``
     - dracut's
     - Take kernel modules from ``<dir>/<release>``.
   * - ``--no-kernel``
     - off
     - Embed no kernel modules.
   * - ``--module-dir``
     - the script's directory
     - The dracut module to build with.
   * - ``--``
     -
     - Pass the remaining arguments to ``dracut``.

Examples
--------

Build a config image from a directory:

.. code-block:: console

   operator$ /usr/libexec/shirudo/gen-image/shirudo-gen-image --source ./config-root --output ./config --keys-dir ~/shirudo-keys --kind config

Build the runtime image and its drop-in:

.. code-block:: console

   operator$ /usr/libexec/shirudo/gen-image/shirudo-gen-runtime --binary <target-binary> --bootstrap-conf bootstrap.conf --cert cert.der --config-cert config-cert.der --output ./runtime --keys-dir ~/shirudo-keys --unit-output ./runtime.conf

``<target-binary>`` is the static ``shirudo`` of the target package.

Build the initrd for the running kernel and print the kernel parameters it
needs:

.. code-block:: console

   target# shirudo-gen-initrd --bootstrap-conf <bootstrap-conf>
   target# shirudo-gen-initrd --print-cmdline
   bpf.keyring_unsealed=1 dm_verity.keyring_unsealed=1

``<bootstrap-conf>`` is the bootstrap ``shirudo.conf`` that names the
runtime image (:doc:`/reference/formats/configuration`).

Related
-------

- :doc:`image`
- :doc:`/operate/deploy/boot-integration`
- :doc:`/internals/boot-flow`
- :doc:`/internals/config-images`
- :doc:`/reference/formats/configuration`
