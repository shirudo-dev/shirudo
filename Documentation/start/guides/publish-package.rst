..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Tutorial
:audience: Operators, upatch authors

Publish and install a package
=============================

In this tutorial you put a upatch into a package, publish the package to
an OCI registry on your host and install it on the test target from
there. Targets always pull: the operator publishes to a registry, and the
target fetches, checks and loads.

A package is a ``.bee`` archive built from a ``Beefile``. It holds the
``Beefile``, the signed upatches, the signed unload directive of each,
the certificate of the key that signed them, the README when the package
directory has one, and ``build-environment.json``, a record of the build.

Before you begin
----------------

- The test VM from the :doc:`/start/quickstart`, running as
  ``quickstart``
- The operator shell from the quickstart: in the root of your checkout,
  with ``shirudo`` and ``shirudo-build`` on ``PATH`` and ``KEYS`` naming
  the test VM's key directory
- Docker on the operator host, for a local registry
- A root shell on the target, in which ``shirudo`` runs the runtime
  binary:

  .. guide-check: skip

  .. code-block:: console

     operator$ make vm-ssh VM_NAME=quickstart

Start a registry
----------------

1. Run a registry on the host's loopback interface:

   .. guide-check: registry

   .. code-block:: console

      operator$ docker run -d --name shirudo-registry -p 127.0.0.1:5000:5000 docker.io/library/registry:3

   The registry speaks plain HTTP on port 5000. The test VM reaches the
   host's loopback interface at ``10.0.2.2`` through QEMU's user network.

Build the package
-----------------

1. Make a package directory with a upatch in it:

   .. code-block:: console

      operator$ mkdir ~/hello
      operator$ cp testing/fixtures/basic.bpf.c ~/hello/hello.bpf.c

2. Link the checkout's vendored headers into it:

   .. code-block:: console

      operator$ ln -s "$PWD/vendor" ~/hello/vendor

   The helper compiles in the package directory and looks for the libbpf
   headers and ``vmlinux.h`` under :src:`vendor/` there. An installed operator
   package uses its own copies under ``/usr/share/shirudo`` and needs no
   link.

3. Write ``~/hello/Beefile``:

   .. guide-check: write ~/hello/Beefile

   .. code-block:: toml

      [package]
      name = "hello"
      description = "A first shirudo package"
      license = "GPL-2.0 OR BSD-2-Clause"

      [[upatches]]
      source = "hello.bpf.c"

   Each ``[[upatches]]`` table names one BPF source. The upatch takes its
   name, ``hello``, from the file name.

4. Write ``~/hello/README.md``:

   .. guide-check: write ~/hello/README.md

   .. code-block:: markdown

      # hello

      The hello package installs the hello upatch, an fentry program on
      do_nanosleep that does nothing.

   ``shirudo bpm info`` prints this file from a package archive or an
   ``oci://`` reference, for whoever inspects the package.

5. Build the package from its parent directory:

   .. code-block:: console

      operator$ cd ~
      operator$ shirudo bpm build hello --version 1.0.0 --keys-dir "$KEYS"
      wrote /tmp/shirudo-bpm-build.<random>/0.upatch (insns=992 sig=4853 data=2376 sections=2 maps=0 progs=1 decoders=0 name=hello)
      wrote /tmp/shirudo-bpm-build.<random>/0.unload.upatch (insns=1320 sig=4853 data=2808 sections=2 maps=1 progs=1 decoders=0 name=hello UNLOAD)
      /root/hello-1.0.0.bee

   ``<random>`` is the suffix of a temporary directory. The builder
   compiles and signs the upatch, signs an unload directive bound to its
   payload, and writes ``<name>-<version>.bee`` to the current directory.
   The archive itself is not signed: what protects the target are the
   signatures on its upatches and directives.

Publish it
----------

1. Push the package to the registry:

   .. code-block:: console

      operator$ BPM_OCI_SCHEME=http shirudo bpm push hello-1.0.0.bee oci://127.0.0.1:5000/example/hello --keys-dir "$KEYS" --new-index
      oci://127.0.0.1:5000/example/hello:1.0.0

   The push tags the package with its version. With ``--keys-dir``, it
   also adds the package to the registry's signed index,
   ``<namespace>/bpm-index:stable``, which targets read when they install from
   a registered repository. ``--new-index`` starts that index, as this is
   the namespace's first package; later pushes leave it out. ``BPM_OCI_SCHEME=http`` drops TLS, which suits
   only a registry on your own host. Without it, shirudo speaks HTTPS with
   TLS 1.3 and a hybrid ML-KEM key exchange.

Install it on the target
------------------------

On a production target, the signed config image registers the
repositories the target may install from. The test VM's config registers
none, so here the target installs by direct reference.

1. Install the package:

   .. code-block:: console

      target# BPM_OCI_SCHEME=http shirudo bpm install oci://10.0.2.2:5000/example/hello:1.0.0
      upatch load: --no-precheck, pre-flight state check skipped
      upatch load: signed loader accepted, keyring 272801410, 124 instructions
      upatch load: loader ran, 0 maps and 1 programs
      upatch load: program 0 (raw_tracepoint) pinned at /run/shirudo/bpffs/upatches/hello/link
      upatch load: hello loaded, 1 programs, keyring 272801410
      upatch load: hello measured, register 55a8c670eb10d9bc6a9dc7475e3fc94407066016798dddbc59870138525f61b6

   The target honors ``BPM_OCI_SCHEME`` as the operator does. It
   downloads the package and checks its digest against the registry's
   manifest. It refuses the package unless the package's certificate
   holds the same public key as the target's
   ``/var/lib/shirudo/keys/cert.der``. Then it loads every upatch in the
   package as ``shirudo upatch load --no-precheck`` does: the kernel checks
   each signature and the target measures each load.

2. List the installed packages:

   .. guide-check: match ^\s+hello\s+1\.0\.0\s+direct$

   .. code-block:: console

      target# shirudo bpm list
      Installed packages:
        NAME                      VERSION       SOURCE
        hello                     1.0.0         direct

   ``direct`` marks a package installed by reference rather than from a
   registered repository.

3. Check that its upatch is loaded:

   .. guide-check: match ^\s+hello\s+yes\s

   .. code-block:: console

      target# shirudo upatch list
      Archived upatches (/var/lib/shirudo/upatches):
        NAME                      LOADED  TYPE    KIND  PAYLOAD
        hello                     yes     load    bpf   109848737a32f431..

Remove it
---------

1. Uninstall the package on the target:

   .. guide-check: match hello detached and unpinned

   .. code-block:: console

      target# shirudo bpm uninstall hello
      upatch unload: --no-precheck, pre-flight state check skipped
      upatch unload: signed loader accepted, keyring 272801410, 165 instructions
      upatch unload: hello carries the directive's payload
      upatch unload: hello measured, register f4f9b2f7cb9b442d78acc3b0527ad79a4cf9dd1eae1eaedffce9263c53571c05
      upatch unload: hello detached and unpinned

   The target runs the unload directives that shipped in the package and
   removes the package. ``shirudo bpm list`` no longer lists it.

   .. guide-check: match ^\s+none$

   .. code-block:: console

      target# shirudo bpm list
      Installed packages:
        none

2. Stop the registry on the host:

   .. guide-check: remove

   .. code-block:: console

      operator$ docker rm -f shirudo-registry

Next steps
----------

- :doc:`/reference/formats/beefile` describes every key of a ``Beefile``.
- :doc:`/upatches/publish/publishing` publishes to a registry and to the signed
  upatch tree.
- :doc:`/operate/run/deliver-packages` registers repositories in the signed
  config and lets the timers keep targets up to date.
- :doc:`/reference/cli/bpm` describes every ``shirudo bpm`` command.
