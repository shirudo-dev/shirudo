..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: shirudo contributors

Work from a checkout
====================

This page takes you from a clone of the repository to the operator
binary, the operator-only helper and the static target binary, shows
where the parts of the tree live and how to run the checks CI runs
before you send a change. :doc:`/contribute/testing/testing` covers the tests
and the test VM.

Before you begin
----------------

- A Linux host on x86-64, arm64 or riscv64. The test VM runs on x86-64
  and arm64 hosts only.
- A C compiler, GNU make, ``pkg-config``, ``python3`` and a current
  ``clang`` and ``llvm`` with the BPF target. CI installs clang 20 on
  its Ubuntu runners because clang 18 lacks the BPF address-space casts
  that arena upatches need.
- The development files that :src:`Makefile.config` probes for with
  ``pkg-config``:

  .. list-table::
     :header-rows: 1
     :widths: 40 60

     * - Module
       - Debian or Ubuntu package
     * - ``libcrypto >= 3.5``, ``libssl >= 3.5``
       - ``libssl-dev`` from OpenSSL 3.5 or newer
     * - ``tss2-esys >= 4.0``, ``tss2-tctildr``
       - ``libtss2-dev``
     * - ``libelf``
       - ``libelf-dev``
     * - ``zlib``
       - ``zlib1g-dev``
     * - ``libcurl >= 7.75``
       - ``libcurl4-openssl-dev``
     * - ``luajit``
       - ``libluajit-5.1-dev``

- The ``openssl`` command from OpenSSL 3.5 or newer. The build probe
  runs ``openssl list -public-key-algorithms`` and refuses a version
  without ML-DSA.
- The BTF of a kernel that has the signed-loader ABI, see
  :ref:`dev-vmlinux`.

The probe stops with ``shirudo: missing prerequisite:`` and an install
hint for each module it cannot find. It writes what it found to
``config.mk``, which ``make distclean`` removes.

Install OpenSSL 3.5
-------------------

The build probe's hint names Ubuntu 26.04 and Fedora 43 as the first
releases that ship OpenSSL 3.5. Ubuntu 24.04 ships 3.0. On an older
distribution, build OpenSSL into a prefix of its own the way
:src:`.github/scripts/vm-toolchain.sh` does for CI:

1. Download and unpack the release:

   .. code-block:: console

      $ curl -fsSLO https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz
      $ tar -xf openssl-3.5.9.tar.gz && cd openssl-3.5.9

   Compare the archive with the SHA-256 that ``vm-toolchain.sh`` pins
   before you build it.

2. Configure and install it under ``<prefix>``, a directory of your
   choice:

   .. code-block:: console

      $ ./Configure --prefix=<prefix> --openssldir=/etc/ssl --libdir=lib no-docs no-tests
      $ make -j"$(nproc)" && make install_sw

3. Put it first for every shell you build or test in:

   .. code-block:: console

      $ export PATH=<prefix>/bin:$PATH
      $ export PKG_CONFIG_PATH=<prefix>/lib/pkgconfig
      $ export LD_LIBRARY_PATH=<prefix>/lib

4. Verify that the command knows ML-DSA:

   .. code-block:: console

      $ openssl list -public-key-algorithms | grep -i ml-dsa

``sudo`` drops ``LD_LIBRARY_PATH`` and replaces ``PATH``. When you run
a make target as root, pass both on, as :src:`.github/scripts/tests.sh`
does:

.. code-block:: console

   $ sudo -E env PATH="$PATH" LD_LIBRARY_PATH="$LD_LIBRARY_PATH" make tests

.. _dev-vmlinux:

Select the kernel BTF
---------------------

The BPF objects that shirudo embeds compile against
``vendor/linux/vmlinux.h``. ``shirudo build`` run in the checkout root
uses the same header unless ``--vmlinux`` names another. The build
generates that header from BTF with :src:`tools/gen-vmlinux-h` and never
commits it. The embedded
admission program reads the signature verdict the kernel records in
``prog->aux->sig``, so the header must come from a kernel with the
signed-loader ABI. A header generated from the BTF of a kernel without
that ABI fails the BPF build.

The build takes the first of these sources:

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Source
     - When
   * - ``BPF_VMLINUX_H=<path>``
     - Copies a prepared ``vmlinux.h``.
   * - ``BPF_VMLINUX_BTF=<path>``
     - Generates the header from a BTF file or an ELF file with a
       ``.BTF`` section.
   * - ``artifacts/bpf-next-kernel-debs/vmlinux.btf``
     - The BTF of the test kernel, when ``make -C testing kernel`` has
       built it.
   * - ``/sys/kernel/btf/vmlinux``
     - The running kernel.

``vendor/linux/.vmlinux-btf-source`` records the source used. When you
select another one, the next build regenerates the header.

1. Build the test kernel, which also writes its BTF.
   :doc:`/contribute/testing/testing` describes the kernel build:

   .. code-block:: console

      $ make -C testing kernel

2. Or name the BTF of the kernel you build for:

   .. code-block:: console

      $ make BPF_VMLINUX_BTF=<path-to-btf>

3. Verify which source the header came from:

   .. code-block:: console

      $ cat vendor/linux/.vmlinux-btf-source

Build the operator binary
-------------------------

1. Build ``shirudo`` in the checkout root:

   .. code-block:: console

      $ make

2. Verify the build:

   .. code-block:: console

      $ ./shirudo version

The build compiles the vendored libbpf, generates ``vmlinux.h``,
compiles the userspace objects and the BPF objects under :src:`bpf/`,
embeds the BPF objects into ``util/loader.o`` and links. These make
variables change it:

.. list-table::
   :header-rows: 1
   :widths: 32 68

   * - Variable
     - Effect
   * - ``V=1``
     - Prints the full command lines.
   * - ``WERROR=0``
     - Lets a compiler newer than the tree finish the build. A warning
       fails every build by default, the BPF objects and the vendored
       libbpf included. Fix the warning instead of keeping this set.
   * - ``SHIRUDO_DEBUG=0``
     - Leaves out ``-g``.
   * - ``SANITIZE=address,undefined``
     - Instruments the host binaries and the test helpers with ASan and
       UBSan. See :doc:`/contribute/testing/testing`.

Build the shirudo-build helper
------------------------------

The core binary never compiles or signs. ``shirudo build``, ``shirudo
image build``, ``shirudo image verify``, ``shirudo keys vouch`` and the
operator ``bpm`` subcommands (``build``, ``push``, ``tree append`` and
``config update``) execute the separate ``shirudo-build`` helper, which
is the only binary that links the signer.

1. Build the helper:

   .. code-block:: console

      $ make shirudo-build

2. Point the core binary at it:

   .. code-block:: console

      $ export SHIRUDO_BUILD=$PWD/tools/shirudo-build/shirudo-build
      $ export PATH=$PWD:$PATH

3. Verify that the operator subcommands resolve. ``shirudo bpm --help``
   lists ``build`` and ``push`` only when the helper resolves:

   .. code-block:: console

      $ shirudo bpm --help

The core binary takes the helper from ``SHIRUDO_BUILD``, then from
``$(libexecdir)/shirudo/shirudo-build``, the path compiled in, then
from ``PATH``. Set ``SHIRUDO_BUILD`` rather than relying on ``PATH``:
an operator package installed on the same host provides the compiled-in
path, which takes precedence over ``PATH``.

``bpm build`` compiles with the package directory as its working
directory. To build a package with a checkout's ``vmlinux.h`` and BPF
headers, give the package directory ``vendor`` and ``bpf`` symbolic
links to the checkout's, as ``t7005`` and :src:`testing/end2end/host.sh`
do.

Build the target binary
-----------------------

The target binary is a fully static PIE. It links static archives of
OpenSSL, libcurl and tpm2-tss that ``make target-deps`` builds from
source, and the distribution's static ``libelf``, ``zlib``, ``zstd``
and LuaJIT archives.

1. Install the static archives and the tools the tpm2-tss build needs.
   CI installs ``autoconf``, ``autoconf-archive``, ``automake``,
   ``libtool``, ``libltdl-dev`` and ``libzstd-dev`` for this on Ubuntu.

2. Build the dependencies and the binary:

   .. code-block:: console

      $ make target

   ``make target`` runs ``make target-deps`` first. It builds OpenSSL
   3.5.9, libcurl 8.18.0 and tpm2-tss 4.2.0 under ``build/target-deps``
   and stages every archive in ``build/target-deps/lib``.

3. Verify that the result is a static PIE without an interpreter,
   shared dependencies or library search paths:

   .. code-block:: console

      $ sh .github/scripts/check-static-target.sh shirudo-target

To use dependencies built elsewhere, set ``TARGET_DEPS_PREBUILT=1`` and
point ``SHIRUDO_TARGET_PKG_CONFIG_PATH`` and
``SHIRUDO_TARGET_STATIC_LIBDIR`` at them. ``make target-deps-clean``
removes ``build/target-deps``.

Refresh the vendored libbpf
---------------------------

:src:`vendor/libbpf` holds libbpf, its BPF-side headers and the BPF UAPI
headers. No kernel tree is needed to build. Refresh the copy only when
a change needs a newer libbpf or UAPI:

.. code-block:: console

   $ make bpf-deps KERNEL_SRC=<kernel-tree>

``<kernel-tree>`` is a kernel checkout. Without ``KERNEL_SRC``,
:src:`tools/bpf-deps/bpf-deps.sh` makes a shallow clone of bpf-next.

The source revision is recorded in ``vendor/libbpf/COMMIT``. After
refreshing, reapply the loader-attachment support and the 64-program
limit described in :src:`vendor/libbpf/README.md`.

Other make targets
------------------

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Command
     - Result
   * - ``make install``
     - Installs the operator binary and the bash completion under
       ``prefix``, ``/usr/local`` by default.
   * - ``make install-target``
     - Installs the static target binary as ``shirudo``, the units and
       timers, the dracut module and ``shirudo-gen-initrd``.
   * - ``make install-operator``
     - Installs the operator binary, the helper under
       ``$(libexecdir)/shirudo``, the image scripts, ``vmlinux.h`` and
       the BPF headers.
   * - ``DESTDIR=<dir>``, ``prefix=<dir>``, ``bindir=<dir>``,
       ``libexecdir=<dir>``, ``systemdunitdir=<dir>``
     - Override the install paths. The unit and dracut directories are
       absolute by default and do not follow ``prefix``.
   * - ``make -C packaging bindeb-pkg``, ``binrpm-pkg``, ``bintar-pkg``
     - Build the distribution packages from ``make clean``.
       ``PKG_ROLES=operator`` builds the operator package alone. See
       :doc:`/start/install`.
   * - ``make docs``
     - Renders the documentation and serves it on
       ``http://127.0.0.1:8000``. See
       :doc:`/contribute/documentation/writing-docs`.
   * - ``make clean``, ``make distclean``
     - Remove the build products, and with ``distclean`` also
       ``config.mk``, the target dependencies and the vendored libbpf
       build.
   * - ``make help``, ``make -C testing help``
     - List the targets.

Project layout
--------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Path
     - Contents
   * - :src:`shirudo.c`
     - The command dispatch table.
   * - ``builtin-*.c``, :src:`builtin.h`
     - One file per top-level command: ``attest``, ``bpm``, ``build``,
       ``config``, ``genkey``, ``image``, ``init``, ``keys``,
       ``status``, ``upatch`` and ``version``.
   * - :src:`util/`
     - The userspace library both binaries link. :src:`util/sign.c` is
       linked into ``shirudo-build`` only.
   * - :src:`bpf/`
     - The embedded BPF programs: ``bpf2.c`` (admission, mount, image
       and device guards), ``seal.c`` (the seal) and ``unload.c`` (the
       signed unload directive).
   * - :src:`bpf/lib/`
     - The headers more than one BPF program includes: the LSM helpers
       and verity device records of ``bpf2.c`` and ``seal.c``, and,
       shared with upatches and userspace, decoders, identity,
       serializers, tamper counters and common helpers.
   * - :src:`include/shirudo/`
     - Integer types, string and number helpers, the ``.upatch``
       container layout, TPM types and the enforcement definitions
       shared between userspace and BPF.
   * - :src:`tools/shirudo-build/`
     - The operator-only helper: compile, sign, unload directives,
       image signing, ``keys vouch``, ``bpm build``, ``push``,
       ``tree append`` and ``config update``.
   * - :src:`tools/gen-image/`
     - ``shirudo-gen-image``, ``shirudo-gen-runtime`` and
       ``shirudo-gen-verity``, which make the runtime and config images,
       their shared ``common.sh`` and the runtime unit templates.
   * - :src:`tools/gen-initrd/`
     - The dracut module, the initrd generator and the installer.
   * - :src:`tools/gen-vmlinux-h/`
     - The ``vmlinux.h`` generator.
   * - :src:`tools/bpf-deps/`
     - The script that refreshes :src:`vendor/libbpf`.
   * - :src:`vendor/libbpf/`
     - Vendored libbpf and BPF UAPI headers.
   * - ``vendor/linux/``
     - The generated ``vmlinux.h``. Not tracked.
   * - :src:`kernel/`
     - Kernel patches the test kernel build applies. See
       :doc:`/internals/kernel-patches`.
   * - :src:`upatches/`
     - The shipped packages, ``kernel-obs`` and ``kernel-cve``, each
       with its Beefile.
   * - :src:`systemd/`
     - Unit and timer templates for the target.
   * - :src:`completion/`
     - The bash completion. Command names come from
       ``shirudo --list-cmds``. Option lists are maintained by hand.
   * - :src:`packaging/`
     - The tar, deb and rpm packaging.
   * - :src:`testing/`
     - Unit, functional, end-to-end and fuzz tests, the test VM and
       their helpers. See :doc:`/contribute/testing/testing`.
   * - ``Documentation/``
     - This documentation.
   * - :src:`.github/`
     - The CI workflows and the scripts they run.
   * - ``Makefile``, :src:`Makefile.shirudo`, :src:`Makefile.config`,
       :src:`Makefile.target-deps`, :src:`Makefile.version`
     - The entry points, the build graph, the prerequisite probes, the
       target dependency build and version discovery.
   * - ``build/``, ``artifacts/``
     - Generated: build products, the test VM state and the test
       kernels. Not tracked.

``shirudo --list-cmds`` prints the top-level commands.

Run the CI checks locally
-------------------------

CI runs these scripts from :src:`.github/scripts/`. Each takes the
arguments of ``git rev-list``, such as ``origin/main..HEAD``, and checks
the commit at ``HEAD`` alone without them.

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Script
     - Checks
   * - ``check-dco.sh <range>``
     - A one-line subject, a body beyond the tags and the author's
       ``Signed-off-by:``. See :doc:`/contribute/code/contributing`.
   * - ``check-style.sh <range>``
     - The kernel's ``checkpatch.pl`` in strict mode over the C each
       commit touches and over its message, plus the project rules.
       ``--diff`` checks uncommitted changes and ``--files`` whole
       files.
   * - ``check-spdx.sh``
     - The SPDX tag of every tracked source. Takes no range.
   * - ``check-sparse.sh``
     - ``make sparse``: sparse over the userspace sources the binaries
       are built from, failing on any warning. It finds a value moved
       between host order and ``__le32`` or ``__be32`` without
       ``cpu_to_le32()``, ``le32_to_cpu()`` or their kin from
       ``<shirudo/byteorder.h>``. Takes no range.
   * - ``check-coccinelle.sh [<rule>...]``
     - Every semantic patch in :src:`testing/coccinelle/`, or the rules
       named, over the C the project writes, failing on any match with
       its file, line, rule and message. Takes no range; see
       `Coccinelle rules`_.
   * - ``build-commits.sh <range>``
     - Builds every commit on its own: ``make``, ``make
       shirudo-build`` and ``make -C testing test-helpers``. It
       refuses to start with uncommitted changes and checks out each
       commit in the working tree.
   * - ``check-static-target.sh <binary>``
     - That a target binary is a static PIE.
   * - ``check-runtime-image.sh <binary>``
     - That a runtime image of the default size of
       ``shirudo-gen-runtime`` holds the target binary, and how much
       space it leaves. When it fails, raise ``size=`` in
       :src:`tools/gen-image/shirudo-gen-runtime`.
   * - ``tests.sh setup|run [unit|functional|end2end]``
     - Prepares a CI runner as the VM host and runs ``make tests``, or
       one part of it: ``unit`` runs the unit and ``ci-checks`` tests,
       ``functional`` and ``end2end`` the tier of that name. The ``CI
       suite`` workflow runs the three parts as checks of their own.
       Meant for CI runners, which are discarded afterwards.

``check-style.sh`` fetches the kernel's ``checkpatch.pl`` at a pinned
tag into ``build/checkpatch/`` and verifies its SHA-256. Set
``CHECKPATCH=<path>`` to use a kernel tree's
``scripts/checkpatch.pl`` instead, for example without network access.

Before you send a change:

1. Run the checks over your commits:

   .. code-block:: console

      $ .github/scripts/check-dco.sh origin/main..HEAD
      $ .github/scripts/check-style.sh origin/main..HEAD
      $ .github/scripts/check-spdx.sh
      $ .github/scripts/check-sparse.sh
      $ .github/scripts/check-coccinelle.sh
      $ .github/scripts/build-commits.sh origin/main..HEAD

2. Run the tests the change touches, and ``make tests`` before you
   send. See :doc:`/contribute/testing/testing`.

3. Render the documentation if you changed it:

   .. code-block:: console

      $ make -C Documentation html

4. Verify that every script printed its summary line and exited 0, for
   example ``DCO: 3 commits checked`` and ``style: 3 commits checked``.

Coccinelle rules
----------------

Each semantic patch in :src:`testing/coccinelle/` describes a pattern
the tree is kept free of, and ``check-coccinelle.sh`` fails on any
match, in the ``Coccinelle`` job of the ``Lint`` workflow. The rules
cover the C the project writes, as ``check-style.sh`` takes it: not the
vendored libbpf, the BTF dumps or the generated headers. A rule that
can rewrite what it finds does so with ``-D patch``:

.. code-block:: console

   $ spatch -D patch --sp-file testing/coccinelle/zero_init.cocci \
         --in-place --include-headers util/json.c

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Rule
     - Refuses
   * - ``array_size``
     - An element count divided out by hand rather than
       ``ARRAY_SIZE()``. Rewrites.
   * - ``zero_init``
     - ``= {0}`` rather than ``= {}``. Rewrites.
   * - ``minmax``
     - A ternary that picks the smaller or larger of two values rather
       than ``min()`` or ``max()``. Rewrites.
   * - ``minmax_t``, ``minmax_cast``
     - ``min_t()`` or ``max_t()`` where ``min()`` or ``max()`` takes
       the values as they are, and a cast inside ``min()`` or
       ``max()``.
   * - ``ifnullfree``
     - A NULL test before a free function that takes NULL. Rewrites.
   * - ``void_cast``
     - A ``(void)`` cast, of a result or a variable. Rewrites.
   * - ``scrub``
     - A ``memset()`` of a local that nothing reads afterwards, which
       the compiler may drop, rather than ``memzero_explicit()``.
       Rewrites.
   * - ``secret_cmp``
     - ``memcmp()`` of a secret or what derives from one rather than
       ``memneq_explicit()``.
   * - ``openssl_ret``
     - A test of the truth of an OpenSSL function that returns 0 or a
       negative value on failure.
   * - ``overflow``
     - A sum or product tested for overflow by hand rather than with
       the helpers of ``<shirudo/overflow.h>``.
   * - ``ctype``
     - A ``char`` passed to a ``<ctype.h>`` function without a cast to
       ``__u8``. Rewrites.
   * - ``memnull``
     - A NULL passed to a memory or string function, and a
       ``memcpy()`` of overlapping buffers.
   * - ``sizeof_ptr``
     - The size of a pointer where the object it points to is meant,
       wherever it is taken, unless the pointer's own address goes to
       the same call.
   * - ``literal_len``
     - A length that does not match the string literal it compares or
       copies.
   * - ``test_after_use``
     - A pointer tested for NULL after its use.
   * - ``null_deref``
     - A pointer dereferenced in the branch of the test that found it
       NULL.
   * - ``alloc_unchecked``
     - An allocation used before it is checked.
   * - ``use_after_free``
     - Memory used or freed again after it was freed.
   * - ``uninit``
     - A local read after a ``goto`` jumped over its assignment.
   * - ``alloc_size``
     - An allocation sized for another type than its pointer, and a
       free of memory no allocator returned.
   * - ``double_test``, ``double_init``
     - A term tested twice, an ``if`` whose branches are alike, and a
       member initialized twice.
   * - ``va_end``
     - A ``va_start()`` or ``va_copy()`` without a ``va_end()`` on a
       path out.
   * - ``fd_leak``
     - A descriptor left open on a path out once its open succeeded,
       where it is not returned, stored or handed to what closes it.
   * - ``cloexec``
     - A descriptor or stream opened without close-on-exec.
   * - ``banned``
     - ``rand()``, ``strtok()``, ``usleep()``, ``signal()``,
       ``alloca()``, ``setjmp()``, the time and user database functions
       without ``_r`` and their kin, and ``abort()`` and ``assert()``
       outside :src:`testing/`.
   * - ``no_exec``
     - A function that runs a program, outside the operator helper, the
       command that hands work to it and the tests.
   * - ``anssi_misc``
     - A bitwise operator on a ``bool``, a comma that sequences
       statements, a backward ``goto``, a floating-point loop counter
       and a bare ``NULL`` passed to a variadic function, after the
       ANSSI rules for secure C.
   * - ``cert_misc``
     - A ``char`` array too short for the NUL of the literal it holds, a
       ``char`` that keeps what ``getc()`` returns, and ``getenv()``
       passed on unchecked, after the CERT C rules.

A new pattern worth refusing gets a rule: write it from scratch under
the BSD-2-Clause, with a header that says why the pattern is refused,
fix the tree in the commits before it, and add it to the table.
``check-coccinelle.sh`` runs a rule without the headers a file
includes, which keeps it fast but leaves the types they declare
unknown. A rule that needs them, as ``sizeof_ptr`` needs the type of a
struct member, names its include options on a ``#spatch`` line.

Next steps
----------

- :doc:`/contribute/code/develop-locally` to run both roles on one machine and
  change shirudo end to end
- :doc:`/contribute/testing/testing` to run and write tests
- :doc:`/contribute/code/contributing` for the commit message and the sign-off
- :doc:`/contribute/code/coding-style` for the C code
- :doc:`/reference/cli/index` for the commands
