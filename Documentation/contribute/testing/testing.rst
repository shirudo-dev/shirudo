..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: shirudo contributors

Run and write tests
===================

This page shows how to run shirudo's tests, from one unit suite to the
full run CI makes, how to use the test VM that plays the target, and
where a test you add goes. :doc:`/contribute/testing/test-coverage` lists what
the tests cover.

Before you begin
----------------

- A tree that builds, see :doc:`/contribute/code/developer-guide`. ``make -C
  testing`` builds the binaries, the helper and the test helpers it needs
  itself.
- For the unit and operator tests: ``python3``, ``clang``, OpenSSL 3.5
  or newer and the ``openssl`` command. ``veritysetup`` from
  ``cryptsetup-bin`` and ``mkfs.ext4`` from ``e2fsprogs`` for the image
  tests, ``libtpms-dev`` for the TPM simulator helper and ``rpmbuild``
  for the rpm packaging test.
- For the ``ci-checks`` tests: ``git``, ``jq``, ``pkg-config``,
  ``readelf`` and ``spatch`` from Coccinelle. A test whose tool is
  missing skips. The runner of the ``CI suite`` workflow has them all.
- For the tests that boot a VM: root, a readable and writable
  ``/dev/kvm``, an x86-64 or arm64 host and what ``make target`` needs,
  since the bundle a VM boots holds the static target binary. On Ubuntu,
  ``.github/scripts/tests.sh setup`` installs ``cloud-image-utils``,
  ``dracut-core``, ``file``, ``isc-dhcp-client``, ``libguestfs-tools``,
  ``qemu-system-x86``, ``qemu-utils``, ``swtpm``, ``swtpm-tools`` and
  ``tpm2-tools`` among others. :src:`testing/vm/run.sh` names the packages
  it misses with an install command for ``apt-get`` or ``dnf``.
- For the end-to-end tests: Docker on the host.

Test tiers
----------

.. list-table::
   :header-rows: 1
   :widths: 14 26 30 30

   * - Tier
     - Directory
     - Runs
     - Command
   * - Unit
     - :src:`testing/unit/`
     - On the build host
     - ``make -C testing unit``
   * - CI checks
     - :src:`testing/ci-checks/`
     - On the build host
     - ``make -C testing ci-checks``
   * - Functional
     - ``testing/functional/<family>/``
     - Operator tests on the build host, target tests in a VM per
       family
     - ``make -C testing functional``
   * - End-to-end
     - :src:`testing/end2end/`
     - Around one VM, with a registry and a collector in containers on
       the host
     - ``make -C testing end2end``
   * - Fuzz
     - :src:`testing/fuzz/`
     - On the build host, under libFuzzer, ASan and UBSan
     - ``make -C testing fuzz``

``make tests`` in the checkout root, or ``make -C testing``, runs the
unit, CI check, functional and end-to-end tiers in that order. The fuzz
targets run on their own.

Test numbers and families
-------------------------

A shell test is named ``t<F><K><NN>-<what>.sh``:

- ``F`` is the numbered family. A family may have multiple named
  directories when tests need separate VM suites.
- ``K`` is ``0`` for an operator test, which runs on the build host
  without root, a kernel or a TPM of its own, and ``1`` for a target
  test, which runs as root in the family's VM against an initialized
  target.
- ``NN`` orders the tests of a family and kind, and is the order they
  run in.

.. list-table::
   :header-rows: 1
   :widths: 6 30 64

   * - F
     - Directory
     - Covers
   * - 0
     - ``ci-checks/``
     - The DCO, SPDX and style checkers, the CI commit range and the
       SBOM generator
   * - 1
     - ``functional/build/``
     - Helper dispatch, the command surface, the static target, rpm
       packaging, the initrd generator and installer, the test VM
       scripts and the slim kernel configuration
   * - 2
     - ``functional/signing/``
     - Keys, signatures, vouching, revocation and the trusted set
   * - 3
     - ``functional/upatch/``
     - The ``.upatch`` container, attach metadata, decoders,
       serializers, signed policy labels, load, unload and ``upatch get``
   * - 4
     - ``functional/tpm/``
     - TPM structures, the measurement register, the eventlog,
       attestation, the initrd binding and the register guard
   * - 5
     - ``functional/image/``
     - Runtime and config images, settings, keys, activation,
       revocation and interruption
   * - 6
     - ``functional/tamperproof/``, ``functional/labels/``
     - Attacks on the admission and BPF command policy, bpffs, the
       seal, task authority, task and socket policy inheritance, the
       keyrings and the TPM path
   * - 7
     - ``functional/bpm/``
     - Package commands, Beefile policy labels, publishing and the
       upatch tree
   * - 8
     - ``functional/otel/``
     - Map export, the status keepalive, OTLP transport and TLS policy
   * - 9
     - ``end2end/``
     - The ``kernel-obs`` package against real kernel activity and the
       whole delivery path, plus ksock UDP delivery to the VM host

A test you add takes the next free number of its family and kind. A
number is never reused for another test. A file under :src:`testing/` that
is not a test does not take a name of this form. A target test can have
a Python companion with the same stem, such as
``t5101-verity-boot-signers.py``, which only its shell test runs.

``t4003`` and ``t4004`` carry operator numbers but test the register
before ``init``. They skip on the build host and run in a separate VM
that the ``tpm`` family boots without the production initrd.

Run the tests
-------------

Run everything, as CI does:

.. code-block:: console

   # make tests

``make -C testing help`` lists the unit suites and the families. Run
one tier, one unit suite or one family:

.. code-block:: console

   $ make -C testing unit
   $ make -C testing unit/<suite>
   # make -C testing functional/<family>

``<suite>`` is a file name under :src:`testing/unit/` without ``.c``, such
as ``json``. ``<family>`` is a directory under :src:`testing/functional/`,
such as ``upatch``. A family runs its operator tests in number order,
then boots its VM and runs its target tests there. ``make -j`` boots the
VMs of several families side by side.

Leave out every test that boots a VM, for a host without KVM or root:

.. code-block:: console

   $ make tests VM=0
   $ make -C testing functional/<family> VM=0

Run the cases of a unit suite whose names contain ``<substring>``:

.. code-block:: console

   $ build/unit/<suite> <substring>

Run one operator test directly. It changes to :src:`testing/` itself and
uses the binaries in the checkout root, so build them first:

.. code-block:: console

   $ make && make shirudo-build && make -C testing test-helpers
   $ sh testing/functional/<family>/<test>.sh

A target test runs only in a VM, with its family or by hand in an
interactive VM, see :ref:`testing-by-hand`.

Read the results
~~~~~~~~~~~~~~~~

Every test prints TAP: ``ok <n> - <title>``, ``not ok <n> - <title>``
and a closing ``1..<n>``. A failing case's standard error follows as
lines that start with ``#``. :src:`testing/run-tests.sh` exits with the
number of test scripts that failed.

A test that cannot run prints ``1..0 # SKIP <reason>``. On the build
host a skip counts as a pass, so look for ``# SKIP`` when an operator
test seems to pass too quickly. A target test that skips as a whole
fails its family with ``required target test was skipped``, since every
target test is required.

Run under the sanitizers
------------------------

1. Remove the objects of an earlier build. The build does not track
   compiler flags, so it would keep objects built without the
   sanitizers:

   .. code-block:: console

      $ make clean

2. Build and run every test that needs no VM under ASan and UBSan:

   .. code-block:: console

      $ make tests VM=0 SANITIZE=address,undefined

``SANITIZE`` instruments the host binaries and the test helpers. The BPF
objects are unaffected. Recovery is off, so every report fails the run.
CI runs the same with gcc and with clang.

Run the fuzz targets
--------------------

The fuzz targets cover the parsers of input from outside the host. They
need clang with its libFuzzer runtime, ``libclang-rt-23-dev`` on the CI
runner.

1. Build and run every target on its seed corpus for 60 seconds each:

   .. code-block:: console

      $ make -C testing fuzz FUZZ_SECONDS=60

2. Run one target again, for example after a fix:

   .. code-block:: console

      $ sh testing/fuzz/run.sh 60 <target>

   ``<target>`` is the name of ``testing/fuzz/fuzz-<target>.c``, such as
   ``json``.

``FUZZ_JOBS`` sets how many targets run at a time, one per CPU by
default. A crash fails the run and leaves its input in
``testing/fuzz/crash-<target>-*``.

What a target finds is discarded after the run unless
``FUZZ_CORPUS=<dir>`` names a directory to keep it in. Each target then
starts from ``<dir>/<target>`` as well as its seed corpus and adds what
it finds there, and after a run without a crash the directory is merged
down to the inputs that add coverage, so that it does not grow with
every run. A relative ``<dir>`` is taken from the directory the command
runs in, which ``make -C testing`` changes to ``testing/``:

.. code-block:: console

   $ make -C testing fuzz FUZZ_SECONDS=600 FUZZ_CORPUS=$PWD/build/fuzz-corpus

An input in the kept corpus that crashes a later build fails that run
like any new crash.

The ``libFuzzer`` job of the ``Sanitizers`` workflow runs every target
for 60 seconds on each push and pull request, and for ten minutes in a
nightly run, which also starts by hand from the Actions page. Every run
starts from the corpus the last nightly or manual run kept in the
Actions cache, and only those runs save it. When a run fails, the
inputs that crashed are in its ``fuzz-crashes`` artifact; copy one into
``testing/fuzz/`` and run its target on it to reproduce the crash:

.. code-block:: console

   $ testing/fuzz/fuzz-<target> testing/fuzz/crash-<target>-<hash>

Use the test VM
---------------

The test VM plays a production target. It boots a test kernel, an
Ubuntu cloud image and a software TPM, and runs ``init`` from a dracut
initrd with the dm-verity runtime image and a signed config image. The
family runs, the end-to-end run and the interactive VM all boot it.

Build the test kernel
~~~~~~~~~~~~~~~~~~~~~

``make -C testing kernel`` builds bpf-next with the slim configuration
in :src:`testing/vm/build-kernel.sh` and the patches under :src:`kernel/`. It
writes the kernel image, ``vmlinux.btf``, ``kernel.config``, packages
and a record of the commit it built to
``artifacts/bpf-next-kernel-debs/``. Every target that boots a VM
builds the kernel first when it is missing.

1. Build the kernel:

   .. code-block:: console

      $ make -C testing kernel

2. Verify the commit it built:

   .. code-block:: console

      $ grep '^commit=' artifacts/bpf-next-kernel-debs/bpf-next-kernel-build

The stamp is ``artifacts/bpf-next-kernel-debs/bzImage.sha256sum``
(``Image.sha256sum`` on arm64). Make rebuilds the kernel when
:src:`testing/vm/build-kernel.sh` or a patch under :src:`kernel/` is newer
than the stamp, so a checkout or rebase that touches either rebuilds
it on the next VM run. When you know the kernel is current, touch the
stamp, as :src:`.github/scripts/tests.sh` does. The build removes the
artifact directory first, so do not run it while a VM run or a build
reads ``vmlinux.btf``.

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Variable
     - Effect
   * - ``KERNEL_TAG=v<version>``
     - Builds a release instead of bpf-next, v7.4 or newer, into
       ``artifacts/linux-v<version>-kernel-debs/``.
   * - ``KERNEL_COMMIT=<sha>``
     - Builds an exact commit of a release tag. Not for bpf-next.
   * - ``KERNEL_SOURCE_DIR=<dir>``
     - Builds from a clean git checkout instead of a fresh clone.
   * - ``KERNEL_CONFIG=<file>``
     - Starts from a full configuration instead of the slim fragment.
   * - ``KERNEL_PATCHES=<dir>``
     - Applies these patches instead of :src:`kernel/`.
   * - ``KERNEL_BUILD_JOBS=<n>``
     - Parallel jobs, ``nproc`` by default.
   * - ``WORK_DIR=<dir>``
     - The build directory, read from the environment.
       ``/tmp/<name>-kernel-build`` by default.

``make -C testing bpf-next`` rebuilds bpf-next without looking at the
stamp. The kernel build installs missing build dependencies with
``apt-get`` or ``dnf``, through ``sudo`` when it does not run as root.

Build the bundle
~~~~~~~~~~~~~~~~

The bundle is the operator's side of a VM run: shirudo built for the
target, the test helpers, the upatch fixtures signed with keys
generated for the bundle, the dm-verity runtime image and the signed
config images. :src:`testing/vm/build-bundle.sh` builds the bpf-next
bundle into ``build/test-vm/host-bundle-bpf-next-verity/`` and keeps
the signing key outside the checkout, which every guest can read, in
``/tmp/shirudo-test-vm-private-<uid>/operator-keys/keys/``.
``TEST_VM_HOST_PRIVATE_DIR`` names another directory, which must lie
outside the repository. Every target that boots a VM rebuilds the bundle
when one of its inputs changed, or when that directory does not hold the
key the bundle's fixtures are signed with. Build it alone with:

.. code-block:: console

   $ make -C testing bundle

The bundle script runs Make builds with one job per available CPU reported
by ``nproc``. The eighty status-many fixture pairs build in parallel batches, with one
worker per available CPU reported by ``nproc``. Each worker builds a load
artifact and its matching unload artifact. The ordinary fixture builders, including
the policy and observability fixtures, and the independent unload artifacts
also build in CPU-sized batches. Payload hashes are read after their builders
finish, and the tree test registry is generated after its unload artifact.

Boot an interactive VM
~~~~~~~~~~~~~~~~~~~~~~

1. Boot a VM and leave it running:

   .. code-block:: console

      # make -C testing vm VM_NAME=<name>

   ``<name>`` names the VM state directory
   ``build/test-vm/vms/<name>/``. Without ``VM_NAME`` the script picks a
   unique name and prints it. ``KERNEL=7.4`` boots a release kernel
   instead of bpf-next and builds it if needed.

2. Open a shell on it:

   .. code-block:: console

      # make -C testing vm-ssh VM_NAME=<name>

   Without ``VM_NAME``, ``vm-ssh`` connects to the most recently created
   VM.

3. Verify that the guest is an initialized target:

   .. code-block:: console

      target# shirudo-runtime status

4. Attach to the serial console when SSH does not answer. ``Ctrl-]``
   detaches:

   .. code-block:: console

      # make -C testing vm-console VM_NAME=<name>

5. Stop the VM and keep its state, or remove its state and logs:

   .. code-block:: console

      # make -C testing vm-stop VM_NAME=<name>
      # make -C testing vm-clean VM_NAME=<name>

.. warning::

   Without ``VM_NAME``, ``vm-clean`` removes the whole
   ``build/test-vm/`` directory, the bundles and the cached runtime
   image included. Name the VM to remove only its state.

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Variable
     - Effect
   * - ``TEST_VM_CPUS``, ``TEST_VM_MEMORY``, ``TEST_VM_DISK_SIZE``
     - 4 CPUs, ``4G`` and ``30G`` by default.
   * - ``TEST_VM_SSH_PORT=<port>``
     - The host port for SSH. A free port from 22000 to 22999 by
       default.
   * - ``TEST_VM_QEMU=<path>``
     - Another emulator, such as RHEL's ``/usr/libexec/qemu-kvm``.
   * - ``TEST_VM_TIMEOUT=<seconds>``
     - How long a test-mode VM may run, 3600 by default. CI sets 900.
   * - ``TEST_VM_VERBOSE=1``
     - Streams the console of a test-mode VM to the terminal.

Inside the guest:

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Path
     - Contents
   * - ``/usr/local/bin/shirudo-runtime``
     - The command that runs the runtime image's binary, which holds
       task authority. ``/usr/local/bin/shirudo`` is a copy outside the
       image and has none.
   * - ``/workspace/shirudo``
     - The checkout, as an overlay over the read-only host checkout at
       ``/mnt/shirudo-src``. Writes stay in the VM.
   * - ``/mnt/shirudo-bundle``
     - The bundle: signed upatch fixtures in ``fixtures/``, image
       fixtures in ``verity/``.
   * - ``/mnt/shirudo-out``
     - The result share, ``build/test-vm/vms/<name>/result/`` on the
       host.

.. _testing-by-hand:

Run a target test by hand
~~~~~~~~~~~~~~~~~~~~~~~~~

1. On the interactive VM, change to the tests:

   .. code-block:: console

      target# cd /workspace/shirudo/testing

2. Set the environment a family run sets:

   .. code-block:: console

      target# export SHIRUDO_BIN=/usr/local/bin/shirudo-runtime
      target# export SHIRUDO_TEST_FIXTURES_DIR=/mnt/shirudo-bundle/fixtures
      target# export SHIRUDO_TEST_KEY_FIXTURES=/mnt/shirudo-bundle/verity

3. Run one test, or all target tests of a family. The ``image`` tests
   need the result directories that ``run-target-tests.sh`` sets, so
   run that family through the script:

   .. code-block:: console

      target# sh functional/<family>/<test>.sh
      target# ./run-target-tests.sh <family>

The interactive VM differs from a family's VM. It starts the
map-export, keepalive and package timers, and it keeps whatever the
tests you ran in it before loaded or left in sealed state. Run the
family with ``make -C testing functional/<family>`` for the verdict CI
gives.

Read the VM logs
~~~~~~~~~~~~~~~~

Each VM keeps its state under ``build/test-vm/vms/<name>/``. A family
VM is named ``test-<family>-<suffix>``, or ``<name>-<family>`` when you
set ``VM_NAME``.

.. list-table::
   :header-rows: 1
   :widths: 36 64

   * - File
     - Contents
   * - ``console.log``
     - The guest's serial console.
   * - ``qemu.log``
     - QEMU's own output.
   * - ``result/guest.log``
     - What the guest preparation and the tests printed.
   * - ``result/failed-tests``, ``result/failed-suites``
     - The test cases and scripts that failed.

A run that passed keeps its logs and drops its disk images. A run that
failed keeps its disks too, copies its logs to
``build/test-vm/logs/<name>/`` and prints where they are. Its guest
overlay holds an ephemeral signing key, so do not share the state
directory.

Run the end-to-end tests
------------------------

``make -C testing end2end`` runs ``t9001`` on the host, then
:src:`testing/end2end/host.sh` plays the operator around one VM. It starts
an OCI registry, an OpenTelemetry Collector and ClickHouse in Docker
containers pinned by digest. The registry and collector use a throwaway
CA. It builds ``kernel-obs`` into a package with ``bpm build``, pushes
it with ``bpm push`` and appends it to a signed upatch tree with
``bpm tree append``. The target
activates a signed config that points at the tree and the collector,
and its units pull, verify, load and export. The host then verifies the
target's TPM evidence with ``attest verify`` and checks that the
collector holds the package's records. The earlier ``kernel-obs`` tests
export each map snapshot as local JSON and OTLP from one read; the host
compares the snapshots with the collector's JSON output and queries the
ClickHouse log and sum metric tables to check that both collector exports
hold the same data. The comparison uses event times relative to each
map's interval start and ignores the metric export time, which the two
decoder calls sample independently.

``t9107`` loads and unloads the signed ksock fixture. A host receiver on
``127.0.0.1:19090`` checks the exact datagram independently of load success.
The target kernel must provide the ksock kfuncs.

.. code-block:: console

   # make -C testing end2end

The host side writes to ``build/test-vm/end2end/``. The guest reaches
the registry and collector through QEMU's address for the host. ClickHouse
is available to the collector on the test's Docker network.

Select test scripts
~~~~~~~~~~~~~~~~~~~

Pass ``-t <regex>`` to either runner to select test filenames with a
POSIX extended regular expression. The match includes the ``.sh`` suffix
but not the directory. All TAP cases in a selected script run.

.. code-block:: console

   $ testing/run-tests.sh -t '^t100[67]-' functional/build
   target# testing/run-target-tests.sh -t '^t310[12]-' upatch

With make, set ``TEST_FILTER``; it is passed into test VMs as well:

.. code-block:: console

   $ make -C testing functional/build VM=0 TEST_FILTER='^t100[67]-'

An empty filter selects everything; invalid expressions fail with status
2. ``-t`` overrides ``TEST_FILTER``. For unit tests, the filter selects
suite executable names. Filtering preserves order and does not add
prerequisite scripts or skip the normal build and VM setup.

Write a test
------------

Put a test in the lowest tier that can show the change works:

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - The change touches
     - The test goes in
   * - A function in ``util/<m>.c``
     - ``testing/unit/<m>.c``
   * - A command, a mechanism or an attack on one
     - The family that owns it, as an operator test if it needs no root,
       kernel or TPM, otherwise as a target test
   * - A whole delivery path
     - :src:`testing/end2end/`
   * - A parser of input from outside the host
     - A fuzz target in :src:`testing/fuzz/`, besides the functional test
   * - A script in :src:`.github/scripts/`
     - :src:`testing/ci-checks/`

Write a unit test
~~~~~~~~~~~~~~~~~

``testing/unit/<m>.c`` calls the functions of ``util/<m>.c`` and checks
them with the macros of ``unit.h``: ``EXPECT_*`` records a failure and
continues, ``ASSERT_*`` ends the case. List every case in the table,
which ends with an empty entry:

.. code-block:: c

   static void decode_refuses_non_hex(void)
   {
           __u8 out[1];

           EXPECT_EQ(hex_decode("zz", out, 1), -EINVAL);
   }

   static const struct unit_case cases[] = {
           UNIT_CASE(decode_refuses_non_hex),
           {}
   };

   UNIT_SUITE(hex, cases);

A case left out of the table is an unused static function, which fails
the build. Each case runs in a child process with a 60-second limit, so
a crash, a sanitizer report or a hang fails that case alone.
``unit_skip()`` skips a case with a reason. The suite links the util
objects from an archive and needs no build rule of its own.

Write a shell test
~~~~~~~~~~~~~~~~~~

1. Create ``testing/functional/<family>/t<F><K><NN>-<what>.sh`` with the
   next free number.

2. Start it from :src:`testing/` and source the harness. An operator test
   sources ``test-lib.sh``:

   .. code-block:: sh

      #!/bin/sh
      # SPDX-License-Identifier: BSD-2-Clause
      # Copyright (c) 2026 Authors of shirudo
      #
      # t<F>0<NN> -- <what the test shows>.

      cd "$(dirname "$0")/../.."
      . ./test-lib.sh

      SHIRUDO=${SHIRUDO:-../shirudo}
      [ -x "$SHIRUDO" ] || test_skip_all "shirudo not built"

      WORK=$(mktemp -d)
      trap 'rm -rf "$WORK"' EXIT

      test_expect_success '<what this case shows>' '
              "$SHIRUDO" version >"$WORK/out"
      '

      test_done

   A target test sources ``integration-lib.sh`` instead and calls
   ``target_guard``, which requires root, ``$SHIRUDO_BIN`` and an
   attached LSM:

   .. code-block:: sh

      cd "$(dirname "$0")/../.."
      . ./integration-lib.sh
      target_guard

      require_loaded shirudo-test-basic ||
              test_skip_all "cannot load the basic fixture"

3. Run the family and check that the test ran and passed:

   .. code-block:: console

      # make -C testing functional/<family>

A target test finds loaded only what its family loaded, because each
family boots a VM of its own. ``require_loaded <fixture>`` loads a
signed fixture from the bundle unless it is loaded. State under
``/var/lib/shirudo`` is sealed, so a test cannot remove it, and the
tests of a family see what the earlier ones left there.

``test-lib.sh`` runs under ``set -eu``. Guard every step of an ``EXIT``
trap with ``|| true``, or the first failing step ends the cleanup and
the script fails although every case passed.

Add a fixture or a helper
~~~~~~~~~~~~~~~~~~~~~~~~~

- A target test loads BPF only from signed fixtures. Put the source in
  ``testing/fixtures/<name>.bpf.c`` and add a line
  ``build_fixture <name>.bpf.c <fixture> "$FIXTURE_WORK/trusted"`` to
  :src:`testing/vm/build-bundle.sh`. The bundle signs it on the build host
  and the guest finds it as
  ``$SHIRUDO_TEST_FIXTURES_DIR/<fixture>.upatch``.
- A compiled helper goes in ``testing/helper/<name>.c`` with a build
  rule in :src:`Makefile.shirudo` and an entry in ``TEST_HELPERS``. A
  helper that a target test runs also goes in the list of helpers that
  :src:`testing/vm/build-bundle.sh` copies into the bundle. A Python
  helper needs none of this.
- A fuzz target goes in ``testing/fuzz/fuzz-<name>.c`` with a seed
  corpus in ``testing/fuzz/corpus/<name>/`` and a rule in
  :src:`Makefile.shirudo` that names the sources it links.

Next steps
----------

- :doc:`/contribute/testing/test-coverage` for what each family covers and what
  no test covers
- :doc:`/upatches/test/testing` to test a upatch on a target
- :doc:`/contribute/code/contributing` before you send the change
