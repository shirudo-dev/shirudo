..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: All readers

Cheat sheet
===========

Command lines for common tasks, grouped by task. The prompt says where a
command runs: ``operator$`` on the operator host, ``target#`` as root on a
target, ``$`` and ``#`` in a checkout. On a production target, ``shirudo``
stands for the runtime binary ``/run/shirudo/runtime/usr/bin/shirudo``
(see :doc:`cli/shirudo`). ``~/shirudo-keys`` stands for the operator's keys
directory. Each command links to its reference page.

Keys and signing
----------------

Create an ML-DSA-87 key and certificate with :doc:`cli/genkey`:

.. code-block:: console

   operator$ shirudo genkey --keys-dir ~/shirudo-keys

Show the key material with :doc:`cli/keys`:

.. code-block:: console

   operator$ shirudo keys --keys-dir ~/shirudo-keys

Vouch for a second operator's certificate with :doc:`keys vouch
<cli/keys>`:

.. code-block:: console

   operator$ shirudo keys vouch other-cert.der -o other-cert.der.vouch --keys-dir ~/shirudo-keys

Prepare a new key pair beside the old one and vouch for it with the old
key, before any target relies on it (:doc:`/operate/maintain/keys`):

.. code-block:: console

   operator$ shirudo genkey --keys-dir ~/shirudo-keys-new
   operator$ shirudo keys vouch ~/shirudo-keys-new/cert.der --keys-dir ~/shirudo-keys

Build and inspect
-----------------

Compile and sign a upatch into ``fix.bpf.upatch`` with :doc:`cli/build`:

.. code-block:: console

   operator$ shirudo build fix.bpf.c --keys-dir ~/shirudo-keys --vmlinux <vmlinux-h>

``<vmlinux-h>`` is the ``vmlinux.h`` of the target kernel.

Choose the output and the name, and keep the compiled object, with
:doc:`cli/build`:

.. code-block:: console

   operator$ shirudo build fix.bpf.c -o fix.upatch --name fix --keys-dir ~/shirudo-keys --vmlinux <vmlinux-h> --emit-artifacts

Describe an artifact offline with :doc:`cli/upatch-info`:

.. code-block:: console

   operator$ shirudo upatch info fix.upatch

Read its payload digest with :doc:`cli/upatch-info`:

.. code-block:: console

   operator$ shirudo upatch info --json fix.upatch | jq -r .payload_sha256

Sign the unload directive bound to that payload with :doc:`cli/build`
and ``--unload``:

.. code-block:: console

   operator$ shirudo build --unload fix --payload-sha256 "$(shirudo upatch info --json fix.upatch | jq -r .payload_sha256)" -o fix.unload.upatch --keys-dir ~/shirudo-keys

Target state
------------

Run the pre-flight checks without bringing up enforcement with
:doc:`cli/init`:

.. code-block:: console

   target# shirudo init --check-only

Show the state of the target with :doc:`cli/status`:

.. code-block:: console

   target# shirudo status

Read the verdict in a script with :doc:`cli/status`. The exit status is 0
even when the verdict is ``tampered``:

.. code-block:: console

   target# shirudo status --json | jq -r .status

Show everything, the folded sections, the eventlog and the system, with
:doc:`cli/status`:

.. code-block:: console

   target# shirudo status --show-full

Print the effective configuration with :doc:`cli/config`:

.. code-block:: console

   target# shirudo config

Print the version ID that ``--expect-version-id`` compares with
:doc:`cli/version`:

.. code-block:: console

   target# shirudo version --version-id

Show the certificates and the ``.bpf`` keyring with :doc:`cli/keys`:

.. code-block:: console

   target# shirudo keys

Load and unload
---------------

Load an artifact and print the report with :doc:`cli/upatch-load`:

.. code-block:: console

   target# shirudo upatch load --report=- fix.upatch

Load only when the register holds the value you predicted with
:doc:`cli/upatch-load`. ``<register>`` comes from
:doc:`cli/attest-predict`:

.. code-block:: console

   target# shirudo upatch load --expect-chain=<register> fix.upatch

Load only on the shirudo build you tested with :doc:`cli/upatch-load`:

.. code-block:: console

   target# shirudo upatch load --expect-version-id=<version-id> fix.upatch

Unload with a signed directive and print the category with
:doc:`cli/upatch-unload`:

.. code-block:: console

   target# shirudo upatch unload --report=- fix.unload.upatch | jq -r .category

List the archived and the loaded upatches with :doc:`cli/upatch-list`:

.. code-block:: console

   target# shirudo upatch list --json

Show a loaded upatch with its hook, source lines and every map entry with
:doc:`cli/upatch-get`:

.. code-block:: console

   target# shirudo upatch get fix --json --show-full

Packages and the tree
---------------------

Build ``kernel-obs-1.0.0.bee`` from its Beefile with :doc:`bpm build
<cli/bpm>`:

.. code-block:: console

   operator$ shirudo bpm build upatches/kernel-obs --version 1.0.0 --keys-dir ~/shirudo-keys

List the upatches and directives in a package with :doc:`bpm info
<cli/bpm>`:

.. code-block:: console

   operator$ shirudo bpm info upatches ./kernel-obs-1.0.0.bee --all

Print the fingerprint of the certificate in a package with :doc:`bpm key
<cli/bpm>`:

.. code-block:: console

   operator$ shirudo bpm key fingerprint ./kernel-obs-1.0.0.bee

Publish a package and add it to the registry's signed index with
:doc:`bpm push <cli/bpm>`:

.. code-block:: console

   operator$ shirudo bpm push ./kernel-obs-1.0.0.bee oci://quay.io/example/kernel-obs --keys-dir ~/shirudo-keys

Add ``--new-index`` for the first package of a namespace, which has no
index yet.

Build the next version with a new ``.rodata`` input with :doc:`bpm config
update <cli/bpm>`. ``watch`` names the Beefile input ``watch.list``:

.. code-block:: console

   operator$ shirudo bpm config update --base-package ./kernel-obs-1.0.0.bee --version 1.0.1 --rodata-input watch=./watch.list --keys-dir ~/shirudo-keys

Append a package's tree entries to the signed tree with :doc:`bpm tree
append <cli/bpm>`. ``<package>`` is a built package whose Beefile has
``[upatches.tree]`` entries:

.. code-block:: console

   operator$ shirudo bpm tree append <package> oci://quay.io/example/tree --keys-dir ~/shirudo-keys

Retract them on another tree reference with :doc:`bpm tree append
<cli/bpm>`:

.. code-block:: console

   operator$ shirudo bpm tree append <package> oci://quay.io/example/tree --keys-dir ~/shirudo-keys --reference canary --op delete

Refresh the indexes and upgrade, as ``shirudo-bpm-repo-update.timer``
does, with :doc:`cli/bpm`:

.. code-block:: console

   target# shirudo bpm repo update
   target# shirudo bpm upgrade

Install a pinned version from a registered repository with :doc:`bpm
install <cli/bpm>`:

.. code-block:: console

   target# shirudo bpm install example/kernel-obs@1.0.0

Install directly from a registry reference with :doc:`bpm install
<cli/bpm>`:

.. code-block:: console

   target# shirudo bpm install oci://quay.io/example/kernel-obs:1.0.0

List and remove installed packages with :doc:`cli/bpm`:

.. code-block:: console

   target# shirudo bpm list
   target# shirudo bpm uninstall kernel-obs

Preview a tree sync with :doc:`bpm tree sync <cli/bpm>`:

.. code-block:: console

   target# shirudo bpm tree sync --dry-run --report=/tmp/tree.json

Attestation
-----------

Make a nonce on the operator host:

.. code-block:: console

   operator$ NONCE=$(openssl rand -hex 32)

Produce evidence for that nonce on the target with :doc:`cli/attest`:

.. code-block:: console

   target# shirudo attest --nonce=<nonce> --output=ev.json

Read the attestation key name to pin at enrollment:

.. code-block:: console

   operator$ jq -r .ak.name ev.json

Make a credential challenge for the pinned key with
:doc:`cli/attest-challenge`:

.. code-block:: console

   operator$ shirudo attest challenge --evidence=ev.json --ak-name=<ak-name> --ek-ca=<tpm-vendor-roots> --output=challenge.json

Answer the challenge on the target with :doc:`cli/attest`:

.. code-block:: console

   target# shirudo attest --nonce=<nonce> --challenge=challenge.json --output=ev.json

Predict the register for the certificates the target enrolls and a load
after boot with :doc:`cli/attest-predict`:

.. code-block:: console

   operator$ shirudo attest predict --cert=cert.der --cert=own.der --event=load:fix=<payload-sha256>

Verify evidence against the predicted value with :doc:`cli/attest-verify`:

.. code-block:: console

   operator$ shirudo attest verify --evidence=ev.json --nonce=$NONCE --ak-name=<ak-name> --expect-chain=<register>

Verify against the enrolled certificates, accepting events after boot,
with :doc:`cli/attest-verify`:

.. code-block:: console

   operator$ shirudo attest verify --evidence=ev.json --nonce=$NONCE --ak-name=<ak-name> --cert=cert.der --cert=own.der --allow-runtime-events --require-initrd

Images and config
-----------------

Build a signed config image from a directory with :doc:`cli/gen-tools`:

.. code-block:: console

   operator$ /usr/libexec/shirudo/gen-image/shirudo-gen-image --source ./config-root --output ./config --keys-dir ~/shirudo-keys --kind config

Sign an existing ext4 image with :doc:`image build <cli/image>`:

.. code-block:: console

   operator$ shirudo image build config.ext4 --output config --keys-dir ~/shirudo-keys

Verify an image offline with :doc:`image verify <cli/image>`. The
argument order is fixed:

.. code-block:: console

   operator$ shirudo image verify config --cert config-cert.der

Activate a new config image on a target with :doc:`image update
<cli/image>`:

.. code-block:: console

   target# shirudo image update https://config.example/shirudo/config

Select a config containing new vouched BPF signers for the next planned
reboot with :doc:`image stage <cli/image>`. It leaves the active config,
keyrings and measurements unchanged:

.. code-block:: console

   target# shirudo image stage https://config.example/shirudo/with-new-signer

Cancel that selection before reboot:

.. code-block:: console

   target# shirudo image stage --cancel

Show the config activation with :doc:`image status <cli/image>`. It exits
with 1 while the activation is pending:

.. code-block:: console

   target# shirudo image status

Build the initrd and print the kernel parameters it needs with
:doc:`cli/gen-tools`:

.. code-block:: console

   target# shirudo-gen-initrd --bootstrap-conf <bootstrap-conf>
   target# shirudo-gen-initrd --print-cmdline

Telemetry
---------

List the pinned maps with :doc:`cli/upatch-map`:

.. code-block:: console

   target# shirudo upatch map

Look at a serializer-backed map without draining it with
:doc:`cli/upatch-map`:

.. code-block:: console

   target# shirudo upatch map kernel-obs exec --json --peek

Send one map to a collector with :doc:`cli/upatch-map`:

.. code-block:: console

   target# shirudo upatch map kernel-obs exec --otel --otel-endpoint=https://collector.example:4318 --tenant-id=fleet-eu-1

Export every map to the configured destinations, as
``shirudo-map-export.timer`` does, with :doc:`cli/upatch-map`:

.. code-block:: console

   target# shirudo upatch map --all

Send a keepalive and print it with :doc:`cli/status`. Nothing is sent
without a configured endpoint:

.. code-block:: console

   target# shirudo status --otel --include-system --json

Developing shirudo
------------------

Build the operator binary, the helper and the static target binary
(:doc:`/contribute/code/developer-guide`):

.. code-block:: console

   $ make
   $ make shirudo-build
   $ make target

Run ``shirudo`` from the checkout with the checkout's helper:

.. code-block:: console

   $ export SHIRUDO_BUILD=$PWD/tools/shirudo-build/shirudo-build

Run every test (:doc:`/contribute/testing/testing`):

.. code-block:: console

   $ make tests

Run the tests that need no VM under the sanitizers:

.. code-block:: console

   $ make tests VM=0 SANITIZE=address,undefined

Run one unit suite and one functional family without a VM:

.. code-block:: console

   $ make -C testing unit/hex
   $ make -C testing functional/upatch VM=0

List the suites and families:

.. code-block:: console

   $ make -C testing help

Boot the interactive test VM, log in and stop it. Booting needs root:

.. code-block:: console

   # make -C testing vm
   # make -C testing vm-ssh
   # make -C testing vm-stop

Run the fuzz targets for a minute each:

.. code-block:: console

   $ make -C testing fuzz FUZZ_SECONDS=60

Render and serve the documentation, and check it against the code
(:doc:`/contribute/documentation/writing-docs`):

.. code-block:: console

   $ make docs
   $ make -C Documentation check

Check the commits of a branch as CI does (:doc:`/contribute/code/contributing`):

.. code-block:: console

   $ .github/scripts/check-dco.sh origin/main..HEAD
   $ .github/scripts/check-style.sh origin/main..HEAD
   $ .github/scripts/check-spdx.sh
   $ .github/scripts/build-commits.sh origin/main..HEAD
