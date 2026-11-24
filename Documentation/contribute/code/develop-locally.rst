..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: shirudo contributors

Develop locally
===============

This page sets up both roles on one machine, so that you can change
shirudo and see the result end to end. Your host is the operator: it
runs ``shirudo`` and ``shirudo-build`` from your checkout, a local OCI
registry and a local OpenTelemetry Collector. The test VM is the target:
it boots from your checkout the way a production target boots. You then
take one package through its whole life: write it, publish it, install
it, watch its data arrive in the collector, update it and remove it. The
last section shows how to rebuild after a change to shirudo itself.
The plain HTTP registry and collector of this page are the shortest way
to see a package arrive; :ref:`local-dev-stack` runs the TLS registry,
collector and ClickHouse the end-to-end tests use instead.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Where
     - What runs there
   * - Host, as the operator
     - ``shirudo`` and ``shirudo-build`` from the checkout, the registry
       on ``127.0.0.1:5000``, the collector on ``127.0.0.1:4318``.
   * - Test VM, as the target
     - The runtime image built from the checkout. It reaches the host
       as ``10.0.2.2`` and sees the checkout as ``/workspace/shirudo``.

Before you begin
----------------

- A checkout that builds, as :doc:`/contribute/code/developer-guide` describes.
- The test VM's prerequisites and root on the host, as
  :doc:`/start/quickstart` lists them. Run every host command on this
  page as root, in the root of your checkout.
- Docker, for the registry and the collector.
- Two terminals on the host, one of them for the collector's output.

Set up the operator shell
-------------------------

1. Build ``shirudo`` and the helper:

   .. code-block:: console

      operator$ make
      operator$ make shirudo-build

2. Put both on the ``PATH`` of this shell, and name the helper:

   .. code-block:: console

      operator$ export PATH="$PWD:$PWD/tools/shirudo-build:$PATH"
      operator$ export SHIRUDO_BUILD="$PWD/tools/shirudo-build/shirudo-build"

3. Make a directory for your work. Git ignores ``build/``, and the test VM
   sees it as ``/workspace/shirudo/build/dev``:

   .. code-block:: console

      operator$ DEV=$PWD/build/dev
      operator$ mkdir -p "$DEV"

Start the registry and the collector
------------------------------------

1. Run a registry on the host's loopback interface:

   .. code-block:: console

      operator$ docker run -d --name shirudo-registry -p 127.0.0.1:5000:5000 docker.io/library/registry:3

2. Write ``build/dev/otelcol.yaml``, a collector configuration that
   prints every record it receives:

   .. code-block:: yaml

      receivers:
        otlp:
          protocols:
            http:
              endpoint: 0.0.0.0:4318

      exporters:
        debug:
          verbosity: detailed

      service:
        pipelines:
          logs:
            receivers: [otlp]
            exporters: [debug]
          metrics:
            receivers: [otlp]
            exporters: [debug]

3. Run the collector on the host's loopback interface:

   .. code-block:: console

      operator$ docker run -d --name shirudo-otelcol -p 127.0.0.1:4318:4318 -v "$DEV/otelcol.yaml:/etc/otelcol-contrib/config.yaml:ro" docker.io/otel/opentelemetry-collector-contrib:0.164.0

4. In the second terminal, follow what the collector receives:

   .. code-block:: console

      operator$ docker logs -f shirudo-otelcol

   Both containers speak plain HTTP, which is safe only on your own
   host. A production target speaks HTTPS with TLS 1.3 and a hybrid
   ML-KEM key exchange, see :doc:`/operate/run/telemetry`.

Boot the target
---------------

1. Boot a test VM named ``dev`` without the local-stack config:

   .. code-block:: console

      operator$ make -C testing vm VM_NAME=dev LOCAL_STACK=0

   The first run builds the kernel, the disk image and the bundle, which
   takes a while. :doc:`/contribute/testing/testing` describes the test VM.
   Without ``LOCAL_STACK=0`` the VM activates the ``config-local-stack``
   image, which points the export and the upatch tree at the TLS stack of
   :ref:`local-dev-stack`, not at the registry and collector of this
   page, and the next section would copy that config.

2. Name the bundle's signing key in the operator shell:

   .. code-block:: console

      operator$ KEYS=/tmp/shirudo-test-vm-private-$(id -u)/operator-keys/keys

   The test VM trusts this key for upatches and config images. The
   bundle generates a new one every time it is rebuilt.

3. Open a root shell on the target:

   .. code-block:: console

      operator$ make -C testing vm-ssh VM_NAME=dev

   In this shell ``shirudo`` is an alias of ``shirudo-runtime``, which
   runs the binary on the runtime image, the only one the target lets
   read and change shirudo's state, see :ref:`runtime-invocation`.

Connect the target to the registry and the collector
----------------------------------------------------

A target reads its repositories and its export destination from the
signed config image, not from files on its root file system (see
:doc:`/operate/run/deliver-packages`). Build a config that adds both, starting
from the config the target runs, and activate it.

1. On the target, copy the running config into the VM's result share:

   .. code-block:: console

      target# mkdir /mnt/shirudo-out/config-root
      target# cp -a /run/shirudo/config/etc /run/shirudo/config/keys /mnt/shirudo-out/config-root/

   The host sees the share as ``build/test-vm/vms/dev/result/``.

2. On the host, take the copy as the source of the new config:

   .. code-block:: console

      operator$ cp -a build/test-vm/vms/dev/result/config-root "$DEV/config-root"

3. Send the map exports and keepalives to the collector:

   .. code-block:: console

      operator$ printf '%s\n' 'map_export.otel_endpoint = http://10.0.2.2:4318' 'map_export.otel_insecure = true' >> "$DEV/config-root/etc/shirudo/shirudo.conf"

   ``map_export.otel_insecure`` allows cleartext OTLP to a host other
   than the target itself.

4. Register the registry as the repository ``dev``, with the
   certificate whose key signs its index:

   .. code-block:: console

      operator$ mkdir -p "$DEV/config-root/etc/shirudo/bpm/registries.d" "$DEV/config-root/etc/shirudo/bpm/keys"
      operator$ printf '%s\n' 'endpoint = oci://10.0.2.2:5000' 'index_repository = dev/bpm-index' 'key_file = /etc/shirudo/bpm/keys/dev.der' > "$DEV/config-root/etc/shirudo/bpm/registries.d/dev.conf"
      operator$ cp "$KEYS/cert.der" "$DEV/config-root/etc/shirudo/bpm/keys/dev.der"

5. Build and sign the config image, and verify it:

   .. code-block:: console

      operator$ tools/gen-image/shirudo-gen-image --source "$DEV/config-root" --output "$DEV/config-1" --keys-dir "$KEYS" --kind config --builder "$SHIRUDO_BUILD"
      bcca2bcd9661e77b094bd4197b335482a3a168ef693e2fc6706a37b62d0bcce9
      operator$ shirudo image verify "$DEV/config-1" --cert "$KEYS/cert.der"
      bcca2bcd9661e77b094bd4197b335482a3a168ef693e2fc6706a37b62d0bcce9

   Both commands print the config's root hash.

6. On the target, activate the config:

   .. code-block:: console

      target# shirudo image update /workspace/shirudo/build/dev/config-1
      target# shirudo image status
      Config root hash:      bcca2bcd9661e77b094bd4197b335482a3a168ef693e2fc6706a37b62d0bcce9
      PCR:                   14
      Sequence:              2
      TPM reset count:       1
      Restart count:         0
      Pending:               no
      Consistent:            yes
      target# shirudo bpm config register list
      Registered sources:
        dev

   ``Config root hash`` is the hash the host printed, ``Pending`` is
   ``no`` and ``Consistent`` is ``yes``.

7. Let the target's package commands and services reach the registry
   over plain HTTP:

   .. code-block:: console

      target# mkdir -p /etc/shirudo/bpm
      target# echo BPM_OCI_SCHEME=http > /etc/shirudo/bpm/environment
      target# export BPM_OCI_SCHEME=http

   The services read ``/etc/shirudo/bpm/environment``. Your shell needs
   the variable as well.

8. Check the collector's terminal. Every minute, the target's
   keepalive timer sends a record with ``EventName:
   shirudo.keepalive``.

Write a package
---------------

The package ``exec-count`` counts program executions by command name. A
Lua decoder turns the map into the record the target exports, the same
way a real upatch's data reaches a collector.

1. Make the package directory, with links to the checkout's headers:

   .. code-block:: console

      operator$ mkdir -p "$DEV/exec-count/decoders"
      operator$ ln -s "$PWD/vendor" "$DEV/exec-count/vendor"
      operator$ ln -s "$PWD/bpf" "$DEV/exec-count/bpf"

   ``shirudo-build`` compiles in the package directory. It takes the
   libbpf headers and ``vmlinux.h`` from :src:`vendor/` and
   ``decoder.h`` from :src:`bpf/lib/`. An installed operator
   package brings its own copies and needs no links.

2. Write ``build/dev/exec-count/exec-count.bpf.c``:

   .. literalinclude:: develop-locally/exec-count.bpf.c
      :language: c

   The program runs at every successful ``execve(2)`` and adds one to the
   entry of the new command's name in the hash map ``execs``. The
   manifest in ``.rodata`` names the Lua decoder for the map and the
   signal it produces, a log record. :doc:`/upatches/write/decoders` explains
   each field. A upatch that keeps records rather than counters keeps
   them in an arena with a serializer, see
   :doc:`/upatches/write/maps-arenas-serializers`.

3. Write ``build/dev/exec-count/decoders/execs.lua``:

   .. literalinclude:: develop-locally/execs-1.0.lua
      :language: lua

   The target calls ``decode`` with a snapshot of the map, each entry's
   key and value in hex. It returns the counts by name, which become the
   body of the log record.

4. Write ``build/dev/exec-count/Beefile``:

   .. code-block:: toml

      [package]
      name = "exec-count"
      description = "Counts program executions by command name"
      license = "GPL-2.0 OR BSD-2-Clause"

      [[upatches]]
      source = "exec-count.bpf.c"

5. Write ``build/dev/exec-count/README.md``, which ``shirudo bpm info``
   prints for whoever inspects the package:

   .. code-block:: markdown

      # exec-count

      Counts program executions by command name. A Lua decoder exports the
      counts as the body of one OTLP log record per snapshot of the execs map.

Build and publish it
--------------------

1. Build version 1.0.0:

   .. code-block:: console

      operator$ (cd "$DEV" && shirudo bpm build exec-count --version 1.0.0 --keys-dir "$KEYS")
      wrote /tmp/shirudo-bpm-build.<random>/0.upatch (insns=1664 sig=4853 data=5104 sections=3 maps=2 progs=1 decoders=1 name=exec-count)
      wrote /tmp/shirudo-bpm-build.<random>/0.unload.upatch (insns=1320 sig=4853 data=2808 sections=2 maps=1 progs=1 decoders=0 name=exec-count UNLOAD)
      <checkout>/build/dev/exec-count-1.0.0.bee

   ``<random>`` is the suffix of a temporary directory and
   ``<checkout>`` your checkout. The builder compiles and signs the
   upatch with its decoder (``decoders=1``), signs an unload directive for
   it and writes ``build/dev/exec-count-1.0.0.bee``.

2. Push it to the registry and add it to the registry's signed index:

   .. code-block:: console

      operator$ BPM_OCI_SCHEME=http shirudo bpm push "$DEV/exec-count-1.0.0.bee" oci://127.0.0.1:5000/dev/exec-count --keys-dir "$KEYS" --new-index
      oci://127.0.0.1:5000/dev/exec-count:1.0.0

   ``--new-index`` starts the registry's index with this first package;
   later pushes to the namespace leave it out.

   The index holds one package per version. A package built again under
   a version the index lists already is refused with ``bpm push: the
   repository index already lists exec-count 1.0.0 with different
   content``, and every build differs, since every signature does. Give
   every change a new version.

Install it
----------

1. On the target, fetch the repository's index:

   .. code-block:: console

      target# shirudo bpm repo update dev

   The command prints nothing when it succeeds.

2. Install the package from the repository:

   .. code-block:: console

      target# shirudo bpm install dev/exec-count
      upatch load: --no-precheck, pre-flight state check skipped
      upatch load: signed loader accepted, keyring 335804852, 208 instructions
      upatch load: loader ran, 2 maps and 1 programs
      upatch load: program 0 (raw_tracepoint) pinned at /run/shirudo/bpffs/upatches/exec-count/link
      upatch load: map 0 (execs) pinned at /run/shirudo/bpffs/upatches/exec-count/maps/execs
      upatch load: exec-count loaded, 1 programs, keyring 335804852
      upatch load: exec-count measured, register 23d80b8e3a30de1d5a556616d9d3eb388bbdb4bbc97f4e9fa81311909a3437ca

   The target checks the package against the signed index, requires its
   certificate to match the target's, and loads the upatch. The kernel
   checks the signature, and the target measures the load.

3. List the installed packages and the loaded upatches:

   .. code-block:: console

      target# shirudo bpm list
      Installed packages:
        NAME                      VERSION       SOURCE
        exec-count                1.0.0         dev
      target# shirudo upatch list
      Archived upatches (/var/lib/shirudo/upatches):
        NAME                      LOADED  TYPE    KIND  PAYLOAD
        exec-count                yes     load    bpf   00357162c0dfd6dc..

Watch the data
--------------

1. Run a few commands on the target:

   .. code-block:: console

      target# date; uname -a; id

2. Check the collector's terminal. Every five seconds, the target's
   map-export timer reads the map, runs the decoder and sends a record:

   .. code-block:: text

      LogRecord #0
      ObservedTimestamp: 2026-10-29 23:29:10.608332126 +0000 UTC
      Timestamp: 2026-10-29 23:29:10.608332126 +0000 UTC
      SeverityText: INFO
      SeverityNumber: Info(9)
      EventName: shirudo.bpf.map.snapshot
      Body: Map({"execs":[{"command":"modprobe","count":19},{"command":"9","count":17},{"command":"shirudo-runtime","count":16},{"command":"shirudo","count":16},{"command":"date","count":8},{"command":"uname","count":7},...]})
      Attributes:
           -> shirudo.upatch.name: Str(exec-count)
           -> shirudo.upatch.location: Str(tracing/btf_trace_sched_process_exec)
           -> shirudo.map.name: Str(execs)
           -> shirudo.map.type: Str(hash)
           -> shirudo.map.max_entries: Int(1024)
           -> shirudo.map.n_entries: Int(50)
           -> shirudo.map.n_cpus: Int(1)
           -> shirudo.map.serialized: Bool(false)
           -> shirudo.map.truncated: Bool(false)

   The body is what the decoder returned, shortened here. It counts
   every execution on the guest, the target's own timers included, so
   your counts differ. The attributes name the upatch, its attach point
   and the map, see :doc:`/reference/formats/map-export`.

3. While you work on a decoder, run it by hand against the live map:

   .. code-block:: console

      target# shirudo upatch map exec-count execs --json --peek
      {"execs":[{"command":"modprobe","count":16},{"command":"shirudo","count":11},{"command":"shirudo-runtime","count":11},{"command":"date","count":8},...]}

   The command prints the decoder's result as one JSON document,
   shortened here, or the decoder's error. ``--peek`` leaves a serializer-backed map undrained;
   a hash map is never drained.

Update it
---------

1. Change the decoder to report the total as well. Replace ``decode`` in
   ``build/dev/exec-count/decoders/execs.lua``:

   .. literalinclude:: develop-locally/execs-1.1.lua
      :language: lua
      :start-at: function decode

2. Build and push version 1.1.0:

   .. code-block:: console

      operator$ (cd "$DEV" && shirudo bpm build exec-count --version 1.1.0 --keys-dir "$KEYS")
      operator$ BPM_OCI_SCHEME=http shirudo bpm push "$DEV/exec-count-1.1.0.bee" oci://127.0.0.1:5000/dev/exec-count --keys-dir "$KEYS"
      oci://127.0.0.1:5000/dev/exec-count:1.1.0

3. On the target, fetch the index and upgrade:

   .. code-block:: console

      target# shirudo bpm repo update dev
      target# shirudo bpm upgrade
      upatch unload: --no-precheck, pre-flight state check skipped
      upatch unload: signed loader accepted, keyring 335804852, 165 instructions
      upatch unload: exec-count carries the directive's payload
      upatch unload: exec-count measured, register 422dadf3d3e5b1abbc6a9257ccaabecc5259998ad2ace271b52c62a85e728602
      upatch unload: exec-count detached and unpinned
      upatch load: --no-precheck, pre-flight state check skipped
      upatch load: signed loader accepted, keyring 335804852, 208 instructions
      upatch load: loader ran, 2 maps and 1 programs
      upatch load: program 0 (raw_tracepoint) pinned at /run/shirudo/bpffs/upatches/exec-count/link
      upatch load: map 0 (execs) pinned at /run/shirudo/bpffs/upatches/exec-count/maps/execs
      upatch load: exec-count loaded, 1 programs, keyring 335804852
      upatch load: exec-count measured, register 5d01da4114c32805d9863fb76cf7d760c1d86a1839ef4d5f79b41685b833d46b
      target# shirudo bpm list
      Installed packages:
        NAME                      VERSION       SOURCE
        exec-count                1.1.0         dev

   ``upgrade`` unloads the old version with its signed unload directive
   and loads the new one, and restores the old one if the new one fails
   to load. The two commands act at once: from building the new version
   to running it on the target takes a few seconds. The target's package
   timer does the same by itself about a minute after each of its runs,
   which is what a production target relies on; ``journalctl -u
   shirudo-bpm-repo-update.service`` on the target shows its runs.

4. Check the collector's terminal. The records now carry ``total``, and
   the counts start again from zero, since the new version has a new map.

Remove it
---------

1. Uninstall the package on the target:

   .. code-block:: console

      target# shirudo bpm uninstall exec-count
      upatch unload: --no-precheck, pre-flight state check skipped
      upatch unload: signed loader accepted, keyring 335804852, 165 instructions
      upatch unload: exec-count carries the directive's payload
      upatch unload: exec-count measured, register 2bf2d8fda256c469544e6d33638bb23fc0801e650bba4068411a779c698ab131
      upatch unload: exec-count detached and unpinned

   The target runs the package's signed unload directive, measures the
   unload and deletes the package. ``shirudo bpm list`` and ``shirudo
   upatch list`` print ``none``.

2. Check the collector's terminal. The map records stop, and the
   keepalives go on.

The registry keeps every version you pushed. ``bpm upgrade`` only
upgrades installed packages, so it does not bring the package back. To
start over with an empty registry, remove the container as `Clean up`_
shows and start it again.

Change shirudo
--------------

The host runs the operator commands from your checkout, so a change to
them takes effect as soon as you rebuild. The target runs the runtime
image of the bundle the VM booted with, so a change to anything the
target runs takes a new bundle and a new VM.

- After a change to an operator command, ``shirudo-build`` or the package
  tools, rebuild:

  .. code-block:: console

     operator$ make && make shirudo-build

- After a change to the target side, such as a ``builtin-*.c`` command
  the target runs, :src:`util/`, the BPF programs under :src:`bpf/` or the boot
  integration, replace the VM:

  .. code-block:: console

     operator$ make -C testing vm-clean VM_NAME=dev
     operator$ make -C testing vm VM_NAME=dev LOCAL_STACK=0

  ``make -C testing vm`` rebuilds the bundle from your checkout and boots
  a new VM, which takes about two minutes once the kernel and the disk
  image exist. It refuses a name that still has state, hence
  ``vm-clean``. ``shirudo status`` on the target then prints a new
  ``Version ID``. The target accepts only the binary on its
  authenticated runtime image, so there is no faster way to run changed
  target code. The rebuilt bundle has a new signing key, so repeat this
  page from `Boot the target`_ with an empty registry: remove and start
  ``shirudo-registry`` again, build a new config, and build and push your
  packages again.

- Test what you can on the host first. The unit tests and the operator
  tests run in seconds without a VM:

  .. code-block:: console

     operator$ make -C testing unit
     operator$ make -C testing functional/<family> VM=0

  Then run the target tests your change touches by hand in the VM, and
  the whole family for a verdict, as :doc:`/contribute/testing/testing`
  describes.

Clean up
--------

1. Stop the VM and remove its state:

   .. code-block:: console

      operator$ make -C testing vm-clean VM_NAME=dev

2. Remove the containers:

   .. code-block:: console

      operator$ docker rm -f shirudo-registry shirudo-otelcol

Next steps
----------

- :doc:`/upatches/write/decoders` for decoders and metrics
- :doc:`/upatches/write/maps-arenas-serializers` for upatches that keep
  records
- :doc:`/operate/run/deliver-packages` and :doc:`/operate/run/telemetry` for the
  production setup this page reproduces
- :doc:`/contribute/testing/testing` to write and run tests
