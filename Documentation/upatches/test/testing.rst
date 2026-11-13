..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: upatch authors

Test an upatch on a target
==========================

Load an upatch on a real target before it ships, read what it records,
and unload it again. The test VM in a shirudo checkout is such a target:
it boots the dm-verity runtime image and a signed config image from a
dracut initrd, with a software TPM, and runs ``shirudo init`` there as a
production target does. This page uses it, and the commands on the target
are the same elsewhere.

Before you begin
----------------

- A shirudo checkout built with ``make`` and ``make shirudo-build``
- A Linux host with KVM, root, and the host packages the test VM needs,
  listed in :doc:`/contribute/testing/testing`
- An upatch and its unload directive, built as in
  :doc:`/upatches/learn/kernel-fix-tutorial`, or one of the signed fixtures
  below

Boot the test VM
----------------

1. Boot an interactive VM from the checkout's root:

   .. code-block:: console

      # make -C testing vm VM_NAME=upatch-dev

   ``VM_NAME`` is optional and names the VM for the commands below. The VM
   boots a bpf-next kernel by default. ``KERNEL=7.4``, or a later release,
   boots that release instead. The first run builds the kernel and the
   bundle of signed images and fixtures, which takes a while. The command
   returns once the VM is ready.

2. Open a shell on it:

   .. code-block:: console

      # make -C testing vm-ssh VM_NAME=upatch-dev

   Without ``VM_NAME``, ``vm-ssh`` opens the most recently started VM.

3. Check that enforcement is up:

   .. code-block:: console

      target# shirudo-runtime status
      Host:                  upatch-dev
      Roles:                 target
      Status:                ok
      ...

   The ``Status:`` line reads ``ok``. In the VM, run every shirudo command
   as ``shirudo-runtime``. It executes shirudo from the verified runtime
   image, and only a process started from that image has shirudo's runtime
   authority. The plain ``shirudo`` in the VM, ``/usr/local/bin/shirudo``,
   is the same binary outside the runtime image. Every command of it that
   reads shirudo's state stops with ``shirudo: image state: Permission
   denied``.

Get the upatch into the VM
--------------------------

4. Sign the upatch and its unload directive with the key the VM enrolled.
   The bundle keeps it outside the checkout, which the VM can read, in
   ``/tmp/shirudo-test-vm-private-<uid>/operator-keys/keys``, where
   ``<uid>`` is your user ID, or under ``TEST_VM_HOST_PRIVATE_DIR`` when
   you set it. Pass that directory to ``shirudo build --keys-dir``, as
   root: the bundle belongs to the user who built the VM.

5. Put both files under the checkout, for example under ``build/``. The VM
   sees the checkout read-only at ``/mnt/shirudo-src``, so
   ``build/rpl-shield/cve-2026-63984-rpl.upatch`` on the host is
   ``/mnt/shirudo-src/build/rpl-shield/cve-2026-63984-rpl.upatch`` in the
   VM.

Load and observe it
-------------------

6. Load the upatch and keep the report:

   .. code-block:: console

      target# shirudo-runtime upatch load --report=/tmp/load.json \
          /mnt/shirudo-src/<path>.upatch

   ``<path>`` is the upatch's path in the checkout. The command exits with 0
   on success, 2 when an attach target is missing or the command line is
   wrong, and 1 on any other failure. The report's ``category`` says why,
   and :doc:`/upatches/test/debugging` goes through each one. To refuse the load
   unless the measurement register still holds a value you read before, add
   ``--expect-chain=<chain>``, with ``<chain>`` the ``tpm.chain`` field of
   ``shirudo-runtime status --json``.

7. List what is loaded and archived:

   .. code-block:: console

      target# shirudo-runtime upatch list

8. Show where the upatch attached, its program source lines and its maps:

   .. code-block:: console

      target# shirudo-runtime upatch get <name>

   ``<name>`` is the upatch name, which ``shirudo upatch info`` shows on
   the operator host.

9. Run the workload or the reproducer that should reach the hooked code,
   then read a map without draining it:

   .. code-block:: console

      target# shirudo-runtime upatch map <name> <map> --peek

   ``shirudo-runtime upatch map <name>`` lists the upatch's maps. A map
   with a serializer is rendered by it, and ``--peek`` asks the serializer
   to leave the records for the exporter. Add ``--json`` to see what the
   map's decoder returns. For a map without a decoder, ``--json`` fails
   with ``upatch map: print JSON: No data available``.

Unload it
---------

10. Apply the unload directive:

    .. code-block:: console

       target# shirudo-runtime upatch unload --report=- \
           /mnt/shirudo-src/<path>.unload.upatch

    The report shows category ``ok``. ``already_unloaded``, with exit
    status 0, means nothing of that name was loaded. ``payload_mismatch``,
    with exit status 1, means the directive was built for another build of
    the upatch, and the upatch stays loaded.

11. Verify that the upatch is gone and the target is still healthy:

    .. code-block:: console

       target# shirudo-runtime upatch list
       target# shirudo-runtime status

    The upatch is not listed, and ``status`` still reads ``ok``. Every
    load and unload moved the measurement register forward.

12. Leave the VM shell, and stop the VM on the host when you are done:

    .. code-block:: console

       # make -C testing vm-stop VM_NAME=upatch-dev

    Without ``VM_NAME``, ``vm-stop`` stops every VM it tracks. The VM's
    state stays under ``build/test-vm/vms/``.

Use the signed fixtures
-----------------------

The bundle carries upatches signed with the same key, in the VM at
``/mnt/shirudo-bundle/fixtures/``, those below with an ``.unload.upatch``
beside them. Their sources are in :src:`testing/fixtures/`. They are handy for
trying the commands above or for comparing your upatch with a known good
one.

.. list-table::
   :header-rows: 1
   :widths: 38 62

   * - Fixture
     - What it shows
   * - ``shirudo-test-basic``, ``shirudo-test-marker``
     - an ``fentry`` program on ``do_nanosleep`` and nothing else
   * - ``shirudo-test-map-export``
     - two maps, one with a log decoder and one with a metric decoder
   * - ``shirudo-test-otel-backend``
     - log and metric decoders for the OTLP export
   * - ``shirudo-test-serialized-metric``
     - a serializer over an array map, with a metric decoder
   * - ``shirudo-test-arena-tree``
     - a binary tree in an arena, rendered by a serializer
   * - ``shirudo-test-uprobe-multi``
     - ``uprobe.multi`` on ``/tmp/shirudo-test-uprobe-target``. Copy
       ``shirudo-test-uprobe-target`` from the fixtures to that path first.
   * - ``shirudo-test-uretprobe-multi``
     - ``uretprobe.multi`` on the same binary and functions, counting in
       the map ``hits``
   * - ``shirudo-test-uprobe``, ``shirudo-test-uretprobe``
     - ``uprobe`` and ``uretprobe`` on ``fooFunc`` of the same binary,
       counting in ``hits``
   * - ``shirudo-test-uprobe-multi-sleepable``
     - sleepable ``uprobe.multi.s`` on the same binary and functions,
       counting in ``hits`` each call whose ``bpf_copy_from_user()`` of the
       task's arguments succeeds
   * - ``shirudo-test-scope-cgroup``, ``shirudo-test-scope-netfilter``,
       ``shirudo-test-scope-kprobe``
     - ``cgroup_skb``, ``netfilter`` and ``kprobe`` attachments and the
       attach-scope check
   * - ``kernel-obs``
     - the upatch of the ``kernel-obs`` package

The test VM's kernel configuration has no kprobes, so the kprobe fixture
fails there with ``attach_target_missing``, which shows what that
category looks like.

Next steps
----------

- :doc:`/upatches/test/debugging` when a load fails
- :doc:`/upatches/publish/publishing` once the upatch works
- :doc:`/contribute/testing/testing` for the automated tests that boot the same
  VM
