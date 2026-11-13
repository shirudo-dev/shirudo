..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: upatch authors

Debug a failed load
===================

When ``shirudo upatch load`` or ``unload`` fails, its JSON report says
how far the operation got and why it stopped. This page shows how to get
the report, how to read the phase, the category and the verifier log, and
what to change for each failure.

Before you begin
----------------

- Root on the target where the load failed, and the ``.upatch`` file
- The source and the ``vmlinux.h`` the upatch was built from, on the
  operator host

Get the report
--------------

1. Load the upatch again with a report:

   .. code-block:: console

      target# shirudo upatch load --report=- <file>.upatch

   ``<file>`` is the upatch. ``--report=<path>`` writes the report to a
   file instead of standard output. Log lines, including the verifier log,
   go to standard error and to the journal. In the test VM, run
   ``shirudo-runtime`` instead of ``shirudo``.

   A failed load is undone: shirudo removes whatever it pinned, and a load
   that the measurement register did not record is taken back out. You can
   load again after every change.

2. Read three fields of the report: ``phase``, the step that failed,
   ``category``, the kind of failure, and ``errno_name``, the error the
   kernel or shirudo returned. ``message`` adds a short description.
   :doc:`/reference/failure-categories` defines every category and the
   exit status of each command.

   For an upatch that a package or the tree delivered, the same failure
   is in the journal:

   .. code-block:: console

      target# journalctl -t shirudo -p err

Find the cause
--------------

3. Look up the phase and the category. A load goes through the phases in
   this order and stops at the first failure.

   .. list-table::
      :header-rows: 1
      :widths: 20 24 56

      * - Phase
        - Category
        - Cause and what to do
      * - ``pre_flight``
        - ``version_mismatch``
        - ``--expect-version-id`` names another shirudo build than the
          target runs. Build with the target's version, or drop the
          option.
      * - ``pre_flight``
        - ``kernel_abi_unsupported``
        - The kernel's BTF lacks the signed-loader fields shirudo needs.
          ``message`` names the field. Boot a kernel that meets
          :doc:`/operate/plan/system-requirements`.
      * - ``pre_flight``
        - ``keyring_missing``
        - ``shirudo init`` has not frozen a trust anchor this boot. The
          target is not initialized.
      * - ``pre_flight``
        - ``tampered``
        - The ``.bpf`` keyring is not the one ``init`` froze, shirudo's
          LSM link is not pinned, or the register is not the
          ``--expect-chain`` value. Do not retry. Follow
          :doc:`/operate/troubleshoot/incident-tampered`.
      * - ``pre_flight``
        - ``eventlog_full``
        - The eventlog would grow past ``eventlog.max_bytes``. Nothing was
          loaded. The operator has to make room.
      * - ``parse``
        - ``parser_rejected``
        - The file is not a valid upatch, is an unload directive, has a
          name that is not signed or not allowed, a payload digest that
          does not match its content, or attach metadata that is missing
          or invalid. Rebuild it with ``shirudo build`` and check that you
          passed the right file.
      * - ``target_verify``
        - ``attach_target_missing``, ``binary_mismatch``,
          ``parser_rejected``, ``lsm_denied``
        - The binary of a ``uprobe``, ``uretprobe``, ``uprobe.multi`` or
          ``uretprobe.multi`` upatch is missing,
          differs from the one the upatch was built against, is shorter
          than a recorded offset, or could not be read. Rebuild against
          the binary the target runs.
      * - ``signed_loader_load``
        - ``signature_rejected``
        - The signature does not verify against the ``.bpf`` keyring: the
          upatch was signed with a key the target did not enroll, or it
          changed after signing. Compare ``shirudo keys`` on the target
          with your certificate.
      * - ``signed_loader_load``
        - ``keyring_missing``
        - The keyring holds no key for the signer.
      * - ``signed_loader_load``
        - ``signature_unsupported``
        - The kernel cannot verify ML-DSA signatures, because it lacks
          ``CONFIG_CRYPTO_MLDSA``.
      * - ``signed_loader_load``
        - ``lsm_denied``
        - The LSM refused a BPF command, usually because the command did
          not run as shirudo's runtime binary.
      * - ``signed_loader_load``
        - ``verifier_rejected``
        - The verifier refused the loader itself. Read the verifier log.
      * - ``payload_load``
        - ``verifier_rejected``
        - The loader ran and failed: the verifier refused a payload
          program, a CO-RE relocation found no match, a BTF attach target
          does not exist, or a map could not be created. Read the
          verifier log and ``loader_return``.
      * - ``link_create``
        - ``attach_target_missing``
        - A ``kprobe`` symbol that kallsyms does not list, often in a
          module that is not loaded, a kernel without the kprobe PMU, or a
          missing ``/sys/fs/cgroup``. The command exits with 2.
      * - ``link_create``
        - ``attach_scope_mismatch``
        - The kernel attached somewhere else than the metadata names,
          because the command ran in another cgroup or network namespace
          or with a changed sysfs. Load from the host's initial
          namespaces.
      * - ``link_create``
        - ``kernel_abi_unsupported``, ``lsm_denied``, ``binary_mismatch``
        - The kernel does not support the attachment, the LSM refused it,
          or the uprobe binary changed.
      * - ``link_create``
        - ``unknown``
        - Any other error. ``EEXIST``: an upatch of the same name is
          loaded. Unload it first. ``EINVAL``: the kernel refused the
          attachment, such as ``bpf_override_return()`` outside an
          error-injection function. ``EADDRNOTAVAIL``: kallsyms lists the
          ``kprobe`` symbol more than once.
      * - ``persist``
        - ``unknown``
        - The archive copy could not be written. The load was undone.
      * - ``tpm_extend``
        - ``tampered``
        - The register refused the extend because it is not the one
          ``init`` bound. The load was undone. Treat it as an incident.
      * - ``tpm_extend``
        - ``tpm_error``
        - The TPM or the eventlog failed. When the extend itself failed,
          the load was undone.

   An unload reports these besides the shared ones:

   .. list-table::
      :header-rows: 1
      :widths: 20 24 56

      * - Phase
        - Category
        - Cause and what to do
      * - ``parse``
        - ``parser_rejected``
        - The file is a load directive, or its target name is not signed.
      * - ``pin``
        - ``payload_mismatch``
        - The loaded upatch has another payload digest than the directive
          expects, or its recorded digest cannot be read. Build the
          directive with ``--payload-sha256`` set to the digest of the
          loaded build, from ``shirudo upatch info --json``.
      * - ``pin``
        - ``already_loaded``
        - A upatch of that name is loaded. Unload it with its signed
          directive first; nothing was touched.
      * - ``done``
        - ``already_unloaded``
        - Nothing of that name is loaded. Exit status 0, nothing measured.
      * - ``pin``
        - ``detach_failed``
        - The unload was measured, but the pins could not be removed.
          Apply the directive again.

Read the verifier log
---------------------

4. For ``verifier_rejected``, read the report's ``verifier_log``, which
   keeps up to 16 MiB of the kernel's log. In phase
   ``signed_loader_load`` it is the log of the loader's own load. In phase
   ``payload_load`` it is the log of the last load the loader made, since
   the loader passes the same buffer to each map, BTF and program load,
   so its end is about the step that failed. The log on standard error is
   cut at 4096 bytes when the loader returned an error. The report has
   all of it. ``loader_return`` is the loader's negative error.

5. Match the last lines of the log:

   .. list-table::
      :header-rows: 1
      :widths: 42 58

      * - Log
        - Cause and what to do
      * - ``invalid func unknown#195896080``
        - A CO-RE relocation found no matching type or field in the
          target's BTF, and the kernel replaced the instruction. Build
          against the target kernel's ``vmlinux.h``, or test for the field
          with ``bpf_core_field_exists()`` and skip the access.
      * - ``<function>() is not modifiable``
        - ``fmod_ret`` on a function the kernel does not admit. Attach
          elsewhere. :doc:`/upatches/write/attach-kinds` lists the rules.
      * - ``<function> is not sleepable``
        - A ``.s`` section on a function or hook that cannot sleep. Use
          the section without ``.s``.
      * - ``LSM programs must have a GPL compatible license``, ``cannot
          call GPL-restricted function from non-GPL compatible program``
        - Declare ``char _license[] SEC("license") = "Dual BSD/GPL";``.
      * - no log, ``errno_name`` ``ENOENT``, ``loader_return`` -2
        - The loader did not find the ``fentry``, ``fexit``,
          ``fmod_ret``, ``lsm`` or ``tp_btf`` target in the kernel's BTF.
          The function does not exist on this kernel, has another name, or
          is inlined. Choose another attach point, or limit the upatch to
          kernels that have it.
      * - any other verifier message
        - The verifier's own diagnosis of the program. Fix the source.
          The kernel's BPF documentation explains the messages.

Fix and load again
------------------

6. Change the source or the build, rebuild and sign, and load the new
   file. A rebuilt upatch has a new payload digest, so build its unload
   directive again too.

7. Confirm the result with the report's category ``ok`` and with:

   .. code-block:: console

      target# shirudo upatch get <name>

   ``<name>`` is the upatch name. Use shirudo's own commands to look at a
   loaded upatch: the LSM refuses every other tool a descriptor of
   shirudo's maps and links, by pin or by id, and counts each attempt as
   ``ObjGet``.

Next steps
----------

- :doc:`/reference/cli/upatch-load` for the report's fields
- :doc:`/concepts/background/co-re-btf` for how relocations resolve
- :doc:`/upatches/test/testing` for the test VM
