..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

Failure categories and exit status
==================================

``shirudo upatch load`` and ``shirudo upatch unload`` classify every
refusal by a phase and a category. Both appear in the operation report
(``--report``) and in the ``upatch unload failed:`` journal line. Other
commands report failures as messages and exit status only.

Phases
------

The table lists the phases in the order a load reaches them. The
``--expect-version-id`` check of ``pre_flight`` runs before ``parse``.
An unload passes ``pre_flight`` and ``parse``, verifies the directive's
signature in ``signed_loader_load``, compares the payload in ``pin``,
measures in ``tpm_extend`` and removes the pins in ``pin``.

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Phase
     - What runs
   * - ``pre_flight``
     - The ``--expect-version-id`` check, the signed-loader ABI check, the
       comparison of the ``.bpf`` keyring with the frozen record, the
       ``lsm_link`` pin, the ``--expect-chain`` comparison and the
       ``eventlog.max_bytes`` check. ``--no-precheck`` skips the ABI,
       ``lsm_link`` and ``--expect-chain`` checks, not the keyring
       comparison.
   * - ``parse``
     - Reading and staging the artifact, the header checks, the upatch
       name, the signed name, ``payload_sha256`` against the loader and
       data, and the signed attach metadata.
   * - ``target_verify``
     - Opening each ``uprobe.multi`` target binary and comparing its GNU
       build ID with the one the artifact records, and comparing the
       payload of each upatch whose program a program attaches to.
   * - ``signed_loader_load``
     - Creating, filling and freezing ``__loader.map`` and the
       ``BPF_PROG_LOAD`` of the signed loader, where the kernel verifies
       the signature against the ``.bpf`` keyring.
   * - ``payload_load``
     - ``BPF_PROG_TEST_RUN`` of the loader, which loads the payload
       programs and maps through the verifier.
   * - ``link_create``
     - Attaching each program, checking the link against the attach
       metadata and pinning it in the private bpffs.
   * - ``pin``
     - Unload only: comparing the payload recorded on the pin directory
       with the directive's, and removing the pins.
   * - ``persist``
     - Load only: copying the artifact to
       ``/var/lib/shirudo/upatches/<name>.upatch``.
   * - ``tpm_extend``
     - Extending the measurement register and appending the eventlog
       record.
   * - ``done``
     - The operation completed.

Categories
----------

.. list-table::
   :header-rows: 1
   :widths: 18 16 12 27 27

   * - Category
     - Phases
     - errno
     - Meaning
     - Action
   * - ``version_mismatch``
     - ``pre_flight``
     - ``EPERM``
     - ``--expect-version-id`` differs from the target's
       ``SHIRUDO_VERSION_ID``.
     - Compare ``shirudo version --version-id`` on both hosts and
       deploy matching builds. See :doc:`/operate/maintain/upgrade`.
   * - ``kernel_abi_unsupported``
     - ``pre_flight``, ``link_create``
     - ``EOPNOTSUPP``
     - In ``pre_flight``, the kernel lacks the signed-loader ABI; the
       message names the missing part. In ``link_create``, the kernel
       does not support the attach type.
     - Run a kernel that meets :doc:`/operate/plan/system-requirements`.
   * - ``keyring_missing``
     - ``pre_flight``, ``signed_loader_load``
     - errno of the read, ``ENOKEY``
     - In ``pre_flight``, no trust anchor was frozen this boot (``ENOENT``
       when ``init`` has not run). In ``signed_loader_load``, the
       signer's certificate is not in the ``.bpf`` keyring.
     - Check ``shirudo status`` and the journal of ``init``. Compare the
       signer with ``shirudo keys``; enroll a signer through the signed
       config, see :doc:`/operate/maintain/keys`.
   * - ``tampered``
     - ``pre_flight``, ``tpm_extend``
     - none, ``EPERM``, ``EACCES``
     - The ``.bpf`` keyring is not the frozen anchor (no errno), the
       ``lsm_link`` pin cannot be opened, the register differs from
       ``--expect-chain`` or cannot be read (``EPERM``), or the register
       is not the one ``init`` bound (``EACCES``, the load is undone).
     - Do not retry. Keep the eventlog and the journal and handle the
       target as an incident: :doc:`/operate/troubleshoot/incident-tampered`.
   * - ``eventlog_full``
     - ``pre_flight``
     - ``ENOSPC``
     - The eventlog would exceed ``eventlog.max_bytes``. Nothing was
       loaded or measured.
     - Raise ``eventlog.max_bytes`` in the signed config, see
       :doc:`/reference/formats/configuration`. The eventlog is sealed
       and cannot be rotated.
   * - ``parser_rejected``
     - ``parse``, ``target_verify``
     - errno of the read, or none; ``ERANGE``, ``EINVAL``, ``E2BIG``
     - The artifact cannot be read or is malformed: wrong kind (a
       directive given to ``load`` or the reverse), misaligned loader,
       unsafe or unsigned name, ``payload_sha256`` mismatch, unsigned or
       invalid attach metadata. In ``target_verify``, a uprobe offset
       lies beyond the target file.
     - Rebuild the artifact with ``shirudo build`` and check it with
       ``shirudo upatch info``.
   * - ``attach_target_missing``
     - ``target_verify``, ``link_create``
     - ``ENOENT``, ``ENOTDIR``
     - The uprobe binary, the kprobe symbol or its module is absent, or
       the upatch whose program a program attaches to is not loaded.
       ``upatch load`` exits 2. ``bpm tree sync`` records the operation as
       ``skipped: module not loaded`` and continues.
     - Load the module or install the binary, then load again.
   * - ``binary_mismatch``
     - ``target_verify``, ``link_create``
     - ``ESTALE``
     - The uprobe target is not a regular file, was replaced while it
       was opened, or its build ID differs from the recorded one.
     - Rebuild the upatch against the installed binary.
   * - ``signature_rejected``
     - ``signed_loader_load``
     - ``EKEYREJECTED``
     - The kernel rejected the loader's signature.
     - Fetch or rebuild the artifact. Check that the file was not
       modified after signing.
   * - ``signature_unsupported``
     - ``signed_loader_load``
     - ``ENOPKG``
     - The kernel cannot verify ML-DSA signatures.
     - Build the kernel with ``CONFIG_CRYPTO_MLDSA``, see
       :doc:`/operate/plan/system-requirements`.
   * - ``lsm_denied``
     - ``target_verify``, ``signed_loader_load``, ``link_create``
     - ``EACCES``, ``EPERM``
     - The kernel refused an operation with ``EACCES`` or ``EPERM``,
       normally an LSM, shirudo's own or another one.
     - Check the tamper counters in ``shirudo status`` and the other
       LSMs' audit records.
   * - ``verifier_rejected``
     - ``signed_loader_load``, ``payload_load``
     - errno of the call, or the loader's return value
     - The verifier rejected the loader, ``BPF_PROG_TEST_RUN`` failed, or
       the loader returned an error for a payload program, often a CO-RE
       relocation against this kernel's BTF. ``verifier_log`` holds the
       kernel's log.
     - Read ``verifier_log`` and rebuild against the target kernel. See
       :doc:`/upatches/test/debugging`.
   * - ``attach_scope_mismatch``
     - ``link_create``
     - ``EXDEV``
     - The link the kernel reports is not at the site the attach
       metadata names: a cgroup link not at the root cgroup, a netfilter
       link outside the initial network namespace or at another hook or
       priority, a kprobe at another function or offset.
     - Run the load in the host's initial cgroup and network namespaces
       and with the host's sysfs.
   * - ``already_loaded``
     - ``pin``
     - ``EEXIST``
     - A upatch of that name is loaded, with the payload a completed load
       records. Nothing was touched.
     - Unload it with its signed directive first.
   * - ``payload_mismatch``
     - ``pin``, ``target_verify``
     - ``EPERM``, ``EBADMSG``, errno of the read
     - The upatch loaded under the name carries another payload than the
       directive expects, or the recorded payload cannot be read.
       Nothing was detached. In ``target_verify``, the upatch whose
       program a program attaches to is another build than the one the
       artifact was built against; nothing was loaded.
     - Compare the ``Payload`` of ``shirudo upatch get <name>`` with the
       directive and build a directive for the loaded payload.
   * - ``detach_failed``
     - ``pin``
     - errno of the removal
     - The unload was measured, then removing the pins failed.
     - Repeat the unload. Each attempt records another unload event.
   * - ``tpm_error``
     - ``tpm_extend``
     - errno of the call
     - The register lock, the TPM or the extend failed. A load is undone
       when the register did not move. When the extend succeeded and the
       eventlog append failed, the message reads ``eventlog append failed
       after the extend``.
     - Check ``shirudo status``. A register ahead of the eventlog shows as
       ``tampered``; handle that as an incident.
   * - ``unknown``
     - ``parse``, ``target_verify``, ``signed_loader_load``,
       ``payload_load``, ``link_create``, ``persist``
     - errno of the call
     - Any other failure: out of memory, a failed hash of the loader, an
       unclassified attach error, or a failed archive copy (the load is
       undone).
     - Read ``message`` and the journal. For ``persist``, check the space
       on the file system that holds ``/var/lib/shirudo``.

A successful operation reports the category ``ok``. An unload of a
upatch that has no pins reports ``already_unloaded``, exits 0 and
records no event.

Refusals before a command runs
------------------------------

On an enforcing target every command except ``init``, ``genkey``,
``build``, ``help``, ``version``, ``image build`` and ``image verify``
passes a gate first. A refusal prints ``shirudo: image state:
<strerror>`` and exits 1.

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Message
     - Cause
   * - ``shirudo: image state: Operation not permitted``
     - An argument starts with ``--keys-dir``, ``--cert`` or ``--tcti``,
       or a forbidden environment variable is set (see
       :doc:`/reference/environment`).
   * - ``shirudo: image state: Permission denied``
     - The binary is not the runtime binary, so the LSM refuses it access
       to the frozen record.
   * - ``shirudo: image state: Operation now in progress``
     - A config activation is pending. Only ``status`` and ``image`` run
       until the next boot.
   * - ``shirudo: image state: Structure needs cleaning``,
       ``Stale file handle`` or ``Key was rejected by service``
     - The config activation record or the mounted config cannot be
       verified. Only ``status`` and ``image`` run.
   * - ``shirudo: image state: Protocol error``
     - A frozen record exists but enforcement is not active.

Exit status
-----------

Monitoring must not rely on exit status: ``shirudo status`` exits 0 for
every verdict, ``tampered`` included. Parse ``.status`` of
``shirudo status --json`` instead, see :doc:`/reference/formats/status-json`.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Command
     - Exit status
   * - ``shirudo`` without a command
     - 1, after the help text.
   * - ``shirudo help``, ``--help``, ``--list-cmds``
     - 0.
   * - Unknown or ambiguous command
     - 1.
   * - Any command
     - 1 when ``mlockall()`` fails (``hardening: cannot lock process
       memory``) or the gate refuses.
   * - ``genkey``
     - 0; 1 on failure or when keys exist without ``--force``; 2 for an
       unknown option.
   * - ``build``, ``keys vouch``, ``image build``, ``image verify``
     - The exit status of ``shirudo-build``: 0; 1 on failure; 2 for a
       usage error. 127 when the helper is missing, not executable or
       ``SHIRUDO_BUILD`` is empty.
   * - ``init``
     - 0; 1 on any failure, the pre-flight included; 2 for an unknown
       option. ``--check-only`` exits 0 when every check passes, else 1.
   * - ``status``
     - 0 for every verdict; 1 when memory runs out, the configuration
       cannot be loaded for ``--otel`` or the OTLP send fails; 2 for a
       usage error or an invalid ``map_export`` configuration with
       ``--otel``.
   * - ``upatch`` without a subcommand
     - 2.
   * - ``upatch load``
     - 0; 1 on refusal or failure; 2 for a usage error and for
       ``attach_target_missing``.
   * - ``upatch unload``
     - 0, ``already_unloaded`` included; 1 on refusal or failure; 2 for a
       usage error.
   * - ``upatch list``, ``upatch info``
     - 0; 1 on failure; 2 for a usage error.
   * - ``upatch get``
     - 0; 1 when the upatch is not found or cannot be read; 2 for a usage
       error or an invalid name.
   * - ``upatch map``
     - 0; 1 on a read or export failure; 2 for a usage error or an invalid
       ``map_export`` configuration.
   * - ``bpm`` without a subcommand
     - 2.
   * - ``bpm install``, ``uninstall``, ``upgrade``, ``list``, ``pull``,
       ``info``, ``key``, ``repo update``, ``config register``
     - 0, an already installed package included; 1 on failure; 2 for a
       usage error.
   * - ``bpm tree sync``
     - 0, also when no tree is configured; 1 on failure and for an
       unknown option.
   * - ``bpm build``, ``bpm config update``, ``bpm tree append``
     - 0; 1 on failure and for a usage error; 127 when the helper is
       missing.
   * - ``bpm push``
     - 0; 1 on failure; 2 for a usage error; 127 when the helper is
       missing.
   * - ``image`` without a subcommand
     - 2.
   * - ``image update``
     - 0; 1 on failure.
   * - ``image status``
     - 0 when the activation is consistent and not pending; 1 when it is
       pending or inconsistent (after the JSON) or no record exists.
   * - ``attest``
     - 0; 1 when no TPM answers, the register is not bound, the challenge
       is refused or the output cannot be written; 2 for a usage error or
       an unreadable challenge.
   * - ``attest verify``
     - 0 for ``verdict: ok``; 1 for ``verdict: FAIL``; 2 for a usage
       error, an unreadable evidence file or a file that is not an
       evidence document.
   * - ``attest predict``
     - 0; 1 when the write policy cannot be computed; 2 for a usage error
       or invalid input.
   * - ``attest challenge``
     - 0; 1 for ``verdict: FAIL`` or a write error; 2 for a usage error,
       an unreadable evidence file or evidence without an endorsement key.
   * - ``keys``
     - 0; 1 when no key material or no ``.bpf`` keyring is found; 2 for a
       usage error.
   * - ``keys add``
     - 0; 1 on failure, and always on a target with a config image; 2 for
       a usage error.
   * - ``keys revoke``
     - 1.
   * - ``config``
     - 0; 1 when the configuration cannot be loaded or ``map_export`` or
       ``tls.classical_hosts`` is invalid; 2 for an unknown option.
   * - ``version``
     - 0.

Operation report
----------------

``--report=<path>`` writes one JSON object after the operation, also
after a refusal. ``--report=-`` writes it to standard output. A usage
error writes no report. shirudo creates the file with mode ``0644`` and
refuses a sealed file, a path under a sealed directory and a symbolic
link.

.. list-table::
   :header-rows: 1
   :widths: 25 15 60

   * - Field
     - Type
     - Value
   * - ``schema``
     - integer
     - ``1``.
   * - ``result``
     - string
     - ``ok`` or ``failed``.
   * - ``op``
     - string
     - ``upatch_load`` or ``upatch_unload``.
   * - ``phase``
     - string
     - The phase that failed, or ``done``.
   * - ``errno``
     - integer or null
     - The positive errno, null when there is none.
   * - ``errno_name``
     - string or null
     - The errno's symbolic name, such as ``ENOKEY``.
   * - ``category``
     - string
     - One of the categories above, ``ok`` or ``already_unloaded``.
   * - ``message``
     - string
     - A short description, at most 255 bytes. Empty on success.
   * - ``verifier_log``
     - string
     - The kernel's log from ``signed_loader_load`` or ``payload_load``,
       up to 16 MiB. Empty otherwise.
   * - ``loader_return``
     - integer
     - The loader's return value from ``BPF_PROG_TEST_RUN``, 0 when it did
       not run.
   * - ``upatch.path``
     - string
     - The path given on the command line.
   * - ``upatch.name``
     - string
     - The upatch name from the header. Empty when the operation stopped
       before the artifact was read.
   * - ``upatch.payload_sha256``
     - string
     - For a load, the artifact's payload digest. For an unload, the
       payload the directive expects. Empty when the operation stopped
       before the artifact was read.
   * - ``kernel.release``
     - string
     - The running kernel's release, from ``uname``.
   * - ``tpm``
     - object or null
     - Present on success when the register moved, else null.
   * - ``tpm.nv_index``
     - string
     - The register's NV index, ``0x01818E00``.
   * - ``tpm.chain_after``
     - string
     - The register value after the extend, 64 hex characters.

A successful load:

.. code-block:: json

   {"schema":1,"result":"ok","op":"upatch_load","phase":"done",
    "errno":null,"errno_name":null,"category":"ok","message":"",
    "verifier_log":"","loader_return":0,
    "upatch":{"path":"/mnt/shirudo-bundle/fixtures/shirudo-test-basic.upatch",
              "name":"shirudo-test-basic",
              "payload_sha256":"8aee7072a1a15e4dddc93ad6b253a0e2e70ad6cdf767442aa8a1c1997bc3069f"},
    "kernel":{"release":"7.3.0-bpf-next+"},
    "tpm":{"nv_index":"0x01818E00",
           "chain_after":"c50b22ac27c5bb6a90ee5ff9b440fbbd5bb60b84a2aa7b395daec3f330886fcd"}}

A load refused because the register differs from ``--expect-chain``. The
journal line names the cause, ``chain_drift``:

.. code-block:: json

   {"schema":1,"result":"failed","op":"upatch_load","phase":"pre_flight",
    "errno":1,"errno_name":"EPERM","category":"tampered",
    "message":"pre-flight check failed","verifier_log":"","loader_return":0,
    "upatch":{"path":"/mnt/shirudo-bundle/fixtures/shirudo-test-lifecycle.upatch",
              "name":"shirudo-test-lifecycle",
              "payload_sha256":"2324dff6596d09695c57b45a234627a9e3efbd60c9a2818c5914e6c9e52f17b0"},
    "kernel":{"release":"7.3.0-bpf-next+"},"tpm":null}

A load refused by ``--expect-version-id``, before the artifact was read:

.. code-block:: json

   {"schema":1,"result":"failed","op":"upatch_load","phase":"pre_flight",
    "errno":1,"errno_name":"EPERM","category":"version_mismatch",
    "message":"SHIRUDO_VERSION_ID mismatch (operator vs target)",
    "verifier_log":"","loader_return":0,
    "upatch":{"path":"/mnt/shirudo-bundle/fixtures/shirudo-test-lifecycle.upatch",
              "name":"","payload_sha256":""},
    "kernel":{"release":"7.3.0-bpf-next+"},"tpm":null}

A load of an artifact signed by a key the target does not trust:

.. code-block:: json

   {"schema":1,"result":"failed","op":"upatch_load",
    "phase":"signed_loader_load","errno":126,"errno_name":"ENOKEY",
    "category":"keyring_missing",
    "message":"BPF_PROG_LOAD of signed loader failed",
    "verifier_log":"signature verification failed: -126\n","loader_return":0,
    "upatch":{"path":"/mnt/shirudo-bundle/fixtures/shirudo-test-foreign.upatch",
              "name":"shirudo-test-foreign",
              "payload_sha256":"d3e0d0a546f9aacc9e5828d479793dc4e848c4e835c8ac2bd55b2584374bc913"},
    "kernel":{"release":"7.3.0-bpf-next+"},"tpm":null}

An unload directive that expects another payload than the loaded one:

.. code-block:: json

   {"schema":1,"result":"failed","op":"upatch_unload","phase":"pin",
    "errno":1,"errno_name":"EPERM","category":"payload_mismatch",
    "message":"loaded payload does not match directive","verifier_log":"",
    "loader_return":0,
    "upatch":{"path":"/mnt/shirudo-bundle/fixtures/shirudo-test-basic-mismatch.unload.upatch",
              "name":"shirudo-test-basic",
              "payload_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    "kernel":{"release":"7.3.0-bpf-next+"},"tpm":null}

shirudo prints each report on one line. The examples are wrapped.

Tree sync report
----------------

``shirudo bpm tree sync`` writes its own report to standard output, or
to ``--report=<path>`` with mode ``0600``.

.. list-table::
   :header-rows: 1
   :widths: 25 15 60

   * - Field
     - Type
     - Value
   * - ``schema``
     - integer
     - ``1``.
   * - ``dry_run``
     - boolean
     - Whether ``--dry-run`` was given.
   * - ``selected``
     - integer
     - Operations whose selector matches this target.
   * - ``skipped``
     - integer
     - Operations whose selector does not match.
   * - ``applied``
     - integer
     - Operations applied and measured in this run.
   * - ``module_skipped``
     - integer
     - ``add`` operations measured but not loaded because of
       ``attach_target_missing``.
   * - ``tpm_available``
     - boolean
     - Whether the register is bound this boot.
   * - ``last_seq``
     - integer
     - The last operation sequence number this target has processed.
   * - ``projection_root_tpm``
     - string or null
     - The tree's projection root, null without a bound register.

A failed sync logs ``bpm tree sync: phase=<phase> seq=<seq> id=<id>
rc=<rc> (<strerror>)`` and exits 1:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Phase
     - Failure
   * - ``operation_validate``
     - An operation of the publication is malformed or its digest does
       not match.
   * - ``pending_recovery``
     - An interrupted operation cannot be reconciled with the tree
       eventlog.
   * - ``selector_evaluate``
     - The selector cannot be evaluated: the node labels or the kernel
       config cannot be read. The cursor stays on the operation.
   * - ``operation_digest_parse``
     - The operation digest is malformed.
   * - ``expected_payload_digest``
     - The artifact's payload differs from the expected payload.
   * - ``pending_write``
     - ``pending.json`` cannot be written.
   * - ``artifact_fetch_or_verify``
     - The artifact cannot be fetched or does not match its digests.
   * - ``upatch_install``
     - The load or unload failed. ``rc`` is the exit status of
       ``upatch load`` or ``upatch unload``.
   * - ``projection_root_decode``
     - The recorded projection root is malformed.
   * - ``register_extend``
     - The register extend failed.
   * - ``tree_event_append``
     - The tree eventlog record cannot be appended.
   * - ``tree_state_commit``, ``tree_state_commit_final``
     - ``state.json`` cannot be written.
   * - ``tree_status_write``
     - The per-operation status file cannot be written.

Related
-------

- :doc:`/reference/cli/upatch-load` and :doc:`/reference/cli/upatch-unload`
- :doc:`/operate/troubleshoot/troubleshooting`
- :doc:`/operate/troubleshoot/incident-tampered`
- :doc:`/security/tamper-counters`
