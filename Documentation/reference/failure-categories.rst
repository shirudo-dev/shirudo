..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

Failure categories and exit status
==================================

``shirudo upatch load``, ``unload`` and ``reconcile`` classify every
refusal by a phase and a category. Both appear in the operation report
(``--report``) and in the ``upatch unload failed:`` journal line. Other
commands report failures as messages and exit status only.

Phases
------

The table lists the phases in the order a load first reaches them. A
load runs the ``--expect-version-id`` check of ``pre_flight``, reads the
artifact and checks its header in ``parse``, runs the other
``pre_flight`` checks, refuses a name that is loaded in ``pin``, checks
the rest of the artifact in ``parse``, and then goes from
``target_verify`` to ``done``. An unload passes ``parse`` and
``pre_flight``, verifies the directive's signature in
``signed_loader_load``, compares the payload in ``pin``, measures in
``tpm_extend`` and removes the pins in ``pin``.

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
   * - ``pin``
     - Load: refusing a name that is loaded. Unload: comparing the
       payload recorded on the pin directory, or the archive of a Java
       upatch, with the directive's, and removing the pins or the jar.
   * - ``target_verify``
     - Opening each ``uprobe``, ``uretprobe``, ``uprobe.multi`` and
       ``uretprobe.multi`` target binary and comparing its GNU build ID
       with the one the artifact records.
   * - ``signed_loader_load``
     - Creating, filling and freezing ``__loader.map`` and the
       ``BPF_PROG_LOAD`` of the signed loader, where the kernel verifies
       the signature against the ``.bpf`` keyring.
   * - ``java_verify``
     - A Java upatch only, in place of ``signed_loader_load``: its signed
       name, type and payload digest, and its signature over the signed
       data against the certificates of the runtime that the ``.bpf``
       keyring holds.
   * - ``java_install``
     - A Java load only, in place of ``payload_load`` and
       ``link_create``: writing the jar to
       ``/run/shirudo-java/<name>.jar``.
   * - ``payload_load``
     - ``BPF_PROG_TEST_RUN`` of the loader, which loads the payload
       programs and maps through the verifier.
   * - ``link_create``
     - Attaching each program, checking the link against the attach
       metadata, pinning it in the private bpffs and recording the payload
       on the pin directory.
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
   :widths: 18 16 38 28

   * - Category
     - Phases
     - Meaning and errno
     - Action
   * - ``version_mismatch``
     - ``pre_flight``
     - ``EPERM``. ``--expect-version-id`` differs from the target's
       ``SHIRUDO_VERSION_ID``.
     - Compare ``shirudo version --version-id`` on both hosts and
       deploy matching builds. See :doc:`/operate/maintain/upgrade`.
   * - ``kernel_abi_unsupported``
     - ``pre_flight``, ``link_create``
     - ``EOPNOTSUPP``. In ``pre_flight``, the kernel lacks the
       signed-loader ABI; the message names the missing part. In
       ``link_create``, the kernel does not support the attach type.
     - Run a kernel that meets :doc:`/operate/plan/system-requirements`.
   * - ``keyring_missing``
     - ``pre_flight``, ``signed_loader_load``
     - - In ``pre_flight``, no trust anchor was frozen this boot: the
         errno of the read, ``ENOENT`` when ``init`` has not run.
       - In ``signed_loader_load``, the signer's certificate is not in
         the ``.bpf`` keyring: ``ENOKEY``.
     - Check ``shirudo status`` and the journal of ``init``. Compare the
       signer with ``shirudo keys``; enroll a signer through the signed
       config, see :doc:`/operate/maintain/keys`.
   * - ``tampered``
     - ``pre_flight``, ``tpm_extend``
     - - The ``.bpf`` keyring is not the frozen anchor: no errno.
       - The ``lsm_link`` pin is missing: ``ENOENT``.
       - The register differs from ``--expect-chain`` or cannot be
         read: ``EPERM``.
       - The register is not the one ``init`` bound: ``EACCES``. The
         load is undone.
       - This boot's eventlog records do not fold to the register:
         ``EBADMSG``. Nothing changed.
       - From ``upatch reconcile``, the archive of a loaded XDP upatch
         differs from what the records say was loaded: no errno.
       - From ``upatch reconcile``, the XDP program pin is missing
         (``ENOENT``) or holds no XDP program (``ESTALE``).
     - Do not retry. Keep the eventlog and the journal and handle the
       target as an incident: :doc:`/operate/troubleshoot/incident-tampered`.
   * - ``not_initialized``
     - ``pre_flight``
     - No errno. ``upatch reconcile`` ran outside the initial network
       namespace, or before ``init`` finished on the root file system.
     - Wait for ``shirudo.service``; the timer runs the pass again.
   * - ``eventlog_full``
     - ``pre_flight``
     - ``ENOSPC``. The eventlog would exceed ``eventlog.max_bytes``.
       Nothing was loaded or measured.
     - Raise ``eventlog.max_bytes`` in the signed config, see
       :doc:`/reference/configuration`. The eventlog is sealed
       and cannot be rotated.
   * - ``parser_rejected``
     - ``parse``, ``target_verify``, ``java_verify``
     - - The artifact cannot be read or is malformed: the errno of the
         read.
       - Wrong kind (a directive given to ``load`` or the reverse),
         unsafe or unsigned name, ``payload_sha256`` mismatch, or
         unsigned attach metadata: no errno.
       - Invalid attach metadata: the errno of its check.
       - In ``target_verify``, a uprobe offset beyond the target file or
         another target the checks refuse: ``ERANGE``, ``EINVAL`` or
         ``E2BIG``.
     - Rebuild the artifact with ``shirudo build`` and check it with
       ``shirudo upatch info``.
   * - ``attach_target_missing``
     - ``target_verify``, ``link_create``
     - ``ENOENT`` or ``ENOTDIR``. The uprobe binary, the kprobe symbol or
       its module is absent. ``upatch load`` exits 2. ``bpm tree sync``
       records the operation as ``skipped: module not loaded`` and
       continues.
     - Load the module or install the binary, then load again.
   * - ``xdp_multibuf_unsupported``
     - ``link_create``
     - ``EMEDIUMTYPE``. A selected device has native XDP but does not
       report multi-buffer support (``NETDEV_XDP_ACT_RX_SG``). The load was
       undone.
     - Narrow the signed device-class mask, or configure or change the
       device so that it reports multi-buffer XDP. See
       :doc:`/upatches/write/attach-kinds`.
   * - ``xdp_driver_refused``
     - ``link_create``
     - ``ENOPROTOOPT``. The driver of a selected device refused the program
       in its current settings: ``EOPNOTSUPP`` while it reports native XDP,
       from ``virtio_net`` while the host does GRO_HW or checksum offload
       or from ``bnxt`` with header-data split or with rx and tx channels
       not combined; ``EINVAL`` from ``mlx5`` with LRO or hardware GRO on;
       ``ENOSPC`` from a veth with fewer rx queues than its peer has tx
       queues; ``ERANGE`` for an MTU the driver cannot take. The journal
       names the driver's errno. The load was undone.
     - Change the setting that rules XDP out, which ``bnxt`` names in the
       kernel log, or narrow the signed device-class mask. See
       :doc:`/upatches/write/attach-kinds`.
   * - ``xdp_device_occupied``
     - ``link_create``
     - ``EBUSY``. A selected device already runs another XDP program, in
       any mode: another upatch's, or one shirudo did not attach, generic
       and offloaded programs included. The kernel holds one XDP program
       per device. The load was undone.
     - Unload the upatch that holds the device, detach the other
       program, or narrow the signed device-class mask. See
       :doc:`/upatches/write/attach-kinds`.
   * - ``binary_mismatch``
     - ``target_verify``, ``link_create``
     - ``ESTALE``. The uprobe target is not a regular file, was replaced
       while it was opened, or its build ID differs from the recorded one.
     - Rebuild the upatch against the installed binary.
   * - ``signature_rejected``
     - ``signed_loader_load``, ``java_verify``
     - ``EKEYREJECTED``. The kernel rejected the loader's signature, or
       no enrolled certificate verifies a Java upatch's signature.
     - Fetch or rebuild the artifact. Check that the file was not
       modified after signing.
   * - ``signature_unsupported``
     - ``signed_loader_load``
     - ``ENOPKG``. The kernel cannot verify ML-DSA signatures.
     - Build the kernel with ``CONFIG_CRYPTO_MLDSA``, see
       :doc:`/operate/plan/system-requirements`.
   * - ``lsm_denied``
     - ``pre_flight``, ``target_verify``, ``signed_loader_load``,
       ``link_create``
     - ``EACCES`` or ``EPERM``. The kernel refused an operation with
       ``EACCES`` or ``EPERM``, normally an LSM, shirudo's own or another
       one. In ``pre_flight`` it refused to open the ``lsm_link`` pin or,
       from ``upatch reconcile``, an XDP program pin.
     - Check the tamper counters in ``shirudo status`` and the other
       LSMs' audit records.
   * - ``verifier_rejected``
     - ``signed_loader_load``, ``payload_load``
     - The errno of the call, or the loader's return value. The verifier
       rejected the loader, ``BPF_PROG_TEST_RUN`` failed, or the loader
       returned an error for a payload program, often a CO-RE relocation
       against this kernel's BTF. ``verifier_log`` holds the kernel's log.
     - Read ``verifier_log`` and rebuild against the target kernel. See
       :doc:`/upatches/test/debugging`.
   * - ``attach_scope_mismatch``
     - ``link_create``
     - - The link the kernel reports is not at the site the attach
         metadata names: a cgroup link not at the root cgroup, a
         netfilter link outside the initial network namespace or at
         another hook or priority, a kprobe at another function or
         offset: ``EXDEV``.
       - For XDP, a load outside the initial network namespace, where a
         device's name no longer gives its index: ``EXDEV``.
       - For XDP, a link the kernel made for another device:
         ``EREMOTE``.

       An XDP mismatch also fails boot restore, and stops an
       ``upatch reconcile`` pass.
     - Run the load in the host's initial cgroup and network namespaces
       and with the host's sysfs.
   * - ``already_loaded``
     - ``pin``
     - ``EEXIST``. A upatch of that name is loaded, with the payload a
       completed load records. Nothing was touched. A ``bpm`` install or a
       tree sync of an artifact with that very payload counts it as
       installed instead.
     - Unload it with its signed directive first.
   * - ``payload_mismatch``
     - ``pin``
     - - The upatch loaded under the name carries another payload than
         the directive expects: ``EPERM``.
       - The payload recorded on its pins cannot be read: the errno of
         the read.
       - With no pins, the archive of the name holds another payload
         (``EPERM``) or cannot be read (the errno of the read).

       Nothing was detached or removed.
     - Compare the ``Payload`` of ``shirudo upatch get <name>`` with the
       directive and build a directive for the loaded payload.
   * - ``detach_failed``
     - ``pin``
     - The errno of the removal. The unload was measured, then removing the
       pins failed.
     - Repeat the unload. Each attempt records another unload event.
   * - ``tpm_error``
     - ``tpm_extend``; ``pre_flight`` from ``upatch reconcile``
     - The errno of the call. The register lock could not be taken, or this
       boot's records could not be read or what they do not cover could not
       be undone, in which case nothing was loaded or detached, or the TPM
       or the extend failed. A failed extend undoes a load and detaches
       nothing for an unload, though a lost answer can leave the register
       moved, and the message then reads ``the TPM may have taken the event
       without its record``. When the extend succeeded and the eventlog
       append failed, the message reads ``eventlog append failed after the
       extend`` and the load stays.
     - Check ``shirudo status``. A register ahead of the eventlog shows as
       ``tampered``; handle that as an incident.
   * - ``unknown``
     - ``pre_flight``, ``parse``, ``target_verify``,
       ``signed_loader_load``, ``java_verify``, ``java_install``,
       ``payload_load``, ``link_create``, ``persist``, ``pin``
     - The errno of the call. Any other failure: out of memory, a failed
       hash of the loader, an unclassified attach error, a payload that
       cannot be recorded on the pin directory or a failed archive copy
       (the load is undone for both). In ``pin``, from ``upatch unload``,
       a pin directory that cannot be looked at for a reason other than
       its absence: nothing is detached. In ``pre_flight``, settings that
       cannot be read, which leave ``eventlog.max_bytes`` unknown, or the
       ``lsm_link`` pin or, from ``upatch reconcile``, an XDP program pin
       that cannot be opened for a reason that says nothing about the pin,
       such as ``EMFILE`` or ``ENOMEM``, or the pin directory of a upatch
       that cannot be read for a reason other than its absence: the pass
       stops before it attaches anything.
     - Read ``message`` and the journal. For ``persist``, check the space
       on the file system that holds ``/var/lib/shirudo``.

A successful operation reports the category ``ok``. An unload of a
upatch that has no pins reports ``already_unloaded``, exits 0 and
records no event, after removing an archive of the directive's payload.

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
     - 1 when the hardening fails (``hardening: cannot reset the
       personality``, ``cannot reset the resource limits``, ``cannot
       disarm the interval timers``, ``cannot lock process memory``) or
       when the gate refuses.
   * - ``genkey``
     - 0; 1 on failure or when keys exist without ``--force``; 2 for an
       unknown option.
   * - ``build``, ``keys vouch``, ``image build``, ``image verify``
     - The exit status of ``shirudo-build``: 0; 1 on failure; 2 for a
       usage error. 127 when the helper is missing, not executable or
       ``SHIRUDO_BUILD`` is empty.
   * - ``init``
     - 0; 1 on any failure, the pre-flight included; 2 for an unknown
       option or for ``--json`` without ``--check-only``.
       ``--check-only`` exits 0 when every check passes, else 1.
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
   * - ``upatch reconcile``
     - 0 when the pass finishes, whatever each device's outcome; 1 when it
       stops; 2 for a usage error.
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
       unknown option; 2 for too many arguments or a ``--report`` path
       that is too long.
   * - ``bpm build``, ``bpm config update``, ``bpm tree append``,
       ``bpm tree show``
     - 0; 1 on failure and for a usage error; 127 when the helper is
       missing.
   * - ``bpm push``
     - 0; 1 on failure; 2 for a usage error; 127 when the helper is
       missing.
   * - ``image`` without a subcommand
     - 2.
   * - ``image update``, ``image stage``
     - 0; 1 on failure; 2 for a usage error. Ctrl-C during an HTTPS
       transfer ends the command by SIGINT once it removed the staged
       downloads.
   * - ``image status``
     - 0 when the activation is consistent and not pending; 1 when it is
       pending or inconsistent (after the JSON) or no record exists.
   * - ``attest``
     - 0; 1 when no TPM answers, the register is not bound, the challenge
       is refused or the output cannot be written; 2 for a usage error or
       an unreadable challenge.
   * - ``attest verify``
     - 0 for ``verdict: ok``; 1 for ``verdict: fail``; 2 for a usage
       error, an unreadable evidence file or a file that is not an
       evidence document.
   * - ``attest predict``
     - 0; 1 when the write policy cannot be computed; 2 for a usage error
       or invalid input.
   * - ``attest challenge``
     - 0; 1 for ``verdict: fail`` or a write error; 2 for a usage error,
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
       up to 16 MiB, with U+FFFD for each byte that is no UTF-8, as a
       source line or a file name the log quotes can hold. Empty
       otherwise.
   * - ``loader_return``
     - integer
     - The loader's return value from ``BPF_PROG_TEST_RUN``, 0 when it did
       not run.
   * - ``upatch.path``
     - string
     - The path given on the command line, with U+FFFD for each byte
       that is no UTF-8.
   * - ``upatch.name``
     - string
     - The upatch name from the header, as the file has it and with
       U+FFFD for each byte that is no UTF-8: a name the load refuses is
       reported too. Empty when the operation stopped before the
       artifact was read.
   * - ``upatch.payload_sha256``
     - string
     - For a load, the artifact's payload digest. For an unload, the
       payload the directive expects. Empty when the operation stopped
       before the artifact was read.
   * - ``kernel.release``
     - string
     - The running kernel's release, from ``uname``, with U+FFFD for
       each byte that is no UTF-8.
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
   * - ``outcomes_check``
     - The ``outcomes`` record does not cover the recorded ``last_seq``:
       it is missing (``ENOENT``), has a gap or a malformed line, or ends
       early (``EBADMSG``), or it cannot be read or cut. Nothing is
       applied.
   * - ``segment_walk``
     - The segment the tag names starts further past the node's last
       applied ``seq`` than the walk limit allows (``E2BIG``): 65,536
       operations, or 1,048,576 for a node that has processed none. A
       line before it names the segment's base, the limit and the node's
       ``seq``. Nothing is fetched further and nothing is applied.
   * - ``segment_fetch``
     - A sealed segment of the walk cannot be fetched, ``ENOENT`` when
       the registry does not serve its digest, or does not verify, or
       has changed when it is fetched again. A line before it names its
       digest. Nothing past it is applied.
   * - ``segment_chain``
     - A sealed segment is not the one its successor names: another
       digest, tree, head or a generation that is not lower, or it does
       not follow the node's state (``ERANGE``).
   * - ``history_base``
     - The segment's ``base.history_root`` is not the ``history_root``
       the node's ``outcomes`` holds at ``base.seq`` (``EKEYREJECTED``),
       or that line cannot be read. Nothing of the segment is applied.
   * - ``history_prefix``
     - The publication's operations up to the node's last applied
       ``seq`` are not the ones the node processed: their
       ``history_root`` differs from the node's (``EKEYREJECTED``).
       Nothing of the publication is applied.
   * - ``pending_recovery``
     - An interrupted operation above the cursor is not one the
       publication holds (``ERANGE``) or cannot be reconciled with the
       tree eventlog, or its ``outcomes`` lines or state cannot be
       written. One at or below the cursor is removed, whatever the
       publication holds.
   * - ``selector_evaluate``
     - The selector cannot be evaluated: the node labels or the kernel
       config cannot be read. The cursor stays on the operation.
   * - ``operation_digest_parse``
     - The operation digest is malformed.
   * - ``pending_write``
     - ``pending.json`` cannot be written.
   * - ``artifact_fetch_or_verify``
     - The artifact cannot be fetched or does not match its digests.
   * - ``upatch_install``
     - The load or unload failed. ``rc`` is the exit status of
       ``upatch load`` or ``upatch unload``.
   * - ``projection_root_decode``
     - The recorded projection root is malformed.
   * - ``projection_root_hash``
     - The next projection root cannot be computed. The register is
       not extended.
   * - ``register_extend``
     - The register extend failed.
   * - ``tree_event_append``
     - The tree eventlog record cannot be appended.
   * - ``tree_outcome_append``
     - The operation's ``outcomes`` line cannot be appended. The cursor
       stays before the operation.
   * - ``tree_state_commit_accept``, ``tree_state_commit``,
       ``tree_state_commit_final``
     - ``state.json`` cannot be written: when the publication is
       recorded, after an operation, or at the end of the sync.
   * - ``tree_status_write``
     - The per-operation status file cannot be written.

Related
-------

- :doc:`/reference/cli/upatch-load` and :doc:`/reference/cli/upatch-unload`
- :doc:`/operate/troubleshoot/troubleshooting`
- :doc:`/operate/troubleshoot/incident-tampered`
- :doc:`/security/tamper-counters`
