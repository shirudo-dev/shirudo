..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators

Troubleshoot by symptom
=======================

This page starts from what you see: a message a command prints, the
failure category of a upatch load or unload, or a status verdict. Each
entry says what the symptom means, what causes it and what to do. The
output shown was captured from the test VM.

:doc:`/reference/failure-categories` lists every category and exit
status. :doc:`/operate/run/read-status` explains the status report.

Before you begin
----------------

- On the target, ``shirudo`` means the binary on the runtime image,
  ``/run/shirudo/runtime/usr/bin/shirudo``, see
  :ref:`runtime-invocation`.
- Run ``shirudo status`` first. It is the target's own report, and it
  still runs when most other commands refuse. The ``Status`` line gives
  the verdict, and the conditions below it the checks the verdict
  is derived from. A healthy target starts its report like this:

  .. code-block:: console

     target# shirudo status
     Host:                  docs
     Roles:                 target
     Status:                ok
     Version ID:            d0d7aa800303439023907d1979d917d46a21bec21f816689c138728a28e84af9

     Conditions:
       TYPE               STATUS  DETAIL
       LsmAttached        OK      lsm/bpf link present and pinned
       KeyringSealed      OK      bpf serial 272801410, dm-verity serial 799624487, pins match
       ChainIntact        OK      live register equals the eventlog replay
       UpatchesMeasured   OK      every pinned or archived upatch is in this boot's records
       TpmMeasured        OK      NV index 0x01818E00 readable
       ConfigActive       OK      config 6d5ed552f448.. is active
       XdpCovered         OK      every device an XDP upatch selects runs it
     ...

  A verdict other than ``ok`` is followed by its reason in parentheses,
  and the condition that raised it shows ``WARN`` or ``ALERT`` with a
  detail. Look the verdict up under `Status verdicts`_. ``status`` exits
  0 whatever the verdict unless you pass ``--check``, so read the
  ``Status`` line, not the exit status. If ``status`` itself prints
  ``shirudo: image state:``, start from that message under `Commands
  refused before they run`_.
- Every message shirudo prints also goes to the journal under the
  identifier ``shirudo``. Read the messages of this boot, and the two
  ``init`` runs, with:

  .. code-block:: console

     target# journalctl -b -t shirudo
     target# journalctl -b -u shirudo-initrd.service -u shirudo.service

- ``upatch load`` and ``upatch unload`` print a JSON report with the
  category, the phase and the verifier log when you pass
  ``--report=-``, see :doc:`/reference/cli/upatch-load`.

Commands refused before they run
--------------------------------

On a production target every target command except ``init`` first
checks its runtime authority, the TPM and the config activation. A refusal prints ``shirudo: image state:`` and the error,
and the command exits 1 without doing anything.

``shirudo: image state: Permission denied``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   target# /usr/local/bin/shirudo status
   shirudo: image state: Permission denied

Meaning
   The command has no runtime authority, or the TPM is not the one
   ``init`` bound.

Causes
   - You ran a copy of the binary other than the runtime image's, for
     example the one a package installed under ``/usr/bin``. The LSM
     refuses it the identity pin, which also counts as ``ObjGet``.
   - A drop-in or override of your own runs a binary outside the
     runtime image.
   - The message follows ``tpm: not the TPM init bound (attestation key
     name differs)``: the TPM that answers is not the TPM ``init`` bound
     this boot.

Action
   - Run ``/run/shirudo/runtime/usr/bin/shirudo``, see
     :ref:`runtime-invocation`.
   - Point every ``ExecStart=`` at the runtime image's binary, see
     :ref:`unit-drop-ins`.
   - A different TPM is an incident, see
     :doc:`/operate/troubleshoot/incident-tampered`.

``shirudo: image state: Operation not permitted``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Meaning
   The command carries a setting that a production target takes only
   from its authenticated images.

Causes
   - An argument starts with ``--keys-dir``, ``--cert`` or ``--tcti``.
     A target refuses all three, so ``attest verify`` and ``attest
     predict`` with ``--cert=`` run on the operator host, not on a
     target.
   - The message follows ``bootstrap override <name> is forbidden``: the
     environment sets one of ``SHIRUDO_KEYS_DIR``, ``SHIRUDO_TPM_TCTI``,
     ``SHIRUDO_TPM_OWNER_AUTH``, ``SHIRUDO_EVENTLOG_PATH``,
     ``SHIRUDO_EVENTLOG_PENDING_PATH``, ``SHIRUDO_INITRD_RELEASE`` or
     ``SHIRUDO_SYSROOT``. ``init`` refuses the same variables with
     ``init: authenticated image settings: Operation not permitted``.

Action
   - Drop the argument, or run the command on the operator host.
   - Unset the variable in your shell, or remove it from the
     environment file of the unit: ``/etc/shirudo/map-export.env`` or
     ``/etc/shirudo/bpm/environment``.

``shirudo: image state: Operation now in progress``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Meaning
   A config activation is pending until the next reboot. Only
   ``status`` and ``image status`` run, and ``status`` reports
   ``reboot-pending``.

Causes
   - ``shirudo image update`` was interrupted after it recorded the
     pending selection.
   - ``init`` failed after it measured this boot's config, while it
     restored the archived upatches or bound the register. The journal
     shows ``image: activation is pending; further changes are blocked``
     for a re-run of ``init``.

Action
   Reboot. Nothing clears the pending state within the boot. See
   :ref:`status-reboot-pending`.

``shirudo: image state: Structure needs cleaning``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Meaning
   The config PCR, the activation records and the mounted config
   disagree. ``status`` runs and reports ``tampered`` with the reason
   ``the selected config cannot be verified against its records``. Two
   other errors belong to the same state: ``Stale file handle`` when the
   activation record belongs to another TPM boot, and ``Key was rejected
   by service`` when the mounted config is not the selected one.

Causes
   - Something extended the config PCR after this boot's config
     measurement, either an attacker or other software that measures
     into the same PCR.
   - The TPM was reset or restarted without a reboot, for example by a
     resume from hibernation.
   - The config mount was replaced.

Action
   Do not retry. Handle the target as an incident, see
   :doc:`/operate/troubleshoot/incident-tampered`, and reboot once you have the
   evidence. If other software extends the PCR, choose another config
   PCR, see :doc:`/operate/plan/hardening`.

``image: waiting for another shirudo command to release the config operation lock``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Meaning
   Every target command holds ``/var/lib/shirudo/config-update/lock``
   for its whole run. Your command waits for the one that holds it, and
   prints this message after one second. After 30 seconds it gives up
   with ``image: another shirudo command still holds the config
   operation lock /var/lib/shirudo/config-update/lock after 30 seconds``
   and ``shirudo: image state: Resource temporarily unavailable``.

Causes
   A long command runs, typically a timer service: a package update or
   tree sync against a slow registry, or a map export.

Action
   1. See which shirudo services run:

      .. code-block:: console

         target# systemctl list-units 'shirudo-*'

   2. Wait for the active one to finish, then run your command again.

``hardening: cannot lock process memory``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Meaning
   Every ``shirudo`` and ``shirudo-build`` invocation locks its memory
   with ``mlockall`` before it dispatches a command. The lock failed and
   the command exited 1.

Causes
   The process has no ``CAP_IPC_LOCK`` and its memory-lock limit is too
   small: an unprivileged operator shell, a container or a unit without
   ``LimitMEMLOCK=infinity``.

Action
   Raise the limit in the shell (``ulimit -l unlimited`` as root) or
   set ``LimitMEMLOCK=infinity`` in the unit. The shipped units set it.

Files refused
-------------

shirudo reads a settings, repository, tree or certificate file under
``/etc/shirudo`` or ``/var/lib/shirudo``, and the registry auth file or
CA certificate the environment names there, only when no user but root
or the one running the command could change or replace it, see
:ref:`trusted-files`. A refusal names the path the command was given,
then what fails the check, and the command fails.

``<path>: link <link>, owner <uid>: refusing a file another user could replace``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   target# REGISTRY_AUTH_FILE=/etc/shirudo/bpm/auth.json shirudo bpm tree sync
   /etc/shirudo/bpm/auth.json: link /etc/shirudo/bpm/auth.json, owner 65534: refusing a file another user could replace
   bpm tree sync: Operation not permitted

Meaning
   A symbolic link on the path belongs to a user other than root and
   the one running the command, who could point it at another file.
   The same message names a directory on the path, the one that holds a
   link included, as ``directory <dir>, owner <uid>, mode <mode>``,
   when another user owns it or it is writable by group or others and
   not root's and sticky, and the file itself as ``owner <uid>, mode
   <mode>``.

Causes
   - The link was made as another user, or copied with its owner by
     ``tar``, ``rsync -a`` or ``cp -a`` run as root.
   - A link leads through a directory that another user can write. A CA
     certificate linked to a local one in ``/etc/ssl/certs``, which
     ``update-ca-certificates`` links on into
     ``/usr/local/share/ca-certificates``, is refused where a directory
     on the way is writable by its group, as Debian's ``root:staff``
     mode ``2775`` layout of ``/usr/local`` leaves it. The message names
     that directory.

Action
   - Give the link to root, ``chown -h root:root <link>``, or make it
     again as root.
   - Make each directory on the path root's and not writable by group
     or others, or keep the file in a directory that is, such as
     ``/etc/shirudo`` itself.

``<path>: names another file than the one opened; refusing it``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Meaning
   The name kept changing while the command read it. Between each open
   and its check, a new file was renamed over the name, or a new link
   over a link on its path, so the path led to another file than the
   one opened. A file renamed over once, as a configuration manager, a
   package or shirudo's own state writes replace one, is opened again
   and checked in full, up to three more times; only a name that
   changes on every attempt ends here. The command uses nothing from the
   files it opened, and fails, most commands with ``Stale file handle``.

Causes
   Something renames new files over the file, or over a link on its
   path, in a loop: a configuration manager that rewrites it on every
   run, or a script.

Action
   Find what rewrites the file that often and stop it, then run the
   command again.

upatch load and unload failures
-------------------------------

Each failure ends in one category, which the JSON report of
``--report`` carries. The journal holds the messages, but not every
load failure names its category there, so pass ``--report`` when you
need it. Nothing changed on the target unless the entry says otherwise.

``tampered``, message ``chain_drift``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   target# shirudo upatch load --expect-chain=0000000000000000000000000000000000000000000000000000000000000000 --report=- /mnt/shirudo-bundle/fixtures/shirudo-test-lifecycle.upatch
   upatch load: pre-flight refused (category: tampered, message: chain_drift): live register c50b22ac27c5bb6a90ee5ff9b440fbbd5bb60b84a2aa7b395daec3f330886fcd is not the expected one; run status and pass the refreshed value
   {"schema":1,"result":"failed","op":"upatch_load","phase":"pre_flight","errno":1,"errno_name":"EPERM","category":"tampered","message":"pre-flight check failed",...}

Meaning
   The live register is not the value you passed with
   ``--expect-chain``. The command stopped before it loaded anything.
   ``tampered`` also ends a load whose pre-flight finds the ``lsm/bpf``
   link unpinned (message ``lsm_detached``) or the ``.bpf`` keyring
   different from the one ``init`` sealed.

Causes
   - Something changed the register after you read the value: another
     operator, or a timer that installed or upgraded a package or
     applied a tree operation.
   - Something changed the register outside shirudo.

   The target cannot tell you which, and its own report is not proof.

Action
   Do not repeat the command with the value the message prints. Keep the
   journal and the eventlog, and follow
   :doc:`/operate/troubleshoot/incident-tampered`. TPM-signed evidence, checked
   against the events you expect, decides whether the change was yours.

``version_mismatch``
~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   target# shirudo upatch load --expect-version-id=0000000000000000000000000000000000000000000000000000000000000000 --report=- /mnt/shirudo-bundle/fixtures/shirudo-test-lifecycle.upatch
   upatch load: version mismatch, the operator expects 0000000000000000000000000000000000000000000000000000000000000000 and the target is 58b05ab35a2bcefaa649faf15f8c6be0211e24cea710450c1a29298c3b5c7de0; deploy a matching shirudo or pass --no-version-check
   {"schema":1,"result":"failed","op":"upatch_load","phase":"pre_flight","errno":1,"errno_name":"EPERM","category":"version_mismatch","message":"SHIRUDO_VERSION_ID mismatch (operator vs target)",...}

Meaning
   The target runs a shirudo build other than the one
   ``--expect-version-id`` names. The check runs first, before anything
   else.

Causes
   - The target was not upgraded, or was upgraded to another build.
   - The id you expect comes from a binary built on another host. The
     identifier covers the build configuration, so two builds of one
     commit on different hosts differ, see :doc:`/operate/maintain/upgrade`.

Action
   1. Read the identifier of the target:

      .. code-block:: console

         target# shirudo version --version-id
         58b05ab35a2bcefaa649faf15f8c6be0211e24cea710450c1a29298c3b5c7de0

   2. Compare it with the build you deployed to this target. If the
      target runs the wrong build, upgrade it. If your expectation came
      from another host's build, record the target's identifier as the
      expected one.

``keyring_missing``
~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   target# shirudo upatch load --report=- /mnt/shirudo-bundle/fixtures/shirudo-test-foreign.upatch
   BPF_PROG_LOAD (signed loader): Required key not available
   loader verifier log:
   signature verification failed: -126

   {"schema":1,"result":"failed","op":"upatch_load","phase":"signed_loader_load","errno":126,"errno_name":"ENOKEY","category":"keyring_missing","message":"BPF_PROG_LOAD of signed loader failed",...}

Meaning
   The kernel found no key in the ``.bpf`` keyring that verifies the
   loader's signature (``ENOKEY``). The artifact is signed by a key the
   target does not trust. In the pre-flight phase the same category
   means that no keyring was recorded this boot: ``no trust anchor
   frozen this boot``.

Causes
   - The artifact was signed with another operator key.
   - The signing key is not in the target's trusted set. A key enters
     the ``.bpf`` keyring only at boot, from the runtime image and the
     config selected for that boot.
   - The signing key was revoked.

Action
   1. Print the fingerprints the target trusts:

      .. code-block:: console

         target# shirudo keys

   2. Print the fingerprint of the key that signed the artifact, on the
      operator host:

      .. code-block:: console

         operator$ shirudo keys --keys-dir=<keys-dir>

   3. Compare the ``SPKI fingerprint`` of the operator's certificate
      with the members of the target's ``Trusted set``. Sign with a
      trusted key, or see :doc:`/operate/maintain/keys` for how a key becomes
      trusted.

``<keys-dir>`` is the directory that holds the signing key the artifact
was built with.

``payload_mismatch``
~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   target# shirudo upatch unload --report=- /mnt/shirudo-bundle/fixtures/shirudo-test-basic-mismatch.unload.upatch
   upatch unload: signed loader accepted, keyring 272801410, 165 instructions
   upatch unload: payload_mismatch, the upatch loaded under 'shirudo-test-basic' is not what the directive expects; refused
   upatch unload failed: name=shirudo-test-basic phase=pin category=payload_mismatch err=1 (Operation not permitted) message=loaded payload does not match directive
   {"schema":1,"result":"failed","op":"upatch_unload","phase":"pin","errno":1,"errno_name":"EPERM","category":"payload_mismatch","message":"loaded payload does not match directive",...}

Meaning
   The unload directive is signed for one payload, and the upatch loaded
   under that name has another. The upatch stays loaded.

Causes
   - The directive was built for another version of the upatch, for
     example before a package upgrade replaced it.
   - The payload record of the loaded upatch cannot be read, which the
     journal reports as ``cannot read the payload recorded for``.

Action
   1. Read the payload digest of the loaded upatch:

      .. code-block:: console

         target# shirudo upatch get <name>

   2. Build a directive for that payload on the operator host:

      .. code-block:: console

         operator$ shirudo build --unload <name> --payload-sha256 <payload> --keys-dir <keys-dir> -o <name>.unload.upatch

``<name>`` is the upatch name, ``<payload>`` the 64-character digest
from the ``Payload sha256:`` line, and ``<keys-dir>`` the directory of a
trusted signing key.

``attach_target_missing``
~~~~~~~~~~~~~~~~~~~~~~~~~

Meaning
   The kernel has no attach point where the upatch's metadata names one:
   a kprobe function, a module, or the binary of a uprobe. The journal
   shows ``attach prog <n> (<kind> <target>): No such file or
   directory``, or ``uprobe target verification failed
   (attach_target_missing)``. Nothing stays loaded. ``upatch load`` exits
   2 for this category.

Causes
   - The function does not exist in the running kernel, or its module is
     not loaded.
   - The binary of a uprobe is not at the path the upatch names.
   - The upatch was built for another kernel.

Action
   Check the attach point on the target, load the module first if the
   upatch needs one, or ship a upatch built for this kernel.

``attach_scope_mismatch``
~~~~~~~~~~~~~~~~~~~~~~~~~

Meaning
   The kernel created the link, but not at the site the metadata names,
   so shirudo refused to pin it (``EXDEV``). The journal shows ``attach
   prog <n> (<kind> <target>): the link is not at the site the metadata
   names``.

Causes
   The command ran in a namespace other than the host's initial ones: a
   ``cgroup_skb`` link not at the root cgroup, a ``netfilter`` link in
   another network namespace, a kprobe at another function or offset.

Action
   Run the load from the host's initial namespaces, not from a container
   or from a unit with private namespaces.

``verifier_rejected``
~~~~~~~~~~~~~~~~~~~~~

Meaning
   The kernel rejected the payload, or the signed loader failed to load
   it. The journal shows ``loader returned error: <n>`` and the loader's
   runtime log, or ``BPF_PROG_TEST_RUN:`` with the error. The report
   carries the log in ``verifier_log``.

Causes
   - The upatch was built against another kernel's BTF, and a CO-RE
     relocation or an attach target does not resolve on this kernel.
   - The kernel lacks a helper, kfunc or program type the payload uses.

Action
   Read ``verifier_log`` in the report. Rebuild the upatch against the
   target kernel's ``vmlinux.h``, or ship a version for this kernel.

``kernel_abi_unsupported``
~~~~~~~~~~~~~~~~~~~~~~~~~~

Meaning
   The kernel lacks the signed-loader interfaces shirudo requires. The
   pre-flight prints ``upatch: pre-flight refused (category:
   kernel_abi_unsupported, message: <detail>)``, where the detail names
   the missing piece, for example ``struct bpf_map.excl_prog_sha is
   missing; boot a shirudo-patched kernel``. The same category ends a
   load whose attach kind the kernel does not support.

Causes
   The target booted a kernel without the required ABI.

Action
   Boot a kernel that meets :doc:`/operate/plan/system-requirements`.

``eventlog_full``
~~~~~~~~~~~~~~~~~

Meaning
   The next record would take the eventlog past ``eventlog.max_bytes``.
   The command refused before it loaded or extended anything:
   ``upatch load: eventlog /var/lib/shirudo/eventlog would exceed
   eventlog.max_bytes <n>; refused, nothing loaded or extended``.

Causes
   The eventlog grows by one record per boot, load, unload, revocation
   and tree operation, and shirudo never rotates it.

Action
   Raise ``eventlog.max_bytes`` in a signed config and activate it, see
   :doc:`/reference/configuration`. Keep the cap below 8 MiB:
   every reader of the eventlog fails on a larger log. This works only
   while ``init`` completes: once the eventlog reaches the cap, ``init``
   fails at every boot and leaves the activation pending, and ``image
   update`` and ``image stage`` refuse a pending activation, so the
   target has to be provisioned again.
   :doc:`/operate/maintain/backup-recovery` covers the eventlog's lifetime.

Boot and init
-------------

``init: pre-flight failed``
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Meaning
   One of the checks ``init`` runs before it changes anything failed.
   ``init`` prints a table with ``FAIL`` and a detail for each failed
   check, then ``init: pre-flight failed, <failed> of <total> checks``.
   In the initrd the table is in the journal of
   ``shirudo-initrd.service``. A passing run looks like this:

   .. code-block:: console

      target# shirudo init --check-only
      Pre-flight checks:
        OK    root
        OK    bpf_lsm_active
        OK    bpffs_supported
        OK    signed_loader_kernel_abi
        OK    kernel_lsm_hooks
        OK    module_signatures
        OK    cert_on_disk
        OK    cert_algorithm
        OK    cert_kernel_support
        OK    kernel_keyring
        OK    embedded_loader
        OK    tpm2_reachable: TCTI from the config: device:/dev/tpmrm0
      12 of 12 passed

Causes
   The check names the requirement that is missing: root, the BPF LSM
   in the kernel's active LSM list, bpffs, the signed-loader ABI, an
   LSM hook only the kernel project patches add, module signatures in
   a kernel that loads modules, the certificate and its algorithm, the
   kernel keyring, the embedded loader or the TPM.

Action
   Fix the requirement, see :doc:`/operate/plan/system-requirements`, and
   reboot. :doc:`/operate/deploy/initialize` describes the init runs.

``init: boot-restore failed; further changes and attestation remain blocked``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Meaning
   ``init`` could not load one of the archived upatches, preceded by
   ``boot-restore: failed to apply <file>``. It stops at the first
   failure. The upatches it loaded before stay loaded, and the register
   is not bound. The config activation stays pending, so every command
   except ``status`` and ``image status`` refuses until the next boot,
   and ``status`` reports ``reboot-pending``.

Causes
   The archived upatch does not load on this kernel, typically after a
   kernel upgrade. The load failure before this message carries its
   category. For an XDP upatch, a line ``XDP: attach <device>`` before
   it names a device whose driver refused the program: a NIC added since
   the load, or a setting that survived the reboot, in the NIC's firmware
   or the hypervisor, such as LRO, header-data split or a device without
   multi-buffer XDP.

Action
   A reboot restores the same archive and fails the same way.
   :ref:`boot-restore-lockout` describes what works and what does not.

Status verdicts
---------------

:ref:`status-verdicts` explains every verdict in full. The short form:

``tampered``
   Handle as an incident, see :doc:`/operate/troubleshoot/incident-tampered`. Do
   not retry and do not reboot before you have the evidence.

``reboot-pending``
   A config activation is pending. Reboot.

``degraded``
   Enforcement is up, but there is no register to check, or a device an
   XDP upatch selects does not run it. Read the reason on the ``Status``
   line, see :ref:`status-degraded`.

``lsm-off``
   Enforcement did not come up this boot and the target is unprotected.
   Read the journal of ``shirudo-initrd.service``, fix the cause and
   reboot, see :ref:`status-lsm-off`.

``init-pending``
   ``init`` did not finish this boot. The ``lsm/bpf`` link is pinned,
   but no keyring is recorded. Read the journal of
   ``shirudo-initrd.service``, fix the cause and reboot, see
   :doc:`/operate/deploy/initialize`.

Next steps
----------

- :doc:`/reference/failure-categories` for every category and exit
  status
- :doc:`/operate/troubleshoot/incident-tampered` for a ``tampered`` refusal or
  verdict
- :doc:`/operate/run/read-status` for the status report
