..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators

Report a bug
============

Collect what the maintainers need to reproduce a problem, remove what
identifies your hosts, and file it as a GitHub issue. This page is for
bugs. A suspected vulnerability goes to :doc:`/security/reporting`
instead, privately.

Before you begin
----------------

- Decide whether the problem is a vulnerability: a way to load BPF that
  no trusted key signed, to detach or bypass enforcement, to change
  sealed state, or to make evidence verify for a state the target is not
  in. Report those as :doc:`/security/reporting` describes, and do not
  open a public issue.
- If a command refused with ``tampered`` or ``shirudo status`` reports
  ``tampered``, preserve the evidence first, as
  :doc:`/operate/troubleshoot/incident-tampered` describes, and do not reboot
  the target before it is safe.
- Reproduce the problem on the ``main`` branch. shirudo has no releases
  yet (:doc:`/reference/versions`).
- Root on the target. On a target, ``shirudo`` is the binary on the
  runtime image (:doc:`/operate/deploy/boot-integration`).
- A directory on the target for the files, here ``bug/``, outside
  ``/var/lib/shirudo``. shirudo refuses to write a report into sealed
  state.

Collect on the target
---------------------

1. Record the version and the version ID:

   .. code-block:: console

      target# shirudo version > bug/version.txt

   It prints two lines, for example::

      shirudo (58d3fa7-dirty-rc0, "Social BPF Coding")
      version-id: 58b05ab35a2bcefaa649faf15f8c6be0211e24cea710450c1a29298c3b5c7de0

2. Save the status with the system block and the eventlog:

   .. code-block:: console

      target# shirudo status --json --show-full > bug/status.json

   The ``system`` block holds the kernel release, version and build ID,
   and every ``CONFIG_*`` value from ``/boot/config-<release>`` when that
   file exists. :doc:`/reference/formats/status-json` lists the fields.

3. Save the pre-flight checks:

   .. code-block:: console

      target# shirudo init --check-only > bug/preflight.txt

   ``--check-only`` runs the pre-flight checks and stops there.

4. Save the report of the command that fails. ``upatch load`` and
   ``upatch unload`` write one with ``--report``:

   .. code-block:: console

      target# shirudo upatch load --report=bug/load-report.json <upatch>

   ``<upatch>`` is the artifact that fails to load. ``bpm tree sync``
   prints its report to standard output, or to ``--report=<path>``. Run
   a command again only to get its report. Never repeat a command that
   refused with ``tampered``.

5. Save shirudo's journal of this boot:

   .. code-block:: console

      target# journalctl --boot --identifier=shirudo \
          --output=short-iso-precise > bug/journal.txt

   shirudo logs under the identifier ``shirudo``, from the initrd's
   ``init`` on. For a problem in an earlier boot, pass that boot, for
   example ``--boot=-1``.

6. Save the kernel's messages of this boot:

   .. code-block:: console

      target# journalctl --boot --dmesg --output=short-iso-precise \
          > bug/kernel.txt

7. Record the kernel command line and the active LSMs:

   .. code-block:: console

      target# cat /proc/cmdline /sys/kernel/security/lsm > bug/cmdline.txt

8. If ``kernel_config`` in ``status.json`` is empty, because there is no
   ``/boot/config-<release>``, save the configuration the kernel carries
   instead:

   .. code-block:: console

      target# zcat /proc/config.gz > bug/config.txt

   This needs ``CONFIG_IKCONFIG_PROC``. Otherwise take the configuration
   from the kernel build.

9. Add the kernel tree, the commit and the patches applied to it. A
   release number does not identify a bpf-next kernel, see
   :doc:`/operate/plan/system-requirements`.

Collect on the operator host
----------------------------

Collect these when the problem involves a build, a package, a
publication or a verification:

1. Record the operator's version:

   .. code-block:: console

      operator$ shirudo version > bug/operator-version.txt

2. Record the package and the toolchain:

   .. code-block:: console

      operator$ dpkg-query --show shirudo-operator >> bug/operator-version.txt
      operator$ openssl version >> bug/operator-version.txt
      operator$ clang --version >> bug/operator-version.txt

   On an RPM-based host use ``rpm --query shirudo-operator``. The
   ``shirudo-build`` helper has no version command. Note which one ran:
   ``SHIRUDO_BUILD`` if set, else ``/usr/libexec/shirudo/shirudo-build``,
   else the first on ``PATH``.

3. Save the exact command line, its complete output and its exit status.

4. For a problem with an artifact, save what it declares:

   .. code-block:: console

      operator$ shirudo upatch info --json <upatch> > bug/upatch-info.json

   Attach the artifact itself only if you may share the program it
   carries.

5. For a problem with ``attest verify`` or ``attest predict``, save the
   command and its report. Attach the evidence document only after you
   have read the next section.

Remove what identifies your hosts
---------------------------------

None of the files above contains the TPM owner password or a registry or
collector credential. ``shirudo config`` prints ``tpm.owner_auth`` as
redacted and has no credential settings. They do contain values that
identify your hosts and your infrastructure:

.. list-table::
   :header-rows: 1
   :widths: 34 36 30

   * - Value
     - Where
     - Identifies
   * - Host name
     - ``status.json`` (``host`` and, when present, ``system.hostname``)
       and the journal
     - The host
   * - ``machine_id``, ``boot_id``
     - ``status.json``. ``boot_id`` also in the evidence document
     - The host and the boot
   * - Attestation key name, endorsement key and its certificate
     - The evidence document, ``attest`` command lines
     - The TPM. Its endorsement key is unique to it
   * - The firmware event log and systemd's measurement log
     - ``logs`` in the evidence document
     - The firmware, its boot entries, and what systemd measured, which
       can include the machine ID
   * - Certificate SHA-256 values and fingerprints
     - ``status.json`` and the eventlog in it
     - Your signing keys
   * - Registry hosts and repositories, OTLP endpoint, S3 URI, tenant ID
     - The journal of the bpm and export units, ``shirudo config``
     - Your infrastructure
   * - Addresses, user names, paths
     - The journal, the kernel messages
     - Hosts and people

Replace each value with the same placeholder everywhere it appears, so
that the files stay consistent with each other.

Never attach these files:

- ``/etc/shirudo/shirudo.conf`` from the initrd or from the runtime
  image. Both carry ``tpm.owner_auth``.
- ``/etc/shirudo/bpm/environment`` and ``/etc/shirudo/map-export.env``.
  They carry registry and collector credentials.
- Registry authentication files.
- The operator's key directory, ``/var/lib/shirudo/keys`` by default or
  the one ``--keys-dir`` names. It holds the private signing key.

File the issue
--------------

1. Open https://github.com/shirudo-dev/shirudo/issues/new.
2. Write a title that names the command or component and the symptom,
   for example ``upatch load: verifier_rejected for a kprobe upatch``.
3. Describe what you did, what you expected and what happened, and give
   the shirudo commit, the version IDs of the target and the operator,
   and the kernel tree and commit.
4. Attach the files from ``bug/`` and submit the issue.

Verify
------

Open the issue and read each attachment once more for a value from the
table above. If one slipped through, delete the attachment and attach a
cleaned copy.

Next steps
----------

- :doc:`/operate/troubleshoot/troubleshooting` for known symptoms and their
  causes
- :doc:`/reference/failure-categories` for the category and phase in a
  report
- :doc:`/operate/plan/interoperability` when the problem involves other
  software on the target
