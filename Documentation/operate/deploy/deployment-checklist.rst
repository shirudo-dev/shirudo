..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

Deployment checklist
====================

Everything a production target needs, in the order you set it up. Each
item names the page that does it.

Plan
----

.. list-table::
   :header-rows: 1
   :widths: 6 54 40

   * - #
     - Item
     - Page
   * - 1
     - Hardware with a TPM 2.0, a kernel with the signed BPF loader
       interface, the BPF LSM and the dm-verity keyring, and systemd and
       dracut in the initrd.
     - :doc:`/operate/plan/system-requirements`
   * - 2
     - Kernel configuration and command line chosen from the hardening
       checklist, including the PCR for config measurements.
     - :doc:`/operate/plan/hardening`
   * - 3
     - Operator host with the operator package, ``veritysetup`` and
       ``mkfs.ext4``. It never runs as a target.
     - :doc:`/operate/plan/system-requirements`
   * - 4
     - BPF signing key and config signing key created, with their
       custody decided.
     - :doc:`/operate/maintain/keys`

Build on the operator host
--------------------------

.. list-table::
   :header-rows: 1
   :widths: 6 54 40

   * - #
     - Item
     - Page
   * - 5
     - Initial config image built and signed. Its
       ``etc/shirudo/shirudo.conf`` holds only ``eventlog.max_bytes`` and
       ``map_export.*`` keys.
     - :doc:`/operate/deploy/boot-integration`
   * - 6
     - Repository definitions, the upatch tree subscription and node
       labels placed in the config image.
     - :doc:`/operate/run/deliver-packages`
   * - 7
     - Collector endpoint in the config image's ``map_export.*`` keys.
     - :doc:`/operate/run/telemetry`
   * - 8
     - Runtime bootstrap file written with ``config.image``,
       ``config.verification_key``, ``config.pcr`` and ``tpm.tcti``.
     - :doc:`/operate/deploy/boot-integration`
   * - 9
     - Runtime image built with the static target binary, the BPF
       certificate and the config certificate. Its root hash and the
       ``shirudo.service`` drop-in kept.
     - :doc:`/operate/deploy/boot-integration`
   * - 10
     - Version ID of the target binary recorded.
     - :doc:`/operate/maintain/upgrade`
   * - 11
     - UKI bootstrap file written with ``runtime.image`` and
       ``runtime.root_hash``.
     - :doc:`/operate/deploy/boot-integration`

Prepare the target
------------------

.. list-table::
   :header-rows: 1
   :widths: 6 54 40

   * - #
     - Item
     - Page
   * - 12
     - Target package and dracut installed.
     - :doc:`/operate/deploy/boot-integration`
   * - 13
     - Runtime and config images placed in ``/var/lib/shirudo/images``
       before the first boot with enforcement.
     - :doc:`/operate/deploy/boot-integration`
   * - 14
     - For a dynamically linked binary, drop-ins from
       ``shirudo-gen-runtime --unit-dir`` installed for all six target
       services (optional for a static PIE target package, except when
       clearing ``EnvironmentFile=`` on ``shirudo.service``).
     - :ref:`unit-drop-ins`
   * - 15
     - Environment files ``/etc/shirudo/map-export.env`` and
       ``/etc/shirudo/bpm/environment`` reviewed.
     - :doc:`/operate/plan/hardening`
   * - 16
     - Initrd generated with ``shirudo-gen-initrd --bootstrap-conf`` and
       passed ``shirudo-gen-initrd --check``.
     - :doc:`/operate/deploy/boot-integration`
   * - 17
     - UKI built with ``bpf.keyring_unsealed=1`` and
       ``dm_verity.keyring_unsealed=1`` on its command line, signed for
       Secure Boot and installed as the default entry.
     - :doc:`/operate/deploy/boot-integration`

Boot and enroll
---------------

.. list-table::
   :header-rows: 1
   :widths: 6 54 40

   * - #
     - Item
     - Page
   * - 18
     - First boot completed: ``status`` reports ``ok``, ``status
       --show-full`` shows ``Bound in: initrd``, and ``image status``
       reports ``Pending: no``.
     - :doc:`/operate/deploy/initialize`
   * - 19
     - Attestation key name recorded and the target's endorsement key
       checked with a credential challenge.
     - :doc:`/operate/run/attest`
   * - 20
     - Expected PCR 9 and PCR 11 values at binding, the expected register
       and the approved config root recorded for the verifier.
     - :doc:`/operate/run/attest`
   * - 21
     - First packages installed and their delivery through the timers
       observed.
     - :doc:`/operate/run/deliver-packages`

Run
---

.. list-table::
   :header-rows: 1
   :widths: 6 54 40

   * - #
     - Item
     - Page
   * - 22
     - Alerts on the ``status`` field of ``status --json``, on tamper
       counters and on a missing keepalive, not on the exit status.
     - :doc:`/operate/run/read-status`, :doc:`/operate/run/telemetry`
   * - 23
     - Attestation scheduled with a fresh nonce and the verifier's
       required flags.
     - :doc:`/operate/run/attest`
   * - 24
     - Backup of ``/var/lib/shirudo`` and of the operator's build inputs.
     - :doc:`/operate/maintain/backup-recovery`
   * - 25
     - Incident procedure for a ``tampered`` target agreed with the
       security team.
     - :doc:`/operate/troubleshoot/incident-tampered`
   * - 26
     - Upgrade procedure for shirudo and the kernel tried on a canary
       target, with the previous UKI kept as a boot entry.
     - :doc:`/operate/maintain/upgrade`
