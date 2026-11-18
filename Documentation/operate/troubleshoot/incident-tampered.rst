..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators, SecOps

Respond to a tampered target
============================

shirudo reports ``tampered`` when the state it protects is not what it
recorded. Handle every ``tampered`` as an incident: keep the evidence,
get an account from the TPM that the target cannot forge, and compare it
with your own records.

A target reports ``tampered`` in two ways:

- A command refuses with the failure category ``tampered``. A load or
  unload refuses before it touches the kernel when the BPF keyring is not
  the one init froze, when the LSM link is not pinned, or when the
  register differs from the value ``--expect-chain`` gave. The last case
  carries the message ``chain_drift``. A load is also undone when the
  register refuses its extension because it is not the register init
  bound. Init refuses when the register it recorded this boot is gone or
  replaced, or when another task restricted the BPF keyring first.
- ``shirudo status`` reports the verdict ``tampered``: the live register
  differs from the eventlog replay, the BPF keyring is not the one init
  froze or is gone, or the config PCR, the activation records and the
  mounted config disagree.

Do not retry the refused command, with or without an ``--expect-chain``
value read from the target. A value read from the target accepts
whatever changed it. Do not reboot the target before the evidence is
safe: a reboot starts a new register, and the TPM can no longer certify
the state of this boot.

A tamper or integrity counter that moved is a different signal:
something tried an operation and the LSM refused it.
:doc:`/security/tamper-counters` and :doc:`/security/integrity-counters`
explain the counters.

Before you begin
----------------

- Root on the target. On the target, ``shirudo`` is the runtime image's
  binary, as :ref:`runtime-invocation` sets up.
- The operator host with the operator package, and a place off the
  target for the evidence.
- The target's enrolled attestation key name, and the values
  :doc:`/operate/run/attest` pins: the endorsement key name, the PCR 9 and
  PCR 11 binding values of its UKI, and the approved config root and PCR.
- Your records of what the target should run: the certificates it
  enrolled, the upatches it restored at boot, and every load and unload
  since.

Preserve the evidence
---------------------

1. Stop the timers that change state, so that nothing extends the
   register while you collect evidence:

   .. code-block:: console

      target# systemctl stop shirudo-bpm-repo-update.timer shirudo-bpm-tree-sync.timer

   ``shirudo-bpm-repo-update.timer`` runs ``shirudo bpm upgrade`` every
   60 seconds, and ``shirudo-bpm-tree-sync.timer`` applies the upatch
   tree every 60 seconds. Both load and unload upatches.

2. Save the target's own account, with this boot's eventlog:

   .. code-block:: console

      target# shirudo status --json --include-eventlog > status.json

   ``status`` runs in every state, and without ``--check`` it exits 0
   even when the verdict is ``tampered``. Keep the file, but do not rely
   on it: the target wrote it.

3. Copy the eventlog, the pending init record and the config activation
   records:

   .. code-block:: console

      target# mkdir evidence
      target# cp /var/lib/shirudo/eventlog evidence/
      target# cp /var/lib/shirudo/config-update/state evidence/
      target# cp /var/lib/shirudo/config-update/events evidence/

   Copy ``/run/shirudo/eventlog.pending`` too when it exists. Use plain
   ``cp``. With ``-a`` or ``--preserve=xattr``, ``cp`` tries to copy the
   seal label to the copy, which the seal refuses and counts as
   ``SealLabel``.

4. Save the journal of this boot:

   .. code-block:: console

      target# journalctl -b -o export > evidence/journal.export

   shirudo logs under the identifier ``shirudo``. The journal holds the
   refusal messages, and an audit line for every measured load and
   unload with the register value after it.

5. Choose a fresh nonce on the operator host:

   .. code-block:: console

      operator$ openssl rand -hex 32

6. Have the TPM sign evidence for that nonce:

   .. code-block:: console

      target# shirudo attest --nonce=<nonce> --output=evidence/evidence.json

   When the config cannot be verified or its activation is pending,
   every command but ``status`` and ``image status`` refuses,
   ``attest`` included, with ``shirudo: image state:`` and the reason. The TPM cannot certify this
   boot's state then. Keep what steps 2 to 4 saved and go to
   `After the investigation`_.

7. Copy ``status.json`` and the ``evidence`` directory to the operator
   host.

Verify with the TPM
-------------------

1. Predict the register from your records, as
   :doc:`/operate/run/attest` describes. Never take the certificates or the
   events from the target's eventlog: that would check the target
   against itself.

   .. code-block:: console

      operator$ shirudo attest predict --cert=<cert> --upatch=<upatch> \
          --event=load:<name>=<payload-sha256>

   ``<cert>`` is each certificate the target enrolled, ``<upatch>`` each
   upatch it restored at boot, and each ``--event=`` one change after
   boot that you know of. Use ``register_after_events``, or
   ``register_at_boot`` when there are no events.

2. Verify the evidence with every value pinned:

   .. code-block:: console

      operator$ shirudo attest verify --evidence=evidence.json --nonce=<nonce> \
          --ak-name=<ak-name> --ek-name=<ek-name> \
          --expect-bind-pcr=9=<pcr9> --expect-bind-pcr=11=<pcr11> \
          --require-initrd --expect-chain=<register> \
          --expect-config-root=<config-root> --expect-config-pcr=<config-pcr>

   :doc:`/operate/run/attest` explains each option and the report.

Read the result
---------------

.. list-table::
   :header-rows: 1
   :widths: 30 38 32

   * - Result
     - Meaning
     - Next
   * - ``verdict: ok``
     - The TPM certifies a register that your records explain. For a
       ``chain_drift`` refusal, the value the command expected was out of
       date.
     - Find out who issued the command with that value. Record the
       incident.
   * - ``FAIL`` on ``state:`` lines only
     - The register is a genuine record, but it holds changes your
       records do not cover. The ``event after boot`` notes list them.
       Each was a signed artifact that a process with shirudo's
       authority loaded or unloaded.
     - Match every note with the journal's ``upatch load: <name>
       measured, register <value>`` and ``upatch unload: <name>
       measured, register <value>`` lines and with your change records,
       timers and tree included. A change nobody authorized means a
       signing key or root on the target is compromised.
   * - ``FAIL`` on ``eventlog:`` replay, ``register:``, ``anchor:`` or
       ``binding:`` lines
     - Something extended or replaced the register outside shirudo's
       records, or bound it outside the initrd.
     - Treat the target as compromised. Keep every file.
   * - ``FAIL`` on the nonce or the attestation key
     - The evidence is not this TPM's answer to your request.
     - Treat the target and the path you collected it on as
       compromised.
   * - ``attest`` refused with ``shirudo: image state:``
     - The config PCR, the activation records and the mounted config
       disagree, or an activation is pending.
     - Keep ``status.json``, the config activation records and the
       journal. The TPM cannot certify this boot.

After the investigation
-----------------------

1. Reboot the target once the evidence is off it. The new boot binds a
   new register and runs init from the initrd again.

2. Verify the new boot with every value pinned, as in
   `Verify with the TPM`_. A upatch that someone loaded with an
   enrolled key is in the archive, and init restores it at boot. The init
   event then covers it, and the verification fails on
   ``state: init event covers the expected certificate, set and tree root``.

3. Remove what you did not authorize: unload a upatch with a signed
   unload directive, or revoke its signer through a signed config as
   :doc:`/operate/maintain/keys` describes.

The timers you stopped start again at boot when they are enabled.

Related
-------

- :doc:`/operate/run/attest` for enrollment and the verification options
- :doc:`/operate/run/read-status` for the verdicts and conditions
- :doc:`/operate/troubleshoot/troubleshooting` for the other failure messages
- :doc:`/reference/failure-categories` for every category
- :doc:`/security/threat-model` for what the measurement does not cover
