..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Tutorial
:audience: Operators

Attest a target
===============

In this tutorial you enroll the test target's TPM and then verify what the
target runs. You take a first piece of evidence and record the TPM's
attestation key from it. A credential challenge then proves that this key
lives in the same TPM as the endorsement key the evidence names. With the
key pinned, you predict the target's measurement register and verify
evidence against the prediction.

The target's TPM signs the evidence, and you check it on the operator
host against values you compute yourself from your certificates and
artifacts.

Before you begin
----------------

- The test VM from the :doc:`/start/quickstart`, running as
  ``quickstart``, with the upatch ``basic`` loaded and unloaded. The
  examples come from a test VM on which other guides ran as well, so
  their lists of events after boot are longer than yours.
- The operator shell from the quickstart: in the root of your checkout,
  with ``shirudo`` on ``PATH``, ``KEYS`` naming the test VM's key
  directory and ``PAYLOAD`` holding the payload digest of
  ``basic.upatch``.
- ``jq`` and the ``openssl`` command on the operator host.
- A root shell on the target, in which ``shirudo`` runs the runtime
  binary:

  .. guide-check: skip

  .. code-block:: console

     operator$ make vm-ssh VM_NAME=quickstart

Take the first evidence
-----------------------

1. Name the second enrolled certificate and the directory the test VM
   shares with the host:

   .. code-block:: console

      operator$ OWN=build/test-vm/host-bundle-bpf-next-verity/fixtures/own.der
      operator$ RESULT=$(realpath build/test-vm/vms/quickstart/result)

   ``realpath`` resolves any symlinks in the path so shirudo can write
   the challenge. The guest sees ``$RESULT`` as ``/mnt/shirudo-out``.

2. Make a nonce:

   .. guide-check: capture nonce1

   .. code-block:: console

      operator$ NONCE1=$(openssl rand -hex 32)
      operator$ echo "$NONCE1"

3. Take evidence on the target with that nonce:

   .. code-block:: console

      target# shirudo attest --nonce=<nonce1> --output=/mnt/shirudo-out/first.json

   ``<nonce1>`` is the value you printed.

Record the key names
--------------------

1. Read the names of the attestation key and the endorsement key from the
   evidence:

   .. code-block:: console

      operator$ AK=$(jq -r .ak.name "$RESULT/first.json")
      operator$ EK=$(jq -r .ek.name "$RESULT/first.json")

   The attestation key (AK) signs the evidence. It is a primary key that
   the TPM derives from a fixed template under its endorsement hierarchy,
   so the same TPM yields the same key and name again on later boots.
   The endorsement key (EK) identifies the TPM. So far these are only
   names the document claims, and nothing ties them to a TPM yet.

Challenge the attestation key
-----------------------------

1. Make a credential challenge for the attestation key:

   .. guide-check: capture credential

   .. code-block:: console

      operator$ shirudo attest challenge --evidence="$RESULT/first.json" --ak-name="$AK" --trust-presented-ek --output="$RESULT/challenge.json"
        OK    attestation key: the pinned key
        OK    endorsement key: name matches its public area
        OK    endorsement key: TCG default template under the endorsement policy
        OK    endorsement certificate: describes the endorsement key
        NOTE  endorsement certificate: not checked against an issuer bundle (--ek-ca)
      challenge: .../vms/quickstart/result/challenge.json
      credential: b17d3f29447eaf539bcffa2556b010082a7a10e2b7ab60746c485d176b7a40cc

   The challenge holds a random credential, encrypted to the endorsement
   key and bound to the attestation key's name. Only the TPM that holds
   the endorsement key can decrypt it, and that TPM releases it only to a
   key with that exact name. The command prints the credential. Keep it
   for the verification, and do not hand it to the target.

2. Keep the credential:

   .. code-block:: console

      operator$ CRED=<credential>

   ``<credential>`` is the value the command printed.

The test VM builder signs the software TPM's endorsement certificate
with a temporary test CA. With ``--trust-presented-ek``, the command
checks that the certificate describes the presented endorsement key and
skips issuer validation. Never use that option for a production target:
whoever controls the target could present the keys of a software TPM,
answer the challenge there and sign any evidence. Use one of these
instead:

- ``--ek-ca=<bundle>``, a PEM bundle of the TPM vendors' CA certificates.
  The command then requires the endorsement certificate the TPM carries
  to chain to one of them and to describe the presented key.
- ``--ek-name=<ek-name>``, an endorsement key name you recorded through a
  channel you trust, for example when the machine was provisioned.

Answer the challenge on the target
----------------------------------

1. Make a second nonce on the operator host:

   .. guide-check: capture nonce2

   .. code-block:: console

      operator$ NONCE2=$(openssl rand -hex 32)
      operator$ echo "$NONCE2"

2. Take evidence that answers the challenge:

   .. code-block:: console

      target# shirudo attest --nonce=<nonce2> --challenge=/mnt/shirudo-out/challenge.json --output=/mnt/shirudo-out/enrolled.json

   The TPM activates the credential for its attestation key, and the
   evidence carries the recovered value. A challenge made for another
   attestation key fails here and writes no evidence:

   .. code-block:: console

      attest: the challenge was made for another attestation key
      attest: the TPM refused the challenge; the attestation key or the endorsement key is not this TPM's

Verify the enrollment
---------------------

1. Verify the evidence with both key names, the credential and the
   enrolled certificates:

   .. guide-check: match activated the credential

   .. code-block:: console

      operator$ shirudo attest verify --evidence="$RESULT/enrolled.json" --nonce="$NONCE2" --ak-name="$AK" --ek-name="$EK" --expect-credential="$CRED" --cert="$KEYS/cert.der" --cert="$OWN" --allow-runtime-events
        OK    nonce matches the request
        OK    attestation key: restricted, fixed to this TPM
        OK    attestation key: name matches its public area
        OK    attestation key: the pinned key
        OK    endorsement key: name matches its public area
        OK    endorsement key: TCG default template under the endorsement policy
        OK    endorsement key: the pinned key
        OK    attestation key: activated the credential made for it under the endorsement key
      ...
        OK    eventlog: 7 records replay to the certified value
        OK    anchor: record digest matches the index name
        OK    anchor: PCR 9 equals the recorded value extended by the anchor
        OK    state: init event covers the expected certificate, set and tree root
        OK    state: 6 events after boot change the register
        NOTE  event after boot: upatch_load basic
        NOTE  event after boot: upatch_unload basic
      ...
      verdict: ok

   The credential proves that the attestation key sits in the same TPM
   as the endorsement key. ``--cert`` gives every certificate the target
   enrolled, and the boot event must cover exactly that set.
   ``--allow-runtime-events`` accepts the loads and unloads after boot
   without checking them.

2. Record ``$AK`` and ``$EK`` with the target's other records. They are
   its identity from now on. Every later verification pins the signer
   with ``--ak-name``, and the credential needs no second check.

Predict the register
--------------------

1. Predict the register at boot from the enrolled certificates:

   .. code-block:: console

      operator$ shirudo attest predict --cert="$KEYS/cert.der" --cert="$OWN"
      set_digest: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      init_event: cb206abf8e514bc714fc69f372d464d2c7512f1489431aed2319551c5ed34b9a
      register_at_boot: d1bdb80f7c0cfc1560f0a5a0b974d282bfd05fc95852b7649d59a054b450aa51

   Your values differ, because the bundle generated your keys. The boot
   event covers the digest of the whole enrolled set. With one
   certificate missing, the prediction describes another target:

   .. code-block:: console

      operator$ shirudo attest predict --cert="$KEYS/cert.der"
      set_digest: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      init_event: 1014642f2d76b1eb10b4872c4299a70e191be0eb2958de65a7098bfe92a93124
      register_at_boot: 33ec2c3ed20693c2e40131e693a11b169b91efd8f7438f86313c915e512121e5

   Verifying against that set fails with ``FAIL  state: init event
   covers the expected certificate, set and tree root``.

2. Add the events since boot, in their order:

   .. guide-check: capture register-after-events

   .. code-block:: console

      operator$ shirudo attest predict --cert="$KEYS/cert.der" --cert="$OWN" --event=load:basic="$PAYLOAD" --event=unload:basic="$PAYLOAD"
      set_digest: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      init_event: cb206abf8e514bc714fc69f372d464d2c7512f1489431aed2319551c5ed34b9a
      register_at_boot: d1bdb80f7c0cfc1560f0a5a0b974d282bfd05fc95852b7649d59a054b450aa51
      register_after_events: fe7bd139c02aca0d6e5efc3940c1cd902adbe676b7875be4c73c878b3f5212b8

   ``register_after_events`` is the register value after the load and the
   unload: the value the unload printed in the quickstart, and the
   ``Chain`` that ``shirudo status`` shows on the target. If you followed
   other quick guides on this VM, the target measured their loads and
   unloads too. Add them in the order you ran them, each with the payload
   digest of its upatch.

Verify evidence
---------------

1. Make a fresh nonce:

   .. guide-check: capture nonce3

   .. code-block:: console

      operator$ NONCE3=$(openssl rand -hex 32)
      operator$ echo "$NONCE3"

2. Take evidence with it on the target:

   .. code-block:: console

      target# shirudo attest --nonce=<nonce3> --output=/mnt/shirudo-out/ev.json

3. Verify it with the pinned key and the predicted register:

   .. guide-check: match ^verdict: ok$

   .. code-block:: console

      operator$ shirudo attest verify --evidence="$RESULT/ev.json" --nonce="$NONCE3" --ak-name="$AK" --expect-chain=<register-after-events>
        OK    nonce matches the request
      ...
        OK    eventlog: 7 records replay to the certified value
        OK    anchor: record digest matches the index name
        OK    anchor: PCR 9 equals the recorded value extended by the anchor
        OK    state: register equals the expected value
        NOTE  event after boot: upatch_load basic
        NOTE  event after boot: upatch_unload basic
      ...
      verdict: ok

   ``<register-after-events>`` is the last value of the prediction.

``attest verify`` requires only ``--evidence`` and ``--nonce``. Without
``--ak-name`` it warns ``attest verify: no --ak-name; the signer is not
pinned``. Without a state expectation it checks no state at all, yet
still reports ``verdict: ok``:

.. guide-check: match ^verdict: ok$

.. code-block:: console

   operator$ shirudo attest verify --evidence="$RESULT/ev.json" --nonce="$NONCE3" --ak-name="$AK"
   ...
     OK    anchor: PCR 9 equals the recorded value extended by the anchor
     NOTE  no expected state given; the register value is 52764aa4e68b762c7e5bbacf1261bd3242b44a0b66876f34c89c5b8d57da7177
     NOTE  event after boot: upatch_load basic
   ...
   verdict: ok

That verdict says only that the pinned TPM signed some state. Always give
``--ak-name`` and a state expectation: ``--expect-chain``, or ``--cert``
with ``--upatch`` or ``--expect`` for the upatches restored at boot. The
threat model lists this behavior among the threats to resolve.

Next steps
----------

- :doc:`/operate/run/attest` attests production targets, with the binding
  PCRs and the approved config image.
- :doc:`/concepts/measurement-register` explains the register, its events
  and its binding.
- :doc:`/reference/cli/attest-verify` lists every check and option of
  ``shirudo attest verify``.
- :doc:`/security/threat-model` describes what attestation covers and
  what it leaves open.
