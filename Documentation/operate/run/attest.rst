..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators, SecOps

Attest targets
==============

``shirudo status`` is the target's own account of itself, and a target
that root controls can say anything. Attestation gives you an account
the target cannot forge: the TPM signs the measurement register and the
PCRs for a nonce you chose, and you check the signature and the values
on the operator host against what you installed.

This page enrolls a target once, then collects and verifies evidence.
Enrollment records the names of the TPM's attestation key and
endorsement key, and there are two ways to trust them:

- `Enroll from a target activation`_: the target answers a credential
  challenge, which the TPM can only answer when the attestation key is in
  the TPM that holds an endorsement key you vouch for. Use it when the
  TPM has a manufacturer's endorsement certificate or you hold its
  endorsement key name.
- `Enroll from a builder's records`_: the hypervisor or provisioning step
  that created the TPM's keys records their names before handover, with
  no exchange with the target. Use it when you trust that builder.

Either way, every later verification pins those names. The checks only
mean something when you pin the values the target reports about itself,
so the verification step lists the options you must pass.

Before you begin
----------------

- The operator package on the operator host. ``attest verify``,
  ``attest predict`` and ``attest challenge`` run there, offline. They
  need no TPM. A target running shirudo refuses any argument that starts
  with ``--cert``, so do not run them on a target.
- A target that completed init: ``shirudo status`` reports ``ok``.
  :doc:`/operate/run/read-status` explains the report.
- On the target, ``shirudo`` is the runtime image's binary, as
  :ref:`runtime-invocation` sets up.
- For enrollment: the PEM bundle of your TPM manufacturer's
  endorsement key issuers, or the endorsement key name from an
  inventory you trust.
- Your records of what the target runs: the certificates it enrolled,
  the upatches it restored at boot, every load and unload since, and the
  root hash of the config you activated.

What a verifier must pin
------------------------

``shirudo attest verify`` checks that the evidence is consistent and
signed by a TPM. Whether it is the right TPM and the right state is up
to the options you pass. Without them, any TPM that signs a consistent
document passes, as `A verify that pins nothing`_ shows.

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Option
     - What it pins
   * - ``--ak-name=<ak-name>``
     - Required. The attestation key that signed the quote and the
       register certification is the one you enrolled. Without it, any
       TPM's key passes.
   * - ``--expect-bind-pcr=9=<pcr9>`` and ``--expect-bind-pcr=11=<pcr11>``
     - Required. The PCR values the register was bound to at init. PCR
       11 holds the ``enter-initrd`` phase only while the initrd runs, so
       the PCR 11 value proves that init bound the register from the
       initrd. Without them, verify recomputes the register's name from
       the values the target recorded about itself.
   * - ``--require-initrd``
     - Optional. The init record says the binding was made in the
       initrd. The record is the target's own word, so this option does
       not replace ``--expect-bind-pcr=11``.
   * - ``--expect-chain=<register>``, or ``--cert=`` with ``--upatch=``
     - Required, one of the two. The register equals the value you
       predicted for the certificates, the boot set and the events you
       expect. Without either, no state is checked.
   * - ``--expect-config-root=<config-root>`` with
       ``--expect-config-pcr=<config-pcr>``
     - Required. The config the target activated is the one you
       approved, recorded in the PCR the runtime bootstrap file names.
       The first option needs the second.
   * - ``--ek-name=<ek-name>``
     - Optional. The endorsement key in the evidence is the enrolled
       one.
   * - ``--expect-credential=<credential>``
     - At enrollment. The attestation key activated the credential you
       made for it under the endorsement key. Needs ``--ak-name``.
   * - ``--allow-runtime-events``
     - Optional. With ``--cert=``, accepts any number of loads, unloads,
       revocations and tree operations after boot, as long as each one
       replays and derives from its own fields. It does not compare them
       with anything you expect. Pin runtime events with
       ``--expect-chain`` instead.
   * - ``--strict-anchor``
     - Optional. Nothing was extended into PCR 9 after the register's
       anchor. Without it, verify notes further measurements and passes.

Record these values for each target. Each comes from its own source and
changes for its own reason, and a verify against an old value fails.

.. list-table:: Values to record for each target
   :header-rows: 1
   :widths: 22 24 30 24

   * - Value
     - Option
     - Where you get it
     - Changes when
   * - Attestation key name
     - ``--ak-name``
     - Enrollment, `Enroll from a target activation`_ or `Enroll from a
       builder's records`_.
     - The TPM changes, or a virtual TPM gets fresh state.
   * - Endorsement key name
     - ``--ek-name``
     - Enrollment, as above.
     - As above.
   * - PCR 9 and PCR 11 at the binding
     - ``--expect-bind-pcr=9=`` and ``--expect-bind-pcr=11=``
     - ``tpm.pcr_before`` and ``tpm.phase_before`` of ``shirudo status
       --json`` on a boot of the same UKI on a host you trust, see
       `Verify evidence`_.
     - The UKI changes: a new kernel, initrd, command line or runtime
       image.
   * - Register
     - ``--expect-chain=``
     - ``shirudo attest predict`` from your records, see `Predict the
       register`_.
     - Every boot set change, load, unload, revocation and tree
       operation.
   * - Config root
     - ``--expect-config-root=``
     - ``<prefix>.roothash`` of the config you activated.
     - Every config you activate, live or by staging it and a reboot.
   * - Config PCR
     - ``--expect-config-pcr=``
     - ``config.pcr`` of the runtime bootstrap file.
     - A runtime image with another ``config.pcr``.

Enroll from a target activation
-------------------------------

Enroll a target once per TPM. You record the name of its attestation
key and prove that the key sits in the same TPM as an endorsement key
you trust. When a builder you trust created the TPM's keys, its records
can take the place of these steps (`Enroll from a builder's records`_).
Figure 1 shows the steps: two runs of ``attest``, each with its own
nonce, and a challenge in between.

.. figure:: /images/operate-attest-activation.svg
   :alt: The operator sends a nonce; the target has the TPM create the
         attestation key and the endorsement key and returns enroll.json.
         The operator makes a challenge for an endorsement key it vouches
         for and sends it with a second nonce. The TPM releases the
         credential only to that attestation key under that endorsement
         key, and the target returns answer.json. The operator verifies
         the credential and records both names in its inventory.

   Figure 1. Enrolling through credential activation. The TPM proves to
   the operator that the attestation key is in it.

1. Choose a nonce on the operator host:

   .. code-block:: console

      operator$ openssl rand -hex 32

2. Collect evidence on the target, with that nonce:

   .. code-block:: console

      target# shirudo attest --nonce=<nonce> --output=enroll.json

   ``<nonce>`` is the hex string from step 1. The command prints nothing
   on success and writes the file with mode ``0600``. Copy
   ``enroll.json`` to the operator host.

3. Read the names of the attestation key and the endorsement key:

   .. code-block:: console

      operator$ jq -r .ak.name enroll.json
      operator$ jq -r .ek.name enroll.json

4. Make a credential challenge for that attestation key under the
   endorsement key:

   .. code-block:: console

      operator$ shirudo attest challenge --evidence=enroll.json \
          --ak-name=<ak-name> --ek-ca=<ek-issuers.pem> --output=challenge.json

   ``<ak-name>`` is the name from step 3. ``<ek-issuers.pem>`` is your
   manufacturer's issuer bundle. The endorsement certificate in the
   evidence must chain to it. A TPM without an endorsement certificate,
   as virtual TPMs usually are, needs ``--ek-name=<ek-name>`` from an
   inventory you trust instead. ``--trust-presented-ek`` waives the
   check and proves only that the same TPM answers each time. The
   command prints its checks, then ``challenge: challenge.json`` and
   ``credential: <credential>``. Keep the credential on the operator
   host.

5. Copy ``challenge.json`` to the target and answer it, with a new
   nonce:

   .. code-block:: console

      target# shirudo attest --nonce=<nonce-2> --challenge=challenge.json \
          --output=answer.json

   The TPM can recover the credential only when the attestation key and
   the endorsement key are in it. The command refuses with
   ``attest: the TPM refused the challenge; the attestation key or the
   endorsement key is not this TPM's`` otherwise.

6. Verify the answer on the operator host:

   .. code-block:: console

      operator$ shirudo attest verify --evidence=answer.json --nonce=<nonce-2> \
          --ak-name=<ak-name> --ek-name=<ek-name> --expect-credential=<credential>

   The report must contain
   ``OK    attestation key: activated the credential made for it under the endorsement key``
   and end with ``verdict: ok``.

7. Record ``<ak-name>`` and ``<ek-name>`` for this target in your
   inventory. Every later verification pins them.

8. If you run the keepalive backend, mark the key as enrolled, so that
   the node reads ``enrolled`` rather than ``untrusted``
   (:doc:`/operate/backend/index`):

   .. code-block:: console

      operator$ clickhouse-client --query "INSERT INTO shirudo.nodes \
          (ak_name, trust) VALUES ('<ak-name>', 'enrolled')"

Enroll from a builder's records
-------------------------------

Credential activation lets you learn from the target that its
attestation key is in a TPM you trust. When a builder you trust controls
the TPM before the target gets it, such as the hypervisor that creates a
virtual TPM or a provisioning step before deployment, the builder can
record the names itself, and enrollment needs no challenge.

The builder then becomes part of what you trust, and for a virtual TPM
so does the host that runs it. The attestation key's name is trusted
because the builder saw the key created in that TPM, and the key is fixed
to it, so no other TPM can sign with it. Nothing in the evidence ties the
endorsement key to the attestation key on this path: ``--ek-name`` checks
only the endorsement key the target reports.

Figure 2 shows the path: the builder records the names once, before
handover, and every attestation after that is a nonce, the evidence and a
verify that pins them.

.. figure:: /images/operate-attest-builder.svg
   :alt: Before handover, the builder has the TPM create the attestation
         key and the endorsement key from attest's templates and gives
         their names to the operator's inventory. For every attestation,
         the operator sends a nonce, the target has the TPM create the
         same attestation key, certify the registers on both sides of a
         PCR quote, and return the evidence document, which the
         operator verifies with the recorded names. There is no
         credential challenge.

   Figure 2. Enrolling from a builder's records. The builder, not the
   TPM, vouches for the names.

The steps below are for a virtual TPM run by swtpm, before the guest's
first boot. They need swtpm and tpm2-tools on the builder host.
``<state-dir>`` is the directory that holds the guest's TPM state, the
one QEMU's or libvirt's swtpm will use.

1. Create the TPM state, unless the guest already has some:

   .. code-block:: console

      builder$ swtpm_setup --tpm2 --tpmstate <state-dir> --createek

2. Run swtpm on that state, with the guest stopped:

   .. code-block:: console

      builder$ swtpm socket --tpm2 --tpmstate dir=<state-dir> \
          --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
          --flags not-need-init,startup-clear --pid file=swtpm.pid --daemon
      builder$ export TPM2TOOLS_TCTI=swtpm:port=2321

3. Create the attestation key from the template ``attest`` uses, and save
   its public area:

   .. code-block:: console

      builder$ tpm2_createprimary -C e -g sha256 -G ecc256:ecdsa-sha256:null \
          -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign' \
          -c ak.ctx
      builder$ tpm2_readpublic -c ak.ctx -o ak.pub
      builder$ tpm2_flushcontext -t

4. Create the endorsement key from the TCG default template, and save its
   public area:

   .. code-block:: console

      builder$ tpm2_createek -c - -G ecc -u ek.pub

   The evidence carries the ECC endorsement key unless the TPM's only
   endorsement certificate is RSA; use ``-G rsa`` for such a TPM.

5. Compute the two names, ``000b`` and the SHA-256 of each public area:

   .. code-block:: console

      builder$ echo 000b$(tail -c +3 ak.pub | sha256sum | cut -c1-64)
      builder$ echo 000b$(tail -c +3 ek.pub | sha256sum | cut -c1-64)

   The first line is ``<ak-name>``, the second ``<ek-name>``.

6. Shut the TPM down in order and stop swtpm, which saves the state.
   swtpm releases ``<state-dir>`` only when its process exits, so wait
   for that before the guest's swtpm opens it, then start the guest:

   .. code-block:: console

      builder$ tpm2_shutdown
      builder$ pid=$(cat swtpm.pid)
      builder$ swtpm_ioctl --tcp :2322 -s
      builder$ while kill -0 "$pid" 2>/dev/null; do sleep 0.1; done

7. Record both names for this target in your inventory. Take them from
   the builder, never from the target.

8. If you run the keepalive backend, enroll the key from the builder's
   names with :doc:`/operate/backend/enroll-put`, which also names the
   node and keeps the binding. It can run before the target first boots;
   its first keepalive joins it:

   .. code-block:: console

      operator$ printf '{"source": "%s", "nodes": [{"ak_name": "%s", "ek_name": "%s", "node_id": "%s"}]}' \
          <builder> <ak-name> <ek-name> <node-id> | tools/backend/jobs/enroll-put -

9. Verify every evidence document with the recorded names, as
   `Verify evidence`_ shows. There is no credential to expect:

   .. code-block:: console

      operator$ shirudo attest verify --evidence=ev.json --nonce=<nonce> \
          --ak-name=<ak-name> --ek-name=<ek-name> \
          --expect-bind-pcr=9=<pcr9> --expect-bind-pcr=11=<pcr11> \
          --require-initrd --expect-chain=<register> \
          --expect-config-root=<config-root> --expect-config-pcr=<config-pcr>

For a physical TPM a provisioning step controls, skip steps 1, 2 and 6
and leave ``TPM2TOOLS_TCTI`` unset, so that tpm2-tools uses the TPM
device. The names are the TPM's own and stay with it.

A virtual TPM cloned with its state presents the original's keys, so give
each clone fresh state and record its own names. A migration that keeps
the state keeps the names, and ``TPM2_Clear`` changes neither.

A builder that records only the endorsement key's name still saves the
endorsement certificate check: pass that name as ``--ek-name`` in step 4
of `Enroll from a target activation`_, and the challenge proves that the
attestation key is in that TPM.

Predict the register
--------------------

Compute the register value the target should hold from your own
records, never from the target's eventlog.

1. Read the payload digest of every upatch you loaded after boot:

   .. code-block:: console

      operator$ shirudo upatch info --json <upatch> | jq -r .payload_sha256

   ``<upatch>`` is the ``.upatch`` file you loaded.

2. Predict the register:

   .. code-block:: console

      operator$ shirudo attest predict --cert=cert.der --cert=own.der \
          --event=load:basic=46f3d9f5f6568bddb7692cad28e99a86a3104192d8a2251f9ef9ec6d593c2035
      set_digest: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      init_event: cb206abf8e514bc714fc69f372d464d2c7512f1489431aed2319551c5ed34b9a
      register_at_boot: d1bdb80f7c0cfc1560f0a5a0b974d282bfd05fc95852b7649d59a054b450aa51
      register_after_events: ff0eb201e073fdeeba80a4b268f039bea58ec6dd2998e6651c4834ee99f3e103

   Pass one ``--cert=`` for each certificate the target enrolled: the
   runtime primary and each vouched certificate of the selected config,
   without the revoked ones. Pass one ``--upatch=`` for each upatch the
   target restored at boot. Pass one ``--event=`` for each change after
   boot, in
   order: ``load:<name>=<payload-sha256>``,
   ``unload:<name>=<payload-sha256>``,
   ``revoke:<label>=<cert-sha256>`` or ``tree:<seq>=<digest>``.

   ``set_digest`` covers the boot set, ``init_event`` is the init
   record's digest and ``register_at_boot`` is the register right after
   init. ``register_after_events`` is the value to pin with
   ``--expect-chain``. Without events, pin ``register_at_boot``. The
   test target in the example enrolled two certificates, ``cert.der`` and
   ``own.der``, restored no upatch at boot and loaded one after.

Collect evidence
----------------

1. Choose a fresh nonce on the operator host:

   .. code-block:: console

      operator$ openssl rand -hex 32

2. Collect the evidence on the target:

   .. code-block:: console

      target# shirudo attest --nonce=<nonce> --output=ev.json

   The evidence holds the TPM quote of PCRs 0 to 7, 9 and 11 to 15, the
   certified register, this boot's eventlog records and the config
   activation history. ``--pcrs=`` selects other PCRs. The command
   refuses while a config activation is pending or cannot be verified,
   and when the register is not bound this boot.

3. Copy ``ev.json`` to the operator host.

Verify evidence
---------------

1. Get the binding values for the UKI the target booted: the PCR 9 and
   PCR 11 values at the moment init bound the register. Record them from
   a boot of the same UKI on a host you trust, where they are the
   ``tpm.pcr_before`` and ``tpm.phase_before`` fields of
   ``shirudo status --json``. systemd's
   ``systemd-measure calculate --phase=enter-initrd`` also computes the
   PCR 11 value from the UKI's sections.

2. Verify the evidence with every value pinned:

   .. code-block:: console

      operator$ shirudo attest verify --evidence=ev.json --nonce=<nonce> \
          --ak-name=<ak-name> --ek-name=<ek-name> \
          --expect-bind-pcr=9=<pcr9> --expect-bind-pcr=11=<pcr11> \
          --require-initrd --expect-chain=<register> \
          --expect-config-root=<config-root> --expect-config-pcr=<config-pcr>

   ``<register>`` is the value from `Predict the register`_.
   ``<config-root>`` is the content of ``<prefix>.roothash`` of the config
   you activated. ``<config-pcr>`` is ``config.pcr`` of the runtime
   bootstrap file.

3. Check the exit status: 0 for ``verdict: ok``, 1 for ``verdict: fail``
   and 2 for a usage error or a file that is not an evidence document.

The report prints one line per check, ``OK`` or ``FAIL``, and ``NOTE``
lines that check nothing. This is a real report from a test target,
verified with ``--ak-name`` and ``--expect-chain`` only:

.. code-block:: console

   operator$ shirudo attest verify --evidence=ev.json --nonce=$NONCE \
       --ak-name=<ak-name> --expect-chain=<register>
     OK    nonce matches the request
     OK    attestation key: restricted, fixed to this TPM
     OK    attestation key: name matches its public area
     OK    attestation key: the pinned key
     OK    endorsement key: name matches its public area
     OK    endorsement key: TCG default template under the endorsement policy
     OK    quote: ECDSA signature by the attestation key
     OK    quote: signed by the key as an endorsement primary
     OK    quote: carries the expected challenge
     OK    quote: covers the PCRs the document lists
     OK    quote: PCR digest matches the listed values
     OK    register: ECDSA signature by the attestation key
     OK    register: signed by the key as an endorsement primary
     OK    register: carries the expected challenge
     OK    register: certification names the listed index
     OK    register: certified contents match the listed value
     OK    quote and certification are of one TPM boot
     OK    register after quote: ECDSA signature by the attestation key
     OK    register after quote: signed by the key as an endorsement primary
     OK    register after quote: carries the expected challenge
     OK    register after quote: same index and value on both sides of the PCR quote
     OK    config: config root history matches the quoted PCR
     NOTE  config root has no operator approval; use --expect-config-root with --expect-config-pcr
     NOTE  config records a selection; operation completion depends on trusted runtime guards
     OK    eventlog: this boot has an init record
     OK    register: the document names index 0x01818E00 and PCRs 9 and 11
     OK    register: public area is bound to PCRs 9 and 11 as recorded
     NOTE  binding: made in the initrd
     OK    eventlog: one init record for this TPM reset (1 this boot)
     OK    register: init record is of the TPM's current reset count
     OK    eventlog: 2 records replay to the certified value
     OK    anchor: record digest matches the index name
     OK    anchor: PCR 9 equals the recorded value extended by the anchor
     OK    state: register equals the expected value
     NOTE  event after boot: upatch_load basic
   verdict: ok

Read it in groups:

- The nonce, attestation key and endorsement key lines say the TPM you
  enrolled signed this evidence for your request.
- The quote and register lines say the PCR values and the register
  value were present together when the TPM signed the quote.
- The config lines replay the config activation history to the quoted
  config PCR. The note says no root was pinned: this run left out
  ``--expect-config-root``.
- The eventlog and binding lines replay this boot's records to the
  certified register and recompute the register's name from the PCR
  values it was bound to. ``note  binding: made in the initrd`` is the
  target's own claim. With ``--expect-bind-pcr``, the report adds
  ``binding: PCR 9 held the expected value`` and the same line for
  PCR 11, which check the binding against values you know.
- ``state: register equals the expected value`` is the line that ties
  the evidence to your records. The ``event after boot`` notes list what
  changed the register since init.

With ``--expect-config-root``, the config line checks that the last
activation recorded is your root.

What failure looks like
~~~~~~~~~~~~~~~~~~~~~~~

A wrong or stale nonce fails the first check, and the verdict follows:

.. code-block:: console

   operator$ shirudo attest verify --evidence=ev.json --nonce=<wrong-nonce> \
       --ak-name=<ak-name>
     FAIL  nonce matches the request
     OK    attestation key: restricted, fixed to this TPM
   ...
   verdict: fail

A target whose state differs from your records fails the state lines.
This report is from a second test target. The verifier expected the boot
set only, but a load and an unload happened after boot:

.. code-block:: console

   operator$ shirudo attest verify --evidence=ev.json --nonce=$NONCE \
       --ak-name=<ak-name> --cert=cert.der --require-initrd --strict-anchor
   ...
     OK    binding: made while the initrd ran
     OK    eventlog: one init record for this TPM reset (1 this boot)
     OK    register: init record is of the TPM's current reset count
     OK    eventlog: 3 records replay to the certified value
     OK    anchor: record digest matches the index name
     OK    anchor: PCR 9 equals the recorded value extended by the anchor
     FAIL  state: init event covers the expected certificate, set and tree root
     FAIL  state: 2 events after boot change the register
     NOTE  event after boot: upatch_load shirudo-test-basic
     NOTE  event after boot: upatch_unload shirudo-test-basic
   verdict: fail

The init event line fails too, because that target enrolled two
certificates and the verifier passed one. A failed state check does not
tell you which side is wrong. Compare the notes with your records before
you conclude anything, and follow :doc:`/operate/troubleshoot/incident-tampered`
when the target ran something you did not install.

A verify that pins nothing
~~~~~~~~~~~~~~~~~~~~~~~~~~

Evidence from the second test target above, verified with only the
evidence and the nonce:

.. code-block:: console

   operator$ shirudo attest verify --evidence=ev.json --nonce=$NONCE
   attest verify: no --ak-name; the signer is not pinned
     OK    nonce matches the request
     OK    attestation key: restricted, fixed to this TPM
     OK    attestation key: name matches its public area
     NOTE  attestation key not pinned: name 000b6e354140b22198138167393ecd1233cfc27e8b16ef0b2b60cce88563c5588dbc
   ...
     NOTE  no expected state given; the register value is e57e1428ab398e758b63f8eda52bac87b5d85c1368c2d8d786ed446448e46239
     NOTE  event after boot: upatch_load shirudo-test-basic
     NOTE  event after boot: upatch_unload shirudo-test-basic
   verdict: ok

The verdict is ``ok`` and the exit status 0, but the run proves only
that some TPM signed a consistent document for this nonce. A consistent
document from any TPM passes, whatever the target runs. Treat a
verification without ``--ak-name`` and without an expected state as no
verification.

Next steps
----------

- :doc:`/operate/troubleshoot/incident-tampered` when a target refuses with
  ``tampered`` or fails verification
- :doc:`/reference/cli/attest`, :doc:`/reference/cli/attest-verify`,
  :doc:`/reference/cli/attest-predict` and
  :doc:`/reference/cli/attest-challenge` for every option
- :doc:`/concepts/measurement-register` and
  :doc:`/internals/measurement-register` for what the register records
- :doc:`/security/threat-model` for what attestation does not cover
