..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

status JSON
===========

``shirudo status --json`` prints one JSON object on one line. The
status keepalive that ``status --otel`` sends carries a smaller record,
the keepalive body that ``status --keepalive`` prints, see
:ref:`keepalive-body-format`. Options and exit status are in
:doc:`/reference/cli/status`. How to read a report is in
:doc:`/operate/run/read-status`.

.. code-block:: console

   target# shirudo status --json

``status`` exits ``0`` for every verdict, ``tampered`` included, unless
``--check`` is given, which exits ``1`` for ``tampered``. A monitor
reads ``status`` and the fields in `Fields to alert on`_, never the
exit status alone.

Top-level fields
----------------

Fields appear in this order. ``null`` stands for a value that cannot be
determined, as noted.

.. list-table::
   :header-rows: 1
   :widths: 26 16 58

   * - Field
     - Type
     - Value
   * - ``schema``
     - integer
     - ``1``
   * - ``version_id``
     - string
     - The binary's ``SHIRUDO_VERSION_ID``, as
       ``shirudo version --version-id`` prints it.
   * - ``host``
     - string
     - The host name, with U+FFFD for each byte that is no UTF-8.
   * - ``is_target``
     - boolean
     - ``true`` when the certificate is present, the LSM link is
       pinned or the ``.bpf`` keyring ``init`` recorded exists.
   * - ``is_operator``
     - boolean
     - ``true`` when ``/var/lib/shirudo/keys/signing_key.pem`` exists.
   * - ``status``
     - string
     - The verdict, see `Verdicts`_.
   * - ``reason``
     - string or ``null``
     - The reason the human report prints after the verdict, ``null``
       for ``ok``, see `Verdicts`_.
   * - ``conditions``
     - array of object
     - Seven conditions, each with ``type``, ``status`` and ``detail``,
       see `Conditions`_.
   * - ``lsm_attached``
     - boolean
     - ``true`` when the pin ``/run/shirudo/bpffs/lsm_link`` opens.
   * - ``enforcement``
     - string or ``null``
     - ``strict`` or ``shared``, as ``init`` froze it in the identity
       record from the runtime image's ``enforcement.mode``. ``null``
       when there is no record, see :doc:`/internals/enforcement`.
   * - ``keyring_mode``
     - string
     - ``bpf`` when the ``.bpf`` keyring is present, else ``none``.
   * - ``keyring_present``
     - boolean
     - ``true`` when ``init`` recorded a keyring serial and the
       ``.bpf`` keyring exists.
   * - ``keyring_serial``
     - integer or ``null``
     - Serial of the live ``.bpf`` keyring. ``null`` when it is absent.
   * - ``keyring_serial_pinned``
     - integer or ``null``
     - Serial ``init`` froze in the identity pin. ``null`` before
       ``init``.
   * - ``keyring_serial_matches``
     - boolean or ``null``
     - ``keyring_serial`` equals ``keyring_serial_pinned``. ``null``
       unless both are known.
   * - ``cert_present``
     - boolean
     - The primary certificate exists: on an image target
       ``/run/shirudo/runtime/keys/cert.der``.
   * - ``certs``
     - array of object
     - The trusted certificate set, each with ``sha256`` (of the DER),
       ``fingerprint`` (SHA-256 of the public key) and ``primary``
       (boolean). Empty when the set cannot be loaded.
   * - ``certs_revoked``
     - integer
     - Certificates under ``keys/revoked``.
   * - ``certs_unvouched``
     - integer
     - Certificates under ``keys/trusted`` without a valid vouch.
   * - ``certs_enrolled``
     - integer or ``null``
     - Asymmetric keys in the ``.bpf`` keyring. ``null`` when the
       keyring is absent.
   * - ``bpf_keyring``
     - object
     - The ``.bpf`` keyring, its trusted certificates and their keys,
       see `Keyrings`_.
   * - ``dm_verity_keyring``
     - object
     - The ``.dm-verity`` keyring, its config certificates and their keys,
       see `Keyrings`_.
   * - ``signing_key_present``
     - boolean
     - Same value as ``is_operator``.
   * - ``upatches_loaded``
     - array of object
     - One object per upatch pinned under
       ``/run/shirudo/bpffs/upatches``, then one per loaded Java agent,
       see `upatches_loaded`_.
   * - ``assets``
     - object
     - Persistent state, see `assets`_.
   * - ``tamper_attempts``
     - object or ``null``
     - Attempts counted this boot, refused except ``SealSignal``, see
       `tamper_attempts`_. ``null``
       until ``init`` has pinned the counters.
   * - ``integrity_attempts``
     - object or ``null``
     - Changes or reads of the running kernel refused this boot, see
       `integrity_attempts`_. ``null`` until ``init`` has pinned the
       counters.
   * - ``config``
     - object or ``null``
     - Config image activation, see `config`_. ``null`` on a host
       without config activation state.
   * - ``system``
     - object
     - Only with ``--include-system``, see `Optional blocks`_.
   * - ``tpm``
     - object
     - The measurement register, see `tpm`_.
   * - ``upatch_tree``
     - object
     - The upatch tree, see `upatch_tree`_.

.. _status-json-verdicts:

Verdicts
--------

``status`` takes the first verdict in this order whose condition holds,
and ``reason`` names the first of its causes that applies, in the order
of the table. ``reason`` is ``null`` for ``ok``. The third column names
the condition that is not ``OK`` with it.

.. list-table::
   :header-rows: 1
   :widths: 16 50 34

   * - ``status``
     - ``reason``
     - Condition
   * - ``tampered``
     - ``live register differs from the eventlog replay``
     - ``ChainIntact`` ``ALERT``
   * -
     - ``the archive of a loaded XDP upatch differs from what was
       loaded``
     - ``UpatchesMeasured`` ``ALERT``
   * -
     - ``a loaded upatch is missing a link or its archive``
     - ``UpatchesMeasured`` ``ALERT``
   * -
     - ``a upatch is pinned or archived without a record of this boot``
     - ``UpatchesMeasured`` ``ALERT``
   * -
     - ``this boot's records do not fold to the measurement register``
     - ``UpatchesMeasured`` ``ALERT``
   * -
     - ``the selected config cannot be verified against its records``
     - ``ConfigActive`` ``ALERT``
   * -
     - ``the keyring init froze is gone``: the ``.bpf`` keyring
     - ``KeyringSealed`` ``ALERT``
   * -
     - ``keyring serial swap detected``: the ``.bpf`` keyring's serial
       differs from the one ``init`` pinned
     - ``KeyringSealed`` ``ALERT``
   * -
     - ``the dm-verity keyring init froze is gone``
     - ``KeyringSealed`` ``ALERT``
   * -
     - ``dm-verity keyring serial swap detected``
     - ``KeyringSealed`` ``ALERT``
   * -
     - ``a keyring holds a link init did not freeze``: ``.bpf`` or
       ``.dm-verity``
     - ``KeyringSealed`` ``ALERT``
   * -
     - ``the config key init froze is gone``: from ``.dm-verity``
     - ``KeyringSealed`` ``ALERT``
   * - ``lsm-off``
     - ``LSM not attached, enforcement off``: the LSM link is not pinned
     - ``LsmAttached`` ``ALERT``
   * - ``init-pending``
     - ``.bpf keyring absent before init``: ``init`` has not completed
     - ``KeyringSealed`` ``WARN``
   * - ``reboot-pending``
     - ``a config activation is pending until the next reboot``
     - ``ConfigActive`` ``WARN``
   * - ``degraded``
     - ``no TPM answered``
     - ``ChainIntact`` and ``TpmMeasured`` ``WARN``
   * -
     - ``no register bound this boot``: a TPM answered, but the NV index
       is not written
     - ``ChainIntact`` and ``TpmMeasured`` ``WARN``
   * -
     - ``a device an XDP upatch selects does not run it``
     - ``XdpCovered`` ``WARN``
   * - ``ok``
     - ``null``: none of the above
     - No condition at ``ALERT``

Conditions
----------

``conditions`` always holds these seven types, in this order. ``status``
is ``OK``, ``WARN`` or ``ALERT``. ``<serial>``, ``<n>`` and ``<root>``
stand for a keyring serial, a number of links and the first 12 hex
digits of the config root hash. ``KeyringSealed`` reports the first of
its details that applies, in the order listed. A detail is at most 191
bytes: a longer one, such as a long list of names, is cut and ends with
``...``.

.. list-table::
   :header-rows: 1
   :widths: 18 10 72

   * - ``type``
     - ``status``
     - ``detail``
   * - ``LsmAttached``
     - ``OK``
     - ``lsm/bpf link present and pinned``
   * -
     - ``ALERT``
     - ``lsm/bpf link absent, enforcement off``
   * - ``KeyringSealed``
     - ``ALERT``
     - ``pinned serial <serial>, the .bpf keyring is gone``
   * -
     - ``WARN``
     - ``.bpf keyring absent before init``
   * -
     - ``ALERT``
     - ``pinned serial <serial>, live serial <serial>: swapped``
   * -
     - ``ALERT``
     - ``the BPF keyring holds <n> link(s) init did not freeze``
   * -
     - ``ALERT``
     - ``dm-verity pinned serial <serial>, the dm-verity keyring is
       gone``
   * -
     - ``ALERT``
     - ``dm-verity pinned serial <serial>, live serial <serial>:
       swapped``
   * -
     - ``ALERT``
     - ``the dm-verity keyring holds <n> link(s) init did not freeze``
   * -
     - ``ALERT``
     - ``a config key init froze is gone from the dm-verity keyring``
   * -
     - ``OK``
     - ``bpf serial <serial>, dm-verity serial <serial>, pins match``
   * -
     - ``OK``
     - ``bpf serial <serial>, pin matches``, when ``init`` recorded no
       ``.dm-verity`` serial
   * -
     - ``OK``
     - ``bpf serial <serial>, no pin recorded``
   * - ``ChainIntact``
     - ``OK``
     - ``live register equals the eventlog replay``
   * -
     - ``WARN``
     - ``no register bound this boot (init incomplete)``
   * -
     - ``WARN``
     - ``no TPM answered, no register to replay``
   * -
     - ``WARN``
     - ``chain present, replay not evaluated``
   * -
     - ``ALERT``
     - ``live register differs from the eventlog replay``
   * - ``UpatchesMeasured``
     - ``OK``
     - ``every pinned or archived upatch is in this boot's records``
   * -
     - ``WARN``
     - ``no record of this boot to check the pins against``
   * -
     - ``WARN``
     - ``pins not checked against the records: <error>``
   * -
     - ``WARN``
     - ``links or archives not checked: <error>``
   * -
     - ``ALERT``
     - ``<n> XDP archives differ from the loaded payload: <names>``
   * -
     - ``ALERT``
     - ``<n> upatches are missing a link or their archive: <names>``
   * -
     - ``ALERT``
     - ``<n> pinned or archived without a record of this boot: <names>``
   * -
     - ``ALERT``
     - ``this boot's records do not fold to the measurement register``
   * - ``TpmMeasured``
     - ``OK``
     - ``NV index 0x01818E00 readable``
   * -
     - ``WARN``
     - ``NV index 0x01818E00 not bound this boot``
   * -
     - ``WARN``
     - ``no TPM answered``
   * - ``ConfigActive``
     - ``OK``
     - ``config <root>.. is active``
   * -
     - ``WARN``
     - ``no config activation state before init``
   * -
     - ``WARN``
     - ``the activation of config <root>.. is pending until the next
       reboot``
   * -
     - ``ALERT``
     - ``the config activation record does not belong to this TPM
       boot``
   * -
     - ``ALERT``
     - ``the mounted config does not match the selected root``
   * -
     - ``ALERT``
     - ``the config PCR, activation records and mounted config
       disagree``
   * - ``XdpCovered``
     - ``OK``
     - ``every device an XDP upatch selects runs it``
   * -
     - ``WARN``
     - ``<n> selected devices run without their XDP upatch: <upatch>
       on <device> (<why>), ...``
   * -
     - ``WARN``
     - ``XDP coverage not checked: <error>``

Keyrings
--------

``bpf_keyring`` and ``dm_verity_keyring`` have the same shape. A link
is one entry of the keyring: the key of a certificate, or anything else
the keyring holds, another keyring included (see
:doc:`/concepts/background/keyrings`). A link is frozen when ``init``
recorded its serial: every key of ``.bpf`` and the config key of
``.dm-verity``.

.. list-table::
   :header-rows: 1
   :widths: 22 18 60

   * - Field
     - Type
     - Value
   * - ``present``
     - boolean
     - ``true`` when ``init`` recorded the keyring and it exists.
   * - ``serial``
     - integer or ``null``
     - Serial of the live keyring. ``null`` when it is absent.
   * - ``serial_pinned``
     - integer or ``null``
     - Serial ``init`` froze in the identity pin. ``null`` before
       ``init``.
   * - ``serial_matches``
     - boolean or ``null``
     - ``serial`` equals ``serial_pinned``. ``null`` unless both are
       known.
   * - ``certs``
     - array of object
     - The certificates the keyring should hold: the trusted set for
       ``.bpf``, the config certificates the runtime image names for
       ``.dm-verity``. Each is described below.
   * - ``other_links``
     - array of object
     - Every link that holds none of ``certs``, each with ``serial``,
       ``type`` (``asymmetric``, ``keyring`` and so on), ``description``
       and ``frozen``. ``type`` and ``description`` are ``null`` for a
       link shirudo cannot describe. Empty on a healthy target.

Each entry of ``certs``:

.. list-table::
   :header-rows: 1
   :widths: 22 18 60

   * - Field
     - Type
     - Value
   * - ``sha256``
     - string
     - SHA-256 of the certificate's DER file.
   * - ``fingerprint``
     - string
     - SHA-256 of its public key.
   * - ``primary``
     - boolean
     - In ``bpf_keyring`` only: the runtime image's certificate.
   * - ``config``
     - boolean
     - In ``dm_verity_keyring`` only: always ``true``.
   * - ``subject``
     - string or ``null``
     - The certificate's subject on one line, for example
       ``CN=shirudo``.
   * - ``algorithm``
     - string or ``null``
     - The public key algorithm, for example ``ML-DSA-87``.
   * - ``not_before``
     - string or ``null``
     - The date the certificate was issued, the start of its validity
       period, ``YYYY-MM-DD`` in UTC. Nothing compares it with the
       clock, and the end of the period is not reported.
   * - ``key_serial``
     - integer or ``null``
     - Serial of the key in the keyring that holds the certificate.
       ``null`` when the keyring holds none: for ``.bpf`` a certificate
       added by a config update, enrolled at the next boot.
   * - ``key_description``
     - string or ``null``
     - The kernel's description of that key, ``<subject>: <key id>``.
   * - ``frozen``
     - boolean or ``null``
     - ``init`` froze that key. ``null`` without a key.

``subject``, ``algorithm`` and the dates are ``null`` when the
certificate cannot be parsed.

upatches_loaded
---------------

.. list-table::
   :header-rows: 1
   :widths: 22 18 60

   * - Field
     - Type
     - Value
   * - ``name``
     - string
     - The upatch name.
   * - ``location``
     - string
     - The attach point, for example ``fentry/do_nanosleep``; ``java``
       for a Java agent, ``?`` when it cannot be read.
   * - ``status``
     - string
     - ``success``
   * - ``n_maps``
     - integer
     - Maps pinned for the upatch.
   * - ``missed_runs``
     - integer or ``null``
     - Runs of the upatch's programs the kernel skipped since the load,
       a lower bound. ``null`` for an upatch of no attach kind that
       counts them, or when they cannot be read.
   * - ``loaded_at``
     - string
     - Change time of the upatch's pin directory, or of a Java agent's
       jar, ISO 8601 UTC.
   * - ``age_sec``
     - integer or ``null``
     - Seconds since ``loaded_at``.
   * - ``payload_sha256``
     - string or ``null``
     - The loaded payload's digest, as in the eventlog.

assets
------

.. list-table::
   :header-rows: 1
   :widths: 22 18 60

   * - Field
     - Type
     - Value
   * - ``root``
     - string
     - ``/var/lib/shirudo``
   * - ``cert``
     - boolean
     - Same test as ``cert_present``.
   * - ``signing_key``
     - boolean
     - Same test as ``is_operator``.
   * - ``eventlog``
     - boolean
     - ``/var/lib/shirudo/eventlog`` exists.
   * - ``eventlog_bytes``
     - integer
     - Its size, all boots.
   * - ``upatches``
     - integer or ``null``
     - ``.upatch`` files in ``/var/lib/shirudo/upatches``. ``null``
       when the directory is absent.
   * - ``bpffs_mounted``
     - boolean
     - ``/run/shirudo/bpffs`` is the root of a bpffs mount, not
       hidden under another mount.

tamper_attempts
---------------

.. list-table::
   :header-rows: 1
   :widths: 22 18 60

   * - Field
     - Type
     - Value
   * - ``total``
     - integer
     - Sum of all counters.
   * - ``counters``
     - object
     - Every counter by name, zero or not, so the keys are the same in
       every report. :doc:`/security/tamper-counters` lists them.

The counters live in a pinned BPF map under ``/run/shirudo/bpffs`` and
start at zero at every boot.

integrity_attempts
------------------

The same two fields as `tamper_attempts`_, ``total`` and ``counters``,
for the integrity counters, which :doc:`/security/integrity-counters`
lists. They live in their own pinned map and start at zero at every
boot.

config
------

.. list-table::
   :header-rows: 1
   :widths: 22 18 60

   * - Field
     - Type
     - Value
   * - ``root_hash``
     - string
     - Root hash of the selected config image, 64 hex digits.
   * - ``activation_pending``
     - boolean
     - ``true`` while an activation waits for the next reboot.
   * - ``error``
     - string or ``null``
     - Why the selected config cannot be verified, as an ``strerror``
       text. ``null`` when it is active or pending.

tpm
---

.. list-table::
   :header-rows: 1
   :widths: 26 18 56

   * - Field
     - Type
     - Value
   * - ``reachable``
     - boolean
     - A TPM answered.
   * - ``nv_index``
     - string
     - ``0x01818E00``
   * - ``chain``
     - string or ``null``
     - The live register value. ``null`` when no register is bound.
   * - ``nv_name``
     - string or ``null``
     - The register's TPM name. ``null`` when no register is bound.
   * - ``register_bound``
     - boolean
     - The NV index is defined and written.
   * - ``register_anchored``
     - boolean
     - The register's name equals the name this boot's ``init``
       record gives, for the TPM's current reset count, and the
       recorded PCR values and writer key give that name.
   * - ``init_records``
     - integer
     - ``init`` records this boot.
   * - ``register_rebound``
     - boolean
     - Two ``init`` records this boot name the same TPM reset count.
   * - ``pcr``
     - integer
     - ``9``
   * - ``phase_pcr``
     - integer
     - ``11``
   * - ``pcr_before``
     - string or ``null``
     - PCR 9 before the binding, from the ``init`` record. ``null``
       without one.
   * - ``phase_before``
     - string or ``null``
     - PCR 11 at the binding, from the ``init`` record. ``null``
       without one.
   * - ``bound_in``
     - string or ``null``
     - ``initrd`` or ``root``, from the ``init`` record. ``null``
       without one.
   * - ``chain_matches_eventlog``
     - boolean or ``null``
     - The register is anchored, not rebound, and equals this boot's
       eventlog replay. ``null`` when no register is bound.
   * - ``eventlog``
     - object
     - ``present`` (boolean), ``entries`` (lines in
       ``/var/lib/shirudo/eventlog``, all boots), ``bytes``, and
       ``events`` with ``--include-eventlog``.

:doc:`/reference/eventlog` defines the records and the replay.

upatch_tree
-----------

.. list-table::
   :header-rows: 1
   :widths: 28 18 54

   * - Field
     - Type
     - Value
   * - ``configured``
     - boolean
     - A tree configuration exists, in the config image on an image
       target.
   * - ``pending``
     - boolean
     - ``/var/lib/shirudo/bpm/upatch-tree/pending.json`` exists.
   * - ``tree_id``, ``generation``, ``last_seq``, ``projection_root``,
       ``manifest_digest``
     - string, integer, integer, string, string
     - The tree state, present when it can be read.
   * - ``state``
     - ``null``
     - Present instead of the five fields above when there is no tree
       state.
   * - ``eventlog_projection_root``
     - string or ``null``
     - Replay of the tree's projection log. ``null`` when it cannot be
       replayed.
   * - ``eventlog_matches_state``
     - boolean or ``null``
     - The replay equals ``projection_root``; ``false`` when the tree
       state cannot be read, as the keepalive's ``tree_log_mismatch``
       has it, and ``null`` when the log cannot be replayed.

:doc:`upatch-tree` defines the tree state.

Optional blocks
---------------

``--show-full`` turns on both blocks below.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Adds
   * - ``--include-system``
     - ``system``: ``hostname``, ``os`` (``PRETTY_NAME`` from
       ``/etc/os-release``), ``kernel_release``, ``kernel_version``,
       ``kernel_build_id`` (from ``/sys/kernel/notes``),
       ``kernel_config`` (every ``CONFIG_*`` in
       ``/boot/config-<release>``, ``n`` for one not set, empty without
       the file), ``architecture``, ``machine_id``, ``boot_id``,
       ``nproc``, ``mem_total_kb``, ``mem_avail_kb``, ``disk_total_kb``
       and ``disk_used_kb`` (of ``/``), ``uptime_seconds``. A number
       that cannot be read is ``-1`` and a text that cannot be read is
       empty. A NUL byte where a value is read counts as a read error:
       ``kernel_config`` then ends with the line before it. A line of
       the kernel config longer than 8191 bytes is left out. The text
       the kernel and these files give is written with U+FFFD for each
       byte that is no UTF-8.
   * - ``--include-eventlog``
     - ``tpm.eventlog.events``: one object per line of
       ``/var/lib/shirudo/eventlog``, all boots, with ``ts``, ``type``
       and ``digest``, plus ``set_digest`` for ``init`` and ``upatch``
       (``name``, ``payload_sha256``) for upatch events. A line that
       does not parse, one that holds a NUL byte among them, gives
       ``{"type": "unparseable"}``, and the lines after it follow. A
       last line without its newline, an append that did not finish,
       gives none, so that ``events`` holds ``entries`` objects.

``status`` sizes its output buffer from the options, the eventlog size
and the number of loaded upatches, at most 8 MiB. A document that does
not fit is not printed: ``status`` writes ``status: json encode failed:
<reason>`` to standard error, nothing to standard output, and exits 1.
With ``--otel`` the keepalive is sent all the same: it does not carry
this document.

Fields to alert on
------------------

.. list-table::
   :header-rows: 1
   :widths: 34 22 44

   * - Field
     - Alert when
     - Next step
   * - ``status``
     - ``tampered``
     - Handle as an incident: :doc:`/operate/troubleshoot/incident-tampered`.
   * - ``status``
     - any value but ``ok``
     - :doc:`/operate/run/read-status`
   * - ``conditions[].status``
     - ``ALERT``
     - The ``detail`` names the cause.
   * - ``tamper_attempts.total``
     - rises
     - The counter that moved names the refused action,
       :doc:`/security/tamper-counters`.
   * - ``tamper_attempts``
     - ``null`` on a target
     - ``init`` has not pinned the counters this boot.
   * - ``integrity_attempts.total``
     - rises
     - The counter that moved names the refused change of the running
       kernel, :doc:`/security/integrity-counters`.
   * - ``integrity_attempts``
     - ``null`` on a target
     - ``init`` has not pinned the counters this boot.
   * - ``lsm_attached``
     - ``false``
     - Enforcement is off.
   * - ``keyring_serial_matches``
     - ``false``
     - The ``.bpf`` keyring was replaced.
   * - ``bpf_keyring.serial_matches``, ``dm_verity_keyring.serial_matches``
     - ``false``
     - The keyring was replaced.
   * - ``other_links[].frozen`` in either keyring
     - ``false``
     - A link ``init`` did not freeze is trusted for signatures.
   * - ``tpm.chain_matches_eventlog``
     - ``false``
     - The register and the eventlog disagree.
   * - ``tpm.register_rebound``
     - ``true``
     - The register was bound twice in one TPM reset period.
   * - ``tpm.bound_in``
     - ``root``
     - The register was bound after the initrd.
   * - ``config.error``
     - not ``null``
     - The selected config cannot be verified.
   * - ``config.activation_pending``
     - ``true``
     - Every command but ``status`` is refused until a reboot.
   * - ``upatch_tree.eventlog_matches_state``
     - ``false``
     - The tree state and its projection log disagree.
   * - ``version_id``
     - differs from the expected build
     - A different shirudo build runs on the target.

A collector that stops receiving the keepalive from a target has lost
the target or its export, see :doc:`keepalive`.

Example
-------

``shirudo status --json`` on a test target with one upatch loaded,
indented here:

.. code-block:: json

   {
     "schema": 1,
     "version_id": "d0d7aa800303439023907d1979d917d46a21bec21f816689c138728a28e84af9",
     "host": "docs",
     "is_target": true,
     "is_operator": false,
     "status": "ok",
     "reason": null,
     "conditions": [
       {
         "type": "LsmAttached",
         "status": "OK",
         "detail": "lsm/bpf link present and pinned"
       },
       {
         "type": "KeyringSealed",
         "status": "OK",
         "detail": "bpf serial 272801410, dm-verity serial 799624487, pins match"
       },
       {
         "type": "ChainIntact",
         "status": "OK",
         "detail": "live register equals the eventlog replay"
       },
       {
         "type": "UpatchesMeasured",
         "status": "OK",
         "detail": "every pinned or archived upatch is in this boot's records"
       },
       {
         "type": "TpmMeasured",
         "status": "OK",
         "detail": "NV index 0x01818E00 readable"
       },
       {
         "type": "ConfigActive",
         "status": "OK",
         "detail": "config 6d5ed552f448.. is active"
       },
       {
         "type": "XdpCovered",
         "status": "OK",
         "detail": "every device an XDP upatch selects runs it"
       }
     ],
     "lsm_attached": true,
     "enforcement": "strict",
     "keyring_mode": "bpf",
     "keyring_present": true,
     "keyring_serial": 272801410,
     "keyring_serial_pinned": 272801410,
     "keyring_serial_matches": true,
     "cert_present": true,
     "certs": [
       {
         "sha256": "79b04130628135a03630a0ed9e92a574f8701847404ec281469348a09b9b3b45",
         "fingerprint": "a8be2bb837b0f052f7652f9edf446594a5465eed614d939964ddfcc96e61ba7f",
         "primary": false
       },
       {
         "sha256": "c00c2d9a30c11dd98bb53200ac79c744b063a50489e5780968ea97bcb5745eb1",
         "fingerprint": "6bd6b1a28b631295a013102d358d371d52ab1c894587aedceaf02e472c88f858",
         "primary": true
       }
     ],
     "certs_revoked": 0,
     "certs_unvouched": 0,
     "certs_enrolled": 2,
     "bpf_keyring": {
       "present": true,
       "serial": 272801410,
       "serial_pinned": 272801410,
       "serial_matches": true,
       "certs": [
         {
           "sha256": "79b04130628135a03630a0ed9e92a574f8701847404ec281469348a09b9b3b45",
           "fingerprint": "a8be2bb837b0f052f7652f9edf446594a5465eed614d939964ddfcc96e61ba7f",
           "primary": false,
           "subject": "CN=shirudo",
           "algorithm": "ML-DSA-87",
           "not_before": "2026-11-03",
           "key_serial": 465853497,
           "key_description": "shirudo: 30dee65057025367c4c384928bcf1e4cd8fe0265",
           "frozen": true
         },
         {
           "sha256": "c00c2d9a30c11dd98bb53200ac79c744b063a50489e5780968ea97bcb5745eb1",
           "fingerprint": "6bd6b1a28b631295a013102d358d371d52ab1c894587aedceaf02e472c88f858",
           "primary": true,
           "subject": "CN=shirudo",
           "algorithm": "ML-DSA-87",
           "not_before": "2026-11-03",
           "key_serial": 91435879,
           "key_description": "shirudo: 7fa1d435249690766f8b1397122775d26f1ed92e",
           "frozen": true
         }
       ],
       "other_links": []
     },
     "dm_verity_keyring": {
       "present": true,
       "serial": 799624487,
       "serial_pinned": 799624487,
       "serial_matches": true,
       "certs": [
         {
           "sha256": "c00c2d9a30c11dd98bb53200ac79c744b063a50489e5780968ea97bcb5745eb1",
           "fingerprint": "6bd6b1a28b631295a013102d358d371d52ab1c894587aedceaf02e472c88f858",
           "config": true,
           "subject": "CN=shirudo",
           "algorithm": "ML-DSA-87",
           "not_before": "2026-11-03",
           "key_serial": 403194297,
           "key_description": "shirudo: 7fa1d435249690766f8b1397122775d26f1ed92e",
           "frozen": true
         }
       ],
       "other_links": []
     },
     "signing_key_present": false,
     "upatches_loaded": [
       {
         "name": "shirudo-test-basic",
         "location": "fentry/do_nanosleep",
         "status": "success",
         "n_maps": 0,
         "missed_runs": 0,
         "loaded_at": "2026-11-03T14:54:33Z",
         "age_sec": 1,
         "payload_sha256": "8aee7072a1a15e4dddc93ad6b253a0e2e70ad6cdf767442aa8a1c1997bc3069f"
       }
     ],
     "assets": {
       "root": "/var/lib/shirudo",
       "cert": true,
       "signing_key": false,
       "eventlog": true,
       "eventlog_bytes": 2324,
       "upatches": 1,
       "bpffs_mounted": true
     },
     "tamper_attempts": {
       "total": 28,
       "counters": {
         "LoadNotLoader": 15,
         "LoadUnsigned": 0,
         "LoadUnverified": 0,
         "LoadKeyringKind": 0,
         "LoadKeyring": 0,
         "MapCreate": 1,
         "MapWrite": 0,
         "MapFdWrite": 0,
         "ProgRun": 0,
         "ProgAttach": 0,
         "ObjPin": 0,
         "BpfCommand": 8,
         "ExeIdentity": 0,
         "KeyringWrite": 0,
         "PinUnlink": 0,
         "PinRename": 0,
         "PinXattr": 0,
         "BpffsUmount": 1,
         "BpffsUmountAbove": 0,
         "BpffsMount": 0,
         "SealWrite": 1,
         "SealUnlink": 0,
         "SealRename": 0,
         "SealSetattr": 0,
         "SealXattr": 0,
         "SealLabel": 0,
         "SealPtrace": 0,
         "SealPerf": 0,
         "ExecTraced": 0,
         "SealEntry": 2,
         "PerfAttach": 0,
         "PinEntry": 0,
         "SealCopyUp": 0,
         "Kexec": 0,
         "TpmExtend": 0,
         "ObjGet": 0,
         "SealSignal": 0,
         "SealCoreDump": 0,
         "SealUprobe": 0,
         "ExecShared": 0,
         "XattrHandle": 0,
         "Lockdown": 0,
         "SealRlimit": 0
       }
     },
     "config": {
       "root_hash": "6d5ed552f4487728d1ccec8604ddb44b66b18e3430614c20bb4d284995f99f63",
       "activation_pending": false,
       "error": null
     },
     "tpm": {
       "reachable": true,
       "nv_index": "0x01818E00",
       "chain": "7f63313a31ac8ddd3a6a16fce2038322c9c782d5787155d2dc18dfa582dff548",
       "nv_name": "000b21eb0d45ac9ee1bb0a87dbb069120e3b8cb251b3d40cc2a86a307ab73f728789",
       "register_bound": true,
       "register_anchored": true,
       "init_records": 1,
       "register_rebound": false,
       "pcr": 9,
       "phase_pcr": 11,
       "pcr_before": "0000000000000000000000000000000000000000000000000000000000000000",
       "phase_before": "0000000000000000000000000000000000000000000000000000000000000000",
       "bound_in": "initrd",
       "chain_matches_eventlog": true,
       "eventlog": {
         "present": true,
         "entries": 2,
         "bytes": 2324
       }
     },
     "upatch_tree": {
       "configured": false,
       "pending": false,
       "state": null,
       "eventlog_projection_root": null,
       "eventlog_matches_state": null
     }
   }

After refused tamper attempts as root (reading and removing a pin,
unmounting the private bpffs, appending to the eventlog), the counters
of the same target read:

.. code-block:: json

   {
     "total": 44,
     "counters": {
       "LoadNotLoader": 27, "LoadUnsigned": 0, "LoadUnverified": 0, "LoadKeyringKind": 0,
       "LoadKeyring": 0, "MapCreate": 1, "MapWrite": 0, "MapFdWrite": 0,
       "ProgRun": 0, "ProgAttach": 0, "ObjPin": 0, "BpfCommand": 12,
       "ExeIdentity": 0, "KeyringWrite": 0, "PinUnlink": 1, "PinRename": 0,
       "PinXattr": 0, "BpffsUmount": 1, "BpffsUmountAbove": 0, "BpffsMount": 0,
       "SealWrite": 1, "SealUnlink": 0, "SealRename": 0, "SealSetattr": 0,
       "SealXattr": 0, "SealLabel": 0, "SealPtrace": 0, "SealPerf": 0,
       "ExecTraced": 0, "SealEntry": 0, "PerfAttach": 0, "PinEntry": 0,
       "SealCopyUp": 0, "Kexec": 0, "TpmExtend": 0, "ObjGet": 1,
       "SealSignal": 0, "SealCoreDump": 0, "SealUprobe": 0,
       "ExecShared": 0, "XattrHandle": 0, "Lockdown": 0, "SealRlimit": 0
     }
   }

Related
-------

- :doc:`/reference/cli/status`
- :doc:`/operate/run/read-status`
- :doc:`/security/tamper-counters`
- :doc:`/reference/eventlog`
- :doc:`otlp`
- :doc:`keepalive`
