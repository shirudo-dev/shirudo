..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: Kernel developers, security reviewers

Config images and dm-verity
===========================

A target runs shirudo from a read-only runtime image and takes its
updatable settings from a separate, signed config image. Both are
dm-verity file systems. This page explains why there are two, which
settings live where, how a target maps and checks an image, which keys
verify it, how a config becomes active, what happens when an activation
is interrupted, and what can change without a reboot.

Problem
-------

The binary that holds runtime authority has to be the one the operator
built, and the settings that decide trust, the certificates, the TPM
settings and the config PCR, have to be the operator's too. On the host
root file system root can replace both. Some settings must still change
while a target runs: repositories, the tree subscription, node labels,
export destinations, revocations.

Why a signed file is not enough
-------------------------------

A signature on a file is checked when the file is read. Root can change
the file after the check and before the use, or the target can read it
twice and get two answers. A userspace verifier also runs before the
thing it is supposed to establish, so its own integrity is the question.

dm-verity moves the check into the kernel and makes it continuous. The
kernel checks every block it reads from the data device against a hash
tree whose root hash is the one trusted value. Whoever knows that the
root hash is right knows that every read returns the operator's bytes,
for as long as the mapping exists. :doc:`/concepts/background/dm-verity`
explains the mechanism.

Two images
----------

The runtime image carries what may execute and what decides trust. The
UKI's bootstrap settings name its exact root hash, so no other image can
take its place, and no signature is involved. It is mounted at
``/run/shirudo/runtime`` with ``ro,nodev,nosuid``. Every executable on it
is eligible for runtime authority, which is why a config image, however
validly signed, can never be one.

The config image carries what may change during a boot. A CMS signature
over its root hash authorizes it, so the operator can sign a new one at
any time. It is mounted at ``/run/shirudo/config`` with
``ro,nodev,nosuid,noexec``, and no exec from it grants authority.

Bootstrap files
---------------

Two different files carry bootstrap settings. The runtime image's file
refuses the ``runtime.*`` keys that the initrd's requires; the initrd's
file refuses none of the runtime image's keys.

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - File
     - Required keys
     - Further keys
   * - ``/etc/shirudo/shirudo.conf`` in the initrd, inside the UKI
     - ``runtime.image``, the cache prefix of the runtime image, and
       ``runtime.root_hash``, its 64-character root hash
     - ``tpm.tcti``, ``tpm.owner_auth``, and the ``config.*`` keys
   * - ``etc/shirudo/shirudo.conf`` on the runtime image
     - ``config.image``, the initial config prefix;
       ``config.verification_key``, one or more certificate paths under
       ``/run/shirudo/runtime/``; ``config.pcr``, a PCR from 0 to 15
       other than 9 and 11, or ``config.nvpcr``, the config NvPCR
     - ``tpm.tcti``, ``tpm.owner_auth``, ``tls.classical_hosts``. Any
       ``runtime.*`` key is refused.

The initrd's file must exist before the runtime image is known, and the
runtime root hash it names is known only once the runtime image is built,
so the runtime image is built first. Where both files set a key, the
runtime image's value wins, and the root file system's ``init`` reads only
the runtime image's file. With a TPM owner password, both files carry
``tpm.owner_auth``: ``init`` in the initrd creates the NV writer with the
initrd's file, and later commands use the runtime image's. The initrd's
file must then not be readable by group or others. The initial BPF
certificate is not a setting: it is ``keys/cert.der`` on the runtime
image.
:doc:`/reference/configuration` lists every key.

Image files
-----------

An image is four files with a common prefix:

``<prefix>.img``
    The ext4 data.

``<prefix>.verity``
    The hash tree with a standard ``veritysetup`` superblock: format
    version 1, hash type 1, SHA-256, 4096-byte data and hash blocks.

``<prefix>.roothash``
    The root hash as exactly 64 lowercase hexadecimal characters.

``<prefix>.p7s``
    For a config image, a detached CMS signature over exactly those 64
    ASCII bytes, without a newline, at most 16 KiB. The target does not
    read one for the runtime image.

The target parses the superblock and checks the sizes of both files
against it; it builds no hash tree of its own. ``shirudo image build``
and ``shirudo image verify`` on the operator use ``veritysetup``.

Mapping and checking an image
-----------------------------

:src:`util/dm_verity.c` maps an image through kernel interfaces only:

#. Attach the data and hash files to loop devices.
#. Create a device-mapper device. For a config image, stage the root the
   task expects in ``shirudo_roots``.
#. Load a read-only ``verity`` table:
   ``1 <data> <hash> 4096 4096 <blocks> 1 sha256 <root> <salt>``. For a
   config image the table adds ``2 root_hash_sig_key_desc <desc>``, and
   the signature travels as a ``user`` key with a random description in
   the thread keyring, whose permission allows only a possessor's
   search.
#. Resume the device and read the table back; it must name the same
   devices, root and salt.
#. Read the whole mapping once, with ``O_DIRECT``, so that every block
   passes the hash check before anything parses the contents, then check
   that the loop devices still back the same files.
#. Mount it as ext4 with ``ro,nodev,nosuid``, ``noexec`` for a config,
   and ``noload``, and check that the mount is that device.

When the table loads, the kernel verifies the config root signature. When
the device resumes, ``lsm.s/bdev_setintegrity`` sees its root hash and
records the device: as runtime when the root equals the runtime root
frozen in the identity map, as config when it equals the root the calling
task staged, which is then used up. Any other mapping gets no record. The
records are what make a runtime executable eligible for authority, and
what the mount guards protect. :doc:`enforcement` lists the hooks.

Which keys verify a config
--------------------------

The kernel's dm-verity signature check tries the built-in trusted keys
first, together with the secondary keyring when
``CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG_SECONDARY_KEYRING`` is set, then
the platform keyring when
``CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG_PLATFORM_KEYRING`` is set, and the
``.dm-verity`` keyring last, once it is sealed and holds a key.

The runtime bootstrap lists the allowed config certificates through
repeated ``config.verification_key`` entries, at most 16. The target
reads them from the authenticated runtime device, requires ML-DSA-87 and
rejects duplicate public keys. Before creating any config mapping,
including the temporary full-read verification mapping, it verifies the
CMS root signature against this set. A certificate trusted only by
another kernel keyring cannot authorize a config.

``init`` enrolls all these certificates in ``.dm-verity`` and seals it,
which the kernel leaves open only with
``dm_verity.keyring_unsealed=1``. It verifies that the keyring holds
exactly that set and freezes every serial in the identity map.
``lsm/key_permission`` protects the ring and its certificates.

The ``.bpf`` keyring is separate. A valid config signature does not
authorize unsigned BPF: every loader still needs a signature under an
enrolled BPF signing key.

Config contents
---------------

A config image holds:

- ``etc/shirudo/shirudo.conf``, which must exist and may set only
  ``eventlog.max_bytes`` and ``map_export.*`` keys;
- ``etc/shirudo/bpm/registries.d/`` and ``etc/shirudo/bpm/keys/``, the
  repositories and their certificates;
- ``etc/shirudo/bpm/upatch-tree.conf``, the tree subscription;
- ``etc/shirudo/node.labels``, the labels tree selectors match;
- ``keys/trusted/``, further BPF certificates, each with a ``.vouch``
  signature by a certificate already in the set;
- ``keys/revoked/``, revoked certificates named
  ``<fingerprint>.der``.

The target validates the tree before it uses it: regular files and
directories only, all on the image's device, at most 65536 entries and 32
levels. It opens everything below the image root through the root
descriptor, never through a path string.

The BPF trust set of a config is the runtime image's ``keys/cert.der``
plus every certificate in ``keys/trusted/`` that a member of the set
vouches for, less the revoked ones.

Activation
----------

``shirudo image update <prefix>`` copies the four files, from a local
prefix or an ``https://`` one, into a staging directory under
``/var/lib/shirudo/images``, maps and checks the image there, and only
then publishes it in the cache as ``<root hash>.img`` and its siblings.
It then activates it:

#. Map and check the candidate as above, require the device record,
   mount it at ``/run/shirudo/config-candidate``, open its root once and
   check on that descriptor that it is the image's device and the root
   inode of its file system, validate it, and check that every
   certificate of its trust set is in the sealed ``.bpf`` keyring.
   Everything that follows reads the image through that descriptor.
#. Record the selection in the journal as pending.
#. Extend the config PCR with the update event.
#. Read the PCR and the TPM's reset and restart counts back; the PCR must
   hold the expected value.
#. Append the event to the config log.
#. Apply the revocations: unlink each revoked certificate that is in the
   ``.bpf`` keyring, extend the register with a ``key_revoke`` event,
   and purge the archived upatches the certificate signed, unloading
   those that are loaded. Each purge checks the signer again under the
   register lock, so a upatch an upgrade replaced in the meantime with
   one another key signed stays.
#. Mount the candidate at ``/run/shirudo/config``.
#. Record the selection as complete.

At boot, ``init`` runs the same sequence as a boot event for the selected
config, but completes it only at the end of ``init``, after the restore
and the register binding. A live update refuses a config with revocation
records, in step 1 and again in step 6, while the archive holds a file no
signer can be read from. A boot enrolls no revoked key and leaves such a
file for the restore to ignore, unless a pin directory or a jar of its
name exists, as after an ``init`` run by hand in a boot that loaded
upatches. :doc:`boot-flow` gives the boot order. Figure 1
shows the sequence, the two ways into it, and the span in which an
interruption leaves the selection pending.

.. figure:: /images/internals-config-activation.svg
   :alt: image stage verifies and caches a config and writes the
         next-boot record; after a reboot by hand, init at boot selects
         the record's target or the staged one. Both init and image
         update run the same eight steps: verify, map, mount and check
         the candidate; read the TPM's counts and the config PCR; record
         the selection pending; extend the config PCR; read it back and
         compare; append to the events; revoke keys and mount the
         config; record it complete. A refusal before the pending record
         records nothing. A stop or refusal from the pending record on
         leaves the selection pending, and every command but status and
         image status refuses until the next TPM boot, whose init records
         a fresh boot event.

   Figure 1. Activating a config, live or at boot.

Next-boot selection
-------------------

``shirudo image stage <prefix>`` verifies and caches a config without
activating it. Unlike a live update, it allows new vouched BPF signers:
init can enroll them during the next planned boot, before sealing
``.bpf``. The command leaves the active config mount, keyrings, PCR and register
unchanged.

The sealed ``next-boot`` file uses the same selection record format as
``state``. Its target is the candidate and its sequence and TPM reset
count identify the completed activation it was staged from.
Init selects it only in a later TPM boot, after a TPM reset and not a
resume or a restart, with that parent still selected.
It rechecks the exact root, signature, image contents and certificate
vouches before enrollment. The normal boot event measures its activation.

A live update that activates a different root removes the stage.
Updating to the already active root preserves it. A stale stage is ignored
with a warning. A valid stage stays on disk until full init succeeds,
including upatch restore and register binding. An interrupted init uses
the normal pending-activation recovery rules. Staging again replaces the
record; ``image stage --cancel`` removes it. Neither operation reboots.

The journal lives in ``/var/lib/shirudo/config-update``: ``state`` holds
the current selection and whether it is pending, ``events`` the config
log, and ``lock`` the lock every target command holds while it runs,
waiting up to 30 seconds for another command to finish. The files must
belong to the user running shirudo, have mode ``0600`` and one link.
:doc:`measurement-register` gives the event digest and what attestation
checks.

Interrupted activation
----------------------

An activation can stop after the pending record is on disk, as Figure 1
shows, and shirudo does not try again within the same TPM boot. The node
keeps running, with the guards and the loaded upatches it had; shirudo
never reboots it.

The reboot is the recovery. At the next boot, ``init`` selects the
config the record names, pending or not, maps and checks it again,
records a fresh boot event in the config PCR and completes. It never
repeats the previous boot's extension. A TPM boot is the TPM's reset
count: a resume from suspend or a TPM restart keeps it, so neither ends a
pending activation, and ``init`` run by hand after one records nothing.

A pending selection is one of three states in which every target
command except ``shirudo status`` and ``shirudo image status`` refuses,
``init`` too while the TPM boot is the same. The table compares them; a
stale next-boot record is none of them, since ``init`` ignores it with a
warning.

.. list-table::
   :header-rows: 1
   :widths: 18 37 45

   * - State and errno
     - Arises when
     - Ends when
   * - Pending, ``EINPROGRESS``
     - An activation stops or is refused after its pending record: a
       crash, a power loss, a failed extension, append, revocation or
       mount, or an ``init`` that fails after its boot event.
     - The next TPM boot's ``init``, after a reboot, records a fresh boot
       event and completes. A resume or a TPM restart is no new TPM boot.
   * - Drift, ``EUCLEAN``
     - The config PCR does not replay from the config log, because
       something else extended it, a TPM restart cleared it, or it does
       not read back as extended; or the log or the mounted config is not
       the one the record names.
     - A reboot.
   * - Another TPM boot, ``ESTALE``
     - The TPM's reset count differs from the record's, after a TPM
       reset or ``TPM2_Clear`` without a reboot, or it or the restart
       count changes while a command reads them.
     - ``init`` records a boot event for the new TPM boot, binds the
       register from the root file system and completes;
       :doc:`boot-flow` explains what a verifier sees.

Lean 4 proves this protocol for every sequence of commands, crashes,
failed or lost TPM answers, extensions by other processes and reboots:
shirudo extends the config PCR at most once per activation and TPM boot
and never after an interruption, a pending or drifted state refuses
every command but ``status`` and ``image status`` until the TPM boot
changes, and after a reboot an uninterrupted ``init`` records the boot
event and admits commands again. On any TPM, a pending activation stays
pending through every resume and TPM restart until the reset count
changes. The other theorems take a TPM whose reset count changes only
between commands and never back to a value it had, and which restarts
without a reboot only by a resume between commands. Root can break that
with a suspend in the middle of a command, a TPM restart or
``TPM2_Clear`` (R4 in :doc:`/security/threat-model`); then one activation
can be extended twice in one TPM boot, and only the journal, the mount,
the save before each extension and ``init``'s completion stay proven.
The model also covers which root ``init`` selects: a staged one only when
the stage copies the completed record ``init`` starts from and was made
in an earlier TPM boot. It does not model the signature and vouch checks
of a staged config, which the staging tests exercise. CBMC shows that
``event_follows()`` accepts exactly the records the model lets follow.
The proofs are in :doc:`/contribute/testing/proof-coverage`.

What can change without a reboot
--------------------------------

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Change
     - How
   * - Repositories, tree subscription, node labels, eventlog limit,
       export settings
     - A new config image and ``shirudo image update``.
   * - Revoking an enrolled BPF certificate
     - A new config image with the certificate in ``keys/revoked/``. It
       is unlinked, measured and its upatches purged.
   * - Adding a BPF certificate
     - Not live. The ``.bpf`` keyring is sealed, so activation refuses a
       candidate whose trust set holds a certificate the keyring lacks.
       ``image stage`` selects such a candidate for the next boot.
   * - The config verification certificate, the config PCR, the TPM
       settings, ``tls.classical_hosts``, the initial BPF certificate
     - Not live. They are on the runtime image, which only a new UKI and
       a reboot replace.
   * - The shirudo binary
     - Not live, for the same reason.

Two boot-time rules bear on key rotation. ``init``
selects the config that the journal names, not ``config.image``, once a
selection exists. A valid next-boot selection overrides that journal target on a later
TPM boot. Init enrolls the config verification certificates from the
runtime image before mapping the selected config. A replacement runtime
must therefore include a certificate that verifies that selection.
Config-key rotation uses a runtime with both old and new certificates,
then a config signed by the new key, then a runtime with only the new
certificate. :doc:`/operate/maintain/keys` covers key changes.

Limits
------

These are properties of the design as implemented.
:doc:`/security/threat-model` gives their consequences.

- Nothing prevents rollback. Any config ever signed by an accepted key
  can be activated again.
- Any process that can send ``TPM2_PCR_Extend`` can extend the config
  PCR; the register's writer guard does not cover it.
- shirudo does not remove cached images.

Related
-------

- :doc:`/concepts/background/dm-verity` for the mechanism
- :doc:`/operate/deploy/boot-integration` for building the images and the
  initrd
- :doc:`/reference/cli/image` for the ``shirudo image`` commands
- :doc:`/reference/configuration` for the settings
