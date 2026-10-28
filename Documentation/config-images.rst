..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Executable and configuration images
===================================

Shirudo puts its executable and configuration on separate read-only dm-verity
filesystems. The host root filesystem stays in place. Writable Shirudo state
keeps its xattr protection. BPF upatches still use signed loaders verified by
the kernel BPF keyring, including when config itself has a valid signature.
There is one target policy; authenticated bootstrap settings are required.

The executable image is fixed for the boot. Configuration updates install
another signed immutable image while the system runs. They do not write
through dm-verity or modify the active filesystem in place. Each update
transfers the complete image and its verification data. Reusing blocks and
rollback prevention are deferred.


1) Filesystems and trust
------------------------

The target uses these mounts and directories::

    /                       host root filesystem
    /run/shirudo/runtime     executable image: ro,nodev,nosuid
    /run/shirudo/config      config image: ro,nodev,nosuid,noexec
    /run/shirudo/bpffs       protected BPF objects
    /var/lib/shirudo         protected writable state

The runtime image contains the fully static target binary, bootstrap
``shirudo.conf``, initial BPF trust anchors and the
config verification certificate. Every executable on this image has the
same eligibility for Shirudo authority. Do not include shells, debuggers
or general-purpose interpreters unless that authority is intended.

The UKI authenticates the runtime image's expected dm-verity root hash.
After mounting that image, Shirudo reads the config verification
certificate from it. Config signatures cover exactly the 64 lowercase
ASCII hex bytes of the dm-verity root hash, without a newline. The kernel
verifies that signature using its dm-verity trust path, including built-in
trusted keys. The private signing key remains on the operator. A config cannot replace this verification
certificate, initial BPF trust anchors, executable authority or TPM
settings. Rotating the config verification certificate requires a new
runtime image and UKI followed by reboot.

The static target runs directly from the runtime image. It needs no ELF
interpreter or shared libraries at startup. Additional dynamic executables
supplied by the operator bring their interpreter and libraries into the
image. Executable mappings from outside the image are denied.

The authenticated bootstrap configuration selects the initial cached config
prefix, the verification certificate and a reserved static TPM PCR. For
example, a deployment that has reserved PCR 14 uses::

    config.image = /var/lib/shirudo/images/initial
    config.verification_key = /run/shirudo/runtime/etc/shirudo/config-cert.der
    config.pcr = 14

PCR 14 is an example, not a universal allocation. The deployment must ensure
that its firmware, bootloader and other OS software do not use the selected
PCR. Image mode accepts static SHA-256 PCRs 0 through 15 except PCRs 9
and 11, which the existing upatch register uses. Unsupported PCR reads fail
initialization. Resettable PCRs are refused. A config update or environment
override cannot change the selection.

The UKI's bootstrap configuration names the runtime cache prefix and its
expected 64-character root hash::

    runtime.image = /var/lib/shirudo/images/runtime
    runtime.root_hash = <expected SHA-256 root hash>

An image pathname is a location, not an authentication mechanism. Boot
checks the expected runtime hash; config activation checks the signature
and the actual kernel mapping.


2) What configuration contains
------------------------------

A configuration source directory contains the existing updateable inputs
under their image-relative paths:

* ``etc/shirudo/shirudo.conf``: eventlog limits and map-export settings.
* ``etc/shirudo/bpm/registries.d/`` and ``etc/shirudo/bpm/keys/``:
  repository definitions and verification certificates.
* ``etc/shirudo/bpm/upatch-tree.conf``: the tree subscription.
* ``etc/shirudo/node.labels``: labels used by tree selectors.
* ``keys/trusted/``: additional BPF certificates and vouch signatures.
* ``keys/revoked/``: revocation records.

Repository ``key_file`` paths are resolved under the held config-image root.
Use an image-relative path such as ``etc/shirudo/bpm/keys/repo.der`` or the
conventional ``/etc/shirudo/bpm/keys/repo.der`` spelling; both name the
certificate inside the image. Other absolute paths and traversal are refused.
Tree publications are verified against the runtime image's initial BPF
certificate. Repository indexes use their configured repository certificate.

The initial BPF certificate, TPM configuration and
``tls.classical_hosts`` policy belong in the runtime image's
``etc/shirudo/shirudo.conf``. For example::

    tls.classical_hosts = ghcr.io,quay.io

The target reads this policy from the immutable runtime image; operator
commands read it from the root-managed host config. The updateable config
image cannot set or change ``tls.classical_hosts``. More generally, attempts
to override settings owned by the runtime bootstrap are rejected. Shirudo
rejects these and other invalid config images before extending the config
PCR.
Config images must not contain symbolic links or special files.

Writable state still includes downloaded upatch archives, repository
indexes, package caches, installed state, pending tree operations, locks,
telemetry output and the eventlog. Image mode adds complete-image caches
under ``/var/lib/shirudo/images`` and the activation journal and config
measurement log under ``/var/lib/shirudo/config-update``.

No persistent certificate-enrollment catalog is added. Complete revocation
coverage across reissued certificates with the same public key has not been
established by this implementation; do not infer it from a matching fingerprint
alone.

The existing ``security.bpf.shirudo`` seal protects writable state. The
runtime and config filesystems need no seal xattr writes. bpffs keeps its
separate object and payload protections.


3) Build and verify images
--------------------------

Run image generation on the operator. The Bash scripts require GNU coreutils,
``mkfs.ext4`` from
``e2fsprogs``, the standard ``veritysetup`` executable (``cryptsetup-bin``
on Debian/Ubuntu, ``cryptsetup`` on Fedora/RHEL) and the operator-only
build helper::

    tools/gen-image/shirudo-gen-image --source config-root --output config \
        --keys-dir operator-keys \
        --builder tools/shirudo-build/shirudo-build

The source directory becomes the config image root. The four outputs are::

    config.img       ext4 filesystem
    config.verity    standard verity superblock followed by the hash tree
    config.roothash  64 lowercase ASCII hex bytes, without a newline
    config.p7s       detached ML-DSA-87 CMS signature

All four files share a prefix. Existing output files are refused. The
operator can also sign an already prepared 4096-byte-aligned ext4 image::

    shirudo image build filesystem.img -o config --keys-dir operator-keys

Generate the runtime image with its static executable and public assets::

    tools/gen-image/shirudo-gen-runtime --binary ./shirudo-target \
        --bootstrap-conf bootstrap.conf --cert initial-bpf-cert.der \
        --config-cert config-signing-cert.der --output runtime \
        --keys-dir operator-keys \
        --builder tools/shirudo-build/shirudo-build

Use trusted native input binaries. Dynamic executable inspection runs
their ELF interpreter on the operator. Never put private keys in either image.

The Bash builder runs standard ``veritysetup format`` with format version 1,
SHA-256, 4096-byte data and hash blocks and a 32-byte salt. The standard
superblock starts at offset zero and the hash tree starts at block one.
The C helper signs the root's exact ASCII representation. ``--kind config|runtime``
is a packaging hint, not a signed format field or an authority decision.
Shirudo has no custom hash-tree builder.
The scripts share argument and output checks in ``common.sh`` and keep the
systemd service template in a separate file. ``make install-operator`` installs
them under ``libexec/shirudo/gen-image/``. Generation happens in a temporary
directory beside the requested output. The builder verifies the image before
publishing any files and refuses to replace existing output files.


Verify a staged bundle offline on the operator without activating it::

    shirudo image verify config --cert config-signing-cert.der

This command dispatches to ``shirudo-build``. The helper authenticates the
root signature with the supplied certificate, validates the standard
superblock and exact file sizes, then runs ``veritysetup verify``. This
operator check does not select the target kernel's trust policy.
It requires the operator helper and ``veritysetup``, but no root, TPM or
active device-mapper mapping. It is not a target-side health command.

Target operations use linked code and kernel APIs. After authenticating
runtime root from the UKI, or asking the kernel to authenticate the config
root signature, the target creates or validates a strict read-only mapping
and reads the whole data device through the kernel. It validates the
standard superblock and exact backing-file sizes. These checks precede
candidate parsing and PCR extension, including for reused mappings. Integrity failures and incomplete reads refuse preparation.
The target never shells out to ``veritysetup``, ``dmsetup`` or a filesystem
builder and does not implement a userspace hash-tree verifier.


4) Boot and live updates
------------------------

Boot follows the systemd initrd flow in the initrd guide. The authenticated
initrd first verifies the runtime and selected config to determine the
boot-enrolled signer set. Image boot requires
``dm_verity.keyring_unsealed=1``: the trusted initrd enrolls the config
verification certificate in the dedicated ``.dm-verity`` keyring and seals
it before handing control to the host. Enrollment and sealing address the
kernel ring through ``KEY_SPEC_DM_VERITY_KEYRING``; there is no search of
``/proc/keys`` or fallback to a user-created keyring. Built-in kernel trust remains part
of config-root verification. The initrd also enrolls and seals the BPF
keyring, attaches the guards, mounts
the runtime under guard protection and completes measured config activation.
The runtime bootstrap settings select the config verification key and PCR.
After switch-root, services and CLI commands execute the static binary at
``/run/shirudo/runtime/usr/bin/shirudo`` directly. The generator prints
that invocation and can write a service override with ``--unit-output``.
The ``shirudo`` commands below denote that configured runtime invocation;
substitute the command and arguments for its final ``init`` when invoking
the generated command directly.

Image mode needs writable ``/var/lib/shirudo`` available during the initrd
run: the image cache and pending activation record must be durable before a
PCR extension. If that directory resides on a separate filesystem, mount
it under the initrd's system root before Shirudo starts. A separate state
filesystem is not required.
The mounts under ``/run`` survive switch-root.

Boot verifies the selected cached config, validates its mapping and
contents, records a BOOT measurement and applies the selected BPF trust
set and archived upatches. Missing or invalid images fail initialization.
The current installed config and the first installed config use the same
signature verification path. Repeating init within the same TPM boot does not append another config
event.

The target's live update command accepts a local complete bundle prefix or
an HTTPS prefix::

    shirudo image update /path/to/config
    shirudo image update https://config.example/shirudo/config
    shirudo image status

The update sequence is::

    take the operation lock
      -> fetch the bundle and authenticate its root and backing files
      -> prepare a strict read-only candidate mapping and read every data block
      -> mount and validate the candidate contents
      -> save and fsync the pending activation record
      -> extend the selected PCR
      -> save the measurement record
      -> finish authorized key changes and mount replacement
      -> save completed state

Each operation reads through a held directory FD for the selected config.
The operation lock prevents a command from mixing old and new settings.
Old references can finish, but new commands use the active image. The
runtime image and host root filesystem remain unchanged during config
updates.

Additional BPF signing keys still need valid vouches under the existing
BPF trust rules. The config signature alone cannot authorize BPF code.
Before measuring, Shirudo validates the full vouch graph and every
revocation record. Revocation filenames are canonical lowercase public-key
fingerprints with a ``.der`` suffix; their certificate must match the
fingerprint. Unknown entries, malformed records and unvouched signers are
refused. The selected config must retain at least one unrevoked authorized
BPF signer; an all-revoked set is refused by this implementation.
BPF signing keys are enrolled at boot before the existing reject-all
keyring restriction is installed. Live config activation cannot enroll new
keys into that sealed keyring. A candidate containing a signer absent from
the live keyring is refused before measurement. It is not activated as a
pending enrollment. A new signing key must be supplied through the config
selected for boot and requires reboot and vouch verification; no kernel
keyring changes are included. This requires boot-time provisioning: there
is no live command to queue a new signer for a future boot. An existing
activation record selects its cached bundle prefix ahead of the initial
``config.image`` setting. Changing that setting alone does not override an
existing selection, and deleting the journal is not a supported update
procedure.

The selected trust configuration is covered by the config PCR event.
Omitting a certificate from a replacement image does not
revoke a key already enrolled this boot; include an explicit revocation
record. Vouch verification follows the historical chain rooted in the
runtime image's initial certificate. Revoking a signer for BPF loading does
not invalidate its earlier vouches or remove that immutable chain anchor.

Revocations arrive only through signed config images. The image-mode
target has no local revocation command or writable revocation override.
``keys add``, ``keys revoke`` and ``bpm key add`` refuse local mutations
with guidance for signed config updates or boot-time enrollment. The same
applies to ``bpm config register add``, ``remove`` and ``rm``: put repository
definitions and public certificates in the signed config, then activate it.
Command help and read-only inspection remain available. ``status``,
``config`` and ``keys show`` report the authenticated inputs; ``config``
prints effective settings and does not write them. Upatch load/unload,
package install/upgrade/uninstall, repository refresh, tree sync, map export
and attestation remain target operations under the active image policy.
Operator build, publish and vouch commands remain operator operations.

Signed upatch load and unload checks continue to apply. Signed config
revocations reuse the existing key unlink, measured key-revoke and live
upatch unload operations. Startup removes archives signed by revoked keys
before restoring upatches. There is no separate purge journal or same-boot
purge recovery.


5) Measurements and interrupted activation
------------------------------------------

The config event digest binds the event kind and binary root hash::

    SHA256("shirudo-config-root-v1\0" || big_endian_u32(BOOT_or_UPDATE)
           || root_hash_32_bytes)

BOOT is 1 and UPDATE is 2. The TPM extends this digest into the reserved
SHA-256 config PCR. Returning to a previously selected root produces an
UPDATE event; requesting the current root is a no-op. Each new boot records
a fresh BOOT event. The config log is separate from the upatch NV register.

The verified bundle and pending selection become durable before extension
or activation. Failures before that point leave the active config usable.
Once pending, any interruption, including an ambiguous TPM response,
requires a manual reboot before Shirudo can resume state changes. The node
keeps running: Shirudo never triggers a reboot. The operator chooses when
to reboot. State-changing operations and config attestation refuse;
there is no ``image recover`` command or same-boot extension retry.

At the next trusted boot, initialization selects and verifies the cached
pending config, records a fresh BOOT event, applies its revocations before
upatch restoration and completes only after startup succeeds. Missing files
or invalid signatures stop initialization. The previous boot's extension
is not replayed, and an older config is not silently selected as fallback.
The pending record retains the selected prefix/root and boot identity;
it does not persist per-effect phases or predicted PCR before/after values.

Direct TPM-command measurement spoofing remains separate work. Genuine
operations are measured and their history is replayed, but a PCR alone
does not prove activation against an attacker able to issue measurement
commands. The separate upatch NV register requires a guarded boot-writer
signature; that authorization does not cover config PCR extensions.
No IMA integration is added, and signatures do not prevent rollback.

Attestation includes the config PCR even if ``--pcrs`` omits it. The
``config`` object contains ``schema: 1``, ``pcr``, ``reset_count``,
``restart_count``, ``initial_pcr`` and an ``events`` array. Each event holds
``sequence``, ``kind`` and ``root_hash``. The current boot's history derives
the terminal root and PCR; duplicated terminal fields are not needed.
The operator verifies its intended root with::

    shirudo attest verify --evidence=evidence.json --nonce=<fresh nonce> \
        --ak-name=<enrolled AK name> --expect-chain=<expected upatch chain> \
        --expect-config-root=<approved config root hash> --expect-config-pcr=14

Both config expectation flags are required to approve a root. The verifier
checks BOOT/UPDATE order, sequence and boot identity, derives each digest
and replays it from ``initial_pcr`` to the PCR covered by the TPM quote.
Without an expected root it reports consistency and explicitly notes that
operator approval was not supplied. Pending state cannot produce healthy
config evidence. This remains subject to the direct-writer limitation.


6) Enforcement and tests
------------------------

The binary embeds one BPF object pair: ``bpf/bpf2.c`` and ``bpf/seal.c``.
Initialization always loads both. ``bpf/admission.h`` supplies BPF command,
signature, keyring and bpffs checks. ``bpf/seal.h`` supplies writable-state
xattr checks, label inheritance and ptrace/perf checks. The device and task
helpers live in ``bpf/verity_policy.h``.

The seal label marks a protected writable target. It never grants the caller
write access. Runtime and config files use dm-verity, while writable state
continues to use seal xattrs. Caller authority comes from runtime exec.

Shirudo marks tasks after successful exec from the approved runtime
device, inherits the mark on fork and re-evaluates it on every successful
exec. Exec outside the runtime clears authority. Failed exec preserves
the running image's mark. Changing ``mm->exe_file`` cannot grant authority.
Runtime exec checks for an existing tracer or seccomp filter. The existing
perf allocation check denies targets already marked trusted, but is not
serialized with the exec transition. The separate `perf/exec investigation
<https://github.com/shirudo-dev/shirudo/issues/11>`__ records that source-derived race and the limitation
of an earlier proposed exec-time snapshot check. Neither has a runtime
reproduction in this work.
Do not add a systemd syscall filter to the runtime
invocation: caller-controlled seccomp could otherwise spoof the kernel
enforcement query used to detect hidden bpffs pins.

The LSM observes dm-verity metadata through the existing
``bdev_setintegrity`` hook. Lookup checks the block-device pointer, device
number and disk sequence. The runtime root must match the authenticated
bootstrap value. A config root must match the expected root staged by the
trusted task creating that mapping. An unrelated mapping made by a trusted
task is not a config device.

Expected roots live in task storage. The hook reads the preparing
task's entry and consumes it when the kernel reports the matching root.
Creation clears it on every exit and reports an error if cleanup fails. A
remaining valid entry blocks another preparation until cleared or task exit.
The same helper covers boot activation, temporary download verification and
live config activation. Initial trusted boot validates the key set before
installing the guards, then recreates those mappings under enforcement.
Untrusted tasks cannot modify the expectation map through BPF or a writable
FD.
The free hook attempts to delete the device record,
but upstream dispatch can skip that notification. Device identity checks
and cleanup are distinct concerns.

Image mode requires a kernel without 32-bit compatibility support, as
listed in the `kernel requirements <requirements.rst>`__.
The ``file_ioctl`` and ``file_ioctl_compat`` hooks deny mutating
DM-control commands from untrusted callers, including commands on old or
inherited FDs. The restriction covers all DM devices in image mode, so
ordinary untrusted volume-management tools cannot mutate unrelated DM
mappings either. Read-only control queries remain available, and trusted
image tasks retain control access. Shirudo creates strict mappings, but the
upstream metadata hook does not expose every verification option. Existing
mount hooks reject direct operations on the bpffs, and ``sb_umount``
refuses an unmount that would take the bpffs mount init made with it, by
subtree or by propagation (residual risk 3 in the threat model).
The image mount hooks do not cover every mount attribute change or
unmount of a parent mount above the runtime and config images. Legacy ``mount(MS_MOVE)`` can relocate an image;
the separate `mount-move investigation <https://github.com/shirudo-dev/shirudo/issues/12>`__ records
the VM result and the same source-check gap in the baseline bpffs policy.
A changed pathname does not change device-bound executable authority.
No additional LSM hooks are required.

Process-memory protection remains necessary: dm-verity protects backing
files, not writable mappings, ptrace or process-memory writes. Trusted
processes reject untrusted executable mappings, anonymous executable
memory and transitions that introduce executable pages from writable
memory.

Writable state retains the xattr seal, with image task authority used to
authorize the caller. New inodes receive their parent's label during the
creation transaction when a cached parent mark is present. Shirudo's writers
hold the parent directory open while creating; they apply a fallback label
when needed. Cached marks can be absent after directory-inode eviction, and
link or rename can introduce an existing unlabelled inode. The seal does not
exclude every foreign entry or revoke previously opened writable descriptors
and shared mappings. The `threat model <threat-model.rst>`__ describes these
current limits; the separate `directory-entry investigation
<https://github.com/shirudo-dev/shirudo/issues/13>`__ records the earlier baseline.

The enforcement hooks are present at bpf-next commit
``0867b7bfa9de65674c6e599fa21b762b71011b14``. Direct access to the kernel
``.dm-verity`` keyring additionally requires patch 1/3 of the bpf-next v2
series ``keys: Add well known IDs for fs-verity/dm-verity keys``. The test-
kernel build applies the local copy under ``kernel/``.
Shirudo also requires the signed-BPF kernel interfaces listed in
`requirements <requirements.rst>`__.

The host tests exercise standard superblocks, exact root encoding,
``veritysetup`` formatting and offline verification, signature failures,
durable pending selections, interrupted activation and fresh-boot history.
The libtpms cases use actual PCR commands in addition to injected callbacks.
Host fault injection and the VM interruption check are separate evidence;
neither proves behavior under every hardware failure.


The target tamperproof tests exercise executable authority, fork and exec,
executable mappings, direct and inherited DM controls, mount namespaces,
ptrace, ``/proc/<pid>/mem``, ``process_vm_writev`` and perf observers.
Observer tests do not establish that concurrent perf attachment is excluded.
The target suite runs against an image-backed installation. The final
interruption case leaves pending state and ends the VM run; it does not
initiate a reboot. A skipped required fixture fails the run.


7) Run the target suite
-----------------------

The standard harness builds and signs fixtures on the operator and deploys
only public artifacts. Run the suite with::

    sudo make -C testing test-tgt

The harness requires dracut, initrd boot and all seal hooks. It rejects
``TEST_VM_INITRD=0`` and ``TEST_VM_SKIP_SEAL=1``. The only accepted value of
the old ``TEST_VM_MODE`` setting is ``verity``; no selection is needed.
CI uses this same required suite and reports its failures.

The guest boots with ``config-boot-keys``. The runtime fixture includes an
authority probe and an interrupted-activation helper; these test executables
have full authority and must never ship in a deployment runtime.

The suite checks signed upatch load and unload, foreign signature rejection,
TPM replay, uprobes, map and arena serialization, tree updates, OTLP services,
keyring controls, runtime exec authority, executable mappings, device controls,
process observers, hidden bpffs, signed config updates and measured revocation.
After the final interrupted update it checks that changes and attestation
refuse while the node continues running.

Required image fixtures and helpers are failures when absent. A whole suite
that skips in image mode fails the runner. Test ordering matters:
boot-signer assertions run before config changes. Revocation removes a
signer for the remainder of the boot; the interruption case runs last
because it leaves the activation pending. Use a fresh test
VM and state for another complete run.

For an already provisioned disposable image-mode VM, install the complete
public fixture set and cache every config bundle under
``/var/lib/shirudo/images``, then run::

    export SHIRUDO_BIN="$PWD/testing/helper/image-shirudo"
    export SHIRUDO_TEST_FIXTURES_DIR=/path/to/public-upatch-fixtures
    export SHIRUDO_TEST_KEY_FIXTURES=/path/to/public-image-fixtures
    export SHIRUDO_TEST_RESULTS=/root/test-results/verity
    sh testing/run-target-tests.sh

``contrib/verity-vm-config-fixtures.sh --keys-dir <operator-keys>
--output <new-directory>`` builds the signed config and revocation fixtures;
only its ``public/`` directory belongs on the target. The standard host
bundle also packages the runtime and static test helpers. The
``image-shirudo`` test wrapper executes the runtime binary directly.
Production services use the invocation
emitted by ``shirudo-gen-runtime``.

For built-in kernel trust coverage, the operator may supply
``TEST_VM_BUILTIN_SIGNING_KEY`` and ``TEST_VM_BUILTIN_SIGNING_CERT`` while
building the host bundle. Use the private key corresponding to a certificate
already built into the test kernel. The fixture builder uses that host key
in place and exports only its public certificate and signed image files.
The test checks that this certificate differs from the initrd-enrolled
config certificate, then activates its signed image. Without this input,
that individual case is explicitly skipped; no key or kernel is generated.

The runner saves individual suite logs and config evidence in its results
directory, under the VM result share for a standard run. These commands
describe coverage to execute; validation results and limitations belong in
run does not establish that either complete suite passed.
