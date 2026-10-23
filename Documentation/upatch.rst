..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Writing, building and shipping upatches
=======================================

This is the author's and operator's guide to upatches: how a BPF
program becomes a signed ``.upatch``, how upatches are tested, bundled
into a BPM package, published to an OCI registry, and how a target pulls
them, by package or through the signed upatch tree.  The
`upatch-spec <upatch-spec.rst>`__ is the byte-level reference for the
artifact, the `architecture <architecture.rst>`__ explains the signed
load path and the registry formats, and the `telemetry
<telemetry.rst>`__ document covers decoders and the export pipeline in
depth.  This guide is the workflow that ties them together.

Operator build, sign and publish commands prepare artifacts on the operator.
Targets receive repository definitions, public verification certificates, tree
subscriptions and node labels in a signed config image. Local repository and
key mutations are refused. Examples that prepare these files belong on the
operator before image generation; target package and tree commands read the
selected config. BPF programs still require signed loaders and vouched boot
enrollment. See `config-images <config-images.rst>`__.

1) What an upatch is
--------------------

A upatch is one BPF object, signed.  The signature covers the loader
instructions and the frozen data they load, so the kernel refuses any
byte that changed between the operator's build and the target's load.
Two kinds exist:

load directive
    Carries one or more programs and their maps.  ``shirudo upatch
    load`` verifies it, lets the signed loader install the payload,
    attaches each program at the point its section name says, pins
    the links and maps under ``/run/shirudo/bpffs/upatches/<name>/``,
    archives the file under ``/var/lib/shirudo/upatches/`` so that
    ``init`` restores it on the next boot, and extends the measurement
    register.

unload directive
    Carries no payload of its own, only the name of the upatch it
    detaches and the payload hash it expects to find on that upatch's
    pin.  It is signed like any other loader and goes through the same
    ``BPF_PROG_LOAD``; the detach happens only when the pin's recorded
    payload matches (``payload_mismatch`` otherwise).

Every upatch has a name, by default the source file's base name, that
becomes the pin directory and the eventlog's ``name``; it is sanitised
to what bpffs accepts.

2) Writing the BPF side
-----------------------

A upatch is ordinary libbpf-style BPF C.  The smallest possible one::

    // SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
    #include "vmlinux.h"
    #include <bpf/bpf_helpers.h>
    #include <bpf/bpf_tracing.h>

    char _license[] SEC("license") = "Dual BSD/GPL";

    SEC("fentry/do_nanosleep")
    int BPF_PROG(shield_nanosleep)
    {
        return 0;
    }

The licence must be GPL-compatible (``Dual BSD/GPL`` is the project's
choice) because the kernel's LSM and tracing hooks refuse anything
else.  The section name picks the attach point; the loader reads it
from the object's metadata at build time and attaches the program
there, nowhere else.  The kinds a target supports depend on its kernel
configuration, listed under *Attach points for upatches* in the
`requirements <requirements.rst>`__:

* ``fentry/<fn>``, ``fexit/<fn>``, ``fmod_ret/<fn>`` on kernel
  functions, the last one rejecting a call before its body runs;
* ``lsm/<hook>`` and ``tp_btf/<tracepoint>``;
* ``kprobe/<fn>`` and ``kretprobe/<fn>``;
* ``uprobe.multi/<path>:<pattern>`` on userspace binaries, for example
  ``SEC("uprobe.multi//usr/bin/example:*Func")``;
* ``cgroup_skb`` on the cgroup v2 root and ``netfilter`` at IPv6
  pre-routing.

A upatch may hold several programs; each gets its own link, pinned as
``link_0``, ``link_1`` and so on (a single program pins as ``link``).

CO-RE and the kernel
~~~~~~~~~~~~~~~~~~~~

Include the ``vmlinux.h`` of the kernel generation the upatch is for.
CO-RE relocations make the artifact portable across builds of the same
kernel, not across kernels that renamed or moved a field: a load on
the wrong kernel fails with ``btf_mismatch`` or ``verifier_rejected``
and the verifier log in the report says which access.  A hard-coded
struct offset signs fine and fails on the wrong kernel in the same
way; there is no runtime probing.  When a fleet runs several kernel
generations, build one upatch per generation and let the tree's
selectors pick (section 7).

Maps and their export
~~~~~~~~~~~~~~~~~~~~~

Maps are declared as usual in ``SEC(".maps")``.  Every map a upatch
creates is pinned under ``upatches/<name>/maps/`` in the private bpffs
and can be read with ``shirudo upatch map <name> <map>``, exported by
the map-export timer and shipped to a collector as described in the
telemetry document.  A map whose name starts with ``obs_i_`` is
private to the upatch and is neither pinned for the operator nor
exported.  The metadata the loader needs rides in frozen, exclusive
array maps the builder creates; an author never sees them.

Decoders
~~~~~~~~

A map becomes a log record or a metric through a decoder: a Lua
function shipped inside the upatch, signed with it, that turns a map
snapshot into OTLP attributes.  The author declares one per exported
map with a manifest in ``.rodata``::

    #include "shirudo_decoder.h"

    const struct shirudo_decoder_manifest counters_decoder SEC(".rodata") = {
        .magic = SHIRUDO_DECODER_MANIFEST_MAGIC,
        .version = SHIRUDO_UPATCH_DECODER_VERSION,
        .language = SHIRUDO_UPATCH_DECODER_LANG_LUA,
        .api_version = 1,
        .input_format = SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1,
        .export_signal = SHIRUDO_UPATCH_DECODER_EXPORT_METRIC,
        .upatch = "my-shield",
        .map = "counters",
        .source = "decoders/counters.lua",
        .entrypoint = "decode",
    };

``export_signal`` is ``EXPORT_LOG`` or ``EXPORT_METRIC``; ``source``
is the Lua file relative to the build context, which the builder
embeds; ``upatch`` must be the upatch's name.  The Lua API, the
snapshot layout the function receives and the records it must return
are in the telemetry document's *Decoders* section.  ``shirudo upatch
info`` lists the decoders a built upatch carries.

Serializers and test programs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Two further program roles are recognised by name.  A program named
``shirudo_serialize__<map>`` in ``SEC("syscall")`` is a serializer: the
exporter runs it on the target to render ``<map>`` into the
``shirudo_ser`` output map (``struct shirudo_serial_chunk`` from
``shirudo_serializer.h``) instead of reading the map directly, which
is how a map of structs or a per-CPU map becomes a flat record stream
(``testing/fixtures/serialized-metric.bpf.c`` is a complete example).
A program named ``shirudo_test__*`` in ``SEC("syscall")`` is a
test-run program: it is pinned but never attached, and exists for the
author's own checks.  The builder refuses a serializer without the
output map, one that targets a reserved or missing map, and two for
the same map.

What a upatch cannot do
~~~~~~~~~~~~~~~~~~~~~~~

Nothing a upatch loads can introduce unsigned code, and nothing it does
is hidden from the operator: every load and unload is measured.  A
upatch does what its author wrote, within the kernel's verifier;
shirudo guarantees provenance, not correctness.  Test on a kernel like
the target's before signing for a fleet.

3) Building and signing
-----------------------

On the operator::

    shirudo build shield.bpf.c
    shirudo build shield.bpf.o -o shield.upatch
    shirudo build --unload shield --payload-sha256 <64 hex>

``shirudo build`` dispatches to ``shirudo-build``, which compiles with
``clang -target bpf -O2 -g`` when given a ``.bpf.c``, generates the
signed loader, signs it with the operator key and writes the
container.  The output defaults to the input name with ``.c`` or ``.o``
replaced by ``.upatch``, next to the input; ``--unload`` writes
``<name>.unload.upatch`` in the current directory.  Options:

``--name <name>``
    The upatch name when it is not the file's base name.

``--keys-dir <dir>``, ``--key <pem>``, ``--cert <der>``
    Where the signing material is; the default is
    ``/var/lib/shirudo/keys`` or ``SHIRUDO_KEYS_DIR``.  The
    `key-lifecycle <key-lifecycle.rst>`__ guide covers the keys.

``--vmlinux <vmlinux.h>``
    The kernel headers to compile against when the default
    ``vendor/linux/vmlinux.h`` is not the target kernel's.

``--extra-cflags '<flags>'``
    Passed to clang.

``--emit-artifacts``
    Keeps the compiled ``.bpf.o`` next to the ``.upatch``.

``--payload-sha256 <hex>`` (``--unload`` only)
    The payload hash the unload directive must find on the pin.  When
    omitted it is read from the local archive
    ``/var/lib/shirudo/upatches/<name>.upatch`` and, failing that, left
    all-zero, which makes the target skip the payload check.  Always
    give it when the directive leaves the operator.

Review the result before it leaves the operator::

    shirudo upatch info shield.upatch
    shirudo upatch info --json shield.upatch

``info`` is an offline view: header, sections, attach metadata and the
signed decoders.  The signing key is never needed on a target, and the
operator never touches a keyring or a TPM.

4) Testing on a target
----------------------

A target that ran ``shirudo init`` loads a local file with::

    sudo shirudo upatch load shield.upatch --report=-
    sudo shirudo upatch get shield
    sudo shirudo upatch map shield counters
    sudo shirudo upatch unload shield.unload.upatch --report=-

``--report=<path>`` (``-`` for stdout) writes the JSON report the
architecture document describes under *Failure reporting*: the phase
reached, the category, the verifier log when the verifier spoke, and
the register value after the operation.  ``upatch get`` shows the
program as the kernel loaded it, which is the thing to compare with
the source.  Two options matter when scripting against a target:

``--expect-chain <hex>``
    The register value the operation must find first, from ``shirudo
    attest predict`` or the last report; a disagreement refuses
    ``tampered`` without loading anything.

``--expect-version-id <id>``
    The target's ``SHIRUDO_VERSION_ID`` (``shirudo version
    --version-id``), to catch an operator and a target of different
    builds.

``--no-precheck`` skips the state check that guards a load; it exists
for tests and ``init``'s own boot-restore, not for operation.

5) Packaging
------------

A package is a directory with a ``<name>.bee`` Beefile next to the sources::

    example-shields/
    ├── example-shields.bee
    └── shield.bpf.c

The ``.bee`` suffix names the package definition. ``bpm build`` writes
the versioned package archive as ``<name>-<version>.bee`` and stores the
definition inside that archive under the member name ``Beefile``. Pass
the local definition with ``-f``; the legacy default filename
``Beefile`` remains accepted when ``-f`` is omitted.

Example ``example-shields.bee``::

    [package]
    name = "example-shields"
    description = "Example shields for the fleet"
    license = "GPL-2.0 OR BSD-2-Clause"
    authors = ["Example Org"]

    [[files]]
    source = "decoders/counters.lua"
    target = "decoders/counters.lua"

    [[upatches]]
    source = "shield.bpf.c"
    load_target = "upatches/shield.upatch"
    unload_target = "upatches/shield.unload.upatch"

    [upatches.tree]
    id = "shield"
    load_artifact = "upatches/shield.upatch"
    unload_artifact = "upatches/shield.unload.upatch"

    [upatches.tree.selector]
    kernel_release_prefix = ["7.3.0-rc5"]
    kernel_build_id = ["534043106db415bc0a983a3393e06c81b431bd39"]
    architecture = ["x86_64"]

    [upatches.tree.selector.kconfig]
    CONFIG_E1000 = ["y", "m"]

    [upatches.tree.selector.labels]
    env = ["prod", "canary"]

``[package]``
    ``name`` (also the package file's base name), ``description``,
    ``license`` and ``authors``, which document the Beefile and are
    not copied into the package; its README is the ``README.md``
    beside the Beefile, when there is one.

``[[files]]``
    Files copied into the package as they are: headers, decoders,
    reproducers, generated tables.  ``target`` defaults to ``source``.

``[[upatches]]``
    One entry per upatch to build and sign.  ``source`` is the BPF
    source or object; ``load_target`` and ``unload_target`` name the
    artifacts inside the package (the defaults derive from the
    source name).  The unload directive is generated with the built
    artifact's payload hash, so a package always ships both halves.

``[upatches.tree]`` and its selector
    Optional; present when the entry is to be published to a upatch
    tree.  ``id`` is the operation's identity across generations, the
    two artifact fields name the package members, and the selector
    says where the entry applies: kernel release prefixes, kernel
    build IDs (``/sys/kernel/notes``), architectures, Kconfig values
    and node labels, all as lists of accepted values; a node matches
    when it satisfies every key given.  An entry without a selector
    applies everywhere.

``upatches/kernel-cve/kernel-cve.bee`` in the tree is a worked example
with one entry per CVE shield, and
``upatches/kernel-obs/kernel-obs.bee`` one with
decoders and shared headers.  Build and inspect::

    shirudo bpm build ./example-shields --version 1.0.0 \
        -f ./example-shields/example-shields.bee \
        --keys-dir /var/lib/shirudo/keys
    shirudo bpm info ./example-shields-1.0.0.bee

``bpm build`` is an operator-only command.  ``shirudo`` exposes it only
when it can resolve ``shirudo-build``; an installed operator package
provides the helper.  From a checkout, set ``SHIRUDO_BUILD`` to
``tools/shirudo-build/shirudo-build`` or put both that directory and the
checkout root on ``PATH``.  If ``shirudo bpm --help`` shows only target
commands, the helper was not found.

``bpm build [context] --version <v> [-f <name>.bee] [--keys-dir <dir>]``
builds and signs every entry through ``shirudo-build`` and writes
``<name>-<version>.bee``: a gzip tarball with the ``Beefile``, the
``upatches/*.upatch`` and ``*.unload.upatch`` artifacts, the
``README.md`` when there is one, the signing ``cert.der`` and a
``build-environment.json`` recording the toolchain.  Versions are what
the registry index orders by and are immutable once published, so a
rebuilt package gets a new version.

6) Publishing
-------------

Packages go to an OCI registry; the registry is untrusted and only
transports them.  ``bpm push`` uploads the package and its certificate
and, given the signing material, adds the version to the registry's
signed index::

    shirudo bpm push ./example-shields-1.0.0.bee \
        oci://registry.example.com/shirudo/example-shields \
        --keys-dir /var/lib/shirudo/keys

The repository is ``oci://host/namespace/name`` without a tag.  The
index lives at ``shirudo/bpm-index:stable`` in the same registry and
is a detached CMS signature by the operator key over the list of
packages and versions with their digests; a target verifies it against
the certificate it registered with the repository, and a package
against the digests the index records.  An index that already lists
the version with other digests is refused, so a published version
cannot be replaced.  Credentials and transport come from
``BPM_OCI_USERNAME`` and ``BPM_OCI_PASSWORD``, ``REGISTRY_AUTH_FILE``
or ``DOCKER_CONFIG``, ``BPM_OCI_CA_FILE`` for a private CA and
``BPM_OCI_SCHEME=http`` for a cleartext local registry; TLS is 1.3 with
hybrid ML-KEM key exchange only.

The upatch tree
~~~~~~~~~~~~~~~

A package is the unit an administrator installs by name.  The tree is
the unit a fleet follows without naming anything: an append-only,
globally ordered sequence of ``add`` and ``delete`` operations, each
with a selector, published as one signed JSON document whose format
the architecture document gives under *Tree publication format*.
Appending a package's ``[upatches.tree]`` entries::

    shirudo bpm tree append ./example-shields-1.0.0.bee \
        oci://registry.example.com/shirudo/tree --keys-dir /var/lib/shirudo/keys
    shirudo bpm tree append ./example-shields-1.0.0.bee \
        oci://registry.example.com/shirudo/tree --keys-dir /var/lib/shirudo/keys \
        --op delete

``tree append`` fetches and verifies the current publication at
``<repository>:<reference>`` (``stable`` by default; a missing one
starts generation 1 with the package name as tree id, ``--tree-id``
overrides), pushes each artifact as an immutable manifest, appends one
operation per entry and republishes the next generation with the
previous manifest's digest as its parent.  ``--op delete`` publishes
the entries' unload directives instead; a target accepts a delete only
for an id it loaded from the same tree.  To withdraw a shield from the
fleet, append a delete; to replace it, append a delete and then an add
of the new version.  Nothing is ever removed from the sequence, which
is what lets a verifier replay a node's projection.

7) On the target
----------------

Packages by name
~~~~~~~~~~~~~~~~

Register the repository once with the certificate that must sign its
index, then install, upgrade and remove by name::

    sudo shirudo bpm config register add example oci://registry.example.com \
        --key-file cert.der
    sudo shirudo bpm repo update
    sudo shirudo bpm install example/example-shields
    sudo shirudo bpm install example/example-shields@1.0.0
    sudo shirudo bpm install oci://registry.example.com/shirudo/example-shields:1.0.0
    sudo shirudo bpm list
    sudo shirudo bpm upgrade
    sudo shirudo bpm uninstall example-shields

``register add`` writes ``/etc/shirudo/bpm/registries.d/<name>`` with
``endpoint`` and ``key_file`` lines.  ``repo update`` fetches and
verifies the index; ``shirudo-bpm-repo-update.timer`` runs it at boot
and ``shirudo-bpm-tree-sync.timer`` every minute, and they are the
only pull mechanism there is.  ``install`` pulls, verifies, unpacks
and loads every upatch in the package, each load measured; ``upgrade``
moves installed packages to the newest indexed version; ``uninstall``
loads the package's unload directives, so a package can only be
removed through artifacts its operator signed.  ``bpm info`` prints a
package's README from a local file or a reference before installing
it.

The tree
~~~~~~~~

A target follows a tree when ``/etc/shirudo/bpm/upatch-tree.conf``
names it::

    endpoint = oci://registry.example.com/shirudo/tree
    reference = stable

and ``/etc/shirudo/node.labels`` holds the node's labels, one
``key=value`` per line, for the selectors to match.  Then::

    sudo shirudo bpm tree sync --dry-run
    sudo shirudo bpm tree sync --report=-

``tree sync`` fetches the publication, verifies the signature and the
sequence continuity against the state it kept under
``/var/lib/shirudo/bpm/upatch-tree/``, evaluates every unseen
operation's selector against ``uname``, the kernel build ID,
``/proc/config.gz`` and the node labels, and applies the matching ones
in sequence order: an ``add`` fetches the artifact (once; the cache is
keyed by layer digest) and loads it, a ``delete`` fetches the unload
directive and unloads.  Each applied operation is measured as a
``tree_op`` event, and the node's projection root enters the next
boot's ``init`` event, so ``shirudo attest predict`` can be given the
tree state to predict the register.  ``--dry-run`` shows what would
apply; the timer runs the real thing every minute.  A node that stops
matching an operation it applied does not unload it: removal is always
an explicit ``delete``.

Verifying what landed
~~~~~~~~~~~~~~~~~~~~~

``shirudo status`` lists the loaded set with the hook each upatch
attached to and ``shirudo upatch list`` flags drift between the
archive and the live pins.  The operator's view is ``shirudo attest``
on the target and ``shirudo attest verify`` against ``shirudo attest
predict``, which takes the installed artifacts and the tree state and
computes the register value a healthy target must certify; the
`tpm <tpm.rst>`__ document describes both.

8) Releasing a mitigation
-------------------------

In order, for a fix the fleet should carry within the hour:

1. Write the shield against the fix, build it against the BTF of each
   kernel generation in the fleet, load it on a test target of each
   and read ``upatch get`` and the report.
2. Give every entry a selector that names the kernel generation and
   the Kconfig the shield depends on; a shield that attaches to a
   function the kernel does not have fails at load, so narrow
   selectors are cheaper than failing nodes.
3. ``bpm build`` with a new version, ``bpm info`` to read the README
   a target will show, ``bpm push`` so that named installation works,
   ``bpm tree append`` so that the fleet pulls it on the next sync.
4. Record the expected register with ``shirudo attest predict`` for
   each kernel generation's installed set and verify a sample of
   targets with ``shirudo attest verify``.
5. To withdraw, ``bpm tree append --op delete``; the fleet unloads on
   its next sync, every unload measured.
