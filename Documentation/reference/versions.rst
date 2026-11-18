..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: All readers

Versions and compatibility
==========================

What identifies a build of shirudo, which format and schema numbers its
files and documents carry, what each reader does with them, and which
mixes of builds work together.

Releases
--------

There is no shirudo release. ``main`` is the development branch, and no
stable branches are maintained. Every push to ``main`` builds the
packages in the ``Build packages`` workflow, where they are available as
run artifacts. Until a release, no format below carries a compatibility
promise.

Version string
--------------

``shirudo version`` prints the version string and the version ID
(:doc:`/reference/cli/version`)::

   shirudo (<describe><extraversion>, "<release-name>")
   version-id: <version-id>

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Part
     - Source
   * - ``<describe>``
     - ``git describe --tags --always --dirty`` of the build tree, or
       the content of the :src:`VERSION` file, ``0.0.0-dev``, outside a git
       checkout. Without tags, describe prints the abbreviated commit,
       with ``-dirty`` for uncommitted changes.
   * - ``<extraversion>``
     - ``EXTRAVERSION`` in the top-level ``Makefile``, ``-rc0``.
   * - ``<release-name>``
     - ``NAME`` in the top-level ``Makefile``.

The package versions in :src:`packaging/Makefile` derive from the same
describe string. ``<describe>`` alone, without ``<extraversion>``,
appears as ``service.version`` and the scope version in OTLP documents
(:doc:`/reference/formats/otlp`) and as ``bpm_version`` and
``shirudo.version`` in a package's ``build-environment.json``.

Version ID
----------

``SHIRUDO_VERSION_ID`` is the SHA-256 that the build writes into the
generated ``util/version_id.c`` (:src:`Makefile.shirudo`). Its input:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Input
     - Value
   * - Revision
     - ``git rev-parse HEAD``, or the content of :src:`VERSION` outside a
       git checkout.
   * - Dirty mark
     - ``-dirty`` when ``git diff-index HEAD`` reports a change to a
       tracked file. Untracked files do not count.
   * - Build configuration
     - The first 16 hexadecimal digits of a SHA-256 over the checksums of
       ``config.mk`` and :src:`Makefile.shirudo`.

``config.mk`` is the operator profile's configuration, which the
feature probes in :src:`Makefile.config` write. It records the compiler and
linker flags of the libraries on the build host, with their paths. The
target profile writes its configuration to ``config-target.mk``, which
the ID does not cover: a target binary's ID takes the ``config.mk`` of
the tree it was built in, or :src:`Makefile.shirudo` alone in a tree
without one, as after ``make clean`` and ``make target``.

Two builds of one commit therefore get different IDs when their trees
hold different ``config.mk`` files, for example an operator package
built on its distribution and a target package built on another host.
``make`` and ``make target`` in one tree give both binaries the same ID.
Outside a git checkout, every build of the same :src:`VERSION` with the
same ``config.mk`` gets the same ID.

The ID does not cover the compiler and its version, the contents of the
libraries, the generated ``vendor/linux/vmlinux.h`` that the BPF objects
compile against, untracked files, ``EXTRAVERSION`` or the release name.

Where it appears and what checks it:

.. list-table::
   :header-rows: 1
   :widths: 42 58

   * - Place
     - Use
   * - ``shirudo version``, ``shirudo version --version-id``
     - Printed.
   * - ``shirudo status``, ``version_id`` in ``status --json``
     - Printed.
   * - ``version_id`` in an evidence document
     - Written by ``attest``. ``attest verify`` does not compare it.
   * - ``upatch load`` and ``upatch unload`` with
       ``--expect-version-id=<hex>``
     - Compared with the target binary's ID. A difference refuses the
       command in phase ``pre_flight`` with ``version_mismatch``
       (``EPERM``). Without the option, or with
       ``--no-version-check``, nothing is compared.

The ID keeps an operator and a target of different builds apart when the
operator asks for it. It authenticates nothing (R5 in
:doc:`/security/threat-model`). :doc:`/operate/maintain/upgrade` says where to
take the expected ID from.

Format and schema numbers
-------------------------

A number names the layout its writer used. No reader converts one
layout into another, and readers ignore JSON keys they do not know.

Artifacts and published documents, which the operator writes and the
target reads:

.. list-table::
   :header-rows: 1
   :widths: 30 12 58

   * - Structure
     - Number
     - Reader on another value
   * - ``.upatch`` container header ``version``
     - 1
     - The target rejects the file. The section versions are in
       :doc:`/reference/formats/upatch-format`.
   * - Repository index ``schema``
     - 1
     - The target refuses the index (``EINVAL``).
   * - Tree publication ``schema``
     - 1
     - The target refuses the publication (``EINVAL``).
   * - ``build-environment.json`` ``format_version``
     - 1
     - Not checked.

:doc:`/reference/formats/bpm-formats` describes the package and index
documents, :doc:`/reference/formats/upatch-tree` the tree documents.

Documents the target writes for operators, collectors and scripts:

.. list-table::
   :header-rows: 1
   :widths: 30 12 58

   * - Document
     - Number
     - Reader on another value
   * - Eventlog record ``schema``
     - 1
     - Not checked by ``status``, ``init``, ``attest`` or ``attest
       verify``. See :doc:`/reference/eventlog`.
   * - Evidence document ``schema``, with ``kind``
       ``shirudo-attestation``
     - 1
     - Neither is checked by ``attest verify``.
   * - ``config`` block of an evidence document, ``schema``
     - 1
     - ``attest verify`` refuses the document (``EINVAL``).
   * - Credential from ``attest challenge``, ``schema``, with ``kind``
       ``shirudo-credential``
     - 1
     - ``attest --challenge`` requires the ``kind`` and does not check
       ``schema``.
   * - ``status --json``
     - 1
     - For consumers. See :doc:`/reference/formats/status-json`.
   * - Operation report of ``upatch load`` and ``upatch unload``, report
       of ``bpm tree sync``
     - 1
     - For consumers. See :doc:`/reference/failure-categories`.
   * - ``--json`` output of ``upatch info``, ``upatch list``, ``upatch
       get`` and ``upatch map``
     - 1
     - For consumers.

State the target keeps for itself:

.. list-table::
   :header-rows: 1
   :widths: 30 12 58

   * - File
     - Number
     - Reader on another value
   * - Config activation records under ``/var/lib/shirudo/config-update``
     - 1
     - Refused as malformed (``EBADMSG``). The active config can then
       not be verified, and commands stop with ``shirudo: image state:``
       and the error.
   * - ``state.json`` and ``pending.json`` of the upatch tree and the
       lines of its ``outcomes``
     - 1
     - Refused by ``bpm tree sync``.

Configuration and bootstrap files carry no version. Unknown keys in the
two bootstrap files and the host file draw a warning, and a config image
whose ``shirudo.conf`` holds a key other than ``eventlog.max_bytes`` or
``map_export.*`` is refused (:doc:`/reference/configuration`).
The config image's hash tree must carry the standard ``veritysetup``
superblock, version 1, with hash type 1, SHA-256, 4096-byte blocks and a
32-byte salt.

Kernel ABI
----------

shirudo needs the signed-loader ABI of the bpf-next tree it targets and
the kernel patches it carries, among them the ``tpm_command`` and
``mm_read_access`` LSM hooks. A release number does not identify such a
kernel. The pre-flight checks ``signed_loader_kernel_abi`` and
``kernel_lsm_hooks`` read the running kernel's BTF, and a load on a
kernel without the ABI fails with ``kernel_abi_unsupported``.
:doc:`/operate/plan/system-requirements` lists the kernel requirements and how
to identify a kernel, :doc:`/internals/kernel-interfaces` every interface
shirudo uses, and :doc:`/internals/kernel-patches` the carried patches.

Mixing builds
-------------

No command negotiates a version with another build, and only
``--expect-version-id`` compares two builds. Keep the operator and every
target on builds of the same commit.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Combination
     - Behavior
   * - Initrd binary and runtime image binary
     - Must be the same build (:doc:`/operate/deploy/boot-integration`).
       Nothing compares their IDs. The runtime binary reads the identity
       map and the tamper and integrity counters that the initrd's
       ``init`` pinned and refuses maps whose layout differs from its
       own: a different identity layout stops every command with
       ``shirudo: image state: Protocol error``.
   * - Operator artifacts on a target of another build
     - Load when a key the target trusts signed them, the container and
       section versions match, and the target kernel accepts the signed
       loader. The target does not check which build produced an
       artifact or a package.
   * - ``attest predict`` and ``attest verify`` against evidence from
       another build
     - Work as long as both builds compute event digests and the
       register the same way. Nothing checks that.
   * - ``shirudo`` and the ``shirudo-build`` helper
     - ``shirudo`` runs the helper that ``SHIRUDO_BUILD`` names, else
       ``/usr/libexec/shirudo/shirudo-build`` (the compiled-in libexec
       path), else the first on ``PATH``, and does not compare versions.

Related
-------

- :doc:`/operate/maintain/upgrade`
- :doc:`/reference/cli/version`
- :doc:`/reference/formats/index`
- :doc:`/operate/plan/system-requirements`
