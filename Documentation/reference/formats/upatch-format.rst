..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: upatch authors, Kernel developers, security reviewers

.upatch format
==============

A ``.upatch`` file is the signed container that :doc:`/reference/cli/build`
writes and that :doc:`/reference/cli/upatch-load` and
:doc:`/reference/cli/upatch-unload` consume. One layout serves both a load
artifact and an unload directive. The structures are defined in
:src:`include/shirudo/upatch.h`. The writer is :src:`tools/shirudo-build/package.c`
and the reader is :src:`util/upatch.c`.

Conventions
-----------

- Every multi-byte integer is little-endian on every architecture.
- Header offsets count from the start of the file. Offsets inside
  ``data`` count from the start of ``data``.
- Fixed-size string fields are NUL-padded and must contain a NUL.
- A file is at most 16 MiB (``UPATCH_FILE_MAX``).

Layout
------

The writer emits the regions in the order below. A reader locates each
region through the header only.

.. list-table::
   :header-rows: 1
   :widths: 18 32 50

   * - Region
     - Located by
     - Content
   * - header
     - offset 0, 360 bytes
     - ``struct upatch_header``.
   * - ``loader_insns``
     - ``loader_insns_off``, ``loader_insns_len``
     - The ``BPF_PROG_TYPE_SYSCALL`` loader program that libbpf's
       ``bpf_object__gen_loader()`` generates, as 8-byte
       ``struct bpf_insn`` records. The writer places it at offset 360.
   * - ``signature``
     - ``signature_off``, ``signature_len``
     - Detached CMS signature over ``loader_insns || data``.
   * - ``data``
     - ``data_off``, ``data_len``
     - The loader's data blob (``gen_loader_opts.data``), then the signed
       sections, their directory and the trailer.
   * - ``metadata``
     - ``metadata_off``, ``metadata_len``
     - Absent. ``shirudo build`` sets both fields to 0. The target never
       reads this region.

Header
------

``struct upatch_header``, 360 bytes, no padding.

.. list-table::
   :header-rows: 1
   :widths: 8 6 20 66

   * - Offset
     - Size
     - Field
     - Value
   * - 0
     - 8
     - ``magic``
     - ``0x53485244554e4150``. The file starts with the bytes
       ``PANUDRHS``.
   * - 8
     - 4
     - ``version``
     - ``1``.
   * - 12
     - 4
     - ``flags``
     - Bit 0, ``DIRECTIVE_UNLOAD``: 0 for a load artifact, 1 for an
       unload directive. Writers set bits 1 to 31 to 0. The reader does not
       check them.
   * - 16
     - 256
     - ``name``
     - The upatch name, NUL-padded. Writers accept 1 to 255 characters of
       ``[A-Za-z0-9._-]`` that do not start with ``.``. For an unload
       directive, the name of the upatch to unload.
   * - 272
     - 32
     - ``payload_sha256``
     - SHA-256 of ``loader_insns || data``, the bytes the signature covers.
   * - 304
     - 4
     - ``loader_insns_off``
     - At least 360 and a multiple of 8.
   * - 308
     - 4
     - ``loader_insns_len``
     - Non-zero multiple of 8.
   * - 312
     - 4
     - ``signature_off``
     - File offset of the signature.
   * - 316
     - 4
     - ``signature_len``
     - Non-zero.
   * - 320
     - 4
     - ``metadata_off``
     - 0.
   * - 324
     - 4
     - ``metadata_len``
     - 0.
   * - 328
     - 4
     - ``data_off``
     - File offset of ``data``.
   * - 332
     - 4
     - ``data_len``
     - Length of ``data``, signed sections included.
   * - 336
     - 4
     - ``log_buf_sz``
     - Writers set 1048576. The target ignores the field and sizes its
       verifier log at 16 MiB.
   * - 340
     - 4
     - ``nr_maps``
     - Number of maps in the BPF object, the count of map descriptors the
       loader writes behind its context.
   * - 344
     - 4
     - ``nr_progs``
     - Number of programs in the BPF object, the count of program
       descriptors behind the map descriptors.
   * - 348
     - 4
     - ``rodata_data_off``
     - Offset in ``data`` of the initial ``.rodata`` value, or 0 when the
       object has no ``.rodata``. At most ``data_len``.
   * - 352
     - 4
     - ``type``
     - ``1`` (``UPATCH_TYPE_BPF``).
   * - 356
     - 4
     - ``reserved1``
     - 0.

Signature
---------

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Property
     - Value
   * - Signed bytes
     - ``loader_insns`` followed by ``data``, exactly as stored. The header
       and ``metadata`` are outside the signature.
   * - Encoding
     - DER CMS ``SignedData``, detached (no encapsulated content), no
       certificates. The signer is identified by its subject key
       identifier.
   * - Algorithm
     - ML-DSA-87. The writer refuses any other key.
   * - Signed attributes
     - Built against OpenSSL 3.x: signed attributes with a SHA-512 message
       digest and no signing time. Built against OpenSSL 4: no signed
       attributes, the signature covers the content directly.
   * - Size
     - At most 16 KiB from the writer. The kernel accepts at most 64 KiB.
   * - Verifier
     - The kernel, during ``BPF_PROG_LOAD`` of the loader, with
       ``attr.keyring_id`` set to ``KEY_SPEC_BPF_KEYRING`` (the ``.bpf``
       keyring). The target passes ``data`` as the frozen value of a
       one-element array map, ``__loader.map``, made exclusive to the
       loader by ``excl_prog_hash`` (SHA-256 of ``loader_insns``), as
       ``fd_array[0]`` with ``fd_array_cnt`` set to 1. The kernel verifies
       the signature over the instructions followed by that map value.

:doc:`/internals/signed-loader` describes the load sequence around this
check.

Signed sections
---------------

What the target needs beyond the loader rides inside ``data``, behind the
loader's own bytes, so the signature covers it. The loader addresses only
its own prefix of ``data``.

.. code-block:: text

   data:  loader data | pad | section | pad | section ... | pad | directory | trailer

The writer aligns each section and the directory to 8 bytes from the start
of ``data`` and fills the padding with zeros. The trailer is the last 16
bytes of ``data``.

Trailer
~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 8 6 20 66

   * - Offset
     - Size
     - Field
     - Value
   * - +0
     - 4
     - ``magic``
     - ``0x52544753``, the bytes ``SGTR``.
   * - +4
     - 4
     - ``version``
     - ``1``.
   * - +8
     - 4
     - ``dir_off``
     - Offset of the directory in ``data``.
   * - +12
     - 4
     - ``nr_sections``
     - Number of directory entries, 1 to 8.

Directory entry
~~~~~~~~~~~~~~~

``nr_sections`` entries of 16 bytes each.

.. list-table::
   :header-rows: 1
   :widths: 8 6 20 66

   * - Offset
     - Size
     - Field
     - Value
   * - +0
     - 4
     - ``tag``
     - Section tag, one of the table below.
   * - +4
     - 4
     - ``reserved``
     - 0.
   * - +8
     - 4
     - ``off``
     - Offset of the section in ``data``.
   * - +12
     - 4
     - ``len``
     - Length of the section in bytes.

Section tags
~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 10 14 12 64

   * - Tag
     - Value
     - Length
     - Content and presence
   * - ``NAME``
     - ``0x454d414e``
     - 256
     - The upatch name, NUL-padded, byte-for-byte equal to the header
       ``name``. Required in a load artifact and in an unload directive.
   * - ``UPGM``
     - ``0x4d475055``
     - variable, non-zero
     - Attach metadata, see `UPGM section`_. Required in a load artifact.
   * - ``UNLD``
     - ``0x444c4e55``
     - 32
     - The ``payload_sha256`` the loaded upatch must carry. Required in an
       unload directive.
   * - ``DCDB``
     - ``0x42444344``
     - variable
     - Signed decoders, see `DCDB section`_. Present in a load artifact
       when its programs declare decoders.

The writer emits ``NAME``, then ``UNLD`` for an unload directive, or
``UPGM`` and an optional ``DCDB`` for a load artifact.

UPGM section
~~~~~~~~~~~~

A 16-byte header followed by ``nr_progs`` program entries, in libbpf's
program iteration order, which is the order of the loader's program
descriptors.

.. list-table::
   :header-rows: 1
   :widths: 8 6 20 66

   * - Offset
     - Size
     - Field
     - Value
   * - +0
     - 4
     - ``magic``
     - ``0x4d475055``, the bytes ``UPGM``.
   * - +4
     - 4
     - ``version``
     - ``1``.
   * - +8
     - 4
     - ``nr_progs``
     - Number of program entries. Equal to the header ``nr_progs``.
   * - +12
     - 4
     - ``nr_maps``
     - Number of maps in the BPF object. Equal to the header ``nr_maps``.

Each program entry is 160 bytes:

.. list-table::
   :header-rows: 1
   :widths: 8 6 20 66

   * - Offset
     - Size
     - Field
     - Value
   * - +0
     - 4
     - ``role``
     - Program role, see the table below.
   * - +4
     - 4
     - ``kind``
     - Attach kind, see the table below. 0 for the serializer and test-run
       roles.
   * - +8
     - 8
     - ``offset``
     - Byte offset into the function for ``kprobe``. 0 for every other
       kind and role.
   * - +16
     - 128
     - ``target``
     - NUL-terminated. The kernel symbol for ``kprobe`` and
       ``kretprobe``, the function glob for ``uprobe.multi`` (no ``,`` or
       ``|``). Empty for every other kind and role.
   * - +144
     - 16
     - ``map``
     - NUL-terminated name of the map a serializer reads. Empty for every
       other role.

.. list-table::
   :header-rows: 1
   :widths: 10 20 70

   * - ``role``
     - Name
     - Program
   * - 0
     - attach
     - A program the target attaches and pins as a link.
   * - 1
     - serializer
     - A ``SEC("syscall")`` program named ``shirudo_serialize__<map>``.
   * - 2
     - test-run
     - The one ``SEC("syscall")`` program named ``shirudo_test__<id>``.
   * - 3
     - loader link
     - A program the signed loader attaches. The target validates and pins
       the returned link without attaching the program again. Only kinds
       0 and 5 are valid for this role.

A loader with role 3 programs returns one link descriptor per program
slot after the program descriptors. Each descriptor is a native-endian
32-bit file descriptor, zero for a slot without a loader-created link.
The signed role requires a positive descriptor in its slot. Readers that
do not support role 3 reject the metadata. Existing role 0 artifacts
retain their userspace attachment path.

.. list-table::
   :header-rows: 1
   :widths: 10 34 56

   * - ``kind``
     - Name
     - Sections that produce it
   * - 0
     - raw tracepoint (BTF target)
     - ``fentry/``, ``fentry.s/``, ``fexit/``, ``fexit.s/``, ``lsm/``,
       ``lsm.s/``, ``tp_btf/``
   * - 1
     - kprobe
     - ``kprobe/<symbol>[+<offset>]``
   * - 2
     - kretprobe
     - ``kretprobe/<symbol>``
   * - 3
     - cgroup_skb ingress
     - ``cgroup_skb/ingress``
   * - 4
     - cgroup_skb egress
     - ``cgroup_skb/egress``
   * - 5
     - fmod_ret
     - ``fmod_ret/<symbol>``, ``fmod_ret.s/<symbol>``
   * - 6
     - netfilter IPv6 pre-routing
     - ``netfilter``
   * - 7
     - uprobe.multi entry probe
     - ``uprobe.multi/<absolute-path>:<function-glob>``

:doc:`/upatches/write/attach-kinds` describes how the target attaches each kind.

When any entry has kind 7, one ``UPUT`` block follows the program entries
and ends the section. Without a kind 7 entry the section ends after the
program entries.

.. list-table::
   :header-rows: 1
   :widths: 8 6 20 66

   * - Offset
     - Size
     - Field
     - Value
   * - +0
     - 4
     - ``magic``
     - ``0x54555055``, the bytes ``UPUT``.
   * - +4
     - 4
     - ``version``
     - ``1``.
   * - +8
     - 4
     - ``nr_targets``
     - Number of target records, equal to the number of kind 7 entries.
   * - +12
     - 4
     - ``reserved``
     - 0.

Each target record is a 16-byte head followed, without padding, by its
variable parts:

.. list-table::
   :header-rows: 1
   :widths: 14 20 66

   * - Offset
     - Field
     - Value
   * - +0
     - ``prog_idx``
     - Index of a kind 7 program entry. Each such entry has exactly one
       record.
   * - +4
     - ``path_len``
     - Length of the path, 1 to 4095.
   * - +8
     - ``build_id_len``
     - Length of the GNU build ID, 1 to 64.
   * - +12
     - ``nr_offsets``
     - Number of offsets, 1 to 1048576.
   * - +16
     - path
     - ``path_len`` bytes, an absolute path without a NUL.
   * - then
     - build ID
     - ``build_id_len`` bytes of the ELF's GNU build ID.
   * - then
     - offsets
     - ``nr_offsets`` little-endian ``u64`` ELF file offsets, strictly
       increasing.

DCDB section
~~~~~~~~~~~~

A 16-byte header, ``nr_decoders`` entries of 200 bytes, then the decoder
sources, concatenated without terminators.

.. list-table::
   :header-rows: 1
   :widths: 8 6 20 66

   * - Offset
     - Size
     - Field
     - Value
   * - +0
     - 4
     - ``magic``
     - ``0x42444344``, the bytes ``DCDB``.
   * - +4
     - 4
     - ``version``
     - ``1``.
   * - +8
     - 4
     - ``nr_decoders``
     - At least 1.
   * - +12
     - 4
     - ``reserved``
     - 0.

Each decoder entry:

.. list-table::
   :header-rows: 1
   :widths: 8 6 20 66

   * - Offset
     - Size
     - Field
     - Value
   * - +0
     - 4
     - ``language``
     - ``1``, Lua.
   * - +4
     - 4
     - ``api_version``
     - ``1``.
   * - +8
     - 4
     - ``input_format``
     - ``1``, ``shirudo.map.v1``.
   * - +12
     - 4
     - ``export_signal``
     - ``1`` log, ``2`` metric.
   * - +16
     - 64
     - ``upatch``
     - NUL-terminated upatch name. The writer requires the artifact's name.
   * - +80
     - 16
     - ``map``
     - NUL-terminated name of a map in the object.
   * - +96
     - 64
     - ``source``
     - NUL-terminated relative path of the decoder source, resolved
       against the directory of the ``.bpf.c`` file. No ``..`` component.
   * - +160
     - 32
     - ``entrypoint``
     - NUL-terminated name of the Lua function.
   * - +192
     - 4
     - ``source_off``
     - Offset of the source in the section, behind the entries.
   * - +196
     - 4
     - ``source_len``
     - Length of the source, non-zero.

The writer takes each entry from a ``struct decoder_manifest`` that
the BPF program declares in ``.rodata`` (:src:`bpf/lib/decoder.h`,
192 bytes, magic ``0x44434544``, the bytes ``DECD``, ``u16`` fields
``version``, ``language``, ``api_version``, ``input_format``,
``export_signal`` and ``reserved``, then the same four strings). It scans
``.rodata`` at 4-byte steps, accepts one decoder per upatch and map, and
reads each source file, at most 16 MiB. A decoder whose ``language``,
``api_version``, ``input_format`` or ``export_signal`` differs from the
values above fails the build. :doc:`/upatches/write/decoders` covers the decoder
API.

Header fields outside the signature
-----------------------------------

The header is not signed. The target checks some fields against the
signed bytes and trusts others as they are.

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Field
     - Treatment
   * - ``name``
     - Must equal the signed ``NAME`` section, all 256 bytes, for a load
       and for an unload.
   * - ``payload_sha256``
     - Recomputed as SHA-256 of ``loader_insns || data`` and must match.
       The target records it in the ``security.bpf.shirudo.payload`` xattr
       of the upatch's pin directory, measures it in the load event and
       matches it against an unload directive's ``UNLD`` value.
   * - ``flags``
     - Bit 0 selects the load or the unload path. Each path refuses an
       artifact without the signed section it requires (``UPGM`` or
       ``UNLD``).
   * - ``nr_progs``
     - Must equal the ``nr_progs`` of the signed ``UPGM`` section.
   * - ``nr_maps``
     - Must equal the ``nr_maps`` of the signed ``UPGM`` section. The
       target uses it to find the program descriptors behind the map
       descriptors in the loader context, and to pin and close the map
       descriptors.
   * - ``rodata_data_off``
     - Bounds-checked only: the ``.rodata`` size from the signed BTF must
       fit between it and the end of ``data``. ``bpm info data`` reads
       ``.rodata`` at this offset, and the operator's ``.rodata`` rewrites
       (``bpm build`` and ``bpm config update`` rodata entries) patch at it
       and re-sign.
   * - ``log_buf_sz``
     - Ignored.
   * - ``metadata_off``, ``metadata_len``
     - Bounds-checked. Not read on the target.
   * - ``magic``, ``version``, ``type``, ``reserved1``, section offsets and
       lengths
     - Checked by the reader, see `Reader validation`_.

Reader validation
-----------------

:src:`util/upatch.c` applies these checks in order. Any failure rejects the
file.

#. The file is a regular file, not empty and at most 16 MiB.
#. The file is at least 360 bytes long.
#. ``magic`` equals ``0x53485244554e4150``.
#. ``version`` equals 1.
#. ``name`` contains a NUL.
#. ``reserved1`` is 0.
#. ``type`` equals 1.
#. ``loader_insns_off`` is at least 360 and a multiple of 8,
   ``loader_insns_len`` is a multiple of 8, and the region lies inside the
   file.
#. ``signature``, ``metadata`` and ``data`` each lie inside the file, and
   each non-empty one starts at or after offset 360.
#. ``rodata_data_off`` is at most ``data_len``.
#. ``loader_insns_len`` and ``signature_len`` are not 0.

The reader then parses the signed sections. A failure here does not reject
the file. The reader treats the whole directory as absent, so a load or an
unload later refuses for the section it lacks, and
:doc:`/reference/cli/upatch-info` shows no signed sections.

#. ``data`` is at least 16 bytes long and its last 16 bytes are a trailer
   with magic ``SGTR`` and version 1.
#. ``nr_sections`` is 1 to 8, and the directory lies between ``dir_off``
   and the trailer.
#. Each entry has ``reserved`` 0 and a section that ends at or before
   ``dir_off``.
#. Each tag is ``NAME``, ``UPGM``, ``UNLD`` or ``DCDB``, and appears at most
   once.
#. ``NAME`` is 256 bytes and contains a NUL. ``UPGM`` is not empty.
   ``UNLD`` is 32 bytes.
#. ``DCDB`` has magic ``DCDB``, version 1, at least one entry, all entries
   inside the section, NUL-terminated strings, non-zero ``language``,
   ``api_version``, ``input_format`` and ``export_signal``, and each source
   inside the section behind the entries.

Target admission
----------------

A load artifact passes the reader, then these checks in order. A failure
of checks 1 to 6 is reported as ``parser_rejected``, see
:doc:`/reference/failure-categories`.

#. ``flags`` bit 0 is clear.
#. ``loader_insns_len`` is a multiple of 8.
#. The header ``name`` is not empty, does not start with ``.`` and
   contains only ``[A-Za-z0-9._-]``.
#. A ``NAME`` section is present and equals the header ``name``.
#. ``payload_sha256`` equals SHA-256 of ``loader_insns || data``.
#. A ``UPGM`` section is present and parses: version 1 (any other version
   is ``EOPNOTSUPP``), ``nr_maps`` and ``nr_progs`` equal to the header's,
   every entry valid for its role and kind, and a ``UPUT`` block that is
   present exactly when a kind 7 entry exists and ends the section.
#. Each ``uprobe.multi`` target file is a regular file whose GNU build ID
   equals the recorded one.
#. The kernel verifies the signature in ``BPF_PROG_LOAD``.

An unload directive passes the reader, then these checks:

#. ``flags`` bit 0 is set.
#. ``NAME`` and ``UNLD`` sections are present and ``NAME`` equals the
   header ``name``.
#. Load checks 2 to 5 above, then the kernel verifies the signature in
   ``BPF_PROG_LOAD``. The target never runs the directive's loader.
#. The ``UNLD`` value equals the ``security.bpf.shirudo.payload`` xattr of
   the loaded upatch, or no upatch of that name is pinned.

Versioning
----------

.. list-table::
   :header-rows: 1
   :widths: 30 14 56

   * - Structure
     - Version
     - Reader on another value
   * - Container header
     - 1
     - Rejects the file.
   * - Trailer
     - 1
     - Treats the directory as absent.
   * - ``UPGM``
     - 1
     - Load refused (``EOPNOTSUPP``).
   * - ``UPUT``
     - 1
     - Load refused.
   * - ``DCDB``
     - 1
     - Treats the directory as absent.
   * - Decoder manifest in ``.rodata``
     - 1
     - The writer skips the candidate.

A section tag the reader does not know makes it treat the directory as
absent. A new section therefore needs readers that know its tag before
writers emit it. Reserved fields are 0 in every file a writer emits. The
reader checks ``reserved1``, the directory entries' ``reserved`` and the
``UPUT`` ``reserved`` field. It does not check ``flags``
bits 1 to 31 or the ``DCDB`` ``reserved`` field.

Limits
------

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - Item
     - Limit
   * - File size
     - 16 MiB
   * - Signature
     - 16 KiB (writer), 64 KiB (kernel)
   * - Signed sections
     - 1 to 8
   * - Name of an upatch
     - 255 characters of ``[A-Za-z0-9._-]``, not starting with ``.``
   * - ``kprobe``, ``kretprobe`` or ``uprobe.multi`` target
     - 127 bytes
   * - Serializer map name
     - 15 bytes
   * - ``uprobe.multi`` path
     - 4095 bytes
   * - GNU build ID
     - 1 to 64 bytes
   * - ``uprobe.multi`` offsets per program
     - 1 to 1048576
   * - Decoder source
     - 16 MiB per file
   * - Target verifier log
     - 16 MiB

Related
-------

- :doc:`/reference/cli/build` and :doc:`/reference/cli/upatch-info`
- :doc:`/internals/signed-loader`
- :doc:`/upatches/write/attach-kinds`
- :doc:`bpm-formats` for the packages that carry ``.upatch`` files
