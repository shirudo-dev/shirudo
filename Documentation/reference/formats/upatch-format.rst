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
region through the header only. Figure 1 shows the regions in file
order and what ``data`` holds.

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

.. figure:: /images/reference-upatch-layout.svg
   :alt: A strip of the file: an unsigned 360-byte header, then
         loader_insns, the signature and data, with a bracket that joins
         loader_insns and data as the signed bytes. Below, data drawn
         wider: the loader data, then the NAME, UPGM or UNLD, DCDB and
         SHPL sections at 8-byte boundaries, the directory and the
         16-byte trailer, whose dir_off points to the directory, whose
         entries point to the sections.

   Figure 1. A ``.upatch`` file in file order, not to scale, with
   ``data`` drawn wider below. The signed bytes are two regions with the
   signature between them.

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
       ``[A-Za-z0-9._-]``, each ``.`` counting as two, that do not start
       with ``.``. For an unload
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
     - ``1`` (``UPATCH_TYPE_BPF``) or ``2`` (``UPATCH_TYPE_JAVA``), see
       `Java payloads`_. Equal to the signed ``PTYP`` section, or 1 where
       there is none.
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
     - For a Java payload, the target in userspace, see `Java payloads`_.
       For a BPF payload, the kernel, during ``BPF_PROG_LOAD`` of the loader, with
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
loader's own bytes, so the signature covers it, as Figure 1 shows. The
loader addresses only its own prefix of ``data``. The writer aligns each
section and the directory to 8 bytes from the start of ``data`` and fills
the padding with zeros. The trailer is the last 16 bytes of ``data``, and
the directory ends where the trailer begins.

The signature and ``payload_sha256`` cover ``loader_insns`` followed by
``data`` with nothing between the two, and the header that gives their
lengths is not signed. The trailer is the last 16 of the signed bytes
wherever a header ends the loader, and ``dir_off + 16 * nr_sections + 16``
is the length of ``data``. A header that divides the same signed bytes
elsewhere therefore names a directory that does not end at the trailer.
The reader treats that directory as absent, and the load refuses for
the signed name it lacks.

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
     - Offset of the directory in ``data``. The directory's last entry
       ends at the trailer.
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
   * - ``SHPL``
     - ``0x4c504853``
     - variable
     - Signed policy labels, each naming a policy ID, one-hot bit and
       absolute file path or pattern. Its presence opts into the shared task
       ``shirudo_task_policy`` and socket ``shirudo_sock_policy``
       bindings.
   * - ``PTYP``
     - ``0x50595450``
     - 4
     - The payload type, a little-endian ``__u32`` equal to the header
       ``type``. Required in a Java payload, absent from a BPF one.
   * - ``JAVA``
     - ``0x4156414a``
     - variable, non-zero
     - The Java agent ``.jar``, byte for byte. Required in a Java load
       artifact.

For a BPF payload the writer emits ``NAME``, then ``UNLD`` for an unload
directive, or ``UPGM`` and optional ``DCDB`` and ``SHPL`` sections for a
load artifact. For a Java payload it emits ``NAME`` and ``PTYP``, then
``UNLD`` for an unload directive or ``JAVA`` for a load artifact.

Java payloads
~~~~~~~~~~~~~

A Java payload (``type`` 2) carries a Java agent ``.jar`` instead of a BPF
loader. It has no loader instructions and no ``metadata``, and
``loader_insns_off``, ``log_buf_sz``, ``nr_maps``, ``nr_progs`` and
``rodata_data_off`` are 0. Its ``data`` holds only signed sections, so the
signature covers ``data`` alone and ``payload_sha256`` is SHA-256 of
``data``. The kernel never sees a Java payload. The target verifies its
signature in userspace with OpenSSL, against the unrevoked certificates of
the authenticated runtime's set, and then requires the signer to be a key
the sealed ``.bpf`` keyring holds. That lookup compares the description the
kernel gives the key, not the key material.

The header is not signed, so the signed ``PTYP`` section carries the type
too, and the reader refuses a file whose header ``type`` differs from it. A
BPF payload's header cannot be relabelled ``2``, since its signed sections
carry no ``PTYP``. A Java payload cannot pass for a BPF one either: its
``data`` has no loader, and any split of its signed bytes into a loader and
data leaves a directory that does not end at the trailer, so the reader
finds no ``NAME`` and the load refuses.

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
     - ``offset`` / ``xdp``
     - Byte offset into the function for ``kprobe`` and for ``uprobe`` at a
       function; the file offset the target uses is in the ``UPUT`` record.
       For XDP, a
       little-endian ``u32 device_classes`` followed by ``u32 reserved``
       (0). The mask is nonzero and uses only bits 1 (network-facing),
       2 (virtual), 8 (VM) and 16 (unknown); 27 selects all classes.
       0 for every other kind and role.
   * - +16
     - 128
     - ``target``
     - NUL-terminated. The kernel symbol for ``kprobe`` and
       ``kretprobe``, the function or the ``0x`` file offset as written for
       ``uprobe`` and ``uretprobe``, the function glob for ``uprobe.multi``
       and ``uretprobe.multi`` (no ``,`` or ``|``). Empty for every other
       kind and role.
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
     - uprobe.multi
     - ``uprobe.multi/<absolute-path>:<function-glob>``,
       ``uprobe.multi.s/<absolute-path>:<function-glob>``
   * - 8
     - native XDP device classes
     - ``xdp/<decimal-mask>``
   * - 9
     - uretprobe.multi
     - ``uretprobe.multi/<absolute-path>:<function-glob>``,
       ``uretprobe.multi.s/<absolute-path>:<function-glob>``
   * - 10
     - uprobe
     - ``uprobe/<absolute-path>:<function>[+<offset>]``,
       ``uprobe/<absolute-path>:0x<file-offset>``, and their ``uprobe.s``
       forms
   * - 11
     - uretprobe
     - ``uretprobe/<absolute-path>:<function>``,
       ``uretprobe/<absolute-path>:0x<file-offset>``, and their
       ``uretprobe.s`` forms

:doc:`/upatches/write/attach-kinds` describes how the target attaches each kind.
XDP retains the 160-byte entry and UPGM version 1; readers that do not
know kind 8 refuse it. Its ``target`` and ``map`` are empty. A reader
refuses a device-class mask that sets a bit outside 27, which bit 4 is,
and a table whose XDP entries share a class.
:doc:`/upatches/write/attach-kinds` says how a device is classified.

When any entry has kind 7, 9, 10 or 11, one ``UPUT`` block follows the
program entries and ends the section. Without such an entry the section
ends after the program entries.

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
     - Number of target records, equal to the number of kind 7, 9, 10 and
       11 entries.
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
     - Index of a kind 7, 9, 10 or 11 program entry. Each such entry has
       exactly one record.
   * - +4
     - ``path_len``
     - Length of the path, 1 to 4095.
   * - +8
     - ``build_id_len``
     - Length of the GNU build ID, 1 to 64.
   * - +12
     - ``nr_offsets``
     - Number of offsets, 1 to 1048576; exactly 1 for kinds 10 and 11.
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
     - NUL-terminated, empty or the artifact's name. The writer refuses
       another name. A reader ignores the field: the decoder belongs to
       the upatch whose signed data carries it, and the reader picks it
       by ``map``.
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
``.rodata`` at 4-byte steps, accepts one decoder per map, and reads each
source file, at most 16 MiB. A decoder whose ``language``,
``api_version``, ``input_format`` or ``export_signal`` differs from the
values above fails the build. :doc:`/upatches/write/decoders` covers the decoder
API.

SHPL section
~~~~~~~~~~~~

``SHPL`` starts with a 20-byte version 1 header, followed by ``count``
fixed-size entries. ``policy_map_idx`` and ``socket_policy_map_idx`` are
the zero-based indices of the shared maps in the loader's map descriptor
array. The builder accepts this section only when the BPF object declares
compatible maps named ``shirudo_task_policy`` and ``shirudo_sock_policy``.
At load time, shirudo supplies the pinned task and socket storage maps at
those descriptors; the loader does not create or pin private copies.
upatches without ``SHPL`` use their normal maps.

.. list-table::
   :header-rows: 1
   :widths: 8 6 24 62

   * - Offset
     - Size
     - Field
     - Value
   * - +0
     - 4
     - ``magic``
     - ``0x4c504853``, the bytes ``SHPL``.
   * - +4
     - 4
     - ``version``
     - ``1``.
   * - +8
     - 4
     - ``count``
     - Number of policy/path entries; non-zero.
   * - +12
     - 4
     - ``policy_map_idx``
     - Map descriptor index, less than ``nr_maps`` and 64.
   * - +16
     - 4
     - ``socket_policy_map_idx``
     - Distinct map descriptor index, less than ``nr_maps`` and 64.

Each entry is 4168 bytes: a little-endian one-hot ``u64`` policy bit,
64 bytes of NUL-terminated policy ID, then 4096 bytes that hold a
NUL-terminated absolute path of at most 255 bytes. The path does not end
in ``/``, and ``*`` and ``?`` appear in its last component alone, where
they make it a pattern (:doc:`beefile`); the target refuses a section
with any other path. After a successful load, shirudo applies each entry
by ORing the policy bit into the existing policy xattr of the inode the
path names, or of every regular file in the path's directory whose name
the pattern matches, without following a symbolic link there. It takes
the entries from the copy of the artifact the kernel verified, not from
the file again.

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
     - Must equal the offset in ``data`` from which the signed loader's
       ``BPF_MAP_UPDATE_ELEM`` of the ``.rodata`` map takes its value,
       which also holds the ``.rodata`` size from the BTF its one
       ``BPF_BTF_LOAD`` takes from ``data``. ``bpm info data`` reads
       ``.rodata`` there, and the operator's ``.rodata`` rewrites
       (``bpm build`` and ``bpm config update`` rodata entries) patch
       there and re-sign. A header that names another offset is
       refused, so a package from a registry cannot aim the rewrite at
       other signed bytes.
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
#. ``signature``, ``metadata`` and ``data`` each lie inside the file, and
   each non-empty one starts at or after offset 360.
#. ``signature_len`` is not 0.
#. ``type`` is 1 or 2.
#. For ``type`` 1: ``loader_insns_off`` is at least 360 and a multiple of
   8, ``loader_insns_len`` is a multiple of 8 and not 0, the region lies
   inside the file, and ``rodata_data_off`` is at most ``data_len``.
#. For ``type`` 2: ``loader_insns_off``, ``loader_insns_len``,
   ``metadata_len``, ``log_buf_sz``, ``nr_maps``, ``nr_progs`` and
   ``rodata_data_off`` are 0, and ``data_len`` is not.

The reader then parses the signed sections. A failure here does not reject
the file. The reader treats the whole directory as absent, so a load or an
unload later refuses for the section it lacks, and
:doc:`/reference/cli/upatch-info` shows no signed sections.

#. ``data`` is at least 16 bytes long and its last 16 bytes are a trailer
   with magic ``SGTR`` and version 1.
#. ``nr_sections`` is 1 to 8, and the directory's entries start at
   ``dir_off`` and end where the trailer begins.
#. Each entry has ``reserved`` 0 and a section that ends at or before
   ``dir_off``.
#. Each tag is ``NAME``, ``UPGM``, ``UNLD``, ``DCDB``, ``SHPL``, ``PTYP``
   or ``JAVA``, and appears at most once.
#. ``NAME`` is 256 bytes and contains a NUL. ``UPGM`` is not empty.
   ``UNLD`` is 32 bytes. ``PTYP`` is 4 bytes. ``JAVA`` is not empty.
#. ``DCDB`` has magic ``DCDB``, version 1, at least one entry, all entries
   inside the section, NUL-terminated strings, non-zero ``language``,
   ``api_version``, ``input_format`` and ``export_signal``, and each source
   inside the section behind the entries.

Last, the reader rejects the file unless the header ``type`` equals the
``PTYP`` value, or is 1 where the sections carry no ``PTYP``. A Java file
whose directory is malformed is therefore rejected rather than read with
no sections.

CBMC proves these checks of the reader for every header, of a file of
any size, and for the signed sections, decoders, policy labels and
program table within the bounds
:doc:`/contribute/testing/proof-coverage` lists: what the reader accepts
lies inside the file, and what it refuses leaves nothing behind. Within
the bounds listed there it also proves that the reader takes what the
writer lays out, and reads back the header, the signed sections, the
decoders and the program table as they were written.

Target admission
----------------

A load artifact passes the reader, then these checks in order. A failure
of checks 1 to 7 is reported as ``parser_rejected``, see
:doc:`/reference/failure-categories`.

#. ``flags`` bit 0 is clear.
#. ``type`` is 1.
#. ``loader_insns_len`` is a multiple of 8.
#. The header ``name`` is not empty, does not start with ``.``, contains
   only ``[A-Za-z0-9._-]`` and has at most 255 characters with each ``.``
   counted twice, so that its pin directory name fits.
#. A ``NAME`` section is present and equals the header ``name``.
#. ``payload_sha256`` equals SHA-256 of ``loader_insns || data``.
#. A ``UPGM`` section is present and parses: version 1 (any other version
   is ``EOPNOTSUPP``), ``nr_maps`` and ``nr_progs`` equal to the header's,
   every entry valid for its role and kind, and a ``UPUT`` block that is
   present exactly when a kind 7, 9, 10 or 11 entry exists and ends the
   section.
#. Each ``uprobe``, ``uretprobe``, ``uprobe.multi`` and
   ``uretprobe.multi`` target file is a regular file whose GNU build ID
   equals the recorded one.
#. The kernel verifies the signature in ``BPF_PROG_LOAD``.

A Java load artifact passes the reader, then, in place of the checks
above: ``flags`` bit 0 is clear, the name is as in check 4, ``NAME``,
``PTYP`` and ``JAVA`` are present, ``NAME`` equals the header ``name``,
``PTYP`` is 2, ``payload_sha256`` equals SHA-256 of ``data``
(``parser_rejected``), and the signature verifies over ``data`` under a
certificate ``init`` enrolled in the ``.bpf`` keyring
(``signature_rejected``). A Java unload directive takes the same checks
with ``UNLD`` in place of ``JAVA`` and bit 0 set. See
:doc:`/upatches/write/java-agents`.

An unload directive passes the reader, then these checks:

#. ``flags`` bit 0 is set.
#. ``NAME`` and ``UNLD`` sections are present and ``NAME`` equals the
   header ``name``.
#. Load checks 2 to 6 above, then the kernel verifies the signature in
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
   * - ``SHPL``
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
   * - Name of a upatch
     - 255 characters of ``[A-Za-z0-9._-]``, each ``.`` counting as two,
       not starting with ``.``
   * - ``kprobe``, ``kretprobe``, ``uprobe``, ``uretprobe``,
       ``uprobe.multi`` or ``uretprobe.multi`` target
     - 127 bytes
   * - Serializer map name
     - 15 bytes
   * - ``uprobe``, ``uretprobe``, ``uprobe.multi`` or ``uretprobe.multi``
       path
     - 4095 bytes
   * - GNU build ID
     - 1 to 64 bytes
   * - ``uprobe.multi`` or ``uretprobe.multi`` offsets per program
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
