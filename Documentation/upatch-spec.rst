..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

The .upatch container format
============================

This document specifies the on-disk ``.upatch`` container: the portable,
signed unit the operator produces with ``shirudo build`` and the target
consumes with ``shirudo upatch load`` and ``unload``.  It is the
byte-level reference.  The structures live in
``include/shirudo/upatch.h``, the writer in
``tools/shirudo-build/package.c``, the reader in ``util/upatch.c``.

A ``.upatch`` carries everything a signed ``BPF_PROG_LOAD`` needs to
install a BPF program on a machine other than the one that built it:
the gen_loader "light skeleton" instructions, the data those
instructions reference, a detached CMS signature, and a small amount of
metadata.  There is exactly one container shape for both LOAD artifacts
and UNLOAD directives; a flag bit distinguishes them.

1) Conventions
--------------

Every multi-byte integer is little-endian on every supported
architecture.  Operator and target may differ in architecture; the
wire format does not.

The file begins with a 360-byte header of naturally aligned fields
with no padding.  All other content is referenced by
``*_off``/``*_len`` pairs in the header, as byte offsets from the start
of the file.  Sections do not overlap the header and must lie within
the file.

Sizes are bounded: a reader rejects a file larger than 16 MiB.
Artifacts are small in practice.

2) File layout
--------------

::

    offset 0    +-------------------------------------------+
                | header (360 bytes, fixed)                 |
    360         +-------------------------------------------+
                | loader_insns   (signature-covered)        |
                +-------------------------------------------+
                | signature      (CMS/PKCS#7, detached)     |
                +-------------------------------------------+
                | data           (signature-covered)        |  optional
                +-------------------------------------------+
                | metadata                                  |  optional
                +-------------------------------------------+

The writer emits the sections in this order, but a reader must rely
only on the header offsets, never on adjacency.  ``loader_insns``
begins at offset 360, immediately after the header.  ``data`` and
``metadata`` are optional; an absent section
has its ``*_off`` set to 0.

3) Header
---------

``struct shirudo_upatch_header``, 360 bytes, little-endian, no padding:

==========  ====  ======  =====================  ===========================================
offset      size  type    field                  meaning
==========  ====  ======  =====================  ===========================================
0           8     u64     magic                  ``0x53485244554E4150`` (see below)
8           4     u32     version                ``1``
12          4     u32     flags                  bit 0 = ``DIRECTIVE_UNLOAD``; bits 1-31 zero
16          256   char[]  name                   upatch name; NUL-padded, not guaranteed
                                                 NUL-terminated on disk
272         32    u8[]    payload_sha256         SHA-256 of ``loader_insns || data``
304         4     u32     loader_insns_off       file offset of the loader instructions
308         4     u32     loader_insns_len       length in bytes (multiple of 8)
312         4     u32     signature_off          file offset of the CMS signature
316         4     u32     signature_len          length in bytes
320         4     u32     metadata_off           file offset of metadata, or 0
324         4     u32     metadata_len           length in bytes, or 0
328         4     u32     data_off               file offset of the loader data, or 0
332         4     u32     data_len               length in bytes, or 0
336         4     u32     log_buf_sz             verifier-log buffer size to allocate at load
340         4     u32     nr_maps                gen_loader bpf_map_desc count
344         4     u32     nr_progs               gen_loader bpf_prog_desc count
348         4     u32     reserved0              zero
352         4     u32     type                   ``1`` = BPF
356         4     u32     reserved1              zero
==========  ====  ======  =====================  ===========================================

magic
~~~~~

``magic`` is the u64 ``0x53485244554E4150`` stored little-endian; its
bytes spell ``SHRDUNAP`` when read most-significant-first.  A reader
that sees any other value rejects the file.

log_buf_sz
~~~~~~~~~~

There is no log-buffer section in the file.  ``log_buf_sz`` (typically
1 MiB) records the size of the verifier-log buffer the target allocates
in memory at load, so a verifier rejection can be captured in full and
surfaced in the failure report.  Only the size travels in the artifact.

nr_maps and nr_progs
~~~~~~~~~~~~~~~~~~~~

After the signed loader runs under ``BPF_PROG_TEST_RUN``, it writes the
created map and program fds into descriptor arrays trailing its
context, in libbpf's object-iteration order.  The target has only the
``.upatch``, not the original object, so these counts tell it where to
find the resulting ``prog_fd`` to attach and pin.  They mirror
gen_loader's own iteration.

4) Sections
-----------

loader_insns
~~~~~~~~~~~~

The bytes of ``gen_loader_opts.insns`` after ``bpf_object__gen_loader()``
and ``bpf_object__load()`` on the operator.  This is a
``BPF_PROG_TYPE_SYSCALL`` "light skeleton" loader: run via
``BPF_PROG_TEST_RUN`` on the target, it issues the ``bpf()`` calls
(``BPF_BTF_LOAD``, ``BPF_MAP_CREATE``, ``BPF_PROG_LOAD``, ...) that
install the payload.  The signature covers this section concatenated
with ``data``.

For an UNLOAD directive (``flags & DIRECTIVE_UNLOAD``) the loader is not
a gen_loader output but the compiled bytes of the small hand-written
``bpf/unload.c`` template, parameterised through its ``.rodata`` with
the target name and the expected ``payload_sha256``.

signature
~~~~~~~~~

A detached CMS/PKCS#7 signature over ``loader_insns || data``, produced
by the vendored ``util/sign.c`` on the operator.  On the target, the
kernel's ``bpf_prog_verify_signature()`` checks it against the
certificate in the sealed bpf keyring, named as ``attr.keyring_id``
(``KEY_SPEC_BPF_KEYRING``), before the
verifier and the LSM hooks run.

The container is algorithm-agnostic: the SignerInfo names the key
algorithm, the signer is identified by subjectKeyIdentifier, and no
certificate is embedded.  shirudo's writer signs with ML-DSA-87 only
(it refuses other keys) and emits one of two kernel-accepted forms,
depending on the OpenSSL it links: signed attributes (contentType and
messageDigest only, no signingTime, so the bytes are reproducible) with
a SHA-512 message digest on OpenSSL 3.x, or a signature over the
content itself with no attributes on OpenSSL 4.  An ML-DSA-87
SignerInfo is about 4.9 KiB.  The writer caps ``signature_len`` at
16 KiB and the kernel at 64 KiB.

data
~~~~

The bytes of ``gen_loader_opts.data``: the blob the loader instructions
reference (the program BTF, ``.rodata`` and map initial values,
relocation inputs, ...).  The loader is parameterised by this data, so
it must travel with the instructions.  Absent (``data_off == 0``) only
for artifacts with no such data.  Writers may append a decoder blob and
trailer; generated loaders ignore the trailing bytes because all their
offsets refer to the original prefix.

Signed decoder trailer.  A BPF source declares
``struct shirudo_decoder_manifest`` in ``.rodata``.  At build time
shirudo resolves and embeds each referenced decoder source before
signing ``loader_insns || data``, so the decoders are signature-covered.
The final 16 bytes of ``data`` are:

==========  ====  =====================  ====================================
offset      size  field                  meaning
==========  ====  =====================  ====================================
+0          4     magic                  ``0x52544344`` (``"DCTR"`` LE)
+4          4     version                ``1``
+8          4     decoder_off            offset from the start of ``data``
+12         4     decoder_len            decoder blob length
==========  ====  =====================  ====================================

The blob starts with magic ``0x42444344`` (``"DCDB"`` LE), a version, a
decoder count and a reserved word.  Each 200-byte entry holds the
language, API version, input format, fixed-size upatch, map, source
and entrypoint strings, and the source offset and length within the
blob.  Version 1 defines language ``1`` as Lua and input format ``1``
as serializer pages v2.  The decoder API itself is described in
`telemetry <telemetry.rst>`__.

metadata
~~~~~~~~

Optional auxiliary bytes, not signature-covered.  An UNLOAD directive
carries its expected ``payload_sha256`` here so the target can compute
the unload chain event without parsing the loader data.

A LOAD upatch produced by ``shirudo build`` carries attach metadata:

==========  ====  =====================  ====================================
offset      size  field                  meaning
==========  ====  =====================  ====================================
+0          4     magic                  ``0x4D475055`` (``"UPGM"`` LE)
+4          4     version                ``1``
+8          4     nr_progs               number of program entries
+12         4     reserved               zero
+16         var   progs                  one entry per program
==========  ====  =====================  ====================================

Each program entry is 160 bytes:

==========  ====  =====================  ====================================
offset      size  field                  meaning
==========  ====  =====================  ====================================
+0          4     role                   ``0`` attach program, ``1`` serializer
+4          4     kind                   ``0`` raw tracepoint, ``1`` kprobe,
                                         ``2`` kretprobe,
                                         ``3`` cgroup_skb ingress,
                                         ``4`` cgroup_skb egress,
                                         ``5`` fmod_ret,
                                         ``6`` netfilter IPv6 pre-routing,
                                         ``7`` uprobe.multi entry probe
+8          8     offset                 kprobe offset; otherwise zero
+16         128   target                 NUL-terminated kprobe symbol or
                                         uprobe function glob
+144        16    map                    NUL-terminated serializer target map
==========  ====  =====================  ====================================

Version 1 optionally appends one ``UPUT`` target block after the fixed
program entries when any entry has attach kind 7.  Without uprobe
programs, version 1 ends after the fixed entries:

==========  ====  =====================  ====================================
offset      size  field                  meaning
==========  ====  =====================  ====================================
+0          4     magic                  ``0x54555055`` (``"UPUT"`` LE)
+4          4     version                ``1``
+8          4     nr_targets             number of variable target records
+12         4     reserved               zero
+16         var   targets                one record per uprobe program
==========  ====  =====================  ====================================

Each target record begins with four little-endian ``u32`` values:
``prog_idx``, ``path_len``, ``build_id_len`` and ``nr_offsets``.  They
are followed immediately, without padding, by ``path_len`` path bytes
(no NUL), ``build_id_len`` raw GNU build-ID bytes, and ``nr_offsets``
little-endian ``u64`` ELF file offsets.  Paths are absolute and shorter
than 4096 bytes; build IDs are 1 to 64 bytes; offset arrays are
non-empty, sorted, unique and limited to 1,048,576 entries.  The target
count must equal the number of kind-7 program entries, each program
index appearing once.

Attach metadata is advisory in the container integrity model because
metadata is not CMS-signed in v1.  The loaded program bytes remain
hash-locked by the signed loader; the target validates this blob before
creating links.  ``cgroup_skb`` support is limited to
``cgroup_skb/ingress`` and ``cgroup_skb/egress`` sections, attached to
the cgroup v2 root through a pinned ``bpf_link``.  ``netfilter``
sections attach as ``BPF_NETFILTER`` at IPv6 ``NF_INET_PRE_ROUTING``
with ``NF_IP6_PRI_RAW_BEFORE_DEFRAG`` priority, an early IPv6 ingress
hook before extension-header protocol delivery.  ``sk_skb`` and socket
filter sections are rejected by ``shirudo build``.  ``fmod_ret/<symbol>``
and ``fmod_ret.s/<symbol>`` sections attach as ``BPF_MODIFY_RETURN`` so
a return-value override can reject a call before the hooked function
body runs.  Kprobe return override uses a normal ``kprobe/<symbol>``
section plus the program's ``bpf_override_return()`` call; the attach
metadata remains ``kprobe``.

Uprobe authoring uses the entry-only section form
``SEC("uprobe.multi//absolute/path:function_glob")``.  The glob has
libbpf's semantics: ``*`` matches any sequence and ``?`` one character,
so ``*Func`` selects both ``fooFunc`` and ``barFunc`` in one ELF.
Comma and ``|`` alternation, return probes and session probes are not
supported.  At build time shirudo resolves the glob against ``STT_FUNC``
symbols, converts matches to ELF file offsets, sorts and de-duplicates
them, and records the target's GNU build ID.  A zero-match glob or a
missing build ID is a build error.

Before any BPF load, the target opens the recorded ELF, verifies that
its GNU build ID is unchanged, and keeps the descriptor open through
link creation.  It creates a system-wide ``BPF_TRACE_UPROBE_MULTI``
entry link with ``BPF_F_UPROBE_MULTI_PATH_FD``.  ``shirudo status``
renders such a link as ``uprobe.multi/<path> (<count> funcs)``.

5) flags
--------

``flags`` bit 0 is ``SHIRUDO_DIRECTIVE_UNLOAD``.  Clear, the artifact is
a LOAD (install a program); set, it is a signed UNLOAD directive
(authorise removing a named, previously loaded upatch).  Bits 1-31 are
reserved and must be zero.  The flag changes the loader program and the
metadata semantics but nothing about the layout, the signed-content
digest or the kernel verification: both kinds load through the same
``BPF_PROG_LOAD`` + signature + ``keyring_id`` check.

6) payload_sha256
-----------------

For LOAD artifacts and UNLOAD directives alike this is the SHA-256 of
``loader_insns || data``, the exact bytes the detached CMS signature
covers.  At load, shirudo recomputes it.  For a loaded upatch it is also
recorded as the ``security.bpf.shirudo.payload`` xattr on the pin
directory.  An UNLOAD directive's expected target digest is carried
separately in its loader ``.rodata`` and in its metadata.

It also lets ``shirudo upatch list`` and ``status`` identify an artifact
without parsing the instruction stream.

7) What is signed
-----------------

The CMS signature covers ``loader_insns || data``.  ``metadata`` is not
signed.  The integrity model is therefore:

- the loader instructions and loader data are signature-verified by
  the kernel before anything runs;
- the payload program is separately hash-locked by the loader's
  ``excl_prog_hash`` and checked by the kernel at ``BPF_PROG_LOAD``;
- decoder sources are signature-covered because they are appended
  inside ``data`` before signing;
- ``metadata`` is advisory.  Tampering with a LOAD artifact's attach
  metadata changes where the hash-verified program is attached, not
  what it contains, and the target validates the blob before creating
  links.  Tampering with an UNLOAD directive's metadata can only
  produce a chain value the operator's expectation rejects, or a
  ``payload_mismatch``; the residual that remains is risk 1 in
  `threat-model <threat-model.rst>`__.

8) Versioning and compatibility
-------------------------------

``version`` is ``1``.  The format grows additively without a version
bump:

- a signed decoder blob may be appended inside ``data`` and located by
  the trailer at its end.  Older loaders ignore the additional bytes;
  older readers treat them as opaque loader data;
- the 360-byte header includes ``type`` and ``reserved1`` after
  ``reserved0``;
- ``reserved0`` and ``reserved1`` are zero in every file a writer
  emits; a reader rejects a file in which ``reserved0`` is not, so the
  slot can be given a meaning later without a flag day.

A reader must reject a file whose ``magic`` or ``version`` does not
match, before trusting any offset.

9) Reader validation rules
--------------------------

``util/upatch.c`` enforces, in order:

1. the file is a regular file, non-empty, and at most 16 MiB;
2. ``magic`` and ``version`` match;
3. each section ``(off, len)`` lies within the file, and any non-empty
   section starts at or after the 360-byte header;
4. ``loader_insns_len`` and ``signature_len`` are non-zero, and
   ``reserved0`` and ``reserved1`` are zero;
5. decoders are parsed only if ``data`` ends with a matching trailer,
   all blob and entry bounds fit, fixed strings are NUL-terminated, and
   every source range stays inside the blob.  Malformed decoder
   metadata is treated as absent by offline inspection.

10) Production and consumption
------------------------------

Produced by ``shirudo build``, which dispatches to the operator-only
``shirudo-build``: compile ``.bpf.c`` with ``clang -target bpf -O2 -g``
(or accept a ``.bpf.o``), run ``bpf_object__gen_loader()`` and
``bpf_object__load()``, CMS-sign the loader and data bytes, embed the
signed decoder sources, and serialise the container.  ``--unload
<name>`` emits an UNLOAD directive instead.

Inspected by ``shirudo upatch info <file>`` (offline: header, sections,
attach metadata, signed decoders) and listed by ``shirudo upatch list``.

Consumed by ``shirudo upatch load`` and ``unload`` on the target through
the signature-gated ``BPF_PROG_LOAD`` naming the sealed keyring.
Artifacts reach the target inside a ``.bee`` package pulled from an OCI
registry, as an upatch-tree artifact, or as a file the administrator
copied there.

Introspected after load by ``shirudo upatch get <name>``, which reads
the loaded program's ``line_info`` and BTF from the kernel.

See `architecture <architecture.rst>`__ for the surrounding design and
`threat-model <threat-model.rst>`__ for the trust boundaries.
