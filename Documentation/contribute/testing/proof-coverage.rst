..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: shirudo contributors

Proof coverage
==============

This page lists the CBMC proofs under :src:`testing/proofs/cbmc/` and the
Lean 4 proofs under :src:`testing/proofs/lean4/`, what each one proves and
for which inputs, and the parsers no proof covers yet. :doc:`proofs`
explains how to run and write them.

CBMC proofs
-----------

Every CBMC proof shows that the code reads and writes nothing outside its
objects and has no undefined arithmetic for the inputs it covers, besides
the properties the table lists. "Every input" means every input of any
length. A bound such as "up to 22 bytes" means every input of that length
or shorter, and "lengths 0 to 6" every input of each of those lengths.

.. list-table::
   :header-rows: 1
   :widths: 22 26 18 34

   * - Proof
     - Code
     - Inputs
     - Properties
   * - ``string-number``
     - ``parse_u64()``, ``parse_x64()``, ``parse_s64()``, ``digits()``
     - Up to 22 bytes, past the 20 digits of the largest value
     - Refuses exactly what is empty or holds a non-digit; a number
       within its bounds and of the sign the string spells; nothing
       written on refusal; ``digits()`` finds the whole run
   * - ``string-number-model``
     - ``parse_u64()``, ``parse_x64()``
     - Up to 4 bytes
     - The value of the Lean model ``Shirudo.Number``, or ``-ERANGE``
       exactly where the model refuses
   * - ``string-utf8``
     - ``utf8_width()``
     - Every input
     - Equals Table 3-7 of the Unicode Standard, the well-formed byte
       sequences, row by row
   * - ``string-sanitize``
     - ``text_sanitize()``
     - Lengths 0 to 6, with and without line breaks
     - Leaves well-formed UTF-8 without a C0, DEL or C1 control but a
       kept line break; changes a byte only to ``?``; keeps every
       printable character
   * - ``string-copy``
     - ``strscpy()``
     - Strings and buffers up to 8 bytes
     - Terminates what it writes; the whole string and its length, or
       what fits and ``-E2BIG``
   * - ``string-suffix``
     - ``name_has_suffix()``
     - Names up to 6 bytes, suffixes up to 3
     - True exactly when the name's last bytes are the suffix and at
       least one byte comes before them
   * - ``hex``
     - ``hex_encode()``, ``hex_decode()``, ``hex_decode_max()``
     - Up to 4 bytes, strings up to 9 characters
     - Lowercase hex that decodes back to the input; a decode takes
       exactly ``2 * n`` hex digits of either case and yields their
       value, and ``hex_decode_max()`` any even count up to ``2 * cap``,
       reading no further than the digit after them
   * - ``hex-model``
     - ``hex_encode()``, ``hex_decode()``, ``hex_decode_max()``
     - Up to 8 bytes, strings up to 17 characters, counts and capacities
       up to 8 and past ``SIZE_MAX / 2``
     - The result and the bytes of the Lean model ``Shirudo.Hex``
   * - ``io-lines``
     - ``lines_len()``
     - Up to 8 bytes
     - Ends at a newline or is 0, with no newline behind it
   * - ``attest-pcrs``
     - ``attest_parse_pcrs()``, ``attest_parse_pcr_value()``
     - Up to 6 bytes
     - A list is accepted exactly when it is decimal PCRs 0 to 23 apart
       by single commas, into the mask of those PCRs; a value exactly
       after a PCR to 23 and an equals sign
   * - ``attest-name-digest``
     - ``attest_parse_name_digest()``
     - Lengths 64 to 70
     - Accepted exactly when a name of a byte or more runs to the first
       equals sign and 64 hex digits follow, into that name and their
       value
   * - ``paths-bpffs-name``
     - ``upatch_bpffs_name()``, ``upatch_name_from_bpffs()``
     - Names up to 4 bytes, pin names up to 8
     - A name without ``~`` maps to a pin name without a dot and back to
       itself; a pin name without a dot that decodes is the encoding of
       what it decodes to
   * - ``bpm-tar-octal``
     - ``bpm_tar_octal()``
     - Every field of 8 and 12 bytes
     - Accepted exactly as octal digits with blanks or NULs around them,
       at their value; nothing written on refusal
   * - ``paths-bpffs-name-model``
     - ``upatch_bpffs_name()``, ``upatch_name_from_bpffs()``
     - Up to 8 bytes, buffers up to 18
     - The result and the string of the Lean model ``Shirudo.PinName``
   * - ``bpm-tar-header``
     - ``bpm_tar_header_ok()``
     - Every header without an octal checksum; the checksum against
       headers with 64 free bytes at three places
     - Holds exactly when the field is the byte sum with its own bytes as
       blanks
   * - ``bpm-archive-path``
     - ``bpm_archive_rel_ok()``, ``package_member_name_ok()``
     - Names of 0 to 10 bytes
     - A name passes exactly when it cannot leave its directory; a member
       exactly when it is the path below the one top directory
   * - ``bpm-names``
     - ``bpm_name_ok()``, ``bpm_version_ok()``, ``bpm_package_name_ok()``
     - Up to 129 bytes, past the 128-byte limit
     - Exactly the character, length and first-character rules
   * - ``bpm-archive-path-model``
     - ``bpm_archive_rel_ok()``, ``package_member_name_ok()``
     - Names of lengths 0 to 10, members up to 3 bytes
     - The decision of the Lean model ``Shirudo.ArchivePath``
   * - ``bpm-semver-valid``
     - ``bpm_semver_valid()``
     - Up to 11 bytes
     - Valid exactly by the SemVer 2.0.0 grammar; the pre-release parsed
       is the text between the core and ``+``
   * - ``bpm-semver-order``
     - ``bpm_semver_compare()``
     - Every pair of strings up to 7 bytes
     - Antisymmetric; equal exactly up to build metadata; every version
       above every invalid string; the core by number; a pre-release
       below its release
   * - ``bpm-semver-transitive``
     - ``bpm_semver_compare()``
     - Every three strings up to 7 bytes
     - Transitive, valid versions or not
   * - ``bpm-semver-prerelease``
     - ``prerelease_compare()``
     - Identifiers up to 3 bytes, lists up to 5
     - Numeric by value and below alphanumeric, alphanumeric by bytes;
       the first difference decides, else the longer list
   * - ``bpm-semver-model``
     - ``bpm_semver_compare()``, ``semver_parse()``,
       ``prerelease_compare()``
     - Every pair of strings up to 9 bytes
     - The sign of the Lean model ``Shirudo.SemVer``
   * - ``bpm-oci-challenge``
     - ``parse_challenge()``
     - ``WWW-Authenticate`` values up to 17 bytes
     - Outputs terminated in their buffers; only ``Bearer`` with a realm;
       each value a quoted value of the header
   * - ``bpm-oci-token``
     - ``token_from_body()``
     - Answers up to 17 bytes
     - Nothing written on refusal; a token without controls, quotes or
       backslashes, quoted in the answer under ``token`` or
       ``access_token``
   * - ``bpm-oci-header``
     - ``bpm_header()``
     - Header lines up to 20 bytes, NULs included
     - The whole line taken; values terminated, without a leading blank,
       a media type without parameters, a location without CR or LF
   * - ``bpm-oci-descriptor``
     - ``on_descriptor()``, ``on_index_entry()``
     - Any descriptor or index entry, into an empty or a full table
     - Kept exactly when whole, with a ``sha256:`` digest of 64 digits,
       and with room; copied as read; a refusal not counted
   * - ``bpm-oci-strings``
     - ``bpm_trim()``, ``bpm_copy_string()``, ``bpm_digest_matches()``
     - Strings up to 6 bytes, buffers up to 4
     - Terminated, what fits; a digest matches exactly ``sha256:`` and its
       hex in either case
   * - ``bpm-source-config``
     - ``bpm_parse_source_line()``, ``bpm_parse_tree_line()``
     - Lines up to 12 bytes
     - A setting written only for its exact key and terminated, without
       CR or LF
   * - ``bpm-tree-selector``
     - ``tree_selector_kv_add()``, ``tree_selector_copy()``,
       ``tree_selector_free()``, ``tree_text()``
     - 0 or 1 pairs, every limit, allocations allowed to fail
     - ``-E2BIG`` exactly at the limit with nothing changed; a copy owns
       its arrays, a failed one holds nothing; text without controls
   * - ``bpm-tree-reader``
     - ``tree_map_pair()``, ``tree_take_operation()``
     - Every pair and operation, into an empty or a full publication
     - A key taken once, with a value, below its limit; an operation
       taken exactly when whole and with room
   * - ``bpm-tree-follows``
     - ``tree_publication_follows()``
     - Every sequence number and generation; strings up to 2 bytes
     - Accepts exactly a publication of the same tree, of a later
       generation unless the same manifest, naming the recorded parent
       when the next generation, with the node's cursor between its base
       and head; without a state, one that starts at 0
   * - ``bpm-tree-signers``
     - ``tree_fetch_publication()``
     - Active or inactive image config; every signing-set count through
       capacity, every unvouched count through the set size, and parse,
       allocation, load, check and fetch failures
     - An active image fetch receives the same set whose load and check
       succeeded, only when it is nonempty and fully vouched; preflight
       failures refuse the fetch and every allocated set is released
   * - ``bpm-tree-sync-model``
     - ``cmd_bpm_tree_sync()``, ``tree_recover_pending()``,
       ``tree_publication_check()``, ``tree_publication_follows()``
     - The full command with 0 or 1 operation, every pending state,
       selector answer and first failing I/O call, or no failure.
       Names have one byte and the previous root has 32 symbolic bytes.
     - Writes match the Lean model ``Shirudo.TreeSync`` in order;
       nothing is written after a failure and every expected write
       happens when nothing fails
   * - ``bpm-tree-sync-application``
     - ``cmd_bpm_tree_sync()``
     - Two operations with no pending record; every selector answer
       and first failing I/O call, or no failure. The previous root
       has 32 symbolic bytes.
     - The same ordered-write properties as ``bpm-tree-sync-model``
   * - ``bpm-tree-sync-pending``
     - ``cmd_bpm_tree_sync()``, ``tree_recover_pending()``
     - Two operations with a pending record; every selector answer,
       measured state and first failing I/O call, or no failure. TPM
       replay equals the previous root, the next root, or neither;
       the previous root has 32 symbolic bytes.
     - The same ordered-write properties as ``bpm-tree-sync-model``
   * - ``bpm-tree-recovery-model``
     - ``tree_recover_pending()``
     - Publications with 0 to 2 operations, a matching or unrelated
       pending record, each TPM replay class, the measured flag and
       every first failing I/O call. The previous root has all 32
       symbolic bytes.
     - The return decision, ordered writes, cursor, tree ID, manifest
       and both projection roots match the independent recovery model
   * - ``bpm-upatch-member``
     - ``bpm_upatch_member()``, ``bpm_upatch_pair()``
     - Lengths 0 to 18
     - What install loads and uninstall unloads goes by the suffix alone;
       a pair is terminated, the other half, and pairs back to the name
   * - ``upatch-header``
     - ``parse_header()``, ``validate_bounds()`` of the ``.upatch``
       reader
     - Every file: the header is read from a buffer of exactly its size
       for files of any size
     - Reads nothing past the header; an accepted header has its magic,
       version, zero reserved field and a terminated name, a BPF
       payload, a loader and a signature, whole aligned instructions,
       every section inside the file and behind the header, and a
       ``.rodata`` offset inside the data
   * - ``upatch-signed-sections``
     - ``parse_signed_sections()``
     - Data of 15, 16, 40 and 64 bytes
     - Sections kept only behind a valid trailer, the directory below
       the trailer, each section inside the data below the directory;
       nothing kept on refusal
   * - ``upatch-signed-name``
     - The ``NAME`` and ``DECODERS`` sections of
       ``parse_signed_sections()``
     - A one-section directory in 288 bytes
     - A kept name is terminated within 256 bytes; a refusal keeps
       neither
   * - ``upatch-decoders``
     - ``parse_decoders()``, ``upatch_decoder_view()``,
       ``upatch_has_decoders()``
     - Sections of every length declaring up to 2 decoders
     - Names terminated, each source non-empty and inside the section
       behind the entries, every kind set, nothing kept on refusal,
       ``-ENOENT`` past the last decoder
   * - ``upatch-policy-labels``
     - ``parse_policy_labels()``
     - Sections of 0, 1 and 2 labels and the lengths around them
     - An accepted section fills its length exactly, with its magic and
       version, two distinct map indexes below the map count, one bit
       per label and a terminated name and absolute path; a refusal
       writes nothing
   * - ``upatch-name``
     - ``upatch_name_valid()``, ``upatch_select()``,
       ``upatch_prog_name()``
     - Names up to 24 bytes, archive names up to 31
     - Valid exactly for ``[A-Za-z0-9._-]+`` not starting with a dot
       whose pin directory name, each dot two bytes, fits ``NAME_MAX``;
       an archive entry exactly for a name and ``.upatch``; a program
       name zero-padded, of the header's bytes or ``_`` in their place
   * - ``upatch-prog-specs``
     - ``prog_specs_parse()``, ``prog_specs_free()``
     - Tables of 3, 15, 16 and 176 bytes, as many programs as fit, every
       allocation allowed to fail
     - A refusal leaves nothing allocated and ``*out`` NULL; an accepted
       program has a known role and kind, a terminated target and map,
       and uprobe fields only on a uprobe
   * - ``upatch-prog-uprobes``
     - The uprobe target records of ``prog_specs_parse()``
     - One program and one record in 226 bytes, path and build ID up to
       9 bytes, up to 2 offsets
     - An absolute path of its stated length without a NUL, a target
       without ``,`` or ``|``, a build ID of 1 to 64 bytes, offsets
       non-empty and strictly rising, everything freed
   * - ``upatch-loader``
     - ``loader_lddw()``, ``sys_bpf_call()``, ``map_create_slot()``,
       ``map_update_slot()``, ``loader_store_source()``
     - Loaders of 4, 5, 25 and 49 instructions
     - Reads only the loader, and only instructions before the call it
       looks back from; reports exactly what it matched; every slot
       below the table's size
   * - ``upatch-rodata-btf``
     - ``loader_btf()``
     - Loaders of 4, 10 and 15 instructions and 24 bytes of data
     - The BTF it locates lies inside the data
   * - ``upatch-rodata``
     - ``find_rodata_data()``, ``map_name_rodata()``
     - Any loader of 6 or 8 instructions; at 24, the shape the loader
       generator emits with every other field free; 48 bytes of data
     - The value it locates lies inside the data, with the size and type
       its section declares
   * - ``upatch-btf``
     - ``btf_name_printable()``, ``btf_decl_printable()``,
       ``btf_unwrap()``
     - BTF of 4 types, names up to 6 bytes, libbpf modelled
     - A printed name is printable ASCII, an accepted declaration chain
       has no loop, an unwrapped type is 0 or has no qualifier
   * - ``upatch-btf-int``
     - ``btf_integer()``
     - Every encoding and every value of up to 8 bytes
     - The bits stay inside the integer's bytes; the value is zero- or
       sign-extended from them
   * - ``json-string``
     - ``parse_string()`` of :src:`util/json.c`
     - Lengths 0 to 6, every room up to one byte more
     - Accepts exactly the ECMA-404 strings without ``\u0000``, a lone
       surrogate or bytes that are not UTF-8, decoded as a reference
       decoder does; ``-ENOSPC`` exactly when the value does not fit;
       nothing written past its room
   * - ``json-escape``
     - ``\u`` escapes and surrogate pairs
     - Every pair of code units
     - A pair is its 4-byte UTF-8, a code unit its own; ``\u0000`` and
       a lone surrogate refused
   * - ``json-field``
     - ``parse_value()`` into an integer, string or boolean field
     - Values of 0 to 6 bytes
     - An integer field takes exactly an ECMA-404 integer at its value; a
       string fits its room; a boolean takes ``true`` or ``false``;
       ``null`` gives no value
   * - ``json-string-model``
     - ``parse_string()``
     - Lengths 0 to 6, every buffer up to 7 bytes or none, a
       ``JSON_MAX_STRING_BYTES`` of 3
     - The result, end and bytes of the Lean model ``Shirudo.JsonString``
   * - ``json-escape-model``
     - ``parse_string()``
     - Every pair of ``\u`` escapes in either case, every buffer up to 8
       bytes or none
     - The result, end and bytes of the Lean model ``Shirudo.JsonString``,
       surrogate pairs, ``\u0000`` and lone surrogates included
   * - ``json-walk``
     - ``json_walk()``
     - Every document of up to 2 bytes, depth 2
     - Agrees with an independent ECMA-404 recognizer; containers in
       pairs, numbers whole with their integer flag
   * - ``json-limits``
     - The bounds of ``json_walk()`` and ``json_parse()``
     - Fixed documents at small bounds
     - Past the size or depth limit ``-E2BIG`` before any read; a
       callback's error ends the walk; a declared key named twice,
       null or not, refused
   * - ``json-emit-string``
     - ``put_string_n()`` of the JSON writer, strict and lossy
     - Strings of 0 to 4 bytes
     - Refuses exactly a NUL or bytes that are not UTF-8; writes one
       ECMA-404 string that decodes back to the input, or with U+FFFD in
       place of each NUL and stray byte
   * - ``json-roundtrip``
     - The writer and ``parse_string()``
     - Strings of 0 to 4 bytes
     - Every string the strict writer takes reads back whole
   * - ``json-emit-string-model``
     - ``put_string_n()``, strict
     - Lengths 0 to 4
     - Refuses exactly where the Lean model ``Shirudo.JsonString`` does,
       and otherwise writes the same bytes
   * - ``json-emit-buffer``
     - ``put()``, ``grow()``
     - Texts of 0 to 4 bytes, every room and limit, allocations allowed
       to fail
     - Grows only up to its limit; fails exactly when the text does not
       fit, keeping the longest prefix that does, terminated
   * - ``json-emit-nest``
     - Every container and key writer
     - Every sequence of up to 4 calls, every depth
     - Valid JSON by a byte-level recognizer; a comma only after a
       member; ``-E2BIG`` past the deepest level
   * - ``otel-header-fields``
     - The OTLP header checks and ``percent_decode()``
     - Strings up to 32 bytes
     - Names exactly RFC 9110 tokens, values without controls but tab;
       each ``%XX`` decoded, a stray ``%`` and ``%00`` refused
   * - ``otel-retry-after``
     - ``otel_retry_after()``, ``response_header()``
     - Headers up to 32 bytes, dates modelled
     - A delay is at most 30 seconds, the value itself when shorter; a
       header line read only within itself
   * - ``tpm-reader``
     - The TPM reader primitives of :src:`util/tpm_wire.c`: ``get8()``
       to ``get64()``, ``get2b()``, ``get2b_fixed()``, ``get_name()``
     - Every reader state over an input of any size
     - Every read stays inside what is left, and what is left still ends
       at the input's end; a sized field lies inside the input and its
       bound; a name is at most 34 bytes
   * - ``tpm-signature``
     - ``tpm_ecdsa_signature_parse()``
     - Every input
     - Accepts exactly ECDSA over SHA-256 with 32-byte r and s, in 72
       bytes, and returns those bytes
   * - ``tpm-attest``
     - ``tpm_attest_parse()``
     - Every input; takes about 8 minutes
     - Starts with ``TPM_GENERATED``; names fit 34 bytes; extra data of
       at most 64 bytes inside the input; a quote spans the input with a
       24-bit PCR mask; an NV certification ends with its data, at most
       2048 bytes
   * - ``tpm-public``
     - ``tpm_public_parse()``, ``tpm_ecc_public_parse()``
     - Every input; takes about 5 minutes and 7 GB
     - Accepts only the key shapes shirudo uses, P-256 or RSA-2048 with a
       256-byte modulus, each spanning exactly the input
   * - ``tpm-digest``
     - The policy, name and cpHash digests of :src:`util/tpm_wire.c`,
       the register's policy, ``tpm_writer_auth_hash()``
     - Names of any length, every PCR mask, up to 24 PCR values, SHA-256
       as any result
     - Each reads only whole inputs and writes only its output; an object
       name has a public area of 4 bytes or more; a writer's
       authorization takes a nonce of 1 to 64 bytes
   * - ``tpm-kdf``
     - ``tpm_kdfa()``, ``tpm_kdfe()``, ``tpm_credential_protect()``
     - Labels up to 66 bytes, outputs up to 64, any context
     - Reads and writes only what it is given; an oversized context or
       party is refused
   * - ``attest-fields``
     - ``record_word()``
     - Up to 16 characters
     - Passes exactly ``[a-z_]``
   * - ``attest-pcr``
     - ``on_pcr()`` of the evidence parser
     - Every index and 64-byte value text
     - Stores only PCRs 0 to 23 and marks exactly that one, from 64 hex
       digits; a refusal marks nothing
   * - ``chain-events``
     - ``chain_upatch_event()``, ``chain_key_event()``,
       ``chain_tree_event()``, ``chain_fold()``, ``chain_init_event()`` of
       an empty set
     - Names of 0 to 8 and 255 to 257 bytes; every payload, digest,
       sequence number and register
     - SHA-256 is given exactly the bytes of the Lean model
       ``Shirudo.Events``: the tag and its NUL, then the fixed fields, the
       name cut at 256 bytes and the sequence number most significant byte
       first; the event is the digest, or zeros with the error
   * - ``measured-fold-model``
     - ``measured_event()``, ``measured_holds()``
     - Every sequence of up to six init, load and unload records over two
       names and two payloads
     - The set holds a name with a payload exactly as the Lean model
       ``Shirudo.UpatchLoad`` folds the records, and never with the empty
       payload of a missing xattr
   * - ``eventlog-records``
     - ``log_records()``
     - Logs of 0 to 32 bytes
     - Refuses exactly a log with a NUL; keeps whole lines unchanged up
       to the last newline, cutting only a torn last line
   * - ``config-image``
     - ``config_image_read_header()``
     - Hash files of 0, 511, 512 and 4096 bytes
     - Accepts exactly the version 1 SHA-256 layout with 4096-byte blocks,
       a 32-byte salt and 1 to 2^28 data blocks; the hash tree's size
       by dm-verity's own formula; nothing changed on refusal
   * - ``config-auth``
     - ``set_owner_auth()``
     - Values of 0 to 16 bytes
     - A passphrase as it stands, ``hex:`` digits as the bytes they spell;
       a refusal keeps the value before
   * - ``config-hosts``
     - ``tls_classical_hosts_valid()``
     - Values of 0 to 7 bytes
     - Empty, or DNS names apart by commas
   * - ``config-update-follows``
     - ``event_follows()`` and ``same_event()`` of :src:`util/config_update.c`
     - Every record ``record_decode()`` accepts, and the zeroed one before
       the first line
     - ``event_follows()`` accepts exactly what ``Follows`` of
       ``Shirudo.ConfigActivation`` does and refuses with ``EUCLEAN``;
       ``same_event()`` is the equality of TPM boot, sequence, PCR, kind,
       initial value and root
   * - ``image-bootstrap``
     - ``bootstrap_parse()`` with ``read_text_line()``
     - One settings line of 0 to 8 bytes, every earlier state, failed
       reads and allocations
     - A bounded set of certificates under the runtime directory; a PCR
       only one the config accepts; nothing changes the runtime outside
       the initial settings
   * - ``image-bootstrap-certificates``
     - ``bootstrap_add_certificate()``
     - Every earlier key count through capacity, present or absent paths,
       paths outside the runtime and parent traversal
     - Only a distinct runtime path joins a non-full set; duplicates,
       invalid paths and overflow leave the count unchanged; earlier
       paths keep their order
   * - ``image-path``
     - ``image_path_valid()``
     - Up to 8 bytes
     - An accepted path is absolute, not ``/``, with no ``..`` component
       and no empty one but the last; every absolute path of plain
       components is accepted
   * - ``dm-names``
     - ``dm_name_ok()``, ``dm_device()``
     - Up to 7 bytes
     - A name of 1 to 127 of ``[A-Za-z0-9._-]``, not ``.`` or ``..``; a
       device as decimal major and minor
   * - ``kernel-notes``
     - ``kernel_build_id_from_notes()``
     - Notes of 0 to 24, 28, 32, 36 and 40 bytes
     - Reads nothing past the notes; a build ID of 1 to 64 lowercase hex
       digits that is the first GNU build ID note's, or empty, and none
       from a section whose one note is another
   * - ``kernel-release``
     - ``kernel_release_prefix_matches()``
     - Releases and prefixes up to 8 bytes
     - Matches exactly where the prefix ends with the release or before a
       ``.`` or ``-``
   * - ``log-escape``
     - ``escape()`` of :src:`util/log.c`
     - Messages of 0 to 5 bytes, every buffer size
     - Terminated printable ASCII, every backslash a ``\\`` or three octal
       digits, decoding to the message or to a prefix cut between
       characters

Lean 4 proofs
-------------

Each proof holds for every input of the model; the last column says how
the model follows the C.

.. list-table::
   :header-rows: 1
   :widths: 22 30 26 22

   * - Model
     - Theorems
     - Assumptions
     - Follows the C
   * - ``Shirudo.Number``, ``parse_base()`` of :src:`util/string.c`
     - ``parse_exact``: for digit strings of every length, the value they
       spell, or ``-ERANGE`` exactly when it passes ``max``
     - ``max`` fits a ``__u64``
     - CBMC, ``string-number-model``, up to 4 bytes
   * - ``Shirudo.Chain``, the register of :src:`util/chain.c`
     - ``register_injective``, ``register_tagged_injective``: equal
       registers come from the same events, tagged the same, in the same
       order; ``register_injective_on``: the same with the hash injective
       only on the pairs the two sequences fold; ``register_eq_foldl``: the
       register folds the events in the order they came
     - The hash is injective on the (register, event) pairs (for
       ``register_injective_on`` only those folded) and never yields the
       initial value; ``register_tagged_injective`` also takes the tagged
       encoding as injective, which ``Shirudo.Events`` proves
     - Review
   * - ``Shirudo.Events``, the event encodings of :src:`util/chain.c`
     - ``bytes_injective``: two admitted events hash the same bytes only
       when they are the same event; ``listing_injective``: the init
       event's listing spells one set while no name holds a newline;
       ``sorts_unique``: ``qsort()`` leaves a set of distinct names in one
       order; ``replay_injective_on``, ``replay_collision``,
       ``verify_sound``: equal registers come from the same typed events in
       the same order, or the strings hashed hold a SHA-256 collision or a
       string that hashes to zero; ``upatch_cut``, ``listing_newline``,
       ``sorts_tie``: where the domain ends
     - SHA-256 maps no two different strings the two histories hash to one
       digest and none to 32 zero bytes; names ``upatch_name_valid()``
       accepts of at most 256 bytes; sequence numbers of a ``__s64``
     - CBMC, ``chain-events``, names of up to 8 and of 255 to 257 bytes;
       the listing of a non-empty set and the NV extend by review
   * - ``Shirudo.Measured``, ``measured_event()`` of :src:`util/measured.c`
     - ``holds_iff``: ``measured_holds()`` finds a name and payload exactly
       when the last init, load or unload bearing on the name is its load
       with that payload; ``measuredSet_nodup``: each name once;
       ``measuredSet_init``: an init record starts the set over;
       ``holds_last_load``, ``not_holds_after_unload``
     - None
     - Review
   * - ``Shirudo.SemVer``, ``bpm_semver_compare()`` of
       :src:`util/bpm_package.c`
     - ``compareStrings_refl``, ``compareStrings_swap``,
       ``compareStrings_trans``: a total order on strings of every
       length; ``compareStrings_eq_iff``, ``compareStrings_invalid``,
       ``compareStrings_valid``: equal exactly for the same version up to
       build metadata, and for strings that are not SemVer for the same
       bytes; ``numCmp_value`` and the other rules of SemVer 2.0.0
       precedence
     - None; numeric identifiers compare by value only without a leading
       zero, which ``semverParse_wellFormed`` shows the parser ensures
     - CBMC, ``bpm-semver-model``, up to 9 bytes
   * - ``Shirudo.PinName``, ``upatch_bpffs_name()`` and
       ``upatch_name_from_bpffs()`` of :src:`util/paths.h`
     - ``decode_encode``: a name without ``~`` decodes back from its
       encoding; ``dot_not_mem_encode``: an encoding holds no dot;
       ``encode_injective``: no two names without ``~`` share a pin;
       ``encode_decode``, ``tilde_not_mem_decode``: a pin name without a
       dot that decodes is the encoding of a name without ``~``;
       ``bpffsName_ok``, ``nameFromBpffs_ok``, ``pin_round_trip``: the
       same through the buffers, ``-ENAMETOOLONG`` exactly where the C
       refuses
     - A C string is shorter than 2^63 bytes
     - CBMC, ``paths-bpffs-name-model``, up to 8 bytes
   * - ``Shirudo.ArchivePath``, ``bpm_archive_rel_ok()``,
       ``package_member_name_ok()`` and the member checks of
       ``bpm_pkg_extract()`` of :src:`util/bpm_package.c`
     - ``relOk_iff``, ``relOk_plain``: the check takes exactly the relative
       paths of plain components, with or without a final ``/``;
       ``relOk_contained``: every name it takes, resolved below any
       directory, leads strictly below it, as does each directory on the
       way; ``memberNameOk_iff``: a member matches only as one plain
       component, ``/`` and the member; ``extract_contained``: every
       member extracted is a regular file or a directory strictly below
       ``dest``, or ``dest`` itself
     - Resolution as the kernel walks a path, ``.`` staying, ``..`` going
       up and an empty component refused; the extraction's limits on
       count, size and path length are left out
     - CBMC, ``bpm-archive-path-model``, names of lengths 0 to 10; review
       for ``bpm_pkg_extract()``
   * - ``Shirudo.Hex``, :src:`util/hex.c`
     - ``decode_encode``, ``length_encode``, ``encode_lower``: an encoding
       is lowercase hex twice its length that decodes back;
       ``decode_spec``: ``hex_decode()`` takes exactly ``2 * n`` hex
       digits of either case, and its bytes encode back to them in
       lowercase; ``decodeMax_spec``: ``hex_decode_max()`` takes exactly
       the even runs of at most ``2 * cap``; ``encode_injective``
     - A string is shorter than ``SIZE_MAX``
     - CBMC, ``hex-model``, up to 8 bytes and 17 digits
   * - ``Shirudo.JsonString``, the strict ``put_string_n()`` that
       ``json_str()`` calls and ``parse_string()`` of :src:`util/json.c`
     - ``read_write``: the reader returns exactly every string the writer
       takes and stops at its closing quote; ``write_isSome``: the writer
       takes exactly well-formed UTF-8 without NUL; ``write_string``: it
       writes one ECMA-404 string in well-formed UTF-8, with no control
       byte and no ``"`` or ``\`` outside an escape; ``readString_wf``:
       whatever the reader returns, from any input, is well-formed UTF-8
       without NUL
     - The emitter has room; for ``read_write``, the string fits
       ``JSON_MAX_STRING_BYTES`` and the buffer; well-formed UTF-8 is
       Table 3-7, which ``string-utf8`` proves ``utf8_width()`` computes
     - CBMC, ``json-emit-string-model`` up to 4 bytes,
       ``json-string-model`` lengths 0 to 6, ``json-escape-model`` every
       pair of ``\u`` escapes
   * - ``Shirudo.ConfigActivation``, the config activation of
       :src:`util/config_update.c` as ``image update``, ``status`` and
       ``init`` drive it
     - ``consistent_or_refusing``, ``refusal_persists``: the PCR replays
       from the record with its config mounted, or every command but
       ``status`` and ``image status`` refuses, a pending or drifted state
       until the TPM boot changes; ``extends_once``,
       ``extension_follows_pending``, ``interrupted_never_extends``: one
       extension per activation and TPM boot, after the pending record,
       none after an interruption; ``reboot_stale``, ``reboot_recovers``,
       ``boot_completion``: after a reboot commands refuse until ``init``
       records a boot event, which an uninterrupted ``init`` does, and from
       any journal ``init`` completes only with the PCR holding exactly the
       selected config's boot event; ``configInUse_vouched``,
       ``mounted_selected``, ``consistent_mounted``, ``journal_wellformed``,
       ``pcr_replay``, ``completion_by_complete``
     - Commands one at a time; an atomic ``state`` rename; a crash leaves a
       prefix of a line; only shirudo writes the journal and the config
       mount during a boot; PCRs reset only at a reboot or TPM Restart;
       equal values from equal extensions (``pcr_value_eq_iff`` with
       ``Shirudo.Chain``'s assumptions); TPM boot identities never repeat;
       a TPM Restart or Resume only between commands
     - Review; CBMC, ``config-update-follows``, for ``event_follows()`` and
       ``same_event()``
   * - ``Shirudo.UpatchLoad``, the load, unload and purge of
       :src:`builtin-upatch.c`, the gate of :src:`util/image_runtime.c` and
       the boot restore of :src:`builtin-init.c`
     - ``undo_pass_sound``: once a command's undo pass is done, every pin
       directory holds one link, of the payload its xattr names and this
       boot's records hold, and every archive file shirudo wrote is on
       record; ``loaded_once``: no name holds two links;
       ``recorded_runs``: every name the records hold is pinned with one
       link of that payload; ``commands_need_init``: every command runs
       in a boot whose init record is on the log;
       ``init_restores_exactly``: ``init`` loads exactly the labeled
       archive files whose last record is a load of that payload, and the
       new boot's records hold exactly those; ``log_sublist_register``,
       ``register_length``, ``register_eq_log_iff``, ``replay_differs``:
       this boot's records are a sublist of the register's events, equal
       once the lock is free unless an append was lost, and a difference
       shows in the replay; dropping the lock, the undo pass, its refusal,
       the gate, the undo of a failed payload xattr, the lock across the
       purge or the restore's filter breaks the matching theorem
     - The lock excludes and a kill releases it; a kill keeps pins and
       files; pin directory removals, archive renames and appends are
       whole; a reboot clears pins and register and ``init`` runs as one
       step; root changes only unlabeled archive files and brings files
       back; the hash of ``Shirudo.Chain`` for ``replay_differs``
     - CBMC, ``measured-fold-model``, for ``measured_event()`` and
       ``measured_holds()`` up to six records; review for the rest
   * - ``Shirudo.TreeSync``, ``cmd_bpm_tree_sync()`` and
       ``tree_recover_pending()`` of :src:`builtin-bpm.c`
     - ``generation_mono``, ``lastSeq_mono``, ``log_grows``: between any two
       points of any history of syncs of signed publications, stops after
       any write and reboots, the generation, the cursor and the tree
       eventlog never go back; ``manifest_fixed``: at an equal generation
       only the recorded manifest; ``older_refused``,
       ``accepted_older_refused``: a publication older than one accepted
       writes nothing; ``log_increasing``, ``measured_increasing``: each
       operation applied at most once, in increasing order, in the tree
       eventlog and in this boot's records; ``recover_pending``,
       ``measured_kept``, ``recover_settles``: after a stop between
       ``pending.json`` and the commit, recovery appends the operation once,
       exactly when it was measured or appended, and otherwise leaves the
       cursor below it; nothing measured is lost; ``state_is_fold``,
       ``replay_not_bad``: the state is the fold of the tree eventlog but
       between an append and its commit; ``applied_signed``,
       ``applied_consistent``: an applied operation is one of a signed
       publication of the tree, and that of every one when the signer never
       gives a number two operations
     - A manifest digest names one publication; the hash is injective on
       (root, digest) and never 64 zeros; only sync writes the tree files,
       each write whole, one sync at a time; the unlink of ``pending.json``
       succeeds; an extend and its eventlog record are one write
     - CBMC: ``bpm-tree-follows`` for ``tree_publication_follows()``,
       ``bpm-tree-sync-model`` and its two-operation variants for
       sync writes, ``bpm-tree-recovery-model`` for pending recovery;
       ``tree_parse()`` by review

Not covered yet
---------------

The fuzz targets in :doc:`test-coverage` cover these parsers; no proof
does: how ``json_parse()`` dispatches objects, arrays and maps to their
schemas, the OTLP headers a configuration adds, the walk over a
package's tar members, the registry references and URLs, the kernel
configuration the tree selectors read, the tree log, the eventlog's
lines, the evidence document beyond its PCRs, the config update record,
the site configuration file and the config image's settings and tree.
The ``.upatch`` reader, the TPM structures and the package, index and
tree readers are covered part by part, as the table shows; what joins
those parts has no proof.

Within the ``.upatch`` reader, the proofs cover its parts but not their
composition: ``upatch_parse()`` and ``upatch_open_memory()`` join the
header, the signed sections, the decoders and the policy labels the
proofs cover one by one, and a proof of the whole file runs out of
memory. A program table of two or more programs, ``find_rodata_data()``
on loaders of other shapes, ``btf_dump_cost()``, the ``.rodata`` printers
and the libbpf calls behind ``btf_rodata_btf()`` have no proof.
