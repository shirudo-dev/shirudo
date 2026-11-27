..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: shirudo contributors

Proof coverage
==============

This page lists the CBMC proofs under :src:`testing/proofs/cbmc/`, the
Kani proofs beside their Rust code, and the Lean 4 proofs under
:src:`testing/proofs/lean4/`, what each one proves and
for which inputs, the source files no proof reads and the parsers no
proof covers yet. :doc:`proofs` explains how to run and write them. CI
runs every proof after a push to main but the CBMC proofs
:src:`testing/proofs/cbmc/ci-skip.list` names, which take hours each:
only a run a developer starts checks those.

Kani proofs
-----------

Kani checks the production Rust code for every input within each
harness's stated bound. The harnesses live beside that code under
``#[cfg(kani)]``. The project runs them with ``make -C testing kani``;
:src:`testing/proofs/kani/proofs.list` names each one.

.. list-table::
   :header-rows: 1
   :widths: 22 26 18 34

   * - Proof
     - Code
     - Inputs
     - Properties
   * - ``string_suffix``
     - ``name_has_suffix()`` of :src:`rust/src/text.rs`
     - Names up to 6 bytes, suffixes up to 3
     - True exactly when the last bytes equal the suffix and the name
       has at least one byte before it
   * - ``string_copy``
     - ``strscpy()`` of :src:`rust/src/text.rs`
     - Source and destination lengths up to 8 bytes
     - Exact copy and length on success; partial copy and ``-E2BIG``
       on truncation; terminator when space exists; other bytes unchanged
   * - ``hex_roundtrip``
     - ``encode_into()`` and ``decode()`` of :src:`rust/src/util/hex.rs`
     - Byte strings of every length from 0 to 4
     - Encoding matches ``Shirudo.Hex.encodeByte`` and decodes back
       to the original bytes
   * - ``attest_fields``
     - ``record_word()`` of :src:`rust/src/util/attest.rs`
     - All byte strings up to 16 bytes
     - Accepts only lowercase ASCII letters and underscores
   * - ``attest_pcr_value``
     - ``parse_pcr_value()`` of :src:`rust/src/util/attest.rs`
     - All byte strings up to 6 bytes
     - Accepts a decimal PCR from 0 to 23, then an equals sign and any
       value text, returning its PCR and the exact value slice
   * - ``string_number_model``
     - ``parse_u64()`` and ``parse_x64()`` of :src:`rust/src/text.rs`
     - Up to 4 bytes, any maximum and either base
     - The value of ``Shirudo.Number.valueFrom`` in
       :src:`testing/proofs/lean4/Shirudo/Number.lean`, or the exact
       invalid-input or range error
   * - ``string_search``
     - ``find()`` and ``contains()`` of :src:`rust/src/text.rs`
     - Haystacks up to 5 bytes, needles up to 2 bytes
     - The first matching position, including the empty needle; the
       boolean result agrees with whether a position exists
   * - ``string_utf8``
     - ``utf8_width()`` of :src:`rust/src/text.rs`
     - Every 0 to 4 byte prefix, plus an arbitrary fifth byte
     - The width in Unicode Table 3-7; a later byte does not change
       the width determined by the first four

   * - ``hex_decode``
     - ``decode()`` of :src:`rust/src/util/hex.rs`
     - Up to 8 bytes, or 16 hex digits
     - Accepts exactly valid digit pairs and writes the bytes they spell
   * - ``hex_decode_max``
     - ``decode_max()`` of :src:`rust/src/util/hex.rs`
     - Text up to 17 bytes and output capacity up to 8 bytes
     - Accepts exactly even, valid hex within capacity; on success
       writes the decoded prefix and leaves the rest unchanged
   * - ``hex_encode_model``
     - ``encode_into()`` of :src:`rust/src/util/hex.rs`
     - Up to 8 arbitrary bytes
     - Writes the lowercase high and low nibbles from
       ``Shirudo.Hex.encodeByte``
   * - ``hex_digest_one_digit``
     - ``decode_sha256_digest()`` of :src:`rust/src/util/hex.rs`
     - Each of 64 positions, one arbitrary byte among zero digits
     - Decodes a valid digit at that position and rejects an invalid one
   * - ``hex_digest_shape``
     - ``decode_sha256_digest()`` of :src:`rust/src/util/hex.rs`
     - Lengths 0, 6, 7, 8, 70, 71 and 72; one arbitrary prefix byte
     - Requires the exact ``sha256:`` prefix and 64 digits
   * - ``pin_name_one``
     - ``pin_name()`` of :src:`rust/src/util/upatch.rs`
     - Every single byte
     - Replaces a dot with ``~d`` and otherwise copies the byte
   * - ``pin_name_encode``
     - ``pin_name_into()`` of :src:`rust/src/util/upatch.rs`
     - Names up to 8 arbitrary bytes
     - Encodes every dot as ``~d`` and copies every other byte
   * - ``pin_name_decode``
     - ``name_from_pin_into()`` of :src:`rust/src/util/upatch.rs`
     - Pin names up to 8 arbitrary bytes
     - Accepts exactly tilde followed by ``d``; restores dots and
       copies other bytes
   * - ``pin_name_roundtrip``
     - Pin-name slice helpers of :src:`rust/src/util/upatch.rs`
     - Names up to 4 bytes without a tilde
     - A name decodes back after encoding
   * - ``io_lines``
     - ``last_newline_end()`` of :src:`rust/src/util/io.rs`
     - Text up to 8 arbitrary bytes
     - Returns the position after the last newline, or zero
   * - ``io_append_text``
     - ``append_text()`` of :src:`rust/src/util/io.rs`
     - Text up to 3 arbitrary bytes
     - Removes one final newline; rejects an embedded newline or NUL
   * - ``paths_key_file``
     - ``key_file_size()`` and ``key_file_into()`` of
       :src:`rust/src/util/paths.rs`
     - Directory up to 2 arbitrary bytes, file ``f``
     - Refuses an empty directory or NUL and adds one separator only
       when needed, then copies the file name
   * - ``paths_key_file_parts``
     - ``key_file_size()`` and ``key_file_into()`` of
       :src:`rust/src/util/paths.rs`
     - Directory and file up to 2 bytes each; output capacity 0 to 6
     - Joins the parts with at most one slash when capacity is exact;
       otherwise refuses without changing the output

   * - ``attest_pcrs``
     - ``parse_pcrs()`` of :src:`rust/src/util/attest.rs`
     - Every text up to 6 arbitrary bytes
     - Accepts comma-separated decimal PCRs from 0 to 23 and returns
       the corresponding bit mask
   * - ``attest_name_digest_one_digit``
     - ``parse_name_digest()`` of :src:`rust/src/util/attest.rs`
     - Each of 64 digest positions, one arbitrary byte among zeros;
       name ``n``
     - Decodes the digit at that position or rejects an invalid one
   * - ``attest_name_digest_short_shape``
     - ``parse_name_digest()`` of :src:`rust/src/util/attest.rs`
     - Names of 0 to 4 ``n`` bytes and 63 to 65 zero digits
     - Requires a nonempty name and exactly 64 digest digits

These bounded checks do not prove file-system writes, TPM effects, or
arbitrary-length inputs. The I/O, key-path and pin-name slice helpers
are called by the production code; their allocation and external-call
wrappers are also exercised by unit and functional tests. The two C
pin-name proofs remain until the lead accepts a complete replacement.

The removed C proofs for full six-byte sanitization, 22-byte number
parsing, attestation replay, the 256-byte name limit, a complete 64-digit
PCR value, and pin path construction do not yet have equivalent Kani harnesses. The Rust port
uses slices and standard methods instead of the old C span, prefix and
token helpers, so those C-only memory contracts do not have a direct
production function to prove. The corresponding behavior still needs
review at its Rust call sites. The claims above are limited to the
functions and inputs each row names.

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
   * - ``paths-bpffs-name``
     - ``upatch_bpffs_name()``, ``upatch_name_from_bpffs()``
     - Names up to 4 bytes, pin names up to 8
     - A name without ``~`` maps to a pin name without a dot and back to
       itself; a pin name without a dot that decodes is the encoding of
       what it decodes to
   * - ``paths-bpffs-name-model``
     - ``upatch_bpffs_name()``, ``upatch_name_from_bpffs()``
     - Up to 8 bytes, buffers up to 18
     - The result and the string of the Lean model ``Shirudo.PinName``

Lean 4 proofs
-------------

Each proof holds for every input of the model; the last column says how
the model follows production code.

.. list-table::
   :header-rows: 1
   :widths: 22 30 26 22

   * - Model
     - Theorems
     - Assumptions
     - Follows the code
   * - ``Shirudo.Number``, ``parse_u64()`` and ``parse_x64()`` of
       :src:`rust/src/text.rs`
     - ``parse_exact``: for digit strings of every length, the value they
       spell, or ``-ERANGE`` exactly when it passes ``max``
     - ``max`` fits a ``__u64``
     - Kani comparison ``string_number_model`` covers inputs up to
       4 bytes
   * - ``Shirudo.Chain``, the register of :src:`rust/src/util/chain.rs`
     - ``register_injective``, ``register_tagged_injective``: equal
       registers come from the same events, tagged the same, in the same
       order; ``register_injective_on``: the same with the hash injective
       only on the pairs the two sequences fold; ``register_eq_foldl``: the
       register folds the events in the order they came;
       ``history_ignores_outcomes``: a upatch tree's history root is the
       same on two nodes that processed operations of the same digests,
       whatever outcome each had; ``processAll_history``,
       ``historyRoot_append_one``: it takes one step per operation
     - The hash is injective on the (register, event) pairs (for
       ``register_injective_on`` only those folded) and never yields the
       initial value; ``register_tagged_injective`` also takes the tagged
       encoding as injective, which ``Shirudo.Events`` proves
     - Review
   * - ``Shirudo.Events``, the event encodings of
       :src:`rust/src/util/chain.rs`
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
     - Review of the listing of a non-empty set and the NV extend; the
       CBMC harness of the rest, ``chain-events``, went with
       ``util/chain.c`` in the port to Rust
   * - ``Shirudo.Measured``, ``measured_event()`` of
       :src:`rust/src/util/measured.rs`
     - ``holds_iff``: ``measured_holds()`` finds a name and payload exactly
       when the last init, load or unload bearing on the name is its load
       with that payload; ``measuredSet_nodup``: each name once;
       ``measuredSet_init``: an init record starts the set over;
       ``holds_last_load``, ``not_holds_after_unload``
     - None
     - Review
   * - ``Shirudo.EventlogRecord``, ``walk_lines()`` of
       :src:`rust/src/util/eventlog/mod.rs` and ``upatches_line()`` of
       :src:`rust/src/util/eventlog/records.rs` on the records
       :src:`rust/src/builtin/upatch/ops.rs`,
       :src:`rust/src/builtin/init/restore.rs`,
       :src:`rust/src/builtin/keys.rs` and
       :src:`rust/src/builtin/bpm/tree.rs` write
     - ``read_upatch``, ``read_init``, ``read_key``, ``read_tree``: every
       record the writers give reads back as exactly the events
       ``Shirudo.Measured`` folds, whatever its other fields hold;
       ``load_from_fields``, ``unload_from_fields``, ``init_from_type``:
       from any line, a load or an unload comes only from that line's
       ``type`` and ``upatch`` member, or from an entry of an init
       record's ``set`` that names both its fields, each with a name and
       a payload ``upatch_member_valid()`` accepts, and an init event only
       from a ``type`` of ``init``
     - ``parse_schema()`` hands over the members as the line holds them,
       its strings as ``Shirudo.JsonString`` proves them read; names
       ``upatch_name_valid()`` accepts and 64 hex digits from the
       writers; the limits on a key's, a string's and a line's length,
       on depth and on the number of keys, which only refuse more, are
       left out
     - Review; the ``eventlog`` unit suite reads a line whose set entry
       names no upatch
   * - ``Shirudo.AttestReplay``, ``on_record()``, ``check_epoch()``,
       ``check_replay()`` and the expected init check of
       ``check_state()`` of :src:`rust/src/util/attest.rs`
     - ``select_sound``: when every check passes, the certified register
       value is the fold of the last init record and the records after
       it, that init carries the expected digest and the certified reset
       count, and every record after it names an event whose digest is
       its own; ``verify_history``: whatever extended the register, it
       was extended by the expected init event and then by exactly the
       events those records name, in order, or SHA-256 collides on the
       strings of the two folds; ``passes_witness``: the checks can pass
     - The register value and its certification as ``read_register()``,
       ``check_signed()`` and ``check_certify()`` check them; the expected init event, which
       ``attest verify`` computes when given ``--cert``; SHA-256 as
       ``Shirudo.Events`` takes it for ``verify_history``
     - Review; the bounded CBMC bridge went with the C implementation in
       the port to Rust
   * - ``Shirudo.SemVer``, ``semver::compare()`` of
       :src:`rust/src/util/bpm_package/`
     - ``compareStrings_refl``, ``compareStrings_swap``,
       ``compareStrings_trans``: a total order on strings of every
       length; ``compareStrings_eq_iff``, ``compareStrings_invalid``,
       ``compareStrings_valid``: equal exactly for the same version up to
       build metadata, and for strings that are not SemVer for the same
       bytes; ``numCmp_value`` and the other rules of SemVer 2.0.0
       precedence
     - None; numeric identifiers compare by value only without a leading
       zero, which ``semverParse_wellFormed`` shows the parser ensures
     - None since the port to Rust; the CBMC model went with
       ``util/bpm_package.c``
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
     - Kani ``pin_name_encode``, ``pin_name_decode`` and
       ``pin_name_roundtrip`` compare the Rust slice helpers within
       their stated bounds. CBMC ``paths-bpffs-name-model`` still
       checks the C path.
   * - ``Shirudo.ArchivePath``, ``archive_rel_ok()``,
       ``package_member_name_ok()`` and the member checks of
       ``extract()`` of :src:`rust/src/util/bpm_package/`
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
     - Review; the CBMC model of the two checks went with
       ``util/bpm_package.c`` in the port to Rust
   * - ``Shirudo.Hex``, :src:`rust/src/util/hex.rs`
     - ``decode_encode``, ``length_encode``, ``encode_lower``: an encoding
       is lowercase hex twice its length that decodes back;
       ``decode_spec``: ``decode()`` takes exactly ``2 * n`` hex
       digits of either case, and its bytes encode back to them in
       lowercase; ``decodeMax_spec``: ``decode_max()`` takes exactly
       the even runs of at most ``2 * cap``; ``encode_injective``
     - A string is shorter than ``SIZE_MAX``
     - Kani comparisons ``hex_roundtrip``, ``hex_decode``,
       ``hex_decode_max`` and ``hex_encode_model`` cover their
       stated bounds; the C model went with ``util/hex.c``
   * - ``Shirudo.JsonString``, the strict ``put_string()`` that
       ``json_str()`` calls and ``Cursor::string()`` of
       :src:`rust/src/util/json/`
     - ``read_write``: the reader returns exactly every string the writer
       takes and stops at its closing quote; ``write_isSome``: the writer
       takes exactly well-formed UTF-8 without NUL; ``write_string``: it
       writes one ECMA-404 string in well-formed UTF-8, with no control
       byte and no ``"`` or ``\`` outside an escape; ``readString_wf``:
       whatever the reader returns, from any input, is well-formed UTF-8
       without NUL
     - The emitter has room; for ``read_write``, the string fits
       ``JSON_MAX_STRING_BYTES`` and the buffer; well-formed UTF-8 is
       Table 3-7, which the Rust core checks
     - None since the port to Rust; the CBMC models went with
       ``util/json.c``
   * - ``Shirudo.ConfigActivation``, the config activation of
       :src:`rust/src/util/config_update.rs` as ``image update``,
       ``status`` and ``init`` drive it
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
     - Review; the CBMC harness ``config-update-follows`` of
       ``event_follows()`` and ``same_event()`` went with
       ``util/config_update.c`` in the port to Rust
   * - ``Shirudo.UpatchLoad``, the load, unload and purge of
       :src:`rust/src/builtin/upatch/ops.rs`, the gate of :src:`rust/src/util/image_runtime.rs` and
       the boot restore of :src:`rust/src/builtin/init/restore.rs`
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
     - Review; the CBMC harness ``measured-fold-model`` of
       ``measured_event()`` and ``measured_holds()`` went with
       ``util/measured.c`` in the port to Rust
   * - ``Shirudo.TreeSync``, ``sync()`` and ``recover_pending()`` of
       :src:`rust/src/builtin/bpm/tree.rs`
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
       gives a number two operations; ``outcomes_cover``,
       ``outcomes_fixed``, ``lastSeq_le_head``: the outcomes record has a
       line for every operation from 1 to the cursor, in order, no line
       at or below the cursor ever changes, and the cursor never passes
       the head of the recorded publication. All of these hold across
       segment boundaries, as a publication of any base is a sync;
       ``walk_same_ops``: the segments of a walk, each recorded before
       its operations, apply the operations of the tree taken as one
       publication, in its order, with the same ``pending.json``,
       register, tree eventlog and outcomes writes, and end at the same
       cursor and projection root
     - A sync that walks is one sync per segment: it leaves out only the
       state each segment but the last writes at its end, which the next
       segment's record overwrites with the same cursor and root, and
       its cut keeps every line; the base and prefix checks are left out
       of the model, as they only refuse more. A manifest digest names
       one publication; the hash is injective on
       (root, digest) and never 64 zeros; only sync writes the tree files,
       each write whole, one sync at a time; the unlink of ``pending.json``
       succeeds; an extend and its eventlog record are one write
     - Review, ``TreePublication::parse()`` included; the CBMC harnesses
       ``bpm-tree-follows`` of ``tree_publication_follows()`` and
       ``bpm-tree-sync-model`` of the writes of a sync of up to two
       operations went with ``util/bpm_tree.c`` in the port to Rust
   * - ``Shirudo.TreeOverlap``, :src:`rust/src/util/bpm_tree_overlap.rs`
       against ``selector_matches()`` of
       :src:`rust/src/util/bpm_tree_state.rs`
     - ``disjoint_sound``: no node matches two selectors that
       ``selectors_disjoint()`` calls disjoint; ``covers_sound``: a
       selector that ``selector_covers()`` says covers another matches
       every node the other matches; ``addLive_false``: an add that
       ``add_live()`` says is no longer live is followed by a delete of
       the same upatch that matches every node the add matches;
       ``prefixes_meet_iff``: two release prefixes take a common release
       exactly when one takes the other read as a release;
       ``disjoint_comm``, ``covers_refl``: the order of two selectors
       does not matter, and a selector covers itself
     - One node for both selectors: its release, machine, build ID,
       config values and labels are the same for the two matches, and
       ``/proc/config.gz`` and ``/boot/config-<release>`` give an option
       the same value; a match that returns an error is no answer
     - Review; the CBMC harnesses of the publisher's checks and the
       node's match went with ``util/bpm_tree_overlap.c`` and
       ``util/bpm_tree_state.c`` in the port to Rust

Not covered yet
---------------

The fuzz targets in :doc:`test-coverage` cover these parsers; no proof
does: the JSON reader and writer of :src:`rust/src/util/json/`, the OCI
client of :src:`rust/src/util/bpm_oci/`, the package reader of
:src:`rust/src/util/bpm_package/`, its tar headers, member paths,
version order and upatch member names included, the TPM structures,
policy digests and key derivations of :src:`rust/src/util/tpm_wire/`,
the eventlog of :src:`rust/src/util/eventlog/`, the site configuration
of :src:`rust/src/util/config.rs`, the kernel's build ID and release
match of :src:`rust/src/util/kernel_build_id.rs` and
:src:`rust/src/util/kernel_release.rs`, the registry source and tree
lines of :src:`rust/src/util/bpm_source_config.rs`, the bootstrap file
and config root event of :src:`rust/src/util/image_bootstrap.rs` and
:src:`rust/src/util/config_measure.rs`, the config image's superblock
of :src:`rust/src/util/config_image.rs`, the ``.upatch`` container
reader of :src:`rust/src/util/upatch.rs` and its ``.rodata`` reader of
:src:`rust/src/util/upatch_rodata.rs`, and the tree publications of
:src:`rust/src/util/bpm_tree.rs`, whose CBMC proofs went with the C
they proved when the modules moved to Rust; and how
``parse_schema()`` dispatches objects, arrays and maps to their schemas,
the OTLP headers a configuration adds, the registry references and URLs,
the kernel configuration the tree selectors read, the tree log, the
evidence document beyond its PCRs, the config update record, the site
configuration file and the config image's settings and tree.
