# Use rust/src/util/, and grow it

Write common code once, in `rust/src/util/`, and call it. A hash, an
encoding, a digest's text form, a path, a record format, a file read
with its checks, the parse of a name or a number: code that does a job
like these belongs in a module of `rust/src/util/`, or in
`rust/src/text.rs` for the string and number basics, not inline in a
command or a tool. Write it there from the start when a second caller
is in sight, rather than waiting for the copy. Copies drift apart, and
the difference between them is usually a bug in one: the `sha256:`
digest of a manifest was checked and decoded by hand in six places, one
with a length check the others lacked, and written in ten, each its own
way, until `decode_sha256_digest()` and `sha256_digest_encode()`, now
of `rust/src/util/hex.rs`, took the place of them all.

Never write the same logic twice. Before writing a parser, a check, a
path, a copy loop or a record format, look for one that already does it,
in `rust/src/util/`, `rust/src/text.rs` and the commands alike: `git grep
-n '<word>'`. A variant that differs only in a length check, a bound or a
message is still a copy: make one helper, with a parameter or with the
extra check left to the caller, and move one found in a command into
`rust/src/util/` for both. A copy found while working on something else
is consolidated in a commit of its own, before the change that needed
it. A review asks of every new block of code whether `rust/src/util/`
has it already, or should. The basics:

| Need | Use |
|---|---|
| Parse a number | `parse_u64()`, `parse_s64()`, `parse_x64()`, `digits()` (`rust/src/text.rs`) |
| Copy a string into a fixed buffer | `strscpy()`, and check `-E2BIG`; `strsprintf()` to join parts, `csprintf!` for a C format (`rust/src/text.rs`) |
| An upatch's pin directory or a pin in it | `pin_path()` (`rust/src/util/upatch_resolve.rs`) |
| A string's prefix, or a span that must be one literal | `starts_with()` to test a prefix, `strip_prefix()` to step past it, `==` for a span; never a length counted by hand |
| A file name's extension | `name_has_suffix()` (`rust/src/text.rs`), and `dir_names()` (`rust/src/util/io.rs`) with it for the files of a directory that have one |
| Text from outside on a terminal | `sanitize()`; UTF-8 with `utf8_width()` (`rust/src/text.rs`); `rust/src/log.rs` escapes what it logs |
| Sizes and lengths | `checked_add()`, `checked_mul()` and kin, `div_ceil()` |
| Memory | `Vec` and `Box`, from the scrubbing global allocator of `rust/src/heap.rs`; wrap a buffer returned by a C library in an owning type with `Drop` |
| Secrets | `explicit_bzero()` (`rust/src/sys/libc.rs`), `memneq_explicit()` (`rust/src/util/chain.rs`) |
| Files | `read()`, `read_whole()`, `write_complete()`, `append_line()`, `dir_names()`, `dir_names_at()`, `open_beneath()`, `lock_exclusive()` (`rust/src/util/io.rs`) |
| Sealed state and paths root names | `open()`, `open_read()`, `open_sealed()`, `lock()`, `append()`, `mkdir_p()`, `write_file()`; `Output::create()` and `Output::commit()` for a report or export, `output_open()` for one appended to (`rust/src/util/seal.rs`) |
| Bytes on the wire | `from_le_bytes()`, `to_be_bytes()` and kin; `encode()`, `decode()` and `decode_max()` for hex (`rust/src/util/hex.rs`) |
| SHA-256 | `sha256()` or `sha256_into()` of a slice, or a `Sha256Ctx` through `sha256_init()`, `sha256_update()` and `sha256_final()` over pieces (`rust/src/util/crypto_openssl.rs`); `sha256_digest_encode()` and `decode_sha256_digest()` for the `sha256:<hex>` form (`rust/src/util/hex.rs`), `sha256_hex()` for its bare hex (`rust/src/util/bpm_oci/http.rs`) |
| JSON | `rust/src/util/json/`: `parse_schema()` over a table of `JsonField`s into a state the caller passes, each field naming its place in it, and `JsonEmit`, whose `str_lossy()` and `key_lossy()` write text from outside |
| Messages | `log::err()`, `warn()`, `info()`, `audit()`, and `log_c!` for a C format (`rust/src/log.rs`) |
| A command's options | a table of `OptSpec` indexed by the command's constant for each option, an `OptParser` and a `match` over its `next()`, `number()` for a value in a range, `choice()` for one from a set of `OptName`s, `usage()` and `EXIT_USAGE` (`rust/src/util/options.rs`); `HelpSection::options()` (`rust/src/util/help.rs`) lists the same table in help, and `--list-opts` for completion; never compare an argument by hand |

Code that a second place needs moves into `rust/src/util/<m>.rs`, or
into `rust/src/text.rs` for the string and number basics, with cases in
its `tests.rs`, and the copies it replaces go in the same commit, whose
message names each copy and how they differed. Two private copies of
one helper in two commands are a bug in waiting: one gets fixed and the
other does not. A util function takes a slice rather than trusting a
terminator in outside data, returns 0 or a negative errno, or a
`Result` whose error is one, and leaves the message to its caller.

Code the BPF programs share goes in `bpf/lib/` the same way. Where a
shared helper does not make sense, the copy stays and its commit says
why: operator-only code, signing and the package builder, stays out of
the core binary, and a file a CBMC proof includes whole keeps a local
copy when a call into another file would leave the proof a function
without a body.
