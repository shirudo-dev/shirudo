# Use util/, and grow it

Write common code once, in `util/`, and call it. A hash, an encoding, a
digest's text form, a path, a record format, a file read with its
checks, the parse of a name or a number: code that does a job like
these belongs in a helper of `util/`, or of `include/shirudo/` for the
project's basics, not inline in a builtin or a tool. Write it there
from the start when a second caller is in sight, rather than waiting
for the copy. Copies drift apart, and the difference between them is
usually a bug in one: the `sha256:` digest of a manifest was checked
and decoded by hand in six places, one with a length check the others
lacked, and written in ten, each its own way, until
`sha256_digest_decode()` and `sha256_digest_encode()` in `util/hex.c`
took the place of them all.

Never write the same logic twice. Before writing a parser, a check, a
path, a copy loop or a record format, look for one that already does it,
in `util/`, `include/shirudo/` and the builtins alike: `git grep -n
'<word>'`. A variant that differs only in a length check, a bound or a
message is still a copy: make one helper, with a parameter or with the
extra check left to the caller, and move one found in a builtin into
`util/` for both. A copy found while working on something else is
consolidated in a commit of its own, before the change that needed it.
A review asks of every new block of code whether `util/` has it
already, or should. The basics:

| Need | Use |
|---|---|
| Parse a number | `parse_u64()`, `parse_s64()`, `parse_x64()`, `digits()` (`<shirudo/string.h>`) |
| Copy or format a string | `strscpy()`, `strsprintf()`, `vstrsprintf()`, and check `-E2BIG`; `strscpy_literal()` for a string literal into an array, which fails the build where it does not fit (`<shirudo/string.h>`) |
| A upatch's pin directory or a pin in it | `upatch_pin_path()` (`util/paths.h`) |
| A string's prefix, or a span that must be one string | `str_has_prefix()` to test a literal prefix and `str_skip_prefix()` to step past it, `str_after_prefix()` for the rest after a prefix known only at run time, each with a `_nocase` form for a letter in either case; `span_equals()` for a span of known length against a literal, `span_equals_str()` against a string, `span_has_prefix_nocase()` for a span's start; `str_equals_nocase()` for two whole strings in either case (`<shirudo/string.h>`); `strncmp()` and `strncasecmp()`, whose length a caller counts by hand, and `strcasecmp()` are poisoned |
| A byte of a set, or a string, in the bytes you hold | `span_until()` for the length up to the first byte of a set, `span_find()` for where a string lies in a span, `str_contains()` for whether a string holds another (`<shirudo/string.h>`); `strcspn()`, `strpbrk()` and `strstr()`, which search to a terminator, are poisoned |
| The lines of a buffer, the words of a line, the entries of a list | `for_each_token()` (`<shirudo/string.h>`), which gives each token as pointer and length and writes nothing; a caller that needs a terminated token ends it in a buffer of its own; `strtok_r()`, `strtok()` and `strsep()` are poisoned |
| A file name's extension | `name_has_suffix()` (`<shirudo/string.h>`), `upatch_select()` for a scandir of upatches |
| Text from outside on a terminal | `text_sanitize()`; UTF-8 with `utf8_width()` |
| Bytes from outside as a string | `span_to_str()` (`<shirudo/string.h>`), which takes their length and refuses a NUL among them; `read_text_line()` for a line of a settings file (`util/io.h`) |
| Sizes and lengths | `check_add_overflow()` and kin, `size_add()`, `size_mul()`, `struct_size()`, `DIV_ROUND_UP()` (`<shirudo/overflow.h>`) |
| Smaller or larger | `min()`, `max()` (`<shirudo/misc.h>`) |
| Memory | `xmalloc()`, `xcalloc()`, `xreallocarray()`, `xstrndup()`, `xasprintf()`, `xfree(p, size)` (`util/malloc.h`) |
| Secrets | `memzero_explicit()`, `memneq_explicit()` |
| Files | `read_file()`, `read_fd()`, `write_complete()`, `append_line()`, `lines_len()`, `open_beneath()`, `lock_exclusive()` (`util/io.h`); `open_trusted()` to open by name a file under `/etc/shirudo` or `/var/lib/shirudo` that steers what shirudo trusts, never `open()` and `check_trusted()`, and `check_secret()` once such a file turns out to hold a secret |
| Sealed state and paths root names | `seal_open()`, `seal_lock()`, `seal_append_line()`, `seal_write_file()`; `seal_output_create()` and `seal_output_commit()` for a report or export (`util/seal.h`) |
| Bytes on the wire | `get_le32()`, `put_be32()`, `le32_to_cpu()` and kin (`<shirudo/byteorder.h>`), `hex_encode()`, `hex_decode()`, `hex_decode_max()` (`util/hex.h`) |
| SHA-256 | `sha256_buffer()`, or `sha256_init()`, `sha256_update()` and `sha256_final()` over pieces (`util/crypto.h`); `sha256_digest_encode()` and `sha256_digest_decode()` for the `sha256:<hex>` form (`util/hex.h`), `bpm_sha256_digest()` to hash and write it at once (`util/bpm_oci.h`) |
| JSON | `util/json.h`: `json_parse()` with a schema, `json_walk()`, `struct json_emit` |
| Messages | `pr_err()`, `pr_warn()`, `pr_info()`, `pr_audit()` (`util/log.h`) |
| A command's options | a table of `struct opt_spec` indexed by the command's enum, `OPT_INIT()`, a switch over `opt_next()`, `opt_u64()`, `OPT_CHOICE()` for a value from a set of names, `opt_usage()` and `EXIT_USAGE` (`util/options.h`); `HELP_OPTIONS()` lists the same table in help, and `--list-opts` for completion; never compare `argv[]` by hand |

Code that a second place needs moves into `util/<m>.c`, declared in
`util/<m>.h`, or in `include/shirudo/` for the project's basics, with
cases in `testing/unit/<m>.c`, and the copies it replaces go in the same
commit, whose message names each copy and how they differed. Two static
copies of one helper in two builtins are a bug in waiting: one gets
fixed and the other does not. A util function takes a length rather
than trusting a terminator in outside data, returns 0 or a negative
errno, and leaves the message to its caller.

Code the BPF programs share goes in `bpf/lib/` the same way. Where a
shared helper does not make sense, the copy stays and its commit says
why: operator-only code, signing and the package builder, stays out of
the core binary, and a file a CBMC proof includes whole keeps a local
copy when a call into another file would leave the proof a function
without a body.
