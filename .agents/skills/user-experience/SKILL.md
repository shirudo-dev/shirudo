---
name: user-experience
description: Keeps shirudo's command output, JSON, messages, options and help consistent. Covers field names, report layout, stable keys, exit statuses and the docs and tests affected by output changes. Use when changing a command, option, message, help text, report line, table or JSON key, and when reviewing what a command prints.
paths:
  - "rust/src/builtin/**"
  - "rust/src/util/json/**"
  - "rust/src/util/options.rs"
  - "rust/src/util/options/**"
  - "rust/src/util/format.rs"
  - "rust/src/util/image_runtime.rs"
  - "rust/src/util/attest.rs"
  - "rust/src/util/help.rs"
  - "rust/src/util/report.rs"
  - "rust/src/log.rs"
  - "rust/src/shirudo_build/**"
  - "tools/gen-image/**"
  - "completion/**"
  - "Documentation/reference/cli/**"
  - "Documentation/reference/formats/**"
  - "Documentation/reference/failure-categories.rst"
---

# User experience

What a command prints is an interface: the report people read, the JSON
scripts parse, the messages the journal keeps, the help an agent learns
the command from, and the exit status. `shape.md` of the `coding` skill
says it of command output, JSON keys and exit statuses: changing them
breaks their users. Write output like the commands that already
print the same kind of thing, and read the printers named below before
adding one. [fields.md](fields.md) holds the names of the fields that
several commands show.

## Human output

Results go to standard output, messages and help to standard error
(`help::print_help()` and `rust/src/log.rs`); only the scripts under
`tools/gen-image/` print their help on standard output. A report is a
header line, then key-value lines, then sections:

```text
Payload sha256:        <digest>

Signature:
  Length:              42 bytes
```

- Labels occupy 22 columns, two spaces in when they sit in a
  section, with their colon inside the padding, as in
  `rust/src/builtin/status.rs`, `rust/src/builtin/upatch/`,
  `rust/src/builtin/keys.rs` and `rust/src/util/image_runtime.rs`.
  A label is sentence case and keeps acronyms as written:
  "Payload sha256:", "SPKI fingerprint:", "TPM:".
- A section heading is sentence case and ends in a colon, after a blank
  line. A section that lists items carries their count: "Loaded upatches
  (1):", "Pinned maps (2):", "Members (3):". A section that groups the
  fields of one thing has none: "Signature:", "Loader:".
- An empty list prints one line, `  none`. A value that is absent prints
  `none`, a value that cannot be read or formatted `?`, with the reason
  where one is known ("unavailable: %s").
- A table is indented two spaces. Its first column is as wide as the
  longest name and at least 24 bytes, as `name_column_width()` in
  `rust/src/util/format.rs` calculates. Separate columns by two spaces
  and use upper-case headers: NAME, LOADED, TYPE, KIND, PAYLOAD in
  `upatch list`; NAME, LOCATION, MAPS, MISSED, STATUS, AGE in `status`;
  UPATCH, MAP, TYPE in `upatch map`; TYPE, STATUS, DETAIL for conditions;
  NAME, VERSION, SOURCE in `bpm list`. Print the header above rows only;
  with no rows, print `  none` under the section heading.
- A checklist line is `  OK    text`, `  FAIL  text` or `  NOTE  text`:
  upper case, the text at column 8. `Report::check()` and
  `Report::note()` in `rust/src/util/attest.rs` write them for `attest verify` and `attest challenge`;
  `print_preflight()` in `rust/src/builtin/init/mod.rs` writes them
  for `init --check-only`. The last line is `verdict: ok` or
  `verdict: fail`.
- `status` folds a section whose condition is OK unless `--show-full` is
  given, and its last line names every section it folded. A section
  that is long and usually healthy folds the same way.
- Values are lower case words (`yes`, `no`, `load`, `unload`, `bpf`),
  digests full lower-case hex; a table column may cut a digest to 16
  digits and `..`. Condition statuses (`OK`, `WARN`, `ALERT`) and the
  checklist marks are the upper-case exceptions, in text and JSON alike.
- shirudo and upatch stay lower case in output as in prose, at the start
  of a line too, and so does any name the command prints. Text that comes
  from outside, a name from a file or a registry's error body, goes out
  through `fputs_sanitized()` or `text::sanitize()`.

## One name per field

A field that several commands show has one name: the same label in
text, the same column header in tables and the matching JSON key.

- The JSON key is the label in lower case without its colon, spaces and
  hyphens turned into underscores: "Payload sha256:" is `payload_sha256`,
  "File size:" is `file_size`, "Frozen serial:" is `frozen_serial`.
  A label inside a section takes the section's word where the key would
  otherwise clash: "Name:" under "Signed sections:" is `signed_name`.
- The column header is the label's head noun in upper case, the shortest
  that stays unambiguous in that table: "Payload sha256:" is PAYLOAD in
  `upatch list`.
- A value keeps its meaning under its name everywhere: "Fingerprint:"
  and `fingerprint` are the SHA-256 of a certificate's SPKI, the value
  `bpm key fingerprint` prints, and "Certificate sha256:" and
  `cert_sha256` the SHA-256 of its DER.
- Before naming a field, look it up in [fields.md](fields.md) and grep
  for it: `git grep -n '"<key>"' -- rust/src` and
  `git grep -n '"<Label>:"' -- rust/src`. A field shown for the first time
  gets its row there.

## Structured output

These commands take `--json`: `status`, `init --check-only`,
`keys`, `upatch list`, `upatch info`, `upatch get`, `upatch map`,
`attest verify`, `attest predict`, `image status`, `bpm list`,
`bpm key list`, `bpm config register list` and `bpm info data`.
`upatch map --json=<path>` appends to a file. An operation writes its
report with `--report=<path>`: `upatch load`, `unload` and `reconcile`
through `rust/src/util/report.rs`, `-` for standard output, and `bpm tree sync`.
A command that prints a report people read and gains a JSON form takes
`--json`.

- The JSON form is complete: every field the text shows, with the same
  value in its raw form, a number as a number, a flag as a boolean,
  absent or unreadable as `null`. Text may fold or cut; JSON does
  neither. A row the text shows, an unreadable entry included, is a row
  in the JSON.
- Write it through `JsonEmit` in `rust/src/util/json/`: `obj_open()`,
  `kv_string()`, `kv_int()`, `kv_u64()`, `kv_bool()`, `kv_null()` and
  the array methods, with `kv_string_lossy()` for outside text.
  Check the emitter's error before writing the document. Never
  assemble JSON with formatting calls.
- Every top-level object starts with `"schema": 1`. One document goes
  to standard output; messages stay on standard error.
- Keys are snake_case. Enumerated values are lower case: `ok`, `fail`,
  `note` in checklists, `load` and `unload`, `bpf` and `java`. Formats
  shirudo does not own keep their spelling (`mediaType` in OCI,
  `stringValue` in OTLP), only in `rust/src/util/bpm_oci/`, `rust/src/util/bpm_package/`,
  `rust/src/util/decode/`, `rust/src/util/otel/` and
  `rust/src/shirudo_build/bpm/publish.rs`.
- Keys are stable. Adding a key is compatible; renaming or removing one,
  or changing a value's type or meaning, breaks the scripts that read it
  and changes the format page in the same commit.

## Messages

Every message goes through `log::err()`, `log::warn()`,
`log::info()` or `log::audit()` (`rust/src/log.rs`): syslog under
`LOG_AUTHPRIV` and standard error, once only under a systemd unit.
A usage error goes through `OptParser::usage()`. There is no separate hint logger; put what to check
in the message itself.

- Start with the command as typed, `upatch load: `, or for a step many
  commands share its subsystem in lower case, `tpm: `, `seal: `. Then a
  statement in natural English: what failed, on what, and why. No
  question, no " -- " and no " + ", no shouting ("NOT"), no closing
  period. Name a command to run in backticks with `shirudo`, as
  `` `shirudo image update` ``.
- Keep each message one literal on one source line, however long, with
  its arguments on the next lines, so that `git grep` finds the text
  users report. `check-style.sh` lets `LONG_LINE_STRING` pass for that
  reason. Help strings may break after a `\n`.
- No `\n` in a message: `log::escape()` in `rust/src/log.rs` prints every
  non-printable byte as a backslash and three octal digits, so a line
  break shows up as `\012`. `rust/src/log.rs` does not wrap; a message is one
  line on the terminal and in the journal.
- Never name a page under `Documentation/`: a target may not ship the
  docs. Name the command, the file, the setting (`eventlog.max_bytes`)
  or the kernel option (`CONFIG_CRYPTO_MLDSA`).
- Where shirudo treats the node or the input as tampered or untrusted,
  the message states what does not match and stops there. It never
  suggests retrying, re-issuing with a refreshed value, unloading,
  rebooting or any other way around; the advice is to keep the eventlog
  and the journal as evidence and handle the node as an incident. A
  known benign cause may be stated as a fact. Retry advice belongs to
  operational failures only: network, disk, lock, TPM busy, stale index.
- `log::audit()` records a change of state, one line per change, in the
  same sentence form ("upatch load: %s loaded, %u programs, keyring %d").
- A usage error reads `<command>: <what is wrong>` and the command
  returns `EXIT_USAGE`. Say what the command takes: "takes <file.upatch>",
  "takes <package-file> and <repository>", "unexpected argument '%s'",
  "--all goes with upatches alone". `OptParser::next()` already says
  "unknown option", "takes a value", "takes no value", "given twice".

## Options

Every command parses its options with `OptSpec` and `OptParser`
from `rust/src/util/options.rs`. A table of specs is indexed by the
command's option constants; a loop over `OptParser::next()` returns 0
on `OPT_DONE`, `EXIT_USAGE` on `OPT_USAGE` and on an `OPT_ARG` it does
not take. `number()` and `choice()` read numbers and names; `OPT_REPEAT`,
`OPT_EMPTY` and `OPT_OPTIONAL` mark the exceptions. The parser
gives every command the same rules: `--opt=value` and `--opt value`, `-h` and `--help`,
`--list-opts` for completion, `--` to end the options, a did-you-mean
after an unknown option.

- The same function has the same name: `-o`/`--output` for a file to
  write, `--cert` for a certificate, `--key` for a signing key,
  `--keys-dir` for the directory of both, `--file` for a Beefile,
  `--json` for the JSON form, `--report` for an operation's report,
  `--vmlinux`, `--version`. `-f` is `--force`, in `genkey` alone; the
  only other short options are `-o` and `-h`.
- A value's placeholder is one already in use for that kind of value:
  `<dir>`, `<path>`, `<hex>`, `<cert.der>`, `<signing_key.pem>`,
  `<version>`, `<url>`. `completion/shirudo.bash` offers files for any
  placeholder `_shirudo_value()` does not list, so a placeholder for a
  value that is not a file gets its case there.
- `HelpSection::options()` puts the table in the help, and
  `--list-opts` prints it, so help, completion and parser cannot
  drift. A subcommand group answers `--list-cmds` through `print_subcmd_list()` and resolves names
  with `resolve_subcommand()`. `image build` alone is parsed by
  `tools/gen-image/shirudo-gen-verity`, and completion lists its options
  by hand.

## Help text

`help::print_help()` (`rust/src/util/help.rs`) prints a `Help`:
`usage: ` and the usage lines, the summary, sections and footer.

- Every command and subcommand has usage, a summary and, where it takes
  options, `HelpSection::options(c"options:", &OPTS)`. Section headings
  are lower case ("options:", "subcommands:", "sync options:").
- Every command and subcommand ends its help with an `Examples:` footer
  of at least one worked example, the most common use first. A change
  to a command whose help has none adds them.
- An example is a whole command line from `shirudo`, indented two
  spaces, without a prompt: the prompts `operator$` and `target#`
  belong to the docs' console blocks (`writing-docs.rst`). It uses the
  real option names in their long form, values a reader can copy (a
  package of `upatches/`, `cve-2026-31431`, `kernel-obs`), and
  `<lowercase-words>` where no real value exists. Never `$(...)` or
  `foo`. A long line continues with ` \` and four spaces.
- Usage lines write an option as the options section does,
  `--cert <cert.der>`, and `--json[=<path>]` for one whose value is
  optional, with the placeholders of the option table.
- `print_help()` wraps only the item summaries, at `HELP_WIDTH` (90).
  Break the summary and the footer with `\n` yourself, under 80 columns.
- A subcommand the core binary hands to `shirudo-build` prints the
  helper's help, so `--help` and `--list-opts` describe the same
  options.

## Exit statuses and failure categories

0 is success, 1 a refusal or failure, `EXIT_USAGE` (2) a usage error,
127 a `shirudo-build` helper that cannot run. `upatch load`, `unload`
and `reconcile` also name a phase and a category in their report.
`Documentation/reference/failure-categories.rst` is the home of the
categories and of the exit statuses of every command; each page under
`Documentation/reference/cli/` repeats its command's own in its "Exit
status" section. A change to an exit status changes both in the same
commit, and a new category goes into `failure-categories.rst` with the
phases that reach it.

## What a change to output touches

The `docs` skill lists the pages; for output they are:

- `Documentation/reference/cli/<command>.rst`: usage, options, output,
  examples and exit status.
- `Documentation/reference/cheat-sheet.rst` and the guides under
  `Documentation/start/` and `Documentation/operate/` that run the
  command: `git grep -n '<old wording>' Documentation`.
- The format page of a JSON form: `reference/formats/status-json.rst`,
  `keepalive.rst`, `map-export.rst`, `otlp.rst`, `bpm-formats.rst`,
  `upatch-tree.rst`.
- `completion/shirudo.bash` for an option it lists by hand or a
  placeholder that is not a file.
- Transcripts on a page are captured from a run in the test VM (the
  `testing` skill boots one), never typed or edited by hand.
- Tests grep output: `git grep -n '<old wording>' testing/` before
  rewording a label, heading, message or key, and change the tests in
  the same commit.

## Check

Before handing over a change to output:

- [ ] Run the changed command with and without `--json` and read both:
      the same fields, the same values, `"schema": 1` first.
- [ ] Labels `%-22s`, headings in sentence case with a count on a list,
      `  none` when empty, table headers in upper case.
- [ ] Every field name the change prints found in [fields.md](fields.md),
      or added there.
- [ ] Every message: a prefix, a statement, one literal on one line, no
      `\n`, no " -- ", no " + ", no `Documentation/`, no retry or
      workaround on a tampered state.
- [ ] `<command> --help` shows usage, options and an example;
      `<command> --list-opts` lists the same options.
- [ ] An option that does what another command's does has its name and
      placeholder.
- [ ] Exit statuses checked against `failure-categories.rst` and the
      command's page.
- [ ] `git grep` of every old label, message and key in `testing/`,
      `Documentation/` and `.agents/skills/` comes back empty or changed.
- [ ] `.github/scripts/check-docs.sh` passes; transcripts recaptured in
      the test VM.
