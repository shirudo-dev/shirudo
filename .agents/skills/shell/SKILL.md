---
name: shell
description: "Writes and changes shirudo's shell scripts in the tree's style, from the CI scripts of .github/scripts and the test library under testing to the test VM harness and the image, initrd, packaging and backend scripts. Covers when a script is POSIX sh for dash and when bash, the header, set -eu, messages and exit status, quoting and printf, LC_ALL=C, temporary directories and EXIT traps that cannot fail the script, the dash traps that cost time, ShellCheck as CI runs it, where a script goes and its ci-checks test, and never running a guest or CI script on the developer's host. Use whenever writing, changing, reviewing or dry-running a shell script in shirudo."
paths:
  - "**/*.sh"
  - ".github/scripts/**"
  - "tools/gen-image/**"
  - "tools/gen-initrd/**"
  - "tools/backend/jobs/**"
  - "tools/put-shields"
  - "tools/put-shirudo-build"
  - "testing/helper/image-shirudo"
  - "testing/vm/files/shirudo-runtime.in"
  - "testing/fixtures/pipeline/trivy"
  - "upatches/java-sql-inj/sql_inj_vuln"
---

# Shell

Most of the tree that is not C is shell: the CI scripts of
`.github/scripts/`, the runners, `testing/test-lib.sh` and the tests,
the VM harness of `testing/vm/`, the generators of `tools/gen-image/`
and `tools/gen-initrd/`, the jobs of `tools/backend/jobs/` and the
scripts of `packaging/`. Read the script and its directory before a
change and write like them. [dash.md](dash.md) gives, construct by
construct, what dash does with bash and what to write instead: read it
before using a construct this page does not show, and when a script
behaves under `sh` unlike in your shell.

## Pick the shell

`#!/bin/sh` is the default, nine shell scripts in ten. The
runners start every `.sh` test as `sh <test>` (`testing/run-tests.sh`,
`testing/run-target-tests.sh`), make runs recipes with `/bin/sh`, and
workflows start many CI scripts as `sh .github/scripts/<name>.sh`.
`/bin/sh` is dash on Debian and Ubuntu, which the CI runners and the
test VM's guest run, and bash on Fedora: a bashism that passes on
Fedora fails in CI.

Take bash only where sh cannot do the job, and then `set -euo pipefail`:
when a bash program sources the script, as dracut sources
`tools/gen-initrd/module-setup.sh`; when it builds an argument list
whose words hold spaces, as `QEMU_ARGS` in `testing/vm/run.sh`; when a
pipeline's first stage must fail it, as the `tail | head | gzip -dc` of
`testing/vm/build-bundle.sh`. The bash scripts under `tools/`, most of
which `install-operator` and `install-target` install, take
`#!/bin/bash`; any other takes `#!/usr/bin/env bash`, as most outside
`tools/` do. Start a bash script by its path or with `bash`, never with
`sh`, which runs it under dash whatever its shebang says.

A library that scripts source has no shebang and is not executable:
the SPDX tag is line 1 and `# shellcheck shell=sh` (or `bash`) line 2,
as in `testing/test-lib.sh`. Source it by a path with a slash,
`. ./test-lib.sh`: dash's `.` looks a bare name up in `PATH` only, and
ends the script when it is not there. Before a `.` of a computed path,
`# shellcheck source=<path from the root>` names the file it reads.

## Write for dash

POSIX sh has no arrays, `[[ ]]`, `==`, `echo -e`, `$'...'`,
`set -o pipefail`, `source`, `<<<`, `<(...)`, `${v:0:1}`, `${v//a/b}`
or `((...))`, and the tree's sh scripts do without `local` too, all but
`testing/test-lib.sh`. These behaviors cost the most time:

- A special builtin that fails ends the shell, whatever `||` follows:
  `: >"$f"` whose file cannot be opened, a `.` of a file that is not
  there, `exec 3>"$f"`, `shift 2` with one argument, `set -o pipefail`.
  In the `(eval "$body")` of `test_expect_success` it ends the case.
  Create or empty a file with `true >"$f"` or `touch "$f"`.
- `echo` expands backslash escapes in its arguments and takes a leading
  `-n` for its option, so `echo "$out"` alters output that holds `\n`
  or starts with `-n`. `printf '%s\n' "$out"` prints it as it is.
- `[[` is a command dash cannot find: in an `if` its status 127 reads as
  false and the script runs on. `((x = 1))` parses as two nested
  subshells and sets nothing.
- `cmd &>"$f"` starts `cmd` in the background and empties `$f`. Write
  `cmd >"$f" 2>&1`.
- `set -e` is off in an `if` or `while` condition, on either side of
  `&&` and `||`, after `!`, and in everything a function called there
  runs, its own `set -e` included: chain such a function's steps with
  `&&`. A pipeline fails only when its last command does, and
  `local x=$(cmd)` or `export x=$(cmd)` does not fail when `cmd` does.

## Lay a script out

```sh
#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/check-example.sh -- what the script checks or does, and
# the why a reader cannot get from the code.
#
#   .github/scripts/check-example.sh <file>...

set -eu
```

[skeleton.md](skeleton.md) continues this into a whole CI check, with
its traps, messages and exit status: start a script from it.

- The shebang, the SPDX tag on line 2 (`check-spdx.sh` refuses it
  anywhere else), the copyright on line 3, then the header: the path,
  ` -- ` and what the script does, the usage lines indented three
  spaces, and what its arguments and environment select. A test names
  its number in place of the path, `# t0001 -- ...`. A script for a
  throwaway machine says where it runs, as `testing/vm/guest.sh` does.
- `set -eu` follows the header. A library leaves the options to the
  scripts that source it, except `testing/test-lib.sh`, which sets
  `-eu` for every test.
- Tabs eight wide, lines near 80 columns, a message whole on one line so
  that it can be grepped. `case` labels align with `case`, as nearly all
  do. Functions open `name() {` in `.github/scripts/` and the tests, and
  put the brace on a line of its own in `testing/vm/` and `tools/`:
  follow the directory.
- Lowercase variables are the script's own. A setting from the
  environment is read once, with its default,
  `readelf=${READELF:-readelf}`; one the script cannot run without is
  checked first, `: "${OUTPUT_DIR:?OUTPUT_DIR must name ...}"`.
- A CI script that reads the checkout starts with
  `cd "$(git rev-parse --show-toplevel)"`, so it runs from anywhere in
  it.
- A script started by its path is committed executable, as most in
  `.github/scripts/` are. `shirudo-build` execs the scripts of
  `tools/gen-image/` by path, so their shebang and mode are
  load-bearing.

## Messages and exit status

- Everything but the result goes to stderr. A failure prints
  `<script>: <reason>`, from a `die()` where there are several, and
  exits 1. A usage error prints `usage: ...` and exits 2, and so does a
  tool the script cannot run without, with what to install:
  `check-sparse: cgcc not found; install sparse`.
- A check reports every finding, the file or commit first, then exits 1
  with a count; when it passes it prints one line on stdout. Under
  `GITHUB_ACTIONS` each finding also goes to stdout as
  `::error file=<file>::<reason>`, which annotates the pull request, as
  in `check-spdx.sh`. A failure that does not matter is spelled
  `|| true`.

## Quoting and text

- Quote every expansion: `"$var"`, `"$@"`, `"$(cmd)"`. Leave one
  unquoted only to split it on purpose, with the disable and its reason
  on the line before:
  `# shellcheck disable=SC2086 # a command with its options, to be split`.
  An unquoted word also globs, so split only values that cannot hold
  `*`, `?` or `[`.
- Print with `printf` and a literal format, `printf '%s\n' "$x"`, never
  `printf "$x"`. Read lines with `while IFS= read -r line`, as every
  `read` in the tree does.
- Set `LC_ALL=C` where bytes matter: a bracket range in `grep` or `sed`
  (`check-dco.sh`), a sort order `comm` or a later compare relies on
  (`check-style.sh`), the output of a tool parsed as text (`readelf` and
  `ldd` in `tools/gen-image/shirudo-gen-runtime`).
- `command -v`, never `which`. `$(...)` drops every trailing newline,
  and a number with a leading zero is octal in `$((...))`.

## Scratch files and cleanup

- One scratch directory per script, from `mktemp -d`, removed by the
  EXIT trap, every temporary file inside it; never a fixed name under
  `/tmp`. Empty the variable and install the traps before `mktemp`, so
  the cleanup always has a value to test:

  ```sh
  work=
  cleanup() {
  	[ -z "$work" ] || rm -rf "$work"
  }
  trap cleanup EXIT
  trap 'exit 1' HUP INT TERM
  work=$(mktemp -d)
  ```

- dash runs no EXIT trap when a signal ends it, so
  `trap 'exit 1' HUP INT TERM` turns the signal into an exit, which
  runs the cleanup. Never put the signals on the cleanup itself: after
  `trap cleanup EXIT INT TERM` a signal runs the cleanup and the script
  carries on where it was, its scratch gone, and can exit 0, under dash
  and bash alike.
- The cleanup cannot fail the script. Under `set -e` a command that
  fails in the EXIT trap ends the trap, skips the rest of the cleanup
  and makes the status 1 after every step passed; a test then exits 1
  with every case `ok`. End each step that can fail with `|| true`, and
  test with `[ -z "$x" ] || ...`, never `[ -n "$x" ] && ...`, whose
  false test becomes the function's status.
- An operator script writes only the artifacts its caller names, and no
  state, cache or log beside them: the operator is stateless.

## Where a script goes

| Script | Directory | Started by |
|---|---|---|
| A CI step | `.github/scripts/<name>.sh` | the workflow |
| A test | `testing/ci-checks/`, `testing/functional/<family>/`, `testing/end2end/` | the runners |
| The test VM | `testing/vm/` | the VM goals of `testing/Makefile` |
| Image generation, operator | `tools/gen-image/` | `shirudo-build`, installed by `install-operator` |
| Initrd generation, target | `tools/gen-initrd/` | the administrator and dracut, installed by `install-target` |
| A backend job | `tools/backend/jobs/` | the backend's operator, by hand or from a timer |
| A package build | `packaging/deb/`, `packaging/rpm/`, `packaging/tar/` | `make -C packaging` |

- Shell that a workflow runs lives in `.github/scripts/`, not inline in
  the workflow file: only a file gets ShellCheck and a test.
- A change to a check of `.github/scripts/`, or to a script whose logic
  decides a result, adds or updates its test,
  `testing/ci-checks/t00<NN>-<script>.sh`, as `t0001-check-dco.sh`
  runs `check-dco.sh` on a throwaway repository. A script that only
  sets up a throwaway machine is checked by the workflow that runs it.
- `t1007-test-vm-cli.sh` greps lines of `testing/vm/guest.sh` and
  `testing/vm/run.sh` as they are written, and `t1006-gen-initrd-cli.sh`
  checks the options of the initrd generator and installer: a change to
  `testing/vm/` or `tools/gen-initrd/` runs both.
- For a script a page or a skill names, `git grep -n '<script>'
  Documentation .agents/skills` and follow the `docs` skill.

## Target, operator and license

- The `shirudo` binary never runs a script or an external tool on a
  target, and no script stands in for a target operation. Besides the
  maintainer scripts that `packaging/deb/builddeb.sh` and
  `packaging/rpm/buildrpm.sh` write as here-documents, which ShellCheck
  never sees, the target package installs two scripts,
  `shirudo-gen-initrd` and the dracut module `90shirudo`, which the
  administrator and dracut run.
- Operator shell runs under `shirudo-build`, which execs the scripts of
  `tools/gen-image/`; the tools they call, `veritysetup` and `mkfs.ext4`
  among them, are operator-only dependencies and stay out of
  `install-target`.
- Every script is BSD-2-Clause and written from scratch. Never copy
  shell from a GPL source, dracut's own modules or the kernel's scripts
  among them; `testing/test-lib.sh` is a whiteroom of the harness
  subset the tests use. A GPL tool a script runs stays out of the tree:
  `check-style.sh` fetches `checkpatch.pl` at a pinned SHA-256 into
  `build/checkpatch/`.

## Scripts for a throwaway machine

Many scripts assume a disposable VM, container or CI runner and change
it as root: they install packages, write `/etc` and `/boot`, rebuild
initrds. Among them are `testing/vm/guest.sh` and `testing/vm/files/`,
the LVH guest's `lvh-prepare.sh`, `lvh-target-deps.sh`,
`kernel-obs-in-lvh.sh`, `kernel-obs-apt-diagnostics.sh` and
`sanitizer-deps.sh`, the runner setup of `install-clang.sh`,
`debian-deps.sh`, `vm-toolchain.sh` and `tests.sh setup`,
`infra/aws/packer/scripts/`, and every target test, `t?1??`. Never run
one on the developer's host, and never with `sudo`; the `testing` skill
runs them in a VM.

Before a dry run of any script, read every script it can reach, by
`sh`, `bash`, `.`, a path in a variable or an absolute path, and replace
each with a stub that only logs its arguments; never copy a real helper
into the stub tree. A stub in `PATH` replaces only a command looked up
by name: `kernel-obs-in-lvh.sh` starts
`/bin/sh /host/.github/scripts/kernel-obs-apt-diagnostics.sh` on its apt
failure path, which runs `update-initramfs` for every kernel under
`/lib/modules`. Reached once in a stubbed dry run, it rebuilt the
initrds of the developer's host.

Try a snippet with `sh -c '...'`, or in a file run with `sh`, never in
your interactive shell: that is bash, and in an agent's shell `grep`,
`find` and `clang` can be functions or aliases (`type grep` says so).

## Check

```sh
sh -n <script>                 # bash -n for a bash script
shellcheck <script>            # fix what it reports in the lines you wrote
shellcheck -S error <script>   # what CI's ShellCheck job fails on
.github/scripts/check-spdx.sh
make -C testing ci-checks      # after a change to .github/scripts/
make -C testing functional/build VM=0 TEST_FILTER='^t100[67]-'
                               # after one to testing/vm/ or tools/gen-initrd/
```

The ShellCheck job of `.github/workflows/lint.yml` runs on every pull
request, push to main and merge queue. It checks each `*.sh` file and
each executable file without a dot in its name whose first line names a
shell, outside `vendor/`, one at a time, at severity error, with the
latest stable ShellCheck; the tree passes it. It misses the bashisms of
a `#!/bin/sh` script, which ShellCheck reports as warnings (SC3xxx),
and every file it does not find, such as
`testing/vm/files/shirudo-runtime.in`, so run `shellcheck` at its
default severity yourself, from the root, where the `source=` paths
resolve. What the tree carries there stays: SC2016, SC2034 and SC2164
by the hundred in the tests, for the bodies `test_expect_success`
evaluates and the `cd` before `. ./test-lib.sh`, and SC1091 wherever a
script sources a file. Fix what the lines you wrote add.

Then run the tests of the family that starts the script as the
`testing` skill says and the `pre-submit` checks on the series, and
write the commit message as the `commits` skill says.
