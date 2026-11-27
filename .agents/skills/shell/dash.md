# What dash does differently

What dash, the `/bin/sh` of Debian and Ubuntu, does with what a bash
user writes, each checked with `dash -c` on the 0.5.12 of Ubuntu 24.04.
A later dash may take a construct or two of these; the scripts avoid
them all the same, so that any dash runs them.

- [Constructs dash does not have](#constructs-dash-does-not-have)
- [Special builtins that end the shell](#special-builtins-that-end-the-shell)
- [Where set -e does not reach](#where-set--e-does-not-reach)
- [Traps and signals](#traps-and-signals)
- [echo, read and expansions](#echo-read-and-expansions)
- [See it for yourself](#see-it-for-yourself)

## Constructs dash does not have

| Construct | What dash does | Write |
|---|---|---|
| `a=(1 2)` | syntax error, the script does not start | `set -- "$@" "$x"`, or one item per line |
| `${a[0]}`, `${PIPESTATUS[0]}` | `Bad substitution`, ends the script | as for arrays; a status saved in a variable |
| `[[ -n $x ]]` | `[[: not found`, status 127, false in an `if` | `[ -n "$x" ]`, `case` for a pattern |
| `[ "$a" == b ]`, `=~` | `unexpected operator`, status 2, false in an `if` | `=`, `case` |
| `function f {` | syntax error | `f() {` |
| `local x` | keeps the caller's value of `x` | a name no caller uses, or `f() ( ... )` |
| `$'\t'` | a literal `$` followed by `\t` | `tab=$(printf '\t')` |
| `echo -e` | prints `-e` | `printf` |
| `set -o pipefail` | illegal option, ends the script | check the stage that can fail on its own |
| `source f` | `source: not found` | `. ./f` |
| `cmd <<< "$x"`, `<(cmd)` | syntax error | a here-document, a file in the scratch directory |
| `cmd &>f` | runs `cmd &`, then empties `f` | `cmd >f 2>&1` |
| `cmd \|& next` | syntax error | `cmd 2>&1 \| next` |
| `${v:0:1}`, `${v//a/b}`, `${v,,}`, `${v^^}` | `Bad substitution`, ends the script | `case`, `${v#...}`, `${v%...}`, `tr`, `sed` |
| `{a,b}`, `{1..3}` | left as written | the words spelled out |
| `((n++))`, `((x = 1))` | two nested subshells, nothing set: `n++: not found` | `n=$((n + 1))` |
| `let`, `declare`, `mapfile`, `readarray` | not found, status 127 | `$((...))`, plain assignment, `while IFS= read -r` |
| `printf -v x`, `printf %q` | illegal option, invalid directive | `x=$(printf ...)` |
| `read -a`, `read -t`, `read -n`, `read -s`, `read -d` | illegal option | `IFS= read -r` and `-p`, the options dash has |
| `[ -v name ]` | unexpected operator | `[ -n "${name+set}" ]` |
| `kill -SIGTERM`, `wait -n` | illegal option | `kill -TERM`, one `wait "$pid"` each |
| `trap cmd ERR` | `bad trap`, nothing installed | test each step |
| `$(< file)` | empty | `$(cat file)` |
| `$RANDOM` | empty | `mktemp` for a unique name |

## Special builtins that end the shell

`.`, `:`, `eval`, `exec`, `export`, `readonly`, `set`, `shift` and the
other special builtins end a non-interactive dash when they fail, and an
`||` after them never runs:

```sh
: >/nonexistent/f || echo handled     # ends the script, status 2
true >/nonexistent/f || echo handled  # prints the error, then handled
```

The same holds for a `.` of a file that is not there, `exec 3>"$f"`
that cannot open `$f`, `shift 2` with one argument, `set -o` with an
option dash lacks, an assignment to a readonly name, `export 1x=2`, an
`eval` of a syntax error, and a function whose body does any of these.
Inside `( ... )` or `$( ... )` only that subshell ends, so in a test
body, which `test_expect_success` runs as `(eval "$body")`, the case
fails with no message of its own. `command` in front makes the builtin
an ordinary command: `command . ./f || ...` returns instead of ending.
A `trap` naming a signal dash does not know prints `bad trap` and goes
on.

## Where set -e does not reach

- An `if`, `elif`, `while` or `until` condition, a command before `&&`
  or `||`, a command after `!`, and everything a function called from
  one of those runs, a `set -e` in its body included.
- Every command of a pipeline but the last.
- `local x=$(cmd)`, `export x=$(cmd)` and `readonly x=$(cmd)`: their
  status is the builtin's. A plain `x=$(cmd)` fails as `cmd` does.
- In dash a command substitution inherits `set -e`, so
  `x=$(false; echo hi)` ends the script. Bash turns `-e` off there
  unless `shopt -s inherit_errexit` is set, and the same line gives
  `hi`.
- `set -u` does not catch an unset name inside `$((...))`, which dash
  reads as 0. `${name:-}` marks a variable that may be unset.

## Traps and signals

- dash runs no EXIT trap when a signal ends it; bash does. With
  `trap 'exit 1' HUP INT TERM` the signal becomes an exit and the EXIT
  trap runs in both.
- A trap action that does not exit lets the script carry on where the
  signal came: `trap cleanup EXIT INT TERM` runs `cleanup` on `TERM`,
  continues, runs `cleanup` again at the end and can exit 0.
- `$?` at the start of the EXIT trap is the status the script is
  leaving with, and it stays the exit status unless the trap calls
  `exit` or a command in it fails under `set -e`, which makes it 1 and
  skips the rest of the trap. `testing/functional/tpm/t4103-nv-writer.sh`
  saves `result=$?` first, clears the trap with `trap - EXIT`, gathers
  the cleanup's failures into `result` and exits with it.

## echo, read and expansions

- dash's `echo` expands `\n`, `\t`, `\b` and the rest in its arguments,
  stops all output at `\c`, and reads a leading `-n` as its option.
  `printf '%s\n' "$x"` prints any value as it is.
- `read` without `-r` drops backslashes, and without `IFS=` strips
  leading and trailing blanks: `IFS= read -r line` reads a line whole.
- A `while read` at the end of a pipeline runs in a subshell, and what
  it assigns is gone after the loop. Read from a file instead,
  `done <"$work/list"`, or a here-document.
- `$(...)` drops every trailing newline. Keep them with
  `x=$(cmd; echo .); x=${x%.}`.
- A number with a leading zero is octal: `$((010))` is 8, `$((08))` an
  error and `printf %d 08` a failure. Strip the zeros of a number read
  from text first.
- An unquoted expansion is split on `IFS` and globbed. `[ $x = y ]`
  with an empty `x` is `[ = y ]`, an error; quote it.

## See it for yourself

- `dash -c '<snippet>'`, or a file run with `sh` where `/bin/sh` is
  dash. The interactive shell an agent works in is bash, often with
  `grep`, `find` or `clang` redefined (`type grep`), so a line that
  works there proves nothing about the script.
- `dash -n <script>` reports only syntax errors: arrays, `<<<`,
  `function f {`. `[[`, `local`, `echo -e`, `$'...'`, `==` and `source`
  pass it and fail when the line runs.
- `shellcheck <script>` at its default severity names each bashism of a
  `#!/bin/sh` script with a warning numbered SC3xxx. CI's ShellCheck
  job, at severity error, does not.
