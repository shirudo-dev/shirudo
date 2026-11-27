---
name: functional-tests
description: Writes shirudo's shell tests in testing/functional/, the operator tests (t?0??) that run on the build host and the target tests (t?1??) that run as root in a fresh VM per family, and the tests of .github/scripts in testing/ci-checks/. Covers test-lib.sh and integration-lib.sh, choosing the family and a free number, signed upatch and config image fixtures, compiled helpers, the test-coverage row, why a target test never skips, the errexit, eval and dash traps of the harness, and reading guest.log and result/status. Use when adding, changing or debugging a shell test, a fixture or helper it uses, or a test of a CI script.
paths:
  - "testing/functional/**"
  - "testing/ci-checks/**"
  - "testing/test-lib.sh"
  - "testing/integration-lib.sh"
---

# Functional tests

A functional test shows one command, mechanism or attack: as an
operator test on the build host when it needs no root, kernel or TPM,
as a target test in its family's VM when it does. The tests of
`.github/scripts/` work the same way in `testing/ci-checks/`. A pure
function goes in a unit suite, a path across operator, registry,
target and backend in end2end: "Choose a tier" in the `testing` skill.

`Documentation/contribute/testing/testing.rst` is the reference: "Test
numbers and families", "Write a shell test" with both skeletons, and
"Add a fixture or a helper". This skill adds the procedure and the
traps.

## Place and number it

1. Take the family that owns the mechanism from the table in
   `testing.rst`. `K` is `0` for an operator test, `1` for a target
   test. The directories of one family share its numbers: `upatch` and
   `upatch-many`, `image` and `image-reboot`, `tamperproof` and `labels`,
   `bpm` and its `bpm-*`.
2. Take the next number after the highest of the family and kind, and
   check that no test ever had it:

   ```sh
   ls testing/functional/*/t<F><K>??-*.sh
   git log --format= --name-only -- 'testing/*t<F><K><NN>-*'
   ```

   A hit outside the family's directories comes from an older
   numbering and does not count.
3. Name it `t<F><K><NN>-<what>.sh`. A Python companion takes the same
   stem (`t5101-verity-boot-signers.py`) and only its shell test runs
   it. A file that is not a test takes no name of this form.

Nothing registers a test. `testing/run-tests.sh` runs every
`t?0??-*.sh` of the family in name order on the host,
`testing/run-target-tests.sh` every `t?1??-*.sh` in its VM, and
`testing/Makefile` makes a family of each directory that holds either.
A directory added is a family of its own: add it, where `make -C
testing help` lists it, to the families the case `the runners split
the tests by number` of `testing/functional/build/t1007-test-vm-cli.sh`
compares, and to the family tables of `testing.rst` and
`test-coverage.rst`. CI's `functional-ci-4` shard takes it,
`functional-ci-3` one named `bpm-*`.

## Operator tests

- Start from `testing/` (`cd "$(dirname "$0")/../.."`, then
  `. ./test-lib.sh`), as `testing.rst` shows. Name the binaries
  `S=../shirudo` and `SHB=../tools/shirudo-build/shirudo-build`; a test
  that runs `bpm build` exports `SHIRUDO_BUILD` with an absolute path,
  as `t7006-policy-labels.sh` does.
- `test_skip_all` only for what a host may lack, a tool or an unbuilt
  binary. On the host a skip passes, so it must never stand in for a
  result.
- CI runs the host tier as root (`sudo make` in
  `.github/scripts/tests.sh`); you run it as yourself. A case whose
  result depends on the user branches on `id -u`, as `t1006` does.
- The libtpms simulator stands in for a TPM on the host:
  `SHIRUDO_TPM_TCTI="cmd:exec $(pwd)/helper/tpmsim-cmd <state-dir>"`,
  as `t4005-tpm-session.sh` sets it.

## Target tests

Source `integration-lib.sh` and call `target_guard`, which skips
without root, `$SHIRUDO_BIN` or an attached LSM. The guest's
`/etc/shirudo-test-vm.env` sets:

| Variable | Value |
|---|---|
| `SHIRUDO_BIN` | `/usr/local/bin/shirudo-runtime`, the runtime image's command, with task authority; `/usr/local/bin/shirudo` is a copy without it, for what an unauthorized caller gets |
| `SHIRUDO_TEST_FIXTURES_DIR` | `/mnt/shirudo-bundle/fixtures`, the signed `.upatch` fixtures |
| `SHIRUDO_TEST_KEY_FIXTURES` | `/mnt/shirudo-bundle/verity`, the signed config images |
| `SHIRUDO_TEST_RESULTS` | `/mnt/shirudo-out/verity`, `result/verity/` on the host |

`integration-lib.sh` gives `require_loaded <fixture>` (loads a signed
fixture unless its pins exist), `report_field <key>` (a top-level field
of a `--report=-` document on stdin), `runtime_binary`, `keyring_mode`,
`fifo_release <fifo>`, and the `tree_*` helpers that `t7101` to `t7103`
share.

- Each family boots its own VM, so a test finds loaded only what its
  family loaded. Call `require_loaded` rather than counting on an
  earlier test (`t3104`, `t6117`).
- The tests of a family share one VM in number order, and state under
  `/var/lib/shirudo` is sealed, so nothing a test leaves there goes
  away. Unload in the `EXIT` trap what the test loaded, with
  `"$SHIRUDO_BIN" upatch unload <fixture>.unload.upatch --no-precheck`
  as `t8101` does. A probe that may damage labeled state works on the scratch
  image of `t6111-seal-scratch.sh`, never on `/var/lib/shirudo`.
- A target test never skips: `run-target-tests.sh` fails a test that
  prints `1..0 # SKIP` with `required target test was skipped`. Its
  `test_skip_all` lines catch a VM that lacks a tool or fixture, which
  should fail the family. For a kernel feature the test VM's kernel
  lacks, run a case that needs nothing and guard the feature's case
  with an `if`, as `t6153-xfs-attrmulti.sh` does for XFS.
- Read a tamper counter before and after, from `"$SHIRUDO_BIN" status
  --json` under `tamper_attempts.counters`, and compare with `-gt` or
  `-ge` (`t6118`).
- Every target command holds the config operation lock for its whole
  run, so two never run at once. A test that keeps one stopped, on a
  FIFO that `fifo_release` opens, reads `status` before and after it,
  not while it waits.
- To stop a command partway, start it in the background in the case,
  poll with builtins only (`kill -0`, `[ -e ]`) and bound the loop: a
  child that exited stays a zombie and `kill -0` succeeds until it is
  reaped (`stopped_load()` in `t6144`).
- What only the next boot shows goes in `image-reboot`, whose VM runs
  its tests, reboots and runs them again: a test reads
  `SHIRUDO_TEST_BOOT`, `1` or `2`, and keeps what it carries across
  under `SHIRUDO_TEST_RESULTS` (`t5106`).

## Fixtures and helpers

- A signed upatch fixture is `testing/fixtures/<name>.bpf.c` and a line
  `queue_fixture build_fixture <name>.bpf.c shirudo-test-<x>
  "$FIXTURE_WORK/trusted"` in `testing/vm/build-bundle-payload.sh`. Its
  unload directive takes a `<x>_payload=` read with `upatch info --json`
  and a line `shirudo-test-<x> $<x>_payload shirudo-test-<x>.unload.upatch`
  in the list `shirudo-build --unload` reads there. A fixture file the
  globs of `TEST_VM_BUNDLE_SOURCES` in `testing/Makefile` do not match,
  one in a subdirectory of `testing/fixtures/` not listed there, goes
  in that list, or a change to it does not rebuild the bundle.
- A signed config image is a name in the loop of
  `testing/vm/image-fixtures.sh` with a `case` for its files. The guest
  finds it as `$SHIRUDO_TEST_KEY_FIXTURES/<name>` and activates it with
  `"$SHIRUDO_BIN" image update`, as `tree_configure` does.
- A compiled helper is `testing/helper/<name>.c` with a rule and a
  `TEST_HELPERS` entry in `Makefile.shirudo`; one a target test runs is
  also in the helper list of `build-bundle-payload.sh`. `make` alone
  does not rebuild helpers: `make -C testing test-helpers`.

## Harness traps

The `shell` skill has the dash and errexit traps of every script; these
are the ones the harness adds or makes worse.

- `test-lib.sh` runs `set -eu`. A failing step of an `EXIT` trap ends
  the trap and the script exits 1 with every case `ok`; guard each step
  with `|| true` (`restore()` in `t6118`).
- A body runs as `if (eval "$body")`: errexit is off inside it, so a
  failing line followed by another passes. Chain every step with `&&`.
- A body's standard output is discarded; write what a failure needs
  to `>&2`, which comes back as `#` lines.
- A body is a subshell: a variable it sets never reaches the script or the
  next case, and `wait` there cannot reap a child the script started
  (it returns 127 at once). Keep state in files under the test's
  directory.
- Tests run under `sh`, dash on Ubuntu. A redirection that fails on a
  special builtin ends the whole case under dash, even negated:
  `! : >"$sealed/f"` reports `not ok`. Write `! true >"$sealed/f"` or
  `! touch "$sealed/f"`.
- `mv` across file systems copies and unlinks instead of renaming. A
  probe of the rename hook stages its source where `rename(2)` can
  reach the target, as `t6118` stages in `/var/lib/t6118-stage`; and
  `mv` of a directory onto an existing one moves it inside.
- Never `rm -rf` a scratch tree that may still hold a bind of `/run`:
  removing it empties the real `/run`. `cleanup()` in
  `t6120-umount-above.sh` unmounts the tree and removes it only when
  `$W/run` is no longer a mount point.
- `sync && echo 2 >/proc/sys/vm/drop_caches` evicts the seal's
  directory marks. The entry hooks read the label again, so eviction
  must open nothing: `t6115` and `t6118` try a rename after each
  eviction to show it. It is no way to plant an entry in sealed state.
- A `BUILD_CONTAINER` exported in the shell fails a case of `t1007`,
  which reads the default from `make -n`. Run the host tier without it.

Run `shellcheck <test>` from the root before the family and fix what
the lines you wrote add; the Lint workflow fails only at `-S error`,
which misses the bashisms the default severity names (the `shell`
skill).

## Run and read

1. Run the family's host tests first; they take seconds, and a failure
   there stops the family's run before its VM boots anyway:

   ```sh
   make -C testing functional/<family> VM=0
   ```

2. Run the family, which boots its VM (the `testing` skill, "Before a
   VM goal"). `TEST_FILTER` selects tests in the VM too:

   ```sh
   make -C testing functional/<family> TEST_FILTER='^t6118-'
   ```

3. Read the result. The run ends with `[test-vm] result: PASS` or
   `FAIL`, then:
   - `failed tests:` names each case that printed `not ok`;
   - `failed suites: ... (no individual TAP failure recorded)` is a
     script that exited non-zero with every case `ok`: its `EXIT` trap
     or a top-level command failed;
   - `failed tests: none recorded (failure occurred before the test
     suite)` is the guest's preparation: read `result/guest.log` from
     the top and `console.log`.

   The VM is `build/test-vm/vms/test-<family>-<suffix>/`. Its
   `result/guest.log` holds what every test printed,
   `result/verity/<test>.sh.log` one test's output, `result/status` the
   guest's exit status. A failed run keeps its disks and copies its logs
   to `build/test-vm/logs/<vm>/`.
4. Fix and run the family again. While a family runs, edit nothing and
   start no second run in the checkout: a run whose inputs changed
   rebuilds the bundle under the running guest, whose fixtures vanish
   mid-test (`No such file or directory` under `/mnt/shirudo-bundle`).
   `make -j` boots several families on one bundle.

A test run by hand in an interactive VM is no verdict. That VM enables
the timers, and the map export runs every 5 seconds and takes the config
operation lock, so a command there can print `waiting for another
shirudo command to release the config operation lock` or fail after 30
seconds with `Resource temporarily unavailable`. It keeps what earlier
runs left in sealed state. A suite started in the background from an
`ssh` session inherits its session keyring, which Ubuntu's PAM revokes
at logout, and every `add_key()` then fails with `Key has been revoked`.
`make -C testing functional/<family>` gives the verdict CI gives.

## Document it

Add the test's row to its family's table in
`Documentation/contribute/testing/test-coverage.rst`, `t<F><K><NN>-<what>`
and what it covers, and name it in "Coverage by area", in "Coverage by
threat" and the threat's `:Tests:` field in
`Documentation/security/threat-model.rst` when it covers one, and in
"Coverage of tamper counters" when it moves one. A test that closes a
line of "Not covered" removes it. `.github/scripts/check-docs.sh` fails
on a page that names a test that does not exist, never on a missing row.

## Tests of CI scripts

A script of `.github/scripts/` is tested in
`testing/ci-checks/t00<NN>-<what>.sh`, family 0, kind 0, as
`t0001-check-dco.sh` tests `check-dco.sh`:

- Start one level up, `cd "$(dirname "$0")/.."`, source `./test-lib.sh`,
  and name the script `$(cd .. && pwd)/.github/scripts/<script>`.
- Give it a throwaway repository or tree under `mktemp -d`, never the
  checkout (`t0001`).
- Put a stub of every command it would run first on `PATH`, as
  `t0011-main-status.sh` stubs `gh` in `$fixture/bin`. Stub the scripts
  it calls as well: several scripts there run `apt-get`, and
  `kernel-obs-apt-diagnostics.sh` runs `update-initramfs`, which must
  never reach the host.
- Run `make -C testing ci-checks`, or `sh testing/ci-checks/<test>.sh`.
  CI runs the tier with the unit tests (`tests.sh run unit`) and in the
  sanitizer jobs. Its row goes under ``ci-checks`` (0) in
  `test-coverage.rst`.
