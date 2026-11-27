---
name: testing
description: Runs shirudo's tests and its test VM, and decides which tier a test belongs in. Covers the unit, ci-checks, functional and end2end tiers, one suite or family, the target tests that boot a QEMU guest with a software TPM, sanitizer and fuzz runs, and booting, reusing or stopping an interactive VM. Use when asked to run or debug a test, to choose where a new test goes, to boot or use a test VM, or when a task needs shirudo running as a target. Takes an optional kernel, bpf-next by default or a release from 7.4 up.
---

# Testing

`Documentation/contribute/testing/testing.rst` is the reference: the
tiers, the families and how tests are named, and the VM under "Boot an
interactive VM" and "Run a target test by hand".
`Documentation/contribute/testing/test-coverage.rst` lists what each test
covers and changes with every test added or removed.

## Choose a tier

Put a test in the lowest tier that can show the change works, then load
that tier's skill to write it:

| Under test | Tier and file | Cost | Reaches | CI runs it | Skill |
|---|---|---|---|---|---|
| A function or parser of `util/`, or an object a suite links through `UNIT_OBJS` | unit, `testing/unit/<m>.c` | seconds | the code in-process, files under `TMPDIR`, a private mount namespace as root; no BPF LSM, keyring, TPM or VM | Build with gcc and clang on every pull request, in the merge queue and on main; the CI suite's unit and arm64 host jobs; ASan, UBSan and MSan on pull requests, TSan on main | `unit-tests` |
| A script of `.github/scripts/` | ci-checks, `testing/ci-checks/t00<NN>-*.sh` | seconds | a throwaway repository and stubbed commands | the CI suite's unit and arm64 host jobs and the ASan and UBSan job, on pull requests and main | `functional-tests` |
| A command's behavior on the build host: build, sign, package, publish to a mock registry, `attest verify`, TPM structures under the libtpms simulator, the build and VM scripts | operator test `t<F>0<NN>` in its family's directory | seconds to a minute | the checkout's binaries and helpers, as the user who runs it, root in CI | the CI suite's functional shards and arm64 host job and the ASan and UBSan job, on pull requests and main | `functional-tests` |
| Enforcement or state on a booted target: an LSM hook, the seal, the keyrings, the register, load and unload, tree sync | target test `t<F>1<NN>` in its family's directory | a bundle build and a VM boot per family, minutes | root in a fresh VM with the test kernel, a software TPM, the initrd, signed fixtures and config images | the CI suite's functional shards, x86-64, on pull requests and main | `functional-tests` |
| A flow across the operator, a registry, targets and the backend | end2end, `testing/end2end/t91<NN>-*.sh` | the whole tier, the longest run: the operator package built in a VM and up to five target boots | the operator VM, fresh nodes, the registry and the keepalive backend | the CI suite's end-to-end job, x86-64, on pull requests and main | `end2end-tests` |

A parser of input from outside the host also gets a fuzz target (the
`fuzz-target` skill) and a CBMC proof where one fits (the `proofs`
skill), which CI runs on main only. The SQL of `tools/backend` is
tested by `tools/backend/test/<name>.sql`, as "Run the backend tests"
in `testing.rst` says. The merge queue runs none of the shell tiers.

## Tiers

```sh
make tests                                  # every test, as CI runs them
make -C testing unit|ci-checks|functional|end2end|backend
make -C testing unit/<suite>                # one unit suite
make -C testing functional/<family>         # one family, its VM tests too
make tests VM=0                             # without the target tests
make tests BACKEND=0                        # without the backend's SQL tests
make tests VM=0 BACKEND=0 SANITIZE=address,undefined  # CI: gcc on a PR, clang too on main
make tests VM=0 BACKEND=0 SANITIZE=thread CC=clang    # CI on main: TSan, for threads and handlers
sh .github/scripts/msan-deps.sh             # MSan: instrumented libraries once,
sh .github/scripts/msan-tests.sh [60]       # then unit and fuzz from a clean tree
make -C testing fuzz [FUZZ_SECONDS=60] [FUZZERS=<target>...]
.github/scripts/afl-deps.sh                 # AFL++ for clang 23, into build/afl
PATH=$PWD/build/afl/bin:$PATH make -C testing afl [AFL_SECONDS=600]
make -C testing help
tools/backend/test/run.sh <name>...         # only the SQL tests named
make -C tools/xtop tests                    # xtop: tsc and bun test, needs bun
```

The end2end tier runs node A's tests, t9101 to t9107, over SSH, then
the host tests t9109 to t9114 in rounds on fresh nodes, against the
keepalive backend `host.sh` starts. The `end2end-tests` skill says what
each round boots, what the host needs and where each log goes;
"Run the end-to-end tests" in `testing.rst` has the whole run.

Host tests run as they are. A target test, `t?1??`, runs in a fresh VM
per family, which needs KVM, an unlimited `ulimit -l`, the test kernel
and the bundle, but not root; see
below. The VM always boots the dm-verity runtime and the signed config
from a dracut initrd. The runner caches the initrd by kernel, bundle and
initrd inputs, while each family keeps its own VM and guest state. CI
runs the same suite through `.github/scripts/tests.sh`, as root.

## Reading results

- The host tiers print TAP. Look for `not ok`, `runtime error:` and
  `ERROR: AddressSanitizer`, and read the reason of every `# SKIP`: a
  skip can hide a failure. `grep -nE '^not ok|runtime error:|ERROR:
  AddressSanitizer|# SKIP'` finds each. t3004 skips when the arena serializer does
  not build, so a sanitizer abort in `shirudo-build` reads as a skip
  there.
- A family's target tests print only `[test-vm] result: PASS` or
  `FAIL`. Their TAP output is in
  `build/test-vm/vms/<name>/result/guest.log`, the exit status in
  `result/status`. The end-to-end VM's tests run over SSH from the
  host, which appends their output to the same `guest.log`; there
  `result/status` is only the guest's preparation, and `the SSH session
  that ran the target tests failed` is the channel failing, not a test.
- `end2end` runs an operator VM, `end2end-<pid>-operator`, around node
  A and node B. A failure there reads `host.sh failed with status <n>`;
  the `end2end operator:` lines say which step, the package build log
  is its `result/operator-build.log`, and what it published and verified
  is in its `result/end2end/`.
- A fuzz failure leaves its input in `testing/fuzz/crash-<target>-*`.
  Run the target binary on that file to reproduce it. An `abort()` in
  the harness is a property that failed, which can be the harness's own.

## Before a VM goal

- `vm`, `test-vm-bundle` and every family with target tests need a
  kernel staged under `artifacts/bpf-next-kernel-debs/`. When none is,
  the goal runs `testing/vm/kernel-artifact.sh fetch`, which downloads
  the prerelease the script pins with `curl` and checks its SHA-256
  before it unpacks it; `KERNEL_RUN_ID=<run>`, with an authenticated
  `gh`, fetches another run of Build kernel packages instead. A kernel
  already staged is used as it is: remove the directory to get the
  pinned one, and say so first. Building, staging or publishing a
  kernel and moving the pin are the `kernel` skill's.
- The bundle builds in the build container (`testing/container/`) from
  a copy of the files git sees in the checkout, tracked and untracked but
  not ignored, so uncommitted changes are tested; edit nothing until the
  copy is made. The first build makes the image, with network access,
  and the static target dependencies, which takes minutes; say so.
- With `BUILD_CONTAINER=0` the bundle builds in the checkout itself: edit
  nothing and run no other build there until it is built. It then
  compiles its BPF fixtures with the clang `shirudo-build` was built
  for, `SHIRUDO_CLANG_PATH`, `/usr/bin/clang` unless set. It must be
  clang 23; an older one stops at a release store with
  `Cannot select: ... AtomicStore`. Make does not rebuild the helper
  when only that variable changes: remove
  `tools/shirudo-build/compile.o` first.
- `end2end` prepares the operator VM's image on first use, with network
  access for clang 23 from apt.llvm.org, and caches it beside the
  runtime image; every run then builds the operator package in that VM,
  which takes minutes. Say so before starting.

## Run unconfined

No VM goal needs root. A terminal installed as a snap, such as
Alacritty, gives everything it starts its `snap.<name>` AppArmor label
(`cat /proc/self/attr/current`), and Ubuntu's `swtpm` profile takes
signals only from unconfined processes and from `swtpm`: Ctrl-C, the
runner's cleanup and `vm-stop` then leave `swtpm` running. When `cat
/proc/self/attr/current` prints anything but `unconfined`, run the
goal as a transient user service, which runs unconfined; otherwise run
it directly, with the shell's environment and limits. It starts with the
environment and limits of the user manager, not the shell's. The
families build the host tier on the host, and so does the bundle with
`BUILD_CONTAINER=0`; pass on the `PATH` and `LD_LIBRARY_PATH` a host
with an older OpenSSL or clang than the tree needs for that. `end2end`
builds nothing on the host and needs neither. Check that `systemctl
--user show -p DefaultLimitMEMLOCK` reads `infinity`, the unlimited
`ulimit -l` a VM goal needs.

```sh
systemd-run --user --pipe --same-dir --wait --collect \
	--setenv=PATH="$PATH" --setenv=LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
	--setenv=PKG_CONFIG_PATH="$PKG_CONFIG_PATH" \
	--setenv=SHIRUDO_CLANG_PATH="${SHIRUDO_CLANG_PATH:-/usr/bin/clang}" \
	make -C testing <goal>
```

- `make -C testing vm` adds `-p KillMode=process`, so that QEMU and
  `swtpm`, started inside the unit, outlive it. Leave it out for the
  families and `end2end`, whose VM ends with the run: stopping the unit,
  `systemctl --user stop run-u<N>.service` with the name `systemd-run`
  prints, then stops everything the run started.
- Run `vm-stop` and `vm-clean` the same way. `vm-ssh` and `vm-console`
  need the terminal and signal nothing; run them from the shell.
- A leftover `swtpm` dies the same way, by PID:
  `systemd-run --user --wait --collect --quiet kill <pid>...`. A
  `pkill -f <pattern>` also matches the shell whose command line
  carries the pattern, and kills it.

## Kernel

The optional argument is passed as `KERNEL=` to select an already staged
artifact. Leave it out for `bpf-next`, the kernel the test suite runs.
The BPF build reads `artifacts/bpf-next-kernel-debs/vmlinux.btf` in
place of `/sys/kernel/btf/vmlinux` (`Makefile.shirudo`).

## Reuse a running VM

A VM belongs to the checkout that booted it. Its state lives in that
checkout's `build/test-vm/vms/<name>/`, and the guest mounts that
checkout's source. Consider only VMs of the current checkout. Other QEMU
processes on the host, such as little-vm-helper guests, are not shirudo
targets.

A VM named `<name>-operator` or `<name>-end2end` belongs to an
end-to-end run, which stops it when it ends; `vm-ssh` reaches it while
the run lasts, but never reuse, stop or clean it.

A VM under `build/test-vm/vms/<name>/` can be reused when all of these
hold:

1. It runs. `qemu.pid` holds a live PID, and `/proc/<pid>/cmdline`
   names the state directory.
2. It booted the requested kernel. The `-kernel` path in that command
   line lies in the selected staged kernel artifact directory.
3. It runs the current build. The command line names the bundle it
   booted, `shirudo-bundle,path=<bundle>`. The VM is stale when
   `<bundle>/.stamp` is newer than `created-at` (nanoseconds since the
   epoch), or when the tree has changed since the bundle was built, which
   `make -C testing -q KERNEL=<kernel> <bundle>/.stamp` reports with a
   non-zero exit.

```sh
for vm in build/test-vm/vms/*/; do
	vm=${vm%/}
	pid=$(cat "$vm/qemu.pid" 2>/dev/null) || continue
	cmd=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null) || continue
	case $cmd in *"$PWD/$vm"*) ;; *) continue ;; esac
	printf '%s\n' "$vm: $cmd"
done
```

Use a VM that passes all three checks, and name it in every command with
`VM_NAME=<name>`. When no VM of this checkout runs, boot one (`make -C
testing vm`) and say so. Ask the user when one runs a different kernel
or a stale build, or when several pass: offer to boot a new VM beside
it, to stop or replace the old one, or to use it anyway. Never stop,
replace or clean a VM without that answer.

## Commands

Run each as yourself, as above; root is not needed.

```sh
make -C testing vm VM_NAME=<name> [KERNEL=<kernel>]
make -C testing vm-ssh VM_NAME=<name>
make -C testing vm-console VM_NAME=<name>
make -C testing vm-stop VM_NAME=<name>
make -C testing vm-clean VM_NAME=<name>
```

Adding `VM_SSH_COMMAND='<command>'` to `vm-ssh` runs one command in the
guest and returns. In the guest, `shirudo-runtime` is the runtime the
initrd verified, and `shirudo` an alias of it only in the shell `vm-ssh`
opens from a terminal; `shirudo-runtime status` shows an initialized target,
and `. /etc/shirudo-test-vm.env` sets the environment a family run
gives the target tests.
The checkout is mounted read-only at `/workspace/shirudo`. Without
`VM_NAME`, `vm-clean` stops every VM and removes the state and logs of
them all, and leaves the bundles, the cache and the local stack; name
the VM to remove only its state. `make stack-down` removes the local
stack with its data and CA.
