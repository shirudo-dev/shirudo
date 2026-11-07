---
name: testing
description: Run shirudo's tests and its test VM. Covers the unit, ci-checks, functional and end2end tiers, one suite or family of them, the target tests that each boot a QEMU guest with a software TPM, sanitizer and fuzz runs, and booting, reusing or stopping an interactive VM. Use when asked to run, add or debug a test, to boot or use a test VM, or when a task needs shirudo running as a target, which the host cannot do. Takes an optional kernel for the VM, bpf-next by default or a release from 7.4 up.
---

# Testing

`Documentation/contribute/testing/testing.rst` is the reference: the
tiers, the families and how tests are named, and the VM under "Boot an
interactive VM" and "Run a target test by hand".
`Documentation/contribute/testing/test-coverage.rst` lists what each test
covers and changes with every test added or removed.

## Tiers

```sh
make tests                                  # every test, as CI runs them
make -C testing unit|ci-checks|functional|end2end
make -C testing unit/<suite>                # one unit suite
make -C testing functional/<family>         # one family, its VM tests too
make tests VM=0                             # without the target tests
make tests VM=0 SANITIZE=address,undefined  # CI: once with gcc, once with clang
make -C testing fuzz [FUZZ_SECONDS=60]
make -C testing help
```

Host tests run as they are. A target test, `t?1??`, runs in a fresh VM
per family, which needs root, KVM, the test kernel and the bundle; see
below. The VM always boots the dm-verity runtime and the signed config
from a dracut initrd. The runner caches the initrd by kernel, bundle and
initrd inputs, while each family keeps its own VM and guest state. CI
runs the same suite through `.github/scripts/tests.sh`. A change to
`util/<m>.c` adds or updates its cases in `testing/unit/<m>.c`, and a
parser of input from outside the host gets a target in `testing/fuzz/`.

## Reading results

- The host tiers print TAP. Look for `not ok`, `runtime error:` and
  `ERROR: AddressSanitizer`, and read the reason of every `# SKIP`: a
  skip can hide a failure. t7005 and t7006 skip when `bpm build` fails,
  so a sanitizer abort in `shirudo-build` reads as a skip there, and
  t3004 skips when the arena serializer does not build.
- A family's target tests print only `[test-vm] result: PASS` or
  `FAIL`. Their TAP output is in
  `build/test-vm/vms/<name>/result/guest.log`, the exit status in
  `result/status`.
- A fuzz failure leaves its input in `testing/fuzz/crash-<target>-*`.
  Run the target binary on that file to reproduce it. An `abort()` in
  the harness is a property that failed, which can be the harness's own.

## Before a VM goal

- `vm`, `test-vm-bundle` and every family with target tests build the
  kernel first when `testing/vm/build-kernel.sh` or a kernel patch is
  newer than the artifact's `bzImage.sha256sum`. The build deletes the
  artifact directory, needs gigabytes of disk and takes long, and a
  checkout or rebase that touches the script triggers it. Compare the
  times before starting and tell the user when a rebuild is due.
- The bundle is built in the checkout from the working tree, so
  uncommitted changes are tested. Edit nothing and run no other build in
  that checkout until it is built.
- The bundle compiles its BPF fixtures with the clang `shirudo-build`
  was built for, `SHIRUDO_CLANG_PATH`, `/usr/bin/clang` unless set. It
  must be clang 23; an older one stops at a release store with
  `Cannot select: ... AtomicStore`. Make does not rebuild the helper
  when only that variable changes: remove
  `tools/shirudo-build/compile.o` first.

## Kernel

The optional argument is passed as `KERNEL=`. Leave it out for
`bpf-next`, the kernel the test suite runs. A release such as `7.4`
boots that tag instead. `testing/Makefile` refuses one older than
`VM_KERNEL_MIN`. Either kernel is built on first use, which takes a
while; say so before starting. A build that fails because the host's
kernel BTF lacks the signed-loader ABI needs the kernel, not a VM: after
`make -C testing kernel` the build reads
`artifacts/bpf-next-kernel-debs/vmlinux.btf` in place of
`/sys/kernel/btf/vmlinux` (`Makefile.shirudo`).

## Reuse a running VM

A VM belongs to the checkout that booted it. Its state lives in that
checkout's `build/test-vm/vms/<name>/`, and the guest mounts that
checkout's source. Consider only VMs of the current checkout. Other QEMU
processes on the host, such as little-vm-helper guests, are not shirudo
targets.

A VM under `build/test-vm/vms/<name>/` can be reused when all of these
hold:

1. It runs. `qemu.pid` holds a live PID, and `/proc/<pid>/cmdline`
   names the state directory.
2. It booted the requested kernel. The `-kernel` path in that command
   line lies in `artifacts/bpf-next-kernel-debs/` for bpf-next, or in
   `artifacts/linux-v<version>-kernel-debs/` for a release.
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
`VM_NAME=<name>`. Ask the user what to do in any other case: when no VM
runs, when one runs a different kernel or a stale build, or when several
pass. Offer to boot a new VM, to stop or replace the old one, or to use it
anyway. Never stop, replace or clean a VM without that answer.

## Commands

Run each as root, as the testing guide does.

```sh
make -C testing vm VM_NAME=<name> [KERNEL=<kernel>]
make -C testing vm-ssh VM_NAME=<name>
make -C testing vm-console VM_NAME=<name>
make -C testing vm-stop VM_NAME=<name>
make -C testing vm-clean VM_NAME=<name>
```

Adding `VM_SSH_COMMAND='<command>'` to `vm-ssh` runs one command in the
guest and returns. In the guest, `shirudo-runtime` is the runtime the
initrd verified; `shirudo-runtime status` shows an initialized target.
The checkout is mounted read-only at `/workspace/shirudo`. Without
`VM_NAME`, `vm-clean` removes all of `build/test-vm/`, the bundles and
the cached runtime image included, so always name the VM.
