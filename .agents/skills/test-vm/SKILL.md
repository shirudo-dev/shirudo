---
name: test-vm
description: Boot, reuse or stop the shirudo test VM that `make -C testing vm` runs, a QEMU guest with a software TPM, the kernel built with the patches in `kernel/`, and `init` run from a dracut initrd. Use when asked to spin up, boot or start a test VM, or when a task needs shirudo running as a target or a target test run by hand, which the host cannot do. Takes an optional kernel, bpf-next by default or a release from 7.4 up.
---

# Test VM

shirudo runs as a target only inside the VM that `make -C testing vm`
boots. Do not run `shirudo init` or a target test (`t?1??`) on the host.
`Documentation/contribute/testing/testing.rst` is the reference, under
"Boot an interactive VM" and "Run a target test by hand".

## Kernel

The optional argument is passed as `KERNEL=`. Leave it out for
`bpf-next`, the kernel the test suite runs. A release such as `7.4`
boots that tag instead. `testing/Makefile` refuses one older than
`VM_KERNEL_MIN`. Either kernel is built on first use, which takes a
while; say so before starting.

## When the task needs no interactive VM

- The target suite, or one family of it, boots a fresh VM per family
  on its own: `make -C testing functional[/<family>]` or
  `make -C testing end2end`.
- A build that fails because the host's kernel BTF lacks the
  signed-loader ABI needs the test kernel, not a VM. After
  `make -C testing kernel`, the build reads
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
guest and returns. `shirudo-runtime status` in the guest shows an initialized
target. Without `VM_NAME`, `vm-clean` removes all of `build/test-vm/`,
the bundles and the cached runtime image included, so always name the VM.
