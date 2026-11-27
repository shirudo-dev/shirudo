# Build, stage and BTF

- Build the test kernel by hand
- Stage a build for the VM
- vmlinux.h, BTF and vendor/libbpf

## Build the test kernel by hand

```sh
testing/kernel/build-kernel.sh --config-only   # patches and .config only
testing/kernel/build-kernel.sh --llvm 20       # as CI builds, host arch
testing/kernel/build-kernel.sh --llvm 20 --arch arm64
```

- Install what `.github/scripts/build-test-kernel.sh` lists, or ask the
  user to; never run that script on a host. The script checks for its
  tools and for a complete LLVM: `clang`, `ld.lld`, `llvm-objcopy`,
  `llvm-ar`, `llvm-nm` and `llvm-config` of one version, with its
  headers, which `CONFIG_BPF_FMODRET_SCAN` needs. Without `--llvm` the
  newest complete version on `PATH` builds; `LLVM_CONFIG` names another
  `llvm-config`.
- Every run applies every patch, `--config-only` included. No option
  skips or selects one, and a patch that touches one architecture's
  files is applied on the others too. Only x86-64 and arm64 build.
- The configuration is `allnoconfig`, the common and architecture
  fragments, `olddefconfig`. Then every symbol a fragment sets is
  checked against the result, and `CONFIG_LSM="bpf"` and
  `CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y` whatever the fragments
  say. A symbol whose dependencies are missing ends unset and fails the
  check; a `lint:` line names one the tree does not have. Each group of
  options carries a comment saying why the test kernel needs it.
- Under `build/test-kernel/`, or the directory `-o` names:
  - `src/`, the bpf-next checkout with the patches as commits. Never
    edit it: every run checks out the pin there again, and an edit that
    does not conflict is built in silently.
  - `obj-<arch>/`, the object tree with `.config`, `merge.log` and the
    module signing key, which stays there.
  - `kernel-<arch>.config`, the verified configuration.
  - `pkgs/<arch>/<release>-<stamp>/`, the packages, `config-<release>`,
    `System.map-<release>`, `vmlinux-<release>.btf`, the module signing
    certificate, `BUILD-INFO` and `SHA256SUMS`.
  - `kernel-ci-source.tar.zst`, the patched source with
    `testing/kernel/`.
- An arm64 build on an x86-64 host has no headers package.

## Stage a build for the VM

```sh
testing/vm/kernel-artifact.sh stage build/test-kernel/pkgs/<arch>/<release>-<stamp>
```

`stage` takes the directory of one build (or a directory holding
exactly one), checks its BTF for the signed-loader ABI and every hook
`bpf/*.c` attaches to, and puts the image, BTF, configuration and
modules under `artifacts/bpf-next-kernel-debs/`. That replaces the
checkout's staged kernel, which every VM goal and every BPF build then
uses: say so first. It writes no `kernel-run-id`. Remove
`artifacts/bpf-next-kernel-debs/` to get the pinned kernel back on the
next VM goal. A headers package is optional.

## vmlinux.h, BTF and vendor/libbpf

- `vendor/linux/vmlinux.h` is generated, never committed:
  `tools/gen-vmlinux-h/gen-vmlinux-h` dumps the BTF `BPF_VMLINUX_BTF`
  names, by default `artifacts/bpf-next-kernel-debs/vmlinux.btf` when a
  kernel is staged and `/sys/kernel/btf/vmlinux` otherwise;
  `BPF_VMLINUX_H=<file>` copies a header instead.
  `vendor/linux/.vmlinux-btf-source` records the source, and a build
  regenerates the header when the selection or the BTF changes.
  `make -n -f Makefile.shirudo vendor/linux/vmlinux.h` shows what it
  would read.
- A worktree has no `artifacts/`; give it `BPF_VMLINUX_BTF` (`pre-submit`
  skill).
- `upatches/kernel-cve/vmlinux.h` is a tracked header of that package;
  nothing regenerates it.
- `make bpf-deps` refreshes `vendor/libbpf/`, libbpf and the BPF UAPI
  headers, not `vmlinux.h`. Run it only when asked. Pass
  `KERNEL_SRC=<tree at the pin>`; without it the script clones
  bpf-next's tip, which can be ahead of the pin. It overwrites the local
  changes `vendor/libbpf/README.md` lists: apply them again.
  `vendor/libbpf/COMMIT` records its commit, which need not be the pin.
